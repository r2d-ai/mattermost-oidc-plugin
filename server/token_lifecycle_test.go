package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func lifecycleFixture(t *testing.T, h http.HandlerFunc) (*Plugin, *identityAPI, ResolvedIdentity, *CredentialStore, StoredCredentials) {
	t.Helper()
	var issuer string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks", "revocation_endpoint": issuer + "/revoke"})
			return
		}
		h(w, r)
	}))
	issuer = srv.URL
	t.Cleanup(srv.Close)
	p, a, _ := fixtureIdentity(t)
	p.discoveryClient = srv.Client()
	cfg := p.getConfiguration()
	cfg.IssuerURL = issuer
	cfg.EnablePlaneBroker = true
	cfg.EnableTokenPersistence = true
	p.setConfiguration(cfg)
	fp := identityFingerprint(issuer, cfg.ClientID)
	a.kv[identityGateKey], _ = json.Marshal(identityGate{Version: 1, Status: "active", Epoch: 2, Issuer: issuer, ClientID: cfg.ClientID, IdentityFingerprint: fp})
	s := &LoginSnapshot{IdentityFingerprint: fp, GateEpoch: 2, configuration: *cfg}
	p.loginSnapshot = s
	r, _, e := p.resolveVerifiedLogin(context.Background(), s, VerifiedLoginIdentity{issuer, "lifecycle-sub"}, &OIDCUserInfo{Subject: "lifecycle-sub", Email: "life@example.com", Username: "life"})
	require.NoError(t, e)
	credentialKeys(t, "current", map[string]string{"current": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))})
	c := StoredCredentials{Binding: r.Binding, AccessToken: "access-old", RefreshToken: "refresh-old", AccessExpiresAt: time.Now().Add(-time.Minute), GateEpoch: r.GateEpoch, BindingRevision: r.BindingRevision}
	store := newCredentialStore(p)
	require.NoError(t, store.Save(context.Background(), c))
	return p, a, r, store, c
}
func lifecycleOther(p *Plugin, a *identityAPI) *TokenLifecycle {
	q := &Plugin{discoveryClient: p.discoveryClient}
	q.SetAPI(a)
	q.setConfiguration(p.getConfiguration())
	return newTokenLifecycle(q)
}
func refreshResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"access_token":"access-new","refresh_token":"refresh-new","token_type":"Bearer","expires_in":300}`))
}
func TestConcurrentRefreshAcrossNodes(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	p, a, r, store, _ := lifecycleFixture(t, func(w http.ResponseWriter, req *http.Request) {
		require.Equal(t, "/token", req.URL.Path)
		require.NoError(t, req.ParseForm())
		require.Equal(t, "refresh-old", req.Form.Get("refresh_token"))
		require.Equal(t, "refresh_token", req.Form.Get("grant_type"))
		require.Empty(t, req.Form.Get("scope"))
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		refreshResponse(w)
	})
	claims, allowClaims := make(chan struct{}, 2), make(chan struct{})
	var releaseClaims sync.Once
	t.Cleanup(func() { releaseClaims.Do(func() { close(allowClaims) }) })
	a.beforeCAS = func(k string, old, next []byte) *model.AppError {
		var env credentialEnvelope
		_ = json.Unmarshal(next, &env)
		if k == credentialKey(r.Binding) && env.State == "refreshing" && env.Phase == "" {
			claims <- struct{}{}
			<-allowClaims
		}
		return nil
	}
	type result struct {
		token UserToken
		err   error
	}
	results := make(chan result, 2)
	for _, l := range []*TokenLifecycle{newTokenLifecycle(p), lifecycleOther(p, a)} {
		go func() { v, e := l.UserAccessToken(context.Background(), r.Binding); results <- result{v, e} }()
	}
	for range 2 {
		select {
		case <-claims:
		case <-time.After(time.Second):
			t.Fatal("both nodes did not reach refresh claim")
		}
	}
	releaseClaims.Do(func() { close(allowClaims) })
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("no owner")
	}
	close(release)
	for range 2 {
		select {
		case v := <-results:
			require.NoError(t, v.err)
			require.Equal(t, "access-new", v.token.Value)
			require.Equal(t, uint64(2), v.token.Generation)
		case <-time.After(3 * time.Second):
			t.Fatal("refresh blocked")
		}
	}
	require.Equal(t, int32(1), calls.Load())
	c, e := store.Load(context.Background(), r.Binding)
	require.NoError(t, e)
	require.Equal(t, "refresh-new", c.RefreshToken)
}
func TestRefreshWithoutReplacementRequiresReconnect(t *testing.T) {
	p, _, r, store, _ := lifecycleFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"access-new","token_type":"Bearer","expires_in":300}`))
	})
	_, err := newTokenLifecycle(p).UserAccessToken(context.Background(), r.Binding)
	require.ErrorIs(t, err, ErrReconnectRequired)
	env, _, err := store.read(r.Binding)
	require.NoError(t, err)
	require.Equal(t, "invalidated", env.State)
}

func TestRefreshResponseLostRequiresReconnect(t *testing.T) {
	var calls atomic.Int32
	p, _, r, store, _ := lifecycleFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		conn, _, _ := w.(http.Hijacker).Hijack()
		_ = conn.Close()
	})
	for range 2 {
		_, e := newTokenLifecycle(p).UserAccessToken(context.Background(), r.Binding)
		require.ErrorIs(t, e, ErrReconnectRequired)
	}
	require.Equal(t, int32(1), calls.Load())
	env, _, e := store.read(r.Binding)
	require.NoError(t, e)
	require.Equal(t, "invalidated", env.State)
}
func TestCrashDuringRefreshDoesNotReuseToken(t *testing.T) {
	var calls atomic.Int32
	p, a, r, store, _ := lifecycleFixture(t, func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); refreshResponse(w) })
	a.beforeCAS = func(k string, old, next []byte) *model.AppError {
		if k == credentialKey(r.Binding) && bytes.Contains(next, []byte(`"state":"refreshing"`)) {
			a.mu.Lock()
			a.kv[k] = bytes.Clone(next)
			a.mu.Unlock()
			return failAPI()
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	_, e := newTokenLifecycle(p).UserAccessToken(ctx, r.Binding)
	require.Error(t, e)
	time.Sleep(100 * time.Millisecond)
	_, e = lifecycleOther(p, a).UserAccessToken(context.Background(), r.Binding)
	require.ErrorIs(t, e, ErrReconnectRequired)
	require.Zero(t, calls.Load())
	env, _, _ := store.read(r.Binding)
	require.Equal(t, "invalidated", env.State)
}
func TestDisconnectWinsOverRefresh(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	p, _, r, store, _ := lifecycleFixture(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/token" {
			close(entered)
			<-release
			refreshResponse(w)
		}
	})
	done := make(chan error, 1)
	go func() { _, e := newTokenLifecycle(p).UserAccessToken(context.Background(), r.Binding); done <- e }()
	<-entered
	require.NoError(t, newTokenLifecycle(p).Disconnect(context.Background(), r.Binding))
	once.Do(func() { close(release) })
	require.Error(t, <-done)
	env, _, e := store.read(r.Binding)
	require.NoError(t, e)
	require.Equal(t, "invalidated", env.State)
}
func TestDeactivationBlocksStoredCredential(t *testing.T) {
	p, a, r, store, c := lifecycleFixture(t, func(w http.ResponseWriter, _ *http.Request) { refreshResponse(w) })
	c.AccessExpiresAt = time.Now().Add(time.Hour)
	require.NoError(t, store.Save(context.Background(), c))
	a.users[r.Binding.MattermostUserID].DeleteAt = 1
	_, e := p.freezeIdentityGate()
	require.NoError(t, e)
	_, e = newTokenLifecycle(p).UserAccessToken(context.Background(), r.Binding)
	require.ErrorIs(t, e, ErrUserInactive)
	env, _, e := store.read(r.Binding)
	require.NoError(t, e)
	require.Equal(t, "invalidated", env.State)
}
func TestUnrelatedUsersDoNotSerialize(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	p, _, r, store, c := lifecycleFixture(t, func(w http.ResponseWriter, req *http.Request) {
		require.NoError(t, req.ParseForm())
		if req.Form.Get("refresh_token") == "refresh-old" {
			close(entered)
			<-release
		}
		refreshResponse(w)
	})
	s, e := p.currentLoginSnapshot(context.Background())
	require.NoError(t, e)
	other, _, e := p.resolveVerifiedLogin(context.Background(), s, VerifiedLoginIdentity{r.Binding.Issuer, "other"}, &OIDCUserInfo{Subject: "other", Email: "other@ex.com", Username: "other"})
	require.NoError(t, e)
	c.Binding = other.Binding
	c.RefreshToken = "refresh-other"
	require.NoError(t, store.Save(context.Background(), c))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _, _ = newTokenLifecycle(p).UserAccessToken(ctx, r.Binding) }()
	<-entered
	short, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	v, e := newTokenLifecycle(p).UserAccessToken(short, other.Binding)
	require.NoError(t, e)
	require.Equal(t, "access-new", v.Value)
	cancel()
	<-done
}

type lifecycleSessionAPI struct {
	*identityAPI
	session *model.Session
}

func (a *lifecycleSessionAPI) GetSession(id string) (*model.Session, *model.AppError) {
	if a.session == nil || id != a.session.Id {
		return nil, absentAPI()
	}
	return a.session, nil
}
func TestDisconnectSessionCSRFBoundary(t *testing.T) {
	for _, mode := range []string{"valid_oidc", "valid_password", "no_context", "no_header", "wrong_header", "wrong_session", "expired", "pat", "oauth", "bot", "deleted", "no_csrf", "wrong_csrf", "empty_session_csrf", "xmlhttprequest", "form_csrf"} {
		t.Run(mode, func(t *testing.T) {
			p, a, r, store, _ := lifecycleFixture(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
			sess := &model.Session{Id: model.NewId(), UserId: r.Binding.MattermostUserID, ExpiresAt: time.Now().Add(time.Hour).UnixMilli(), Props: map[string]string{"csrf": "csrf-secret"}}
			p.SetAPI(&lifecycleSessionAPI{a, sess})
			p.initRouter()
			pc := &plugin.Context{SessionId: sess.Id}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/plane/disconnect?user_id="+model.NewId(), nil)
			req.Header.Set("Mattermost-User-Id", sess.UserId)
			req.Header.Set("X-CSRF-Token", "csrf-secret")
			switch mode {
			case "valid_password":
				a.users[sess.UserId].AuthService = ""
				a.users[sess.UserId].AuthData = nil
			case "no_context":
				pc = nil
			case "no_header":
				req.Header.Del("Mattermost-User-Id")
			case "wrong_header":
				req.Header.Set("Mattermost-User-Id", model.NewId())
			case "wrong_session":
				pc.SessionId = model.NewId()
			case "expired":
				sess.ExpiresAt = 1
			case "pat":
				sess.Props[model.SessionPropType] = model.SessionTypeUserAccessToken
			case "oauth":
				sess.IsOAuth = true
			case "bot":
				a.users[sess.UserId].IsBot = true
			case "deleted":
				a.users[sess.UserId].DeleteAt = 1
			case "no_csrf":
				req.Header.Del("X-CSRF-Token")
			case "wrong_csrf":
				req.Header.Set("X-CSRF-Token", "wrong")
			case "empty_session_csrf":
				sess.Props["csrf"] = ""
			case "xmlhttprequest":
				req.Header.Set("X-CSRF-Token", "wrong")
				req.Header.Set("X-Requested-With", "XMLHttpRequest")
			case "form_csrf":
				req.Header.Del("X-CSRF-Token")
				req.Form = url.Values{"csrf": {"csrf-secret"}}
			}
			out := httptest.NewRecorder()
			p.ServeHTTP(pc, out, req)
			env, _, e := store.read(r.Binding)
			require.NoError(t, e)
			if strings.HasPrefix(mode, "valid_") {
				require.Equal(t, 204, out.Code)
				require.Equal(t, "invalidated", env.State)
			} else {
				require.Equal(t, 401, out.Code)
				require.Equal(t, "ready", env.State)
			}
		})
	}
}
func TestAdminRevokeFrozenInactiveTarget(t *testing.T) {
	for _, admin := range []bool{false, true} {
		t.Run(fmt.Sprint(admin), func(t *testing.T) {
			p, a, r, store, _ := lifecycleFixture(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
			actor := &model.User{Id: model.NewId(), Roles: "system_user"}
			if admin {
				actor.Roles += " system_admin"
			}
			a.users[actor.Id] = actor
			a.users[r.Binding.MattermostUserID].DeleteAt = 1
			_, e := p.freezeIdentityGate()
			require.NoError(t, e)
			sess := &model.Session{Id: model.NewId(), UserId: actor.Id, Props: map[string]string{"csrf": "csrf"}}
			p.SetAPI(&lifecycleSessionAPI{a, sess})
			p.initRouter()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/plane/revoke", strings.NewReader(`{"user_id":"`+r.Binding.MattermostUserID+`"}`))
			req.Header.Set("Mattermost-User-Id", actor.Id)
			req.Header.Set("X-CSRF-Token", "csrf")
			out := httptest.NewRecorder()
			p.ServeHTTP(&plugin.Context{SessionId: sess.Id}, out, req)
			env, _, e := store.read(r.Binding)
			require.NoError(t, e)
			if admin {
				require.Equal(t, 204, out.Code)
				require.Equal(t, "invalidated", env.State)
			} else {
				require.Equal(t, 403, out.Code)
				require.Equal(t, "ready", env.State)
			}
		})
	}
}
func TestDeactivationHookFrozenCleanupAndFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			p, a, r, store, _ := lifecycleFixture(t, func(w http.ResponseWriter, _ *http.Request) { refreshResponse(w) })
			a.users[r.Binding.MattermostUserID].DeleteAt = 1
			_, e := p.freezeIdentityGate()
			require.NoError(t, e)
			if fail {
				a.failKey = credentialPrefix
			}
			p.UserHasBeenDeactivated(nil, a.users[r.Binding.MattermostUserID])
			env, _, e := store.read(r.Binding)
			require.NoError(t, e)
			if fail {
				require.Equal(t, "ready", env.State)
			} else {
				require.Equal(t, "invalidated", env.State)
			}
			_, e = newTokenLifecycle(p).UserAccessToken(context.Background(), r.Binding)
			require.ErrorIs(t, e, ErrUserInactive)
		})
	}
}

func TestLifecycleDelayedPublication(t *testing.T) {
	for _, phase := range []string{"claim", "candidate", "ready"} {
		for _, successor := range []string{"none", "disconnect", "save"} {
			t.Run(phase+"_"+successor, func(t *testing.T) {
				var calls atomic.Int32
				p, a, r, store, c := lifecycleFixture(t, func(w http.ResponseWriter, req *http.Request) {
					if req.URL.Path == "/token" {
						calls.Add(1)
						refreshResponse(w)
					}
				})
				entered, release := make(chan struct{}), make(chan struct{})
				var blocked atomic.Bool
				a.beforeCAS = func(k string, old, next []byte) *model.AppError {
					if k != credentialKey(r.Binding) {
						return nil
					}
					var env credentialEnvelope
					_ = json.Unmarshal(next, &env)
					match := (phase == "claim" && env.State == "refreshing" && env.Phase == "") || (phase == "candidate" && env.Phase == "candidate") || (phase == "ready" && env.State == "ready" && env.Generation == 2)
					if match && blocked.CompareAndSwap(false, true) {
						close(entered)
						<-release
					}
					return nil
				}
				ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
				defer cancel()
				done := make(chan error, 1)
				go func() { _, e := newTokenLifecycle(p).UserAccessToken(ctx, r.Binding); done <- e }()
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("publication not reached")
				}
				// A candidate remains unavailable even before expiry.
				if phase == "ready" {
					_, e := store.Load(context.Background(), r.Binding)
					require.Error(t, e)
				}
				switch successor {
				case "disconnect":
					require.NoError(t, newTokenLifecycle(p).Disconnect(context.Background(), r.Binding))
				case "save":
					c.AccessToken = "successor"
					c.RefreshToken = "successor-refresh"
					c.AccessExpiresAt = time.Now().Add(time.Hour)
					require.NoError(t, store.Save(context.Background(), c))
				}
				<-ctx.Done()
				close(release)
				select {
				case e := <-done:
					require.Error(t, e)
				case <-time.After(time.Second):
					t.Fatal("late owner stuck")
				}
				if successor == "save" {
					latest, e := store.Load(context.Background(), r.Binding)
					require.NoError(t, e)
					require.Equal(t, "successor", latest.AccessToken)
				} else {
					env, _, e := store.read(r.Binding)
					require.NoError(t, e)
					require.Equal(t, "invalidated", env.State)
				}
				if phase == "claim" {
					require.Zero(t, calls.Load())
				} else {
					require.Equal(t, int32(1), calls.Load())
				}
			})
		}
	}
}
func TestLifecycleWaiterCancellationAndExpiredOwner(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	p, a, r, store, _ := lifecycleFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		close(entered)
		<-release
		refreshResponse(w)
	})
	ownerCtx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := newTokenLifecycle(p).UserAccessToken(ownerCtx, r.Binding); done <- e }()
	<-entered
	waiterCtx, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer stop()
	start := time.Now()
	_, e := lifecycleOther(p, a).UserAccessToken(waiterCtx, r.Binding)
	require.ErrorIs(t, e, ErrTemporarilyUnavailable)
	require.Less(t, time.Since(start), time.Second)
	require.Error(t, <-done)
	close(release)
	_, e = lifecycleOther(p, a).UserAccessToken(context.Background(), r.Binding)
	require.ErrorIs(t, e, ErrReconnectRequired)
	require.Equal(t, int32(1), calls.Load())
	env, _, _ := store.read(r.Binding)
	require.Equal(t, "invalidated", env.State)
}
func TestLifecycleMissingRotationInvalidGrantAndRedirect(t *testing.T) {
	for _, mode := range []string{"omitted_refresh", "invalid_grant", "redirect", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			p, _, r, _, _ := lifecycleFixture(t, func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				switch mode {
				case "omitted_refresh":
					_, _ = w.Write([]byte(`{"access_token":"new","expires_in":300,"token_type":"Bearer"}`))
				case "invalid_grant":
					w.WriteHeader(400)
					_, _ = w.Write([]byte(`{"error":"invalid_grant","secret":"must-not-escape"}`))
				case "redirect":
					http.Redirect(w, req, "https://unapproved.invalid/steal", 307)
				case "oversize":
					_, _ = w.Write(bytes.Repeat([]byte("x"), 65537))
				}
			})
			for range 2 {
				_, e := newTokenLifecycle(p).UserAccessToken(context.Background(), r.Binding)
				require.ErrorIs(t, e, ErrReconnectRequired)
				require.NotContains(t, e.Error(), "must-not-escape")
			}
			require.Equal(t, int32(1), calls.Load())
		})
	}
}
func TestLifecycleAuthorityChanges(t *testing.T) {
	for _, mode := range []string{"login_disabled", "broker_disabled", "persistence_disabled", "native_changed", "issuer_changed", "secret_changed", "deactivated"} {
		t.Run(mode, func(t *testing.T) {
			var p *Plugin
			var a *identityAPI
			var r ResolvedIdentity
			p, a, r, _, _ = lifecycleFixture(t, func(w http.ResponseWriter, _ *http.Request) {
				cfg := p.getConfiguration()
				switch mode {
				case "broker_disabled":
					cfg.EnablePlaneBroker = false
				case "persistence_disabled":
					cfg.EnableTokenPersistence = false
				case "issuer_changed":
					cfg.IssuerURL = "https://different.example"
				case "secret_changed":
					cfg.ClientSecret = "new-secret"
				case "native_changed":
					a.mu.Lock()
					a.users[r.Binding.MattermostUserID].AuthData = model.NewPointer("different")
					a.mu.Unlock()
				case "deactivated":
					a.mu.Lock()
					a.users[r.Binding.MattermostUserID].DeleteAt = 1
					a.mu.Unlock()
				}
				if mode != "login_disabled" {
					p.setConfiguration(cfg)
				}
				refreshResponse(w)
			})
			if mode == "login_disabled" {
				cfg := p.getConfiguration()
				cfg.Enable = false
				p.setConfiguration(cfg)
				p.clearOIDCProvider()
			}
			v, e := newTokenLifecycle(p).UserAccessToken(context.Background(), r.Binding)
			if mode == "login_disabled" {
				require.NoError(t, e)
				require.Equal(t, "access-new", v.Value)
			} else {
				require.Error(t, e)
				require.Empty(t, v.Value)
			}
		})
	}
}
func TestLifecycleEnvelopeMetadataAuthenticated(t *testing.T) {
	for _, field := range []string{"phase", "deadline", "started"} {
		t.Run(field, func(t *testing.T) {
			_, a, r, store, c := lifecycleFixture(t, func(w http.ResponseWriter, _ *http.Request) { refreshResponse(w) })
			c.AccessExpiresAt = time.Now().Add(time.Hour)
			require.NoError(t, store.Save(context.Background(), c))
			env, _, e := store.read(r.Binding)
			require.NoError(t, e)
			switch field {
			case "phase":
				env.Phase = "candidate"
			case "deadline":
				env.Deadline = time.Now().UnixNano()
			case "started":
				env.StartedAt = time.Now().UnixNano()
			}
			a.kv[credentialKey(r.Binding)], _ = json.Marshal(env)
			_, e = store.Load(context.Background(), r.Binding)
			require.Error(t, e)
		})
	}
}
func TestUserTokenCannotSerializeSecret(t *testing.T) {
	v := UserToken{Value: "secret-token", Generation: 4}
	raw, e := json.Marshal(v)
	require.NoError(t, e)
	require.NotContains(t, string(raw), v.Value)
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		require.NotContains(t, fmt.Sprintf(format, v), v.Value)
	}
}

func TestLifecycleLoginDisabledPreservesGateAndLoginDenial(t *testing.T) {
	for _, gate := range []string{"active", "frozen", "mismatch"} {
		t.Run(gate, func(t *testing.T) {
			p, _, r, _, _ := lifecycleFixture(t, func(w http.ResponseWriter, _ *http.Request) { refreshResponse(w) })
			cfg := p.getConfiguration()
			cfg.Enable = false
			if gate == "mismatch" {
				cfg.ClientID = "different-client"
			}
			p.setConfiguration(cfg)
			if gate == "frozen" {
				_, e := p.freezeIdentityGate()
				require.NoError(t, e)
			}
			_, e := p.currentLoginSnapshot(context.Background())
			require.Error(t, e)
			require.Error(t, p.assertLoginSnapshot(context.Background(), p.loginSnapshot))
			token, e := newTokenLifecycle(p).UserAccessToken(context.Background(), r.Binding)
			if gate == "active" {
				require.NoError(t, e)
				require.Equal(t, "access-new", token.Value)
			} else {
				require.Error(t, e)
				require.Empty(t, token.Value)
			}
		})
	}
}
func TestLifecycleAmbiguousCandidateOrReadyCAS(t *testing.T) {
	for _, phase := range []string{"candidate", "ready"} {
		for _, successor := range []bool{false, true} {
			t.Run(phase+fmt.Sprint(successor), func(t *testing.T) {
				p, a, r, store, c := lifecycleFixture(t, func(w http.ResponseWriter, _ *http.Request) { refreshResponse(w) })
				var trigger atomic.Bool
				a.beforeCAS = func(k string, old, next []byte) *model.AppError {
					if k != credentialKey(r.Binding) {
						return nil
					}
					var env credentialEnvelope
					_ = json.Unmarshal(next, &env)
					matches := (phase == "candidate" && env.Phase == "candidate") || (phase == "ready" && env.State == "ready" && env.Generation == 2)
					if matches && trigger.CompareAndSwap(false, true) {
						a.mu.Lock()
						a.kv[k] = bytes.Clone(next)
						a.mu.Unlock()
						if successor {
							c.AccessToken = "successor"
							c.AccessExpiresAt = time.Now().Add(time.Hour)
							require.NoError(t, store.Save(context.Background(), c))
						}
						return failAPI()
					}
					return nil
				}
				token, e := newTokenLifecycle(p).UserAccessToken(context.Background(), r.Binding)
				require.Error(t, e)
				require.Empty(t, token.Value)
				if successor {
					c, e := store.Load(context.Background(), r.Binding)
					require.NoError(t, e)
					require.Equal(t, "successor", c.AccessToken)
				} else {
					env, _, e := store.read(r.Binding)
					require.NoError(t, e)
					require.Equal(t, "invalidated", env.State)
				}
			})
		}
	}
}
func TestDeactivationCleanupRequiresCorroboratedRegistry(t *testing.T) {
	for _, mutation := range []string{"missing", "pending", "wrong_id", "conflicting_pair"} {
		t.Run(mutation, func(t *testing.T) {
			p, a, r, store, _ := lifecycleFixture(t, func(w http.ResponseWriter, _ *http.Request) { refreshResponse(w) })
			a.users[r.Binding.MattermostUserID].DeleteAt = 1
			rec, _, e := p.readIdentityRecord(identityUserPrefix + r.Binding.MattermostUserID)
			require.NoError(t, e)
			switch mutation {
			case "missing":
				delete(a.kv, identityUserPrefix+r.Binding.MattermostUserID)
			case "pending":
				rec.State = "pending"
				a.kv[identityUserPrefix+r.Binding.MattermostUserID], _ = json.Marshal(rec)
			case "wrong_id":
				rec.Binding.MattermostUserID = model.NewId()
				a.kv[identityUserPrefix+r.Binding.MattermostUserID], _ = json.Marshal(rec)
			case "conflicting_pair":
				rec.Revision++
				a.kv[pairKey(r.Binding)], _ = json.Marshal(rec)
			}
			_, e = p.cleanupBinding(r.Binding.MattermostUserID)
			require.Error(t, e)
			p.UserHasBeenDeactivated(nil, a.users[r.Binding.MattermostUserID])
			env, _, e := store.read(r.Binding)
			require.NoError(t, e)
			require.Equal(t, "ready", env.State)
			_, e = newTokenLifecycle(p).UserAccessToken(context.Background(), r.Binding)
			require.ErrorIs(t, e, ErrUserInactive)
		})
	}
}
func TestLifecycleDeactivationFencesLateRefreshOwner(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	p, a, r, store, _ := lifecycleFixture(t, func(w http.ResponseWriter, _ *http.Request) { close(entered); <-release; refreshResponse(w) })
	done := make(chan error, 1)
	go func() { _, e := newTokenLifecycle(p).UserAccessToken(context.Background(), r.Binding); done <- e }()
	<-entered
	a.mu.Lock()
	a.users[r.Binding.MattermostUserID].DeleteAt = 1
	u := copyUser(a.users[r.Binding.MattermostUserID])
	a.mu.Unlock()
	_, e := p.freezeIdentityGate()
	require.NoError(t, e)
	p.UserHasBeenDeactivated(nil, u)
	close(release)
	require.Error(t, <-done)
	env, _, e := store.read(r.Binding)
	require.NoError(t, e)
	require.Equal(t, "invalidated", env.State)
}
func TestLifecycleAssertGenerationAndKeyLoss(t *testing.T) {
	p, _, r, store, c := lifecycleFixture(t, func(w http.ResponseWriter, _ *http.Request) { refreshResponse(w) })
	c.AccessExpiresAt = time.Now().Add(time.Hour)
	require.NoError(t, store.Save(context.Background(), c))
	l := newTokenLifecycle(p)
	v, e := l.UserAccessToken(context.Background(), r.Binding)
	require.NoError(t, e)
	require.NoError(t, l.AssertGeneration(context.Background(), r.Binding, v.Generation))
	require.NoError(t, store.Invalidate(context.Background(), r.Binding))
	require.Error(t, l.AssertGeneration(context.Background(), r.Binding, v.Generation))
	require.NoError(t, store.Save(context.Background(), c))
	t.Setenv("MM_OIDC_CREDENTIAL_KEYS", "{}")
	_, e = l.UserAccessToken(context.Background(), r.Binding)
	require.ErrorIs(t, e, ErrReconnectRequired)
	require.NoError(t, l.Disconnect(context.Background(), r.Binding))
}

func TestCrashLeavesAbandonedRefreshState(t *testing.T) {
	for _, phase := range []string{"", "candidate"} {
		t.Run("phase_"+phase, func(t *testing.T) {
			var calls atomic.Int32
			p, a, r, store, c := lifecycleFixture(t, func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); refreshResponse(w) })
			env, _, e := store.read(r.Binding)
			require.NoError(t, e)
			env.State = "refreshing"
			env.Owner = "dead-node"
			env.Phase = phase
			env.StartedAt = time.Now().Add(-time.Second).UnixNano()
			env.Deadline = time.Now().Add(-time.Millisecond).UnixNano()
			if phase == "candidate" {
				env.Generation++
				c.AccessToken = "rotated-but-unacknowledged"
				c.RefreshToken = "rotated-refresh"
			}
			_, raw, e := store.sealTransition(c, env)
			require.NoError(t, e)
			a.kv[credentialKey(r.Binding)] = raw
			_, e = lifecycleOther(p, a).UserAccessToken(context.Background(), r.Binding)
			require.ErrorIs(t, e, ErrReconnectRequired)
			require.Zero(t, calls.Load())
			next, _, e := store.read(r.Binding)
			require.NoError(t, e)
			require.Equal(t, "invalidated", next.State)
			require.Equal(t, env.Generation+1, next.Generation)
			require.NoError(t, store.Save(context.Background(), c))
			next, _, e = store.read(r.Binding)
			require.NoError(t, e)
			require.Equal(t, env.Generation+2, next.Generation)
		})
	}
}
func TestDisconnectRevocationIsAfterFenceAndBestEffort(t *testing.T) {
	for _, mode := range []string{"failure", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			var store *CredentialStore
			var r ResolvedIdentity
			var calls atomic.Int32
			p, _, bound, s, _ := lifecycleFixture(t, func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				require.Equal(t, "/revoke", req.URL.Path)
				env, _, e := store.read(r.Binding)
				require.NoError(t, e)
				require.Equal(t, "invalidated", env.State)
				if mode == "timeout" {
					<-release
					return
				}
				w.WriteHeader(503)
			})
			store = s
			r = bound
			ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
			defer cancel()
			require.NoError(t, newTokenLifecycle(p).Disconnect(ctx, r.Binding))
			require.Equal(t, int32(1), calls.Load())
			env, _, e := store.read(r.Binding)
			require.NoError(t, e)
			require.Equal(t, "invalidated", env.State)
		})
	}
}
func TestAdminRevokeRejectsUnboundedOrAmbiguousSelector(t *testing.T) {
	for _, body := range []string{`{}`, `{"user_id":"not-a-uuid"}`, `{"user_id":"` + model.NewId() + `","extra":1}`, `{} {}`, strings.Repeat("x", 1025)} {
		t.Run(fmt.Sprint(len(body))+body[:1], func(t *testing.T) {
			p, a, r, store, _ := lifecycleFixture(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
			a.users[r.Binding.MattermostUserID].Roles = "system_admin"
			sess := &model.Session{Id: model.NewId(), UserId: r.Binding.MattermostUserID, Props: map[string]string{"csrf": "csrf"}}
			p.SetAPI(&lifecycleSessionAPI{a, sess})
			p.initRouter()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/plane/revoke", strings.NewReader(body))
			req.Header.Set("Mattermost-User-Id", sess.UserId)
			req.Header.Set("X-CSRF-Token", "csrf")
			out := httptest.NewRecorder()
			p.ServeHTTP(&plugin.Context{SessionId: sess.Id}, out, req)
			require.Equal(t, 400, out.Code)
			env, _, e := store.read(r.Binding)
			require.NoError(t, e)
			require.Equal(t, "ready", env.State)
		})
	}
}
