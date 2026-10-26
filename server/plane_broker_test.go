package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type brokerFixtureState struct {
	p       *Plugin
	a       *identityAPI
	users   []ResolvedIdentity
	calls   atomic.Int32
	claims  func(map[string]any)
	output  func(map[string]any)
	after   func()
	status  int
	refresh http.HandlerFunc
}

func brokerFixture(t *testing.T) *brokerFixtureState {
	t.Helper()
	brokerKeys(t)
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, e)
	f := &brokerFixtureState{}
	var issuer string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys"})
		case "/keys":
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "alg": "RS256", "kid": "test", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		case "/token":
			f.calls.Add(1)
			require.NoError(t, r.ParseForm())
			if r.Form.Get("grant_type") == "refresh_token" && f.refresh != nil {
				f.refresh(w, r)
				return
			}
			require.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", r.Form.Get("grant_type"))
			require.Equal(t, "mattermost-oidc", r.Form.Get("client_id"))
			require.Equal(t, "plane-api", r.Form.Get("audience"))
			require.Equal(t, "urn:ietf:params:oauth:token-type:access_token", r.Form.Get("subject_token_type"))
			require.Empty(t, r.Form.Get("requested_subject"))
			if f.status != 0 {
				w.WriteHeader(f.status)
				return
			}
			now := time.Now().Unix()
			claims := map[string]any{"iss": issuer, "sub": r.Form.Get("subject_token"), "aud": "plane-api", "azp": "mattermost-oidc", "typ": "Bearer", "scope": r.Form.Get("scope"), "iat": now, "exp": now + 180}
			if f.claims != nil {
				f.claims(claims)
			}
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test"}`))
			raw, _ := json.Marshal(claims)
			input := header + "." + base64.RawURLEncoding.EncodeToString(raw)
			hash := sha256.Sum256([]byte(input))
			sig, e := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
			require.NoError(t, e)
			token := input + "." + base64.RawURLEncoding.EncodeToString(sig)
			if f.after != nil {
				f.after()
			}
			output := map[string]any{"access_token": token, "expires_in": 180, "token_type": "Bearer", "issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "refresh_token": "NEVER-RELEASE-REFRESH", "id_token": "NEVER-RELEASE-ID"}
			if f.output != nil {
				f.output(output)
			}
			_ = json.NewEncoder(w).Encode(output)
		default:
			w.WriteHeader(404)
		}
	}))
	issuer = srv.URL
	t.Cleanup(srv.Close)
	p, a, _ := fixtureIdentity(t)
	f.p = p
	f.a = a
	p.discoveryClient = srv.Client()
	cfg := p.getConfiguration()
	cfg.IssuerURL = issuer
	cfg.ClientID = "mattermost-oidc"
	cfg.EnablePlaneBroker = true
	cfg.EnableTokenPersistence = true
	p.setConfiguration(cfg)
	fp := identityFingerprint(issuer, cfg.ClientID)
	a.kv[identityGateKey], _ = json.Marshal(identityGate{Version: 1, Status: "active", Epoch: 2, Issuer: issuer, ClientID: cfg.ClientID, IdentityFingerprint: fp})
	s := &LoginSnapshot{IdentityFingerprint: fp, GateEpoch: 2, configuration: *cfg}
	p.loginSnapshot = s
	p.initRouter()
	credentialKeys(t, "current", map[string]string{"current": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))})
	for _, sub := range []string{"alice-sub", "bob-sub"} {
		r, _, e := p.resolveVerifiedLogin(context.Background(), s, VerifiedLoginIdentity{issuer, sub}, &OIDCUserInfo{Subject: sub, Email: sub + "@example.com", Username: sub})
		require.NoError(t, e)
		f.users = append(f.users, r)
		require.NoError(t, newCredentialStore(p).Save(context.Background(), StoredCredentials{Binding: r.Binding, AccessToken: sub, RefreshToken: "refresh", AccessExpiresAt: time.Now().Add(time.Hour), GateEpoch: r.GateEpoch, BindingRevision: r.BindingRevision}))
	}
	return f
}
func (f *brokerFixtureState) body(user int, scope string) string {
	return fmt.Sprintf(`{"mm_user_id":%q,"audience":"plane-api","scope":%q,"request_id":"test-1"}`, f.users[user].Binding.MattermostUserID, scope)
}
func TestBrokerNeverReturnsRefreshOrIDToken(t *testing.T) {
	f := brokerFixture(t)
	for i := range 2 {
		w := serveBroker(f.p, signedBrokerRequest(f.body(i, "plane.read"), 0))
		require.Equal(t, 200, w.Code, w.Body.String())
		var out map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
		require.Len(t, out, 2)
		require.NotContains(t, w.Body.String(), "NEVER-RELEASE")
		raw, e := base64.RawURLEncoding.DecodeString(strings.Split(out["access_token"].(string), ".")[1])
		require.NoError(t, e)
		var claims map[string]any
		require.NoError(t, json.Unmarshal(raw, &claims))
		require.Equal(t, f.users[i].Binding.Subject, claims["sub"])
		require.Equal(t, claims["exp"], out["expires_at"])
	}
	require.Equal(t, int32(2), f.calls.Load())
}
func TestBrokerScopesAndAudience(t *testing.T) {
	f := brokerFixture(t)
	for _, scope := range []string{"plane.write", "plane.read plane.write extra", "openid plane.read", "plane.read plane.read"} {
		require.Equal(t, 403, serveBroker(f.p, signedBrokerRequest(f.body(0, scope), 0)).Code)
	}
	require.Equal(t, 403, serveBroker(f.p, signedBrokerRequest(strings.ReplaceAll(f.body(0, "plane.read"), "plane-api", "other"), 0)).Code)
	require.Zero(t, f.calls.Load())
	require.Equal(t, 200, serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read plane.write"), 0)).Code)
}
func TestBrokerDisabledAfterWarmCache(t *testing.T) {
	f := brokerFixture(t)
	require.Equal(t, 200, serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read"), 0)).Code)
	cfg := f.p.getConfiguration()
	cfg.EnablePlaneBroker = false
	f.p.setConfiguration(cfg)
	require.Equal(t, 503, serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read"), 0)).Code)
	require.Equal(t, int32(1), f.calls.Load())
}
func TestBrokerRejectsSignedTokenProfile(t *testing.T) {
	for _, name := range []string{"iss", "sub", "aud", "azp", "typ", "scope", "iat", "exp", "nbf", "lifetime", "fractional"} {
		t.Run(name, func(t *testing.T) {
			f := brokerFixture(t)
			f.claims = func(c map[string]any) {
				switch name {
				case "iat":
					delete(c, "iat")
				case "exp":
					c["exp"] = time.Now().Unix() + 30
				case "nbf":
					c["nbf"] = time.Now().Unix() + 31
				case "lifetime":
					c["exp"] = time.Now().Unix() + 301
				case "fractional":
					c["iat"] = float64(time.Now().Unix()) + 0.5
				default:
					c[name] = "wrong"
				}
			}
			require.Equal(t, 503, serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read"), 0)).Code)
		})
	}
}
func TestBrokerFinalAuthority(t *testing.T) {
	for _, change := range []string{"disable-reenable", "disconnect", "native-auth", "inactive"} {
		t.Run(change, func(t *testing.T) {
			f := brokerFixture(t)
			f.after = func() {
				switch change {
				case "disable-reenable":
					cfg := f.p.getConfiguration()
					off := cfg.Clone()
					off.EnablePlaneBroker = false
					f.p.setConfiguration(off)
					f.p.setConfiguration(cfg)
				case "disconnect":
					require.NoError(t, newTokenLifecycle(f.p).Disconnect(context.Background(), f.users[0].Binding))
				case "native-auth":
					f.a.mu.Lock()
					*f.a.users[f.users[0].Binding.MattermostUserID].AuthData = "wrong"
					f.a.mu.Unlock()
				case "inactive":
					f.a.mu.Lock()
					f.a.users[f.users[0].Binding.MattermostUserID].DeleteAt = 1
					f.a.mu.Unlock()
				}
			}
			require.NotEqual(t, 200, serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read"), 0)).Code)
		})
	}
}
func TestBrokerStrictJSON(t *testing.T) {
	f := brokerFixture(t)
	body := f.body(0, "plane.read")
	for _, bad := range []string{body + `{}`, strings.Replace(body, `"scope":`, `"unknown":1,"scope":`, 1), strings.Replace(body, `"scope":`, `"scope":"plane.read","scope":`, 1), strings.Replace(body, `"test-1"`, `"bad\nlog"`, 1), strings.Repeat(" ", 4097)} {
		w := serveBroker(f.p, signedBrokerRequest(bad, 0))
		require.Equal(t, 400, w.Code)
	}
	require.Zero(t, f.calls.Load())
}
func TestBrokerLoginSwitchIndependence(t *testing.T) {
	f := brokerFixture(t)
	cfg := f.p.getConfiguration()
	cfg.Enable = false
	f.p.setConfiguration(cfg)
	require.Equal(t, 200, serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read"), 0)).Code)
	for _, path := range []string{"/oauth2/connect", "/oauth2/callback"} {
		w := serveBroker(f.p, httptest.NewRequest("GET", path, nil))
		require.Equal(t, 400, w.Code)
	}
	f = brokerFixture(t)
	cfg = f.p.getConfiguration()
	cfg.Enable = true
	cfg.EnablePlaneBroker = false
	f.p.setConfiguration(cfg)
	w := serveBroker(f.p, httptest.NewRequest("GET", "/api/v1/config", nil))
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), `"enable":true`)
	require.NoError(t, cfg.IsValid())
	f.p.loginSnapshot.oauth.Endpoint.AuthURL = cfg.IssuerURL + "/auth"
	f.p.oauth2Config = &f.p.loginSnapshot.oauth
	w = serveBroker(f.p, httptest.NewRequest("GET", "/oauth2/connect", nil))
	require.Equal(t, 302, w.Code)
	require.True(t, strings.HasPrefix(w.Header().Get("Location"), cfg.IssuerURL+"/auth?"))
}
func TestBrokerProviderFailureAndCancelledDeadline(t *testing.T) {
	f := brokerFixture(t)
	f.status = 500
	require.Equal(t, 503, serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read"), 0)).Code)
	f.status = 0
	r := signedBrokerRequest(f.body(0, "plane.read"), 0)
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	w := serveBroker(f.p, r.WithContext(ctx))
	require.Equal(t, 503, w.Code)
	require.Equal(t, int32(1), f.calls.Load())
}
func TestBrokerWrongNativeBindingNeverExchanges(t *testing.T) {
	f := brokerFixture(t)
	f.a.mu.Lock()
	*f.a.users[f.users[0].Binding.MattermostUserID].AuthData = "wrong"
	f.a.mu.Unlock()
	require.Equal(t, 403, serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read"), 0)).Code)
	require.Zero(t, f.calls.Load())
}

type brokerRoundTripper func(*http.Request) (*http.Response, error)

func (fn brokerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }
func TestBrokerHTTPBudgets(t *testing.T) {
	f := brokerFixture(t)
	base := f.p.discoveryClient.Transport
	var deadlines []time.Duration
	f.p.discoveryClient.Transport = brokerRoundTripper(func(r *http.Request) (*http.Response, error) {
		d, ok := r.Context().Deadline()
		require.True(t, ok)
		deadlines = append(deadlines, time.Until(d))
		return base.RoundTrip(r)
	})
	require.Equal(t, 200, serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read"), 0)).Code)
	require.Len(t, deadlines, 3)
	for _, d := range deadlines {
		require.LessOrEqual(t, d, 5*time.Second)
	}
	p, _, bound, _, _ := lifecycleFixture(t, func(w http.ResponseWriter, r *http.Request) { refreshResponse(w) })
	base = p.discoveryClient.Transport
	deadlines = nil
	p.discoveryClient.Transport = brokerRoundTripper(func(r *http.Request) (*http.Response, error) {
		d, ok := r.Context().Deadline()
		require.True(t, ok)
		deadlines = append(deadlines, time.Until(d))
		return base.RoundTrip(r)
	})
	ctx := context.WithValue(context.Background(), brokerHTTPBudgetKey{}, 5*time.Second)
	_, err := newTokenLifecycle(p).UserAccessToken(ctx, bound.Binding)
	require.NoError(t, err)
	require.Len(t, deadlines, 2)
	for _, d := range deadlines {
		require.LessOrEqual(t, d, 5*time.Second)
	}
}
func TestBrokerHTTPStallHonorsFiveSeconds(t *testing.T) {
	f := brokerFixture(t)
	f.p.discoveryClient.Transport = brokerRoundTripper(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	started := time.Now()
	w := serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read"), 0))
	require.Equal(t, 503, w.Code)
	require.Less(t, time.Since(started), 6*time.Second)
	require.Greater(t, time.Since(started), 4*time.Second)
	require.Zero(t, f.calls.Load())
}
func TestBrokerWholeCallHonorsEarlierDeadline(t *testing.T) {
	f := brokerFixture(t)
	f.p.discoveryClient.Transport = brokerRoundTripper(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	r := signedBrokerRequest(f.body(0, "plane.read"), 0)
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	w := serveBroker(f.p, r.WithContext(ctx))
	require.Equal(t, 503, w.Code)
	require.Less(t, time.Since(started), time.Second)
	require.Zero(t, f.calls.Load())
}
func TestBrokerNoKeyOrStoreFailureNeverExchanges(t *testing.T) {
	for _, problem := range []string{"hmac", "aes", "aes-malformed", "aes-active-missing", "kv", "signature"} {
		t.Run(problem, func(t *testing.T) {
			f := brokerFixture(t)
			r := signedBrokerRequest(f.body(0, "plane.read"), 0)
			want := 503
			switch problem {
			case "hmac":
				t.Setenv("MM_PLANE_BROKER_HMAC_KEYS", "")
			case "aes":
				t.Setenv("MM_OIDC_CREDENTIAL_KEYS", "")
			case "aes-malformed":
				t.Setenv("MM_OIDC_CREDENTIAL_KEYS", `{malformed`)
			case "aes-active-missing":
				t.Setenv("MM_OIDC_CREDENTIAL_ACTIVE_KEY_ID", "absent")
			case "kv":
				f.a.readFail = true
			case "signature":
				r.Header.Del("X-Plane-Signature")
				want = 401
			}
			w := serveBroker(f.p, r)
			require.Equal(t, want, w.Code)
			require.Zero(t, f.calls.Load())
			require.NotContains(t, w.Body.String(), "access_token")
		})
	}
}
func TestBrokerWholeCallTenSecondBudget(t *testing.T) {
	f := brokerFixture(t)
	base := f.p.discoveryClient.Transport
	var calls int
	f.p.discoveryClient.Transport = brokerRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		timer := time.NewTimer(4 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			return base.RoundTrip(r)
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	})
	started := time.Now()
	w := serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read"), 0))
	require.Equal(t, 503, w.Code)
	require.Equal(t, 3, calls)
	require.Greater(t, time.Since(started), 9*time.Second)
	require.Less(t, time.Since(started), 11*time.Second)
}
func TestBrokerRejectsMalformedProviderOutput(t *testing.T) {
	for _, name := range []string{"signature", "algorithm", "size", "type", "issued_type", "metadata", "fractional_expiry"} {
		t.Run(name, func(t *testing.T) {
			f := brokerFixture(t)
			f.output = func(out map[string]any) {
				switch name {
				case "signature":
					token := out["access_token"].(string)
					parts := strings.Split(token, ".")
					sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
					sig[0] ^= 1
					out["access_token"] = parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
				case "algorithm":
					parts := strings.Split(out["access_token"].(string), ".")
					out["access_token"] = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"test"}`)) + "." + parts[1] + "." + parts[2]
				case "size":
					out["access_token"] = strings.Repeat("a", 16385)
				case "type":
					out["token_type"] = "ID"
				case "issued_type":
					out["issued_token_type"] = "urn:ietf:params:oauth:token-type:id_token"
				case "metadata":
					out["expires_in"] = 10
				case "fractional_expiry":
					out["expires_in"] = 180.5
				}
			}
			w := serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read"), 0))
			require.Equal(t, 503, w.Code)
			require.NotContains(t, w.Body.String(), "access_token")
		})
	}
}

func TestBrokerCredentialRingLossAfterNetwork(t *testing.T) {
	for _, mode := range []string{"missing", "malformed", "active-missing"} {
		t.Run(mode, func(t *testing.T) {
			f := brokerFixture(t)
			f.after = func() {
				switch mode {
				case "missing":
					t.Setenv("MM_OIDC_CREDENTIAL_KEYS", "")
				case "malformed":
					t.Setenv("MM_OIDC_CREDENTIAL_KEYS", `{malformed`)
				case "active-missing":
					t.Setenv("MM_OIDC_CREDENTIAL_ACTIVE_KEY_ID", "absent")
				}
			}
			w := serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read"), 0))
			require.Equal(t, 503, w.Code)
			require.JSONEq(t, `{"error":"unavailable","request_id":"test-1"}`, w.Body.String())
			require.Equal(t, int32(1), f.calls.Load())
			require.NotContains(t, w.Body.String(), "access_token")
		})
	}
}
func TestBrokerCredentialRingLossDuringLifecycleError(t *testing.T) {
	f := brokerFixture(t)
	store := newCredentialStore(f.p)
	c, e := store.Load(context.Background(), f.users[0].Binding)
	require.NoError(t, e)
	c.AccessExpiresAt = time.Now().Add(-time.Minute)
	require.NoError(t, store.Save(context.Background(), c))
	f.refresh = func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "refresh", r.Form.Get("refresh_token"))
		t.Setenv("MM_OIDC_CREDENTIAL_KEYS", "")
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}
	w := serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read"), 0))
	require.Equal(t, 503, w.Code)
	require.JSONEq(t, `{"error":"unavailable","request_id":"test-1"}`, w.Body.String())
	require.Equal(t, int32(1), f.calls.Load())
	require.NotContains(t, w.Body.String(), "access_token")
}
func TestBrokerCredentialGenerationFailuresRemainReconnect(t *testing.T) {
	for _, mode := range []string{"missing", "invalidated", "ambiguous", "historical-key", "tampered"} {
		t.Run(mode, func(t *testing.T) {
			f := brokerFixture(t)
			b := f.users[0].Binding
			store := newCredentialStore(f.p)
			switch mode {
			case "missing":
				f.a.mu.Lock()
				delete(f.a.kv, credentialKey(b))
				f.a.mu.Unlock()
			case "invalidated":
				require.NoError(t, store.Invalidate(context.Background(), b))
			case "ambiguous":
				c, e := store.Load(context.Background(), b)
				require.NoError(t, e)
				env, _, e := store.read(b)
				require.NoError(t, e)
				env.State = "refreshing"
				env.Phase = "candidate"
				env.Deadline = time.Now().Add(-time.Second).UnixNano()
				env.StartedAt = env.Deadline - int64(time.Second)
				_, raw, e := store.sealTransition(c, env)
				require.NoError(t, e)
				f.a.mu.Lock()
				f.a.kv[credentialKey(b)] = raw
				f.a.mu.Unlock()
			case "historical-key":
				credentialKeys(t, "new", map[string]string{"new": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))})
			case "tampered":
				env, _, e := store.read(b)
				require.NoError(t, e)
				env.Ciphertext[0] ^= 1
				raw, e := json.Marshal(env)
				require.NoError(t, e)
				f.a.mu.Lock()
				f.a.kv[credentialKey(b)] = raw
				f.a.mu.Unlock()
			}
			w := serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read"), 0))
			require.Equal(t, 409, w.Code)
			require.JSONEq(t, `{"error":"reconnect_required","request_id":"test-1"}`, w.Body.String())
			require.Zero(t, f.calls.Load())
			require.NotContains(t, w.Body.String(), "access_token")
		})
	}
}
