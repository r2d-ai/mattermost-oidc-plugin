package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin/plugintest"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

const (
	testSubject = "idp-subject"
	testUserID  = "aaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// loginEnv is a plugin wired to an in-memory KV store and a fake identity provider.
type loginEnv struct {
	t              *testing.T
	client         *http.Client
	p              *Plugin
	user           *model.User
	mu             sync.Mutex
	kv             map[string][]byte
	ttl            map[string]int64
	nonce          string
	sessions       int
	api            *plugintest.API
	refreshToken   string
	idToken        string
	onSession      func()
	onCAS          func(string, []byte, []byte) *model.AppError
	revoked        []string
	activeSessions map[string]bool
}

func newLoginEnv(t *testing.T, siteURL string) *loginEnv {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}

	e := &loginEnv{t: t, kv: map[string][]byte{}, ttl: map[string]int64{}, refreshToken: "desktop-refresh-secret", activeSessions: map[string]bool{"preexisting-session": true}}
	var issuer string
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks"})
		case "/token":
			e.mu.Lock()
			nonce := e.nonce
			e.mu.Unlock()
			claims, _ := json.Marshal(map[string]any{"iss": issuer, "sub": testSubject, "aud": "mattermost", "nonce": nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "email": "alice@example.test"})
			jws, _ := signer.Sign(claims)
			raw, _ := jws.CompactSerialize()
			e.mu.Lock()
			e.idToken = raw
			refresh := e.refreshToken
			e.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "desktop-access-secret", "refresh_token": refresh, "expires_in": 600, "refresh_expires_in": 1800, "token_type": "Bearer", "id_token": raw})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.Close)
	issuer = idp.URL
	e.client = idp.Client()
	provider, err := oidc.NewProvider(oidc.ClientContext(context.Background(), idp.Client()), issuer)
	if err != nil {
		t.Fatal(err)
	}

	e.user = &model.User{Id: testUserID, Username: "alice", Email: "alice@example.test", AuthService: AuthService, AuthData: model.NewPointer(testSubject)}
	binding := IdentityBinding{Issuer: issuer, Subject: testSubject, MattermostUserID: testUserID}
	identity := identityRecord{Version: 1, Binding: binding, Revision: 1, TransactionID: "reviewed-fixture", State: "committed", Mode: LegacyRaw, AuthService: AuthService, AuthData: testSubject}
	e.kv[pairKey(binding)], _ = json.Marshal(identity)
	e.kv[identityUserPrefix+testUserID], _ = json.Marshal(identity)
	e.kv[identityGateKey], _ = json.Marshal(identityGate{Version: 1, Status: "active", Epoch: 1, Issuer: issuer, ClientID: "mattermost", IdentityFingerprint: identityFingerprint(issuer, "mattermost")})

	api := &plugintest.API{}
	e.api = api
	cfg := &model.Config{}
	cfg.SetDefaults()
	cfg.ServiceSettings.SiteURL = model.NewPointer(siteURL)
	api.On("GetConfig").Return(cfg)
	api.On("KVGet", mock.Anything).Return(func(k string) ([]byte, *model.AppError) {
		e.mu.Lock()
		defer e.mu.Unlock()
		return bytes.Clone(e.kv[k]), nil
	})
	api.On("KVSetWithExpiry", mock.Anything, mock.Anything, mock.Anything).Return(func(k string, v []byte, ttl int64) *model.AppError {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.kv[k], e.ttl[k] = bytes.Clone(v), ttl
		return nil
	})
	api.On("KVCompareAndSet", mock.Anything, mock.Anything, mock.Anything).Return(func(k string, old, next []byte) (bool, *model.AppError) {
		if e.onCAS != nil {
			if err := e.onCAS(k, old, next); err != nil {
				return false, err
			}
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		if !bytes.Equal(e.kv[k], old) {
			return false, nil
		}
		e.kv[k] = bytes.Clone(next)
		return true, nil
	})
	api.On("KVCompareAndDelete", mock.Anything, mock.Anything).Return(func(k string, old []byte) (bool, *model.AppError) {
		e.mu.Lock()
		defer e.mu.Unlock()
		if cur, ok := e.kv[k]; !ok || !bytes.Equal(cur, old) {
			return false, nil
		}
		delete(e.kv, k)
		return true, nil
	})
	api.On("GetUser", testUserID).Return(func(string) (*model.User, *model.AppError) {
		e.mu.Lock()
		defer e.mu.Unlock()
		return copyUser(e.user), nil
	})
	api.On("CreateSession", mock.Anything).Return(func(s *model.Session) (*model.Session, *model.AppError) {
		e.mu.Lock()
		e.sessions++
		s.Id = model.NewId()
		s.Token = model.NewId()
		e.activeSessions[s.Id] = true
		e.mu.Unlock()
		if e.onSession != nil {
			e.onSession()
		}
		return s, nil
	})

	api.On("RevokeSession", mock.Anything).Return(func(id string) *model.AppError {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.revoked = append(e.revoked, id)
		delete(e.activeSessions, id)
		return nil
	})

	e.p = &Plugin{
		encryptionKey: "test-key",
		oidcProvider:  provider,
		oidcVerifier:  oidc.NewVerifier(issuer, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, &oidc.Config{ClientID: "mattermost"}),
		oauth2Config: &oauth2.Config{
			ClientID: "mattermost", ClientSecret: "secret",
			Endpoint:    oauth2.Endpoint{AuthURL: issuer + "/authorize", TokenURL: issuer + "/token"},
			RedirectURL: siteURL + "/plugins/" + PluginID + "/oauth2/callback",
		},
	}
	e.p.SetAPI(quietAPI{api})
	e.p.setConfiguration(&Configuration{Enable: true, IssuerURL: issuer, ClientID: "mattermost", ClientSecret: "secret", Scopes: "openid", EmailClaim: "email", UsernameClaim: "preferred_username"})
	e.p.discoveryClient = idp.Client()
	e.p.loginSnapshot = makeLoginSnapshot(e.p.getConfiguration(), provider, e.p.oidcVerifier, e.p.oauth2Config, e.p.encryptionKey)
	e.p.initRouter()
	return e
}

func (e *loginEnv) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.p.router.ServeHTTP(rec, req.WithContext(context.WithValue(req.Context(), oauth2.HTTPClient, e.client)))
	return rec
}

func (e *loginEnv) get(path string) *httptest.ResponseRecorder {
	return e.do(httptest.NewRequest(http.MethodGet, path, nil))
}

// keys returns the stored KV keys with the given prefix.
func (e *loginEnv) keys(prefix string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for k := range e.kv {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out
}

func (e *loginEnv) sessionCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sessions
}

// authorize follows a connect response to the IdP and returns the callback path the IdP would redirect to.
func (e *loginEnv) authorize(authURL string) string {
	u, err := url.Parse(authURL)
	if err != nil {
		e.t.Fatal(err)
	}
	e.mu.Lock()
	e.nonce = u.Query().Get("nonce")
	e.mu.Unlock()
	return "/oauth2/callback?code=idp-code&state=" + url.QueryEscape(u.Query().Get("state"))
}
