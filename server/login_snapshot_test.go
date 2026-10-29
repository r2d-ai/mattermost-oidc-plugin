package main

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSecretRotationOnlyInvalidatesCallback(t *testing.T) {
	var up atomic.Bool
	var hits atomic.Int32
	up.Store(true)
	p, _ := newDiscoveryTestPlugin(t, &up, &hits, nil)
	require.NoError(t, p.initOIDCProvider())
	first := p.loginSnapshot
	cfg := p.getConfiguration()
	cfg.ClientSecret = "rotated"
	p.setConfiguration(cfg)
	require.NoError(t, p.initOIDCProvider())
	require.Equal(t, first.IdentityFingerprint, p.loginSnapshot.IdentityFingerprint)
	require.NotEqual(t, first.CallbackFingerprint, p.loginSnapshot.CallbackFingerprint)
}
func TestCallbackSnapshotCannotMixProviders(t *testing.T) {
	var up atomic.Bool
	var hits atomic.Int32
	up.Store(true)
	var p *Plugin
	p, _ = newDiscoveryTestPlugin(t, &up, &hits, func() {
		if p != nil {
			cfg := p.getConfiguration()
			cfg.ClientID = "new"
			p.setConfiguration(cfg)
		}
	})
	require.Error(t, p.initOIDCProvider())
	require.Nil(t, p.loginSnapshot)
}
func TestCallbackPolicyAndOptionalConfigFingerprints(t *testing.T) {
	var up atomic.Bool
	var hits atomic.Int32
	up.Store(true)
	p, _ := newDiscoveryTestPlugin(t, &up, &hits, nil)
	require.NoError(t, p.initOIDCProvider())
	first := p.loginSnapshot
	cfg := p.getConfiguration()
	cfg.ButtonText = "New label"
	cfg.AutoLinkByEmail = true
	p.setConfiguration(cfg)
	require.NoError(t, p.initOIDCProvider())
	require.Equal(t, first.CallbackFingerprint, p.loginSnapshot.CallbackFingerprint)
	cfg.EmailClaim = "different"
	p.setConfiguration(cfg)
	require.NoError(t, p.initOIDCProvider())
	require.Equal(t, first.IdentityFingerprint, p.loginSnapshot.IdentityFingerprint)
	require.NotEqual(t, first.CallbackFingerprint, p.loginSnapshot.CallbackFingerprint)
}
func TestCallbackGateEpochChanged(t *testing.T) {
	p, a, s := fixtureIdentity(t)
	p.loginSnapshot = s
	_, err := p.currentLoginSnapshot(context.Background())
	require.NoError(t, err)
	_, err = p.freezeIdentityGate()
	require.NoError(t, err)
	require.Error(t, p.assertLoginSnapshot(context.Background(), s))
	var g identityGate
	require.NoError(t, json.Unmarshal(a.kv[identityGateKey], &g))
	g.Status = "active"
	g.Epoch++
	a.kv[identityGateKey], _ = json.Marshal(g)
	require.Error(t, p.assertLoginSnapshot(context.Background(), s))
}
func TestStateKeyInitializationConvergesAcrossNodes(t *testing.T) {
	a := newIdentityAPI()
	p, q := &Plugin{}, &Plugin{}
	p.SetAPI(a)
	q.SetAPI(a)
	var wg sync.WaitGroup
	for _, node := range []*Plugin{p, q} {
		wg.Add(1)
		go func(node *Plugin) { defer wg.Done(); require.NoError(t, node.initializeStateKey()) }(node)
	}
	wg.Wait()
	require.NotEmpty(t, p.getEncryptionKey())
	require.Equal(t, p.getEncryptionKey(), q.getEncryptionKey())
	require.Equal(t, p.getEncryptionKey(), string(a.kv[kvEncryptionKey]))
	require.NoError(t, p.initializeStateKey())
}
func TestCallbackVerifiedIssuerAuthority(t *testing.T) {
	p, _, s := fixtureIdentity(t)
	for _, id := range []VerifiedLoginIdentity{{"https://other.example", "s"}, {"https://a.example", "other"}} {
		_, _, e := p.resolveVerifiedLogin(context.Background(), s, id, &OIDCUserInfo{Subject: "s", Email: "test@example.com", Username: "tester"})
		require.Error(t, e)
	}
}
func TestCallbackFingerprintEveryPolicy(t *testing.T) {
	var up atomic.Bool
	var hits atomic.Int32
	up.Store(true)
	p, _ := newDiscoveryTestPlugin(t, &up, &hits, nil)
	require.NoError(t, p.initOIDCProvider())
	base := p.loginSnapshot
	cases := map[string]func(*Configuration){"secret": func(c *Configuration) { c.ClientSecret = "new" }, "username": func(c *Configuration) { c.UsernameClaim = "new" }, "email": func(c *Configuration) { c.EmailClaim = "new" }, "first": func(c *Configuration) { c.FirstNameClaim = "new" }, "last": func(c *Configuration) { c.LastNameClaim = "new" }, "position": func(c *Configuration) { c.PositionClaim = "new" }, "verified": func(c *Configuration) { c.EmailVerifiedClaim = "new" }, "require": func(c *Configuration) { c.RequireEmailVerified = true }, "create": func(c *Configuration) { c.AutoCreateAccounts = true }, "team": func(c *Configuration) { c.DefaultTeam = "new" }, "scopes": func(c *Configuration) { c.Scopes = "openid profile" }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base.configuration
			change(&cfg)
			oc := base.oauth
			oc.Scopes = cfg.GetScopes()
			next := makeLoginSnapshot(&cfg, base.provider, base.verifier, &oc, p.getEncryptionKey())
			require.Equal(t, base.IdentityFingerprint, next.IdentityFingerprint)
			require.NotEqual(t, base.CallbackFingerprint, next.CallbackFingerprint)
		})
	}
	oc := base.oauth
	oc.RedirectURL += "changed"
	next := makeLoginSnapshot(&base.configuration, base.provider, base.verifier, &oc, p.getEncryptionKey())
	require.NotEqual(t, base.CallbackFingerprint, next.CallbackFingerprint)
	oc = base.oauth
	oc.Scopes = []string{"openid", "openid"}
	next = makeLoginSnapshot(&base.configuration, base.provider, base.verifier, &oc, p.getEncryptionKey())
	require.Equal(t, base.CallbackFingerprint, next.CallbackFingerprint)
}
func TestStateKeyDefersEarlyPublication(t *testing.T) {
	var up atomic.Bool
	var hits atomic.Int32
	up.Store(true)
	p, _ := newDiscoveryTestPlugin(t, &up, &hits, nil)
	p.encryptionKey = ""
	require.NoError(t, p.initOIDCProvider())
	require.Nil(t, p.loginSnapshot)
	require.Zero(t, hits.Load())
	p.encryptionKey = "winner"
	require.NoError(t, p.initOIDCProvider())
	require.NotNil(t, p.loginSnapshot)
	require.Equal(t, int32(1), hits.Load())
}

func TestCallbackSameRevisionDiscoveryCannotPublishOlderResult(t *testing.T) {
	firstStarted, secondStarted := make(chan struct{}), make(chan struct{})
	releaseFirst, releaseSecond := make(chan struct{}), make(chan struct{})
	var firstOnce, secondOnce sync.Once
	unblockFirst := func() { firstOnce.Do(func() { close(releaseFirst) }) }
	unblockSecond := func() { secondOnce.Do(func() { close(releaseSecond) }) }
	var requests atomic.Int32
	var issuer string
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suffix := "newer"
		if requests.Add(1) == 1 {
			suffix = "older"
			close(firstStarted)
			<-releaseFirst
		} else {
			close(secondStarted)
			<-releaseSecond
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "authorization_endpoint": issuer + "/auth/" + suffix, "token_endpoint": issuer + "/token/" + suffix, "userinfo_endpoint": issuer + "/userinfo/" + suffix, "jwks_uri": issuer + "/keys/" + suffix})
	}))
	t.Cleanup(idp.Close)
	t.Cleanup(func() { unblockFirst(); unblockSecond() })
	issuer = idp.URL
	p, a, _ := fixtureIdentity(t)
	cfg := p.getConfiguration()
	cfg.IssuerURL = issuer
	p.setConfiguration(cfg)
	a.kv[identityGateKey], _ = json.Marshal(identityGate{Version: 1, Status: "active", Epoch: 2, Issuer: issuer, ClientID: cfg.ClientID, IdentityFingerprint: identityFingerprint(issuer, cfg.ClientID)})
	p.discoveryClient = idp.Client()
	p.clearOIDCProvider()
	oldResult := make(chan error, 1)
	go func() { oldResult <- p.initOIDCProvider() }()
	select {
	case <-firstStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("first discovery did not start")
	}
	// Simulate direct lifecycle discovery overlapping the login retry entrypoint.
	retryFinished := make(chan struct{})
	go func() { p.retryOIDCProvider(); close(retryFinished) }()
	select {
	case <-secondStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("second discovery did not start")
	}
	unblockSecond()
	select {
	case <-retryFinished:
	case <-time.After(3 * time.Second):
		t.Fatal("newer discovery did not finish")
	}
	newer, err := p.currentLoginSnapshot(context.Background())
	require.NoError(t, err)
	require.Equal(t, issuer+"/auth/newer", newer.oauth.Endpoint.AuthURL)
	unblockFirst()
	select {
	case err = <-oldResult:
	case <-time.After(3 * time.Second):
		t.Fatal("older discovery did not return")
	}
	require.ErrorIs(t, err, ErrCallbackConfigurationChanged, "superseded same-revision discovery must not publish")
	current, err := p.currentLoginSnapshot(context.Background())
	require.NoError(t, err)
	require.Equal(t, newer.CallbackFingerprint, current.CallbackFingerprint)
	require.Equal(t, issuer+"/auth/newer", current.oauth.Endpoint.AuthURL)
	require.Equal(t, issuer+"/token/newer", current.oauth.Endpoint.TokenURL)
	require.Same(t, newer.provider, current.provider)
	require.Same(t, newer.verifier, current.verifier)
	require.NoError(t, p.assertLoginSnapshot(context.Background(), newer))
	require.Equal(t, int32(2), requests.Load())
}
