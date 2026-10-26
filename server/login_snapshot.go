package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	oidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"slices"
	"sort"
)

// LoginSnapshot contains secret-bearing internals. Never serialize or log it.
type LoginSnapshot struct {
	IdentityFingerprint, CallbackFingerprint string
	GateEpoch                                uint64
	configuration                            Configuration
	provider                                 *oidc.Provider
	verifier                                 *oidc.IDTokenVerifier
	oauth                                    oauth2.Config
}

func makeLoginSnapshot(c *Configuration, provider *oidc.Provider, verifier *oidc.IDTokenVerifier, oauth *oauth2.Config, key string) *LoginSnapshot {
	var discovery struct {
		Issuer   string `json:"issuer"`
		Auth     string `json:"authorization_endpoint"`
		Token    string `json:"token_endpoint"`
		Userinfo string `json:"userinfo_endpoint"`
		JWKS     string `json:"jwks_uri"`
	}
	_ = provider.Claims(&discovery)
	scopes := append([]string(nil), oauth.Scopes...)
	sort.Strings(scopes)
	scopes = slices.Compact(scopes)
	fp := identityFingerprint(discovery.Issuer, c.ClientID)
	material := []any{"mm-oidc-callback-v1", fp, c.ClientSecret, oauth.RedirectURL, scopes, c.UsernameClaim, c.EmailClaim, c.FirstNameClaim, c.LastNameClaim, c.PositionClaim, c.EmailVerifiedClaim, c.RequireEmailVerified, c.AutoCreateAccounts, c.DefaultTeam, discovery.Issuer, discovery.Auth, discovery.Token, discovery.Userinfo, discovery.JWKS}
	b, _ := json.Marshal(material)
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write(b)
	oc := *oauth
	oc.Scopes = scopes
	return &LoginSnapshot{IdentityFingerprint: fp, CallbackFingerprint: hex.EncodeToString(mac.Sum(nil)), configuration: *c.Clone(), provider: provider, verifier: verifier, oauth: oc}
}
func (p *Plugin) initializeStateKey() error {
	for i := 0; i < 32; i++ {
		b, e := p.API.KVGet(kvEncryptionKey)
		if e != nil {
			return ErrIdentityUnavailable
		}
		if len(b) == 0 {
			key, e := generateRandomKey(32)
			if e != nil {
				return ErrIdentityUnavailable
			}
			ok, ae := p.API.KVCompareAndSet(kvEncryptionKey, nil, []byte(key))
			if ae != nil {
				return ErrIdentityUnavailable
			}
			if !ok {
				continue
			}
			b = []byte(key)
		}
		p.configurationLock.Lock()
		p.encryptionKey = string(b)
		p.configurationLock.Unlock()
		return nil
	}
	return ErrIdentityUnavailable
}
func (p *Plugin) currentLoginSnapshot(ctx context.Context) (*LoginSnapshot, error) {
	if ctx.Err() != nil {
		return nil, ErrIdentityUnavailable
	}
	cfg := p.getConfiguration()
	g, e := p.observeIdentityGate(cfg)
	if e != nil {
		return nil, e
	}
	if !cfg.Enable || g.Status != "active" || g.IdentityFingerprint != identityFingerprint(configuredIssuer(cfg), cfg.ClientID) {
		return nil, ErrIdentityGateClosed
	}
	p.configurationLock.RLock()
	s := p.loginSnapshot
	if s != nil {
		copy := *s
		s = &copy
	}
	current := p.configuration != nil && *p.configuration == *cfg
	p.configurationLock.RUnlock()
	if s == nil || !current || s.IdentityFingerprint != g.IdentityFingerprint || s.configuration != *cfg {
		return nil, ErrCallbackConfigurationChanged
	}
	// Mattermost SiteURL can change independently of plugin configuration.
	if s.oauth.RedirectURL != "" && s.oauth.RedirectURL != p.getSiteURL()+"/plugins/"+PluginID+"/oauth2/callback" {
		return nil, ErrCallbackConfigurationChanged
	}
	s.GateEpoch = g.Epoch
	return s, nil
}
func (p *Plugin) assertLoginSnapshot(ctx context.Context, expected *LoginSnapshot) error {
	current, e := p.currentLoginSnapshot(ctx)
	if e != nil {
		return e
	}
	if expected == nil || current.GateEpoch != expected.GateEpoch || current.IdentityFingerprint != expected.IdentityFingerprint || current.CallbackFingerprint != expected.CallbackFingerprint {
		return ErrCallbackConfigurationChanged
	}
	return nil
}
