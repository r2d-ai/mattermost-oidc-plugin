package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
)

var (
	ErrReconnectRequired      = errors.New("delegated access requires reconnect")
	ErrIdentityMismatch       = errors.New("delegated identity mismatch")
	ErrUserInactive           = errors.New("delegated user inactive")
	ErrTemporarilyUnavailable = errors.New("delegated access temporarily unavailable")
	ErrIntegrationDisabled    = errors.New("delegated integration disabled")
)

const refreshBudget = 10 * time.Second
const tokenSkew = 30 * time.Second

// UserToken is secret-bearing memory; JSON and fmt must never disclose Value.
type UserToken struct {
	Value      string `json:"-"`
	Generation uint64
}

func (UserToken) String() string   { return "[redacted user token]" }
func (UserToken) GoString() string { return "[redacted user token]" }

type TokenLifecycle struct {
	plugin *Plugin
	store  *CredentialStore
}

func newTokenLifecycle(p *Plugin) *TokenLifecycle { return &TokenLifecycle{p, newCredentialStore(p)} }

func lifecycleError(e error) error {
	switch {
	case e == nil:
		return nil
	case errors.Is(e, ErrIdentityConflict), errors.Is(e, ErrIdentityUnproven):
		return ErrIdentityMismatch
	case errors.Is(e, ErrIdentityGateClosed):
		return ErrIntegrationDisabled
	case errors.Is(e, ErrCredentialsUnavailable):
		return ErrReconnectRequired
	default:
		return ErrTemporarilyUnavailable
	}
}

// cleanupBinding is denial-only authority: a committed corroborated registry
// entry, independent of gate status, current issuer, native auth or DeleteAt.
func (p *Plugin) cleanupBinding(id string) (IdentityBinding, error) {
	if !model.IsValidId(id) {
		return IdentityBinding{}, ErrIdentityMismatch
	}
	reverse, _, e := p.readIdentityRecord(identityUserPrefix + id)
	if e != nil {
		return IdentityBinding{}, lifecycleError(e)
	}
	if reverse.State != "committed" || reverse.Binding.MattermostUserID != id {
		return IdentityBinding{}, ErrIdentityMismatch
	}
	forward, _, e := p.readIdentityRecord(pairKey(reverse.Binding))
	if e != nil {
		return IdentityBinding{}, lifecycleError(e)
	}
	if forward != reverse {
		return IdentityBinding{}, ErrIdentityMismatch
	}
	return reverse.Binding, nil
}
func (l *TokenLifecycle) authority(ctx context.Context, b IdentityBinding) (ResolvedIdentity, error) {
	if ctx.Err() != nil {
		return ResolvedIdentity{}, ErrTemporarilyUnavailable
	}
	if !validCredentialBinding(b) {
		return ResolvedIdentity{}, ErrIdentityMismatch
	}
	u, ae := l.plugin.API.GetUser(b.MattermostUserID)
	if ae != nil || u == nil {
		return ResolvedIdentity{}, ErrTemporarilyUnavailable
	}
	if u.DeleteAt != 0 || u.IsBot {
		// Observe inactivity before checking issuance gates, even if the hook failed.
		if bound, e := l.plugin.cleanupBinding(b.MattermostUserID); e == nil {
			_ = l.store.Invalidate(ctx, bound)
		}
		return ResolvedIdentity{}, ErrUserInactive
	}
	cfg := l.plugin.getConfiguration()
	if !cfg.EnablePlaneBroker || !cfg.EnableTokenPersistence {
		return ResolvedIdentity{}, ErrIntegrationDisabled
	}
	r, e := l.plugin.ResolveBrokerBinding(ctx, b.MattermostUserID)
	if e != nil {
		return r, lifecycleError(e)
	}
	if r.Binding != b {
		return r, ErrIdentityMismatch
	}
	return r, nil
}
func (l *TokenLifecycle) AssertGeneration(ctx context.Context, b IdentityBinding, generation uint64) error {
	if _, e := l.authority(ctx, b); e != nil {
		return e
	}
	c, e := l.store.Load(ctx, b)
	if e != nil {
		return lifecycleError(e)
	}
	if c.Version != generation {
		return ErrReconnectRequired
	}
	if ctx.Err() != nil {
		return ErrTemporarilyUnavailable
	}
	return nil
}
func (l *TokenLifecycle) abandon(b IdentityBinding, env credentialEnvelope, raw []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), refreshBudget)
	defer cancel()
	return lifecycleError(l.store.abandonPublication(ctx, b, env, raw))
}
func (l *TokenLifecycle) UserAccessToken(ctx context.Context, b IdentityBinding) (UserToken, error) {
	ctx, cancel := context.WithTimeout(ctx, refreshBudget)
	defer cancel()
	deadline, _ := ctx.Deadline()
	backoff := 10 * time.Millisecond
	for {
		r, e := l.authority(ctx, b)
		if e != nil {
			return UserToken{}, e
		}
		env, raw, e := l.store.read(b)
		if e != nil {
			return UserToken{}, lifecycleError(e)
		}
		switch env.State {
		case "refreshing":
			if env.StartedAt <= 0 || env.Deadline <= env.StartedAt || env.Deadline-env.StartedAt > int64(refreshBudget) || !time.Now().Before(time.Unix(0, env.Deadline)) {
				if e = l.abandon(b, env, raw); e != nil {
					return UserToken{}, e
				}
				return UserToken{}, ErrReconnectRequired
			}
			remaining := time.Until(time.Unix(0, env.Deadline))
			if remaining < backoff {
				backoff = remaining
			}
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return UserToken{}, ErrTemporarilyUnavailable
			case <-timer.C:
			}
			if backoff < 100*time.Millisecond {
				backoff *= 2
			}
			continue
		case "ready":
		default:
			return UserToken{}, ErrReconnectRequired
		}
		c, e := l.store.Load(ctx, b)
		if e != nil { // A concurrent claim can change ready before Load.
			next, _, readErr := l.store.read(b)
			if readErr == nil && (next.State == "refreshing" || next.Generation != env.Generation) {
				continue
			}
			return UserToken{}, lifecycleError(e)
		}
		if c.Version != env.Generation {
			continue
		}
		if c.AccessExpiresAt.After(time.Now().Add(tokenSkew)) {
			if e = l.AssertGeneration(ctx, b, c.Version); e != nil {
				return UserToken{}, e
			}
			return UserToken{c.AccessToken, c.Version}, nil
		}
		if c.RefreshToken == "" || (!c.RefreshExpiresAt.IsZero() && !c.RefreshExpiresAt.After(time.Now().Add(tokenSkew))) || env.Generation == math.MaxUint64 {
			if e = l.abandon(b, env, raw); e != nil {
				return UserToken{}, e
			}
			return UserToken{}, ErrReconnectRequired
		}
		owner, e := generateRandomKey(16)
		if e != nil {
			return UserToken{}, ErrTemporarilyUnavailable
		}
		env.Owner = owner
		env.State = "refreshing"
		env.StartedAt = time.Now().UnixNano()
		env.Deadline = deadline.UnixNano()
		owned, claim, e := l.store.sealTransition(c, env)
		if e != nil {
			return UserToken{}, lifecycleError(e)
		}
		if ctx.Err() != nil {
			return UserToken{}, ErrTemporarilyUnavailable
		}
		ok, ae := l.plugin.API.KVCompareAndSet(credentialKey(b), raw, claim)
		if ae != nil {
			_ = l.abandon(b, owned, claim)
			return UserToken{}, ErrTemporarilyUnavailable
		}
		if !ok {
			continue
		}
		return l.refresh(ctx, r, c, owned, claim)
	}
}

// delegatedTransport is a request-local snapshot. It never publishes into B0's
// login discovery cache, and remains usable when interactive login is disabled.
type delegatedTransport struct {
	configuration       Configuration
	revision            uint64
	tokenURL, revokeURL string
	client              *http.Client
}

func secureEndpoint(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}
func (l *TokenLifecycle) transport(ctx context.Context, b IdentityBinding) (*delegatedTransport, error) {
	p := l.plugin
	p.configurationLock.RLock()
	cfg := p.configuration.Clone()
	revision := p.configurationRevision
	p.configurationLock.RUnlock()
	if configuredIssuer(cfg) != b.Issuer || !secureEndpoint(b.Issuer) || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, ErrIdentityMismatch
	}
	client := *http.DefaultClient
	if p.discoveryClient != nil {
		client = *p.discoveryClient
	}
	client.Timeout = refreshBudget
	if limit, ok := ctx.Value(brokerHTTPBudgetKey{}).(time.Duration); ok && limit > 0 && limit < client.Timeout {
		client.Timeout = limit
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(b.Issuer, "/")+"/.well-known/openid-configuration", nil)
	if e != nil {
		return nil, ErrTemporarilyUnavailable
	}
	resp, e := client.Do(req)
	if e != nil {
		return nil, ErrTemporarilyUnavailable
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if e != nil || len(raw) > 65536 || resp.StatusCode != http.StatusOK {
		return nil, ErrTemporarilyUnavailable
	}
	var metadata struct {
		Issuer string `json:"issuer"`
		Token  string `json:"token_endpoint"`
		Revoke string `json:"revocation_endpoint"`
	}
	if json.Unmarshal(raw, &metadata) != nil || metadata.Issuer != b.Issuer || !secureEndpoint(metadata.Token) || (metadata.Revoke != "" && !secureEndpoint(metadata.Revoke)) {
		return nil, ErrTemporarilyUnavailable
	}
	t := &delegatedTransport{*cfg, revision, metadata.Token, metadata.Revoke, &client}
	if !l.transportCurrent(t) || ctx.Err() != nil {
		return nil, ErrTemporarilyUnavailable
	}
	return t, nil
}
func (l *TokenLifecycle) transportCurrent(t *delegatedTransport) bool {
	p := l.plugin
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()
	return p.configuration != nil && p.configurationRevision == t.revision && *p.configuration == t.configuration
}
func (t *delegatedTransport) post(ctx context.Context, endpoint string, values url.Values) ([]byte, error) {
	values.Set("client_id", t.configuration.ClientID)
	values.Set("client_secret", t.configuration.ClientSecret)
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if e != nil {
		return nil, ErrTemporarilyUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, e := t.client.Do(req)
	if e != nil {
		return nil, ErrReconnectRequired
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if e != nil || len(raw) > 65536 || resp.StatusCode != http.StatusOK {
		return nil, ErrReconnectRequired
	}
	return raw, nil
}
func (l *TokenLifecycle) refresh(ctx context.Context, r ResolvedIdentity, c StoredCredentials, owned credentialEnvelope, claim []byte) (UserToken, error) {
	b := r.Binding
	cleanup := func(e error) (UserToken, error) {
		if ce := l.abandon(b, owned, claim); ce != nil {
			return UserToken{}, ce
		}
		return UserToken{}, e
	}
	if ctx.Err() != nil {
		return cleanup(ErrReconnectRequired)
	}
	t, e := l.transport(ctx, b)
	if e != nil {
		return cleanup(e)
	}
	if _, e = l.authority(ctx, b); e != nil {
		return cleanup(e)
	}
	current, raw, e := l.store.read(b)
	if e != nil || !bytes.Equal(raw, claim) || current.Owner != owned.Owner || ctx.Err() != nil || !l.transportCurrent(t) {
		return cleanup(ErrReconnectRequired)
	}
	response, e := t.post(ctx, t.tokenURL, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {c.RefreshToken}})
	if e != nil {
		return cleanup(ErrReconnectRequired)
	}
	var token struct {
		Access         string `json:"access_token"`
		Refresh        string `json:"refresh_token"`
		Type           string `json:"token_type"`
		Expires        int64  `json:"expires_in"`
		RefreshExpires int64  `json:"refresh_expires_in"`
	}
	if json.Unmarshal(response, &token) != nil || token.Access == "" || token.Refresh == "" || len(token.Access)+len(token.Refresh) > 32768 || !strings.EqualFold(token.Type, "bearer") || token.Expires <= 30 || token.Expires > 31536000 || token.RefreshExpires < 0 || token.RefreshExpires > 31536000 {
		return cleanup(ErrReconnectRequired)
	}
	if ctx.Err() != nil || !l.transportCurrent(t) {
		return cleanup(ErrReconnectRequired)
	}
	if e = l.plugin.AssertCurrentBinding(ctx, r); e != nil {
		return cleanup(lifecycleError(e))
	}
	if _, e = l.authority(ctx, b); e != nil {
		return cleanup(e)
	}
	c.AccessToken = token.Access
	c.RefreshToken = token.Refresh
	c.AccessExpiresAt = time.Now().Add(time.Duration(token.Expires) * time.Second)
	c.RefreshExpiresAt = time.Time{}
	if token.RefreshExpires > 0 {
		c.RefreshExpiresAt = time.Now().Add(time.Duration(token.RefreshExpires) * time.Second)
	}
	// Nonissuing candidate makes a delayed/ambiguous SDK publication fail closed.
	candidate := owned
	candidate.Phase = "candidate"
	candidate.Generation++
	candidate, candidateRaw, e := l.store.sealTransition(c, candidate)
	if e != nil {
		return cleanup(lifecycleError(e))
	}
	if ctx.Err() != nil {
		return cleanup(ErrReconnectRequired)
	}
	ok, ae := l.plugin.API.KVCompareAndSet(credentialKey(b), claim, candidateRaw)
	if ae != nil || !ok {
		if ae != nil {
			_ = l.abandon(b, candidate, candidateRaw)
		}
		return cleanup(ErrReconnectRequired)
	}
	owned, claim = candidate, candidateRaw
	if ctx.Err() != nil || !l.transportCurrent(t) {
		return cleanup(ErrReconnectRequired)
	}
	if e = l.plugin.AssertCurrentBinding(ctx, r); e != nil {
		return cleanup(lifecycleError(e))
	}
	if _, e = l.authority(ctx, b); e != nil {
		return cleanup(e)
	}
	if ctx.Err() != nil {
		return cleanup(ErrReconnectRequired)
	}
	// Only an on-time acknowledged candidate can construct authenticated ready.
	ready := candidate
	ready.State = "ready"
	ready.StartedAt = 0
	ready.Deadline = 0
	ready.Phase = ""
	ready, readyRaw, e := l.store.sealTransition(c, ready)
	if e != nil {
		return cleanup(lifecycleError(e))
	}
	if ctx.Err() != nil {
		return cleanup(ErrReconnectRequired)
	}
	ok, ae = l.plugin.API.KVCompareAndSet(credentialKey(b), candidateRaw, readyRaw)
	if ae != nil {
		_ = l.abandon(b, ready, readyRaw)
		return UserToken{}, ErrTemporarilyUnavailable
	}
	if !ok {
		return UserToken{}, ErrReconnectRequired
	}
	owned, claim = ready, readyRaw
	if ctx.Err() != nil || !l.transportCurrent(t) {
		return cleanup(ErrReconnectRequired)
	}
	if e = l.AssertGeneration(ctx, b, ready.Generation); e != nil {
		return cleanup(e)
	}
	return UserToken{c.AccessToken, ready.Generation}, nil
}

func (l *TokenLifecycle) Disconnect(ctx context.Context, b IdentityBinding) error {
	// Loading is best effort, and is not cleanup authority. Frozen/keylost records
	// cannot be decrypted; invalidation must still succeed independently.
	c, _ := l.store.Load(ctx, b)
	if e := l.store.Invalidate(ctx, b); e != nil {
		return lifecycleError(e)
	}
	if c.RefreshToken == "" {
		return nil
	}
	revokeCtx, cancel := context.WithTimeout(ctx, refreshBudget)
	defer cancel()
	if t, e := l.transport(revokeCtx, b); e == nil && t.revokeURL != "" && l.transportCurrent(t) {
		_, _ = t.post(revokeCtx, t.revokeURL, url.Values{"token": {c.RefreshToken}, "token_type_hint": {"refresh_token"}})
	}
	return nil
}
