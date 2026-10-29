package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/mattermost/mattermost/server/public/model"
)

// decodeObject rejects duplicate fields, nonobjects and trailing JSON. The byte
// bound is imposed by each caller before parsing; unknown JWT claims are allowed.
func decodeBrokerObject(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, e := d.Token()
	if e != nil || tok != json.Delim('{') {
		return nil, ErrTemporarilyUnavailable
	}
	m := map[string]json.RawMessage{}
	for d.More() {
		tok, e = d.Token()
		key, ok := tok.(string)
		if e != nil || !ok {
			return nil, ErrTemporarilyUnavailable
		}
		if _, exists := m[key]; exists {
			return nil, ErrTemporarilyUnavailable
		}
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return nil, ErrTemporarilyUnavailable
		}
		m[key] = v
	}
	if _, e = d.Token(); e != nil {
		return nil, ErrTemporarilyUnavailable
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrTemporarilyUnavailable
	}
	return m, nil
}

type planeBrokerRequest struct{ UserID, Audience, Scope, RequestID string }

func parseBrokerRequest(raw []byte) (planeBrokerRequest, error) {
	var out planeBrokerRequest
	m, e := decodeBrokerObject(raw)
	if e != nil || len(m) != 4 {
		return out, ErrTemporarilyUnavailable
	}
	for key, dest := range map[string]*string{"mm_user_id": &out.UserID, "audience": &out.Audience, "scope": &out.Scope, "request_id": &out.RequestID} {
		v, ok := m[key]
		if !ok || bytes.Equal(v, []byte("null")) || json.Unmarshal(v, dest) != nil {
			return planeBrokerRequest{}, ErrTemporarilyUnavailable
		}
	}
	if !model.IsValidId(out.UserID) || len(out.RequestID) < 1 || len(out.RequestID) > 128 {
		return planeBrokerRequest{}, ErrTemporarilyUnavailable
	}
	for _, c := range out.RequestID {
		if c < 32 || c > 126 {
			return planeBrokerRequest{}, ErrTemporarilyUnavailable
		}
	}
	return out, nil
}
func brokerFailure(w http.ResponseWriter, status int, code, id string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error     string `json:"error"`
		RequestID string `json:"request_id"`
	}{code, id})
}
func brokerError(err error) (int, string) {
	switch {
	case errors.Is(err, errBrokerSignature):
		return 401, "invalid_signature"
	case errors.Is(err, ErrReconnectRequired):
		return 409, "reconnect_required"
	case errors.Is(err, ErrIdentityMismatch), errors.Is(err, ErrUserInactive):
		return 403, "forbidden"
	default:
		return 503, "unavailable"
	}
}

// A deployment-wide ring outage is retryable at the broker boundary. A valid
// ring with a missing historical key or unusable generation remains B2 reconnect.
func brokerCredentialAvailability() error {
	if _, _, err := credentialKeyring(); err != nil {
		return ErrTemporarilyUnavailable
	}
	return nil
}

func (p *Plugin) handlePlaneBroker(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	if !p.enterBroker() {
		brokerFailure(w, 503, "unavailable", "")
		return
	}
	defer p.leaveBroker()
	started := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, brokerHTTPBudgetKey{}, 5*time.Second)
	outcome := "invalid_input"
	actor, requestID, operation, issuerFP := "", "", "", ""
	defer func() {
		p.API.LogInfo("Plane broker request", "actor_uuid", actor, "request_id", requestID, "issuer_fingerprint", issuerFP, "operation", operation, "outcome", outcome, "latency_ms", time.Since(started).Milliseconds())
	}()
	fail := func(err error) {
		// A ring can disappear after preflight, including while B2 refresh fails.
		// Keep the lifecycle's established error API unchanged.
		if errors.Is(err, ErrReconnectRequired) && brokerCredentialAvailability() != nil {
			err = ErrTemporarilyUnavailable
		}
		status, code := brokerError(err)
		outcome = code
		brokerFailure(w, status, code, requestID)
	}
	if !brokerTarget(r) {
		brokerFailure(w, 400, "invalid_input", "")
		return
	}
	site, e := url.Parse(p.getSiteURL())
	if e != nil || site.Host == "" || (site.Path != "" && site.Path != "/") {
		fail(ErrTemporarilyUnavailable)
		return
	}
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if e != nil {
		brokerFailure(w, 400, "invalid_input", "")
		return
	}
	if e = p.authenticateBroker(r, body, time.Now()); e != nil {
		fail(e)
		return
	}
	input, e := parseBrokerRequest(body)
	if e != nil {
		brokerFailure(w, 400, "invalid_input", "")
		return
	}
	actor = input.UserID
	requestID = input.RequestID
	if input.Audience != "plane-api" || (input.Scope != "plane.read" && input.Scope != "plane.read plane.write") {
		fail(ErrIdentityMismatch)
		return
	}
	operation = input.Scope
	p.configurationLock.RLock()
	cfg := &Configuration{}
	if p.configuration != nil {
		cfg = p.configuration.Clone()
	}
	revision := p.configurationRevision
	p.configurationLock.RUnlock()
	if !cfg.EnablePlaneBroker || !cfg.EnableTokenPersistence {
		fail(ErrIntegrationDisabled)
		return
	}
	if cfg.ClientID != "mattermost-oidc" {
		fail(ErrIdentityMismatch)
		return
	}
	if e = brokerCredentialAvailability(); e != nil {
		fail(e)
		return
	}
	resolved, e := p.ResolveBrokerBinding(ctx, input.UserID)
	if e != nil {
		fail(lifecycleError(e))
		return
	}
	if !p.brokerRate(input.UserID, time.Now()) {
		fail(ErrTemporarilyUnavailable)
		return
	}
	issuerFP = resolved.IdentityFingerprint
	life := newTokenLifecycle(p)
	subject, e := life.UserAccessToken(ctx, resolved.Binding)
	if e != nil {
		fail(e)
		return
	}
	token, expires, e := p.exchangePlaneToken(ctx, cfg, resolved.Binding, subject.Value, input.Scope)
	if e != nil {
		fail(e)
		return
	}
	// Every network operation has completed before the live authority checks.
	if e = life.AssertGeneration(ctx, resolved.Binding, subject.Generation); e != nil {
		fail(e)
		return
	}
	p.configurationLock.RLock()
	current := p.configurationRevision == revision && p.configuration != nil && *p.configuration == *cfg
	p.configurationLock.RUnlock()
	if !current || ctx.Err() != nil || expires <= time.Now().Unix()+30 {
		fail(ErrTemporarilyUnavailable)
		return
	}
	// Recheck deployment key availability at the successful release boundary.
	if e = brokerCredentialAvailability(); e != nil {
		fail(e)
		return
	}
	// Retirement/loss of a verification key takes effect before release too.
	if e = brokerSignature(r, body, started); e != nil {
		fail(e)
		return
	}
	outcome = "success"
	_ = json.NewEncoder(w).Encode(struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   int64  `json:"expires_at"`
	}{token, expires})
}
func brokerReadHTTP(ctx context.Context, client *http.Client, method, endpoint string, body io.Reader) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, method, endpoint, body)
	if e != nil {
		return nil, ErrTemporarilyUnavailable
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
	return raw, nil
}
func brokerEndpoint(issuer, endpoint string) bool {
	if !secureEndpoint(endpoint) {
		return false
	}
	a, _ := url.Parse(issuer)
	b, _ := url.Parse(endpoint)
	return a.Scheme == b.Scheme && a.Host == b.Host && b.User == nil && b.RawQuery == "" && b.Fragment == "" && b.RawPath == "" && !b.ForceQuery
}
func (p *Plugin) exchangePlaneToken(ctx context.Context, cfg *Configuration, b IdentityBinding, subject, scope string) (string, int64, error) {
	fail := func() (string, int64, error) { return "", 0, ErrTemporarilyUnavailable }
	if configuredIssuer(cfg) != b.Issuer || !secureEndpoint(b.Issuer) || cfg.ClientID != "mattermost-oidc" || cfg.ClientSecret == "" {
		return fail()
	}
	client := *http.DefaultClient
	if p.discoveryClient != nil {
		client = *p.discoveryClient
	}
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	raw, e := brokerReadHTTP(ctx, &client, http.MethodGet, strings.TrimRight(b.Issuer, "/")+"/.well-known/openid-configuration", nil)
	if e != nil {
		return fail()
	}
	var meta struct {
		Issuer string `json:"issuer"`
		Token  string `json:"token_endpoint"`
		JWKS   string `json:"jwks_uri"`
	}
	if _, e = decodeBrokerObject(raw); e != nil || json.Unmarshal(raw, &meta) != nil || meta.Issuer != b.Issuer || !brokerEndpoint(b.Issuer, meta.Token) || !brokerEndpoint(b.Issuer, meta.JWKS) {
		return fail()
	}
	values := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "client_id": {cfg.ClientID}, "client_secret": {cfg.ClientSecret}, "subject_token": {subject}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "audience": {"plane-api"}, "scope": {scope}}
	raw, e = brokerReadHTTP(ctx, &client, http.MethodPost, meta.Token, strings.NewReader(values.Encode()))
	if e != nil {
		return fail()
	}
	received := time.Now().Unix()
	var response struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IssuedType  string `json:"issued_token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if _, e = decodeBrokerObject(raw); e != nil || json.Unmarshal(raw, &response) != nil || len(response.AccessToken) == 0 || len(response.AccessToken) > 16384 || response.TokenType != "Bearer" || response.IssuedType != "urn:ietf:params:oauth:token-type:access_token" || response.ExpiresIn <= 0 || response.ExpiresIn > 300 {
		return fail()
	}
	raw, e = brokerReadHTTP(ctx, &client, http.MethodGet, meta.JWKS, nil)
	if e != nil {
		return fail()
	}
	var keys jose.JSONWebKeySet
	if json.Unmarshal(raw, &keys) != nil || len(keys.Keys) == 0 || len(keys.Keys) > 64 {
		return fail()
	}
	signed, e := jose.ParseSigned(response.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	if e != nil || len(signed.Signatures) != 1 {
		return fail()
	}
	var claims []byte
	for _, key := range keys.Keys {
		if !key.Valid() || !key.IsPublic() || (key.Use != "" && key.Use != "sig") || (key.Algorithm != "" && key.Algorithm != "RS256") || key.KeyID != signed.Signatures[0].Header.KeyID {
			continue
		}
		claims, e = signed.Verify(key.Key)
		if e == nil {
			break
		}
	}
	if len(claims) == 0 || e != nil {
		return fail()
	}
	expires, e := verifyPlaneClaims(claims, b, scope, time.Now())
	if e != nil || expires-received-response.ExpiresIn > 30 || expires-received-response.ExpiresIn < -30 {
		return fail()
	}
	return response.AccessToken, expires, nil
}
func verifyPlaneClaims(raw []byte, b IdentityBinding, scope string, now time.Time) (int64, error) {
	fail := func() (int64, error) { return 0, ErrTemporarilyUnavailable }
	m, e := decodeBrokerObject(raw)
	if e != nil {
		return fail()
	}
	for key, want := range map[string]string{"iss": b.Issuer, "sub": b.Subject, "azp": "mattermost-oidc", "typ": "Bearer"} {
		var got string
		if json.Unmarshal(m[key], &got) != nil || got != want {
			return fail()
		}
	}
	var aud string
	var audiences []string
	if json.Unmarshal(m["aud"], &aud) == nil {
		audiences = []string{aud}
	} else if json.Unmarshal(m["aud"], &audiences) != nil {
		return fail()
	}
	if len(audiences) != 1 || audiences[0] != "plane-api" {
		return fail()
	}
	var gotScope string
	if json.Unmarshal(m["scope"], &gotScope) != nil {
		return fail()
	}
	wanted := strings.Fields(scope)
	got := strings.Fields(gotScope)
	if len(got) != len(wanted) {
		return fail()
	}
	seen := map[string]bool{}
	for _, s := range got {
		if seen[s] || (s != "plane.read" && !(s == "plane.write" && len(wanted) == 2)) {
			return fail()
		}
		seen[s] = true
	}
	integer := func(key string) (int64, bool) {
		v, ok := m[key]
		if !ok {
			return 0, false
		}
		n, e := strconv.ParseInt(string(v), 10, 64)
		return n, e == nil
	}
	iat, ok := integer("iat")
	if !ok || iat < 1 || iat > now.Unix()+30 {
		return fail()
	}
	exp, ok := integer("exp")
	if !ok || exp <= now.Unix()+30 || exp <= iat || exp-iat < 120 || exp-iat > 300 {
		return fail()
	}
	if _, present := m["nbf"]; present {
		nbf, ok := integer("nbf")
		if !ok || nbf > now.Unix()+30 || nbf >= exp {
			return fail()
		}
	}
	return exp, nil
}
