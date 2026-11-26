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

// Exchange diagnostics contain only code-selected reasons and HTTP status
// numbers. They never retain provider response bodies, URLs or credentials.
type exchangeDiagnostic struct {
	reason        string
	httpStatus    int
	providerError string
}

func (e *exchangeDiagnostic) Error() string { return "Plane token exchange unavailable" }
func (e *exchangeDiagnostic) Unwrap() error { return ErrTemporarilyUnavailable }

func exchangeFailure(reason string, status int) error {
	return &exchangeDiagnostic{reason: reason, httpStatus: status}
}

func exchangeHTTPFailure(reason string, err error) error {
	status := 0
	var diagnostic *exchangeDiagnostic
	if errors.As(err, &diagnostic) {
		status = diagnostic.httpStatus
		return &exchangeDiagnostic{reason: reason, httpStatus: status, providerError: diagnostic.providerError}
	}
	return exchangeFailure(reason, status)
}

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
	stage := "target"
	var diagnostic *exchangeDiagnostic
	actor, requestID, operation, issuerFP := "", "", "", ""
	defer func() {
		fields := []any{"actor_uuid", actor, "request_id", requestID, "issuer_fingerprint", issuerFP, "operation", operation, "outcome", outcome, "stage", stage, "latency_ms", time.Since(started).Milliseconds()}
		if diagnostic != nil {
			fields = append(fields, "reason", diagnostic.reason, "provider_http_status", diagnostic.httpStatus)
			if diagnostic.providerError != "" {
				fields = append(fields, "provider_error", diagnostic.providerError)
			}
		}
		p.API.LogInfo("Plane broker request", fields...)
	}()
	fail := func(err error) {
		_ = errors.As(err, &diagnostic)
		// A ring can disappear after preflight, including while B2 refresh fails.
		// Keep the lifecycle's established error API unchanged.
		if errors.Is(err, ErrReconnectRequired) && brokerCredentialAvailability() != nil {
			err = ErrTemporarilyUnavailable
			stage = "credential_keyring_recheck"
		}
		status, code := brokerError(err)
		outcome = code
		brokerFailure(w, status, code, requestID)
	}
	if !brokerTarget(r) {
		brokerFailure(w, 400, "invalid_input", "")
		return
	}
	stage = "site_url"
	site, e := url.Parse(p.getSiteURL())
	if e != nil || site.Host == "" || (site.Path != "" && site.Path != "/") {
		fail(ErrTemporarilyUnavailable)
		return
	}
	stage = "request_body"
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if e != nil {
		brokerFailure(w, 400, "invalid_input", "")
		return
	}
	stage = "authenticate"
	if e = p.authenticateBroker(r, body, time.Now()); e != nil {
		fail(e)
		return
	}
	stage = "request"
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
	stage = "integration_flags"
	if !cfg.EnablePlaneBroker || !cfg.EnableTokenPersistence {
		fail(ErrIntegrationDisabled)
		return
	}
	stage = "client_configuration"
	if cfg.ClientID == "" {
		fail(ErrIdentityMismatch)
		return
	}
	stage = "credential_keyring"
	if e = brokerCredentialAvailability(); e != nil {
		fail(e)
		return
	}
	stage = "identity_binding"
	resolved, e := p.ResolveBrokerBinding(ctx, input.UserID)
	if e != nil {
		fail(lifecycleError(e))
		return
	}
	stage = "user_rate_limit"
	if !p.brokerRate(input.UserID, time.Now()) {
		fail(ErrTemporarilyUnavailable)
		return
	}
	issuerFP = resolved.IdentityFingerprint
	life := newTokenLifecycle(p)
	stage = "subject_credentials"
	subject, e := life.UserAccessToken(ctx, resolved.Binding)
	if e != nil {
		fail(e)
		return
	}
	stage = "token_exchange"
	token, expires, e := p.exchangePlaneToken(ctx, cfg, resolved.Binding, subject.Value, input.Scope)
	if e != nil {
		fail(e)
		return
	}
	// Every network operation has completed before the live authority checks.
	stage = "generation_recheck"
	if e = life.AssertGeneration(ctx, resolved.Binding, subject.Generation); e != nil {
		fail(e)
		return
	}
	stage = "configuration_recheck"
	p.configurationLock.RLock()
	current := p.configurationRevision == revision && p.configuration != nil && *p.configuration == *cfg
	p.configurationLock.RUnlock()
	if !current || ctx.Err() != nil || expires <= time.Now().Unix()+30 {
		fail(ErrTemporarilyUnavailable)
		return
	}
	// Recheck deployment key availability at the successful release boundary.
	stage = "credential_keyring_recheck"
	if e = brokerCredentialAvailability(); e != nil {
		fail(e)
		return
	}
	// Retirement/loss of a verification key takes effect before release too.
	stage = "signature_recheck"
	if e = brokerSignature(r, body, started); e != nil {
		fail(e)
		return
	}
	outcome = "success"
	stage = "complete"
	_ = json.NewEncoder(w).Encode(struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   int64  `json:"expires_at"`
	}{token, expires})
}
func brokerReadHTTP(ctx context.Context, client *http.Client, method, endpoint string, body io.Reader) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, method, endpoint, body)
	if e != nil {
		return nil, exchangeFailure("http", 0)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, e := client.Do(req)
	if e != nil {
		return nil, exchangeFailure("http", 0)
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if e != nil || len(raw) > 65536 || resp.StatusCode != http.StatusOK {
		diagnostic := &exchangeDiagnostic{reason: "http", httpStatus: resp.StatusCode}
		if e == nil && len(raw) <= 65536 && resp.StatusCode != http.StatusOK {
			diagnostic.providerError = safeProviderError(raw)
		}
		return nil, diagnostic
	}
	return raw, nil
}

func safeProviderError(raw []byte) string {
	fields, err := decodeBrokerObject(raw)
	if err != nil {
		return ""
	}
	var code string
	if json.Unmarshal(fields["error"], &code) != nil {
		return ""
	}
	switch code {
	case "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client",
		"unsupported_grant_type", "invalid_scope", "invalid_target", "access_denied", "invalid_token":
		return code
	default:
		return ""
	}
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
	fail := func(reason string) (string, int64, error) { return "", 0, exchangeFailure(reason, http.StatusOK) }
	if configuredIssuer(cfg) != b.Issuer || !secureEndpoint(b.Issuer) || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return "", 0, exchangeFailure("exchange_configuration", 0)
	}
	client := *http.DefaultClient
	if p.discoveryClient != nil {
		client = *p.discoveryClient
	}
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	raw, e := brokerReadHTTP(ctx, &client, http.MethodGet, strings.TrimRight(b.Issuer, "/")+"/.well-known/openid-configuration", nil)
	if e != nil {
		return "", 0, exchangeHTTPFailure("discovery_http", e)
	}
	var meta struct {
		Issuer string `json:"issuer"`
		Token  string `json:"token_endpoint"`
		JWKS   string `json:"jwks_uri"`
	}
	if _, e = decodeBrokerObject(raw); e != nil || json.Unmarshal(raw, &meta) != nil || meta.Issuer != b.Issuer || !brokerEndpoint(b.Issuer, meta.Token) || !brokerEndpoint(b.Issuer, meta.JWKS) {
		return fail("discovery_metadata")
	}
	values := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "client_id": {cfg.ClientID}, "client_secret": {cfg.ClientSecret}, "subject_token": {subject}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "audience": {"plane-api"}, "scope": {scope}}
	raw, e = brokerReadHTTP(ctx, &client, http.MethodPost, meta.Token, strings.NewReader(values.Encode()))
	if e != nil {
		return "", 0, exchangeHTTPFailure("exchange_http", e)
	}
	received := time.Now().Unix()
	var response struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IssuedType  string `json:"issued_token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if _, e = decodeBrokerObject(raw); e != nil {
		return fail("response_json")
	}
	if e = json.Unmarshal(raw, &response); e != nil {
		var fieldError *json.UnmarshalTypeError
		if errors.As(e, &fieldError) {
			switch fieldError.Field {
			case "expires_in":
				return fail("response_expires_in")
			case "token_type":
				return fail("response_token_type")
			case "issued_token_type":
				return fail("response_issued_token_type")
			case "access_token":
				return fail("response_access_token")
			}
		}
		return fail("response_json")
	}
	if len(response.AccessToken) == 0 || len(response.AccessToken) > 16384 {
		return fail("response_access_token")
	}
	if response.TokenType != "Bearer" {
		return fail("response_token_type")
	}
	if response.IssuedType != "urn:ietf:params:oauth:token-type:access_token" {
		return fail("response_issued_token_type")
	}
	if response.ExpiresIn <= 0 || response.ExpiresIn > 300 {
		return fail("response_expires_in")
	}
	raw, e = brokerReadHTTP(ctx, &client, http.MethodGet, meta.JWKS, nil)
	if e != nil {
		return "", 0, exchangeHTTPFailure("jwks_http", e)
	}
	var keys jose.JSONWebKeySet
	if json.Unmarshal(raw, &keys) != nil || len(keys.Keys) == 0 || len(keys.Keys) > 64 {
		return fail("jwks_keys")
	}
	signed, e := jose.ParseSigned(response.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	if e != nil || len(signed.Signatures) != 1 {
		return fail("jwt_parse")
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
		return fail("jwt_signature")
	}
	expires, e := verifyPlaneClaims(claims, b, cfg.ClientID, scope, time.Now())
	if e != nil {
		var diagnostic *exchangeDiagnostic
		if errors.As(e, &diagnostic) {
			return fail(diagnostic.reason)
		}
		return fail("claims_json")
	}
	if expires-received-response.ExpiresIn > 30 || expires-received-response.ExpiresIn < -30 {
		return fail("response_expiry_mismatch")
	}
	return response.AccessToken, expires, nil
}
func verifyPlaneClaims(raw []byte, b IdentityBinding, expectedClientID, scope string, now time.Time) (int64, error) {
	fail := func(reason string) (int64, error) { return 0, exchangeFailure(reason, 0) }
	if expectedClientID == "" {
		return fail("exchange_configuration")
	}
	m, e := decodeBrokerObject(raw)
	if e != nil {
		return fail("claims_json")
	}
	for _, claim := range []struct{ key, want, reason string }{
		{"iss", b.Issuer, "claims_issuer"}, {"sub", b.Subject, "claims_subject"},
		{"azp", expectedClientID, "claims_azp"}, {"typ", "Bearer", "claims_type"},
	} {
		var got string
		if json.Unmarshal(m[claim.key], &got) != nil || got != claim.want {
			return fail(claim.reason)
		}
	}
	var aud string
	var audiences []string
	if json.Unmarshal(m["aud"], &aud) == nil {
		audiences = []string{aud}
	} else if json.Unmarshal(m["aud"], &audiences) != nil {
		return fail("claims_audience")
	}
	if len(audiences) != 1 || audiences[0] != "plane-api" {
		return fail("claims_audience")
	}
	var gotScope string
	if json.Unmarshal(m["scope"], &gotScope) != nil {
		return fail("claims_scope")
	}
	wantWrite := scope == "plane.read plane.write"
	if scope != "plane.read" && !wantWrite {
		return fail("claims_scope_unexpected")
	}
	seen := map[string]bool{}
	for _, s := range strings.Fields(gotScope) {
		// OAuth scope-token is printable ASCII except quote and backslash.
		for i := range len(s) {
			if s[i] < 0x21 || s[i] > 0x7e || s[i] == '"' || s[i] == '\\' {
				return fail("claims_scope")
			}
		}
		if seen[s] {
			return fail("claims_scope_duplicate")
		}
		switch s {
		case "plane.read":
		case "plane.write":
			if !wantWrite {
				return fail("claims_scope_unexpected")
			}
		default:
			if strings.HasPrefix(s, "plane.") {
				return fail("claims_scope_unexpected")
			}
			// The broker authorizes only Plane capabilities. Other valid OAuth
			// scope names do not grant Plane access and need no provider allowlist.
		}
		seen[s] = true
	}
	if !seen["plane.read"] || (wantWrite && !seen["plane.write"]) {
		return fail("claims_scope_missing")
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
		return fail("claims_lifetime")
	}
	exp, ok := integer("exp")
	if !ok || exp <= now.Unix()+30 || exp <= iat || exp-iat < 120 || exp-iat > 300 {
		return fail("claims_lifetime")
	}
	if _, present := m["nbf"]; present {
		nbf, ok := integer("nbf")
		if !ok || nbf > now.Unix()+30 || nbf >= exp {
			return fail("claims_lifetime")
		}
	}
	return exp, nil
}
