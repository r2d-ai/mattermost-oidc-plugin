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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const diagnosticSecret = "provider-secret-body-must-not-appear"

func TestExchangeDiagnosticsAreSafeAndPreserveDenial(t *testing.T) {
	for _, mode := range []string{"http400", "http400_json", "http400_unknown", "scope", "lifetime", "expires_in", "token_type", "issued_token_type"} {
		t.Run(mode, func(t *testing.T) {
			brokerKeys(t)
			credentialKeys(t, "current", map[string]string{"current": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))})
			p, a, _ := fixtureIdentity(t)
			cfg := p.getConfiguration()
			cfg.ClientID = "mattermost"
			cfg.EnablePlaneBroker, cfg.EnableTokenPersistence = true, true
			p.setConfiguration(cfg)
			fp := identityFingerprint(cfg.IssuerURL, cfg.ClientID)
			a.kv[identityGateKey], _ = json.Marshal(identityGate{Version: 1, Status: "active", Epoch: 2, Issuer: cfg.IssuerURL, ClientID: cfg.ClientID, IdentityFingerprint: fp})
			snapshot := &LoginSnapshot{IdentityFingerprint: fp, GateEpoch: 2, configuration: *cfg}
			p.loginSnapshot = snapshot
			identity, _, err := resolveTest(p, snapshot)
			require.NoError(t, err)
			require.NoError(t, newCredentialStore(p).Save(context.Background(), StoredCredentials{Binding: identity.Binding, AccessToken: diagnosticSecret, RefreshToken: "refresh-secret", AccessExpiresAt: time.Now().Add(time.Hour), GateEpoch: identity.GateEpoch, BindingRevision: identity.BindingRevision}))
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			now := time.Now().Unix()
			claims := map[string]any{"iss": cfg.IssuerURL, "sub": "s", "aud": "plane-api", "azp": cfg.ClientID, "typ": "Bearer", "scope": "plane.read", "iat": now, "exp": now + 180}
			if mode == "scope" {
				claims["scope"] = "plane.read plane.write"
			}
			if mode == "lifetime" {
				claims["exp"] = now + 900
			}
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test"}`))
			raw, err := json.Marshal(claims)
			require.NoError(t, err)
			signingInput := header + "." + base64.RawURLEncoding.EncodeToString(raw)
			hash := sha256.Sum256([]byte(signingInput))
			signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
			require.NoError(t, err)
			token := signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
			response := map[string]any{"access_token": token, "token_type": "Bearer", "issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "expires_in": 180}
			switch mode {
			case "expires_in":
				response["expires_in"] = 900
			case "token_type":
				response["token_type"] = "wrong"
			case "issued_token_type":
				response["issued_token_type"] = "wrong"
			}
			p.discoveryClient = &http.Client{Transport: brokerRoundTripper(func(r *http.Request) (*http.Response, error) {
				var data any
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					data = map[string]string{"issuer": cfg.IssuerURL, "token_endpoint": cfg.IssuerURL + "/token", "jwks_uri": cfg.IssuerURL + "/keys"}
				case "/token":
					if mode == "http400" {
						return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader(diagnosticSecret))}, nil
					}
					if mode == "http400_json" || mode == "http400_unknown" {
						code := "invalid_target"
						if mode == "http400_unknown" {
							code = diagnosticSecret
						}
						body, err := json.Marshal(map[string]string{"error": code, "error_description": diagnosticSecret})
						require.NoError(t, err)
						return &http.Response{StatusCode: 400, Body: io.NopCloser(bytes.NewReader(body))}, nil
					}
					data = response
				case "/keys":
					data = map[string]any{"keys": []any{map[string]string{"kty": "RSA", "alg": "RS256", "kid": "test", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}}
				default:
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
				body, err := json.Marshal(data)
				require.NoError(t, err)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, nil
			})}
			logger := &brokerStageAPI{identityAPI: a}
			p.SetAPI(logger)
			p.initRouter()
			body := fmt.Sprintf(`{"mm_user_id":%q,"audience":"plane-api","scope":"plane.read","request_id":"diagnostic"}`, identity.Binding.MattermostUserID)
			result := serveBroker(p, signedBrokerRequest(body, 0))
			require.Equal(t, 503, result.Code)
			require.JSONEq(t, `{"error":"unavailable","request_id":"diagnostic"}`, result.Body.String())
			wantReason := map[string]string{"http400": "exchange_http", "scope": "claims_scope_unexpected", "lifetime": "claims_lifetime", "expires_in": "response_expires_in", "token_type": "response_token_type", "issued_token_type": "response_issued_token_type"}[mode]
			if strings.HasPrefix(mode, "http400") {
				wantReason = "exchange_http"
			}
			require.Equal(t, "token_exchange", logger.fields["stage"])
			require.Equal(t, wantReason, logger.fields["reason"])
			wantStatus := 200
			if strings.HasPrefix(mode, "http400") {
				wantStatus = 400
			}
			require.Equal(t, wantStatus, logger.fields["provider_http_status"])
			if mode == "http400_json" {
				require.Equal(t, "invalid_target", logger.fields["provider_error"])
			} else {
				require.NotContains(t, logger.fields, "provider_error")
			}
			logged, err := json.Marshal(logger.fields)
			require.NoError(t, err)
			for _, secret := range []string{diagnosticSecret, "refresh-secret", token, cfg.ClientSecret} {
				require.NotContains(t, string(logged), secret)
				require.NotContains(t, result.Body.String(), secret)
			}
		})
	}
}

func TestExchangeDiagnosticPreservesUnavailableSentinel(t *testing.T) {
	for _, err := range []error{exchangeFailure("claims_scope", 200), exchangeHTTPFailure("exchange_http", exchangeFailure("http", 400))} {
		require.ErrorIs(t, err, ErrTemporarilyUnavailable)
		var diagnostic *exchangeDiagnostic
		require.True(t, errors.As(err, &diagnostic))
	}
}
