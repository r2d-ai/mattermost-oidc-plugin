package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

// Keep the signed TLS login fixture intact. Only the later exchange endpoints
// gain a real signing key and JWKS, under the exact same approved issuer.
func legacyUpgradeBrokerExchange(t *testing.T, e *loginEnv, authorizedParty string) *atomic.Int32 {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	issuer := e.p.getConfiguration().IssuerURL
	base := e.p.discoveryClient.Transport
	calls := &atomic.Int32{}
	client := *e.p.discoveryClient
	client.Transport = brokerRoundTripper(func(request *http.Request) (*http.Response, error) {
		if !strings.HasPrefix(request.URL.String(), issuer+"/") {
			return base.RoundTrip(request)
		}
		var payload any
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			payload = map[string]string{"issuer": issuer, "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/broker-keys"}
		case "/broker-keys":
			payload = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "upgrade-exchange", Algorithm: "RS256", Use: "sig"}}}
		case "/token":
			require.NoError(t, request.ParseForm())
			require.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", request.Form.Get("grant_type"))
			require.Equal(t, "mattermost", request.Form.Get("client_id"))
			require.Equal(t, "secret", request.Form.Get("client_secret"))
			require.Equal(t, "desktop-access-secret", request.Form.Get("subject_token"))
			require.Equal(t, "plane-api", request.Form.Get("audience"))
			require.Empty(t, request.Form.Get("requested_subject"))
			calls.Add(1)
			now := time.Now().Unix()
			claims, err := json.Marshal(map[string]any{"iss": issuer, "sub": testSubject, "aud": "plane-api", "azp": authorizedParty, "typ": "Bearer", "scope": request.Form.Get("scope"), "iat": now, "exp": now + 180})
			require.NoError(t, err)
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"upgrade-exchange"}`))
			input := header + "." + base64.RawURLEncoding.EncodeToString(claims)
			digest := sha256.Sum256([]byte(input))
			signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
			require.NoError(t, err)
			payload = map[string]any{"access_token": input + "." + base64.RawURLEncoding.EncodeToString(signature), "token_type": "Bearer", "issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "expires_in": 180, "refresh_token": "DO-NOT-RELEASE-EXCHANGE-REFRESH"}
		default:
			return base.RoundTrip(request)
		}
		raw, err := json.Marshal(payload)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw)), Request: request}, nil
	})
	e.p.discoveryClient = &client
	return calls
}

func TestLegacyUpgradeBrokerUsesExistingOAuthClient(t *testing.T) {
	brokerKeys(t)
	e := legacyUpgradeLoginEnv(t, true)
	require.Equal(t, "mattermost", e.p.getConfiguration().ClientID)
	gate := bytes.Clone(e.kv[identityGateKey])
	runLegacyUpgradeWebLogin(t, e)
	assertLegacyUpgradeIdentity(t, e)
	calls := legacyUpgradeBrokerExchange(t, e, "mattermost")
	for _, scope := range []string{"plane.read", "plane.read plane.write"} {
		body, err := json.Marshal(map[string]string{"mm_user_id": testUserID, "audience": "plane-api", "scope": scope, "request_id": "upgrade-existing-oauth-client"})
		require.NoError(t, err)
		response := serveBroker(e.p, signedBrokerRequest(string(body), 0))
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		var output map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &output))
		require.Len(t, output, 2)
		require.NotEmpty(t, output["access_token"])
		require.NotEmpty(t, output["expires_at"])
		require.NotContains(t, response.Body.String(), "DO-NOT-RELEASE")
		require.Equal(t, gate, e.kv[identityGateKey], "broker use must not change the approved OAuth identity or require reapproval")
	}
	require.Equal(t, int32(2), calls.Load())
	require.Equal(t, "mattermost", e.p.getConfiguration().ClientID)
	require.Equal(t, 1, e.sessionCount())
	assertLegacyUpgradeIdentity(t, e)
}

func TestLegacyUpgradeBrokerRejectsSignedForeignAuthorizedParty(t *testing.T) {
	brokerKeys(t)
	e := legacyUpgradeLoginEnv(t, true)
	gate := bytes.Clone(e.kv[identityGateKey])
	runLegacyUpgradeWebLogin(t, e)
	calls := legacyUpgradeBrokerExchange(t, e, "mattermost-oidc")
	body := `{"mm_user_id":"` + testUserID + `","audience":"plane-api","scope":"plane.read","request_id":"upgrade-wrong-azp"}`
	response := serveBroker(e.p, signedBrokerRequest(body, 0))
	require.Equal(t, http.StatusServiceUnavailable, response.Code, response.Body.String())
	require.Equal(t, int32(1), calls.Load(), "reject the cryptographically valid token after checking its authorized party")
	require.NotContains(t, response.Body.String(), "access_token")
	require.Equal(t, gate, e.kv[identityGateKey])
	assertLegacyUpgradeIdentity(t, e)
}
