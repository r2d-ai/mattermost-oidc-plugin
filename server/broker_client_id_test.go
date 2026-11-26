package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBrokerConfiguredClientPassesLocalAuthorization(t *testing.T) {
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
	require.NoError(t, newCredentialStore(p).Save(context.Background(), StoredCredentials{Binding: identity.Binding, AccessToken: "access", RefreshToken: "refresh", AccessExpiresAt: time.Now().Add(time.Hour), GateEpoch: identity.GateEpoch, BindingRevision: identity.BindingRevision}))
	providerReached := false
	p.discoveryClient = &http.Client{Transport: brokerRoundTripper(func(*http.Request) (*http.Response, error) {
		providerReached = true
		return nil, errors.New("test provider unavailable")
	})}
	p.initRouter()
	body := fmt.Sprintf(`{"mm_user_id":%q,"audience":"plane-api","scope":"plane.read","request_id":"custom-client"}`, identity.Binding.MattermostUserID)
	response := serveBroker(p, signedBrokerRequest(body, 0))
	require.Equal(t, 503, response.Code, response.Body.String())
	require.True(t, providerReached, "the approved configured client must pass local authorization and reach the provider")
	require.NotContains(t, response.Body.String(), "access_token")
}

func TestBrokerUsesApprovedConfiguredClientID(t *testing.T) {
	for _, clientID := range []string{"mattermost", "mattermost-oidc", "team-sso"} {
		t.Run(clientID, func(t *testing.T) {
			f := brokerFixtureForClient(t, clientID)
			result := serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read"), 0))
			require.Equal(t, 200, result.Code, result.Body.String())
			var response struct {
				AccessToken string `json:"access_token"`
			}
			require.NoError(t, json.Unmarshal(result.Body.Bytes(), &response))
			raw, err := base64.RawURLEncoding.DecodeString(strings.Split(response.AccessToken, ".")[1])
			require.NoError(t, err)
			var claims map[string]any
			require.NoError(t, json.Unmarshal(raw, &claims))
			require.Equal(t, clientID, claims["azp"])
			require.Equal(t, "plane-api", claims["aud"])
			require.Equal(t, "plane.read", claims["scope"])
			require.Equal(t, int32(1), f.calls.Load())
		})
	}
}

func TestBrokerConfiguredClientRejectsAnotherAuthorizedParty(t *testing.T) {
	for _, wrongClient := range []string{"mattermost-oidc", "another-client", ""} {
		t.Run(wrongClient, func(t *testing.T) {
			f := brokerFixtureForClient(t, "mattermost")
			f.claims = func(claims map[string]any) { claims["azp"] = wrongClient }
			result := serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read"), 0))
			require.Equal(t, 503, result.Code, result.Body.String())
			require.NotContains(t, result.Body.String(), "access_token")
			require.Equal(t, int32(1), f.calls.Load())
		})
	}
}

func TestBrokerClientChangeStillFreezesApprovedGate(t *testing.T) {
	f := brokerFixture(t)
	cfg := f.p.getConfiguration()
	cfg.ClientID = "changed-client"
	f.p.setConfiguration(cfg)
	result := serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read"), 0))
	require.Equal(t, 503, result.Code, result.Body.String())
	gate, _, err := f.p.readIdentityGate()
	require.NoError(t, err)
	require.Equal(t, "frozen", gate.Status)
	require.Zero(t, f.calls.Load())
}

type brokerStageAPI struct {
	*identityAPI
	fields map[string]any
}

func (a *brokerStageAPI) LogInfo(message string, values ...any) {
	if message != "Plane broker request" {
		return
	}
	a.fields = map[string]any{}
	for i := 0; i+1 < len(values); i += 2 {
		if key, ok := values[i].(string); ok {
			a.fields[key] = values[i+1]
		}
	}
}

func TestBrokerLogsSafeFailureStage(t *testing.T) {
	for _, stage := range []string{"integration_flags", "credential_keyring", "identity_binding", "subject_credentials", "token_exchange", "complete"} {
		t.Run(stage, func(t *testing.T) {
			f := brokerFixture(t)
			logger := &brokerStageAPI{identityAPI: f.a}
			f.p.SetAPI(logger)
			switch stage {
			case "integration_flags":
				cfg := f.p.getConfiguration()
				cfg.EnablePlaneBroker = false
				f.p.setConfiguration(cfg)
			case "credential_keyring":
				t.Setenv("MM_OIDC_CREDENTIAL_KEYS", "")
			case "identity_binding":
				delete(f.a.kv, identityUserPrefix+f.users[0].Binding.MattermostUserID)
			case "subject_credentials":
				delete(f.a.kv, credentialKey(f.users[0].Binding))
			case "token_exchange":
				f.status = 500
			}
			serveBroker(f.p, signedBrokerRequest(f.body(0, "plane.read"), 0))
			require.Equal(t, stage, logger.fields["stage"])
			for key := range logger.fields {
				require.Contains(t, []string{"actor_uuid", "request_id", "issuer_fingerprint", "operation", "outcome", "stage", "reason", "provider_http_status", "provider_error", "latency_ms"}, key)
			}
		})
	}
}
