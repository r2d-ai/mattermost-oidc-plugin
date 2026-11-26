package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPlaneClaimsScopeCompatibility(t *testing.T) {
	for _, test := range []struct {
		name      string
		requested string
		issued    any
		reason    string
	}{
		{"read only", "plane.read", "plane.read", ""},
		{"standard OIDC", "plane.read", "openid profile email plane.read", ""},
		{"Keycloak defaults", "plane.read", "openid plane.read basic acr roles web-origins microprofile-jwt address phone", ""},
		{"write with profile", "plane.read plane.write", "profile plane.write openid plane.read email", ""},
		{"missing read", "plane.read", "openid profile", "claims_scope_missing"},
		{"missing write", "plane.read plane.write", "openid plane.read", "claims_scope_missing"},
		{"write on read request", "plane.read", "plane.read plane.write", "claims_scope_unexpected"},
		{"write without read", "plane.read plane.write", "plane.write openid", "claims_scope_missing"},
		{"unknown privilege", "plane.read", "plane.read plane.admin", "claims_scope_unexpected"},
		{"offline access scope", "plane.read", "plane.read offline_access", ""},
		{"custom non Plane scopes", "plane.read", "organization plane.read custom_reporting", ""},
		{"write with custom scopes", "plane.read plane.write", "custom_reporting plane.write plane.read organization offline_access", ""},
		{"custom scopes without read", "plane.read", "organization custom_reporting", "claims_scope_missing"},
		{"custom scopes cannot hide write", "plane.read", "organization plane.read custom_reporting plane.write", "claims_scope_unexpected"},
		{"custom scopes cannot hide unknown Plane permission", "plane.read", "organization plane.read plane.admin", "claims_scope_unexpected"},
		{"duplicate Plane scope", "plane.read", "plane.read plane.read", "claims_scope_duplicate"},
		{"duplicate identity scope", "plane.read", "openid plane.read openid", "claims_scope_duplicate"},
		{"duplicate custom scope", "plane.read", "organization plane.read organization", "claims_scope_duplicate"},
		{"nonASCII custom scope", "plane.read", "plane.read custom_雪", "claims_scope"},
		{"quoted custom scope", "plane.read", "plane.read custom\"report", "claims_scope"},
		{"backslash custom scope", "plane.read", "plane.read custom\\report", "claims_scope"},
		{"control in custom scope", "plane.read", "plane.read custom\x00report", "claims_scope"},
		{"array claim", "plane.read", []string{"plane.read"}, "claims_scope"},
		{"null claim", "plane.read", nil, "claims_scope_missing"},
		{"empty claim", "plane.read", "", "claims_scope_missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now()
			binding := IdentityBinding{Issuer: "https://issuer.example", Subject: "subject"}
			claims := map[string]any{"iss": binding.Issuer, "sub": binding.Subject, "azp": "mattermost", "typ": "Bearer", "aud": "plane-api", "scope": test.issued, "iat": now.Unix(), "exp": now.Unix() + 180}
			raw, err := json.Marshal(claims)
			require.NoError(t, err)
			_, err = verifyPlaneClaims(raw, binding, "mattermost", test.requested, now)
			if test.reason == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrTemporarilyUnavailable)
			var diagnostic *exchangeDiagnostic
			require.ErrorAs(t, err, &diagnostic)
			require.Equal(t, test.reason, diagnostic.reason)
		})
	}
}

func TestBrokerSignedSupplementalScopes(t *testing.T) {
	for _, test := range []struct {
		requested, issued string
		status            int
	}{
		{"plane.read", "openid plane.read profile email", 200},
		{"plane.read", "organization plane.read custom_reporting offline_access", 200},
		{"plane.read plane.write", "openid plane.read plane.write profile", 200},
		{"plane.read plane.write", "custom_reporting plane.read organization plane.write", 200},
		{"plane.read", "openid profile", 503},
		{"plane.read", "organization custom_reporting", 503},
		{"plane.read", "plane.read plane.admin custom_reporting", 503},
		{"plane.read", "plane.read plane.write profile", 503},
		{"plane.read plane.write", "plane.read profile", 503},
	} {
		t.Run(test.requested+"/"+test.issued, func(t *testing.T) {
			f := brokerFixtureForClient(t, "mattermost")
			f.claims = func(claims map[string]any) { claims["scope"] = test.issued }
			response := serveBroker(f.p, signedBrokerRequest(f.body(0, test.requested), 0))
			require.Equal(t, test.status, response.Code, response.Body.String())
			require.Equal(t, int32(1), f.calls.Load())
			if test.status != 200 {
				require.NotContains(t, response.Body.String(), "access_token")
			}
		})
	}
}
