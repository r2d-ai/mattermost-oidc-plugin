package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Start with only the data retained by the previous plugin, not an already
// approved gate or registry that would hide the upgrade regression.
func legacyUpgradeLoginEnv(t *testing.T, persistence bool) *loginEnv {
	t.Helper()
	e := newLoginEnv(t, testSite)
	for key := range e.kv {
		if key == identityGateKey || strings.HasPrefix(key, identityPairPrefix) || strings.HasPrefix(key, identityUserPrefix) {
			delete(e.kv, key)
		}
	}
	e.kv[KVOIDCUserPrefix+testSubject] = []byte(testUserID)
	blocked := e.get("/oauth2/connect")
	require.Equal(t, http.StatusServiceUnavailable, blocked.Code)
	require.Contains(t, blocked.Body.String(), "OIDC identity unavailable")
	require.Zero(t, e.sessionCount())
	require.Empty(t, e.keys(KVOAuthStatePrefix))
	e.api.On("KVList", mock.Anything, mock.Anything).Return(func(page, perPage int) ([]string, *model.AppError) {
		e.mu.Lock()
		defer e.mu.Unlock()
		keys := make([]string, 0, len(e.kv))
		for key := range e.kv {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		start := page * perPage
		if start >= len(keys) {
			return nil, nil
		}
		end := start + perPage
		if end > len(keys) {
			end = len(keys)
		}
		return keys[start:end], nil
	})
	actorID := model.NewId()
	e.api.On("GetUser", actorID).Return(&model.User{Id: actorID, Roles: "system_admin"}, nil)
	if persistence {
		credentialKeys(t, "current", map[string]string{"current": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))})
		cfg := e.p.getConfiguration()
		cfg.EnableTokenPersistence, cfg.EnablePlaneBroker = true, true
		e.p.setConfiguration(cfg)
	}
	require.NoError(t, e.p.approveLegacyUpgrade(actorID, e.p.getConfiguration().IssuerURL))
	return e
}

func runLegacyUpgradeWebLogin(t *testing.T, e *loginEnv) *httptest.ResponseRecorder {
	t.Helper()
	start := e.get("/oauth2/connect")
	require.Equal(t, http.StatusFound, start.Code, start.Body.String())
	callback := httptest.NewRequest(http.MethodGet, e.authorize(start.Header().Get("Location")), nil)
	for _, cookie := range start.Result().Cookies() {
		callback.AddCookie(cookie)
	}
	finish := e.do(callback)
	require.Equal(t, http.StatusFound, finish.Code, finish.Body.String())
	userCookie := ""
	for _, cookie := range finish.Result().Cookies() {
		if cookie.Name == "MMUSERID" {
			userCookie = cookie.Value
		}
	}
	require.Equal(t, testUserID, userCookie)
	return finish
}

func assertLegacyUpgradeIdentity(t *testing.T, e *loginEnv) ResolvedIdentity {
	t.Helper()
	identity, err := e.p.ResolveBrokerBinding(context.Background(), testUserID)
	require.NoError(t, err)
	require.Equal(t, testUserID, identity.Binding.MattermostUserID)
	require.Equal(t, testSubject, identity.Binding.Subject)
	require.Equal(t, e.p.getConfiguration().IssuerURL, identity.Binding.Issuer)
	require.Equal(t, LegacyRaw, identity.NativeAuthMode)
	require.Equal(t, testSubject, identity.ExpectedAuthData)
	require.Equal(t, AuthService, e.user.AuthService)
	require.Equal(t, testSubject, *e.user.AuthData)
	var pair, reverse identityRecord
	require.NoError(t, json.Unmarshal(e.kv[pairKey(identity.Binding)], &pair))
	require.NoError(t, json.Unmarshal(e.kv[identityUserPrefix+testUserID], &reverse))
	require.Equal(t, "committed", pair.State)
	require.Equal(t, pair, reverse)
	require.True(t, e.activeSessions["preexisting-session"])
	require.Empty(t, e.revoked)
	e.api.AssertNotCalled(t, "CreateUser", mock.Anything)
	e.api.AssertNotCalled(t, "UpdateUser", mock.Anything)
	e.api.AssertNotCalled(t, "GetUserByEmail", mock.Anything)
	return identity
}

func TestLegacyUpgradeWebCallbackKeepsExistingAccountAndSessions(t *testing.T) {
	for _, persistence := range []bool{false, true} {
		name := "ordinary login"
		if persistence {
			name = "delegated credentials enabled"
		}
		t.Run(name, func(t *testing.T) {
			e := legacyUpgradeLoginEnv(t, persistence)
			runLegacyUpgradeWebLogin(t, e)
			require.Equal(t, 1, e.sessionCount())
			identity := assertLegacyUpgradeIdentity(t, e)
			if persistence {
				credentials, err := newCredentialStore(e.p).Load(context.Background(), identity.Binding)
				require.NoError(t, err)
				require.Equal(t, "desktop-access-secret", credentials.AccessToken)
				require.Equal(t, "desktop-refresh-secret", credentials.RefreshToken)
				for _, raw := range e.kv {
					require.NotContains(t, string(raw), "desktop-access-secret")
					require.NotContains(t, string(raw), "desktop-refresh-secret")
					require.NotContains(t, string(raw), e.idToken)
				}
			}
			// The next login must use the same committed account and registry.
			first := bytes.Clone(e.kv[pairKey(identity.Binding)])
			runLegacyUpgradeWebLogin(t, e)
			require.Equal(t, 2, e.sessionCount())
			assertLegacyUpgradeIdentity(t, e)
			require.Equal(t, first, e.kv[pairKey(identity.Binding)])
		})
	}
}

func TestLegacyUpgradeDesktopCallbackKeepsExistingAccountAndSessions(t *testing.T) {
	e := legacyUpgradeLoginEnv(t, true)
	callback, link := e.desktopLogin("/team/town-square")
	require.Equal(t, http.StatusOK, callback.Code, callback.Body.String())
	require.NotEmpty(t, link)
	require.Zero(t, e.sessionCount(), "the browser callback must not create a Desktop session")
	assertLegacyUpgradeIdentity(t, e)
	require.Empty(t, e.keys(credentialPrefix), "credential capture occurs at app redemption")
	result := e.redeem(codeFromLink(t, link), testVerifier)
	require.Equal(t, http.StatusOK, result.Code, result.Body.String())
	require.Equal(t, 1, e.sessionCount())
	identity := assertLegacyUpgradeIdentity(t, e)
	credentials, err := newCredentialStore(e.p).Load(context.Background(), identity.Binding)
	require.NoError(t, err)
	require.Equal(t, "desktop-refresh-secret", credentials.RefreshToken)
	for _, raw := range e.kv {
		require.NotContains(t, string(raw), "desktop-access-secret")
		require.NotContains(t, string(raw), "desktop-refresh-secret")
		require.NotContains(t, string(raw), e.idToken)
	}
}
