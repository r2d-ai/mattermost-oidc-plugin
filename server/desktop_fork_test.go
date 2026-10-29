package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func desktopCaptureEnv(t *testing.T) *loginEnv {
	t.Helper()
	credentialKeys(t, "current", map[string]string{"current": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))})
	e := newLoginEnv(t, testSite)
	cfg := e.p.getConfiguration()
	cfg.EnableTokenPersistence, cfg.EnablePlaneBroker = true, true
	e.p.setConfiguration(cfg)
	return e
}

func desktopBinding(t *testing.T, e *loginEnv) ResolvedIdentity {
	t.Helper()
	binding, err := e.p.ResolveBrokerBinding(context.Background(), testUserID)
	require.NoError(t, err)
	return binding
}

func TestDesktopRedeemRechecksForkAuthority(t *testing.T) {
	cases := map[string]func(*testing.T, *loginEnv){
		"frozen": func(t *testing.T, e *loginEnv) { _, err := e.p.freezeIdentityGate(); require.NoError(t, err) },
		"epoch changed": func(t *testing.T, e *loginEnv) {
			var gate identityGate
			require.NoError(t, json.Unmarshal(e.kv[identityGateKey], &gate))
			gate.Epoch++
			e.kv[identityGateKey], _ = json.Marshal(gate)
		},
		"native auth changed": func(_ *testing.T, e *loginEnv) { e.user.AuthData = model.NewPointer("different") },
		"reverse removed":     func(_ *testing.T, e *loginEnv) { delete(e.kv, identityUserPrefix+testUserID) },
		"revision changed": func(t *testing.T, e *loginEnv) {
			var record identityRecord
			require.NoError(t, json.Unmarshal(e.kv[identityUserPrefix+testUserID], &record))
			record.Revision++
			raw, _ := json.Marshal(record)
			e.kv[identityUserPrefix+testUserID], e.kv[pairKey(record.Binding)] = raw, raw
		},
		"claim policy changed": func(t *testing.T, e *loginEnv) {
			cfg := e.p.getConfiguration()
			cfg.UsernameClaim = "nickname"
			e.p.setConfiguration(cfg)
			require.NoError(t, e.p.initOIDCProvider())
		},
		"client secret changed": func(t *testing.T, e *loginEnv) {
			cfg := e.p.getConfiguration()
			cfg.ClientSecret = "new-secret"
			e.p.setConfiguration(cfg)
			require.NoError(t, e.p.initOIDCProvider())
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newLoginEnv(t, testSite)
			_, link := e.desktopLogin("/")
			require.NotEmpty(t, link)
			mutate(t, e)
			result := e.redeem(codeFromLink(t, link), testVerifier)
			require.NotEqual(t, http.StatusOK, result.Code)
			require.Zero(t, e.sessionCount())
			for _, cookie := range result.Result().Cookies() {
				require.NotEqual(t, "MMAUTHTOKEN", cookie.Name)
			}
		})
	}
}

func TestDesktopCaptureOccursOnlyAtRedeem(t *testing.T) {
	e := desktopCaptureEnv(t)
	_, link := e.desktopLogin("/")
	require.NotEmpty(t, link)
	require.Zero(t, e.sessionCount())
	require.Empty(t, e.keys(credentialPrefix))
	for _, raw := range e.kv {
		require.NotContains(t, string(raw), "desktop-access-secret")
		require.NotContains(t, string(raw), "desktop-refresh-secret")
		require.NotContains(t, string(raw), e.idToken)
	}
	result := e.redeem(codeFromLink(t, link), testVerifier)
	require.Equal(t, http.StatusOK, result.Code)
	binding := desktopBinding(t, e)
	credentials, err := newCredentialStore(e.p).Load(context.Background(), binding.Binding)
	require.NoError(t, err)
	require.Equal(t, "desktop-access-secret", credentials.AccessToken)
	require.Equal(t, "desktop-refresh-secret", credentials.RefreshToken)
	require.WithinDuration(t, time.Now().Add(1800*time.Second), credentials.RefreshExpiresAt, 5*time.Second)
	require.WithinDuration(t, time.Now().Add(600*time.Second), credentials.AccessExpiresAt, 5*time.Second)
	require.NotContains(t, result.Body.String(), "desktop-access-secret")
	require.NotContains(t, result.Body.String(), "desktop-refresh-secret")
}

func TestDesktopHandoffRejectsExpiredAndLegacyRecords(t *testing.T) {
	for _, kind := range []string{"expired", "legacy"} {
		t.Run(kind, func(t *testing.T) {
			e := newLoginEnv(t, testSite)
			_, link := e.desktopLogin("/")
			code := codeFromLink(t, link)
			var record map[string]any
			require.NoError(t, json.Unmarshal(e.kv[desktopCodeKey(code)], &record))
			if kind == "expired" {
				record["expires_at"] = time.Now().Add(-time.Second).Unix()
			} else {
				record = map[string]any{"user_id": testUserID, "challenge": testChallenge, "return_to": "/"}
			}
			e.kv[desktopCodeKey(code)], _ = json.Marshal(record)
			require.Equal(t, http.StatusUnauthorized, e.redeem(code, testVerifier).Code)
			require.Zero(t, e.sessionCount())
		})
	}
}

func TestDesktopFailureRevokesOnlyNewSession(t *testing.T) {
	for _, kind := range []string{"authority", "fence"} {
		t.Run(kind, func(t *testing.T) {
			e := desktopCaptureEnv(t)
			_, link := e.desktopLogin("/")
			e.onSession = func() {
				if kind == "authority" {
					_, err := e.p.freezeIdentityGate()
					require.NoError(t, err)
				} else {
					e.onCAS = func(key string, _, _ []byte) *model.AppError {
						if strings.HasPrefix(key, credentialPrefix) {
							return failAPI()
						}
						return nil
					}
				}
			}
			result := e.redeem(codeFromLink(t, link), testVerifier)
			require.NotEqual(t, http.StatusOK, result.Code)
			require.Len(t, e.revoked, 1)
			require.Equal(t, map[string]bool{"preexisting-session": true}, e.activeSessions)
			for _, cookie := range result.Result().Cookies() {
				require.NotEqual(t, "MMAUTHTOKEN", cookie.Name)
			}
		})
	}
}

func TestDesktopHandoffCannotReplaceLaterCredentials(t *testing.T) {
	for _, kind := range []string{"disconnect", "new login"} {
		t.Run(kind, func(t *testing.T) {
			e := desktopCaptureEnv(t)
			_, link := e.desktopLogin("/")
			binding := desktopBinding(t, e)
			store := newCredentialStore(e.p)
			if kind == "disconnect" {
				require.NoError(t, store.Invalidate(context.Background(), binding.Binding))
			} else {
				require.NoError(t, store.Save(context.Background(), StoredCredentials{Binding: binding.Binding, GateEpoch: binding.GateEpoch, BindingRevision: binding.BindingRevision, AccessToken: "newer-access", RefreshToken: "newer-refresh", AccessExpiresAt: time.Now().Add(time.Hour)}))
			}
			before := bytes.Clone(e.kv[credentialKey(binding.Binding)])
			result := e.redeem(codeFromLink(t, link), testVerifier)
			require.NotEqual(t, http.StatusOK, result.Code)
			require.Equal(t, before, e.kv[credentialKey(binding.Binding)])
		})
	}
}

func TestDesktopOptionalCaptureFailureFencesOldCredentials(t *testing.T) {
	for _, kind := range []string{"missing key at callback", "key lost before redeem", "missing refresh", "tampered ciphertext", "publication failure"} {
		t.Run(kind, func(t *testing.T) {
			e := desktopCaptureEnv(t)
			binding := desktopBinding(t, e)
			store := newCredentialStore(e.p)
			require.NoError(t, store.Save(context.Background(), StoredCredentials{Binding: binding.Binding, GateEpoch: binding.GateEpoch, BindingRevision: binding.BindingRevision, AccessToken: "old-access", RefreshToken: "old-refresh", AccessExpiresAt: time.Now().Add(time.Hour)}))
			if kind == "missing key at callback" {
				t.Setenv("MM_OIDC_CREDENTIAL_KEYS", "")
			}
			if kind == "missing refresh" {
				e.refreshToken = ""
			}
			_, link := e.desktopLogin("/")
			require.NotEmpty(t, link)
			code := codeFromLink(t, link)
			if kind == "key lost before redeem" {
				t.Setenv("MM_OIDC_CREDENTIAL_KEYS", "")
			}
			if kind == "tampered ciphertext" {
				var record desktopCodeRecord
				require.NoError(t, json.Unmarshal(e.kv[desktopCodeKey(code)], &record))
				require.NotNil(t, record.Credentials)
				record.Credentials.Ciphertext[0] ^= 1
				e.kv[desktopCodeKey(code)], _ = json.Marshal(record)
			}
			if kind == "publication failure" {
				e.onCAS = func(key string, _, next []byte) *model.AppError {
					if strings.HasPrefix(key, credentialPrefix) && bytes.Contains(next, []byte(`"state":"ready"`)) {
						return failAPI()
					}
					return nil
				}
			}
			result := e.redeem(code, testVerifier)
			require.Equal(t, http.StatusOK, result.Code)
			env, _, err := store.read(binding.Binding)
			require.NoError(t, err)
			require.Equal(t, "invalidated", env.State)
			require.EqualValues(t, 2, env.Generation)
			require.Empty(t, e.revoked)
		})
	}
}

func TestDesktopDelayedCaptureCASCannotFenceConcurrentDisconnect(t *testing.T) {
	e := desktopCaptureEnv(t)
	_, link := e.desktopLogin("/")
	binding := desktopBinding(t, e)
	fired := false
	e.onCAS = func(key string, _, _ []byte) *model.AppError {
		if key == credentialKey(binding.Binding) && !fired {
			fired = true
			require.NoError(t, newCredentialStore(e.p).Invalidate(context.Background(), binding.Binding))
		}
		return nil
	}
	result := e.redeem(codeFromLink(t, link), testVerifier)
	require.NotEqual(t, http.StatusOK, result.Code)
	env, _, err := newCredentialStore(e.p).read(binding.Binding)
	require.NoError(t, err)
	require.Equal(t, "invalidated", env.State)
	require.EqualValues(t, 1, env.Generation)
	require.Len(t, e.revoked, 1)
}

func TestDesktopCancelledRedeemAndLostConsumeAcknowledgement(t *testing.T) {
	for _, kind := range []string{"cancelled", "lost consume acknowledgement"} {
		t.Run(kind, func(t *testing.T) {
			e := newLoginEnv(t, testSite)
			_, link := e.desktopLogin("/")
			code := codeFromLink(t, link)
			if kind == "lost consume acknowledgement" {
				key := desktopCodeKey(code)
				e.api.On("KVCompareAndDelete", key, mock.Anything).Unset()
				e.api.On("KVCompareAndDelete", key, mock.Anything).Return(func(key string, _ []byte) (bool, *model.AppError) { delete(e.kv, key); return false, failAPI() })
			}
			result := e.redeem(code, testVerifier, func(r *http.Request) {
				if kind == "cancelled" {
					ctx, cancel := context.WithCancel(r.Context())
					cancel()
					*r = *r.WithContext(ctx)
				}
			})
			require.NotEqual(t, http.StatusOK, result.Code)
			require.Zero(t, e.sessionCount())
			require.Equal(t, http.StatusUnauthorized, e.redeem(code, testVerifier).Code)
		})
	}
}

func TestDesktopPersistenceSwitchTiming(t *testing.T) {
	for _, kind := range []string{"enabled only at redeem", "disabled before redeem", "disabled during session"} {
		t.Run(kind, func(t *testing.T) {
			e := desktopCaptureEnv(t)
			binding := desktopBinding(t, e)
			store := newCredentialStore(e.p)
			require.NoError(t, store.Save(context.Background(), StoredCredentials{Binding: binding.Binding, GateEpoch: binding.GateEpoch, BindingRevision: binding.BindingRevision, AccessToken: "existing-access", RefreshToken: "existing-refresh", AccessExpiresAt: time.Now().Add(time.Hour)}))
			before := bytes.Clone(e.kv[credentialKey(binding.Binding)])
			setCapture := func(enabled bool) {
				cfg := e.p.getConfiguration()
				cfg.EnableTokenPersistence = enabled
				e.p.setConfiguration(cfg)
			}
			if kind == "enabled only at redeem" {
				setCapture(false)
			}
			_, link := e.desktopLogin("/")
			require.NotEmpty(t, link)
			switch kind {
			case "enabled only at redeem":
				setCapture(true)
			case "disabled before redeem":
				setCapture(false)
			case "disabled during session":
				e.onSession = func() { setCapture(false) }
			}
			require.Equal(t, http.StatusOK, e.redeem(codeFromLink(t, link), testVerifier).Code)
			require.Equal(t, before, e.kv[credentialKey(binding.Binding)], "a noncapturing login does not revoke or replace prior credentials")
			require.Empty(t, e.revoked)
			setCapture(true)
			credentials, err := store.Load(context.Background(), binding.Binding)
			require.NoError(t, err)
			require.Equal(t, "existing-access", credentials.AccessToken)
		})
	}
}
