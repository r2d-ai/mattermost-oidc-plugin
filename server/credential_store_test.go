package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/stretchr/testify/require"
)

func credentialKeys(t *testing.T, active string, keys map[string]string) {
	t.Helper()
	b, err := json.Marshal(keys)
	require.NoError(t, err)
	t.Setenv("MM_OIDC_CREDENTIAL_KEYS", string(b))
	t.Setenv("MM_OIDC_CREDENTIAL_ACTIVE_KEY_ID", active)
}

func credentialFixture(t *testing.T) (*Plugin, *identityAPI, ResolvedIdentity, *CredentialStore, StoredCredentials) {
	t.Helper()
	p, a, s := fixtureIdentity(t)
	cfg := p.getConfiguration()
	cfg.EnableTokenPersistence, cfg.EnablePlaneBroker = true, true
	p.setConfiguration(cfg)
	s.configuration = *cfg
	r, _, err := p.resolveVerifiedLogin(context.Background(), s, VerifiedLoginIdentity{Issuer: "https://a.example", Subject: "credential-subject"}, &OIDCUserInfo{Subject: "credential-subject", Email: "credential@example.com", Username: "credential"})
	require.NoError(t, err)
	credentialKeys(t, "current", map[string]string{"current": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))})
	c := StoredCredentials{Binding: r.Binding, AccessToken: "access-a", RefreshToken: "refresh-a", AccessExpiresAt: time.Now().Add(time.Hour).UTC(), GateEpoch: r.GateEpoch, BindingRevision: r.BindingRevision}
	return p, a, r, newCredentialStore(p), c
}

func TestCredentialsNeverPersistPlaintext(t *testing.T) {
	_, a, r, store, c := credentialFixture(t)
	require.NoError(t, store.Save(context.Background(), c))
	key := credentialKey(r.Binding)
	require.NotContains(t, key, r.Binding.Subject)
	require.NotContains(t, key, r.Binding.MattermostUserID)
	for k, b := range a.kv {
		if strings.HasPrefix(k, credentialPrefix) {
			for _, secret := range []string{"access-a", "refresh-a", r.Binding.Subject, r.Binding.Issuer, r.Binding.MattermostUserID} {
				require.NotContains(t, string(b), secret)
			}
		}
	}
	loaded, err := store.Load(context.Background(), r.Binding)
	require.NoError(t, err)
	require.Equal(t, c.Binding, loaded.Binding)
	require.Equal(t, "refresh-a", loaded.RefreshToken)
	require.Equal(t, c.AccessExpiresAt, loaded.AccessExpiresAt)
	require.True(t, loaded.RefreshExpiresAt.IsZero())
	require.Equal(t, uint64(1), loaded.Version)
}

func TestBindingTamperDenied(t *testing.T) {
	for _, mutation := range []string{"ciphertext", "nonce", "unknown_key", "refreshing", "format", "generation", "owner", "subject", "revision", "epoch", "native", "deleted", "bot"} {
		t.Run(mutation, func(t *testing.T) {
			_, a, r, store, c := credentialFixture(t)
			require.NoError(t, store.Save(context.Background(), c))
			key := credentialKey(r.Binding)
			var env credentialEnvelope
			require.NoError(t, json.Unmarshal(a.kv[key], &env))
			switch mutation {
			case "ciphertext":
				env.Ciphertext[0] ^= 1
			case "nonce":
				env.Nonce[0] ^= 1
			case "unknown_key":
				env.KeyID = "unknown"
			case "refreshing":
				env.State = "refreshing"
			case "format":
				env.Format++
			case "generation":
				env.Generation++
			case "owner":
				env.Owner = "other"
			case "subject":
				r.Binding.Subject = "other"
			case "revision":
				for k, v := range a.kv {
					if strings.HasPrefix(k, identityPairPrefix) || strings.HasPrefix(k, identityUserPrefix) {
						var rec identityRecord
						require.NoError(t, json.Unmarshal(v, &rec))
						rec.Revision++
						a.kv[k], _ = json.Marshal(rec)
					}
				}
			case "epoch":
				var g identityGate
				require.NoError(t, json.Unmarshal(a.kv[identityGateKey], &g))
				g.Epoch++
				a.kv[identityGateKey], _ = json.Marshal(g)
			case "native":
				a.users[r.Binding.MattermostUserID].AuthData = model.NewPointer("other")
			case "deleted":
				a.users[r.Binding.MattermostUserID].DeleteAt = 1
			case "bot":
				a.users[r.Binding.MattermostUserID].IsBot = true
			}
			a.kv[key], _ = json.Marshal(env)
			loaded, err := store.Load(context.Background(), r.Binding)
			require.Error(t, err)
			require.Empty(t, loaded.AccessToken)
		})
	}
}

func TestCredentialsConcurrentCapture(t *testing.T) {
	p, a, r, store, c := credentialFixture(t)
	q := &Plugin{}
	q.SetAPI(a)
	q.setConfiguration(p.getConfiguration())
	entered, release := make(chan struct{}, 2), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	a.beforeCAS = func(k string, old, next []byte) *model.AppError {
		if k == credentialKey(r.Binding) && len(old) == 0 {
			entered <- struct{}{}
			<-release
		}
		return nil
	}
	results := make(chan error, 2)
	for i, node := range []*CredentialStore{store, newCredentialStore(q)} {
		candidate := c
		candidate.AccessToken = []string{"node-one", "node-two"}[i]
		go func() { results <- node.Save(context.Background(), candidate) }()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("both writers did not reach the initial fence")
		}
	}
	unblock()
	successes := 0
	for range 2 {
		select {
		case err := <-results:
			if err == nil {
				successes++
			} else {
				require.ErrorIs(t, err, ErrCredentialsUnavailable)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("capture did not complete")
		}
	}
	require.GreaterOrEqual(t, successes, 1)
	loaded, err := store.Load(context.Background(), r.Binding)
	require.NoError(t, err)
	require.Contains(t, []string{"node-one", "node-two"}, loaded.AccessToken)
	require.Equal(t, uint64(2), loaded.Version)
}

func TestCredentialsCiphertextCannotMoveBetweenUsers(t *testing.T) {
	p, a, r, store, c := credentialFixture(t)
	require.NoError(t, store.Save(context.Background(), c))
	snapshot, err := p.currentLoginSnapshot(context.Background())
	require.NoError(t, err)
	other, _, err := p.resolveVerifiedLogin(context.Background(), snapshot, VerifiedLoginIdentity{Issuer: r.Binding.Issuer, Subject: "other-subject"}, &OIDCUserInfo{Subject: "other-subject", Email: "other@example.com", Username: "other-user"})
	require.NoError(t, err)
	a.kv[credentialKey(other.Binding)] = bytes.Clone(a.kv[credentialKey(r.Binding)])
	_, err = store.Load(context.Background(), other.Binding)
	require.ErrorIs(t, err, ErrCredentialsUnavailable)
}

func TestSameSubjectDifferentIssuerDenied(t *testing.T) {
	_, _, r, store, c := credentialFixture(t)
	require.NoError(t, store.Save(context.Background(), c))
	r.Binding.Issuer = "https://b.example"
	_, err := store.Load(context.Background(), r.Binding)
	require.Error(t, err)
}

func TestMissingKeyDeniesLoad(t *testing.T) {
	_, _, r, store, c := credentialFixture(t)
	require.NoError(t, store.Save(context.Background(), c))
	t.Setenv("MM_OIDC_CREDENTIAL_KEYS", "{}")
	_, err := store.Load(context.Background(), r.Binding)
	require.ErrorIs(t, err, ErrCredentialsUnavailable)
	require.NoError(t, store.Invalidate(context.Background(), r.Binding))
}

func TestCredentialsFenceBeforeOptionalFailure(t *testing.T) {
	for _, failure := range []string{"missing_key", "publication", "fence"} {
		t.Run(failure, func(t *testing.T) {
			_, a, r, store, c := credentialFixture(t)
			require.NoError(t, store.Save(context.Background(), c))
			switch failure {
			case "missing_key":
				t.Setenv("MM_OIDC_CREDENTIAL_KEYS", "{}")
			case "publication":
				a.beforeCAS = func(k string, old, next []byte) *model.AppError {
					if k == credentialKey(r.Binding) && bytes.Contains(next, []byte(`"state":"ready"`)) {
						return failAPI()
					}
					return nil
				}
			case "fence":
				a.failKey = credentialPrefix
			}
			err := store.Save(context.Background(), c)
			require.Error(t, err)
			if failure == "fence" {
				require.ErrorIs(t, err, ErrCredentialFence)
				return
			}
			require.ErrorIs(t, err, ErrCredentialsUnavailable)
			credentialKeys(t, "current", map[string]string{"current": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))})
			_, err = store.Load(context.Background(), r.Binding)
			require.Error(t, err, "old ready generation must be unavailable after optional capture failure")
			var env credentialEnvelope
			require.NoError(t, json.Unmarshal(a.kv[credentialKey(r.Binding)], &env))
			require.Equal(t, uint64(2), env.Generation)
			require.Equal(t, "invalidated", env.State)
		})
	}
}

func TestCredentialsRotationAndFreshNonce(t *testing.T) {
	_, a, r, store, c := credentialFixture(t)
	require.NoError(t, store.Save(context.Background(), c))
	var first credentialEnvelope
	require.NoError(t, json.Unmarshal(a.kv[credentialKey(r.Binding)], &first))
	keys := map[string]string{"current": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "next": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))}
	credentialKeys(t, "next", keys)
	_, err := store.Load(context.Background(), r.Binding)
	require.NoError(t, err)
	require.NoError(t, store.Save(context.Background(), c))
	var next credentialEnvelope
	require.NoError(t, json.Unmarshal(a.kv[credentialKey(r.Binding)], &next))
	require.Equal(t, "next", next.KeyID)
	require.NotEqual(t, first.Nonce, next.Nonce)
	require.Equal(t, uint64(2), next.Generation)
	require.NoError(t, store.Invalidate(context.Background(), r.Binding))
	require.NoError(t, store.Save(context.Background(), c))
	loaded, err := store.Load(context.Background(), r.Binding)
	require.NoError(t, err)
	require.Equal(t, uint64(4), loaded.Version)
}

func TestCredentialsInvalidateWithFrozenGateAndNoKey(t *testing.T) {
	p, _, r, store, c := credentialFixture(t)
	require.NoError(t, store.Save(context.Background(), c))
	_, err := p.freezeIdentityGate()
	require.NoError(t, err)
	t.Setenv("MM_OIDC_CREDENTIAL_KEYS", "bad")
	require.NoError(t, store.Invalidate(context.Background(), r.Binding))
}

func TestLegacyLoginRequiresReconnect(t *testing.T) {
	_, _, r, store, _ := credentialFixture(t)
	_, err := store.Load(context.Background(), r.Binding)
	require.ErrorIs(t, err, ErrCredentialsUnavailable)
}

func TestCredentialsKeyringRejectsMalformed(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	for _, raw := range []string{"", "null", "[]", `{"key":"no"}`, `{"key":"` + base64.StdEncoding.EncodeToString([]byte("short")) + `"}`, `{"key":"` + valid + `","key":"` + valid + `"}`, `{"bad id":"` + valid + `"}`, `{"key":"` + valid + `"} trailing`} {
		t.Run(raw, func(t *testing.T) {
			_, _, _, store, c := credentialFixture(t)
			t.Setenv("MM_OIDC_CREDENTIAL_KEYS", raw)
			t.Setenv("MM_OIDC_CREDENTIAL_ACTIVE_KEY_ID", "key")
			err := store.Save(context.Background(), c)
			require.True(t, errors.Is(err, ErrCredentialsUnavailable))
		})
	}
}

func TestCredentialsAmbiguousPublication(t *testing.T) {
	for _, mode := range []string{"committed_error", "newer_save", "unavailable_read"} {
		t.Run(mode, func(t *testing.T) {
			_, a, r, store, c := credentialFixture(t)
			require.NoError(t, store.Save(context.Background(), c))
			triggered := false
			a.beforeCAS = func(k string, old, next []byte) *model.AppError {
				if triggered || k != credentialKey(r.Binding) || !bytes.Contains(next, []byte(`"state":"ready"`)) {
					return nil
				}
				triggered = true
				switch mode {
				case "committed_error":
					a.mu.Lock()
					a.kv[k] = bytes.Clone(next)
					a.mu.Unlock()
				case "newer_save":
					newer := c
					newer.AccessToken = "newer-access"
					require.NoError(t, store.Save(context.Background(), newer))
				case "unavailable_read":
					a.readFail = true
				}
				return failAPI()
			}
			err := store.Save(context.Background(), c)
			require.Error(t, err)
			if mode == "unavailable_read" {
				require.ErrorIs(t, err, ErrCredentialFence)
				return
			}
			require.ErrorIs(t, err, ErrCredentialsUnavailable)
			loaded, err := store.Load(context.Background(), r.Binding)
			if mode == "newer_save" {
				require.NoError(t, err)
				require.Equal(t, "newer-access", loaded.AccessToken)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestCredentialsDisabledDeniesWarmSlot(t *testing.T) {
	p, _, r, store, c := credentialFixture(t)
	require.NoError(t, store.Save(context.Background(), c))
	for _, flag := range []string{"persistence", "broker"} {
		cfg := p.getConfiguration()
		cfg.EnablePlaneBroker, cfg.EnableTokenPersistence = true, true
		if flag == "persistence" {
			cfg.EnableTokenPersistence = false
		} else {
			cfg.EnablePlaneBroker = false
		}
		p.setConfiguration(cfg)
		_, err := store.Load(context.Background(), r.Binding)
		require.ErrorIs(t, err, ErrCredentialsUnavailable)
	}
}
