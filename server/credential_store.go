package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"regexp"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
)

var (
	ErrCredentialsUnavailable = errors.New("delegated credentials unavailable; reconnect required")
	ErrCredentialFence        = errors.New("credential authority unavailable")
	credentialKeyID           = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

const credentialPrefix = "credentials_v1_"
const maxCredentialRecord = 65536

// StoredCredentials is secret-bearing memory. Never log or expose it to clients.
// A zero RefreshExpiresAt means the provider did not establish an expiry.
type StoredCredentials struct {
	Binding                           IdentityBinding
	AccessToken, RefreshToken         string
	AccessExpiresAt, RefreshExpiresAt time.Time
	Version                           uint64
	GateEpoch, BindingRevision        uint64
}

// credentialEnvelope is the single CAS authority shared with token lifecycle.
// Only format, encryption key ID and concurrency state are visible in KV.
// refreshing is reserved for the lifecycle's exclusive refresh ownership.
type credentialEnvelope struct {
	Format     int    `json:"format"`
	KeyID      string `json:"key_id,omitempty"`
	State      string `json:"state"`
	Generation uint64 `json:"generation"`
	Owner      string `json:"owner"`
	StartedAt  int64  `json:"started_at,omitempty"`
	Deadline   int64  `json:"deadline,omitempty"`
	Phase      string `json:"phase,omitempty"`
	Nonce      []byte `json:"nonce,omitempty"`
	Ciphertext []byte `json:"ciphertext,omitempty"`
}

type CredentialStore struct{ plugin *Plugin }

// Construction never requires a decrypt key: fencing must survive key loss.
func newCredentialStore(p *Plugin) *CredentialStore { return &CredentialStore{plugin: p} }

func credentialKey(b IdentityBinding) string {
	return credentialPrefix + digestJSON([]string{"mm-oidc-credentials-v1", b.Issuer, b.MattermostUserID})
}

func validCredentialBinding(b IdentityBinding) bool {
	return b.Issuer != "" && b.Subject != "" && model.IsValidId(b.MattermostUserID)
}

// Read external secrets on use so loss/rotation takes effect without a KV key
// fallback. Errors deliberately contain neither the supplied JSON nor key IDs.
func credentialKeyring() (string, map[string][]byte, error) {
	raw, active := os.Getenv("MM_OIDC_CREDENTIAL_KEYS"), os.Getenv("MM_OIDC_CREDENTIAL_ACTIVE_KEY_ID")
	if len(raw) == 0 || len(raw) > 16384 || !credentialKeyID.MatchString(active) {
		return "", nil, ErrCredentialsUnavailable
	}
	d := json.NewDecoder(bytes.NewBufferString(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return "", nil, ErrCredentialsUnavailable
	}
	keys := map[string][]byte{}
	for d.More() {
		tok, err = d.Token()
		id, ok := tok.(string)
		if err != nil || !ok || !credentialKeyID.MatchString(id) || len(keys) >= 16 {
			return "", nil, ErrCredentialsUnavailable
		}
		if _, exists := keys[id]; exists {
			return "", nil, ErrCredentialsUnavailable
		}
		var encoded string
		if d.Decode(&encoded) != nil || len(encoded) != 44 {
			return "", nil, ErrCredentialsUnavailable
		}
		key, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != encoded {
			return "", nil, ErrCredentialsUnavailable
		}
		keys[id] = key
	}
	if _, err = d.Token(); err != nil {
		return "", nil, ErrCredentialsUnavailable
	}
	if _, err = d.Token(); err != io.EOF || keys[active] == nil {
		return "", nil, ErrCredentialsUnavailable
	}
	return active, keys, nil
}

func (s *CredentialStore) read(b IdentityBinding) (credentialEnvelope, []byte, error) {
	raw, ae := s.plugin.API.KVGet(credentialKey(b))
	if ae != nil {
		return credentialEnvelope{}, nil, ErrCredentialFence
	}
	if len(raw) == 0 {
		return credentialEnvelope{}, nil, nil
	}
	var env credentialEnvelope
	if len(raw) > maxCredentialRecord || json.Unmarshal(raw, &env) != nil || env.Format != 1 || env.Generation == 0 || env.Owner == "" || len(env.Owner) > 128 || (env.State != "ready" && env.State != "refreshing" && env.State != "invalidated") {
		return credentialEnvelope{}, nil, ErrCredentialFence
	}
	return env, raw, nil
}

// fence advances the only credential generation. It does not require a key,
// active gate or native user, so explicit invalidation works after revocation.
func (s *CredentialStore) fence(ctx context.Context, b IdentityBinding) (credentialEnvelope, []byte, error) {
	if !validCredentialBinding(b) {
		return credentialEnvelope{}, nil, ErrCredentialFence
	}
	owner, err := generateRandomKey(16)
	if err != nil {
		return credentialEnvelope{}, nil, ErrCredentialFence
	}
	for attempt := 0; attempt < 32; attempt++ {
		if ctx.Err() != nil {
			return credentialEnvelope{}, nil, ErrCredentialFence
		}
		previous, raw, err := s.read(b)
		if err != nil || previous.Generation == math.MaxUint64 {
			return credentialEnvelope{}, nil, ErrCredentialFence
		}
		next := credentialEnvelope{Format: 1, State: "invalidated", Generation: previous.Generation + 1, Owner: owner}
		encoded, _ := json.Marshal(next)
		ok, ae := s.plugin.API.KVCompareAndSet(credentialKey(b), raw, encoded)
		if ae != nil {
			return credentialEnvelope{}, nil, ErrCredentialFence
		}
		if ok {
			return next, encoded, nil
		}
	}
	return credentialEnvelope{}, nil, ErrCredentialFence
}

func (s *CredentialStore) Invalidate(ctx context.Context, binding IdentityBinding) error {
	_, _, err := s.fence(ctx, binding)
	return err
}

// abandonPublication only fences this writer's exact ready bytes. A newer
// generation already fences this writer and must survive cleanup unchanged.
func (s *CredentialStore) abandonPublication(ctx context.Context, b IdentityBinding, owned credentialEnvelope, ready []byte) error {
	for attempt := 0; attempt < 32; attempt++ {
		if ctx.Err() != nil {
			return ErrCredentialFence
		}
		current, raw, err := s.read(b)
		if err != nil {
			return ErrCredentialFence
		}
		if current.Generation > owned.Generation {
			return nil
		}
		if current.Generation != owned.Generation || current.Owner != owned.Owner {
			return ErrCredentialFence
		}
		if current.State == "invalidated" {
			return nil
		}
		if !bytes.Equal(raw, ready) || current.Generation == math.MaxUint64 {
			return ErrCredentialFence
		}
		next := credentialEnvelope{Format: 1, State: "invalidated", Generation: current.Generation + 1, Owner: owned.Owner}
		encoded, _ := json.Marshal(next)
		ok, ae := s.plugin.API.KVCompareAndSet(credentialKey(b), raw, encoded)
		if ae != nil {
			return ErrCredentialFence
		}
		if ok {
			return nil
		}
	}
	return ErrCredentialFence
}

func credentialAAD(env credentialEnvelope, b IdentityBinding, epoch, revision uint64) []byte {
	// Gate epoch and revision stay inside ciphertext; current B0 authority supplies
	// their expected values on decrypt. Binding prevents moving ciphertext slots.
	material := []any{"mm-oidc-credential-envelope-v1", env.Format, env.KeyID, env.State, env.Generation, env.Owner, b, epoch, revision}
	if env.StartedAt != 0 || env.Deadline != 0 || env.Phase != "" {
		material = append(material, env.StartedAt, env.Deadline, env.Phase)
	}
	aad, _ := json.Marshal(material)
	return aad
}

func credentialAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrCredentialsUnavailable
	}
	return cipher.NewGCM(block)
}

func (s *CredentialStore) current(ctx context.Context, b IdentityBinding, epoch, revision uint64) (ResolvedIdentity, error) {
	r, err := s.plugin.ResolveBrokerBinding(ctx, b.MattermostUserID)
	if err != nil {
		return r, err
	}
	if r.Binding != b || r.GateEpoch != epoch || r.BindingRevision != revision {
		return r, ErrIdentityConflict
	}
	return r, s.plugin.AssertCurrentBinding(ctx, r)
}

func (s *CredentialStore) Save(ctx context.Context, credentials StoredCredentials) error {
	_, err := s.save(ctx, credentials)
	return err
}

type credentialPublication struct {
	envelope credentialEnvelope
	ready    []byte
}

func (s *CredentialStore) save(ctx context.Context, credentials StoredCredentials) (*credentialPublication, error) {
	if !s.plugin.getConfiguration().EnableTokenPersistence {
		return nil, ErrCredentialsUnavailable
	}
	r, err := s.current(ctx, credentials.Binding, credentials.GateEpoch, credentials.BindingRevision)
	if err != nil {
		return nil, err
	}
	env, fenced, err := s.fence(ctx, credentials.Binding)
	if err != nil {
		return nil, err
	}
	// From this point the previous ready generation is durably unusable.
	active, keys, err := credentialKeyring()
	if err != nil {
		return nil, err
	}
	if credentials.AccessToken == "" || len(credentials.AccessToken)+len(credentials.RefreshToken) > 32768 {
		return nil, ErrCredentialsUnavailable
	}
	aead, err := credentialAEAD(keys[active])
	if err != nil {
		return nil, ErrCredentialsUnavailable
	}
	credentials.Version = env.Generation
	plaintext, err := json.Marshal(credentials)
	if err != nil {
		return nil, ErrCredentialsUnavailable
	}
	env.State, env.KeyID = "ready", active
	env.Nonce = make([]byte, aead.NonceSize())
	if _, err = rand.Read(env.Nonce); err != nil {
		return nil, ErrCredentialsUnavailable
	}
	env.Ciphertext = aead.Seal(nil, env.Nonce, plaintext, credentialAAD(env, credentials.Binding, credentials.GateEpoch, credentials.BindingRevision))
	encoded, err := json.Marshal(env)
	if err != nil || len(encoded) > maxCredentialRecord {
		return nil, ErrCredentialsUnavailable
	}
	if err = s.plugin.AssertCurrentBinding(ctx, r); err != nil {
		return nil, err
	}
	if !s.plugin.getConfiguration().EnableTokenPersistence {
		return nil, ErrCredentialsUnavailable
	}
	ok, ae := s.plugin.API.KVCompareAndSet(credentialKey(credentials.Binding), fenced, encoded)
	if ae != nil {
		// A lost CAS response may have published ready. Confirm a new durable fence
		// before treating publication failure as optional for ordinary login.
		if err = s.abandonPublication(ctx, credentials.Binding, env, encoded); err != nil {
			return nil, ErrCredentialFence
		}
		return nil, ErrCredentialsUnavailable
	}
	if !ok {
		return nil, ErrCredentialsUnavailable
	}
	if err = s.plugin.AssertCurrentBinding(ctx, r); err != nil {
		if cleanupErr := s.abandonPublication(ctx, credentials.Binding, env, encoded); cleanupErr != nil {
			return nil, cleanupErr
		}
		return nil, err
	}
	return &credentialPublication{envelope: env, ready: encoded}, nil
}

func (s *CredentialStore) Load(ctx context.Context, binding IdentityBinding) (StoredCredentials, error) {
	var empty StoredCredentials
	cfg := s.plugin.getConfiguration()
	if !cfg.EnableTokenPersistence || !cfg.EnablePlaneBroker {
		return empty, ErrCredentialsUnavailable
	}
	r, err := s.plugin.ResolveBrokerBinding(ctx, binding.MattermostUserID)
	if err != nil || r.Binding != binding {
		return empty, ErrCredentialsUnavailable
	}
	env, raw, err := s.read(binding)
	if err != nil || env.State != "ready" {
		return empty, ErrCredentialsUnavailable
	}
	_, keys, err := credentialKeyring()
	if err != nil || keys[env.KeyID] == nil {
		return empty, ErrCredentialsUnavailable
	}
	aead, err := credentialAEAD(keys[env.KeyID])
	if err != nil || len(env.Nonce) != aead.NonceSize() {
		return empty, ErrCredentialsUnavailable
	}
	plain, err := aead.Open(nil, env.Nonce, env.Ciphertext, credentialAAD(env, binding, r.GateEpoch, r.BindingRevision))
	if err != nil {
		return empty, ErrCredentialsUnavailable
	}
	var c StoredCredentials
	if json.Unmarshal(plain, &c) != nil || c.Binding != binding || c.Version != env.Generation || c.GateEpoch != r.GateEpoch || c.BindingRevision != r.BindingRevision || c.AccessToken == "" {
		return empty, ErrCredentialsUnavailable
	}
	_, current, err := s.read(binding)
	if err != nil || !bytes.Equal(current, raw) || s.plugin.AssertCurrentBinding(ctx, r) != nil {
		return empty, ErrCredentialsUnavailable
	}
	cfg = s.plugin.getConfiguration()
	if !cfg.EnableTokenPersistence || !cfg.EnablePlaneBroker {
		return empty, ErrCredentialsUnavailable
	}
	return c, nil
}

// sealTransition authenticates lifecycle state/deadline changes with fresh nonces.
// It never publishes or advances the single durable generation on its own.
func (s *CredentialStore) sealTransition(c StoredCredentials, env credentialEnvelope) (credentialEnvelope, []byte, error) {
	active, keys, err := credentialKeyring()
	if err != nil {
		return env, nil, err
	}
	aead, err := credentialAEAD(keys[active])
	if err != nil {
		return env, nil, ErrCredentialsUnavailable
	}
	env.KeyID = active
	env.Nonce = make([]byte, aead.NonceSize())
	if _, err = rand.Read(env.Nonce); err != nil {
		return env, nil, ErrCredentialsUnavailable
	}
	c.Version = env.Generation
	plain, err := json.Marshal(c)
	if err != nil {
		return env, nil, ErrCredentialsUnavailable
	}
	env.Ciphertext = aead.Seal(nil, env.Nonce, plain, credentialAAD(env, c.Binding, c.GateEpoch, c.BindingRevision))
	raw, err := json.Marshal(env)
	if err != nil || len(raw) > maxCredentialRecord {
		return env, nil, ErrCredentialsUnavailable
	}
	return env, raw, nil
}
