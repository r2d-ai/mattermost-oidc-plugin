package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
)

const (
	KVDesktopCodePrefix = "oidc_desktop_code_"
	desktopCodeExpiry   = 120 * time.Second
)

var (
	desktopChallengeRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	desktopCodeRe      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// The code is temporary transport for a verified login, never identity authority
// by itself. Provider credentials are optional and encrypted with external keys.
type desktopCodeRecord struct {
	UserID               string              `json:"user_id"`
	Challenge            string              `json:"challenge"`
	ReturnTo             string              `json:"return_to"`
	Identity             ResolvedIdentity    `json:"identity"`
	CallbackFingerprint  string              `json:"callback_fingerprint"`
	ExpiresAt            int64               `json:"expires_at"`
	CredentialGeneration *uint64             `json:"credential_generation,omitempty"`
	Credentials          *desktopCredentials `json:"credentials,omitempty"`
}

type desktopCredentials struct {
	KeyID      string `json:"key_id"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func desktopCodeKey(code string) string {
	sum := sha256.Sum256([]byte(code))
	return KVDesktopCodePrefix + hex.EncodeToString(sum[:])
}

func desktopCredentialAAD(key string, record desktopCodeRecord, keyID string) []byte {
	record.Credentials = nil
	raw, _ := json.Marshal([]any{"mm-oidc-desktop-credentials-v1", key, record, keyID})
	return raw
}

func sealDesktopCredentials(key string, record desktopCodeRecord, credentials *StoredCredentials) *desktopCredentials {
	active, keys, err := credentialKeyring()
	if err != nil {
		return nil
	}
	aead, err := credentialAEAD(keys[active])
	if err != nil {
		return nil
	}
	plain, err := json.Marshal(credentials)
	if err != nil || len(plain) > 32768 {
		return nil
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil
	}
	return &desktopCredentials{KeyID: active, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plain, desktopCredentialAAD(key, record, active))}
}

// Missing/unusable optional data still goes through the store's durable fence
// before login can continue without capture. No key or plaintext fallback exists.
func openDesktopCredentials(key string, record desktopCodeRecord) *StoredCredentials {
	if record.CredentialGeneration == nil {
		return nil
	}
	empty := &StoredCredentials{Binding: record.Identity.Binding, GateEpoch: record.Identity.GateEpoch, BindingRevision: record.Identity.BindingRevision}
	sealed := record.Credentials
	if sealed == nil {
		return empty
	}
	_, keys, err := credentialKeyring()
	if err != nil {
		return empty
	}
	aead, err := credentialAEAD(keys[sealed.KeyID])
	if err != nil || len(sealed.Nonce) != aead.NonceSize() || len(sealed.Ciphertext) > maxCredentialRecord {
		return empty
	}
	plain, err := aead.Open(nil, sealed.Nonce, sealed.Ciphertext, desktopCredentialAAD(key, record, sealed.KeyID))
	if err != nil {
		return empty
	}
	var credentials StoredCredentials
	if json.Unmarshal(plain, &credentials) != nil || credentials.Binding != empty.Binding || credentials.GateEpoch != empty.GateEpoch || credentials.BindingRevision != empty.BindingRevision {
		return empty
	}
	return &credentials
}

func (p *Plugin) issueDesktopCode(ctx context.Context, w http.ResponseWriter, state *OAuthState, snapshot *LoginSnapshot, identity ResolvedIdentity, credentials *StoredCredentials) {
	fail := func() { p.renderError(w, "Identity unavailable. Please try again.") }
	siteURL, err := url.Parse(strings.TrimRight(p.getSiteURL(), "/"))
	if err != nil || siteURL.Host == "" {
		fail()
		return
	}
	code, err := generateRandomKey(32)
	if err != nil {
		fail()
		return
	}
	key := desktopCodeKey(code)
	record := desktopCodeRecord{UserID: identity.Binding.MattermostUserID, Challenge: state.DesktopChallenge, ReturnTo: safeReturnTo(state.ReturnTo), Identity: identity, CallbackFingerprint: snapshot.CallbackFingerprint, ExpiresAt: time.Now().Add(desktopCodeExpiry).Unix()}
	if p.getConfiguration().EnableTokenPersistence {
		env, _, err := newCredentialStore(p).read(identity.Binding)
		if err != nil {
			fail()
			return
		}
		record.CredentialGeneration = &env.Generation
		record.Credentials = sealDesktopCredentials(key, record, credentials)
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > maxCredentialRecord || p.assertLoginSnapshot(ctx, snapshot) != nil || p.AssertCurrentBinding(ctx, identity) != nil {
		fail()
		return
	}
	if appErr := p.API.KVSetWithExpiry(key, raw, int64(desktopCodeExpiry.Seconds())); appErr != nil {
		fail()
		return
	}
	if p.assertLoginSnapshot(ctx, snapshot) != nil || p.AssertCurrentBinding(ctx, identity) != nil {
		_, _ = p.API.KVCompareAndDelete(key, raw)
		fail()
		return
	}
	// Built from configured SiteURL, never request host or forwarding headers.
	p.renderAppRedirect(w, "mattermost://"+siteURL.Host+siteURL.Path+"/login?desktop_code="+code)
}

func (p *Plugin) handleDesktopRedeem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if !p.getConfiguration().Enable {
		http.Error(w, "OIDC authentication is not enabled", http.StatusBadRequest)
		return
	}
	if !originMatchesSite(r.Header.Get("Origin"), p.getSiteURL()) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusBadRequest)
		return
	}
	var req struct {
		Code     string `json:"code"`
		Verifier string `json:"verifier"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || decoder.Decode(new(any)) != io.EOF || !desktopCodeRe.MatchString(req.Code) || !desktopChallengeRe.MatchString(req.Verifier) {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	user, record, snapshot := p.redeemDesktopCode(ctx, req.Code, req.Verifier)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	credentials := openDesktopCredentials(desktopCodeKey(req.Code), *record)
	session, _, err := p.createLoginSession(r.WithContext(ctx), user, snapshot, record.Identity, credentials, record.CredentialGeneration, false)
	if err != nil {
		http.Error(w, "Identity unavailable", http.StatusServiceUnavailable)
		return
	}
	p.setSessionCookie(w, r, session, p.getSiteURL())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"return_to": sitePath(p.getSiteURL()) + safeReturnTo(record.ReturnTo)})
}

func (p *Plugin) redeemDesktopCode(ctx context.Context, code, verifier string) (*model.User, *desktopCodeRecord, *LoginSnapshot) {
	raw, err := p.consumeKV(desktopCodeKey(code))
	if err != nil || len(raw) > maxCredentialRecord {
		return nil, nil, nil
	}
	var record desktopCodeRecord
	if json.Unmarshal(raw, &record) != nil || record.ExpiresAt <= time.Now().Unix() || record.ExpiresAt > time.Now().Add(desktopCodeExpiry).Unix() || record.UserID != record.Identity.Binding.MattermostUserID {
		return nil, nil, nil
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(challenge), []byte(record.Challenge)) != 1 {
		return nil, nil, nil
	}
	snapshot, err := p.currentLoginSnapshot(ctx)
	if err != nil || snapshot.CallbackFingerprint != record.CallbackFingerprint || snapshot.GateEpoch != record.Identity.GateEpoch || snapshot.IdentityFingerprint != record.Identity.IdentityFingerprint || p.AssertCurrentBinding(ctx, record.Identity) != nil {
		return nil, nil, nil
	}
	user, appErr := p.API.GetUser(record.UserID)
	if appErr != nil || user == nil {
		return nil, nil, nil
	}
	return user, &record, snapshot
}

// siteOrigin returns rawURL's origin as browsers serialize it in the Origin header:
// lowercase scheme and host, port only if it is not the default one.
func siteOrigin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return ""
	}
	scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	if strings.Contains(host, ":") { // IPv6 literal
		host = "[" + host + "]"
	}
	if port == "" || (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return scheme + "://" + host
	}
	return scheme + "://" + host + ":" + port
}

// originMatchesSite reports whether the Origin header value is the origin of the configured SiteURL.
func originMatchesSite(origin, siteURL string) bool {
	want := siteOrigin(siteURL)
	return want != "" && siteOrigin(origin) == want
}

// sitePath returns the subpath SiteURL is served under ("" for the root), without a trailing slash.
func sitePath(siteURL string) string {
	u, err := url.Parse(siteURL)
	if err != nil {
		return ""
	}
	return strings.TrimRight(u.Path, "/")
}
