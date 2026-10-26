package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

const brokerExternalPath = "/plugins/mattermost-oidc/internal/plane-token"
const brokerLocalPath = "/internal/plane-token"
const brokerSourcePlugin = "mattermost-plugin-plane"
const brokerNoncePrefix = "plane_nonce_v1_"
const brokerNonceSlots = 4096

var errBrokerSignature = errors.New("invalid caller signature")

type brokerHTTPBudgetKey struct{}
type brokerNonce struct {
	Digest  string `json:"digest"`
	Expires int64  `json:"expires"`
}
type brokerLimits struct {
	mu          sync.Mutex
	outstanding int
	minute      int64
	calls       int
	users       map[string]int
	sweep       uint16
}

func (p *Plugin) enterBroker() bool {
	p.broker.mu.Lock()
	defer p.broker.mu.Unlock()
	if p.broker.outstanding >= 8 {
		return false
	}
	p.broker.outstanding++
	return true
}
func (p *Plugin) leaveBroker() { p.broker.mu.Lock(); p.broker.outstanding--; p.broker.mu.Unlock() }

// Empty id charges integration quota; a validated id charges only that user.
func (p *Plugin) brokerRate(id string, now time.Time) bool {
	p.broker.mu.Lock()
	defer p.broker.mu.Unlock()
	minute := now.Unix() / 60
	if p.broker.minute != minute || p.broker.users == nil {
		p.broker.minute = minute
		p.broker.calls = 0
		p.broker.users = map[string]int{}
	}
	if id == "" {
		if p.broker.calls >= 120 {
			return false
		}
		p.broker.calls++
		return true
	}
	if p.broker.users[id] >= 10 || len(p.broker.users) >= 120 && p.broker.users[id] == 0 {
		return false
	}
	p.broker.users[id]++
	return true
}
func brokerKeyring() (string, map[string][]byte, error) {
	active, keys, e := externalKeyring(os.Getenv("MM_PLANE_BROKER_HMAC_KEYS"), os.Getenv("MM_PLANE_BROKER_HMAC_ACTIVE_KEY_ID"))
	if e != nil {
		return "", nil, ErrTemporarilyUnavailable
	}
	return active, keys, nil
}
func brokerTarget(r *http.Request) bool {
	if r.Method != http.MethodPost || r.URL.Path != brokerLocalPath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.Fragment != "" || r.URL.RawFragment != "" || r.URL.ForceQuery || r.URL.Opaque != "" {
		return false
	}
	source := r.Header.Values("Mattermost-Plugin-ID")
	if len(source) == 0 {
		return r.RequestURI == brokerExternalPath
	}
	return len(source) == 1 && source[0] == brokerSourcePlugin && r.RequestURI == ""
}
func brokerSignature(r *http.Request, body []byte, now time.Time) error {
	values := make([]string, 4)
	for i, name := range []string{"X-Plane-Key-Id", "X-Plane-Timestamp", "X-Plane-Nonce", "X-Plane-Signature"} {
		v := r.Header.Values(name)
		if len(v) != 1 {
			return errBrokerSignature
		}
		values[i] = v[0]
	}
	id, stamp, nonce, signature := values[0], values[1], values[2], values[3]
	if !credentialKeyID.MatchString(id) || len(stamp) < 1 || len(stamp) > 12 || len(nonce) != 43 || len(signature) != 64 {
		return errBrokerSignature
	}
	ts, e := strconv.ParseInt(stamp, 10, 64)
	if e != nil || strconv.FormatInt(ts, 10) != stamp || ts < now.Unix()-30 || ts > now.Unix()+30 {
		return errBrokerSignature
	}
	decoded, e := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if e != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != nonce {
		return errBrokerSignature
	}
	sig, e := hex.DecodeString(signature)
	if e != nil || hex.EncodeToString(sig) != signature {
		return errBrokerSignature
	}
	_, keys, e := brokerKeyring()
	if e != nil {
		return e
	}
	key := keys[id]
	if key == nil {
		return errBrokerSignature
	}
	sum := sha256.Sum256(body)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(r.Method + "\n" + brokerExternalPath + "\n" + hex.EncodeToString(sum[:]) + "\n" + stamp + "\n" + nonce))
	if !hmac.Equal(mac.Sum(nil), sig) {
		return errBrokerSignature
	}
	return nil
}
func nonceSlot(index uint16) string { return fmt.Sprintf("%s%04x", brokerNoncePrefix, index) }
func (p *Plugin) authenticateBroker(r *http.Request, body []byte, now time.Time) error {
	if !brokerTarget(r) {
		return errBrokerSignature
	}
	if e := brokerSignature(r, body, now); e != nil {
		return e
	}
	// Authenticate first, then charge integration capacity before allocating KV.
	if !p.brokerRate("", now) {
		return ErrTemporarilyUnavailable
	}
	digest := sha256.Sum256([]byte(r.Header.Get("X-Plane-Nonce")))
	encoded := hex.EncodeToString(digest[:])
	index := (uint16(digest[0])<<8 | uint16(digest[1])) % brokerNonceSlots
	key := nonceSlot(index)
	for range 4 {
		raw, ae := p.API.KVGet(key)
		if ae != nil {
			return ErrTemporarilyUnavailable
		}
		if len(raw) > 0 {
			var old brokerNonce
			if len(raw) > 256 || json.Unmarshal(raw, &old) != nil || len(old.Digest) != 64 || old.Expires <= 0 {
				return ErrTemporarilyUnavailable
			}
			if old.Expires > now.Unix() {
				if old.Digest == encoded {
					return errBrokerSignature
				}
				return ErrTemporarilyUnavailable
			}
		}
		// Reserve the whole-call budget plus integer-second rounding so even
		// a delayed durable ACK retains at least 120 seconds of replay state.
		expires := time.Now().Unix() + 131
		next, _ := json.Marshal(brokerNonce{encoded, expires})
		ok, ae := p.API.KVCompareAndSet(key, raw, next)
		if ae != nil {
			return ErrTemporarilyUnavailable
		}
		if ok {
			if time.Now().Unix()+120 > expires {
				return ErrTemporarilyUnavailable
			}
			p.cleanupBrokerNonces(now)
			return nil
		}
	}
	return ErrTemporarilyUnavailable
}

// Scan exactly four fixed slots per accepted request. Exact-byte deletion cannot
// erase a concurrent replacement; live slots are never evicted, even when full.
func (p *Plugin) cleanupBrokerNonces(now time.Time) {
	p.broker.mu.Lock()
	start := p.broker.sweep
	p.broker.sweep = (start + 4) % brokerNonceSlots
	p.broker.mu.Unlock()
	for i := range uint16(4) {
		key := nonceSlot((start + i) % brokerNonceSlots)
		raw, ae := p.API.KVGet(key)
		if ae != nil || len(raw) == 0 || len(raw) > 256 {
			continue
		}
		var old brokerNonce
		if json.Unmarshal(raw, &old) == nil && old.Expires > 0 && old.Expires <= now.Unix() {
			_, _ = p.API.KVCompareAndDelete(key, raw)
		}
	}
}
