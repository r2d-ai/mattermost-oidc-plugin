package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testBrokerPath = "/plugins/mattermost-oidc/internal/plane-token"

var testBrokerNonceSlot atomic.Uint32

var testBrokerKey = bytes.Repeat([]byte{19}, 32)

func brokerKeys(t *testing.T) {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"current": base64.StdEncoding.EncodeToString(testBrokerKey)})
	t.Setenv("MM_PLANE_BROKER_HMAC_KEYS", string(raw))
	t.Setenv("MM_PLANE_BROKER_HMAC_ACTIVE_KEY_ID", "current")
}
func signedBrokerRequest(body string, offset int64) *http.Request {
	r := httptest.NewRequest("POST", testBrokerPath, strings.NewReader(body))
	r.URL.Path = "/internal/plane-token"
	nonce := make([]byte, 32)
	// Avoid probabilistic slot collisions in tests not exercising capacity.
	target := uint16(testBrokerNonceSlot.Add(1) % brokerNonceSlots)
	for {
		_, _ = rand.Read(nonce)
		encoded := base64.RawURLEncoding.EncodeToString(nonce)
		digest := sha256.Sum256([]byte(encoded))
		if (uint16(digest[0])<<8|uint16(digest[1]))%brokerNonceSlots == target {
			r.Header.Set("X-Plane-Nonce", encoded)
			break
		}
	}
	r.Header.Set("X-Plane-Timestamp", strconv.FormatInt(time.Now().Unix()+offset, 10))
	r.Header.Set("X-Plane-Key-Id", "current")
	resignBrokerRequest(r, body, testBrokerKey)
	return r
}
func resignBrokerRequest(r *http.Request, body string, key []byte) {
	sum := sha256.Sum256([]byte(body))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(r.Method + "\n" + testBrokerPath + "\n" + hex.EncodeToString(sum[:]) + "\n" + r.Header.Get("X-Plane-Timestamp") + "\n" + r.Header.Get("X-Plane-Nonce")))
	r.Header.Set("X-Plane-Signature", hex.EncodeToString(mac.Sum(nil)))
}
func serveBroker(p *Plugin, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	p.ServeHTTP(&plugin.Context{}, w, r)
	return w
}
func TestBrokerRejectsUnsignedForgedUserHeader(t *testing.T) {
	p, _, _ := fixtureIdentity(t)
	p.initRouter()
	brokerKeys(t)
	r := signedBrokerRequest(`{}`, 0)
	r.Header.Del("X-Plane-Signature")
	r.Header.Set("Mattermost-User-Id", "forged")
	w := serveBroker(p, r)
	require.Equal(t, 401, w.Code)
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.JSONEq(t, `{"error":"invalid_signature","request_id":""}`, w.Body.String())
}
func TestBrokerSignatureBindsBodyPathAndMethod(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){"body": func(r *http.Request) { r.Body = http.NoBody }, "method": func(r *http.Request) { r.Method = "GET" }, "path": func(r *http.Request) { r.RequestURI += "/" }, "query": func(r *http.Request) { r.RequestURI += "?access_token=secret" }, "bare_query": func(r *http.Request) { r.RequestURI += "?" }, "escaped": func(r *http.Request) { r.RequestURI = "/plugins/mattermost-oidc/internal/%70lane-token" }, "unknown_key": func(r *http.Request) { r.Header.Set("X-Plane-Key-Id", "unknown") }, "duplicate": func(r *http.Request) { r.Header.Add("X-Plane-Signature", r.Header.Get("X-Plane-Signature")) }} {
		t.Run(name, func(t *testing.T) {
			p, _, _ := fixtureIdentity(t)
			p.initRouter()
			brokerKeys(t)
			r := signedBrokerRequest(`{}`, 0)
			mutate(r)
			require.Contains(t, []int{400, 401}, serveBroker(p, r).Code)
		})
	}
}
func TestBrokerTimestampBoundary(t *testing.T) {
	brokerKeys(t)
	p, _, _ := fixtureIdentity(t)
	for _, offset := range []int64{-31, -30, 30, 31} {
		r := signedBrokerRequest(`{}`, offset)
		now, _ := strconv.ParseInt(r.Header.Get("X-Plane-Timestamp"), 10, 64)
		err := p.authenticateBroker(r, []byte(`{}`), time.Unix(now-offset, 0))
		if offset == 31 || offset == -31 {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}
func TestBrokerReplayAcrossNodesAndRestart(t *testing.T) {
	brokerKeys(t)
	p, a, _ := fixtureIdentity(t)
	r := signedBrokerRequest(`{}`, 0)
	require.NoError(t, p.authenticateBroker(r, []byte(`{}`), time.Now()))
	for range 2 {
		q := &Plugin{}
		q.SetAPI(a)
		require.ErrorIs(t, q.authenticateBroker(r, []byte(`{}`), time.Now()), errBrokerSignature)
	}
	raw, _ := json.Marshal(map[string]string{"current": base64.StdEncoding.EncodeToString(testBrokerKey), "alias": base64.StdEncoding.EncodeToString(testBrokerKey)})
	t.Setenv("MM_PLANE_BROKER_HMAC_KEYS", string(raw))
	r.Header.Set("X-Plane-Key-Id", "alias")
	require.ErrorIs(t, p.authenticateBroker(r, []byte(`{}`), time.Now()), errBrokerSignature)
}
func TestBrokerKeyRotationRejectsRetiredKey(t *testing.T) {
	brokerKeys(t)
	p, _, _ := fixtureIdentity(t)
	next := bytes.Repeat([]byte{20}, 32)
	raw, _ := json.Marshal(map[string]string{"current": base64.StdEncoding.EncodeToString(testBrokerKey), "next": base64.StdEncoding.EncodeToString(next)})
	t.Setenv("MM_PLANE_BROKER_HMAC_KEYS", string(raw))
	t.Setenv("MM_PLANE_BROKER_HMAC_ACTIVE_KEY_ID", "next")
	require.NoError(t, p.authenticateBroker(signedBrokerRequest(`{}`, 0), []byte(`{}`), time.Now()))
	raw, _ = json.Marshal(map[string]string{"next": base64.StdEncoding.EncodeToString(next)})
	t.Setenv("MM_PLANE_BROKER_HMAC_KEYS", string(raw))
	require.ErrorIs(t, p.authenticateBroker(signedBrokerRequest(`{}`, 0), []byte(`{}`), time.Now()), errBrokerSignature)
}

func TestBrokerReplayCapacityAndFailure(t *testing.T) {
	brokerKeys(t)
	p, a, _ := fixtureIdentity(t)
	now := time.Now()
	for i := range uint16(brokerNonceSlots) {
		a.kv[nonceSlot(i)], _ = json.Marshal(brokerNonce{strings.Repeat("a", 64), now.Unix() + 120})
	}
	r := signedBrokerRequest(`{}`, 0)
	require.ErrorIs(t, p.authenticateBroker(r, []byte(`{}`), now), ErrTemporarilyUnavailable)
	require.Len(t, a.kv, brokerNonceSlots+1)
	a.readFail = true
	require.ErrorIs(t, p.authenticateBroker(r, []byte(`{}`), now), ErrTemporarilyUnavailable)
	a.readFail = false
	a.kv = map[string][]byte{}
	a.failKey = brokerNoncePrefix
	require.ErrorIs(t, p.authenticateBroker(r, []byte(`{}`), now), ErrTemporarilyUnavailable)
	a.failKey = ""
	// Ambiguous durable acknowledgement denies but preserves the claim for restart.
	a.beforeCAS = func(k string, old, next []byte) *model.AppError {
		if strings.HasPrefix(k, brokerNoncePrefix) {
			a.mu.Lock()
			a.kv[k] = bytes.Clone(next)
			a.mu.Unlock()
			return failAPI()
		}
		return nil
	}
	require.ErrorIs(t, p.authenticateBroker(r, []byte(`{}`), now), ErrTemporarilyUnavailable)
	a.beforeCAS = nil
	require.ErrorIs(t, p.authenticateBroker(r, []byte(`{}`), now), errBrokerSignature)
}
func TestBrokerNonceRetentionAndCleanup(t *testing.T) {
	brokerKeys(t)
	p, a, _ := fixtureIdentity(t)
	now := time.Now()
	r := signedBrokerRequest(`{}`, 0)
	require.NoError(t, p.authenticateBroker(r, []byte(`{}`), now))
	var key string
	for k := range a.kv {
		if strings.HasPrefix(k, brokerNoncePrefix) {
			key = k
		}
	}
	require.NotEmpty(t, key)
	var nonce brokerNonce
	require.NoError(t, json.Unmarshal(a.kv[key], &nonce))
	require.GreaterOrEqual(t, nonce.Expires, now.Unix()+120)
	p.broker.sweep = 0
	for range brokerNonceSlots / 4 {
		p.cleanupBrokerNonces(now.Add(119 * time.Second))
	}
	require.NotEmpty(t, a.kv[key])
	for range brokerNonceSlots / 4 {
		p.cleanupBrokerNonces(now.Add(132 * time.Second))
	}
	require.Empty(t, a.kv[key])
}
func TestBrokerNodeLimits(t *testing.T) {
	p := &Plugin{}
	for range 8 {
		require.True(t, p.enterBroker())
	}
	require.False(t, p.enterBroker())
	p.leaveBroker()
	require.True(t, p.enterBroker())
	now := time.Now()
	for range 10 {
		require.True(t, p.brokerRate("", now))
		require.True(t, p.brokerRate("alice", now))
	}
	require.False(t, p.brokerRate("alice", now))
	for i := range 110 {
		require.True(t, p.brokerRate("", now))
		require.True(t, p.brokerRate(strconv.Itoa(i), now))
	}
	require.False(t, p.brokerRate("", now))
	require.True(t, p.brokerRate("alice", now.Add(time.Minute)))
}
func TestBrokerInternalTransport(t *testing.T) {
	brokerKeys(t)
	p, _, _ := fixtureIdentity(t)
	r := signedBrokerRequest(`{}`, 0)
	r.RequestURI = ""
	require.Error(t, p.authenticateBroker(r, []byte(`{}`), time.Now()))
	r.Header.Set("Mattermost-Plugin-ID", "other")
	require.Error(t, p.authenticateBroker(r, []byte(`{}`), time.Now()))
	r.Header.Set("Mattermost-Plugin-ID", brokerSourcePlugin)
	require.NoError(t, p.authenticateBroker(r, []byte(`{}`), time.Now()))
	for _, alter := range []func(*http.Request){func(r *http.Request) { r.URL.RawQuery = "x=1" }, func(r *http.Request) { r.URL.ForceQuery = true }, func(r *http.Request) { r.URL.RawPath = "/internal/%70lane-token" }, func(r *http.Request) { r.URL.Fragment = "x" }, func(r *http.Request) { r.RequestURI = testBrokerPath }} {
		r := signedBrokerRequest(`{}`, 0)
		r.Header.Set("Mattermost-Plugin-ID", brokerSourcePlugin)
		r.RequestURI = ""
		alter(r)
		require.False(t, brokerTarget(r))
	}
}

func TestBrokerConcurrentNonceClaimAcrossNodes(t *testing.T) {
	brokerKeys(t)
	p, a, _ := fixtureIdentity(t)
	r := signedBrokerRequest(`{}`, 0)
	results := make(chan error, 12)
	for range 12 {
		q := &Plugin{}
		q.SetAPI(a)
		go func() { results <- q.authenticateBroker(r, []byte(`{}`), time.Now()) }()
	}
	accepted := 0
	for range 12 {
		e := <-results
		if e == nil {
			accepted++
		} else {
			require.ErrorIs(t, e, errBrokerSignature)
		}
	}
	require.Equal(t, 1, accepted)
	require.ErrorIs(t, p.authenticateBroker(r, []byte(`{}`), time.Now()), errBrokerSignature)
}
func TestBrokerIntegrationQuotaPrecedesReplayStorage(t *testing.T) {
	brokerKeys(t)
	p, a, _ := fixtureIdentity(t)
	now := time.Now()
	p.broker.minute = now.Unix() / 60
	p.broker.calls = 120
	p.broker.users = map[string]int{}
	r := signedBrokerRequest(`{}`, 0)
	require.ErrorIs(t, p.authenticateBroker(r, []byte(`{}`), now), ErrTemporarilyUnavailable)
	require.Len(t, a.kv, 1, "throttled valid HMAC must not allocate replay state for invalid JSON")
}
