# B3 broker code-stage evidence

Date: 2026-10-26. This is code/unit/build evidence, **not deployed acceptance**.
Base: `acfc793fbf685d38850e1b0b80cf5a255e5e608a` (independently approved B2).
Plugin manifest: `mattermost-oidc` 0.6.2; module minimum Go 1.26.7;
actual compiler `go1.27.2 darwin/arm64`, Node v26.12.0, plugin SDK v0.4.4.
No dependency version changed; existing go-jose/v4 v4.1.5 became a direct import.
The supplied fixture contract pins Mattermost v12.0.1 and Keycloak 26.8.1.
Neither version was exercised by an installed B3 plugin during this stage.

## Results

| Command / check | Result |
| --- | --- |
| `go test ./... -run TestBroker -count=1` before implementation | RED: absent broker symbols/handler |
| Initial focused broker suite | GREEN |
| Existing archive root-manifest regression | RED: `plugin.json must be at archive root` |
| `TestBrokerIntegrationQuotaPrecedesReplayStorage` during self-review | RED: exhausted integration quota still accepted a nonce |
| Focused rate, concurrent replay and scope regression after correction | GREEN |
| Final `go test -race ./... -count=1` from `server/` | PASS, 26.103 seconds |
| `make all` | PASS: four server targets, webpack and archive validation |
| Final `make bundle -o webapp` after server-only rate fix | PASS: rebuilt all four server targets; retained the unchanged, already-built webapp; archive validation PASS |
| `git diff --check` | PASS |

The final bundle is `dist/mattermost-oidc-0.6.2.tar.gz`, SHA256
`a28d17d24beb676a0cb8831ba4f9ae4744d690948b99e56066db993f5d4a9e08`.
It contains root `plugin.json`, all four declared `server/dist` binaries,
`webapp/dist/main.js`, and `assets/oidc-icon.svg`. `scripts/test_bundle.py` checks
the actual manifest references in each built archive. The existing npm install
baseline remains **one moderate vulnerability**. No audit fix or dependency
upgrade was performed.

## Covered boundaries

Tests cover unsigned/forged headers, body/method/path/query mutation, duplicate
auth headers, timestamp ±30/±31, shared-node CAS replay and simulated plugin
restart, simultaneous nonce claims, key-ID alias replay, overlap and retired
keys, full/colliding nonce storage, ambiguous acknowledgement, unavailable KV,
retention/cleanup, per-node concurrency and integration/user quotas, and both
observed public/PluginHTTP transport shapes. Integration quota is charged after
HMAC verification and before nonce KV, including malformed JSON/scope requests.

The synthetic TLS issuer signs RSA access tokens for separate Alice/Bob bindings.
Tests assert the fixed exchange form and token-only response, exact claims/scope,
wrong signatures/algorithm/metadata, expired/near-expired output, oversized token,
provider failure, current native auth, post-network disconnect/deactivation and
disable/re-enable fencing, missing HMAC/AES keys, five-second HTTP timeout and
ten-second whole-call cancellation. Final checks use B0 plus B2 generation.
Login-off cached-token use and direct connect/callback denial close the carried
B2 minor coverage gap. Broker-off connect still redirects to OIDC authorization.

## Not established here

Core SDK RPC calls are not hard-cancellable. Fixed replay slots conservatively
reject collisions; limits are 8 concurrent calls / 120 authenticated calls per
minute / 10 per user per minute per node. Shared replay slots are capped at
4,096 and retain at least 120 seconds after an accepted durable acknowledgement.
Only root-SiteURL transport is supported. HMAC trusts a caller with authority
over all linked users and does not prove a human event; server plugins inherit
external rings and are trusted deployment code.

The route threat-review decisions were adopted, but independent B3 code review
and controller activation go-ahead are still required. Installed callback
capture, inherited-secret propagation, backup inspection, two-user Keycloak
exchange, actual PluginHTTP dispatch, replay after real process restart and
broker-disable with complete fresh login remain pending. No Docker/runtime,
production/shared-QA, identity map, remote repository, push or merge action was
performed. P2 stays disabled pending its separate shared rollout gate.

## Code-gate fix round 1: AES ring availability classification

I1 was reproduced: absent/malformed external credential rings and unusable active
configuration returned 409 before exchange, after exchange, and during refresh
failure. Broker-owned availability checks now return 503 before lifecycle use
and at release; reconnect errors are reclassified only while the external ring
itself is unavailable. B1/B2 implementations and error APIs remain unchanged.
A valid ring with missing/invalidated/ambiguous generations, a lost historical
decrypt key or tampered ciphertext still returns 409.

Focused RED recorded the 409-versus-503 mismatch. Focused GREEN passed in 2.241s;
covering race tests passed in 5.809s, including existing store/ring/lifecycle key
regressions and happy token/profile/no-secret cases. No full deadline-suite or
npm rebuild was needed for this scoped broker change. `make bundle -o webapp`
rebuilt all four server binaries and passed the actual archive regression.
The new exact archive SHA256 superseding the earlier code-stage archive is
`f91bc0c8a10d2f6b59604a6fbefc37f7d1db8227966589c3947fe426a937241e`.
The one moderate npm baseline remains deferred. Installed enablement is still
held pending scoped re-review; no deployed evidence is claimed.
