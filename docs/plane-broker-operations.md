# Encrypted delegated credentials

The plugin captures encrypted OIDC credentials, serializes refresh/disconnect,
and provides a fixed authenticated Plane token exchange broker. It does not
alter ordinary login scopes. In particular, do not request offline access merely to serve
`/plane tasks`. Production requires its own provider capability proof.

## Enable capture

Keep the B0 identity gate and approved issuer/subject mapping workflow in force.
An existing session has no retained credentials until a fresh verified OIDC
login. An account with unknown legacy provenance first needs an approved B0
identity import, then a fresh login. Email, a raw subject mapping, a request
header, and a supplied Mattermost UUID never establish credential ownership.

Set `EnableTokenPersistence=true` to capture. `EnablePlaneBroker=true` also has
to be set before an internal store load can release credentials. Both default
to false; `Enable` continues to control OIDC login independently. These two
switches are read live and do not change the callback fingerprint. With
persistence off, callbacks bypass the credential store entirely, so a credential
KV outage does not add a failure dependency to ordinary B0 login. With either
switch off, loads deny immediately. Disabling is reversible policy, not durable
revocation: existing encrypted records can remain and re-enabling does not
itself require reconnect. Explicit disconnect/revoke must call invalidation.
A logout on one device does not delete other valid Mattermost sessions.

Provide process secrets to every plugin node through the deployment's protected
environment/secret injection mechanism:

* `MM_OIDC_CREDENTIAL_KEYS` is a JSON object mapping key IDs to standard padded
  base64 encodings of independent random 32-byte keys.
* `MM_OIDC_CREDENTIAL_ACTIVE_KEY_ID` is the exact ID used for new encryption.

For example, the shape is `{"2026-10":"<base64-of-32-random-bytes>"}` with active
ID `2026-10`. The placeholder is not a valid key. Use a secret manager to create
and distribute real values without printing them. IDs contain 1 to 64 ASCII
letters, digits, underscores, or hyphens. At most 16 keys and 16 KiB of JSON are
accepted. Duplicate IDs, invalid base64, wrong key lengths, missing active ID,
and malformed input deny capture/load. Inactive keys decrypt only.

Never place raw keys in plugin KV, System Console settings, browser/public
configuration, logs, or a committed file. The existing KV `encryptionKey` signs
OAuth state only and is never a credential-encryption fallback. Missing keys
do not disable native OIDC login, and key loading is independent of tombstoning.

## Persistence and recovery

Only a successful callback with a verified issuer, subject, signature and nonce,
a current B0/native auth binding, a coherent callback snapshot, and a newly
created native session may capture. It uses the actual returned Mattermost UUID.
It does not keep the ID token. Access/refresh tokens, expiry, issuer/subject/UUID,
gate epoch, identity revision and credential generation stay inside AES-256-GCM
ciphertext. Each publication uses a fresh random nonce. Binding, epoch, revision,
format, key ID, owner, generation and state are authenticated. KV slot keys are
digests of issuer and Mattermost UUID. The clear envelope exposes format/key ID,
concurrency state, nonce and ciphertext only, never email or raw subject.

The envelope is a single CAS-controlled `ready`, `refreshing`, or `invalidated`
record with a monotonic generation and owner. Refreshing records also expose
authenticated start/deadline and optional nonissuing candidate phase. Capture
first durably advances to an invalidated
generation, then encrypts and publishes against those exact owner/generation
bytes. Invalidation advances the same counter and needs neither a decrypt key,
an active identity gate nor an active user. Do not delete/reset tombstones or
create a second lifecycle counter.

An initial fence failure or lost identity/snapshot authority fails the callback,
revokes only its new native session, and releases no new cookie/mobile/popup
session token. Once a fence is confirmed, missing keys or other optional
encryption/publication failures can preserve valid login while that generation
stays unavailable. A publication CAS error may have committed despite a lost
response. Cleanup must confirm the exact owned publication is fenced or already
superseded before treating that failure as optional. It must never erase a newer
login's credentials. Unconfirmed cleanup is an authority failure and denies the
callback. A final snapshot failure similarly fences only this callback's owned
publication. Generic warnings contain no token, key, ID token or provider body.

Loads require current enabled policy, committed B0 forward/reverse binding,
active gate and native nonbot/nondeleted user with exact auth service/data.
They authenticate the current epoch/revision, check the ciphertext binding and
generation, reread the record and reassert authority before returning. Unknown
keys, tampering, nonready records and superseded identity metadata deny access.
Changing issuer/client or returning to an old configuration never thaws B0's
persistent gate or makes legacy mappings authoritative.

`AccessExpiresAt` comes from the OAuth response. `refresh_expires_in` is a
provider-specific relative expiry, accepted only as a positive integer of at
most ten years. Its absence, zero or malformed value leaves `RefreshExpiresAt`
zero, meaning unknown, not unlimited. Providers may still revoke tokens sooner.
Unknown expiry does not prove unlimited validity. The lifecycle refreshes once
when needed and requires reconnect after any rejected or ambiguous refresh.

## Rotate or lose a key

1. Distribute a new independently generated key to all plugin processes while
   retaining previous keys in the ring. Select the new active ID consistently.
2. Old records decrypt with their stored key IDs. Fresh verified logins publish
   with the new active ID and a later credential generation.
3. Retire an old decrypt key only after affected credentials have been replaced
   or explicitly invalidated. Historical DB backups still need protection.

Losing an old key makes its ciphertext unavailable. Restore the correct protected
key if appropriate, or use fresh verified login with a valid new active key to
fence and replace the old record. Generating a replacement key under the lost
ID cannot recover ciphertext. Never regenerate a key from plugin KV or reuse
the OAuth-state HMAC key. A malformed/corrupt concurrency record or unavailable
KV cannot safely establish the next generation; repair the authoritative store
under a reviewed recovery procedure rather than resetting its counter.

Database backups of credential slots contain ciphertext, not raw credentials.
They still disclose key IDs, slot digests and concurrency metadata. Access to a
backup plus its corresponding encryption keys exposes the enclosed tokens.
Keep secret and database backups separately controlled.

## Limits and later stages

Mattermost core session creation/revocation, plugin KV and configuration are not
one atomic transaction. Assertions and exact CAS writes narrow races; they do
not cancel an already executing SDK operation or make response release atomic
with an administrative change. If core session revocation fails, the callback
withholds the token and logs a generic failure; operators must investigate the
unreleased session. Token consumers must reassert authority at use/release.

The lifecycle below owns rotating-refresh exclusion, crash/response ambiguity
and token revocation. The broker owns caller authentication, durable
replay checks, exact audience/scope exchange and release of only a short-lived
`plane-api` token. PluginHTTP alone is not caller authentication. This stage's
internal store methods are not public authorization interfaces.


## Distributed refresh and deadline semantics

`TokenLifecycle.UserAccessToken` and `AssertGeneration` are internal interfaces,
not caller authentication. A token value is excluded from JSON and ordinary Go
formatting. B3 must still authenticate its server caller, constrain exchange,
and reassert generation and identity before release. It must not issue from a
raw user ID or a PluginHTTP call alone.

The lifecycle rereads the current Mattermost user (including `DeleteAt`, bot
status and exact native auth binding), both integration switches and B0 authority
before use/refresh and before returning. Tokens with at most 30 seconds left are
refreshed. Known expired refresh credentials require reconnect. Two nodes share
one durable CAS authority, without a process-wide user mutex:

1. `ready(v)` becomes authenticated `refreshing(v, owner, started_at, deadline)`.
   Only the CAS winner sends a refresh POST, with the old refresh token once.
2. A successful response must include a new refresh token, bearer access token
   and valid expiry. There is no provider-supported omission proof in the spike;
   an omitted replacement, `invalid_grant`, response loss, timeout, malformed or
   oversized response requires reconnect. There is no refresh/auth-style retry.
3. Exact owner bytes become `refreshing(v+1, phase=candidate)` containing the new
   encrypted credentials. This is nonissuing through both store and lifecycle.
   Only a successful acknowledgement within the original absolute budget,
   followed by current identity/config checks, permits construction of the
   authenticated final `ready(v+1)` bytes. No replacement/resumed process may
   promote an abandoned candidate.
4. Final CAS compares the exact candidate bytes. Tombstones and newer captures
   fence all late owners. Expired/abandoned refreshing/candidate state advances
   to a tombstone, never to an owner replaying the old refresh token. Cleanup is
   exact-owned and preserves a newer login's generation.

Refresh, discovery and waiter polling share an absolute maximum ten-second
budget (or the caller's earlier deadline). Waiters use bounded backoff, observe
the owner's stored deadline, and honor request cancellation. SDK KV calls have
no context argument: a blocked RPC cannot be hard-cancelled, and this is not a
wall-clock bound on blocked SDK operations. A delayed candidate acknowledgement
cannot create usable final bytes. Final-ready bytes are constructed only after
an on-time durable candidate acknowledgement; a delayed final CAS therefore
contains an already confirmed rotation, unlike an ambiguous refresh/candidate.
The late caller still denies and exact-cleans its publication. Another caller
can observe that confirmed rotation before cleanup if no tombstone won first.
There is no claim that the physical final KV write always precedes the deadline.

Provider transport is discovered per refresh under that same budget from the
validated HTTPS issuer, client ID and secret, with exact issuer equality,
configuration revision/equality checks and B0 authority checks before/after the
network operation. It does not reuse or publish the interactive-login cache.
Responses are limited to 64 KiB and redirects are refused for discovery,
refresh and revoke. The pinned Keycloak deployment must support
`client_secret_post`; this is the authentication method proven by its spike.
The implementation does not automatically probe/retry other authentication
styles. It requests neither extra scopes nor offline access.

`Enable=false` disables interactive OIDC login but is not a delegated-use gate.
Both delegated switches and the active approved B0 identity gate remain required.
A frozen gate, issuer/client mismatch, lost key or inactive user still denies.
Disabling login does not thaw or create identity mappings.

## Disconnect, administrator revocation and deactivation

Management endpoints are POST only under `/plugins/mattermost-oidc`:

* `/api/v1/plane/disconnect` invalidates the authenticated user's credential.
  User IDs in a query/body/cookie are not self authority.
* `/api/v1/plane/revoke` takes exactly `{"user_id":"<Mattermost UUID>"}` in a
  bounded JSON body. The UUID selects the target only. The actor must have a
  current server-resolved `system_admin` role.

Both require core-supplied `plugin.Context.SessionId` and `Mattermost-User-Id`,
a matching current, nonexpired, nonintegration session resolved by session ID,
and a current active nonbot user. `X-CSRF-Token` must be nonempty and match the
nonempty session CSRF value in constant time. This applies even to ordinary
sessions transported in Authorization. Native-password and OIDC human sessions
qualify; bot, PAT and OAuth integration sessions do not. Form-only CSRF,
`X-Requested-With`, browser user cookies and user headers without a core session
cannot substitute. This proves session possession, not physical human action
or recent reauthentication. Other public login/config routes retain their
existing boundary; the server broker uses its own HMAC guard.

Local invalidation completes before best-effort remote refresh-token revocation.
Provider failure/timeout cannot restore local credentials or make a successful
local disconnect fail. Loading a token for remote revocation remains subject to
normal issuance rules; a frozen gate, missing decrypt key, inactive/native-changed
account, or in-progress refresh can make that token unavailable, so remote revoke
is skipped. There is no cleanup decryption bypass. Local invalidation never
requires provider availability, active gate or encryption keys.

Cleanup locates the original bound issuer/subject using corroborated committed
B0 forward/reverse records. It can invalidate frozen/deactivated identities and
never relabels a slot with the current configured issuer. Missing, pending or
contradictory registry records produce a generic explicit failure; operators
must repair/reconcile the registry rather than guess from email/raw subject.

`UserHasBeenDeactivated` performs best-effort local invalidation. On Mattermost
core v12.0.1 the hook is scheduled asynchronously after persistence/session
revocation, has no evidenced durable retry, and can be omitted by intervening
failures and bulk guest paths. Broker use independently rereads inactivity and
attempts cleanup before issuance-gate checks. Failed/missing hook delivery never
authorizes an inactive user. Neither hook nor rereads make deactivation atomic
with token release, and there is no universal cleanup guarantee. Deployments
requiring cleanup across skipped/bulk paths must explicitly revoke through the
management endpoint before reactivation. No Mattermost core patch or polling
identity registry is installed.

Ordinary device logout leaves other sessions and delegated credentials intact.
Use explicit disconnect/revoke to invalidate delegated access. A fresh verified
OIDC login may reconnect by publishing a strictly later generation; no tombstone
counter may be reset. Tests use synthetic in-process TLS and shared fake durable
KV. This stage does not establish installed-runtime capture, backup handling or
B3/G2 deployment acceptance; the historical local fixture remains frozen.


## Authenticated fixed Plane broker

`POST /plugins/mattermost-oidc/internal/plane-token` accepts exactly one JSON
object with `mm_user_id`, `audience`, `scope`, and `request_id`. Audience is
`plane-api`; scope is exactly `plane.read` or `plane.read plane.write`.
Request IDs contain 1–128 printable ASCII characters. Unknown/duplicate fields,
trailing JSON and bodies over 4 KiB are rejected. Subject tokens, issuer,
requested subject, endpoints, client and secrets are never caller inputs.

Success contains exactly `access_token` and integer Unix-seconds `expires_at`.
Every response has `Cache-Control: no-store` and `Pragma: no-cache`. Errors
contain exactly `error` and `request_id`; absent/unsafe request IDs are empty:

| HTTP | Error | Meaning |
| --- | --- | --- |
| 400 | invalid_input | Method, target or JSON does not meet the fixed contract |
| 401 | invalid_signature | Missing/bad signature, retired/unknown key, stale timestamp or replay |
| 403 | forbidden | Invalid binding, inactive user, audience or scope |
| 409 | reconnect_required | Credentials need a fresh verified OIDC login |
| 503 | unavailable | Integration disabled, provider/store/key configuration unavailable or capacity/rate limit |

Missing/malformed external credential rings or an unusable active key
configuration are integration availability failures (503), checked before
lifecycle use, again at release, and when classifying a lifecycle reconnect
error. A valid current ring with a missing historical decrypt key, tampered
ciphertext, or missing/invalidated/ambiguous credential generation retains the
existing reconnect requirement (409). A deployment ring outage must not direct
users into repeated login attempts.

A 503 is retryable with a fresh nonce and bounded backoff. It must never trigger
an administrator-credential fallback. Failed exchanges retain their nonce.

### Caller authentication and transport

Supply independent external `MM_PLANE_BROKER_HMAC_KEYS` and
`MM_PLANE_BROKER_HMAC_ACTIVE_KEY_ID` process variables. Encoding, key IDs,
maximum ring size and strict parsing match the encryption ring above: JSON
object, canonical padded standard base64, exactly 32 random bytes per key,
1–64 character IDs and at most 16 entries / 16 KiB. The active ID must exist.
The caller signs with the active key; overlap keys verify only. The broker
accepts these dedicated headers once each:

* `X-Plane-Key-Id`: selected verification key ID.
* `X-Plane-Timestamp`: canonical decimal UTC Unix seconds, ±30 seconds inclusive.
* `X-Plane-Nonce`: 32 independently random bytes, unpadded canonical base64url.
* `X-Plane-Signature`: lowercase hex HMAC-SHA256.

Canonical UTF-8 signing bytes are `POST`, newline, the literal external path
`/plugins/mattermost-oidc/internal/plane-token`, newline, lowercase hexadecimal
SHA256 of the exact raw body, newline, timestamp, newline, nonce. There is no
trailing newline. Do not reserialize the body after signing.

Only a root-origin SiteURL is supported. Public HTTP requires the original
`RequestURI` to equal that external literal and the core-stripped local path to
be `/internal/plane-token`. This rejects a bare `?`, escaped alternative paths,
and original `access_token` queries even after core strips the parsed query.
Inter-plugin clients must call `API.PluginHTTP` with exactly
`/mattermost-oidc/internal/plane-token`, empty `RequestURI`, and no URL escaping,
query or fragment. At the target, core must attribute the source ID
`mattermost-plugin-plane`; observed local path/raw path/query/fragment are
checked. Core reparses decoded PluginHTTP paths, so these target-side checks
cannot prove original pre-normalization spelling. The bot must construct the
plain fixed input. HMAC always signs the external literal on both transports.
Subpath SiteURLs and arbitrary proxy rewrites are outside this contract.

HMAC authorizes the trusted integration to select **any eligible linked user**.
A user UUID, forged header or PluginHTTP call alone cannot authorize issuance.
The signature does not independently prove a human event, consent or session.
All normally launched server plugins inherit the server process environment;
trusted installed plugins, administrators and deployment/install authority are
inside this trust boundary. Environment injection separates secrets from
browser settings/config/KV, not from other trusted server plugins. Separate
key names do not provide process isolation. Changing Docker environment settings
does not update already-running plugin processes; apply them through a reviewed
process replacement and prove propagation without printing their values.

### Replay, capacity and time bounds

Replay protection is shared durable KV CAS, independent of node and signing-key
ID. The SHA256 nonce digest selects one of 4,096 fixed slots. An acknowledged
claim uses a 131-second slot lifetime, reserving the call budget and rounding
so a successful durable acknowledgement has at least 120 seconds remaining.
An acknowledgement with less remaining retention denies issuance. An exact
replay returns 401. Each slot stores up to 32 live digests in a CAS-controlled
bucket; a full bucket returns 503. Never evict a live digest. Old nodes cannot
read the new bucket format and fail closed, so drain broker traffic while
upgrading all nodes and do not roll back with broker admission enabled. Use fresh nonces on retry. Four fixed slots are lazily scanned per
accepted request; cleanup compares exact expired bytes so it cannot erase a
replacement. KV failure or ambiguous CAS acknowledgement fails closed.

Each node permits 8 concurrent broker calls, 120 authenticated
calls per UTC minute across the integration, and 10 per user per UTC minute.
These fixed-window rate limits are per process/node and reset on restart; the
replay slots are durable and cluster-wide. Integration quota is charged immediately after valid HMAC, before replay KV,
including invalid JSON/scope requests. Per-user state is created only after
signature, JSON and scope validation and a successful current binding resolution; it is bounded by the integration limit.
Exhausted limits return 503. Unauthenticated input cannot allocate user entries.

A callback failure revokes the session created by that callback when identity authority fails; it does not revoke pre-existing ordinary sessions. Maintenance transitions require the separately documented session revocation procedure. Pending creation with an ambiguous outcome remains blocked until independently reviewed operator reconciliation; it is not automatically expired or reassigned.

The whole call has a 10-second context budget. Every discovery, refresh,
exchange and JWKS HTTP operation has a 5-second timeout within that budget;
redirects are refused and decoded responses are capped at 64 KiB. Tokens are
capped at 16 KiB. Caller cancellation is propagated. Existing SDK KV/user calls
have no context-aware cancellation, so an unresponsive core RPC is not a hard
wall-clock guarantee; after it returns, deadline checks deny release. The HTTP
core owns ingress/body delivery and its limits before plugin invocation.

### Fixed exchange and verified output

The broker exchanges as the configured confidential client `mattermost-oidc`
using `client_secret_post`, V2 token-exchange grant, access-token subject and
requested types, `plane-api` audience and the exact requested scope. Discovery
must return the exact approved HTTPS issuer; token and JWKS endpoints must use
HTTPS on that same origin without query components. No login scope is added;
an ordinary subject token need not itself contain Plane scopes.

Output verification uses only issuer-discovered JWKS and RS256 signatures;
token-directed key URLs are never fetched. Signed claims must contain exact
issuer and current stored subject, audience consisting only of `plane-api`,
`azp=mattermost-oidc`, payload `typ=Bearer`, and exactly the requested scope set.
Integer `iat`/`exp` are mandatory; lifetime must be 120–300 seconds, iat/optional
nbf allow at most 30 seconds of future skew, and more than 30 seconds of actual
validity must remain at release. Expires metadata must agree within 30 seconds
with verified expiry and reception time. No act/delegation-chain claim is
invented. Refresh/ID tokens in a provider response are never returned.

After all network work, the broker repeats current user/native/B0 authority and
credential generation checks. Its captured monotonic configuration revision
must still match, including a disable/re-enable or change/revert during the
call. Current HMAC and encryption key availability is required. These final
checks narrow the last-check/release race; they do not make a configuration
change atomic with bytes already released or revoke a delivered access token.

### Rotation, emergency disable and audit

For HMAC rotation, distribute old + new verification keys to every server and
caller process first, select the new active signing ID, switch callers, then
retire the old ID after the overlap window and bounded in-flight calls drain.
The old key cannot authenticate after retirement. Aliases containing identical
key bytes share the same nonce namespace. Never substitute the OAuth-state KV
key, generate a fallback key, or print rings in diagnostics. Encryption-key
rotation and key-loss/reconnect handling remain as described above.

To stop issuance, set `EnablePlaneBroker=false` (or disable persistence). The
broker checks switches on every call and revision/generation again before
release. Ordinary OIDC login keeps its independent `Enable` switch and works
with broker disabled. Disabling login alone does not disable delegated use.
Already-issued access tokens remain usable until expiry or Plane-side denial;
use explicit disconnect/revoke to fence future delegated use durably.

Audit records contain actor UUID, validated bounded request ID, issuer
fingerprint, allowed operation/scopes, outcome and latency only. They do not
contain task text, tokens, secrets or provider error bodies. Alert on unexpected
cross-user issuance, rapid user switching, write-scope requests outside approved
bot operations, signature/replay failures and sustained 503 capacity/provider
failures. Treat HMAC key compromise as potential issuance for all linked users:
disable integration, retire keys, investigate audit and fence affected records.

Unit tests and packaging validation do not prove installed environment
inheritance, callback capture, encrypted database backups or deployed PluginHTTP
behavior. Those synthetic-runtime gates and independent task review remain
required before rollout. P2 and production remain disabled pending their shared
gate; no unsigned exchange fallback is permitted.
