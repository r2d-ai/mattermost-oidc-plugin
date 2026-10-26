# Encrypted delegated credentials

This stage captures OIDC credentials and serializes refresh/disconnect for later
server-side delegated access. It does not add the broker/exchange endpoint or
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
and token revocation. The later broker owns caller authentication, durable
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
existing boundary; the later server broker will use its own HMAC guard.

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
