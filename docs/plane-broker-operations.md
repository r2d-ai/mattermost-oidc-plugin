# Encrypted delegated credentials

This stage captures OIDC credentials for later server-side delegated access. It
does not add a broker endpoint, refresh tokens, exchange tokens, or alter ordinary
login scopes. In particular, do not request offline access merely to serve
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
record with a monotonic generation and owner. `refreshing` is reserved for the
later refresh lifecycle. Capture first durably advances to an invalidated
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
Unknown expiry cannot justify using a refresh token forever; the later lifecycle
must enforce its own conservative refresh/reconnect policy.

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

The later lifecycle owns rotating-refresh exclusion, crash/response ambiguity
and token revocation. The later broker owns caller authentication, durable
replay checks, exact audience/scope exchange and release of only a short-lived
`plane-api` token. PluginHTTP alone is not caller authentication. This stage's
internal store methods are not public authorization interfaces.
