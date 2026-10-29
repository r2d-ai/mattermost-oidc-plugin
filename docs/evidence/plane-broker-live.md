# B3 isolated deployed evidence

Date: 2026-10-26. **Live checks and cleanup completed; final independent B3
acceptance review remains pending.** No Plane API/P2 or production rollout is
claimed. Machine-readable status-only evidence is in
[plane-broker-live.json](plane-broker-live.json).

## Installed source and environment

The installed plugin is 0.6.2, built from approved clean code commit
`cfbd7101030fef1dd99661f6c8ea5f9e512920c2` with Go 1.27.2, linux/amd64,
`vcs.modified=false`. Its archive SHA256 is
`58d75a366b1bedb58ab00ea684cb78b7941cbcdf8a4a2531724b201235f7a2fe`.
This is the clean-HEAD rebuild, distinct from the earlier precommit code-stage
archive. Mattermost upload returned 201 using the corrected root layout.
The installed binary was privately copied out and matched the local clean-build
binary hash and VCS metadata. Documentation commits do not relabel this binary.

Mattermost Team Edition 12.0.1 runs at local HTTPS port 18445, pinned image digest
`sha256:b0fdecf049bbb5d224d719bade7f438261b27e7061205f904bcc9e4f2f36eb70`.
Keycloak 26.8.1 runs at local HTTPS port 18444, image digest
`sha256:a78d6b79572168cb25886b80a8b5b8d4ed4390743e3eecb810538683e209dd6b`.
API checks and plugin/provider connections used the fixture CA. Isolated
Chromium callback contexts accepted the fixture certificate; no host trust-store
change was made. The ordinary login scopes remained `openid profile email`.

AES and HMAC rings were written only to private 0600 files and injected before
replacing the Mattermost process. Successful real credential capture/decryption
and authenticated exchange established effective inheritance, beyond merely
checking environment presence. Initial inventory contained only `mattermost-oidc`.
A temporary trusted server plugin `mattermost-plugin-plane` was installed for
PluginHTTP proof and removed afterward. All server plugins inherit these
variables; this is trusted deployment authority, not plugin-exclusive isolation.

## Truthful identity maintenance

Cycle 1 began frozen at epoch 7, login disabled and both existing affected
synthetic users already having zero sessions. Targeted revoke returned 200 and
native administrator access remained 200. No old token had been retained, so
this cycle cites historical B0 old-token denial and makes no fresh old-401 claim.
A new two-row retain receipt was written only after current zero-session/drain
checks, then validated/applied/activated with unchanged bytes to epoch 8.

Fresh real Alice/Bob callbacks then retained their native session tokens privately.
Alice kept her reviewed legacy UUID; Bob was newly bound by verified callback
and later returned to the same UUID. Before cycle 2, authenticated self-disconnect
returned 204, the sole node's login/capture/broker were disabled, and completed
callbacks were drained. At frozen epoch 9, all three affected OIDC users had zero
sessions after targeted revocation; actual Alice/Bob old tokens returned 401 and
native admin remained 200. Only then was a new three-row retain map written from
current committed bindings and the known synthetic provenance. Exact bytes were
validated/applied/activated to epoch 10. No guessed email/current-issuer mapping
or stale-map automatic activation was used.

## Actual results

| Boundary | Observed result |
| --- | --- |
| Fresh complete Alice/Bob OIDC callback | Native session 200, distinct stored subjects, same expected UUIDs, encrypted ready credentials |
| Signed public read and read/write for both users | 200; independently verified RS256, issuer, own subject, exact audience/azp/type/scope, 180-second lifetime, expiry derived from claims, exactly two response fields |
| Unsigned, forged user header, modified body, wrong signing path/key, duplicate signature, ±31-second timestamp | 401 |
| Wrong method, query including stripped access_token, raw bare `?`, escaped path, unknown JSON field | 400 |
| Unsupported scope | 403 |
| Same request immediately replayed | 401 |
| Actual PluginHTTP, both users and both scope sets | Signed 200, unsigned/replay 401; independent signed-claim verification in temporary caller; no public token-return route |
| Actual Mattermost process restart, preserved DB/KV | Byte-exact replay 401 at 24 seconds, within timestamp window; fresh nonce with same key 200 |
| Warm broker then disabled broker | 503; fresh complete Alice login still 200 and new encrypted capture succeeded |
| Persistence disabled | Fresh complete Bob login 200 with unchanged credential generation |
| AES env entries removed and process replaced | Broker 503, complete Alice callback 200 with invalidated generation/no ciphertext |
| AES restored and process replaced | 409 for invalidated generation until fresh login; then signed broker 200 |
| Interactive login disabled independently | Connect/callback 400 while signed delegation remained 200 |
| Real native-session/CSRF self-disconnect | 204, current credential slot tombstoned, no ciphertext retained in live slot |

A raw HTTPS client preserved the bare-query spelling and duplicate headers.
The higher-level Playwright client had removed a bare `?`; its resulting 200 was
a normalized plain-path request, not counted as a negative-path result.

The caller was synthetic privileged test code. It used the exact plain internal
input, canonical external signing path and inherited HMAC key. Core overwrote
its supplied source/user header hints. Its admin-only ephemeral command returned
statuses/booleans only, never tokens or task text. HMAC still grants the trusted
caller selection authority over all eligible linked users, not proof of a human
event. Actual multi-node runtime was not deployed; shared-node CAS concurrency
and restart simulation remain separate unit evidence.

## Backup and secret handling

An actual plugin-KV export was retained in a private 0600 artifact. It contains
the existing OAuth-state HMAC key and native identity data and is not a public
or committed backup. Both envelopes were AES-GCM authenticated and decrypted
in memory using current B0 AAD. Actual access/refresh strings and their base64
representations were absent from decoded stored values/export; external AES/HMAC
raw, base64 and hex key representations were also absent. Decrypted credential
schema had no ID-token field. No actual ID-token string comparison is claimed.
No secret/token value was printed or placed in tracked evidence. External ring
values were absent from public and privately inspected plugin configuration.

## Cleanup and limits

Final posture: frozen gate epoch **11**; login, broker and persistence disabled;
synthetic client secret cleared (verified from a private config-file copy),
original issuer retained; all three affected native session lists empty;
latest Alice/Bob tokens 401; original native admin session and fresh native
password login 200. Ordinary native sessions were not targeted. Alice/Bob
credential slots are invalidated without ciphertext. Supported disconnect
performed best-effort revocation of current loaded refresh material. The one
new provider session created during the AES-loss callback was explicitly deleted
(204), leaving preexisting provider sessions untouched. No global provider logout
or universal revocation guarantee is claimed.

The temporary caller is removed; only OIDC remains active with all issuance/login
switches off. DB/volumes and protected runtime evidence/key files remain for G2.
The mounted epoch-9 receipt is intentionally stale at frozen epoch 11 and must
not be reused as fresh approval. Existing moderate npm vulnerability remains the
previous nonblocking baseline; no dependency upgrade was performed.

Post-network configuration/generation races, key rotation, replay capacity/store
failure, concurrency and HTTP deadlines retain their focused/race **unit** proof;
those failure injections were not repeated against deployed storage. Core RPC
cancellation, last-check/release race, hook delivery, already-issued token lifetime,
per-node rate scope, conservative slot collision and root-SiteURL limits remain.
A valid exchanged JWT is not evidence of end-to-end Plane ACL/API acceptance.
