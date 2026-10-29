# Fork differences and commit ledger

This reference records the changes in `r2d-ai/mattermost-oidc-plugin` relative
to `server-camp/mattermost-oidc-plugin`. For integration steps, use
[upstream updates](upstream-updates.md). For operating procedures, use
[identity migration](oidc-identity-migration.md) and
[Plane broker operations](plane-broker-operations.md).

## Audit boundary

Audit date: 2026-10-29. Commit membership was checked against fetched upstream
history, not inferred from author names or version strings.

Audit base: `99920ca1225b5377b4736d7eb7488d92788319ca`

Audit head: `65558da5655e1c8e47f19c8425df3c4102903c7a`

Observed upstream head: `e1dd822d4107ed0e427b6e3167be89e12bf04c79`

| Item | Audited value |
| --- | --- |
| Fork | <https://github.com/r2d-ai/mattermost-oidc-plugin> |
| Upstream | <https://github.com/server-camp/mattermost-oidc-plugin> |
| Common ancestor | `99920ca`, upstream tag `v0.6.2` |
| Fork-only history | 15 commits, including 2 merge commits |
| Upstream-only history | 14 commits at the observed upstream head |
| Fork delta from common ancestor | 34 changed files |
| Fork manifest version | `0.6.2`; fork tags `v0.6.2` and `v0.6.2-1` point at `25835d3` |
| Historical deployed broker build | `cfbd710`; later fixes are outside that runtime evidence |

These are snapshot facts. Upstream `main` and this fork can advance independently.
The fork tag `v0.6.2` is a different commit from upstream's tag with that name.
Do not force-fetch upstream tags over fork tags or identify an installed build
from its version alone. The Go module still uses the inherited
`github.com/server-camp/mattermost-plugin-oidc` path.

Run `python3 scripts/check_fork_docs.py` to verify that every commit in the
recorded base-to-head range appears in the ledger and the named regression tests
exist. This needs the recorded Git history, not a shallow checkout missing those
commits. Add `--upstream <fetched-ref>` to print current divergence and commit
lists. The helper checks references, not behavioral compatibility, and reports
when HEAD advances beyond the recorded audit boundary.

## Inherited behavior

The common ancestor already includes web login, native-mobile deep links and
the optional mobile bridge, Desktop popup login with COOP storage fallback,
browser-bound state cookies, PKCE S256, nonce verification, email-verified and
position claims, core-compatible cookie Domain/Path/lifetime/eviction, and
discovery retry after activation failure. These are not fork inventions.

`webapp/` and `mobile-bridge/` are unchanged between the common ancestor and the
audit head. They still depend on the fork's updated callback retaining their
completion behavior. The plugin ID, public login/config paths, and upstream
license remain unchanged.

## Behavior added or deliberately changed

| Area | Upstream at the common ancestor | Fork contract and owning files |
| --- | --- | --- |
| Identity ownership | Raw-sub KV lookup, optional email linking, raw-sub native auth data | Exact verified issuer/subject pair, one UUID, matching committed forward/reverse records, current native auth checks. New auth data is a 67-byte `v2:` digest. `identity_binding.go` |
| Existing accounts | `AutoLinkByEmail` may convert an existing account to OIDC | Flag retained but ignored. Native accounts are not converted. Legacy OIDC imports require independent issuer provenance and preserve UUID/auth fields. `identity_migration.go` |
| First install and transitions | Configured login can proceed without an approval gate | Durable uninitialized/frozen/active gate, monotonic epoch, explicit empty bootstrap, frozen on issuer/client mismatch even with login off. Config revert/restart never thaws it. `identity_gate.go` |
| Administration | No identity-map maintenance command | Current human system administrator, strict `/oidc-identity` grammar, fixed read-only approval file, exact-byte digest, validate/apply/activate and maintenance receipt. No HTTP apply endpoint. `identity_command.go`, `identity_migration.go` |
| Callback consistency | Separately read cached provider/configuration | One immutable `LoginSnapshot`; state carries gate epoch and identity/callback fingerprints. Userinfo subject must equal verified ID-token subject. Reassert before effects and completion. `login_snapshot.go`, `oauth2.go` |
| Discovery and startup | Retry throttled to one attempt per 10 seconds; discard changed-config results | Retains retry and adds attempt ordering even at the same config revision. State HMAC initialization converges across nodes by CAS. `plugin.go`, `login_snapshot.go` |
| Optional credential capture | Tokens used transiently for login | Fresh verified callback and newly created session may retain encrypted access/refresh tokens. Fence first; optional failure after confirmed fencing may preserve login. Authority/fence failure revokes only the new session and withholds completion. `oauth2.go`, `credential_store.go` |
| Secret storage | KV `_plugin_encryption_key` signs state | Separate external 32-byte AES and broker-HMAC key rings. AES-256-GCM authenticates identity, epoch, revision, generation, and owner. ID tokens are not retained. `credential_store.go`, `broker_auth.go` |
| Refresh and revocation | No delegated lifecycle | One CAS envelope/generation for capture, rotating refresh, candidate publication, and tombstones. Ambiguous refresh cannot retry old tokens. Local invalidation precedes best-effort provider revoke. `token_lifecycle.go` |
| Delegated switches | Interactive `Enable` only | Capture needs `EnableTokenPersistence`; issuance needs it plus `EnablePlaneBroker`. Both default false. Interactive `Enable` is independent. Flags are live policy, not callback-fingerprint inputs. `configuration.go`, `plugin.go` |
| Management API | No delegated management endpoints | POST disconnect/revoke require core session plus explicit CSRF; revoke requires current admin. Frozen/deactivated cleanup uses corroborated original binding without encryption keys. `plugin.go`, `token_lifecycle.go` |
| Plane broker | No broker | Fixed POST exchange with independent HMAC, durable replay checks, current identity/generation/config/key assertions, root-origin SiteURL, fixed `mattermost-oidc` client, `plane-api` audience, and exact read or read/write scopes. `broker_auth.go`, `plane_broker.go` |
| Packaging | Nested plugin-ID archive directory | Flat root manifest and exact declared files, no links/extra files, executable binaries, release version verification and `SHA256SUMS`. `Makefile`, `scripts/test_bundle*.py`, `.github/workflows/ci.yml` |

Source paths in this table are under `server/` unless qualified otherwise.
The full broker transport, signing, JWT, timeout, quota, and error contracts are
in [the operations reference](plane-broker-operations.md#authenticated-fixed-plane-broker).

## Durable storage compatibility

| Key or prefix | Meaning and compatibility requirement |
| --- | --- |
| `_plugin_encryption_key` | Inherited state HMAC key, initialized through CAS in the fork. This is not an AES or broker key. |
| `oidc_state_` | Ten-minute single-use OAuth state. Fork state adds gate epoch and identity/callback fingerprints; pre-upgrade pending flows cannot bypass those checks. |
| `oidc_user_` | Inherited raw-sub mapping, retained only as legacy collision/import evidence. Never restore it as ownership authority. |
| `identity_v1_gate` | Durable approval status, epoch, issuer/client fingerprint, digest and receipt. Restart/config revert must preserve a frozen gate. |
| `identity_v1_pair_`, `identity_v1_user_` | Pair-digest and UUID directions of the same registry record. Both must be committed and identical. Preserve digest serialization and native auth expectations. |
| `credentials_v1_` | Digest of issuer/UUID selects one CAS envelope for encrypted credentials, refresh ownership/candidate, and invalidation. Never reset its generation or delete tombstones. |
| `plane_nonce_v1_` | 4,096 fixed replay slots, up to 32 live nonce digests per bucket. New code reads legacy single-entry records; old code cannot read buckets. Drain admission for upgrades/rollback. |

Exact pair/native-auth digest construction is documented in
[identity and native fields](oidc-identity-migration.md#identity-and-native-fields).
Credential AAD, key rotation, refresh ambiguity, and nonce retention rules are
documented in [broker operations](plane-broker-operations.md). Storage resets are
not a supported recovery shortcut.

## Commit ledger

Every commit reachable from the audit head but not the audit base is listed
below, including merges. Later fixes qualify the behavior introduced by earlier
commits; backport the final contract rather than copying an early stage alone.

| Commit | Change and requirement to preserve |
| --- | --- |
| [8a2791a](https://github.com/r2d-ai/mattermost-oidc-plugin/commit/8a2791a) | Verify release archive ID/version, artifact presence and executable modes; publish and verify SHA256SUMS. Later commits adapt validation to the flat archive layout. |
| [25835d3](https://github.com/r2d-ai/mattermost-oidc-plugin/commit/25835d3) | Merge PR #1, release-asset verification. Also the fork's `v0.6.2` / `v0.6.2-1` tag target. |
| [5adc3b7](https://github.com/r2d-ai/mattermost-oidc-plugin/commit/5adc3b7) | B0 identity foundation: issuer-bound bidirectional CAS registry, qualified native auth, durable gate, reviewed migration commands, coherent callback snapshot, userinfo-subject check, state-key CAS, removal of email-link authority. |
| [4a1c057](https://github.com/r2d-ai/mattermost-oidc-plugin/commit/4a1c057) | Order overlapping discovery attempts, including equal revisions; prove shared-CAS creation recovery, lost response handling, conflicting native auth rejection, partial import resume, and default-team retry. |
| [7d1e20a](https://github.com/r2d-ai/mattermost-oidc-plugin/commit/7d1e20a) | B1 encrypted optional capture: external AES ring, fence-before-publication, monotonic generations, separate default-off switches, final authority checks and revocation of the callback's new session on authority failure. |
| [acfc793](https://github.com/r2d-ai/mattermost-oidc-plugin/commit/acfc793) | B2 distributed rotating refresh and candidate acknowledgement, tombstone fencing, bounded provider transport, disconnect/admin-revoke session+CSRF checks, deactivation hook, and eligibility rereads. |
| [5c026f1](https://github.com/r2d-ai/mattermost-oidc-plugin/commit/5c026f1) | B3 HMAC-authenticated fixed Plane exchange, durable replay CAS and quotas, verified JWT output and final assertions. Add flat archive validation and fail-fast local server builds. Promote existing go-jose to direct dependency. |
| [cfbd710](https://github.com/r2d-ai/mattermost-oidc-plugin/commit/cfbd710) | Classify deployment credential-ring outage as retryable 503 before lifecycle, after network work, and during reconnect classification. Missing historical key or unusable generation with a valid ring stays 409. |
| [53a62ba](https://github.com/r2d-ai/mattermost-oidc-plugin/commit/53a62ba) | Record isolated deployed synthetic acceptance and cleanup tied to `cfbd710` and exact archive hash. This is historical evidence, not production or later-commit acceptance. |
| [e5b9afd](https://github.com/r2d-ai/mattermost-oidc-plugin/commit/e5b9afd) | Require committed forward/reverse broker binding; keep missing-refresh capture unavailable; reject malformed retain/endpoint data; reject unknown internal routes. Align CI flat packaging, reject extra/link/duplicate members, suppress macOS metadata, and run module verification. |
| [890fac3](https://github.com/r2d-ai/mattermost-oidc-plugin/commit/890fac3) | Bound ciphertext, return safe command outcomes, allocate user quota only after valid binding, cover missing-refresh login, and document pending-create and existing-session limitations. |
| [a15b5f2](https://github.com/r2d-ai/mattermost-oidc-plugin/commit/a15b5f2) | Regression tests prove missing username falls back safely despite a username collision, and callback authority failures revoke only the newly created session while preserving pre-existing sessions. |
| [d7f552e](https://github.com/r2d-ai/mattermost-oidc-plugin/commit/d7f552e) | Allow deactivated committed identities as reviewed retain rows without authorizing login/issuance. Replace one-nonce slots with bounded CAS buckets so distinct colliding nonces coexist; legacy slots remain readable. |
| [7626aee](https://github.com/r2d-ai/mattermost-oidc-plugin/commit/7626aee) | Document inactive-retain rules, 32-entry nonce buckets, full-bucket behavior, and all-node drain/rollback constraints for the format change. |
| [65558da](https://github.com/r2d-ai/mattermost-oidc-plugin/commit/65558da) | Merge PR #2, issuer-bound delegated Plane access plus review fixes. This is the audited fork head. |

Stage names B0/B1/B2/B3 in existing docs mean identity, credential persistence,
refresh/revocation lifecycle, and authenticated broker respectively. They are
implemented layers. Historical statements about a stage being future work do
not mean the layer is absent from the audited head.

## Regression test map

Run the entire `server` race suite for authentication changes. These tests are
specific entry points for review; this table is not a replacement for the suite.

| Contract | Existing tests |
| --- | --- |
| No legacy/email/native fallback; qualified auth and two-way ownership | `TestUnknownLegacyHasNoFallback`, `TestNativeAccountUnchanged`, `TestQualifiedNewAuthData`, `TestPartialRegistryNeverAuthorizes`, `TestBrokerRejectsPartiallyCommittedPair`, `TestDifferentPairCannotClaimOccupiedUUID` |
| Concurrent creation and ambiguous recovery | `TestConcurrentPairResolution`, `TestCreateResponseLostResumesSameUser`, `TestCreateResponseLostRenamedRefuses`, `TestCreateResponseLostChangedNativeAuthRefuses`, `TestNewAccountTeamInitializationResumes` |
| Gate, approval, inactive retain, administrator authority | `TestMissingGateDenies`, `TestIssuerChangeFreezesAcrossNodes`, `TestIssuerReturnDoesNotReactivate`, `TestEmptyBootstrapRequiresExplicitCommands`, `TestIdentityApplyPartialResumeAfterReverseCommit`, `TestInactiveRetainedBindingAllowsMaintenanceButDeniesBroker`, `TestIdentityCommandAuthority`, `TestIdentityCommandStrictGrammar`, `TestActivationRequiresMaintenanceReceipt` |
| Snapshot, secret rotation, discovery ordering and shared state key | `TestCallbackFingerprintEveryPolicy`, `TestCallbackSnapshotCannotMixProviders`, `TestSecretRotationOnlyInvalidatesCallback`, `TestCallbackSameRevisionDiscoveryCannotPublishOlderResult`, `TestStateKeyInitializationConvergesAcrossNodes` |
| Full web/popup/mobile callback, userinfo/nonce/cookie checks, capture failures and existing sessions | `TestOAuth2CompleteCallback`, `TestLoginSucceedsWhenPersistenceFails`, `TestSetSessionCookie`, `TestGetCookiePath`, `TestRenderPopupAuthCompleteNoScriptInjection` |
| Encryption, binding authentication, key loss, flags, publication ambiguity | `TestCredentialsNeverPersistPlaintext`, `TestEmptyRefreshTokenDoesNotPublishReadyCredentials`, `TestBindingTamperDenied`, `TestCredentialsCiphertextCannotMoveBetweenUsers`, `TestCredentialsAmbiguousPublication`, `TestCredentialsDisabledDeniesWarmSlot`, `TestCredentialsInvalidateWithFrozenGateAndNoKey` |
| Refresh exclusivity, missing rotation, response loss, candidate/deadline rules and revocation | `TestConcurrentRefreshAcrossNodes`, `TestRefreshWithoutReplacementRequiresReconnect`, `TestRefreshResponseLostRequiresReconnect`, `TestLifecycleAmbiguousCandidateOrReadyCAS`, `TestLifecycleDelayedPublication`, `TestDisconnectWinsOverRefresh`, `TestLifecycleDeactivationFencesLateRefreshOwner` |
| Session/CSRF boundary and frozen/inactive cleanup | `TestDisconnectSessionCSRFBoundary`, `TestAdminRevokeFrozenInactiveTarget`, `TestDeactivationHookFrozenCleanupAndFailure`, `TestDeactivationCleanupRequiresCorroboratedRegistry`, `TestDisconnectRevocationIsAfterFenceAndBestEffort` |
| HMAC, replay, colliding buckets, restart/node behavior and quotas | `TestBrokerSignatureBindsBodyPathAndMethod`, `TestBrokerReplayAcrossNodesAndRestart`, `TestBrokerInternalTransport`, `TestBrokerCollidingNoncesAndReplay`, `TestBrokerNonceRetentionAndCleanup`, `TestBrokerIntegrationQuotaPrecedesReplayStorage`, `TestUnknownUserDoesNotConsumeUserQuota` |
| Exchange output, availability classification, final authority and budgets | `TestBrokerNeverReturnsRefreshOrIDToken`, `TestBrokerRejectsSignedTokenProfile`, `TestBrokerFinalAuthority`, `TestBrokerCredentialRingLossAfterNetwork`, `TestBrokerCredentialRingLossDuringLifecycleError`, `TestBrokerCredentialGenerationFailuresRemainReconnect`, `TestBrokerWholeCallTenSecondBudget`, `TestBrokerLoginSwitchIndependence` |
| Mobile bridge | `TestHandleMobileLogin`, `TestRewriteClientConfig` in `mobile-bridge/main_test.go` |
| Archive | `scripts/test_bundle_validator.py` plus `scripts/test_bundle.py` against the actual built archive; CI release checks executable bits and version |

## Known upstream integration risk

At the observed upstream head, upstream PR #39 adds Desktop system-browser
login and removes popup login. It extracts `createLoginSession`, introduces
`server/desktop.go` and `/oauth2/desktop/redeem`, and exempts its new Desktop
flow from the state cookie in favor of a verifier/code handoff. The fork still
has the inherited popup flow and requires the cookie for web/popup callbacks.

The new upstream desktop code record holds user UUID, challenge, and return
path. Those fields alone do not carry this fork's gate epoch, binding revision,
callback fingerprint, or credential publication authority. Copying that flow
without adapting both callback and redeem can create sessions outside fork
checks or skip credential capture. This is a compatibility assessment of the
upstream-to-fork merge, not a claim of an upstream vulnerability.

The upstream-only history also includes version/dependency/Go updates. None
of those 14 commits has been integrated as part of this documentation audit.
Use the [update procedure](upstream-updates.md#adapt-session-and-desktop-changes)
before adopting their session refactors or Desktop transport.
