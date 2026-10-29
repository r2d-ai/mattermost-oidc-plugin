# OIDC identity migration and recovery

This foundation binds a verified `(issuer, subject)` to one Mattermost UUID. Email is profile data. Native password login and emergency system administrators remain independent of the OIDC gate.

An existing raw-sub lookup is **not** proof of its original issuer. Unapproved legacy accounts fail closed until an administrator reviews independent provenance and imports the exact binding. `AutoLinkByEmail` is retained only for configuration compatibility and has no effect. Existing native password accounts cannot be imported or automatically converted to OIDC.

## Identity and native fields

New accounts keep `AuthService = "oidc"`. Their native AuthData is `v2:` followed by the lowercase SHA-256 digest of Go `encoding/json`'s ordered string array `["mm-oidc-pair-v1", exactIssuer, exactSubject]`: exactly 67 bytes, regardless of issuer/subject length. Verified values are not trimmed or normalized. Imported legacy accounts retain their original UUID, `oidc` marker, raw-sub AuthData, memberships and ownership.

The registry uses `identity_v1_pair_<digest>` and `identity_v1_user_<UUID>`. Both directions must be committed and agree on the complete tuple, UUID, revision, transaction and native auth fields. Pending or conflicting entries authorize nothing. New-account creation persists the chosen username before attempting core creation. Recovery first checks that same username and exact expected native auth. A lost creation response can resume; an ambiguous outcome, renamed pending user, or changed auth fields requires explicit operator reconciliation. Do not delete reservations to retry blindly. A crash between recording a create attempt and the actual core call is deliberately treated as ambiguous.

A committed UUID cannot be reassigned to another pair. This release provides no rebind, native secondary-account linking, credential capture, token exchange, bot or broker API.

## Administrative commands

Use Mattermost's core slash-command execution from an authenticated **current, nondeleted, nonbot system administrator**:

- `/oidc-identity status`
- `/oidc-identity freeze`
- `/oidc-identity validate <sha256>`
- `/oidc-identity apply <sha256>`
- `/oidc-identity activate <sha256>`

Hashes must be exactly 64 lowercase hexadecimal characters. Extra arguments, flags, supplied actors, paths and document bodies are rejected. The command reloads its actor from core for every invocation. Replies are ephemeral, with only gate/epoch, digest, counts and safe outcome codes. There is no HTTP apply route or reusable administration token. `status` and `validate` do not write storage. Validation reports a safe failure category; maintain row-level provenance and diagnostic detail in operator-controlled review artifacts.

All file operations use only `/run/secrets/mm-oidc-identity-map.json`. Mount it read-only on every node with identical bytes. It must be a regular, non-symlink file with write permission bits removed (for example 0444), readable by the Mattermost process. The reader bounds input to 1 MiB and 5,000 rows, checks the exact-byte SHA-256 before parsing that same buffer, and rejects duplicate/unknown fields, trailing JSON, duplicate pairs/UUIDs, and invalid preconditions. Keep the host parent private. Do not paste the map into chat or command arguments.

## Approval document

Collect candidate UUID/auth-field and legacy-map data from trusted administrative exports. Independently establish which exact issuer originally authenticated each subject. Current configuration, an email match, a raw-sub lookup, or an existing session does not establish that provenance. Review the evidence and record a nonsecret `provenance_ref` per row. Runtime validates native and registry preconditions; it does not verify the content of external provenance references. An approved hash alone is not provenance: the current core administrator explicitly approves the reviewed document.

The following is a **synthetic schema example**, not a ready-to-apply map. Receipt booleans describe already completed maintenance; do not set them true in a proposal before that work is verified.

```json
{
  "schema_version": 1,
  "approved": true,
  "expected_gate_epoch": 1,
  "issuer": "https://sso.example/realms/work",
  "client_id": "mattermost-oidc",
  "rows": [
    {
      "action": "import_legacy",
      "approved": true,
      "issuer": "https://sso.example/realms/work",
      "subject": "synthetic-subject",
      "mattermost_user_id": "aaaaaaaaaaaaaaaaaaaaaaaaaa",
      "expected_auth_service": "oidc",
      "expected_auth_data": "synthetic-subject",
      "expected_legacy_mapping": "aaaaaaaaaaaaaaaaaaaaaaaaaa",
      "expected_binding_revision": 0,
      "provenance_ref": "review:synthetic-account-provenance"
    }
  ],
  "maintenance": {
    "scope_sha256": "29e82ff38dd99399aeda1b5b1305054f52f13da8f81eb247c09c674e047608ea",
    "all_nodes_quiesced": true,
    "affected_sessions_revoked": true,
    "evidence_ref": "review:completed-maintenance-evidence"
  }
}
```

Every field shown is required. Each `import_legacy` row requires approved=true, existing nondeleted/nonbot `oidc` auth with `AuthData == subject`, the exact legacy mapping UUID, expected revision 0, and independent provenance. A `retain` row uses the exact existing binding revision, empty `expected_legacy_mapping`, and exact native auth fields; its other fields remain required. All rows must use the document issuer. Every existing committed binding for that issuer must appear as `retain`, or as an import already committed by this exact map transaction. Unknown unimported legacy accounts remain blocked. A different issuer may leave old issuer records untouched, but cannot claim a UUID already reserved by an old issuer.

Include a deactivated user with an existing committed binding as a `retain` row;
omitting it prevents activation. Retention requires matching committed forward
and reverse records, revision, and native authentication fields. It preserves
the binding only: a deactivated user remains ineligible for OIDC login and
broker token issuance. An `import_legacy` row still requires an active user.

`maintenance.scope_sha256` is the SHA-256 of the compact JSON string array of **all affected row UUIDs sorted lexicographically**, including retains. Empty scope is the digest of `[]`. Use `encoding/json`-compatible encoding when computing pair and scope digests. `all_nodes_quiesced` and `affected_sessions_revoked` are administrator attestations, not automated remote-node checks. `evidence_ref` must identify the actual maintenance evidence a release reviewer will inspect.

## Maintenance and activation

1. Verify a separate native system administrator can log in. Prepare trusted exports, provenance review and a proposed map; do not claim maintenance is complete yet.
2. Run `freeze`. Record the resulting epoch. Entering frozen increments the epoch; repeating freeze is idempotent. Freeze closes OIDC identity work, **not existing sessions**. Record `expected_gate_epoch` from the frozen gate.
3. Review and validate the proposal. If applying before maintenance completion, its receipt must truthfully say maintenance is incomplete; such a digest cannot activate. Do not later change those bytes and keep using the old hash. The simplest final sequence is to complete maintenance before approving the final bytes.
4. On every serving node, disable OIDC login or stop intake, drain all in-flight callbacks/session creation, and verify no node remains serving an old configuration. Through the supported native administrator mechanism, revoke only the affected users' sessions; verify resulting session lists and rejection of old sessions. Preserve native emergency-administrator access. `freeze` and the plugin do not perform session revocation.
5. After those checks, finalize the receipt with the actual evidence reference. Independently review the complete final document, compute its exact-byte SHA-256, and mount those identical final bytes on every node. An earlier proposal or a changed receipt has a different digest and must be reviewed and validated anew.
6. Run `validate <final-sha256>`, then `apply <final-sha256>` while frozen at the document epoch. Full-file validation precedes row writes; every row is revalidated at its commit. Apply commits matching reverse then forward entries and publishes the approved digest only after all rows are valid. It does not activate login.
7. Recheck that the verified maintenance state still holds. Run `activate <the-same-final-sha256>` against the unchanged bytes. Activation rechecks native/registry/configuration preconditions, exact approved digest and the receipt, then publishes active at the next epoch. Repeating the successful activation of the same digest is idempotent.
8. Enable login for the approved issuer/client, prove a complete callback, and retain the reviewed bytes/digest, command outcomes and maintenance evidence in private operator records.

Changing a receipt after imports were already committed produces a different map transaction. Represent those already committed bindings as `retain` with their exact revisions in the newly reviewed map; never pretend a changed digest is the original import transaction. Any partial failure leaves the gate frozen. Preserve the same original bytes/hash to resume a partially applied map; deterministic row transaction IDs permit safe retry. Conflicts from another map or changed native fields are not overwritten. A fully applied identical map is a no-op while frozen. Activation cannot proceed on partial or inconsistent registry state.

For an empty bootstrap, explicitly approve a zero-row document with `rows: []`, verified empty scope, valid issuer/client and true completed-quiescence receipt. Still execute freeze → validate → apply → activate. Missing registry/gate state never auto-approves an empty database.

## Configuration and recovery

The durable gate is `identity_v1_gate`, schema v1, with uninitialized/frozen/active status, monotonic epoch, issuer/client identity fingerprint, approved digest and receipt. Missing/read-failed storage denies identity work. Observing an issuer or client-ID mismatch freezes the shared gate, and the observing node denies even if its freeze write fails. Returning to the old configuration or restarting never thaws it. Use a newly reviewed activation after a deliberate identity change.

Identity fingerprint is SHA-256 over `["mm-oidc-identity-v1", issuer, clientID]`. Client-secret rotation does not require new provenance for an unchanged issuer/client. Pending callbacks do fail after secret/discovery/redirect/scopes/claim-policy changes because their server-side HMAC callback fingerprint differs. A callback uses a 30-second timeout derived from the incoming request context. A fresh callback uses one coherent immutable provider/verifier/OAuth/config snapshot and remains eligible under the existing active identity gate. Browser binding, PKCE, nonce, web cookies, desktop popup and mobile completion are preserved. The state signing key converges through KV CAS on first startup and is not a credential encryption key.

Resolve storage/native conflicts using independently reviewed evidence and an explicit reconciliation plan. This release has no automatic repair/reassignment/delete command. Do not downgrade to the old plugin while leaving OIDC login enabled: old raw-sub/email ownership behavior bypasses these protections. Keep native password recovery available and OIDC disabled during any rollback assessment.

Approval validation scans all plugin KV key pages to find every committed identity pair; plan maintenance time for the size of the entire plugin KV store. A bounded identity index is not available in this version.

KV CAS is **not atomic with core session creation**. The all-node intake-stop/drain and affected-session revocation procedure closes transition races operationally. Production requires separately authorized maintenance and evidence from the deployed build. The fixture proof below does not establish remote-node quiescence or production bulk-revocation behavior.

## Local evidence and limitations

The isolated acceptance fixture uses Mattermost Team Edition 12.0.1 and Keycloak 26.8.1 over trusted local TLS. Its own database confirmed new `oidc`/qualified 67-byte native AuthData and unchanged legacy `oidc`/raw-sub native fields. Core administrator command invocation succeeded; an ordinary authenticated native user was denied, with ephemeral responses. Explicit empty bootstrap, complete new/returning web OIDC login, email-profile change without rebinding, mismatch/return freeze, restart persistence, and reviewed synthetic legacy import followed by a complete callback all passed. Native password administrator login passed while uninitialized, frozen and after cleanup.

For the synthetic legacy maintenance, login was disabled and completed browser work drained before targeted revocation of the two affected synthetic users. Core `POST /api/v4/users/{id}/sessions/revoke/all` returned 200, affected session lists were checked empty, an old session returned 401, and the separate native administrator remained 200. Only then was the final receipt written and hashed. Apply/activate used unchanged bytes. The fixture was left with OIDC login disabled, client secret cleared and the gate frozen. Real production maintenance and revocation remain unproven and unauthorized.

The bundle now uses a flat archive root and is checked by `scripts/test_bundle.py`. The historical fixture installation used an ignored flat repack of identical build output; that fixture does not independently verify the current bundle pipeline. Automated tests separately cover signed TLS callback web/popup/mobile responses, nonce/userinfo/browser-binding rejection, shared-CAS concurrency, create-response loss and ambiguous recovery, partial imports, issuer/epoch changes, configuration fingerprint races, map bounds/preconditions, current command authority and receipt enforcement. Automated checks do not substitute for the production maintenance review.

## Handoff

B1/B2/B3 consume `ResolvedIdentity`, `AssertCurrentBinding` and `ResolveBrokerBinding` only after their caller authentication/verified OIDC requirements. The binding carries issuer, subject, Mattermost UUID, native auth expectations, binding revision, gate epoch and identity fingerprint. Reassert it before credential save/use/release. B0 owns identity revision and gate epoch only. B1's `CredentialStore` owns the sole monotonic credential generation/tombstone counter, shared with B2; B0 introduces no credential activation protocol. Credential storage, encrypted publication, refresh/disconnect, exchange and bot command authorization remain separate work.
