# Merge or backport upstream changes

Use this procedure for `server-camp/mattermost-oidc-plugin` changes entering the
`r2d-ai` fork. Read [the fork contracts and ledger](fork-differences.md) first.

## Establish the exact range

1. Record the fork HEAD and worktree changes. Preserve unrelated local work.
2. Fetch upstream without tags. Use an existing verified upstream remote, or
   fetch the URL below. Record `FETCH_HEAD` immediately, since a later fetch
   replaces it. Do not overwrite the fork's `v0.6.2` tag with upstream's tag.

   ```bash
   git status --short --branch
   git rev-parse HEAD
   git fetch --no-tags https://github.com/server-camp/mattermost-oidc-plugin.git main
   git rev-parse FETCH_HEAD
   git merge-base HEAD FETCH_HEAD
   git log --left-right --cherry-mark --oneline HEAD...FETCH_HEAD
   python3 scripts/check_fork_docs.py --upstream FETCH_HEAD
   ```

3. Inspect each candidate commit's diff, its parent dependencies, and the final
   upstream behavior. For a merge, review the upstream-only range, not only the
   merge message. Do not assume a clean Git merge preserves behavior.
4. Work on an isolated integration branch/worktree. Pin the upstream SHA in the
   change description. Choose a full merge or a narrow backport based on the
   needed behavior and dependencies, then inspect the resulting fork diff.

## Review affected contracts

For every changed path, review the corresponding rows in the
[regression test map](fork-differences.md#regression-test-map).

| Candidate touches | Review alongside it |
| --- | --- |
| `oauth2.go`, session helpers, new login routes | `identity_binding.go`, `login_snapshot.go`, `credential_store.go`, full callback fixtures and all completion transports |
| Provider discovery, config loading, scopes or claims | `discoveryAttempt`, monotonic `configurationRevision`, snapshot fingerprints, gate freeze, live delegated switches, broker post-network checks |
| User lookup/create/update/auth fields or email linking | Exact issuer/subject ownership, forward/reverse commits, legacy approval, native-account preservation, default-team recovery |
| KV storage, startup, cleanup, deactivation or logout | Gate durability, state-key CAS, one credential generation, exact-owner cleanup, tombstones, nonce bucket format, active-user checks |
| Router, PluginHTTP or headers | Separate public login, human-session+CSRF management, and canonical HMAC broker boundaries; unknown internal-route rejection |
| Provider/JWT/HTTP libraries | Subject matching, signature/claim profile, redirect refusal, response/token bounds, refresh ambiguity, cancellation and expiry checks |
| Manifest, build, CI, release or versions | Default-off delegated flags, ignored AutoLinkByEmail, unchanged plugin ID, flat archive, exact contents, executable modes, checksums and source identity |
| Webapp/Desktop/mobile bridge | Popup/storage fallback or an explicitly adapted replacement, mobile scheme allowlist, session duration/mobile flag, config enable gating and `/login`-only injection |

Resolve conflicts by preserving the contracts, then incorporating the upstream
fix. Do not resolve entire auth/config/build files with `--theirs` or `--ours`.
Retain fork regression assertions when upstream renames or replaces test helpers.

## Adapt session and desktop changes

Upstream PR #39's system-browser Desktop flow is integrated with fork checks
as part of v0.7.0. Apply these rules to later session or transport refactors:

1. Enumerate every place that creates a native session or releases a cookie,
   app token, or redeem code. Include delayed redemption and new HTTP handlers.
2. Carry the exact verified issuer/subject binding and required snapshot/gate
   metadata across any delayed handoff. Revalidate current native auth, binding
   revision, gate epoch, and configuration before effects and release. A user
   UUID, `AuthService=oidc`, or a previously verified callback is insufficient.
3. Preserve the order of successful session creation, optional capture, durable
   fencing and final authority checks. Decide explicitly how a delayed Desktop
   redemption satisfies fresh verified credential capture. Keep provider
   credentials out of the browser and deep link. Withhold completion on authority
   failure and revoke only the session created by that attempt.
4. Keep web/popup browser-state binding while those paths exist. If replacing
   popup with system-browser login, require the verifier-bound, single-use
   handoff and add fork authority tests at redeem. Do not broaden the mobile
   exemption to unrelated callback paths.
5. Add end-to-end handler tests for the new path, including gate freeze,
   issuer/client or claim-policy change, deactivation, changed native auth,
   replay, stale handoff, optional capture failure, failed fencing, and existing
   session preservation. Preserve working web and mobile login.
6. Update `AGENTS.md`, the contract/test map, and the operator Desktop description
   together when adopting the new transport. Removing the popup implementation
   requires a tested replacement that retains the fork's session guarantees.

## Verify the resulting fork

From the repository root, run the following checks with the selected compatible
Go toolchain and CI's Node version:

```bash
python3 scripts/check_fork_docs.py
python3 scripts/test_bundle_validator.py
(cd server && go mod verify && go test -race ./... -count=1)
(cd mobile-bridge && go vet ./... && go test -race ./... -count=1)
(cd webapp && npm ci && npm test && npm run build)
make all
bundle_version=$(python3 -c 'import json; print(json.load(open("plugin.json"))["version"])')
python3 scripts/test_bundle.py "dist/mattermost-oidc-${bundle_version}.tar.gz"
git diff --check
```

`make all` also validates the actual archive. The validator
fixture alone does not prove the built release artifact is correct. `make test`
covers only the server module; `npm run dev` is a watch build. If upstream adds
webapp tests, run those too.

For changed login, broker, SDK, or provider behavior, use an isolated installed
fixture to exercise real web/Desktop/mobile completion, current identity
bootstrap/import, native administrator recovery, capture, refresh, disconnect,
and authenticated broker transports affected by the change. Record the exact
source commit, compiler, provider/server versions, archive SHA256, and outcomes.
Report any unrun checks. Never relabel historical evidence as verification of a
new build.

## Review storage transitions and rollback

- Keep the existing KV namespaces, digest serialization, qualified native auth,
  gate epochs, credential generations, and encryption AAD compatible. Treat
  any intended format change as a migration with explicit upgrade/rollback rules.
- For nonce single-entry to bucket upgrades, drain broker traffic and upgrade
  all serving nodes. New code reads both formats; old code cannot read buckets.
  Never roll back while broker admission is enabled or evict live replay entries.
- Use the [identity maintenance procedure](oidc-identity-migration.md#maintenance-and-activation)
  for transitions requiring approval. Freeze does not stop all existing sessions
  or atomically drain other nodes. Verify actual quiescence and affected-session
  revocation before finalizing the receipt.
- Do not downgrade to upstream raw-sub/email ownership with OIDC login enabled.
  Preserve separate native administrator access and assess rollback with OIDC
  disabled. Disabling delegated switches stops issuance but does not erase
  credentials, reset tombstones, or invalidate already-issued Plane tokens.

## Record the integration

In the review description, list the exact upstream range, intended behavior,
affected fork contracts, conflict decisions, test/build results, installed
evidence, and any rollout or rollback constraints. Update the fork ledger and
audit boundary when reviewing additional fork commits. Keep historical evidence
files tied to their original build and add separate evidence for the new build.
