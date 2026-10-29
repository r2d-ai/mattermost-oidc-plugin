# AGENTS.md

## Read before changing this fork

This is `r2d-ai/mattermost-oidc-plugin`, forked from
`server-camp/mattermost-oidc-plugin`. It adds issuer-bound identity maintenance
and delegated Plane access to the upstream Mattermost / Mostlymatter OIDC login.

Read [fork differences and commit ledger](docs/fork-differences.md) before editing
authentication, configuration, storage, or packaging. Before merging or
backporting upstream changes, follow [the upstream update procedure](docs/upstream-updates.md).
Upstream files and tests do not describe all of this fork's requirements.

The audited common ancestor is upstream `v0.6.2`, `99920ca`. The fork manifest
also says `0.6.2`; the version alone cannot distinguish upstream, this fork, or
the deployed evidence build. Record source SHA and archive SHA256.

## Contracts to preserve

- Identity ownership is the exact verified `(issuer, subject)` bound to one
  Mattermost UUID through matching committed forward/reverse CAS records.
  `AutoLinkByEmail` is ignored. Email and `oidc_user_<subject>` are never login
  authority. Do not restore upstream `getOrCreateUser` or email-based auth conversion.
- New native `AuthData` is `v2:` plus the pair digest, 67 bytes. Reviewed legacy
  imports retain their UUID and raw-sub auth fields. Never normalize verified
  issuer/subject or reassign a committed UUID.
- Missing/uninitialized/frozen identity gate denies OIDC work. Even an empty
  install needs explicit administrator approval. Issuer/client-ID changes freeze
  the durable gate; reverting config or restarting cannot reactivate it.
  Native password administrator access stays independent.
- Callbacks use one `LoginSnapshot`, signed state fingerprints and gate epoch.
  Keep `assertLoginSnapshot` and `AssertCurrentBinding` checks around account,
  session, credential, and release steps. Discovery results must obey both
  configuration revision and `discoveryAttempt` ordering.
- Preserve HMAC state, atomic state consumption, PKCE S256, nonce, matching
  userinfo subject, web/desktop state-cookie binding, cookie Domain/Path/lifetime,
  desktop popup completion, and allowlisted mobile completion. The current fork
  uses desktop popup login. Upstream's newer system-browser/redeem flow is not
  integrated; its separate session endpoint needs fork authority checks too.
- `Enable` controls interactive login. `EnableTokenPersistence` controls capture.
  Delegated use requires both `EnableTokenPersistence` and `EnablePlaneBroker`,
  each default false, plus current identity authority. Disabling login alone
  does not disable delegated use. Disabling delegated flags is not revocation.
- Credential capture follows verified login and successful session creation.
  Fence before optional encryption/publication. Initial-fence or authority
  failure withholds all completion tokens and revokes only the new session.
  Confirmed fencing allows optional capture failure to preserve ordinary login.
- AES-GCM credentials and refresh use one durable CAS envelope/generation.
  Preserve `ready`, `refreshing`, nonissuing candidate, and `invalidated` semantics.
  Never delete/reset tombstones, retry an ambiguous rotating refresh, or promote
  an abandoned candidate. Cleanup must compare exact owned bytes.
- Credential AES keys and broker HMAC keys come from separate external process
  rings. KV `_plugin_encryption_key` signs OAuth state only. Never use it as an encryption
  or broker fallback, or expose secret-bearing structs/provider bodies in logs.
- Broker calls require canonical HMAC authentication and durable replay CAS on
  both public HTTP and `PluginHTTP`. User headers, UUIDs, and plugin transport
  alone authorize nothing. Keep the fixed client/audience/scopes, verified output,
  generation/configuration/key rechecks, no-store responses, and 409 versus 503
  classification. Nonce bucket collisions must coexist; never evict live nonces.
- Disconnect/revoke require a current core human session and explicit CSRF;
  revoke additionally requires a freshly resolved system administrator.
  Invalidate locally before best-effort provider revoke. Cleanup must work for
  frozen/deactivated bindings without decrypt keys. The deactivation hook is
  best effort; issuance independently checks current user eligibility.
- Keep flat plugin archive roots, manifest-referenced artifacts only, executable
  server binaries, bundle validation, release version checks, and `SHA256SUMS`.

## Code map

| Files | Responsibility |
| --- | --- |
| `server/main.go`, `server/plugin.go` | Lifecycle, ordered discovery, routing, management-session guard, deactivation hook |
| `server/configuration.go`, `plugin.json` | Settings, validation, independent delegated switches, deprecated email linking |
| `server/oauth2.go`, `server/login_snapshot.go` | Verified callback, immutable provider/config snapshot, fingerprints, session and optional capture, web/popup/mobile completion |
| `server/identity_binding.go`, `server/identity_gate.go` | Pair/UUID registry, native auth expectations, durable gate/epoch, current binding assertions |
| `server/identity_command.go`, `server/identity_migration.go` | `/oidc-identity` commands, fixed approval file, reviewed import/retain and activation |
| `server/credential_store.go` | External AES ring, encrypted CAS envelope, generation and invalidation |
| `server/token_lifecycle.go` | Distributed rotating refresh, exact-owner cleanup, disconnect and generation assertions |
| `server/broker_auth.go`, `server/plane_broker.go` | Caller HMAC, durable nonce buckets, quotas, constrained exchange and signed output verification |
| `webapp/src/index.js` | React login button, Desktop detection/popup, storage-event fallback, older-server DOM injection on `/login` |
| `mobile-bridge/` | Separate Go module and ingress proxy, mobile config injection gated on plugin enable, mobile-login redirect |
| `scripts/test_bundle*.py`, `Makefile`, `.github/workflows/ci.yml` | Archive validation, builds and release verification |

Public plugin routes are `GET /oauth2/connect`, `GET /oauth2/callback`, and
`GET /api/v1/config`. Additional routes are `POST /internal/plane-token`,
`POST /api/v1/plane/disconnect`, and `POST /api/v1/plane/revoke`, under
`/plugins/mattermost-oidc`. Unknown `/internal/` routes return 404.

## Build and verification

Use Go compatible with `server/go.mod` and `mobile-bridge/go.mod`. The audited
server minimum is 1.26.7. CI selects Go 1.26 and Node 24. React is external to
the webpack UMD bundle and requires >=16.8.

```bash
make all                         # Four server platforms, webapp, validated archive
make server                      # linux/darwin x amd64/arm64, CGO_ENABLED=0
make webapp                      # npm install + production webpack
make bundle SERVER_PLATFORMS=linux/amd64
make test                        # Server race suite only
make lint                        # Requires golangci-lint
python3 scripts/check_fork_docs.py
python3 scripts/test_bundle_validator.py
(cd server && go mod verify && go test -race ./... -count=1)
(cd mobile-bridge && go vet ./... && go test -race ./... -count=1)
(cd webapp && npm ci && npm run build)
```

`npm run dev` is a watch build, not a test. This fork's webapp has no test
script. Server tests include signed TLS OIDC callbacks, shared fake durable KV,
CAS recovery, encrypted capture, refresh races, management authorization, broker
authentication and exchange. Run the full server race suite for auth changes;
use the [contract-to-test map](docs/fork-differences.md#regression-test-map) to
identify required cases and add tests for new session paths.

`make deploy` uploads to `MM_SERVICESETTINGS_SITEURL` using `MM_ADMIN_TOKEN`.
`make release` commits version changes and tags locally. Run these only as part
of requested deployment/release work. `make clean` also removes node_modules.

## Operations and evidence

- Follow [identity migration and recovery](docs/oidc-identity-migration.md) for
  first-install bootstrap and legacy imports. The only approval file path is
  `/run/secrets/mm-oidc-identity-map.json`. Freeze does not revoke existing sessions.
- Follow [Plane broker operations](docs/plane-broker-operations.md) for key
  rings, switches, API contracts, rotation, disconnect, and rollout limits.
- `docker compose -f docker-compose.dev.yml up -d` starts the HTTP development
  stack at Mattermost `:8065` and Keycloak `:8080`. It does not bootstrap the
  fork's gate or establish delegated HTTPS/provider capability acceptance.
- Historical [isolated deployed evidence](docs/evidence/plane-broker-live.md)
  applies to `cfbd710`, not later hardening commits. Preserve historical artifacts
  and their build hashes. Passing tests or a successful merge does not establish
  production approval, all-node quiescence, or atomic KV/core-session changes.

CI verifies server modules/race tests, vets/tests the mobile bridge, builds four
server targets and the webapp, validates the flat bundle, and builds the bridge
image. The server linter is non-blocking. Release checks require the tag to be
reachable from `main`, matching manifest version, executable artifacts, and
checksums. The audit helper is currently a manual check, not a CI job.
