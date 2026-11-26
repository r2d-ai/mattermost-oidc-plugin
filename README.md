# Mattermost / Mostlymatter OIDC plugin

- [Complete Plane integration setup](https://github.com/r2d-ai/mattermost-plugin-plane/blob/main/docs/setup.md)
- [Broker operations and contracts](docs/plane-broker-operations.md)
- [Troubleshoot broker and Plane API](docs/plane-troubleshooting.md)
- [Identity upgrade and maintenance](docs/oidc-identity-migration.md)
- [Upgrade notes](docs/upgrade-notes.md)

## Configure delegated access before asking users to reconnect

The current manifest version is `0.8.0-p1`. Keep the
existing confidential OAuth client, for example `mattermost`. The internal
Mattermost plugin ID remains `mattermost-oidc`; Plane's browser client can remain
`plane-web`; the API audience is `plane-api`.

Mattermost must inherit all three independent key sets:

```dotenv
MM_PLANE_BROKER_HMAC_ACTIVE_KEY_ID=broker-v1
MM_PLANE_BROKER_HMAC_KEYS={"broker-v1":"REPLACE_WITH_BROKER_KEY"}
MM_PLANE_ACTION_HMAC_ACTIVE_KEY_ID=action-v1
MM_PLANE_ACTION_HMAC_KEYS={"action-v1":"REPLACE_WITH_ACTION_KEY"}
MM_OIDC_CREDENTIAL_ACTIVE_KEY_ID=credential-v1
MM_OIDC_CREDENTIAL_KEYS={"credential-v1":"REPLACE_WITH_CREDENTIAL_KEY"}
```

Broker HMAC authenticates inter-plugin requests, action HMAC signs Plane UI
interactions, and the OIDC credential key encrypts retained user tokens. Run
`openssl rand -base64 32` separately for each new key. Preserve existing keys;
these placeholders are not valid secrets. The Plane plugin's key-reference UI
fields take `broker-v1` and `action-v1`, not the Base64 key values. Inject the
variables into the actual Mattermost service/container and restart/recreate it.
Exporting them in an unrelated terminal does not update running plugin processes.

Enable **Retain Encrypted OIDC Credentials** and **Enable Plane Delegated Access**.
Configure Standard Token Exchange V2, the Optional `plane.read`/`plane.write`
scopes and their `plane-api` audience mapper on the existing requester client.
Normal OIDC login scopes may stay in place. Returned non-Plane scopes do not
grant Plane privileges; all requested Plane grants remain mandatory.

Enable bearer authentication separately in Plane API and verify its effective
policy. It needs the requester in `OIDC_API_ALLOWED_CLIENTS`, algorithm `RS256`,
access-token type `Bearer`, and its API bearer switch enabled. Browser SSO alone
is insufficient. See [complete setup](https://github.com/r2d-ai/mattermost-plugin-plane/blob/main/docs/setup.md)
for environment/database precedence and exact Keycloak steps.

## Recover an initial same-issuer legacy upgrade

Keep a current System Admin session open and install the current build on every
node. Confirm the exact issuer that authenticated existing OIDC users, then run:

```text
/oidc-identity status
/oidc-identity approve-legacy https://login.example.com/realms/work
```

This explicit historical-issuer approval only initializes a clean uninitialized
gate. It cannot unfreeze a gate or replace an existing registry. Each legacy
account migrates during a fresh verified callback, preserving native UUID/auth
fields and existing sessions. No SQL or manual map is needed for this route.
Changing an approved issuer/client still freezes the gate; restoring old config
does not reactivate it. Use reviewed maintenance for those transitions.

Users who need Plane must complete one fresh OIDC login after persistence and
credential keys are ready. `/plane connect` only supplies the link. Do not force
bulk logout or repeat login for every deployment. A verifier-only upgrade or a
Plane API configuration fix does not itself require fresh credentials.

## Verify both broker and resource access

Run `/plane status`, then `/plane projects`. Broker readiness only confirms
verified token issuance. A reconnect message after broker success can be a Plane
API 401. Correlate both components' current logs before changing credentials.
Use the [troubleshooting runbook](docs/plane-troubleshooting.md), including its
warning that `_access_jwks` diagnostics can populate shared Redis.

## Build and verification

Use the Go version declared in `server/go.mod` and `mobile-bridge/go.mod`,
currently Go 1.27.3, plus Node.js 24. Keep dependencies pinned by their module and
npm lockfiles.

```sh
make test
cd mobile-bridge
go vet ./...
go test -race ./... -count=1
cd ../webapp
npm ci
npm test
npm run build
cd ..
make bundle
python3 scripts/test_bundle.py dist/mattermost-oidc-0.8.0-p1.tar.gz
python3 scripts/check_fork_docs.py
```

The installable archive contains the root manifest, four executable server
binaries, webapp and icon. Record source SHA and archive SHA-256; a version string
alone does not identify a local or deployed build. A successful local suite does
not establish production acceptance or cold-cache recovery.

## More documentation

- [Provider, platform and development reference](docs/plugin-reference.md)
- [Fork contracts and regression map](docs/fork-differences.md)
- [Upstream merge/backport procedure](docs/upstream-updates.md)
- [Detailed identity maintenance](docs/oidc-identity-migration.md)

The plugin is based on upstream `server-camp/mattermost-oidc-plugin`, with the
additional identity and delegated-access behavior documented above. See the
[license](LICENSE).
