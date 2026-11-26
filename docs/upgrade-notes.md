# Delegated-access upgrade notes

Current behavior is described in the README and broker operations guide. These
notes record the recovery changes, not a claim that every local build was
published or deployed everywhere.

## Plane scopes and other application scopes

Version `0.7.0-p6` validates the requested `plane.*` grants rather than rejecting
a token because the realm adds an unrelated scope. Missing Plane grants,
unrequested write access, unknown Plane capabilities and duplicate scopes
remain rejected. Existing client IDs, sessions, identity gate and provider
configuration do not need to change to install this fix.


## Standard OIDC scopes in exchanged tokens

Version `0.7.0-p5` accepts ordinary OIDC/Keycloak scopes alongside requested Plane
scopes, including `openid`, `profile` and `email`. It still requires every
requested Plane grant and rejects unrequested Plane write access. Existing
login scopes do not need to be removed to satisfy the broker. Upgrade without
changing client IDs, resetting the gate or forcing another login.


## Diagnose rejected Plane exchange tokens

Version `0.7.0-p4` records the exact exchange failure step, a safe reason code and
HTTP status where available. Existing token validation remains unchanged. It
does not log tokens, credentials or provider response bodies. Upgrade without
changing your current issuer/client settings or approving the identity gate again.


## Fix Plane broker rejection with an existing OAuth client

Version `0.7.0-p3` fixes the broker rejecting an OIDC Client ID other than
`mattermost-oidc`. For example, an existing Keycloak client named `mattermost`
now remains the client used for delegated exchange and verified token `azp`.

| Setting | Value | Purpose |
| --- | --- | --- |
| Plane plugin: Broker plugin ID | `mattermost-oidc` | Internal Mattermost plugin destination. |
| OIDC plugin: Client ID | Your existing client, such as `mattermost` | OAuth client registered in Keycloak. |

Install `0.7.0-p3` without changing either setting. An already active identity
gate and retained credentials continue to work; no repeat `approve-legacy` is
needed for this fix. Run `/plane status` again. Provider-side token-exchange
permissions, audience `plane-api` and Plane scopes must still be configured.
The Plane API's `OIDC_API_ALLOWED_CLIENTS` environment allowlist must also contain
that OAuth Client ID, for example `mattermost`; keep any other required allowed
clients when adding it.


## Recover OIDC login after upgrading from the original plugin

If `/oidc-identity status` reports `gate=uninitialized` and existing users can no
longer start OIDC login, install version `0.7.0-p2` or newer on every Mattermost
node. Keep your current administrator session open.

From a current System Admin session, run this once, replacing the URL with the
**exact issuer that authenticated your existing OIDC users**:

```text
/oidc-identity approve-legacy https://login.example.com/realms/work
```

This is the administrator's explicit approval of the historical issuer for the
existing legacy mappings. It must match the plugin's configured issuer exactly.
The command does not infer ownership from email or silently approve a configured
provider. Run it only after confirming the previous deployment used that issuer.

Existing users can then log in through OIDC. Each successful verified callback
converts its existing linkage to the new registry while keeping its original
Mattermost user ID and native auth fields. Existing sessions stay valid. No SQL,
manual migration JSON, replacement accounts or bulk logout is needed for this
same-issuer upgrade.

The command only initializes a previously uninitialized gate. It cannot unfreeze
a gate, change an approved issuer or reassign an existing account. For deliberate
issuer changes, previously frozen gates or conflicting records, use the reviewed
[identity migration procedure](oidc-identity-migration.md).
