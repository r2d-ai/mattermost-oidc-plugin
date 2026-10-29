# Mattermost / Mostlymatter OIDC Plugin

A Mattermost / Mostlymatter plugin that adds **OpenID Connect (OIDC)** authentication for [Mattermost](https://mattermost.com) and [Mostlymatter](https://framagit.org/framasoft/framateam/mostlymatter) without an Enterprise license.

## This fork

This repository is [r2d-ai's fork](https://github.com/r2d-ai/mattermost-oidc-plugin)
of [server-camp/mattermost-oidc-plugin](https://github.com/server-camp/mattermost-oidc-plugin).
It adds an approved issuer/subject identity registry, encrypted OIDC credential
retention, distributed refresh/revocation, and an authenticated fixed Plane token
broker. Web and mobile login are retained. Desktop uses upstream v0.7.0's system-browser
login, adapted to this fork's identity and credential checks.

First installs and upgrades from upstream require [identity bootstrap or reviewed legacy
import](docs/oidc-identity-migration.md), even when delegated access is disabled.
Email-based account linking is unsupported in this fork. A missing or frozen
identity gate blocks OIDC login; keep a separate native password administrator.

- [Fork differences and complete commit ledger](docs/fork-differences.md)
- [Merge/backport procedure and required regression checks](docs/upstream-updates.md)
- [Plane broker configuration, keys, API, and operational limits](docs/plane-broker-operations.md)

The fork release is `0.7.0-p1`, based on upstream tag `v0.7.0` at `cbb7bda`.
Upstream's matching version has different identity and delegated-access behavior. Identify builds by source SHA and archive SHA256.

## Why this plugin?

Mattermost restricts generic OIDC authentication to the Enterprise/Professional editions. The free Team Edition only supports GitLab as an SSO provider (and even this only in version 10). This plugin bypasses that limitation by implementing a full OIDC flow as a plugin that works with any standards-compliant OIDC provider.

### Supported OIDC Providers

- **Keycloak**
- **Authentik**
- **Authelia**
- **Zitadel**
- **Dex**
- **LemonLDAP::NG**
- **Okta**
- **Auth0**
- **Azure AD / Entra ID**
- **Google Workspace**
- **Any other OIDC-compliant provider**

Please note that the OIDC provider must support **PKCE S256** (standard with OAuth 2.1) and the OpenID Connect `nonce` claim, which is virtually the case for any modern OIDC provider though.

## Architecture

```
┌──────────────┐    ┌──────────────────┐    ┌───────────────┐
│   Browser    │───▶│    Mattermost    │───▶│ OIDC Provider │
│ (Login Page) │◀───│   Mostlymatter   │◀───│  (Keycloak…)  │
│              │    │   OIDC Plugin    │    │               │
└──────────────┘    └──────────────────┘    └───────────────┘
```

**Flow:**

1. User clicks the OIDC login button
2. Plugin redirects to the OIDC provider (Authorization Code Flow)
3. User authenticates with the provider
4. Provider redirects back to the plugin callback
5. Plugin exchanges the code for tokens, verifies the ID token
6. Plugin resolves the approved issuer/subject binding, creates or updates the
   Mattermost user, and creates a session after current identity checks
7. If credential persistence is enabled, plugin fences and optionally captures
   encrypted credentials before completing web, Desktop, or mobile login

This covers **web and desktop** clients out of the box. For the **native mobile app**, an optional reverse-proxy shim ([`mobile-bridge/`](mobile-bridge/README.md)) is required — see [Native mobile app](#native-mobile-app) below.

## Prerequisites

- **Go** compatible with `server/go.mod`, currently 1.27.3+
- **Node.js** 24 and npm, matching CI
- **Make**
- Mattermost / Mostlymatter Server v9.0+

## Build

```bash
# Clone the repository
git clone <this-repo>
cd mattermost-oidc-plugin

# Build the plugin (server + webapp + bundle)
make all

# The bundle will be at:
# dist/mattermost-oidc-0.7.0-p1.tar.gz (version from plugin.json)
```

### Build server or webapp only

```bash
make server   # Go binaries for all platforms
make webapp   # Webpack bundle
```

### Build bundle for specific platform only
```bash
make bundle SERVER_PLATFORMS=linux/amd64
```

## Tests

```bash
# Run Go tests with race detection
make test

# Desktop webapp tests
(cd webapp && npm test)

# Go linting (requires golangci-lint)
make lint

# Separate mobile-bridge module
(cd mobile-bridge && go vet ./... && go test -race ./... -count=1)

# Documented fork history and archive-validator fixtures
python3 scripts/check_fork_docs.py
python3 scripts/test_bundle_validator.py
```

## Installation

### Method 1: System Console

1. Go to **System Console → Plugin Management**
2. Click **Upload Plugin**
3. Download this fork's `.tar.gz` from the [Releases page](https://github.com/r2d-ai/mattermost-oidc-plugin/releases), or build it from the required source commit
4. Enable the plugin, keep OIDC login disabled during identity maintenance, and
   follow [identity bootstrap or migration](docs/oidc-identity-migration.md)

### Method 2: CLI Deploy

```bash
export MM_SERVICESETTINGS_SITEURL=https://chat.example.com
export MM_ADMIN_TOKEN=your-admin-token
make deploy
```

## Configuration

### 1. Set up your OIDC provider

Create a new OIDC application/client with your provider using the following settings:

| Setting          | Value                                                              |
|------------------|--------------------------------------------------------------------|
| **Client Type**  | Confidential                                                       |
| **Grant Type**   | Authorization Code                                                 |
| **Redirect URI** | `https://chat.example.com/plugins/mattermost-oidc/oauth2/callback` |
| **Scopes**       | `openid profile email`                                             |

### 2. Configure the plugin

Go to **System Console → Plugins → OIDC Authentication**:

| Field                                    | Description                       | Example                                               |
|------------------------------------------|-----------------------------------|-------------------------------------------------------|
| **Enable**                               | Enable the plugin                 | `true`                                                |
| **Retain Encrypted OIDC Credentials**     | Optional fresh-login capture; requires external AES ring | `false` |
| **Enable Plane Delegated Access**        | Fixed broker; also requires persistence and external HMAC ring | `false` |
| **Issuer URL**                           | OIDC Issuer URL                   | `https://idp.example.com/application/o/mostlymatter/` |
| **Client ID**                            | Client ID from your provider      | `mostlymatter`                                        |
| **Client Secret**                        | Client secret from your provider  | `secret123`                                           |
| **Scopes**                               | Requested scopes                  | `openid profile email`                                |
| **Button Text**                          | Text on the login button          | `Log in with SSO`                                     |
| **Button Color**                         | Color of the login button         | `#0058CC`                                             |
| **Username Claim**                       | OIDC claim for username           | `preferred_username`                                  |
| **Email Claim**                          | OIDC claim for email              | `email`                                               |
| **First Name Claim**                     | OIDC claim for first name         | `given_name`                                          |
| **Last Name Claim**                      | OIDC claim for last name          | `family_name`                                         |
| **Position Claim**                       | OIDC claim for position/job title | `position`                                            |
| **Email Verified Claim**                 | OIDC claim for email verification | _(empty, set to `email_verified` to enable)_          |
| **Require Email Verified**               | Reject login if claim is not true | `false`                                               |
| **Auto-Create Accounts**                 | Automatically create new accounts | `true`                                                |
| **Auto-link by email (unsupported)**      | Ignored compatibility setting; never grants identity ownership | `false` |
| **Default Team**                         | Team slug for new users           | `main`                                                |

Email is profile data, including when it is verified. It never establishes
ownership of an existing account. Legacy OIDC users need an independently
reviewed issuer/subject import. Existing native password accounts cannot be
automatically converted to OIDC.

The two delegated settings default to false and are live policy. They do not
change pending callback fingerprints. Disabling interactive **Enable** alone
does not disable delegated access. Turning either delegated setting off stops
issuance but does not durably revoke stored credentials. See
[Plane broker operations](docs/plane-broker-operations.md) before enabling them.

#### Desktop app

The Mattermost Desktop app signs in through the system browser and returns to the app via `mattermost://`. This requires that:

- the app's server URL equals the configured `SiteURL`,
- `mattermost://` is registered for the app, and
- the identity provider is not served from the `SiteURL` origin.

The system browser receives a one-time code, not a Mattermost session. The app
redeems the code with its local verifier through `POST /oauth2/callback` within
120 seconds. Redeem checks the current approved identity, callback policy and
native auth before creating a session and completing optional credential capture.
If the gate, binding, or callback policy changed, start a fresh login.


### 3. Approve the identity gate

Use the [identity maintenance procedure](docs/oidc-identity-migration.md#maintenance-and-activation)
to freeze, validate, apply, and activate an approved map. An empty installation
still requires explicit approval of an empty map. Imported users keep their
UUID, memberships, and native OIDC auth fields. A restart does not initialize
or reactivate the gate. After activation, enable OIDC login and verify the
complete callback with the intended client.

## Example: Keycloak Configuration

1. Create a new client
   - Client ID: mostlymatter
   - Client Protocol: openid-connect
   - Access Type: confidential
   - Valid Redirect URIs: https://chat.example.com/plugins/mattermost-oidc/oauth2/callback
2. Ensure client scopes are assigned:
   - `openid`, `profile`, `email` must be assigned
3. Discovery Endpoint:
   https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration

## Example: Authentik Configuration

1. Create an OAuth2/OpenID Provider
   - Name: Mostlymatter
   - Authorization flow: `default-provider-authorization-explicit-consent`
   - Redirect URIs: https://chat.example.com/plugins/mattermost-oidc/oauth2/callback
   - Scopes: `openid`, `profile`, `email`
   - Signing key: _select a valid certificate (may be self-signed)_
2. Create an application and assign the provider
3. Discovery Endpoint:
   https://sso.example.com/application/o/mostlymatter/.well-known/openid-configuration

Note that Authentik doesn't have a `family_name` claim. Mattermost optimistically skips parsing the family name if not present.

## Project Structure

```
mattermost-oidc-plugin/
├── plugin.json              # Plugin manifest and settings schema
├── Makefile                 # Build system
├── README.md                # This file
├── AGENTS.md                # Fork contracts and agent workflow
├── docs/                    # Fork ledger, upstream updates, identity/broker runbooks
├── scripts/                 # Fork documentation and archive checks
├── assets/
│   └── oidc-icon.svg        # Plugin icon
├── server/
│   ├── go.mod               # Go module definition
│   ├── main.go              # Entry point
│   ├── plugin.go            # Plugin struct, lifecycle, router
│   ├── configuration.go     # Configuration type and validation
│   ├── oauth2.go            # Verified callback, session/capture and completion
│   ├── desktop.go           # Verifier-bound Desktop handoff and redeem
│   ├── login_snapshot.go    # Coherent login configuration and fingerprints
│   ├── identity_*.go        # Pair registry, gate, migration and admin commands
│   ├── credential_store.go  # Encrypted CAS envelope and generation
│   ├── token_lifecycle.go   # Distributed refresh and revocation
│   ├── broker_auth.go       # HMAC, replay buckets and quotas
│   └── plane_broker.go      # Fixed exchange and verified output
├── webapp/
│   ├── package.json         # Node dependencies
│   ├── webpack.config.js    # Webpack configuration
│   └── src/
│       ├── index.js         # Login button React component
│       └── desktop_login.js # Desktop verifier, system browser and redeem
└── mobile-bridge/           # Optional reverse-proxy shim for native mobile app
    ├── main.go              # Shim: client-config injection + mobile_login redirect
    ├── Dockerfile           # Container image for the shim
    └── README.md            # Ingress wiring, env vars, test plan, troubleshooting
```

## Security

- **HMAC-signed state parameters** prevent CSRF attacks
- **PKCE S256** is always sent on the authorization request
- **`nonce`** is always sent and checked on the ID token
- **State tokens** are stored in the KV store with an expiry time
- **ID token verification** via the provider's JWKS
- **Issuer/subject ownership** uses committed bidirectional identity records,
  current native auth checks, and an explicitly approved durable gate
- **Optional retained credentials** use AES-256-GCM with external keys, one
  monotonic CAS generation, and durable invalidation
- **Delegated Plane tokens** require canonical caller HMAC, durable replay
  checks, constrained exchange, and verified output claims
- **No client secret** is sent to the browser
- **Secure cookies** are set when HTTPS is configured
- **Username sanitization** prevents injection attacks

### MFA

This plugin creates sessions directly after a successful OIDC flow and does **not** evaluate Mattermost's built-in MFA. If users have Mattermost-level MFA configured, it will be bypassed when logging in via OIDC.

**Recommendation:** Enforce MFA at the OIDC provider level instead (Keycloak, Authentik, Authelia, etc. all support this). This is the more robust approach — MFA is enforced for every login regardless of which client or plugin is used.

## Native mobile app

The plugin's login button only renders in the web and desktop clients. The **native Mattermost mobile app** hardcodes its SSO to the core OpenID flow: it shows an OpenID button only when the *client config* advertises it, and always posts the flow to the core endpoint `/oauth/openid/mobile_login` — neither of which a plugin can influence.

To bridge this, the repository ships an optional reverse-proxy shim in [`mobile-bridge/`](mobile-bridge/README.md). Placed in front of Mattermost in your ingress, it intercepts exactly two paths for mobile clients and forwards everything else (REST, WebSocket, files, `/plugins/...`) untouched:

```
mobile app ──▶ ingress ──▶ /api/v4/config/client      → bridge (inject EnableSignUpWithOpenId=true, mobile UA only)
                           /oauth/openid/mobile_login → bridge (302 → plugin connect with mobile_redirect)
                           everything else            → Mattermost
```

The plugin side handles the mobile callback by handing the session token back to the app via its custom URL scheme (`mmauth://callback?MMAUTHTOKEN=…&MMCSRF=…`), mirroring Mattermost core's `mobile_login` flow. Web and desktop clients are completely unaffected.


## Troubleshooting

**"OIDC provider not initialized"**
→ Check the discovery endpoint, review server logs

**"Authentication session expired"**
→ Ensure that the clocks of Mattermost / Mostlymatter and the OIDC provider are synchronized

**"email claim is empty"**
→ Check that the OIDC provider returns the `email` scope and that the claim name is correct

**Login button not visible**
→ Enable the plugin in the System Console, clear browser cache

**"failed to create user"**
→ Check that auto-create is enabled and that the username doesn't already exist

## Development

### Docker Development Environment

The repository includes a `docker-compose.dev.yml` with Mattermost / Mostlymatter and Keycloak as an OIDC provider:

```bash
# Start the environment
docker-compose -f docker-compose.dev.yml up -d

# Mattermost:  http://localhost:8065
# Keycloak:    http://localhost:8080 (Admin: admin / admin)

# Stop the environment
docker-compose -f docker-compose.dev.yml down
```

After starting Mattermost / Mostlymatter: create an admin account, enable plugin uploads under **System Console → Plugin Management**, then upload the built bundle.

### Build & Deploy

```bash
export MM_SERVICESETTINGS_SITEURL=http://localhost:8065
export MM_ADMIN_TOKEN=your-token

# Build and deploy the plugin
make deploy

# Or use watch mode for the webapp:
cd webapp && npm run dev
```

### Creating a Release

```bash
make release
# Current version: 0.1.0
# New version (without v): 1.0.0
# Tagged v1.0.0 — push with: git push && git push origin v1.0.0
```

Updates `plugin.json` and `webapp/package.json`, commits the version bump, creates an annotated git tag, and prints the push command. The CI/CD pipeline then builds and publishes the release automatically.

## CI/CD

The repository uses GitHub Actions (`.github/workflows/ci.yml`):

| Job             | Trigger          | Description                                              |
|-----------------|------------------|----------------------------------------------------------|
| `test-server`   | every push / PR  | Module verification and Go tests with race detection and coverage |
| `test-mobile-bridge` | every push / PR | Separate module vet and race tests |
| `lint-server`   | every push / PR  | golangci-lint (non-blocking)                             |
| `build-server`  | every push / PR  | Cross-compile for linux/darwin × amd64/arm64             |
| `build-webapp`  | every push / PR  | `npm ci`, Desktop tests, and webpack production build                     |
| `build-bundle`  | every push / PR  | Flat archive, manifest-artifact validation, validator fixtures |
| `build-mobile-bridge` | every push / PR | Multi-architecture bridge image; published outside PRs |
| `release`       | `v*` tags on main | Verify bundle version/executables and publish bundle plus SHA256SUMS |

The pipeline runs automatically on every push and pull request. To cut a release, use `make release` and push the resulting tag.

## License

Apache License 2.0 — compatible with Mattermost and Mostlymatter.

## Disclaimer

This project is an independent community plugin and is **not affiliated with, endorsed by, or officially connected to Mattermost, Inc. or the Mostlymatter project**. "Mattermost" is a trademark of Mattermost, Inc.
