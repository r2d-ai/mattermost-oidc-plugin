# Upstream v0.8.0 merge verification

Verification date is 2026-11-26. The merge commit is `2cb93ab2dc0245b13c5dc7fa89efaceaa481713d`. Its upstream
parent is `7818bd0cdb9a6d3b94f477749ed3cee8b6bf64db`, the exact
`v0.8.0` tag. The fork bundle identifies itself as `0.8.0-p1`.

## Automated checks

Go 1.27.4 and Node 24.21.0 were used. Server module verification and the full
server race suite passed on both the merge commit and the working tree with
the pre-existing p2–p6 changes reapplied. Mobile bridge vet and race tests
passed. The webapp clean install, tests, and production build passed. The fork
ledger, bundle validator fixtures, and actual four-platform bundle passed.

The clean merge bundle was `mattermost-oidc-0.8.0-p1.tar.gz`. Its SHA-256 was
`cac149b4a1c0ec21433bf4badd5d0136dcf78143858c0a82dfd37fcc3f3d0747`.
Build metadata for all four server binaries reported the merge commit and
`vcs.modified=false`. The separate test build with the existing local edits
had archive SHA-256
`d22af6849c08e3539f745af3e674d42e29834f19896c864ee0ac3791cae93480`
and `vcs.modified=true`.

## Installed checks

The clean archive was installed on a disposable local Mattermost Team Edition
12.1.0 instance with Keycloak 26.6.3 and a fixture TLS certificate. Empty-gate
bootstrap used `freeze`, `validate`, `apply`, and `activate`. The stored
client secret was empty. Successful Keycloak authentication used the
`MM_OIDC_CLIENT_SECRET` process value. A fresh native password administrator
login passed before approval and after the OIDC-only login page check.

Web login created a core session and a returning login kept the same UUID.
Desktop created no system-browser session. Verifier-bound redemption created
a core session and replay returned 401. Mobile completion returned the app
deep link and its token authenticated to core. These requests exercised the
installed server transports. Chromium displayed a single OIDC sign-in button
with native sign-in methods disabled.

A preliminary Keycloak realm needed the subject mapper and an exchange lifetime
that met the broker profile. The broker rejected the fixture's missing subject
even though Keycloak returned HTTP 200. No broker validation changed during
the fixture corrections.


Signed public HTTP and `PluginHTTP` requests each returned 200. Replaying either
request returned 401, as did an unsigned `PluginHTTP` request. After the subject
access token entered its refresh window, a fresh signed request returned 200
through Keycloak's rotating refresh. Disconnect without CSRF returned 401.
Disconnect with the current native session and CSRF returned 204, and the
next signed broker request returned 409.

Installed verification covered one Mattermost node and a synthetic identity
realm. Native Electron and mobile app UI, an installed legacy import, and
production rollout remain outside this evidence. Historical evidence for
`cfbd710` retains its original source and archive identity.
