# Upstream v0.7.0 merge verification

Date: 2026-10-29. This records automated integration checks, not installed
Mattermost/Electron/provider acceptance or production rollout.

## Source and merge decisions

The documentation was committed first as `d4c0c9c`. The integration merges exactly
upstream tag `v0.7.0`, `cbb7bda137571bd255497787601618f3ff3e1f6f`.
The later upstream README-only commit `e1dd822` is outside this merge.

The merge adopts upstream's Desktop system-browser flow, SDK 0.6.0, go-jose
4.1.6, and Go 1.27.3. Fork identity, snapshot, capture, lifecycle, broker,
management, and release-archive contracts remain required. The former popup
transport is replaced, while web browser binding and mobile completion remain.

Desktop codes now carry exact binding/snapshot metadata and checked expiry.
Optional provider credentials are encrypted under the external AES ring, bound
to the code digest and metadata. No ID token is stored. Session creation and
capture happen only on verified app redemption, through the same helper as
web/mobile. Delayed capture's initial CAS fence requires the generation observed
at callback, preserving a later login/disconnect even under a concurrent CAS.

A noncapturing login preserves existing credentials if persistence was off at
callback or is off at redeem. Enabling capture after the callback requires a
further fresh login to capture new tokens. This preserves reversible policy
switches and avoids credential-KV dependencies when persistence is off. Explicit
disconnect/revoke remains the durable way to invalidate existing credentials.

## Automated results

| Check | Result |
| --- | --- |
| New Desktop authority/capture/expiry/session/generation regressions against mechanical merge | RED: unadapted redeem accepted stale authority and skipped capture |
| Focused Desktop/web-boundary suite after adaptation | PASS |
| Expanded Desktop race tests for optional failure, cancellation, replay and CAS races | PASS |
| Final server `go mod verify`, `go vet ./...`, `go test -race ./... -count=1` | PASS; final race suite 48.401 seconds |
| Mobile bridge `go vet ./...` and `go test -race ./... -count=1` | PASS; race suite 1.053 seconds |
| Node redeem network/JSON recovery tests before fix | RED, two rejected promises |
| Final `npm test` | PASS, 16 tests |
| `npm ci` and `npm run build` | PASS; npm reported zero vulnerabilities |
| `make all GO=/home/linuxbrew/.linuxbrew/bin/go` | PASS; linux/darwin x amd64/arm64, production webapp, flat archive |
| Webapp rebuilt after recovery fix; `make bundle -o server -o webapp` | PASS; actual archive validator passed |
| `python3 scripts/test_bundle_validator.py` | PASS |
| `python3 scripts/check_fork_docs.py` | PASS; original 15-commit ledger and 76 current test references |
| Local Markdown link/fence check and `git diff --check` | PASS |

The Node test runner emits upstream's package-module-type warning; tests and
production webpack output succeed. No dependency audit fix was applied.
The precommit binary inspection reports Go 1.27.3, SDK 0.6.0, go-jose 4.1.6,
and `vcs.modified=true`, as expected for an in-progress merge. A clean rebuild
of the committed merge is needed for final artifact source identity. This record
does not relabel that precommit archive as a clean or deployed build.

## Independent review

A separate read-only reviewer found no Critical or Important authority,
encryption, expiry, or generation-CAS issues. The reviewer identified a Desktop
client recovery defect: failed redeem fetch/JSON could leave the UI waiting.
Two failing tests reproduced it. `checkDesktopLogin` now resolves to its error
status on those failures and preserves the verifier until a valid response.
The 16-test suite and production build passed after the fix.

## Limits

Actual Electron external-browser/deep-link behavior, installed Mattermost SDK
compatibility, real-provider capture/refresh/broker acceptance, multi-node
quiescence, and production rollout were not exercised in this merge task.
The historical `cfbd710` installed evidence remains tied to that original build.
The local merge does not activate the identity gate, integration switches,
provider settings, or any deployed plugin, and does not publish a release.
