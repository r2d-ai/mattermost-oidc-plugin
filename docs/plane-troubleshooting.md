# Troubleshoot delegated Plane access

Record the time and failing command. Correlate the current `Plane broker request`
log in Mattermost with the matching Plane API request. Do not treat every
reconnect message as a request to repeat login.

## Identify the failing component

| Observation | Meaning | Next check |
| --- | --- | --- |
| `/plane connect` displays a link | Static guidance only. No broker request or capture has run. | Open the link only when a fresh callback is needed. |
| `gate=uninitialized` | OIDC login authority has not been approved. | Use the appropriate initial/legacy approval workflow. |
| `gate=frozen` | Identity work is deliberately blocked. | Reviewed maintenance; do not reset KV or change clients to bypass it. |
| `/plane status` ready | Broker issued a verified token. | Test `/plane projects`; workspace access is still unchecked. |
| `stage=credential_keyring` | OIDC credential-encryption ring is missing/invalid. | Check both `MM_OIDC_CREDENTIAL_*` variables in the Mattermost process. |
| `stage=integration_flags` | Persistence or delegated access is disabled. | Check both OIDC plugin switches. |
| `stage=identity_binding` | Broker could not resolve the current actor's identity. | Check gate and the exact actor's approved binding. |
| `stage=subject_credentials` | Stored credentials, refresh or lifecycle checks failed. | Use the error category; check capture warnings before requesting login. |
| `stage=token_exchange` with provider HTTP 4xx | Provider rejected exchange. | Inspect the allowlisted `provider_error` and Keycloak event at that time. |
| `stage=token_exchange`, HTTP 200 | Exchange responded successfully but output was rejected. | Inspect `reason` below. |
| Broker `outcome=success`, `stage=complete`, then Plane 401 | Token issuance worked; API authentication failed. | Check Plane's effective policy, identity and verifier path. |
| Plane 403 after authentication | Authenticated request lacks required scope or native access. | Check requested Plane grants and current memberships. |

The Plane plugin currently maps Plane API HTTP 401 to reconnect guidance. This
message alone cannot distinguish a failed refresh from API policy, identity,
header or verification failures.

## Read token-exchange diagnostics

OIDC plugin `0.7.0-p4` and newer add a fixed `reason`, numeric
`provider_http_status` and, when recognized, `provider_error`. No raw token,
provider body, secret or error description is logged.

| Reason | Check |
| --- | --- |
| `discovery_http`, `discovery_metadata` | Discovery retrieval and exact issuer/same-origin endpoints. |
| `exchange_http` | Provider HTTP status and allowlisted OAuth error code. |
| `response_expires_in` | Returned access-token expiry must be positive and no more than 300 seconds. |
| `response_token_type`, `response_issued_token_type` | Bearer access-token response, not another token type. |
| `jwks_http`, `jwks_keys`, `jwt_parse`, `jwt_signature` | Public signing keys, format and signature. |
| `claims_issuer`, `claims_subject`, `claims_azp`, `claims_audience`, `claims_type` | Exact issuer/user/requester/API audience/access-token purpose. |
| `claims_scope_missing` | A requested Plane grant was not present. |
| `claims_scope_unexpected` on p6+ | Unrequested write access or an unknown `plane.*` capability. |
| `claims_scope_duplicate`, `claims_scope` | Duplicate or malformed scope claim. |
| `claims_lifetime`, `response_expiry_mismatch` | Signed timing bounds and response expiry metadata. |

Older versions rejected unrelated realm scopes. Use `0.7.0-p6` or newer; do not
keep changing normal login scopes to satisfy an obsolete supplemental allowlist.
A Keycloak `Full scope allowed` deprecation warning is not proof that exchange
failed. Obtain the actual exchange event/error or the broker rejection reason.

## Inspect Plane API policy and identity

Use the effective-policy command in [complete setup](https://github.com/r2d-ai/mattermost-plugin-plane/blob/main/docs/setup.md). Expected values are:

- API bearer enabled.
- Exact shared issuer.
- Allowed API clients includes the Mattermost OAuth Client ID, e.g. `mattermost`.
- Allowed signing algorithms includes `RS256`.
- Access token type is `Bearer`.

A working `plane-web` browser login does not prove these API policies are enabled.
Check settings in the actual API workers, not just a shell with exported values.

To inspect a specific binding in Plane's `python manage.py shell`, replace the
issuer and subject with the intended user's exact verified values:

```python
from plane.db.models import ExternalIdentity
print(list(ExternalIdentity.objects.filter(
    issuer="https://login.example.com/realms/work",
    subject="KEYCLOAK_SUBJECT_TO_CHECK",
).values("issuer", "subject", "user_id", "user__is_active", "user__is_bot")))
```

An empty list means no binding for that pair. A returned row must belong to the
intended active human. Do not infer the actor from another browser's log UUID,
replace a binding based on matching email, or equate application UUIDs with
Keycloak subjects. Pairwise-subject mappers can make subjects client-specific;
verify the actual issuer/subject rather than assuming a Keycloak admin UUID.

Do not modify/delete bindings as a diagnostic step. Use the supported verified
link/migration workflow after establishing the intended ownership.

## Separate public HTTPS tests from API authentication

A script's certificate failure to the public Plane URL is a trust-chain failure
for that script/runtime. It does not establish that the API worker failed to
verify a Keycloak token. Install the correct trusted CA chain for the runtime
that needs it; never use `verify=False` or `curl -k`.

If a container has no shell/curl, use the available Plane Python console rather
than installing tools into a production image. A Django `APIClient` test can
check internal authentication without HTTPS:

```python
from rest_framework.test import APIClient
client = APIClient()
for name, headers in [
    ("no_header", {}),
    ("fake_bearer", {"HTTP_AUTHORIZATION": "Bearer e30.e30.e30"}),
]:
    response = client.get(
        "/api/v1/workspaces/", secure=True,
        HTTP_HOST="plane.example.com", **headers,
    )
    print(name, response.status_code, response.content[:300])
```

Use your real allowed Host. The fake token contains no credentials and should
be denied. Internal tests bypass the external proxy and therefore cannot prove
that the proxy preserves `Authorization`. Compare an external fake-token test
from the relevant network before attributing a failure to header stripping.

## Diagnose JWKS cache behavior without hiding its side effects

The Plane verifier uses shared Redis JWKS snapshots with a 300-second cache
lifetime and a 30-second refresh-acquisition key. A Redis `ping` does not check
its GETRANGE/EVAL/TIME/publication path. Fetching discovery/JWKS directly does
not check that path either.

Before any cache-path probe, capture TTLs while commands are failing. This
reads the two issuer keys without refreshing them or fetching provider keys:

```python
import hashlib
import time
from plane.authentication.oidc.config import load_oidc_config
from plane.authentication.oidc.tokens import _redis_command
c = load_oidc_config(api_only=True)
prefix = "plane:oidc:api:" + hashlib.sha256(c.issuer.encode()).hexdigest()
deadline = time.monotonic() + 3
print({name + "_ttl_ms": _redis_command(deadline, "pttl", prefix + ":" + name)
       for name in ("jwks", "refresh")})
```

A TTL of `-2` means the key is absent. A positive refresh TTL means a refresh
acquisition gate is still held; it does not prove that its owner succeeded.
Record these values with the current broker and API logs. Do not delete keys
or run warming probes before capturing the failing state.

The following optional diagnostic calls the real cache path. **It may acquire a
refresh slot and populate Redis, changing later requests. It is not a read-only
probe.** It prints no tokens, credentials or private key material:

```python
import time
from plane.authentication.oidc.config import load_oidc_config
from plane.authentication.oidc.tokens import (
    provider_metadata, fetch_json, _access_jwks, _key_from_jwks,
)
c = load_oidc_config(api_only=True)
metadata = provider_metadata(c)
keys = fetch_json(metadata["jwks_uri"])["keys"]
key = next(k for k in keys if k.get("kty") == "RSA"
           and k.get("use", "sig") == "sig"
           and k.get("alg", "RS256") == "RS256")
header = {"alg": "RS256", "kid": key["kid"]}
cached = _access_jwks(c, header, deadline=time.monotonic() + 5)
_key_from_jwks(cached, header)
print("api_key_verification_path: OK")
```

A successful probe does not verify the actual bearer token or identify its user.
If requests begin succeeding after this probe, cache warming is a hypothesis,
not a proven cause. Keep configuration unchanged and test normal requests after
the cache lifetime has elapsed, with correlated logs. Do not delete cache keys,
disable validation or call manual warming a permanent fix. Concurrent cold
requests can also be denied while another refresh owner holds the acquisition
key; investigate that separately if it recurs.

## Observed rollout and remaining uncertainty

In the reported rollout, broker issuance eventually succeeded after the key,
client and scope fixes. Plane API initially had bearer access disabled and an
empty access-token-type policy; these were corrected. Provider retrieval,
Redis connectivity and an active identity binding were then checked. The user
later reported working commands without another configuration edit.

The cache-path diagnostic had been run before that report and can warm Redis.
The user subsequently reported losing project access again after a period of
working access. This makes expiration-related behavior worth investigating,
but the exact interval and current failure stage have not been established.
There is still no evidence proving which operation fails after expiry or why
manual warming changed earlier behavior. Keep this limitation distinct from
the verified code fixes and from synthetic/local test results.
