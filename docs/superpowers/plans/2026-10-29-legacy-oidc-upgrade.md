# Legacy OIDC upgrade recovery implementation plan

Goal: let an administrator recover an upstream OIDC installation without SQL or a manual approval map, while preserving existing accounts and sessions.

Architecture: a current system administrator explicitly approves the exact historical issuer once using `/oidc-identity approve-legacy <issuer>`. Only a previously uninitialized gate can accept this approval. A fresh verified OIDC callback then migrates its own exact legacy UUID/native subject into the bidirectional registry using CAS. Frozen gates continue to deny; manual reviewed migration remains unchanged.

Constraints:
- Never infer historical issuer approval from configuration or email.
- Never create a replacement user, change native auth fields, revoke existing sessions, or fabricate maintenance receipts during same-issuer adoption.
- Preserve signed state, nonce, PKCE, cookie binding, Desktop verifier redemption and current snapshot/gate assertions.
- Issuer/client changes and explicit freeze clear the upgrade approval and cannot reactivate automatically.

Tasks:
- [x] Add failing command/adoption tests including uninitialized and frozen gates, exact UUID, native mismatch, conflicts and retries.
- [x] Implement explicit administrator approval and lazy verified-callback adoption.
- [x] Add full signed TLS web and Desktop upgrade regressions from legacy data with no gate/registry.
- [x] Update operating instructions and version to 0.7.0-p2.
- [x] Run full server race suite, mobile bridge checks, webapp tests/build, archive checks and independent review.
- [x] Build the installable bundle, record its SHA-256 and provide exact recovery command.
