# Configured broker OAuth client repair

Goal: use the already configured and approved OAuth client (`mattermost` in the affected installation) instead of confusing it with the fixed Mattermost plugin ID.

- [x] Reproduce authenticated broker 403 with a valid custom configured client.
- [x] Pass the expected configured client into exchange-token `azp` validation; preserve every other issuer/subject/audience/scope/signature/expiry/configuration check.
- [x] Exercise legacy upgrade, verified fresh login, credential capture and authenticated broker exchange together with `ClientID=mattermost`.
- [x] Keep wrong `azp` and changed-client rejection covered.
- [x] Add static broker-stage log context without raw errors or secrets.
- [x] Update documentation and package version 0.7.0-p3; run full server race suite, independent review and archive validation.
