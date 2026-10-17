# Attestation service boundaries

Upstream provenance is recorded in [UPSTREAM.json](UPSTREAM.json). The upstream license is retained in [LICENSE](LICENSE). Package IDs and protocol names remain unchanged.

The trusted device record controls StrongBox requirements. An allowlisted FP6 record permits TEE-backed attestation only after certificate-chain, verified-boot key and locked-boot checks. Other records require StrongBox by default; a display-name change cannot alter that policy.

DiamaneOS and GrapheneOS release signatures use distinct Auditor pairing variants. Empty signature pins accept nothing. Verified-boot keys come from explicit allowlist entries. Sample submission is removed, and request diagnostics are disabled.

## Pairings without a manufacturer root

Some phones attest only with keys that chain to no manufacturer root. A second trust profile accepts their first pairing under these conditions:

- The report comes from `de.diamaneos.auditor` with the DiamaneOS Auditor signer.
- The phone is locked, boots with a configured OS key and reports self-signed verified boot.
- Boot hash, OS version, patch levels, KeyMint and attestation versions exactly match an entry of the signed release list.
- The challenge was issued to the same account and answered within 30 seconds.

The person pairing confirms in Auditor how the phone was set up. The web interface and emails label these devices "First pairing not verified by hardware". Response time and certificate encoding only flag a pairing for review.

Later checks follow the pinned chain like any other pairing. Their boot hash must stay on the release list. A downgrade or an unlisted build from a paired device raises a failure alert.

Device details and trusted keys are in `src/main/resources/app/attestation/server/diamaneos-trust.json`. Test deployments can replace it with `-Ddiamaneos.trust=<file>`.

The release pipeline places the signed list in the working directory as `releases.json`, or at `-Ddiamaneos.releases=<file>`. A list that fails verification or has a lower sequence than an accepted one is ignored.

The database retains accounts, device pairing information, verification history and optional alert addresses. Retention behavior is implemented in [Maintenance.java](src/main/java/app/attestation/server/Maintenance.java).

The [Debian deployment](https://github.com/DiamaneOS/infrastructure/tree/main/debian) separates root-owned code from application-writable encrypted state. The service account has no login or deployment permissions. `nginx/service-state.conf` controls public enrollment.

The inherited website publisher is disabled. The staged server configuration excludes upstream website assets and identity files; nginx blocks their legacy donation, contact and signing paths even when enrollment is enabled.
