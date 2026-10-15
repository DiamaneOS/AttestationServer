# Attestation service boundaries

Upstream provenance is recorded in [UPSTREAM.json](UPSTREAM.json). The upstream license is retained in [LICENSE](LICENSE). Package IDs and protocol names remain unchanged.

The trusted device record controls StrongBox requirements. An allowlisted FP6 record permits TEE-backed attestation only after certificate-chain, verified-boot key and locked-boot checks. Other records require StrongBox by default; a display-name change cannot alter that policy.

DiamaneOS and GrapheneOS release signatures use distinct Auditor pairing variants. Empty signature pins accept nothing. Verified-boot keys come from explicit allowlist entries. Sample submission is removed, and request diagnostics are disabled.

The database retains accounts, device pairing information, verification history and optional alert addresses. Retention behavior is implemented in [Maintenance.java](src/main/java/app/attestation/server/Maintenance.java).

The [Debian deployment](https://github.com/DiamaneOS/infrastructure/tree/main/debian) separates root-owned code from application-writable encrypted state. The service account has no login or deployment permissions. `nginx/service-state.conf` controls public enrollment.

The inherited website publisher is disabled. The staged server configuration excludes upstream website assets and identity files; nginx blocks their legacy donation, contact and signing paths even when enrollment is enabled.
