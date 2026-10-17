# DiamaneOS attestation server

GrapheneOS-derived hardware-attestation verification and account APIs. The HTTP backend listens on loopback behind nginx. Sample submission is disabled.

## Build and check

Initialize the declared submodules, then build with the Gradle wrapper and the Java toolchain declared in [build.gradle.kts](build.gradle.kts):

```sh
git submodule update --init --recursive
./gradlew build
```

The build checks include `diamaneOSPolicyTest` and `profile2Test`. Dependencies are authenticated through [gradle/verification-metadata.xml](gradle/verification-metadata.xml).

`profile2Test` uses the bundled Linux x86-64 SQLite library. On other hosts, pass a matching sqlite4java library directory with `-PsqliteLibraryPath=<dir>`.

## Deployment

Use the [Debian adapters](https://github.com/DiamaneOS/infrastructure/tree/main/debian) for TLS, service isolation and encrypted state. The inherited website publisher is disabled. Nginx serves a separate publication tree and blocks the inherited donation, contact and signing-identity paths.

`nginx/service-state.conf` controls public enrollment. Account creation and remote verification use the existing upstream APIs. State contains accounts, device pairing information, verification history and optional alert addresses.

SMTP configuration is stored in the database. Remote delivery uses SMTP over TLS with certificate verification. The service requires outbound access to its configured mail endpoint.

## Auditor protocol

The pairing QR code contains `<domain> <userId> <subscribeKey> <verifyInterval>`. Treat the subscription key as opaque data.

- `POST /auditor/challenge` returns a single-use challenge. With `Authorization: Auditor <userId> <subscribeKey>` the challenge is bound to that account, a limited number per hour.
- `POST /auditor/verify` verifies the attestation and returns its verification interval.
- Unpaired verification uses `Authorization: Auditor <userId> <subscribeKey>`. Paired verification uses `Authorization: Auditor <userId>`.
- `GET /releases.json` returns the signed release list this server accepted.
- The account page offers the QR data as an `intent://` link restricted to `de.diamaneos.auditor`.

Trust requirements and source provenance are described in [DOWNSTREAM.md](DOWNSTREAM.md).
