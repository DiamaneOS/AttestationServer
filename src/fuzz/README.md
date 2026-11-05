# Fuzz targets

Jazzer targets for the code that reads input from outside the server. Each class names its input
format and the properties it checks at the top.

| Target | Input |
| --- | --- |
| `ProtocolFuzz` | an attestation message as `/auditor/verify` receives it, against a temporary database |
| `CertChainFuzz` | one certificate of a chain, or the attestation extension of a re-signed one |
| `InflateFuzz` | the compressed certificate chain and its length fields |
| `ReleaseListFuzz` | the signed release list and the trust configuration file |
| `HttpFuzz` | requests to every HTTP handler, with two made-up accounts |
| `EmailFuzz` | an alert address and device text through the alert dispatcher |

Run one target:

```sh
./gradlew fuzz -PfuzzTarget=ProtocolFuzz \
    -PfuzzArgs="$PWD/build/fuzz/ProtocolFuzz/corpus $PWD/build/fuzz/ProtocolFuzz/seeds -max_total_time=3600"
```

The `fuzz` task first writes the target's seeds to `build/fuzz/<target>/seeds`. Seeds are made
from throwaway test keys derived from fixed labels, so they stay valid across runs. A test root is
written to `build/fuzz/<target>/roots` and put on the test JVM's class path ahead of the bundled
first root, so reports under it reach the checks behind the signatures. The database is a fresh
file in `build/fuzz/<target>/work`. Corpora and findings stay under `build` and are not committed.
