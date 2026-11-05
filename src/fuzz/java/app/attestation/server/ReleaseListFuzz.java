package app.attestation.server;

import com.google.common.primitives.Bytes;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

// The signed release list file and the trust configuration file.
//
// Input: byte 0 picks the parser (even: release list, odd: trust configuration), the rest is the
// file.
//
// Invariants: both parsers refuse with GeneralSecurityException only, and in bounded time. A
// release list is accepted only with a payload the test signer signed: a changed byte in the payload
// or a signature by another key is refused.
public final class ReleaseListFuzz {
    private static final Set<String> signedPayloads = new HashSet<>();
    private static final List<byte[]> seeds = new ArrayList<>();
    private static TrustConfig trust;

    public static void fuzzerInitialize() throws Exception {
        FuzzFixture.installTestRoot();
        trust = FuzzFixture.trust();
        final byte[][] payloads = {
            FuzzFixture.releasePayload(1, FuzzFixture.release(FuzzFixture.RELEASE_1, 202610)),
            FuzzFixture.releasePayload(7, FuzzFixture.release(FuzzFixture.RELEASE_1, 202610),
                    FuzzFixture.release(FuzzFixture.RELEASE_2, 202611)),
        };
        for (final byte[] payload : payloads) {
            signedPayloads.add(new String(payload, StandardCharsets.ISO_8859_1));
            seeds.add(Bytes.concat(new byte[]{0}, FuzzFixture.releaseEnvelope(FuzzFixture.TEST_LIST_SIGNER, payload)));
        }
        seeds.add(Bytes.concat(new byte[]{0}, FuzzFixture.releaseEnvelope(
                FuzzFixture.keyPair("fuzz test other signer"), payloads[0])));
        seeds.add(Bytes.concat(new byte[]{0}, "[".repeat(20).getBytes(StandardCharsets.UTF_8)));
        seeds.add(Bytes.concat(new byte[]{1}, trustJson()));
        try (var stream = TrustConfig.class.getResourceAsStream("diamaneos-trust.json")) {
            seeds.add(Bytes.concat(new byte[]{1}, stream.readAllBytes()));
        }
    }

    private static byte[] trustJson() throws Exception {
        final TrustConfig config = FuzzFixture.trust();
        return Json.createObjectBuilder()
                .add("format", TrustConfig.FORMAT)
                .add("version", 1)
                .add("auditorReleaseSigner", config.auditorReleaseSigner)
                .add("releaseListSigners", Json.createArrayBuilder().add(java.util.Base64.getEncoder()
                        .encodeToString(FuzzFixture.TEST_LIST_SIGNER.getPublic().getEncoded())))
                .add("devices", Json.createArrayBuilder().add(Json.createObjectBuilder()
                        .add("id", "TEST1")
                        .add("buildDevice", "test1")
                        .add("name", "Test Phone")
                        .add("osName", "Test OS")
                        .add("verifiedBootKey", config.devices.get(0).verifiedBootKey())
                        .add("securityLevel", "STRONG_BOX")))
                .build().toString().getBytes(StandardCharsets.UTF_8);
    }

    public static List<byte[]> seeds() throws Exception {
        fuzzerInitialize();
        return seeds;
    }

    public static void fuzzerTestOneInput(final byte[] data) throws Exception {
        if (data.length < 1) {
            return;
        }
        final byte[] file = Arrays.copyOfRange(data, 1, data.length);
        final long start = System.nanoTime();
        try {
            if ((data[0] & 1) == 0) {
                final ReleaseList list = ReleaseList.parse(file, trust.releaseListSigners);
                final String payload = new String(com.google.common.io.BaseEncoding.base64().decode(
                        Json.createReader(new java.io.ByteArrayInputStream(file)).readObject().getString("payload")),
                        StandardCharsets.ISO_8859_1);
                if (!signedPayloads.contains(payload) || list.sequence < 1) {
                    throw new AssertionError("accepted a release list the test signer never signed");
                }
            } else {
                final TrustConfig config = TrustConfig.parse(file);
                for (final TrustConfig.Device device : config.devices) {
                    if (!device.verifiedBootKey().matches("[0-9A-F]{64}")) {
                        throw new AssertionError("accepted an invalid verified boot key");
                    }
                }
            }
        } catch (final GeneralSecurityException e) {
            // refused
        } finally {
            if (System.nanoTime() - start > 2_000_000_000L) {
                throw new AssertionError("parsing took over two seconds");
            }
        }
    }
}
