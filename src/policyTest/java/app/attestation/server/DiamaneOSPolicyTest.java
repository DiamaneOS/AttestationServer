package app.attestation.server;

import java.security.GeneralSecurityException;

/** Focused regressions for the downstream trust boundaries, without hardware claims. */
public final class DiamaneOSPolicyTest {
    public static void main(final String[] args) throws Exception {
        require(AttestationProtocol.fingerprintsStock.values().stream()
                .noneMatch(device -> device.name().startsWith("Fairphone")) &&
                AttestationProtocol.fingerprintsNonStock.values().stream()
                .noneMatch(device -> device.name().startsWith("Fairphone")),
                "no Fairphone entry until a Fairphone can attest with DiamaneOS");
        require(AttestationProtocol.classifyReleaseSignature(
                "990E04F0864B19F14F84E0E432F7A393F297AB105A22C1E1B10B442A4A62C42C") == 3,
                "upstream signer must retain its distinct pairing variant");
        for (final String invalid : new String[] {"", "0".repeat(64), "0".repeat(62), "0".repeat(66)}) {
            try {
                AttestationProtocol.classifyReleaseSignature(invalid);
                throw new AssertionError("unconfigured or unknown release signer accepted");
            } catch (final GeneralSecurityException expected) {
                // Rejection is the security boundary under test.
            }
        }
        System.out.println("DiamaneOS trust-policy regressions passed; no device attestation is claimed.");
    }

    private static void require(final boolean condition, final String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
