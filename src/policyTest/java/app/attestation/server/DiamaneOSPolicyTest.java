package app.attestation.server;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/** Focused regressions for the downstream trust boundaries, without hardware claims. */
public final class DiamaneOSPolicyTest {
    public static void main(final String[] args) throws Exception {
        final String stockFp6 = "C8677EB0A60727BCCB4AB2BB9B7B156A94A7B729E4720FA21194122E39248177";
        final var fp6 = AttestationProtocol.fingerprintsStock.get(stockFp6);
        require(fp6 != null && !fp6.requiresStrongBox(), "authenticated FP6 entry must use the TEE rule");
        require(AttestationProtocol.fingerprintsStock.entrySet().stream()
                .filter(entry -> !entry.getKey().equals(stockFp6))
                .allMatch(entry -> entry.getValue().requiresStrongBox()),
                "other allowlisted devices must retain StrongBox enforcement");
        require(AttestationProtocol.fingerprintsNonStock.values().stream()
                .allMatch(AttestationProtocol.DeviceInfo::requiresStrongBox),
                "existing custom-OS entries must retain StrongBox enforcement");
        require(new AttestationProtocol.DeviceInfo("Fairphone 6", 300, 300, false, "Stock")
                .requiresStrongBox(), "a display name alone must not grant a TEE exception");
        require(AttestationProtocol.fingerprintsStock.get("0".repeat(64)) == null &&
                AttestationProtocol.fingerprintsNonStock.get("0".repeat(64)) == null,
                "unknown verified-boot keys must not receive an FP6 exception");
        final TrustConfig trust = TrustConfig.get();
        require(trust.releaseListSigners.keySet().equals(java.util.Set.of(
                "0B0A4D2CD3680FF4F3993CA8A61CDA93417680F5151090154EDCD52655C7E4AB")),
                "release lists must be signed by the offline policy key");
        require(AttestationProtocol.classifyRelease("app.attestation.auditor",
                "990E04F0864B19F14F84E0E432F7A393F297AB105A22C1E1B10B442A4A62C42C", trust) == 3,
                "upstream signer must retain its distinct pairing variant");
        require(AttestationProtocol.classifyRelease("de.diamaneos.auditor", trust.auditorReleaseSigner, trust) == 0,
                "DiamaneOS Auditor must use the release variant");
        for (final String[] invalid : new String[][] {{"de.diamaneos.auditor", ""},
                {"de.diamaneos.auditor", "0".repeat(64)}, {"de.diamaneos.auditor", "0".repeat(62)},
                {"app.attestation.auditor", trust.auditorReleaseSigner}}) {
            try {
                AttestationProtocol.classifyRelease(invalid[0], invalid[1], trust);
                throw new AssertionError("unconfigured or unknown release signer accepted");
            } catch (final GeneralSecurityException expected) {
                // Rejection is the security boundary under test.
            }
        }
        operationalLog();
        System.out.println("DiamaneOS trust-policy regressions passed; no device attestation is claimed.");
    }

    // Failures that stop alerts reach the journal, rate limited and without identifiers.
    private static void operationalLog() {
        final List<LogRecord> records = new ArrayList<>();
        final Logger logger = Logger.getLogger("app.attestation");
        logger.setUseParentHandlers(false);
        logger.addHandler(new Handler() {
            @Override
            public void publish(final LogRecord record) {
                records.add(record);
            }

            @Override
            public void flush() {}

            @Override
            public void close() {}
        });
        final Exception failure = new Exception("mail to someone@example.org",
                new java.net.SocketTimeoutException("host mail.example.org"));
        OperationalLog.report("test failure", failure, 1000);
        OperationalLog.report("test failure", failure, 1000 + OperationalLog.INTERVAL_MS - 1);
        require(records.size() == 1, "a repeated failure must wait for the interval");
        require(records.get(0).getLevel() == SyslogLevel.CRIT, "the line must pass the CRIT filter");
        require(records.get(0).getThrown() == null, "a stack trace can hold an address");
        require(!records.get(0).getMessage().contains("example.org"), "the line must hold no identifiers");
        require(records.get(0).getMessage().contains("java.net.SocketTimeoutException"), "the line must name the cause");
        OperationalLog.report("test failure", failure, 1000 + OperationalLog.INTERVAL_MS);
        require(records.size() == 2, "a failure that lasts must show again");
        OperationalLog.report("other failure", null, 1000);
        require(records.size() == 3, "another failure must show at once");
    }

    private static void require(final boolean condition, final String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
