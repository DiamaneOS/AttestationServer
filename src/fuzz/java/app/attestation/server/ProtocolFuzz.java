package app.attestation.server;

import app.attestation.server.attestation.ParsedAttestationRecord;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.common.primitives.Bytes;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.DataFormatException;

// The attestation message as /auditor/verify receives it, against a database with two accounts,
// a pinned profile 1 phone and a pinned, approved profile 2 phone.
//
// Input: one mode byte, then the message. Mode bit 0: paired request (no subscribe key). Bit 1:
// the request names the second account. Bit 2: the challenge was issued to the requesting account.
// The harness marks the challenge in the leaf pending, so mutated reports reach the checks behind it.
//
// Invariants: only the exceptions the handler answers with 400 escape. An accepted report has a
// signed part equal to one the fixture made. A pinned phone's chain, keys, account, profile and
// first time never change, and its versions never go down. A paired check is accepted only for
// the account the phone belongs to.
public final class ProtocolFuzz {
    private static final Cache<ByteBuffer, AttestationProtocol.PendingChallenge> challenges =
            Caffeine.newBuilder().build();
    private static TrustConfig trust;
    private static ReleaseList releases;
    private static final Set<ByteBuffer> signedParts = new HashSet<>();
    private static final List<byte[]> pinned = new ArrayList<>();
    private static final List<List<String>> pinnedRows = new ArrayList<>();
    private static final List<Long> pinnedHistory = new ArrayList<>();
    private static final List<byte[]> seeds = new ArrayList<>();

    private static final String PINNED_COLUMNS = """
            SELECT hex(pinnedCertificates), hex(pinnedVerifiedBootKey), userId, trustProfile,
                verifiedTimeFirst, attestKey, pinnedAppVariant FROM Devices WHERE fingerprint = ?""";
    private static final String[] MONOTONIC = {"pinnedOsVersion", "pinnedOsPatchLevel",
            "coalesce(pinnedVendorPatchLevel, 0)", "coalesce(pinnedBootPatchLevel, 0)", "pinnedAppVersion"};

    public static void fuzzerInitialize() throws Exception {
        FuzzFixture.installTestRoot();
        FuzzDb.setup();
        trust = FuzzFixture.trust();
        releases = FuzzFixture.releases();
        if (!java.util.Arrays.equals(FuzzFixture.testRootEncoded(), testRootSeenByServer())) {
            throw new IllegalStateException("test root not on the classpath ahead of the bundled roots");
        }

        final FuzzFixture p1 = new FuzzFixture("p1 pinned", true);
        final FuzzFixture p2 = new FuzzFixture("p2 pinned", false);
        accept(0x04, p1.message());
        accept(0x04, p2.message());
        if (!Profile2Handlers.approveDevice(FuzzDb.alice, p2.fingerprint())) {
            throw new IllegalStateException("profile 2 phone not approved");
        }
        for (final FuzzFixture phone : List.of(p1, p2)) {
            pinned.add(phone.fingerprint());
            pinnedRows.add(FuzzDb.rows(PINNED_COLUMNS, phone.fingerprint()));
        }
        FuzzDb.snapshot();
        for (final byte[] fingerprint : pinned) {
            pinnedHistory.add(FuzzDb.scalar("SELECT count(*) FROM Attestations WHERE fingerprint = ?", fingerprint));
        }

        // first pairings
        seed(0x04, new FuzzFixture("p1 new", true).message(), true);
        seed(0x04, new FuzzFixture("p2 new", false).message(), true);
        seed(0x06, new FuzzFixture("p1 new bob", true).message(), true);
        seed(0x00, new FuzzFixture("p2 unbound", false).message(), false);
        // later checks, accepted and refused
        for (final FuzzFixture phone : List.of(p1, p2)) {
            phone.nextCheck();
            seed(0x01, phone.message(), true);
            seed(0x03, phone.message(), false);
            phone.nextCheck();
            phone.osPatchLevel = 202609;
            seed(0x01, phone.message(), false);
            phone.osPatchLevel = 202610;
            phone.nextCheck();
            phone.appVersion = 9100;
            seed(0x01, phone.message(), false);
            phone.appVersion = 9202;
            phone.nextCheck();
            phone.locked = false;
            seed(0x01, phone.message(), false);
            phone.locked = true;
        }
        p2.nextCheck();
        p2.bootHash = FuzzFixture.RELEASE_2;
        p2.osPatchLevel = 202611;
        seed(0x01, p2.message(), true);
        p2.nextCheck();
        p2.bootHash = FuzzFixture.sha256("fuzz test unpublished build");
        seed(0x01, p2.message(), false);
    }

    public static List<byte[]> seeds() throws Exception {
        if (seeds.isEmpty()) {
            fuzzerInitialize();
        }
        return seeds;
    }

    private static byte[] testRootSeenByServer() throws Exception {
        final var field = AttestationProtocol.class.getDeclaredField("GOOGLE_ROOT_CERTIFICATE_0");
        field.setAccessible(true);
        return (byte[]) field.get(null);
    }

    private static void accept(final int mode, final byte[] message) throws Exception {
        if (!run(mode, message)) {
            throw new IllegalStateException("fixture report refused");
        }
    }

    private static void seed(final int mode, final byte[] message, final boolean accepted) throws Exception {
        final boolean result = run(mode, message);
        FuzzDb.restore();
        if (result != accepted) {
            throw new IllegalStateException("seed with mode " + mode + " " + (result ? "accepted" : "refused"));
        }
        // every fixture report is validly signed, whether this mode accepts it or not
        signedParts.add(ByteBuffer.wrap(signedPart(message)));
        seeds.add(Bytes.concat(new byte[]{(byte) mode}, message));
    }

    public static void fuzzerTestOneInput(final byte[] data) throws Exception {
        if (data.length < 1) {
            return;
        }
        final int mode = data[0];
        final byte[] message = java.util.Arrays.copyOfRange(data, 1, data.length);
        try {
            final boolean accepted = run(mode, message);
            check(mode, message, accepted);
        } finally {
            FuzzDb.restore();
            challenges.invalidateAll();
        }
    }

    // Returns whether the report was accepted. Exceptions the handler does not answer with 400 escape.
    private static boolean run(final int mode, final byte[] message) throws Exception {
        final long userId = (mode & 2) != 0 ? FuzzDb.bob : FuzzDb.alice;
        final boolean paired = (mode & 1) != 0;
        markPending(message, (mode & 4) != 0 ? userId : -1);
        try {
            AttestationProtocol.verifySerialized(message, challenges, userId, paired, trust, releases);
            return true;
        } catch (final GeneralSecurityException | DataFormatException | BufferUnderflowException |
                NegativeArraySizeException e) {
            return false;
        }
    }

    private static void check(final int mode, final byte[] message, final boolean accepted) throws Exception {
        final long userId = (mode & 2) != 0 ? FuzzDb.bob : FuzzDb.alice;
        for (int i = 0; i < pinned.size(); i++) {
            final byte[] fingerprint = pinned.get(i);
            if (!FuzzDb.rows(PINNED_COLUMNS, fingerprint).equals(pinnedRows.get(i))) {
                throw new AssertionError("pinned phone " + i + " changed");
            }
            for (final String column : MONOTONIC) {
                if (FuzzDb.scalar("SELECT " + column + " FROM Devices WHERE fingerprint = ?", fingerprint)
                        < FuzzDb.scalar("SELECT " + column + " FROM snap.Devices WHERE fingerprint = ?", fingerprint)) {
                    throw new AssertionError("pinned phone " + i + " " + column + " went down");
                }
            }
            if (FuzzDb.scalar("SELECT count(*) FROM Attestations WHERE fingerprint = ?", fingerprint)
                    < pinnedHistory.get(i)) {
                throw new AssertionError("pinned phone " + i + " lost history");
            }
        }
        if (!accepted) {
            return;
        }
        if (!signedParts.contains(ByteBuffer.wrap(signedPart(message)))) {
            throw new AssertionError("accepted a report whose signed part the fixture never made");
        }
        // every device stored or updated by this report belongs to the requesting account
        final List<String> accounts = FuzzDb.rows("""
                SELECT d.userId FROM Devices AS d LEFT JOIN snap.Devices AS s ON s.fingerprint = d.fingerprint
                WHERE s.fingerprint IS NULL OR d.verifiedTimeLast != s.verifiedTimeLast""");
        for (final String account : accounts) {
            if (!account.equals(userId + "|")) {
                throw new AssertionError("report for account " + userId + " changed a device of account " + account);
            }
        }
        // a profile 2 pairing is stored only for a chain outside the trusted roots, and waits
        for (final String row : FuzzDb.rows("""
                SELECT trustProfile, pending FROM Devices WHERE fingerprint NOT IN (SELECT fingerprint FROM snap.Devices)""")) {
            final boolean profile2 = row.startsWith("2|");
            final boolean testRooted = rootIsTestRoot(message);
            if (profile2 == testRooted || (profile2 && !row.equals("2|1|"))) {
                throw new AssertionError("pairing stored with the wrong trust profile: " + row);
            }
        }
    }

    static byte[] signedPart(final byte[] message) {
        try {
            final ByteBuffer buffer = ByteBuffer.wrap(message);
            buffer.get();
            final short length = buffer.getShort();
            final int end = 1 + 2 + length + 32 + 4 + 4 + 3;
            return java.util.Arrays.copyOf(message, Math.min(end, message.length));
        } catch (final RuntimeException e) {
            return message;
        }
    }

    private static Certificate[] chainOf(final byte[] message) {
        try {
            final ByteBuffer buffer = ByteBuffer.wrap(message);
            final byte version = buffer.get();
            final byte[] compressed = new byte[buffer.getShort()];
            buffer.get(compressed);
            return AttestationProtocol.decodeChain(version < 7 ? AttestationProtocol.DEFLATE_DICTIONARY_4
                    : AttestationProtocol.DEFLATE_DICTIONARY_5, compressed);
        } catch (final Exception e) {
            return new Certificate[0];
        }
    }

    private static boolean rootIsTestRoot(final byte[] message) throws Exception {
        final Certificate[] chain = chainOf(message);
        return chain.length > 0 && java.util.Arrays.equals(chain[chain.length - 1].getEncoded(),
                FuzzFixture.testRootEncoded());
    }

    // The harness side of issuing a challenge: whatever the leaf names is pending.
    private static void markPending(final byte[] message, final long challengeUser) {
        final Certificate[] chain = chainOf(message);
        if (chain.length == 0) {
            return;
        }
        try {
            final byte[] challenge = ParsedAttestationRecord.createParsedAttestationRecord(
                    List.of((X509Certificate) chain[0])).attestationChallenge;
            challenges.put(ByteBuffer.wrap(challenge), new AttestationProtocol.PendingChallenge(
                    System.currentTimeMillis() - 1000, challengeUser));
        } catch (final Exception e) {
            // not a parseable leaf, so the server will not find a challenge either
        }
    }
}
