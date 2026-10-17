package app.attestation.server;

import com.almworks.sqlite4java.SQLiteConnection;
import com.almworks.sqlite4java.SQLiteStatement;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.common.io.BaseEncoding;

import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

// Trust profile 2 against a real database. Run from an empty working directory.
public final class Profile2Test {
    private static final Cache<ByteBuffer, AttestationProtocol.PendingChallenge> challenges =
            Caffeine.newBuilder().build();
    private static TrustConfig trust;
    private static int passed;

    public static void main(final String[] args) throws Exception {
        Logger.getLogger("").setLevel(Level.OFF);
        Logger.getLogger("com.almworks.sqlite4java").setLevel(Level.OFF);
        if (Files.exists(Path.of("attestation.db"))) {
            throw new AssertionError("run from an empty working directory");
        }
        AttestationServer.setupAttestationDatabase();
        trust = Profile2Fixture.trust();
        final long alice = account("alice");
        final long bob = account("bob");
        final byte[] release1 = Profile2Fixture.sha256("release 1");
        final byte[] release2 = Profile2Fixture.sha256("release 2");
        final ReleaseList list1 = list(1, Profile2Fixture.release(release1, 202610));
        final ReleaseList list2 = list(2, Profile2Fixture.release(release1, 202610),
                Profile2Fixture.release(release2, 202611));

        // first pairing
        final Profile2Fixture phone = new Profile2Fixture();
        phone.challenge = challenge(alice, 2000);
        final byte[] first = phone.message();
        verify(first, alice, false, list1);
        require(column(phone, "trustProfile") == 2, "profile 2 pinned");
        require(text(phone, "reviewFlags").isEmpty(), "well-formed chain is not flagged");
        rejected("challenge not pending", () -> verify(first, alice, false, list1));

        firstPairingRejected("challenge expired", alice, list1, f -> {}, 31000);
        firstPairingRejected("not issued to this account", bob, list1, f -> {}, 1000, alice);
        firstPairingRejected("not issued to this account", alice, list1, f -> {}, 1000, -1);
        firstPairingRejected("not an official release", alice, list1,
                f -> f.bootHash = Profile2Fixture.sha256("unpublished"), 1000);
        firstPairingRejected("do not match official release", alice, list1, f -> f.keyMintVersion = 400, 1000);
        firstPairingRejected("signing key", alice, list1,
                f -> f.signer = Profile2Fixture.sha256("other signer"), 1000);
        firstPairingRejected("requires the DiamaneOS Auditor", alice, list1, f -> {
            f.packageName = "app.attestation.auditor";
            f.signer = BaseEncoding.base16().decode("990E04F0864B19F14F84E0E432F7A393F297AB105A22C1E1B10B442A4A62C42C");
        }, 1000);
        firstPairingRejected("not locked", alice, list1, f -> f.locked = false, 1000);
        firstPairingRejected("invalid verified boot key", alice, list1,
                f -> f.bootKey = Profile2Fixture.sha256("Pixel key"), 1000);
        // a list from an unknown signer is never loaded, so nothing matches
        firstPairingRejected("not an official release", alice, list(1, Profile2Fixture.keyPair(),
                Profile2Fixture.release(release1, 202610)), f -> {}, 1000);

        // later checks need no bound challenge or time limit, only the pinned keys and the list
        phone.nextCheck(challenge(-1, 600000));
        verify(phone.message(), alice, true, list1);
        rejected("wrong userId", () -> {
            phone.nextCheck(challenge(-1, 0));
            verify(phone.message(), bob, true, list1);
        });

        // approved update, then a downgrade and an unpublished build alert
        phone.nextCheck(challenge(-1, 0));
        phone.bootHash = release2;
        phone.osPatchLevel = 202611;
        rejected("not an official release", () -> verify(phone.message(), alice, true, list1));
        require(column(phone, "failureTimeLast") > 0, "unpublished build alerts");
        phone.nextCheck(challenge(-1, 0));
        verify(phone.message(), alice, true, list2);
        require(column(phone, "pinnedOsPatchLevel") == 202611, "approved update accepted");
        phone.nextCheck(challenge(-1, 0));
        phone.bootHash = release1;
        phone.osPatchLevel = 202610;
        clearFailure(phone);
        rejected("OS patch level downgrade", () -> verify(phone.message(), alice, true, list2));
        require(column(phone, "failureTimeLast") > 0, "downgrade alerts");

        // a different phone cannot take over the pinned record
        final Profile2Fixture other = new Profile2Fixture();
        other.challenge = challenge(alice, 1000);
        other.message();
        other.nextCheck(challenge(-1, 0));
        final byte[] stolen = replaceFingerprint(other.message(), phone);
        rejected("certificate chain mismatch", () -> verify(stolen, alice, true, list2));

        // reset: the new pairing is a new device, the old one is only retired on request
        final Profile2Fixture reset = new Profile2Fixture();
        reset.bootHash = release2;
        reset.osPatchLevel = 202611;
        reset.challenge = challenge(alice, 1000);
        setLastVerified(phone, System.currentTimeMillis() - 13L * 60 * 60 * 1000);
        verify(reset.message(), alice, false, list2);
        require(retireSuggested(phone) && !retireSuggested(reset), "old phone suggested for retiring");
        require(!AttestationServer.retireDevice(bob, fingerprint(phone)), "other account cannot retire it");
        require(AttestationServer.retireDevice(alice, fingerprint(phone)), "account holder retires it");
        require(!retireSuggested(phone), "retired device no longer suggested");
        rejected("device retired", () -> {
            phone.nextCheck(challenge(-1, 0));
            phone.bootHash = release2;
            phone.osPatchLevel = 202611;
            verify(phone.message(), alice, true, list2);
        });

        // the timing heuristic flags but never rejects
        final Profile2Fixture quick = new Profile2Fixture();
        quick.challenge = challenge(bob, 0);
        verify(quick.message(), bob, false, list1);
        require(text(quick, "reviewFlags").equals("fast-response"), "fast response flagged");

        releaseListStore();
        challengeLimit();
        enrollLink();
        System.out.println("Profile 2 server tests: " + passed + " checks passed (software fixtures, no hardware claim).");
    }

    private interface Change {
        void apply(Profile2Fixture fixture);
    }

    private interface Action {
        void run() throws Exception;
    }

    private static void firstPairingRejected(final String reason, final long userId, final ReleaseList list,
            final Change change, final long age) throws Exception {
        firstPairingRejected(reason, userId, list, change, age, userId);
    }

    private static void firstPairingRejected(final String reason, final long userId, final ReleaseList list,
            final Change change, final long age, final long challengeUser) throws Exception {
        final Profile2Fixture fixture = new Profile2Fixture();
        change.apply(fixture);
        fixture.challenge = challenge(challengeUser, age);
        rejected(reason, () -> verify(fixture.message(), userId, false, list));
        require(!exists(fixture), "rejected pairing stores nothing: " + reason);
    }

    private static void verify(final byte[] message, final long userId, final boolean paired,
            final ReleaseList list) throws Exception {
        AttestationProtocol.verifySerialized(message, challenges, userId, paired, trust, list);
        passed++;
    }

    private static void rejected(final String reason, final Action action) throws Exception {
        try {
            action.run();
        } catch (final GeneralSecurityException e) {
            require(e.getMessage() != null && e.getMessage().contains(reason),
                    "expected '" + reason + "' but got: " + e.getMessage());
            return;
        }
        throw new AssertionError("accepted, expected rejection: " + reason);
    }

    private static void require(final boolean condition, final String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        passed++;
    }

    private static byte[] challenge(final long userId, final long ageMs) {
        final byte[] challenge = AttestationProtocol.generateRandomToken();
        challenges.put(ByteBuffer.wrap(challenge),
                new AttestationProtocol.PendingChallenge(System.currentTimeMillis() - ageMs, userId));
        return challenge;
    }

    private static ReleaseList list(final long sequence, final jakarta.json.JsonObject... releases) throws Exception {
        return list(sequence, Profile2Fixture.LIST_SIGNER, releases);
    }

    private static ReleaseList list(final long sequence, final java.security.KeyPair signer,
            final jakarta.json.JsonObject... releases) throws Exception {
        try {
            return ReleaseList.parse(Profile2Fixture.releaseList(signer, sequence, releases),
                    trust.releaseListSigners);
        } catch (final GeneralSecurityException e) {
            // an untrusted list behaves like a missing one
            return null;
        }
    }

    private static long account(final String username) throws Exception {
        final SQLiteConnection conn = AttestationServer.getLocalAttestationConn();
        final SQLiteStatement insert = conn.prepare("""
                INSERT INTO Accounts (username, passwordHash, passwordSalt, subscribeKey, creationTime,
                    loginTime, verifyInterval, alertDelay) VALUES (?, x'00', x'00', x'00', 0, 0, 21600, 172800)""");
        try {
            insert.bind(1, username);
            insert.step();
        } finally {
            insert.dispose();
        }
        return conn.getLastInsertId();
    }

    private static byte[] fingerprint(final Profile2Fixture fixture) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(fixture.persistentCertificate.getEncoded());
    }

    private static boolean exists(final Profile2Fixture fixture) throws Exception {
        return fixture.persistentCertificate != null && query("SELECT 1 FROM Devices WHERE fingerprint = ?",
                fingerprint(fixture)) != null;
    }

    private static long column(final Profile2Fixture fixture, final String column) throws Exception {
        final Object value = query("SELECT " + column + " FROM Devices WHERE fingerprint = ?", fingerprint(fixture));
        return value == null ? 0 : (Long) value;
    }

    private static String text(final Profile2Fixture fixture, final String column) throws Exception {
        final Object value = query("SELECT coalesce(" + column + ", '') FROM Devices WHERE fingerprint = ?",
                fingerprint(fixture));
        return (String) value;
    }

    private static boolean retireSuggested(final Profile2Fixture fixture) throws Exception {
        final SQLiteConnection conn = AttestationServer.getLocalAttestationConn();
        final SQLiteStatement select = conn.prepare("SELECT " + AttestationServer.RETIRE_SUGGESTED
                + " FROM Devices WHERE fingerprint = ?2");
        try {
            select.bind(1, System.currentTimeMillis());
            select.bind(2, fingerprint(fixture));
            return select.step() && select.columnInt(0) == 1;
        } finally {
            select.dispose();
        }
    }

    private static Object query(final String sql, final byte[] fingerprint) throws Exception {
        final SQLiteConnection conn = AttestationServer.getLocalAttestationConn();
        final SQLiteStatement select = conn.prepare(sql);
        try {
            select.bind(1, fingerprint);
            if (!select.step()) {
                return null;
            }
            return select.columnNull(0) ? null : select.columnValue(0) instanceof Integer i
                    ? Long.valueOf(i) : select.columnValue(0);
        } finally {
            select.dispose();
        }
    }

    private static void exec(final String sql, final long value, final byte[] fingerprint) throws Exception {
        final SQLiteStatement update = AttestationServer.getLocalAttestationConn().prepare(sql);
        try {
            update.bind(1, value);
            update.bind(2, fingerprint);
            update.step();
        } finally {
            update.dispose();
        }
    }

    private static void setLastVerified(final Profile2Fixture fixture, final long time) throws Exception {
        exec("UPDATE Devices SET verifiedTimeLast = ? WHERE fingerprint = ?", time, fingerprint(fixture));
    }

    private static void clearFailure(final Profile2Fixture fixture) throws Exception {
        final SQLiteStatement update = AttestationServer.getLocalAttestationConn().prepare(
                "UPDATE Devices SET failureTimeLast = NULL WHERE fingerprint = ?");
        try {
            update.bind(1, fingerprint(fixture));
            update.step();
        } finally {
            update.dispose();
        }
    }

    // A report from another phone presented under the pinned phone's identity.
    private static byte[] replaceFingerprint(final byte[] message, final Profile2Fixture pinned) throws Exception {
        final ByteBuffer buffer = ByteBuffer.wrap(message.clone());
        buffer.get();
        final short compressedLength = buffer.getShort();
        buffer.position(buffer.position() + compressedLength);
        buffer.put(fingerprint(pinned));
        return buffer.array();
    }

    private static void releaseListStore() throws Exception {
        final Path file = Path.of("releases.json");
        System.setProperty(ReleaseListStore.PATH_PROPERTY, file.toString());
        System.setProperty(TrustConfig.PATH_PROPERTY, "trust.json");
        Files.writeString(Path.of("trust.json"), Json.createObjectBuilder()
                .add("format", TrustConfig.FORMAT).add("version", 1)
                .add("auditorReleaseSigner", BaseEncoding.base16().encode(Profile2Fixture.AUDITOR_SIGNER))
                .add("releaseListSigners", Json.createArrayBuilder().add(java.util.Base64.getEncoder()
                        .encodeToString(Profile2Fixture.LIST_SIGNER.getPublic().getEncoded())))
                .add("devices", Json.createArrayBuilder()).build().toString());
        final byte[] release = Profile2Fixture.sha256("release 1");
        Files.write(file, Profile2Fixture.releaseList(Profile2Fixture.LIST_SIGNER, 5,
                Profile2Fixture.release(release, 202610)));
        ReleaseListStore.refresh();
        require(ReleaseListStore.current().sequence == 5, "published list accepted");
        Files.write(file, Profile2Fixture.releaseList(Profile2Fixture.LIST_SIGNER, 4,
                Profile2Fixture.release(release, 202610)));
        Files.setLastModifiedTime(file, java.nio.file.attribute.FileTime.fromMillis(System.currentTimeMillis() + 5000));
        ReleaseListStore.refresh();
        require(ReleaseListStore.current().sequence == 5, "older list refused");
        Files.write(file, Profile2Fixture.releaseList(Profile2Fixture.keyPair(), 6,
                Profile2Fixture.release(release, 202610)));
        Files.setLastModifiedTime(file, java.nio.file.attribute.FileTime.fromMillis(System.currentTimeMillis() + 10000));
        ReleaseListStore.refresh();
        require(ReleaseListStore.current().sequence == 5, "list from an unknown signer refused");
    }

    private static void challengeLimit() {
        final long userId = 4242;
        for (int i = 0; i < AttestationServer.MAX_ACCOUNT_CHALLENGES_PER_HOUR; i++) {
            require(AttestationServer.allowAccountChallenge(userId), "challenge within the limit");
        }
        require(!AttestationServer.allowAccountChallenge(userId), "challenge over the limit refused");
    }

    private static void enrollLink() {
        final byte[] key = new byte[32];
        key[0] = (byte) 0xfb;
        final String link = AttestationServer.enrollLink(7, key, 21600);
        require(link.startsWith("intent://enroll?account=")
                && link.endsWith("#Intent;scheme=diamaneos-auditor;package=de.diamaneos.auditor;end"),
                "link restricted to Auditor");
        final String account = URLDecoder.decode(link.substring("intent://enroll?account=".length(),
                link.indexOf('#')), StandardCharsets.UTF_8);
        require(account.equals(AttestationServer.DOMAIN + " 7 " + BaseEncoding.base64().encode(key) + " 21600"),
                "link carries the QR code data");
    }
}
