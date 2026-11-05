package app.attestation.server;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.sun.net.httpserver.HttpHandler;
import jakarta.mail.Address;
import jakarta.mail.Header;
import jakarta.mail.Message;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

// An alert address set through /api/configuration and text a phone controls (the failure reason
// of a paired profile 2 phone and its review flags), sent through the alert dispatcher to an
// in-memory transport.
//
// Invariants: an address the handler stores yields exactly one plain recipient, that address, and
// no group. A sent message carries only the headers the dispatcher sets, with the fixed subjects,
// and the device text appears in the body unchanged. The dispatcher never throws for any stored
// address or text, so one bad row cannot stop alerts for other accounts.
public final class EmailFuzz {
    private static final byte[] ALICE_TOKEN = FuzzFixture.token("alice session");
    private static final String FROM = "alerts@example.com";
    private static final Set<String> HEADERS = Set.of("Date", "From", "To", "Message-ID", "Subject",
            "MIME-Version", "Content-Type", "Content-Transfer-Encoding");
    private static final Set<String> SUBJECTS = Set.of("Devices provided invalid attestations",
            "New phone waiting for approval", "Was the old phone reset?",
            "Devices failed to provide valid attestations within 48 hours");
    private static HttpHandler configuration;
    private static long aliceSession;
    private static byte[] approved;
    private static byte[] pending;

    public static void fuzzerInitialize() throws Exception {
        FuzzFixture.installTestRoot();
        FuzzDb.setup();
        final var constructor = Class.forName("app.attestation.server.AttestationServer$ConfigurationHandler")
                .getDeclaredConstructor();
        constructor.setAccessible(true);
        configuration = (HttpHandler) constructor.newInstance();
        final Cache<ByteBuffer, AttestationProtocol.PendingChallenge> challenges = Caffeine.newBuilder().build();
        final FuzzFixture first = new FuzzFixture("email p2", false);
        final FuzzFixture second = new FuzzFixture("email p2 pending", false);
        for (final FuzzFixture phone : List.of(first, second)) {
            challenges.put(ByteBuffer.wrap(phone.challenge), new AttestationProtocol.PendingChallenge(
                    System.currentTimeMillis() - 1000, FuzzDb.alice));
            AttestationProtocol.verifySerialized(phone.message(), challenges, FuzzDb.alice, false,
                    FuzzFixture.trust(), FuzzFixture.releases());
        }
        approved = first.fingerprint();
        pending = second.fingerprint();
        Profile2Handlers.approveDevice(FuzzDb.alice, approved);
        final var insert = FuzzDb.conn().prepare("INSERT INTO Sessions (userId, token, expiryTime) VALUES (?, ?, ?)");
        insert.bind(1, FuzzDb.alice).bind(2, ALICE_TOKEN).bind(3, Long.MAX_VALUE);
        insert.step();
        insert.dispose();
        aliceSession = FuzzDb.conn().getLastInsertId();
        FuzzDb.snapshot();
    }

    public static void fuzzerTestOneInput(final FuzzedDataProvider data) throws Exception {
        final String email = data.consumeString(120);
        // device text reaches the server as decoded UTF-8
        final String reason = new String(data.consumeBytes(300), StandardCharsets.UTF_8);
        final String flags = new String(data.consumeRemainingAsBytes(), StandardCharsets.UTF_8);
        try {
            final byte[] body = Json.createObjectBuilder()
                    .add("verifyInterval", 21600)
                    .add("alertDelay", 172800)
                    .add("email", email)
                    .build().toString().getBytes(StandardCharsets.UTF_8);
            final FakeExchange exchange = new FakeExchange("POST", "/api/configuration",
                    URI.create("/api/configuration"), body);
            exchange.header("Origin", "https://" + AttestationServer.DOMAIN);
            exchange.header("Content-Type", "application/json");
            exchange.header("Sec-Fetch-Mode", "same-origin");
            exchange.header("Sec-Fetch-Site", "same-origin");
            exchange.header("Sec-Fetch-Dest", "empty");
            exchange.header("Cookie", "__Host-Http-session=" + aliceSession + "|"
                    + Base64.getEncoder().encodeToString(ALICE_TOKEN));
            configuration.handle(exchange);
            if (exchange.status != 200) {
                if (exchange.status != 400) {
                    throw new AssertionError("configuration answered " + exchange.status);
                }
                return;
            }
            final List<String> stored = FuzzDb.rows("SELECT address FROM EmailAddresses WHERE userId = ?", FuzzDb.alice);
            if (stored.size() != (email.trim().isEmpty() ? 0 : 1)) {
                throw new AssertionError("stored " + stored.size() + " addresses");
            }
            if (stored.isEmpty()) {
                return;
            }
            final String address = stored.get(0).substring(0, stored.get(0).length() - 1);

            // a failed check of the approved phone, and review flags on the pending one
            final var update = FuzzDb.conn().prepare(
                    "UPDATE Devices SET failureTimeLast = ?, failureReason = ? WHERE fingerprint = ?");
            update.bind(1, System.currentTimeMillis()).bind(2, reason).bind(3, approved);
            update.step();
            update.dispose();
            final var flag = FuzzDb.conn().prepare("UPDATE Devices SET reviewFlags = ? WHERE fingerprint = ?");
            flag.bind(1, flags).bind(2, pending);
            flag.step();
            flag.dispose();

            RecordingTransport.sent.clear();
            final AlertDispatcher dispatcher = new AlertDispatcher();
            dispatcher.prepare(FuzzDb.conn());
            dispatcher.dispatch(RecordingTransport.session(), FROM, System.currentTimeMillis());
            final List<Message> sent = new ArrayList<>(RecordingTransport.sent);
            final InternetAddress expected = new InternetAddress(address);
            for (final Message message : sent) {
                check(message, expected, reason, flags);
            }
        } finally {
            FuzzDb.restore();
        }
    }

    private static void check(final Message message, final InternetAddress expected, final String reason,
            final String flags) throws Exception {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        message.writeTo(out);
        final MimeMessage parsed = new MimeMessage(RecordingTransport.session(),
                new ByteArrayInputStream(out.toByteArray()));
        final Enumeration<Header> headers = parsed.getAllHeaders();
        while (headers.hasMoreElements()) {
            final String name = headers.nextElement().getName();
            if (!HEADERS.contains(name)) {
                throw new AssertionError("unexpected header " + name);
            }
        }
        final Address[] recipients;
        try {
            recipients = parsed.getAllRecipients();
        } catch (final jakarta.mail.internet.AddressException e) {
            throw new AssertionError("the sent To header does not parse for " + escape(expected.getAddress()), e);
        }
        if (recipients == null || recipients.length != 1 || !(recipients[0] instanceof InternetAddress to)
                || to.isGroup() || !to.getAddress().equalsIgnoreCase(expected.getAddress())) {
            throw new AssertionError("recipients changed for " + escape(expected.getAddress()) + ": "
                    + escape(java.util.Arrays.toString(recipients)));
        }
        if (parsed.getHeader("To").length != 1 || parsed.getHeader("Subject").length != 1
                || !SUBJECTS.contains(parsed.getSubject())) {
            throw new AssertionError("headers changed");
        }
        final String text = (String) parsed.getContent();
        if (parsed.getSubject().startsWith("Devices provided") && !reason.isEmpty()
                && !lines(text).contains(lines(reason))) {
            throw new AssertionError("failure reason not in the body unchanged: " + escape(reason)
                    + " body: " + escape(text));
        }
        if (parsed.getSubject().startsWith("New phone") && !flags.isEmpty()
                && !lines(text).contains(lines(flags))) {
            throw new AssertionError("review flags not in the body unchanged: " + escape(flags)
                    + " body: " + escape(text));
        }
    }

    // Line ends as mail may rewrite them, the same on both sides of a comparison.
    private static String lines(final String s) {
        return s.replace("\r\n", "\n").replace("\r", "\n");
    }

    static String escape(final String s) {
        final StringBuilder b = new StringBuilder();
        s.chars().forEach(c -> b.append(c >= 0x20 && c < 0x7f ? String.valueOf((char) c) : String.format("\\u%04x", c)));
        return b.toString();
    }

    public static List<byte[]> seeds() {
        return List.of(
                "alice@example.com\nverified boot hash is not an official release\nfast-response".getBytes(StandardCharsets.UTF_8),
                "\"a b\"@example.com\nreason\r\nBcc: x@example.com\nflags".getBytes(StandardCharsets.UTF_8),
                "group: a@example.com, b@example.com;\nr\nf".getBytes(StandardCharsets.UTF_8),
                "Alice <alice@example.com>\nr\nf".getBytes(StandardCharsets.UTF_8));
    }
}
