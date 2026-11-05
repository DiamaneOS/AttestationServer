package app.attestation.server;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.common.io.BaseEncoding;
import com.sun.net.httpserver.HttpHandler;
import jakarta.json.JsonObjectBuilder;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

// Every HTTP handler, called directly with a fake exchange, against a database with two made-up
// accounts, each with a session, an e-mail address and phones.
//
// Invariants: no request ends in a server error or lets an exception out of the handler. A
// request without a valid session gets no account data and changes no account. A session of one
// account never changes the other account's settings, sessions, addresses or phones.
public final class HttpFuzz {
    private record Endpoint(String path, HttpHandler handler, boolean session) {}

    private static final List<Endpoint> endpoints = new ArrayList<>();
    private static final byte[] ALICE_TOKEN = FuzzFixture.token("alice session");
    private static final byte[] BOB_TOKEN = FuzzFixture.token("bob session");
    private static final byte[] ALICE_KEY = FuzzFixture.token("alice subscribe key");
    private static final byte[] BOB_KEY = FuzzFixture.token("bob subscribe key");
    private static long aliceSession;
    private static long aliceExpired;
    private static long bobSession;
    private static final List<String> fingerprints = new ArrayList<>();
    // the last exception a handler logged, which is what a 500 hides
    private static Throwable logged;

    private static HttpHandler handler(final String name, final Object... args) throws Exception {
        final Class<?> type = Class.forName("app.attestation.server." + name);
        for (final var constructor : type.getDeclaredConstructors()) {
            if (constructor.getParameterCount() == args.length) {
                constructor.setAccessible(true);
                return (HttpHandler) constructor.newInstance(args);
            }
        }
        throw new IllegalStateException(name);
    }

    public static void fuzzerInitialize() throws Exception {
        FuzzFixture.installTestRoot();
        FuzzDb.setup();
        final String[][] handlers = {
            {"/api/status", "AttestationServer$StatusHandler", "0"},
            {"/api/create-account", "AttestationServer$CreateAccountHandler", "0"},
            {"/api/change-password", "AttestationServer$ChangePasswordHandler", "1"},
            {"/api/login", "AttestationServer$LoginHandler", "0"},
            {"/api/logout", "AttestationServer$LogoutHandler", "1"},
            {"/api/logout-everywhere", "AttestationServer$LogoutEverywhereHandler", "1"},
            {"/api/rotate", "AttestationServer$RotateHandler", "1"},
            {"/api/account", "AttestationServer$AccountHandler", "1"},
            {"/api/account.png", "AttestationServer$AccountQrHandler", "1"},
            {"/api/configuration", "AttestationServer$ConfigurationHandler", "1"},
            {"/api/delete-device", "AttestationServer$DeleteDeviceHandler", "1"},
            {"/api/retire-device", "Profile2Handlers$RetireDeviceHandler", "1"},
            {"/api/enroll-link", "Profile2Handlers$EnrollLinkHandler", "1"},
            {"/releases.json", "Profile2Handlers$ReleaseListHandler", "0"},
            {"/api/devices.json", "AttestationServer$DevicesHandler", "1"},
            {"/api/attestation-history.json", "AttestationServer$AttestationHistoryHandler", "1"},
            {"/auditor/challenge", "AttestationServer$ChallengeHandler", "0"},
            {"/auditor/verify", "AttestationServer$VerifyHandler", "0"},
        };
        for (final String[] h : handlers) {
            endpoints.add(new Endpoint(h[0], handler(h[1]), h[2].equals("1")));
        }
        endpoints.add(new Endpoint("/api/approve-device", handler("Profile2Handlers$PendingDeviceHandler", true), true));
        endpoints.add(new Endpoint("/api/reject-device", handler("Profile2Handlers$PendingDeviceHandler", false), true));

        // phones: a profile 1 phone of alice, an approved profile 2 phone of alice, a pending one of bob
        final Cache<ByteBuffer, AttestationProtocol.PendingChallenge> challenges = Caffeine.newBuilder().build();
        final TrustConfig trust = FuzzFixture.trust();
        final ReleaseList releases = FuzzFixture.releases();
        final Object[][] phones = {{"http p1", true, FuzzDb.alice}, {"http p2", false, FuzzDb.alice},
                {"http p2 bob", false, FuzzDb.bob}};
        for (final Object[] phone : phones) {
            final FuzzFixture fixture = new FuzzFixture((String) phone[0], (Boolean) phone[1]);
            challenges.put(ByteBuffer.wrap(fixture.challenge), new AttestationProtocol.PendingChallenge(
                    System.currentTimeMillis() - 1000, (Long) phone[2]));
            AttestationProtocol.verifySerialized(fixture.message(), challenges, (Long) phone[2], false, trust, releases);
            fingerprints.add(BaseEncoding.base16().encode(fixture.fingerprint()));
        }
        Profile2Handlers.approveDevice(FuzzDb.alice, BaseEncoding.base16().decode(fingerprints.get(1)));
        aliceSession = session(FuzzDb.alice, ALICE_TOKEN, Long.MAX_VALUE);
        aliceExpired = session(FuzzDb.alice, FuzzFixture.token("alice old session"), 1);
        bobSession = session(FuzzDb.bob, BOB_TOKEN, Long.MAX_VALUE);
        FuzzDb.conn().exec("INSERT INTO EmailAddresses (userId, address) VALUES (" + FuzzDb.alice
                + ", 'alice@example.com'), (" + FuzzDb.bob + ", 'bob@example.com')");
        FuzzDb.snapshot();
        final java.util.logging.Logger logger = java.util.logging.Logger.getLogger("app.attestation");
        logger.setLevel(java.util.logging.Level.ALL);
        logger.addHandler(new java.util.logging.Handler() {
            @Override
            public void publish(final java.util.logging.LogRecord record) {
                if (record.getThrown() != null) {
                    logged = record.getThrown();
                }
            }

            @Override
            public void flush() {}

            @Override
            public void close() {}
        });
    }

    private static long session(final long userId, final byte[] token, final long expiry) throws Exception {
        final var insert = FuzzDb.conn().prepare("INSERT INTO Sessions (userId, token, expiryTime) VALUES (?, ?, ?)");
        try {
            insert.bind(1, userId);
            insert.bind(2, token);
            insert.bind(3, expiry);
            insert.step();
        } finally {
            insert.dispose();
        }
        return FuzzDb.conn().getLastInsertId();
    }

    private static String cookie(final long session, final byte[] token) {
        return "__Host-Http-session=" + session + "|" + Base64.getEncoder().encodeToString(token);
    }

    // What one account owns, as text, for comparing before and after a request.
    private static List<String> state(final long userId) throws Exception {
        final List<String> state = new ArrayList<>();
        state.addAll(FuzzDb.rows("SELECT * FROM Accounts WHERE userId = ?", userId));
        state.addAll(FuzzDb.rows("SELECT * FROM EmailAddresses WHERE userId = ? ORDER BY address", userId));
        state.addAll(FuzzDb.rows("SELECT * FROM Sessions WHERE userId = ? ORDER BY sessionId", userId));
        state.addAll(FuzzDb.rows("SELECT * FROM Devices WHERE userId = ? ORDER BY fingerprint", userId));
        state.addAll(FuzzDb.rows("""
                SELECT count(*) FROM Attestations WHERE fingerprint IN (SELECT fingerprint FROM Devices WHERE userId = ?)""",
                userId));
        return state;
    }

    public static void fuzzerTestOneInput(final FuzzedDataProvider data) throws Exception {
        final Endpoint endpoint = endpoints.get(data.consumeInt(0, endpoints.size() - 1));
        final String method = data.consumeBoolean() ? "POST" : data.pickValue(new String[]{"GET", "PUT", "HEAD"});
        final String path = data.consumeBoolean() ? endpoint.path : endpoint.path + data.consumeString(8);
        URI uri;
        try {
            uri = new URI(null, null, path, null);
        } catch (final java.net.URISyntaxException e) {
            uri = URI.create(endpoint.path);
        }
        final boolean app = endpoint.path.startsWith("/auditor/") || endpoint.path.equals("/api/status");

        final long actor;
        final int cookieChoice = data.consumeInt(0, 6);
        final String cookie = switch (cookieChoice) {
            case 1 -> cookie(aliceSession, ALICE_TOKEN);
            case 2 -> cookie(bobSession, BOB_TOKEN);
            case 3 -> cookie(aliceExpired, FuzzFixture.token("alice old session"));
            case 4 -> cookie(aliceSession, BOB_TOKEN);
            case 5 -> "__Host-Http-session=" + data.consumeString(60);
            case 6 -> data.consumeString(80);
            default -> null;
        };
        actor = cookieChoice == 1 ? FuzzDb.alice : cookieChoice == 2 ? FuzzDb.bob : -1;
        final String authorization = switch (data.consumeInt(0, 5)) {
            case 1 -> "Auditor " + FuzzDb.alice + " " + Base64.getEncoder().encodeToString(ALICE_KEY);
            case 2 -> "Auditor " + FuzzDb.bob;
            case 3 -> "Auditor " + FuzzDb.alice + " " + Base64.getEncoder().encodeToString(BOB_KEY);
            case 4 -> "Auditor " + data.consumeString(40);
            case 5 -> data.consumeString(60);
            default -> null;
        };

        final byte[] body;
        if (data.consumeBoolean()) {
            final JsonObjectBuilder json = Json.createObjectBuilder();
            for (final String key : new String[]{"username", "password", "currentPassword", "newPassword", "email"}) {
                if (data.consumeBoolean()) {
                    json.add(key, data.consumeString(40));
                }
            }
            if (data.consumeBoolean()) {
                json.add("verifyInterval", data.consumeBoolean() ? 21600 : data.consumeInt());
                json.add("alertDelay", data.consumeBoolean() ? 172800 : data.consumeInt());
            }
            final int device = data.consumeInt(0, fingerprints.size());
            json.add("fingerprint", device < fingerprints.size() ? fingerprints.get(device) : data.consumeString(70));
            json.add("offsetId", data.consumeBoolean() ? Long.MAX_VALUE : data.consumeLong());
            body = json.build().toString().getBytes(StandardCharsets.UTF_8);
        } else {
            body = data.consumeRemainingAsBytes();
        }

        final FakeExchange exchange = new FakeExchange(method, endpoint.path, uri, body);
        if (!app || data.consumeBoolean()) {
            header(exchange, data, "Origin", "https://" + AttestationServer.DOMAIN);
        }
        header(exchange, data, "Content-Type", "application/json");
        header(exchange, data, "Sec-Fetch-Mode", "same-origin");
        header(exchange, data, "Sec-Fetch-Site", "same-origin");
        header(exchange, data, "Sec-Fetch-Dest", "empty");
        if (cookie != null) {
            exchange.header("Cookie", cookie);
        }
        if (authorization != null) {
            exchange.header("Authorization", authorization);
        }

        logged = null;
        final List<String> alice = state(FuzzDb.alice);
        final List<String> bob = state(FuzzDb.bob);
        try {
            try {
                endpoint.handler.handle(exchange);
            } catch (final Exception e) {
                throw new AssertionError(endpoint.path + " let an exception out", e);
            }
            if (exchange.status == 500) {
                // reported with the hidden exception's stack, so each cause counts once
                final AssertionError error = new AssertionError(endpoint.path + " answered 500", logged);
                if (logged != null) {
                    error.setStackTrace(logged.getStackTrace());
                }
                throw error;
            }
            if (actor != FuzzDb.alice && !state(FuzzDb.alice).equals(alice)) {
                throw new AssertionError(endpoint.path + " changed alice's account without her session");
            }
            if (actor != FuzzDb.bob && !state(FuzzDb.bob).equals(bob)) {
                throw new AssertionError(endpoint.path + " changed bob's account without his session");
            }
            if (endpoint.session && actor == -1 && exchange.status == 200) {
                throw new AssertionError(endpoint.path + " answered 200 without a valid session");
            }
        } finally {
            FuzzDb.restore();
        }
    }

    private static void header(final FakeExchange exchange, final FuzzedDataProvider data, final String name,
            final String valid) {
        switch (data.consumeInt(0, 3)) {
            case 0 -> exchange.header(name, valid);
            case 1 -> exchange.header(name, data.consumeString(30));
            case 2 -> {
                exchange.header(name, valid);
                exchange.header(name, valid);
            }
            default -> {}
        }
    }

    public static List<byte[]> seeds() {
        // FuzzedDataProvider input: libFuzzer starts from an empty corpus and explores
        final List<byte[]> seeds = new ArrayList<>();
        for (int endpoint = 0; endpoint < 20; endpoint++) {
            seeds.add(new byte[]{(byte) endpoint, 1, 1, 1, 1, 0, 0, 0, 0, 0});
        }
        return seeds;
    }
}
