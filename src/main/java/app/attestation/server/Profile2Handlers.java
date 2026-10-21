package app.attestation.server;

import app.attestation.server.AttestationServer.Account;
import com.almworks.sqlite4java.SQLiteConnection;
import com.almworks.sqlite4java.SQLiteException;
import com.almworks.sqlite4java.SQLiteStatement;
import com.google.common.io.BaseEncoding;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonReader;
import jakarta.json.JsonWriter;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;

import static app.attestation.server.AttestationServer.DOMAIN;
import static app.attestation.server.AttestationServer.getLocalAttestationConn;
import static app.attestation.server.AttestationServer.verifySession;

// DiamaneOS: the account page handlers for profile 2 phones and the release list. Each one is
// registered in AttestationServer with one createContext line.
class Profile2Handlers {
    private static final Logger logger = Logger.getLogger(AttestationServer.class.getName());

    static class RetireDeviceHandler extends AttestationServer.PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLiteException {
            final String fingerprint;
            try (final JsonReader reader = Json.createReader(exchange.getRequestBody())) {
                final JsonObject object = reader.readObject();
                fingerprint = object.getString("fingerprint");
            } catch (final ClassCastException | JsonException | NullPointerException e) {
                logger.log(Level.WARNING, "invalid request", e);
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            final Account account = verifySession(exchange, false);
            if (account == null) {
                return;
            }

            final byte[] fingerprintBytes;
            try {
                fingerprintBytes = BaseEncoding.base16().decode(fingerprint);
            } catch (final IllegalArgumentException e) {
                exchange.sendResponseHeaders(400, -1);
                return;
            }
            if (!retireDevice(account.userId(), fingerprintBytes)) {
                exchange.sendResponseHeaders(400, -1);
                return;
            }
            exchange.sendResponseHeaders(200, -1);
        }
    }

    // Archives a device of this account with its history. It stops raising alerts and its
    // checks are refused from then on.
    static boolean retireDevice(final long userId, final byte[] fingerprint) throws SQLiteException {
        final SQLiteConnection conn = getLocalAttestationConn();
        final SQLiteStatement update = conn.prepare("""
                UPDATE Devices SET retiredTime = ? WHERE userId = ? AND fingerprint = ?
                AND retiredTime IS NULL AND deletionTime IS NULL""");
        try {
            update.bind(1, System.currentTimeMillis());
            update.bind(2, userId);
            update.bind(3, fingerprint);
            update.step();
        } finally {
            update.dispose();
        }
        return conn.getChanges() == 1;
    }

    // The same account data as the QR code, as a link only Auditor can receive.
    static String enrollLink(final long userId, final byte[] subscribeKey, final int verifyInterval) {
        final String account = DOMAIN + " " + userId + " " + BaseEncoding.base64().encode(subscribeKey)
                + " " + verifyInterval;
        return "intent://enroll?account=" + java.net.URLEncoder.encode(account, StandardCharsets.UTF_8)
                .replace("+", "%20")
                + "#Intent;scheme=diamaneos-auditor;package=de.diamaneos.auditor;end";
    }

    static class EnrollLinkHandler extends AttestationServer.PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLiteException {
            final Account account = verifySession(exchange, false);
            if (account == null) {
                return;
            }
            final JsonObjectBuilder result = Json.createObjectBuilder();
            result.add("link", enrollLink(account.userId(), account.subscribeKey(), account.verifyInterval()));
            result.add("userId", account.userId());
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, 0);
            try (final OutputStream output = exchange.getResponseBody();
                    final JsonWriter writer = Json.createWriter(output)) {
                writer.write(result.build());
            }
        }
    }

    // A new profile 2 phone needs the account holder's approval before it is monitored. A rejected
    // one is removed with its history.
    static class PendingDeviceHandler extends AttestationServer.PostHandler {
        private final boolean approve;

        PendingDeviceHandler(final boolean approve) {
            this.approve = approve;
        }

        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLiteException {
            final byte[] fingerprint;
            try (final JsonReader reader = Json.createReader(exchange.getRequestBody())) {
                fingerprint = BaseEncoding.base16().decode(reader.readObject().getString("fingerprint"));
            } catch (final ClassCastException | JsonException | NullPointerException | IllegalArgumentException e) {
                logger.log(Level.WARNING, "invalid request", e);
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            final Account account = verifySession(exchange, false);
            if (account == null) {
                return;
            }

            final boolean changed = approve ? approveDevice(account.userId(), fingerprint)
                    : rejectDevice(account.userId(), fingerprint);
            exchange.sendResponseHeaders(changed ? 200 : 400, -1);
        }
    }

    static boolean approveDevice(final long userId, final byte[] fingerprint) throws SQLiteException {
        final SQLiteConnection conn = getLocalAttestationConn();
        final SQLiteStatement update = conn.prepare("""
                UPDATE Devices SET pending = 0 WHERE userId = ? AND fingerprint = ? AND pending = 1
                AND deletionTime IS NULL""");
        try {
            update.bind(1, userId);
            update.bind(2, fingerprint);
            update.step();
        } finally {
            update.dispose();
        }
        return conn.getChanges() == 1;
    }

    static boolean rejectDevice(final long userId, final byte[] fingerprint) throws SQLiteException {
        final SQLiteConnection conn = getLocalAttestationConn();
        final SQLiteStatement delete = conn.prepare(
                "DELETE FROM Devices WHERE userId = ? AND fingerprint = ? AND pending = 1");
        try {
            delete.bind(1, userId);
            delete.bind(2, fingerprint);
            delete.step();
        } finally {
            delete.dispose();
        }
        return conn.getChanges() == 1;
    }

    // Serves the signed release list this server verified and accepted.
    static class ReleaseListHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            try {
                if (!exchange.getRequestMethod().equals("GET")) {
                    exchange.getResponseHeaders().set("Allow", "GET");
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }
                ReleaseListStore.refresh();
                final byte[] list = ReleaseListStore.currentBytes();
                if (list == null) {
                    exchange.sendResponseHeaders(404, -1);
                    return;
                }
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.getResponseHeaders().set("Cache-Control", "no-cache");
                exchange.sendResponseHeaders(200, list.length);
                try (final OutputStream output = exchange.getResponseBody()) {
                    output.write(list);
                }
            } finally {
                exchange.close();
            }
        }
    }
}
