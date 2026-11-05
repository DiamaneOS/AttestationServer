package app.attestation.server;

import com.almworks.sqlite4java.SQLiteConnection;
import com.almworks.sqlite4java.SQLiteStatement;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

// A temporary database in the fuzz working directory with two made-up accounts.
final class FuzzDb {
    static final String ALICE = "fuzzalice";
    static final String BOB = "fuzzbob";
    static long alice;
    static long bob;

    private FuzzDb() {}

    static void setup() throws Exception {
        Logger.getLogger("").setLevel(Level.OFF);
        Logger.getLogger("app.attestation").setLevel(Level.OFF);
        Logger.getLogger("com.almworks.sqlite4java").setLevel(Level.OFF);
        if (Files.exists(Path.of("attestation.db"))) {
            throw new IllegalStateException("run from an empty working directory");
        }
        AttestationServer.setupAttestationDatabase();
        alice = account(ALICE, FuzzFixture.token("alice subscribe key"));
        bob = account(BOB, FuzzFixture.token("bob subscribe key"));
    }

    static SQLiteConnection conn() throws Exception {
        return AttestationServer.getLocalAttestationConn();
    }

    static long account(final String username, final byte[] subscribeKey) throws Exception {
        final SQLiteStatement insert = conn().prepare("""
                INSERT INTO Accounts (username, passwordHash, passwordSalt, subscribeKey, creationTime,
                    loginTime, verifyInterval, alertDelay) VALUES (?, x'00', x'00', ?, 0, 0, 21600, 172800)""");
        try {
            insert.bind(1, username);
            insert.bind(2, subscribeKey);
            insert.step();
        } finally {
            insert.dispose();
        }
        return conn().getLastInsertId();
    }

    private static final String[] TABLES = {"Accounts", "EmailAddresses", "Sessions", "Devices", "Attestations",
            "Configuration"};

    // Keeps a copy of every table so each input starts from the same state.
    static void snapshot() throws Exception {
        final SQLiteConnection conn = conn();
        conn.exec("ATTACH DATABASE ':memory:' AS snap");
        for (final String table : TABLES) {
            conn.exec("CREATE TABLE snap." + table + " AS SELECT * FROM main." + table);
        }
    }

    static void restore() throws Exception {
        final SQLiteConnection conn = conn();
        AttestationServer.rollbackIfNeeded(conn);
        conn.exec("PRAGMA foreign_keys = OFF");
        conn.exec("BEGIN IMMEDIATE");
        for (final String table : TABLES) {
            conn.exec("DELETE FROM main." + table);
            conn.exec("INSERT INTO main." + table + " SELECT * FROM snap." + table);
        }
        conn.exec("COMMIT");
        conn.exec("PRAGMA foreign_keys = ON");
    }

    // Rows of a query as strings, for comparing state before and after an input.
    static List<String> rows(final String sql, final Object... args) throws Exception {
        final SQLiteStatement select = conn().prepare(sql);
        try {
            for (int i = 0; i < args.length; i++) {
                if (args[i] instanceof byte[] b) {
                    select.bind(i + 1, b);
                } else if (args[i] instanceof Long l) {
                    select.bind(i + 1, l);
                } else {
                    select.bind(i + 1, (String) args[i]);
                }
            }
            final List<String> rows = new ArrayList<>();
            while (select.step()) {
                final StringBuilder row = new StringBuilder();
                for (int c = 0; c < select.columnCount(); c++) {
                    final Object value = select.columnValue(c);
                    row.append(value instanceof byte[] b ? java.util.HexFormat.of().formatHex(b) : String.valueOf(value))
                            .append('|');
                }
                rows.add(row.toString());
            }
            return rows;
        } finally {
            select.dispose();
        }
    }

    static long scalar(final String sql, final Object... args) throws Exception {
        final List<String> rows = rows(sql, args);
        if (rows.isEmpty()) {
            return -1;
        }
        final String value = rows.get(0).substring(0, rows.get(0).length() - 1);
        return value.equals("null") ? -1 : Long.parseLong(value);
    }
}
