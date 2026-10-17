package app.attestation.server;

import com.almworks.sqlite4java.SQLiteConnection;
import com.almworks.sqlite4java.SQLiteException;
import com.almworks.sqlite4java.SQLiteStatement;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;

// Loads the signed release list the release pipeline places next to the database. A file that
// fails verification or is older than one already accepted is ignored.
final class ReleaseListStore {
    static final String PATH_PROPERTY = "diamaneos.releases";
    private static final String SEQUENCE_KEY = "releaseListSequence";
    private static final Logger logger = Logger.getLogger(ReleaseListStore.class.getName());

    private static ReleaseList current;
    private static byte[] currentBytes;
    private static long checkedModified = Long.MIN_VALUE;
    private static long checkedSize = -1;

    private ReleaseListStore() {}

    static Path path() {
        return Path.of(System.getProperty(PATH_PROPERTY, "releases.json"));
    }

    static synchronized ReleaseList current() {
        return current;
    }

    static synchronized byte[] currentBytes() {
        return currentBytes;
    }

    static synchronized void refresh() {
        final Path path = path();
        try {
            final long modified = Files.getLastModifiedTime(path).toMillis();
            final long size = Files.size(path);
            // remembered only once a list is accepted, so a failed attempt is retried
            if (modified == checkedModified && size == checkedSize) {
                return;
            }
            if (size > ReleaseList.MAX_SIZE) {
                throw new GeneralSecurityException("release list too large");
            }
            final byte[] bytes = Files.readAllBytes(path);
            final ReleaseList list = ReleaseList.parse(bytes, TrustConfig.get().releaseListSigners);
            final SQLiteConnection conn = AttestationServer.open(AttestationServer.ATTESTATION_DATABASE);
            try {
                conn.exec("BEGIN IMMEDIATE TRANSACTION");
                if (list.sequence < storedSequence(conn)) {
                    throw new GeneralSecurityException("release list sequence " + list.sequence
                            + " is older than the accepted one");
                }
                final SQLiteStatement update = conn.prepare(
                        "INSERT OR REPLACE INTO Configuration (key, value) VALUES (?, ?)");
                try {
                    update.bind(1, SEQUENCE_KEY);
                    update.bind(2, list.sequence);
                    update.step();
                } finally {
                    update.dispose();
                }
                conn.exec("COMMIT TRANSACTION");
            } finally {
                AttestationServer.rollbackIfNeeded(conn);
                conn.dispose();
            }
            current = list;
            currentBytes = bytes;
            checkedModified = modified;
            checkedSize = size;
        } catch (final NoSuchFileException e) {
            // no release list published yet
        } catch (final GeneralSecurityException | IOException | SQLiteException e) {
            logger.log(Level.WARNING, "ignoring release list " + path, e);
        }
    }

    private static long storedSequence(final SQLiteConnection conn) throws SQLiteException {
        final SQLiteStatement select = conn.prepare("SELECT value FROM Configuration WHERE key = ?");
        try {
            select.bind(1, SEQUENCE_KEY);
            return select.step() ? select.columnLong(0) : 0;
        } finally {
            select.dispose();
        }
    }
}
