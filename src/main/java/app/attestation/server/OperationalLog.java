package app.attestation.server;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import static app.attestation.server.SyslogLevel.CRIT;

// Only CRIT and above reach the journal, which keeps identifiers out of it. A failure that stops
// alerts or release lists must still show, so each kind gets one CRIT line an hour. A line holds
// class names only: an exception's message can hold an address.
final class OperationalLog {
    static final long INTERVAL_MS = 60 * 60 * 1000;
    private static final int MAX_CAUSES = 8;

    private static final Logger logger = Logger.getLogger(OperationalLog.class.getName());
    private static final Map<String, Long> lastLogged = new HashMap<>();

    private OperationalLog() {}

    static void report(final String problem, final Throwable thrown) {
        report(problem, thrown, System.currentTimeMillis());
    }

    static synchronized void report(final String problem, final Throwable thrown, final long now) {
        final String line = problem + classes(thrown);
        final Long last = lastLogged.get(line);
        if (last == null || now - last >= INTERVAL_MS) {
            lastLogged.put(line, now);
            logger.log(CRIT, line);
        }
    }

    private static String classes(Throwable thrown) {
        final StringBuilder names = new StringBuilder();
        for (int i = 0; thrown != null && i < MAX_CAUSES; i++, thrown = thrown.getCause()) {
            names.append(i == 0 ? ": " : ", caused by ").append(thrown.getClass().getName());
        }
        return names.toString();
    }
}
