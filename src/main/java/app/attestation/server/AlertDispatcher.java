package app.attestation.server;

import com.almworks.sqlite4java.SQLiteConnection;
import com.almworks.sqlite4java.SQLiteException;
import com.almworks.sqlite4java.SQLiteStatement;
import com.google.common.io.BaseEncoding;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import static app.attestation.server.SyslogLevel.CRIT;

class AlertDispatcher implements Runnable {
    private static final String EMAIL_DISPLAY_NAME = "DiamaneOS Attestation";
    private static final long WAIT_MS = 60 * 1000;
    private static final int TIMEOUT_MS = 30 * 1000;
    private static final long ALERT_THROTTLE_MS = 24 * 60 * 60 * 1000;

    // Split displayed fingerprint into groups of 4 characters
    private static final int FINGERPRINT_SPLIT_INTERVAL = 4;

    private static final Logger logger = Logger.getLogger(AlertDispatcher.class.getName());

    private record Account(long userId, String username, int alertDelay) {}

    static final String PROFILE_2_LABEL = "First pairing not verified by hardware";

    private static void appendFingerprint(final StringBuilder builder, final byte[] fingerprint,
            final int trustProfile) {
        builder.append("* ");
        final String encoded = BaseEncoding.base16().encode(fingerprint);
        for (int i = 0; i < encoded.length(); i += FINGERPRINT_SPLIT_INTERVAL) {
            builder.append(encoded, i, Math.min(encoded.length(), i + FINGERPRINT_SPLIT_INTERVAL));
            if (i + FINGERPRINT_SPLIT_INTERVAL < encoded.length()) {
                builder.append("-");
            }
        }
        if (trustProfile == 2) {
            builder.append(" (").append(PROFILE_2_LABEL).append(")");
        }
        builder.append("\n");
    }

    // Tells the account once about each new profile 2 phone waiting for approval.
    private static void sendPendingNotices(final Session session, final String emailFrom, final long now,
            final SQLiteStatement selectPendingNotices, final SQLiteStatement updatePendingNotice,
            final SQLiteStatement selectEmails) throws SQLiteException {
        record Notice(long userId, String username, byte[] fingerprint, String details) {}
        final ArrayList<Notice> notices = new ArrayList<>();
        try {
            while (selectPendingNotices.step()) {
                final StringBuilder details = new StringBuilder();
                appendFingerprint(details, selectPendingNotices.columnBlob(2), 2);
                details.append("  Verified boot hash: ").append(selectPendingNotices.columnString(3)).append("\n")
                        .append("  OS version: ").append(selectPendingNotices.columnInt(4))
                        .append(", patch levels: ").append(selectPendingNotices.columnInt(5)).append(" / ")
                        .append(selectPendingNotices.columnInt(6)).append(" / ")
                        .append(selectPendingNotices.columnInt(7)).append("\n")
                        .append("  First check: ").append(new java.util.Date(selectPendingNotices.columnLong(8)))
                        .append("\n");
                if (!selectPendingNotices.columnNull(9) && !selectPendingNotices.columnString(9).isEmpty()) {
                    details.append("  Flagged for review: ").append(selectPendingNotices.columnString(9)).append("\n");
                }
                notices.add(new Notice(selectPendingNotices.columnLong(0), selectPendingNotices.columnString(1),
                        selectPendingNotices.columnBlob(2), details.toString()));
            }
        } finally {
            selectPendingNotices.reset();
        }

        for (final Notice notice : notices) {
            final ArrayList<String> addresses = new ArrayList<>();
            try {
                selectEmails.bind(1, notice.userId);
                while (selectEmails.step()) {
                    addresses.add(selectEmails.columnString(0));
                }
            } finally {
                selectEmails.reset();
            }
            for (final String address : addresses) {
                try {
                    final Message message = new MimeMessage(session);
                    message.setFrom(new InternetAddress(emailFrom, EMAIL_DISPLAY_NAME));
                    message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(address));
                    message.setSubject("New phone waiting for approval");
                    message.setText("This is a message for the account '" + notice.username + "'.\n\n" +
                            "A phone was paired with this account. Its hardware cannot prove that it is genuine:\n\n" +
                            notice.details + "\nApprove it only if you added this phone yourself. Until then it " +
                            "is not monitored and raises no alerts.\n\n" +
                            "Log in to https://" + AttestationServer.DOMAIN + "/ to approve or reject it.\n\n" +
                            "If you do not want to receive these emails and cannot log in to the account,\nemail " +
                            emailFrom + " from the address receiving them.");
                    Transport.send(message);
                } catch (final MessagingException | UnsupportedEncodingException e) {
                    logger.log(Level.WARNING, "email error", e);
                }
            }
            try {
                updatePendingNotice.bind(1, now);
                updatePendingNotice.bind(2, notice.fingerprint);
                updatePendingNotice.step();
            } finally {
                updatePendingNotice.reset();
            }
        }
    }

    // Asks once per device whether a phone that stopped checking in was reset, after a newer device
    // joined the same account. Retiring stays an explicit choice in the web interface.
    private static void sendRetireSuggestions(final Session session, final String emailFrom, final long now,
            final SQLiteStatement selectRetireSuggestions, final SQLiteStatement updateRetireSuggested,
            final SQLiteStatement selectEmails) throws SQLiteException {
        final java.util.LinkedHashMap<Long, String> usernames = new java.util.LinkedHashMap<>();
        final java.util.LinkedHashMap<Long, StringBuilder> devices = new java.util.LinkedHashMap<>();
        final ArrayList<byte[]> fingerprints = new ArrayList<>();
        try {
            selectRetireSuggestions.bind(1, now);
            while (selectRetireSuggestions.step()) {
                final long userId = selectRetireSuggestions.columnLong(0);
                usernames.put(userId, selectRetireSuggestions.columnString(1));
                final byte[] fingerprint = selectRetireSuggestions.columnBlob(2);
                fingerprints.add(fingerprint);
                appendFingerprint(devices.computeIfAbsent(userId, k -> new StringBuilder()), fingerprint,
                        selectRetireSuggestions.columnInt(3));
            }
        } finally {
            selectRetireSuggestions.reset();
        }

        for (final var entry : devices.entrySet()) {
            final ArrayList<String> addresses = new ArrayList<>();
            try {
                selectEmails.bind(1, entry.getKey());
                while (selectEmails.step()) {
                    addresses.add(selectEmails.columnString(0));
                }
            } finally {
                selectEmails.reset();
            }
            for (final String address : addresses) {
                try {
                    final Message message = new MimeMessage(session);
                    message.setFrom(new InternetAddress(emailFrom, EMAIL_DISPLAY_NAME));
                    message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(address));
                    message.setSubject("Was the old phone reset?");
                    message.setText("This is a message for the account '" + usernames.get(entry.getKey()) + "'.\n\n" +
                            "A new device started checking in after these devices stopped:\n\n" +
                            entry.getValue() + "\nWas the old phone reset? Retire it.\n\n" +
                            "Log in to https://" + AttestationServer.DOMAIN + "/ and select Retire on the old device. " +
                            "Its record and history are kept and it stops raising alerts.\n\n" +
                            "If you do not want to receive these emails and cannot log in to the account,\nemail " +
                            emailFrom + " from the address receiving them.");
                    Transport.send(message);
                } catch (final MessagingException | UnsupportedEncodingException e) {
                    logger.log(Level.WARNING, "email error", e);
                }
            }
        }

        for (final byte[] fingerprint : fingerprints) {
            try {
                updateRetireSuggested.bind(1, now);
                updateRetireSuggested.bind(2, fingerprint);
                updateRetireSuggested.step();
            } finally {
                updateRetireSuggested.reset();
            }
        }
    }

    @Override
    public void run() {
        final SQLiteConnection conn;
        try {
            conn = AttestationServer.open(AttestationServer.ATTESTATION_DATABASE);
        } catch (final SQLiteException e) {
            logger.log(CRIT, "database error, cannot set up AlertDispatcher thread", e);
            return;
        }
        final SQLiteStatement selectConfiguration;
        final SQLiteStatement selectAccountsForExpiryAlert;
        final SQLiteStatement selectExpired;
        final SQLiteStatement updateExpired;
        final SQLiteStatement selectFailed;
        final SQLiteStatement selectAccountsForFailureAlert;
        final SQLiteStatement updateFailureAlert;
        final SQLiteStatement selectPendingNotices;
        final SQLiteStatement updatePendingNotice;
        final SQLiteStatement selectRetireSuggestions;
        final SQLiteStatement updateRetireSuggested;
        final SQLiteStatement selectEmails;
        try {
            selectConfiguration = conn.prepare("""
                    SELECT
                    (SELECT value FROM Configuration WHERE key = 'emailLocal'),
                    (SELECT value FROM Configuration WHERE key = 'emailUsername'),
                    (SELECT value FROM Configuration WHERE key = 'emailPassword'),
                    (SELECT value FROM Configuration WHERE key = 'emailHost'),
                    (SELECT value FROM Configuration WHERE key = 'emailPort'),
                    (SELECT value FROM Configuration WHERE key = 'emailFrom')""");
            selectAccountsForExpiryAlert = conn.prepare("""
                    SELECT userId, username, alertDelay FROM Accounts
                    WHERE (SELECT 1 FROM Devices WHERE userId = Accounts.userID
                        AND verifiedTimeLast < ? - alertDelay * 1000 AND deletionTime is NULL
                        AND retiredTime IS NULL AND pending = 0
                        AND (expiredTimeLast IS NULL OR expiredTimeLast < ?))""");
            selectExpired = conn.prepare("""
                    SELECT fingerprint, trustProfile FROM Devices
                    WHERE userId = ? AND verifiedTimeLast < ? AND deletionTime IS NULL
                    AND retiredTime IS NULL AND pending = 0""");
            updateExpired = conn.prepare(
                    "UPDATE Devices SET expiredTimeLast = ? WHERE fingerprint = ?");
            selectFailed = conn.prepare("""
                    SELECT fingerprint, trustProfile, failureReason FROM Devices
                    WHERE userId = ? AND failureTimeLast > coalesce(failureAlertTime, 0)
                    AND trustProfile = 2 AND deletionTime IS NULL AND retiredTime IS NULL AND pending = 0""");
            // Only profile 2 devices record failures, so profile 1 alerting is unchanged.
            selectAccountsForFailureAlert = conn.prepare("""
                    SELECT userId, username, alertDelay FROM Accounts
                    WHERE EXISTS (SELECT 1 FROM Devices WHERE userId = Accounts.userId
                        AND failureTimeLast > coalesce(failureAlertTime, 0) AND trustProfile = 2
                        AND deletionTime IS NULL AND retiredTime IS NULL AND pending = 0)""");
            updateFailureAlert = conn.prepare(
                    "UPDATE Devices SET failureAlertTime = ? WHERE userId = ? AND trustProfile = 2");
            selectPendingNotices = conn.prepare("""
                    SELECT Devices.userId, username, fingerprint, hex(verifiedBootHash), pinnedOsVersion,
                        pinnedOsPatchLevel, pinnedVendorPatchLevel, pinnedBootPatchLevel, verifiedTimeFirst,
                        reviewFlags
                    FROM Devices INNER JOIN Accounts ON Accounts.userId = Devices.userId
                    WHERE pending = 1 AND pendingNoticeTime IS NULL AND deletionTime IS NULL""");
            updatePendingNotice = conn.prepare(
                    "UPDATE Devices SET pendingNoticeTime = ? WHERE fingerprint = ?");
            selectRetireSuggestions = conn.prepare("""
                    SELECT Devices.userId, username, fingerprint, trustProfile FROM Devices
                    INNER JOIN Accounts ON Accounts.userId = Devices.userId
                    WHERE retireSuggestedTime IS NULL AND\s""" + AttestationServer.RETIRE_SUGGESTED);
            updateRetireSuggested = conn.prepare(
                    "UPDATE Devices SET retireSuggestedTime = ? WHERE fingerprint = ?");
            selectEmails = conn.prepare("SELECT address FROM EmailAddresses WHERE userId = ?");
        } catch (final SQLiteException e) {
            conn.dispose();
            logger.log(CRIT, "database error, cannot set up AlertDispatcher thread", e);
            return;
        }

        while (true) {
            try {
                Thread.sleep(WAIT_MS);
            } catch (final InterruptedException e) {
                return;
            }

            logger.info("dispatching alerts");

            try {
                final int emailLocal;
                final String emailUsername;
                final String emailPassword;
                final String emailHost;
                final String emailPort;
                final String emailFrom;
                try {
                    selectConfiguration.step();
                    emailLocal = selectConfiguration.columnInt(0);
                    emailUsername = selectConfiguration.columnString(1);
                    emailPassword = selectConfiguration.columnString(2);
                    emailHost = selectConfiguration.columnString(3);
                    emailPort = selectConfiguration.columnString(4);
                    emailFrom = selectConfiguration.columnString(5);
                } finally {
                    selectConfiguration.reset();
                }

                final Session session;
                if (emailLocal == 1) {
                    if (emailFrom == null) {
                        logger.warning("missing configuration for sending alert emails");
                        continue;
                    }
                    final Properties props = new Properties();
                    props.put("mail.from", emailFrom);
                    props.put("mail.smtp.connectiontimeout", Integer.toString(TIMEOUT_MS));
                    props.put("mail.smtp.timeout", Integer.toString(TIMEOUT_MS));
                    props.put("mail.smtp.writetimeout", Integer.toString(TIMEOUT_MS));
                    session = Session.getInstance(props);
                } else {
                    if (emailUsername == null || emailPassword == null || emailHost == null || emailPort == null || emailFrom == null) {
                        logger.warning("missing configuration for sending alert emails");
                        continue;
                    }

                    final Properties props = new Properties();
                    props.put("mail.from", emailFrom);
                    props.put("mail.transport.protocol.rfc822", "smtps");
                    props.put("mail.smtps.auth", true);
                    props.put("mail.smtps.host", emailHost);
                    props.put("mail.smtps.port", emailPort);
                    props.put("mail.smtps.ssl.checkserveridentity", true);
                    props.put("mail.smtps.ssl.protocols", "TLSv1.3");
                    props.put("mail.smtps.connectiontimeout", Integer.toString(TIMEOUT_MS));
                    props.put("mail.smtps.timeout", Integer.toString(TIMEOUT_MS));
                    props.put("mail.smtps.writetimeout", Integer.toString(TIMEOUT_MS));

                    session = Session.getInstance(props,
                            new jakarta.mail.Authenticator() {
                                protected PasswordAuthentication getPasswordAuthentication() {
                                    return new PasswordAuthentication(emailUsername, emailPassword);
                                }
                            });
                }

                final ArrayList<Account> accountsForExpiryAlert = new ArrayList<>();
                final long now = System.currentTimeMillis();
                try {
                    selectAccountsForExpiryAlert.bind(1, now);
                    selectAccountsForExpiryAlert.bind(2, now - ALERT_THROTTLE_MS);
                    while (selectAccountsForExpiryAlert.step()) {
                        accountsForExpiryAlert.add(new Account(
                                selectAccountsForExpiryAlert.columnLong(0),
                                selectAccountsForExpiryAlert.columnString(1),
                                selectAccountsForExpiryAlert.columnInt(2)));
                    }
                } finally {
                    selectAccountsForExpiryAlert.reset();
                }

                for (final Account account : accountsForExpiryAlert) {
                    final ArrayList<byte[]> expiredFingerprints = new ArrayList<>();
                    final StringBuilder expired = new StringBuilder();
                    try {
                        selectExpired.bind(1, account.userId);
                        selectExpired.bind(2, now - account.alertDelay * 1000);
                        while (selectExpired.step()) {
                            final byte[] fingerprint = selectExpired.columnBlob(0);
                            expiredFingerprints.add(fingerprint);
                            appendFingerprint(expired, fingerprint, selectExpired.columnInt(1));
                        }
                    } finally {
                        selectExpired.reset();
                    }

                    if (expiredFingerprints.isEmpty()) {
                        continue;
                    }

                    final ArrayList<String> addresses = new ArrayList<>();
                    try {
                        selectEmails.bind(1, account.userId);
                        while (selectEmails.step()) {
                            addresses.add(selectEmails.columnString(0));
                        }
                    } finally {
                        selectEmails.reset();
                    }

                    for (final String address : addresses) {
                        logger.info("sending expiry email to " + address + " for account " + account.userId);
                        try {
                            final Message message = new MimeMessage(session);
                            message.setFrom(new InternetAddress(emailFrom, EMAIL_DISPLAY_NAME));
                            message.setRecipients(Message.RecipientType.TO,
                                    InternetAddress.parse(address));
                            message.setSubject(
                                    "Devices failed to provide valid attestations within " +
                                    account.alertDelay / 60 / 60 + " hours");
                            message.setText("This is an alert for the account '" + account.username + "'.\n\n" +
                                    "The following devices have failed to provide valid attestations before the expiry time:\n\n" +
                                    expired + "\nLog in to https://" + AttestationServer.DOMAIN + "/ for more information.\n\n" +
                                    "If you do not want to receive these alerts and cannot log in to the account,\nemail " + emailFrom + " from the address receiving the alerts.");

                            Transport.send(message);

                            for (final byte[] fingerprint : expiredFingerprints) {
                                try {
                                    updateExpired.bind(1, now);
                                    updateExpired.bind(2, fingerprint);
                                    updateExpired.step();
                                } finally {
                                    updateExpired.reset();
                                }
                            }
                        } catch (final MessagingException | UnsupportedEncodingException e) {
                            logger.log(Level.WARNING, "email error", e);
                        }
                    }
                }

                final ArrayList<Account> accountsForFailureAlert = new ArrayList<>();
                try {
                    while (selectAccountsForFailureAlert.step()) {
                        accountsForFailureAlert.add(new Account(
                                selectAccountsForFailureAlert.columnLong(0),
                                selectAccountsForFailureAlert.columnString(1),
                                selectAccountsForFailureAlert.columnInt(2)));
                    }
                } finally {
                    selectAccountsForFailureAlert.reset();
                }

                for (final Account account : accountsForFailureAlert) {
                    final StringBuilder failed = new StringBuilder();
                    try {
                        selectFailed.bind(1, account.userId);
                        while (selectFailed.step()) {
                            appendFingerprint(failed, selectFailed.columnBlob(0), selectFailed.columnInt(1));
                            if (!selectFailed.columnNull(2)) {
                                failed.append("  ").append(selectFailed.columnString(2)).append("\n");
                            }
                        }
                    } finally {
                        selectFailed.reset();
                    }

                    if (failed.length() == 0) {
                        continue;
                    }

                    final ArrayList<String> addresses = new ArrayList<>();
                    try {
                        selectEmails.bind(1, account.userId);
                        while (selectEmails.step()) {
                            addresses.add(selectEmails.columnString(0));
                        }
                    } finally {
                        selectEmails.reset();
                    }

                    for (final String address : addresses) {
                        logger.info("sending failure email to " + address + " for account " + account.userId);
                        try {
                            final Message message = new MimeMessage(session);
                            message.setFrom(new InternetAddress(emailFrom, EMAIL_DISPLAY_NAME));
                            message.setRecipients(Message.RecipientType.TO,
                                    InternetAddress.parse(address));
                            message.setSubject("Devices provided invalid attestations");
                            message.setText("This is an alert for the account '" + account.username + "'.\n\n" +
                                    "The following devices have provided invalid attestations:\n\n" +
                                    failed + "\nLog in to https://" + AttestationServer.DOMAIN + "/ for more information.\n\n" +
                                    "If you do not want to receive these alerts and cannot log in to the account,\nemail " + emailFrom + " from the address receiving the alerts");

                            Transport.send(message);
                        } catch (final MessagingException | UnsupportedEncodingException e) {
                            logger.log(Level.WARNING, "email error", e);
                        }
                    }

                    try {
                        updateFailureAlert.bind(1, now);
                        updateFailureAlert.bind(2, account.userId);
                        updateFailureAlert.step();
                    } finally {
                        updateFailureAlert.reset();
                    }
                }

                sendPendingNotices(session, emailFrom, now, selectPendingNotices, updatePendingNotice,
                        selectEmails);
                sendRetireSuggestions(session, emailFrom, now, selectRetireSuggestions,
                        updateRetireSuggested, selectEmails);
            } catch (final SQLiteException e) {
                logger.log(Level.WARNING, "database error", e);
            }

            logger.info("dispatching alerts completed");
        }
    }
}
