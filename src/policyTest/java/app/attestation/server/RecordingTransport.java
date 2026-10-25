package app.attestation.server;

import jakarta.mail.Address;
import jakarta.mail.Message;
import jakarta.mail.Provider;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.URLName;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

// Keeps sent alert emails in memory instead of sending them.
public final class RecordingTransport extends Transport {
    static final List<Message> sent = new ArrayList<>();

    public RecordingTransport(final Session session, final URLName name) {
        super(session, name);
    }

    static Session session() {
        final Properties props = new Properties();
        props.put("mail.transport.protocol.rfc822", "recording");
        final Session session = Session.getInstance(props);
        session.addProvider(new Provider(Provider.Type.TRANSPORT, "recording",
                RecordingTransport.class.getName(), "DiamaneOS tests", "1"));
        return session;
    }

    @Override
    protected boolean protocolConnect(final String host, final int port, final String user,
            final String password) {
        return true;
    }

    @Override
    public void sendMessage(final Message message, final Address[] addresses) {
        sent.add(message);
    }
}
