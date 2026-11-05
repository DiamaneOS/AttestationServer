package app.attestation.server;

import com.sun.net.httpserver.Authenticator;
import com.sun.net.httpserver.Filter;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpPrincipal;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

// An exchange handed straight to a handler, without a socket.
final class FakeExchange extends HttpExchange {
    private final Headers requestHeaders = new Headers();
    private final Headers responseHeaders = new Headers();
    private final String method;
    private final URI uri;
    private final String contextPath;
    private final InputStream body;
    final ByteArrayOutputStream response = new ByteArrayOutputStream();
    int status = -1;
    int sent;

    FakeExchange(final String method, final String contextPath, final URI uri, final byte[] body) {
        this.method = method;
        this.contextPath = contextPath;
        this.uri = uri;
        this.body = new ByteArrayInputStream(body);
    }

    // A value the server's HTTP parser would refuse never reaches a handler, so it is left out.
    void header(final String name, final String value) {
        try {
            requestHeaders.add(name, value);
        } catch (final IllegalArgumentException e) {
            // not a valid header value
        }
    }

    @Override
    public Headers getRequestHeaders() {
        return requestHeaders;
    }

    @Override
    public Headers getResponseHeaders() {
        return responseHeaders;
    }

    @Override
    public URI getRequestURI() {
        return uri;
    }

    @Override
    public String getRequestMethod() {
        return method;
    }

    @Override
    public HttpContext getHttpContext() {
        return new HttpContext() {
            @Override
            public HttpHandler getHandler() {
                return null;
            }

            @Override
            public void setHandler(final HttpHandler handler) {}

            @Override
            public String getPath() {
                return contextPath;
            }

            @Override
            public HttpServer getServer() {
                return null;
            }

            @Override
            public Map<String, Object> getAttributes() {
                return new HashMap<>();
            }

            @Override
            public List<Filter> getFilters() {
                return List.of();
            }

            @Override
            public Authenticator setAuthenticator(final Authenticator auth) {
                return null;
            }

            @Override
            public Authenticator getAuthenticator() {
                return null;
            }
        };
    }

    @Override
    public void close() {}

    @Override
    public InputStream getRequestBody() {
        return body;
    }

    @Override
    public OutputStream getResponseBody() {
        return response;
    }

    // Like the real server, a second status line for one exchange is an error.
    @Override
    public void sendResponseHeaders(final int code, final long length) throws java.io.IOException {
        if (sent++ > 0) {
            throw new java.io.IOException("headers already sent");
        }
        status = code;
    }

    @Override
    public InetSocketAddress getRemoteAddress() {
        return new InetSocketAddress("127.0.0.1", 40000);
    }

    @Override
    public int getResponseCode() {
        return status;
    }

    @Override
    public InetSocketAddress getLocalAddress() {
        return new InetSocketAddress("127.0.0.1", 8080);
    }

    @Override
    public String getProtocol() {
        return "HTTP/1.1";
    }

    @Override
    public Object getAttribute(final String name) {
        return null;
    }

    @Override
    public void setAttribute(final String name, final Object value) {}

    @Override
    public void setStreams(final InputStream i, final OutputStream o) {}

    @Override
    public HttpPrincipal getPrincipal() {
        return null;
    }
}
