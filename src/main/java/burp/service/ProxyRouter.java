package burp.service;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Locale;

/**
 * Single entry point for all outbound HTTP traffic from BurpMan.
 *
 * <p>When {@link ProxySettings#isEnabled()} is false, delegates to
 * {@code api.http().sendRequest(req)} — the default Montoya path that
 * bypasses Burp's Proxy tool.
 *
 * <p>When enabled, opens a raw socket to the configured upstream proxy
 * (typically Burp's own {@code 127.0.0.1:8080} listener). For HTTPS
 * targets, sends a {@code CONNECT} tunnel first, then wraps the socket
 * with SSL and forwards the request. For plain HTTP, uses the
 * absolute-URI request line form so the proxy can forward it directly.
 *
 * <p>The upshot: traffic passes <b>through</b> Burp Proxy, so it appears
 * in <b>Proxy → HTTP history</b> (in addition to Logger).
 */
public final class ProxyRouter {

    private static final int CONNECT_TIMEOUT_MS = 30_000;
    private static final int READ_TIMEOUT_MS    = 60_000;

    private ProxyRouter() {}

    /**
     * Send {@code req} either directly (proxy disabled) or through the
     * configured upstream proxy. On proxy failure, falls back to direct
     * so runs don't hard-fail — a warning is written to the log sink.
     */
    public static HttpRequestResponse sendRequest(MontoyaApi api, HttpRequest req) {
        ProxySettings ps = ProxySettings.get();
        HttpService svc = req == null ? null : req.httpService();
        if (svc == null || !ps.isEnabled() || ps.shouldBypass(svc.host())) {
            return api.http().sendRequest(req);
        }
        try {
            HttpRequestResponse rr = sendViaProxy(req, ps);
            if (isLoopbackError(rr)) {
                logLoopbackHelp(api, ps);
                return api.http().sendRequest(req);
            }
            return rr;
        } catch (Throwable t) {
            try {
                api.logging().logToError("BurpMan proxy route failed ("
                    + ps.getHost() + ":" + ps.getPort() + "): "
                    + t.getClass().getSimpleName() + ": " + t.getMessage()
                    + " — falling back to direct send");
            } catch (Throwable ignore) {}
            return api.http().sendRequest(req);
        }
    }

    /**
     * Burp returns an HTML error page (not the real target's response) when
     * it detects a request looping back to one of its own Proxy listeners
     * from within the same JVM process. Body contains a distinctive phrase
     * we can match on.
     */
    private static boolean isLoopbackError(HttpRequestResponse rr) {
        try {
            if (rr == null || rr.response() == null) return false;
            String body = rr.response().bodyToString();
            if (body == null) return false;
            return body.contains("looping back to same Proxy listener")
                || body.contains("looping back to the same proxy listener");
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean loopbackHelpLogged = false;
    private static synchronized void logLoopbackHelp(MontoyaApi api, ProxySettings ps) {
        try {
            String msg = "⚠ BurpMan → Burp Proxy loop detected at "
                + ps.getHost() + ":" + ps.getPort()
                + ". Burp dropped the request because it originated from the same "
                + "Burp process. FIX (one-time): Burp → Settings → Tools → Proxy → "
                + "Miscellaneous → uncheck \"Drop requests that appear to be looping "
                + "back to the same Proxy listener\". Falling back to direct send for "
                + "this request.";
            if (!loopbackHelpLogged) {
                api.logging().logToError(msg);
                loopbackHelpLogged = true;
            } else {
                api.logging().logToOutput("↩ Proxy loop-drop again — see earlier "
                    + "error for the Burp setting to uncheck.");
            }
        } catch (Throwable ignore) {}
    }

    private static HttpRequestResponse sendViaProxy(HttpRequest req, ProxySettings ps) throws IOException {
        HttpService svc = req.httpService();
        String targetHost = svc.host();
        int    targetPort = svc.port();
        boolean secure    = svc.secure();

        Socket sock = new Socket();
        sock.connect(new InetSocketAddress(ps.getHost(), ps.getPort()), CONNECT_TIMEOUT_MS);
        sock.setSoTimeout(READ_TIMEOUT_MS);

        try {
            if (secure) {
                // CONNECT tunnel — Burp Proxy will log this as an HTTPS
                // entry and forward the tunneled bytes to the target.
                String connect = "CONNECT " + targetHost + ":" + targetPort + " HTTP/1.1\r\n"
                               + "Host: " + targetHost + ":" + targetPort + "\r\n"
                               + "Proxy-Connection: keep-alive\r\n\r\n";
                OutputStream out = sock.getOutputStream();
                out.write(connect.getBytes(StandardCharsets.US_ASCII));
                out.flush();

                String connectResp = readHeadersUntilBlankLine(sock.getInputStream());
                String status = firstLine(connectResp);
                if (status == null || (!status.contains(" 200") && !status.contains(" 200 "))) {
                    throw new IOException("Upstream proxy refused CONNECT: " + status);
                }

                SSLSocketFactory factory = sslFactory(ps.isTrustAllCerts());
                SSLSocket sslSock = (SSLSocket) factory.createSocket(
                        sock, targetHost, targetPort, true);
                if (ps.isTrustAllCerts()) {
                    // Disable hostname verification when trust-all is on.
                    // OK for testing/local Burp; users can turn it off in
                    // the settings dialog if they need strict validation.
                    sslSock.setUseClientMode(true);
                }
                sslSock.startHandshake();
                sock = sslSock;

                // For HTTPS the request line stays origin-form ("/path")
                // — same as direct, since we're now inside the tunnel.
                byte[] reqBytes = normalizeRequest(req, false);
                sock.getOutputStream().write(reqBytes);
                sock.getOutputStream().flush();
            } else {
                // Plain HTTP through the proxy — request line must be
                // absolute-form: "GET http://host/path HTTP/1.1".
                byte[] reqBytes = normalizeRequest(req, true);
                sock.getOutputStream().write(reqBytes);
                sock.getOutputStream().flush();
            }

            byte[] respBytes = readFullResponse(sock.getInputStream());
            HttpResponse resp = HttpResponse.httpResponse(ByteArray.byteArray(respBytes));
            return HttpRequestResponse.httpRequestResponse(req, resp);
        } finally {
            try { sock.close(); } catch (Throwable ignore) {}
        }
    }

    /**
     * Serialize {@code req} for wire transmission.
     *
     * <p>Downgrades any HTTP/2 or unusual version marker to HTTP/1.1
     * because raw sockets can't speak HTTP/2. When {@code absoluteUri}
     * is true, rewrites the request-line target to include the full
     * scheme + host (required when talking to an HTTP proxy in
     * non-tunneled mode).
     */
    private static byte[] normalizeRequest(HttpRequest req, boolean absoluteUri) {
        byte[] raw = req.toByteArray().getBytes();
        int lineEnd = indexOfCrlf(raw, 0);
        if (lineEnd < 0) return raw;
        String requestLine = new String(raw, 0, lineEnd, StandardCharsets.ISO_8859_1);
        String[] parts = requestLine.split(" ", 3);
        if (parts.length != 3) return raw;

        String method  = parts[0];
        String target  = parts[1];
        String version = "HTTP/1.1";

        if (absoluteUri && !target.toLowerCase(Locale.ROOT).startsWith("http")) {
            HttpService svc = req.httpService();
            String scheme = svc.secure() ? "https" : "http";
            String hostPart = svc.host();
            int p = svc.port();
            boolean defaultPort = (svc.secure() && p == 443) || (!svc.secure() && p == 80);
            if (!defaultPort) hostPart = hostPart + ":" + p;
            target = scheme + "://" + hostPart + target;
        }

        String newLine = method + " " + target + " " + version;
        byte[] newLineBytes = newLine.getBytes(StandardCharsets.ISO_8859_1);
        byte[] rest = new byte[raw.length - lineEnd];
        System.arraycopy(raw, lineEnd, rest, 0, rest.length);
        byte[] out = new byte[newLineBytes.length + rest.length];
        System.arraycopy(newLineBytes, 0, out, 0, newLineBytes.length);
        System.arraycopy(rest, 0, out, newLineBytes.length, rest.length);
        return out;
    }

    /** Read from stream until first {@code \r\n\r\n} — used for CONNECT reply. */
    private static String readHeadersUntilBlankLine(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int state = 0; // 0=start, 1=\r, 2=\r\n, 3=\r\n\r
        while (true) {
            int b = in.read();
            if (b < 0) break;
            buf.write(b);
            if (b == '\r' && state == 0) state = 1;
            else if (b == '\n' && state == 1) state = 2;
            else if (b == '\r' && state == 2) state = 3;
            else if (b == '\n' && state == 3) break;
            else state = 0;
            if (buf.size() > 16384) throw new IOException("CONNECT response too large");
        }
        return buf.toString(StandardCharsets.ISO_8859_1);
    }

    /** Best-effort full HTTP/1.1 response reader (Content-Length + chunked). */
    private static byte[] readFullResponse(InputStream in) throws IOException {
        String headers = readHeadersUntilBlankLine(in);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(headers.getBytes(StandardCharsets.ISO_8859_1));

        String lower = headers.toLowerCase(Locale.ROOT);
        int cl = -1;
        for (String line : lower.split("\r\n")) {
            if (line.startsWith("content-length:")) {
                try { cl = Integer.parseInt(line.substring("content-length:".length()).trim()); }
                catch (Exception ignore) {}
                break;
            }
        }
        boolean chunked = lower.contains("transfer-encoding:")
            && lower.contains("chunked");

        if (chunked) {
            readChunked(in, out);
        } else if (cl > 0) {
            byte[] buf = new byte[8192];
            int remaining = cl;
            while (remaining > 0) {
                int n = in.read(buf, 0, Math.min(buf.length, remaining));
                if (n < 0) break;
                out.write(buf, 0, n);
                remaining -= n;
            }
        } else if (cl == 0) {
            // no body
        } else {
            // Read until EOF (Connection: close semantics)
            byte[] buf = new byte[8192];
            int n;
            try {
                while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            } catch (IOException ignore) {
                // socket may close abruptly on some servers — that's fine
            }
        }
        return out.toByteArray();
    }

    private static void readChunked(InputStream in, ByteArrayOutputStream out) throws IOException {
        while (true) {
            String sizeLine = readLine(in);
            if (sizeLine == null) break;
            out.write(sizeLine.getBytes(StandardCharsets.ISO_8859_1));
            out.write('\r'); out.write('\n');
            int semi = sizeLine.indexOf(';');
            String hex = (semi < 0 ? sizeLine : sizeLine.substring(0, semi)).trim();
            if (hex.isEmpty()) break;
            int size;
            try { size = Integer.parseInt(hex, 16); }
            catch (NumberFormatException e) { throw new IOException("Bad chunk size: " + hex); }
            if (size == 0) {
                // Read trailing headers up to blank line
                String tail = readHeadersUntilBlankLine(in);
                out.write(tail.getBytes(StandardCharsets.ISO_8859_1));
                return;
            }
            byte[] chunk = new byte[size];
            int read = 0;
            while (read < size) {
                int n = in.read(chunk, read, size - read);
                if (n < 0) throw new IOException("Truncated chunk body");
                read += n;
            }
            out.write(chunk);
            // Chunk terminator \r\n
            int c1 = in.read(); int c2 = in.read();
            if (c1 == '\r' && c2 == '\n') { out.write('\r'); out.write('\n'); }
        }
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int prev = -1, b;
        while ((b = in.read()) >= 0) {
            if (prev == '\r' && b == '\n') {
                byte[] arr = buf.toByteArray();
                return new String(arr, 0, arr.length - 1, StandardCharsets.ISO_8859_1);
            }
            buf.write(b);
            prev = b;
            if (buf.size() > 65536) throw new IOException("Line too long");
        }
        return buf.size() == 0 ? null : buf.toString(StandardCharsets.ISO_8859_1);
    }

    private static int indexOfCrlf(byte[] arr, int from) {
        for (int i = from; i + 1 < arr.length; i++) {
            if (arr[i] == '\r' && arr[i + 1] == '\n') return i;
        }
        return -1;
    }

    private static String firstLine(String s) {
        if (s == null) return null;
        int e = s.indexOf('\r');
        if (e < 0) e = s.indexOf('\n');
        return e < 0 ? s.trim() : s.substring(0, e).trim();
    }

    private static SSLSocketFactory sslFactory(boolean trustAll) throws IOException {
        try {
            if (!trustAll) return (SSLSocketFactory) SSLSocketFactory.getDefault();
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] xcs, String s) {}
                    public void checkServerTrusted(X509Certificate[] xcs, String s) {}
                }
            };
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, trustAllCerts, new java.security.SecureRandom());
            return ctx.getSocketFactory();
        } catch (Exception e) {
            throw new IOException("SSL init failed: " + e.getMessage(), e);
        }
    }

    /**
     * Best-effort quick TCP reachability check. Returns null on success
     * or an error message on failure. Used by the settings dialog's
     * "Test connection" button.
     */
    public static String testConnection(String host, int port) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), 5000);
            return null;
        } catch (Throwable t) {
            return t.getClass().getSimpleName() + ": " + t.getMessage();
        }
    }
}
