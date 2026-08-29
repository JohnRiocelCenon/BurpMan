package burp.auth;

import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

final class OAuthBrowserCallbackServer {
   private OAuthBrowserCallbackServer() {
   }

   static boolean canAutoCapture(String callbackUrl) {
      URI cb = parseUri(callbackUrl);
      if (cb == null) return false;
      String scheme = cb.getScheme();
      if (scheme == null || !"http".equalsIgnoreCase(scheme)) return false;
      return isLocalhost(cb.getHost());
   }

   static String openBrowserAndAwaitCode(String authUrl, String callbackUrl, int timeoutSeconds) throws Exception {
      URI cb = parseUri(callbackUrl);
      if (cb == null || !canAutoCapture(callbackUrl)) return null;

      int port = cb.getPort() > 0 ? cb.getPort() : 80;
      String host = cb.getHost();
      String path = cb.getPath();
      if (path == null || path.trim().isEmpty()) path = "/";

      CountDownLatch latch = new CountDownLatch(1);
      AtomicReference<String> codeRef = new AtomicReference<>();
      AtomicReference<String> errRef = new AtomicReference<>();

      HttpServer server = HttpServer.create(new InetSocketAddress(host, port), 0);
      String contextPath = path;
      server.createContext(contextPath, exchange -> {
         try {
            String query = exchange.getRequestURI() == null ? null : exchange.getRequestURI().getRawQuery();
            String code = extractQueryParam(query, "code");
            String error = extractQueryParam(query, "error");
            String errorDesc = extractQueryParam(query, "error_description");
            if (code != null && !code.isEmpty()) {
               codeRef.set(urlDecode(code));
            } else if (error != null && !error.isEmpty()) {
               String msg = urlDecode(error);
               if (errorDesc != null && !errorDesc.isEmpty()) {
                  msg += ": " + urlDecode(errorDesc);
               }
               errRef.set(msg);
            }

            String html = codeRef.get() != null
               ? "<html><body><h3>Authorization received.</h3><p>You can return to BurpMan.</p></body></html>"
               : "<html><body><h3>Authorization response received.</h3><p>Return to BurpMan.</p></body></html>";
            byte[] body = html.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
               os.write(body);
            }
         } finally {
            latch.countDown();
         }
      });

      server.start();
      try {
         BrowserLauncher.open(authUrl);
         boolean received = latch.await(Math.max(10, timeoutSeconds), TimeUnit.SECONDS);
         if (!received) return null;
         if (errRef.get() != null && !errRef.get().isEmpty()) {
            throw new IllegalStateException("OAuth callback error: " + errRef.get());
         }
         return codeRef.get();
      } finally {
         server.stop(0);
      }
   }

   private static URI parseUri(String value) {
      if (value == null || value.trim().isEmpty()) return null;
      try {
         return URI.create(value.trim());
      } catch (Exception ex) {
         return null;
      }
   }

   private static boolean isLocalhost(String host) {
      if (host == null) return false;
      String h = host.trim().toLowerCase();
      return "localhost".equals(h) || "127.0.0.1".equals(h) || "::1".equals(h) || "[::1]".equals(h);
   }

   private static String extractQueryParam(String query, String key) {
      if (query == null || query.isEmpty() || key == null || key.isEmpty()) return null;
      for (String pair : query.split("&")) {
         int eq = pair.indexOf('=');
         String k = eq >= 0 ? pair.substring(0, eq) : pair;
         if (!key.equalsIgnoreCase(k)) continue;
         return eq >= 0 ? pair.substring(eq + 1) : "";
      }
      return null;
   }

   private static String urlDecode(String s) {
      if (s == null) return null;
      return URLDecoder.decode(s, StandardCharsets.UTF_8);
   }
}
