package burp.auth;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;

/**
 * Drives an OAuth sign-in inside a dedicated Chromium window and reads the authorization
 * response straight out of the browser, the way Bruno's embedded browser does.
 *
 * <p>Chromium is started in {@code --app} mode against a throwaway profile with the DevTools
 * protocol enabled. Polling {@code /json/list} reports the URL of every open tab, so the
 * redirect to the callback is observed as soon as the browser attempts it. Nothing has to be
 * proxied, the callback host never has to be reachable, and the callback does not have to point
 * at localhost.
 *
 * <p>Chromium routinely hands a launch off to an already running instance and lets the process
 * we started exit, so neither that process nor the {@code DevToolsActivePort} file is treated as
 * a reliable signal. The debugging port is chosen up front and probed directly instead.
 */
public final class ChromiumOAuthBrowser {

   private ChromiumOAuthBrowser() {
   }

   /** Overrides browser discovery, e.g. -Dburpman.chromium=C:\path\to\chrome.exe */
   private static final String PROPERTY_OVERRIDE = "burpman.chromium";
   private static final String ENV_OVERRIDE = "BURPMAN_CHROMIUM";

   private static final int POLL_INTERVAL_MILLIS = 250;
   private static final int DEVTOOLS_WAIT_MILLIS = 30000;
   /** How long the debugging endpoint may stay unreachable before we call the window closed. */
   private static final int LOST_CONTACT_GRACE_MILLIS = 8000;

   public static final class CaptureResult {
      public final OAuthCallbackParser.Result response;
      public final String failureReason;

      private CaptureResult(OAuthCallbackParser.Result response, String failureReason) {
         this.response = response;
         this.failureReason = failureReason;
      }

      static CaptureResult ok(OAuthCallbackParser.Result response) {
         return new CaptureResult(response, null);
      }

      static CaptureResult failed(String reason) {
         return new CaptureResult(null, reason);
      }

      public boolean succeeded() {
         return this.response != null;
      }
   }

   private static final class Target {
      final String id;
      final String url;

      Target(String id, String url) {
         this.id = id;
         this.url = url;
      }
   }

   public static boolean isAvailable() {
      return findChromiumExecutable() != null;
   }

   /**
    * Locates a Chromium build we can drive. Burp's own bundled browser is preferred because it
    * is the one the user already trusts for this kind of work; otherwise any installed
    * Chromium-family browser will do.
    */
   public static File findChromiumExecutable() {
      String override = System.getProperty(PROPERTY_OVERRIDE);
      if (override == null || override.trim().isEmpty()) {
         override = System.getenv(ENV_OVERRIDE);
      }
      if (override != null && !override.trim().isEmpty()) {
         File f = new File(override.trim());
         if (f.isFile() && f.canExecute()) return f;
      }

      File bundled = findBurpBundledBrowser();
      if (bundled != null) return bundled;

      for (String candidate : systemBrowserCandidates()) {
         File f = new File(candidate);
         if (f.isFile() && f.canExecute()) return f;
      }
      return findOnPath();
   }

   /** Burp downloads its embedded Chromium under the user's Burp config directory. */
   private static File findBurpBundledBrowser() {
      List<File> roots = new ArrayList<>();
      String appData = System.getenv("APPDATA");
      String home = System.getProperty("user.home", "");
      if (appData != null && !appData.trim().isEmpty()) {
         roots.add(new File(appData, "BurpSuite" + File.separator + "burpbrowser"));
      }
      if (!home.isEmpty()) {
         roots.add(new File(home, ".BurpSuite" + File.separator + "burpbrowser"));
         roots.add(new File(home, "BurpSuite" + File.separator + "burpbrowser"));
      }

      String[] relative = {
         "chrome.exe",
         "chrome",
         "Chromium.app/Contents/MacOS/Chromium",
         "Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
      };

      for (File root : roots) {
         File[] versions = root.listFiles(File::isDirectory);
         if (versions == null || versions.length == 0) continue;
         // Newest install wins; Burp keeps older versions around after an upgrade.
         Arrays.sort(versions, Comparator.comparingLong(File::lastModified).reversed());
         for (File version : versions) {
            for (String rel : relative) {
               File exe = new File(version, rel.replace('/', File.separatorChar));
               if (exe.isFile()) return exe;
            }
         }
      }
      return null;
   }

   private static List<String> systemBrowserCandidates() {
      String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
      List<String> out = new ArrayList<>();
      if (os.contains("win")) {
         String pf = System.getenv("ProgramFiles");
         String pf86 = System.getenv("ProgramFiles(x86)");
         String local = System.getenv("LOCALAPPDATA");
         String[] suffixes = {
            "Google\\Chrome\\Application\\chrome.exe",
            "Microsoft\\Edge\\Application\\msedge.exe",
            "BraveSoftware\\Brave-Browser\\Application\\brave.exe",
            "Chromium\\Application\\chrome.exe"
         };
         for (String base : new String[]{pf, pf86, local}) {
            if (base == null || base.trim().isEmpty()) continue;
            for (String suffix : suffixes) {
               out.add(base + File.separator + suffix);
            }
         }
      } else if (os.contains("mac")) {
         out.add("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
         out.add("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge");
         out.add("/Applications/Brave Browser.app/Contents/MacOS/Brave Browser");
         out.add("/Applications/Chromium.app/Contents/MacOS/Chromium");
      } else {
         out.add("/usr/bin/google-chrome");
         out.add("/usr/bin/google-chrome-stable");
         out.add("/usr/bin/chromium");
         out.add("/usr/bin/chromium-browser");
         out.add("/usr/bin/microsoft-edge");
         out.add("/snap/bin/chromium");
      }
      return out;
   }

   private static File findOnPath() {
      String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
      if (os.contains("win")) return null;
      String path = System.getenv("PATH");
      if (path == null || path.isEmpty()) return null;
      String[] names = {"google-chrome", "chromium", "chromium-browser", "microsoft-edge", "brave-browser"};
      for (String dir : path.split(File.pathSeparator)) {
         for (String name : names) {
            File f = new File(dir, name);
            if (f.isFile() && f.canExecute()) return f;
         }
      }
      return null;
   }

   /**
    * Opens {@code authorizationUrl} in a controlled Chromium window and returns the
    * authorization response once the browser navigates to the callback.
    *
    * @param log optional progress sink; may be null
    */
   public static CaptureResult captureAuthorizationResponse(String authorizationUrl,
                                                            String callbackUrl,
                                                            int timeoutSeconds,
                                                            Consumer<String> log) {
      if (authorizationUrl == null || authorizationUrl.trim().isEmpty()) {
         return CaptureResult.failed("Authorization URL is empty.");
      }
      File chromium = findChromiumExecutable();
      if (chromium == null) {
         return CaptureResult.failed("No Chromium-based browser found.");
      }

      Path profile;
      try {
         profile = Files.createTempDirectory("burpman-oauth-");
      } catch (Exception ex) {
         return CaptureResult.failed("Could not create a temporary browser profile: " + ex.getMessage());
      }

      int debugPort = reserveFreePort();
      if (debugPort <= 0) {
         return CaptureResult.failed("Could not reserve a local debugging port.");
      }

      note(log, "🌐 Opening sign-in window (" + chromium.getName()
         + ", empty profile — none of your browser's cookies, cache or history).");

      Process process = null;
      try {
         ProcessBuilder pb = new ProcessBuilder(
            buildCommand(chromium, authorizationUrl, callbackUrl, profile, debugPort));
         pb.redirectErrorStream(true);
         process = pb.start();
         // An unread pipe fills up and would stall the browser before it ever opens the port.
         drainQuietly(process.getInputStream());

         int port = awaitDebuggingEndpoint(debugPort, profile);
         if (port <= 0) {
            return CaptureResult.failed("The sign-in window did not expose its debugging port,"
               + " so the callback could not be read automatically.");
         }

         return pollForCallback(port, callbackUrl, timeoutSeconds, log);
      } catch (Exception ex) {
         return CaptureResult.failed(ex.getClass().getSimpleName() + ": " + ex.getMessage());
      } finally {
         destroyTree(process);
         sleep(400);
         deleteQuietly(profile.toFile());
      }
   }

   private static List<String> buildCommand(File chromium,
                                            String authorizationUrl,
                                            String callbackUrl,
                                            Path profile,
                                            int debugPort) {
      List<String> command = new ArrayList<>();
      command.add(chromium.getAbsolutePath());
      command.add("--remote-debugging-port=" + debugPort);
      command.add("--user-data-dir=" + profile.toAbsolutePath());
      command.add("--no-first-run");
      command.add("--no-default-browser-check");
      command.add("--disable-sync");
      command.add("--no-service-autorun");
      command.add("--disable-background-networking");
      command.add("--disable-popup-blocking");
      command.add("--window-size=520,760");
      // Edge on a domain-joined machine otherwise offers the Windows account for one-click
      // sign-in, hiding whose identity is being used. These turn off its identity integration
      // so the provider's own credential page is what appears. Chromium honours only the last
      // --disable-features, so every flag has to live in this one switch.
      command.add("--disable-features=msSingleSignOn,AadSso,msImplicitSignin,msEdgeAutoSignIn,"
         + "msAccountProfileSync,msIdentityManager,WebViewWindowsSSO,msWebOAuthTokenBroker");
      command.add("--auth-server-allowlist=_no_integrated_auth_");
      command.add("--auth-negotiate-delegate-allowlist=_none_");
      // Stopping the callback from actually loading keeps its query string on screen. Single
      // page apps routinely read the code and immediately rewrite the URL, which would
      // otherwise erase the only copy of it before we look.
      String blockRule = callbackBlockingRule(authorizationUrl, callbackUrl);
      if (blockRule != null) {
         command.add(blockRule);
      }
      command.add("--app=" + authorizationUrl);
      return command;
   }

   private static CaptureResult pollForCallback(int port,
                                                String callbackUrl,
                                                int timeoutSeconds,
                                                Consumer<String> log) {
      long deadline = System.currentTimeMillis() + Math.max(15, timeoutSeconds) * 1000L;
      long lastContact = System.currentTimeMillis();

      while (System.currentTimeMillis() < deadline) {
         List<Target> targets = listTargets(port);
         if (targets == null) {
            // The endpoint is unreachable, which normally means the user closed the window.
            if (System.currentTimeMillis() - lastContact > LOST_CONTACT_GRACE_MILLIS) {
               return CaptureResult.failed("Sign-in window was closed before the callback was reached.");
            }
            sleep(POLL_INTERVAL_MILLIS);
            continue;
         }
         lastContact = System.currentTimeMillis();

         for (Target target : targets) {
            OAuthCallbackParser.Result parsed = evaluate(target.url, callbackUrl);
            if (parsed == null) continue;
            closeTarget(port, target.id);
            if (parsed.hasError()) {
               return CaptureResult.failed("Authorization server returned " + parsed.errorMessage());
            }
            note(log, "✅ Captured the authorization response from the browser.");
            return CaptureResult.ok(parsed);
         }
         sleep(POLL_INTERVAL_MILLIS);
      }
      return CaptureResult.failed("Timed out after " + timeoutSeconds + "s waiting for the callback.");
   }

   /**
    * Decides whether a tab URL is the authorization response. A URL landing on the configured
    * callback endpoint counts even without a code so that server-reported errors surface;
    * anything else has to actually carry a code to avoid reacting to the login journey itself.
    */
   private static OAuthCallbackParser.Result evaluate(String url, String callbackUrl) {
      if (url == null || url.isEmpty()) return null;
      OAuthCallbackParser.Result parsed = OAuthCallbackParser.parse(url);
      if (parsed.isEmpty()) return null;
      if (parsed.hasCode() || parsed.hasToken()) return parsed;
      if (parsed.hasError() && OAuthCallbackParser.matchesCallback(url, callbackUrl)) return parsed;
      return null;
   }

   /** @return the open targets, or null when the debugging endpoint cannot be reached */
   private static List<Target> listTargets(int port) {
      String body = httpGet("http://127.0.0.1:" + port + "/json/list");
      if (body == null) return null;
      List<Target> targets = new ArrayList<>();
      try {
         JsonElement root = JsonParser.parseString(body);
         if (!root.isJsonArray()) return targets;
         JsonArray array = root.getAsJsonArray();
         for (JsonElement element : array) {
            if (!element.isJsonObject()) continue;
            JsonObject object = element.getAsJsonObject();
            String url = stringField(object, "url");
            if (url != null) targets.add(new Target(stringField(object, "id"), url));
         }
      } catch (Exception ignored) {
         // A partially written response just means we retry on the next tick.
      }
      return targets;
   }

   private static void closeTarget(int port, String targetId) {
      if (targetId == null || targetId.isEmpty()) return;
      httpGet("http://127.0.0.1:" + port + "/json/close/" + targetId);
   }

   private static String stringField(JsonObject object, String field) {
      try {
         if (object.has(field) && object.get(field).isJsonPrimitive()) {
            String value = object.get(field).getAsString();
            return value == null || value.isEmpty() ? null : value;
         }
      } catch (Exception ignored) {
      }
      return null;
   }

   /**
    * Waits for the debugging endpoint to answer. The port we asked for is probed directly, and
    * {@code DevToolsActivePort} is consulted only as a hint in case the browser chose another.
    *
    * @return the live port, or -1 if the endpoint never came up
    */
   private static int awaitDebuggingEndpoint(int requestedPort, Path profile) {
      File portFile = new File(profile.toFile(), "DevToolsActivePort");
      long deadline = System.currentTimeMillis() + DEVTOOLS_WAIT_MILLIS;
      while (System.currentTimeMillis() < deadline) {
         if (httpGet("http://127.0.0.1:" + requestedPort + "/json/version") != null) {
            return requestedPort;
         }
         int reported = readReportedPort(portFile);
         if (reported > 0 && reported != requestedPort
            && httpGet("http://127.0.0.1:" + reported + "/json/version") != null) {
            return reported;
         }
         sleep(200);
      }
      return -1;
   }

   private static int readReportedPort(File portFile) {
      if (!portFile.isFile()) return -1;
      try {
         List<String> lines = Files.readAllLines(portFile.toPath(), StandardCharsets.UTF_8);
         return lines.isEmpty() ? -1 : Integer.parseInt(lines.get(0).trim());
      } catch (Exception ex) {
         return -1;
      }
   }

   private static int reserveFreePort() {
      try (ServerSocket socket = new ServerSocket(0)) {
         return socket.getLocalPort();
      } catch (Exception ex) {
         return -1;
      }
   }

   /**
    * Builds a host-resolver rule that makes the callback host unreachable, so the browser stops
    * at the redirect and leaves the authorization response in the address bar for us to read.
    * Returns null when the callback shares a host with the authorization server, since blocking
    * it would break the sign-in itself.
    */
   static String callbackBlockingRule(String authorizationUrl, String callbackUrl) {
      String callbackHost = hostOf(callbackUrl);
      if (callbackHost == null) return null;
      String authHost = hostOf(authorizationUrl);
      if (authHost != null && authHost.equals(callbackHost)) return null;
      if ("localhost".equals(callbackHost) || "127.0.0.1".equals(callbackHost) || "::1".equals(callbackHost)) {
         // A loopback callback may be served by our own listener, which must stay reachable.
         return null;
      }
      return "--host-resolver-rules=MAP " + callbackHost + " ~NOTFOUND";
   }

   private static String hostOf(String url) {
      if (url == null || url.trim().isEmpty()) return null;
      try {
         String host = java.net.URI.create(url.trim()).getHost();
         return host == null || host.trim().isEmpty() ? null : host.trim().toLowerCase(Locale.ROOT);
      } catch (Exception ex) {
         return null;
      }
   }

   private static String httpGet(String url) {
      HttpURLConnection connection = null;
      try {
         connection = (HttpURLConnection) new URL(url).openConnection();
         connection.setConnectTimeout(1200);
         connection.setReadTimeout(2500);
         connection.setRequestMethod("GET");
         if (connection.getResponseCode() != 200) return null;
         StringBuilder sb = new StringBuilder();
         try (BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) sb.append(line);
         }
         return sb.toString();
      } catch (Exception ex) {
         return null;
      } finally {
         if (connection != null) connection.disconnect();
      }
   }

   private static void drainQuietly(InputStream stream) {
      Thread drain = new Thread(() -> {
         byte[] buffer = new byte[4096];
         try {
            while (stream.read(buffer) >= 0) {
               // Discarded; we only need to keep the pipe from filling.
            }
         } catch (Exception ignored) {
         }
      }, "oauth-browser-output");
      drain.setDaemon(true);
      drain.start();
   }

   /** Chromium spawns helper processes, so the whole tree has to go. */
   private static void destroyTree(Process process) {
      if (process == null) return;
      try {
         process.descendants().forEach(handle -> {
            try {
               handle.destroy();
            } catch (Exception ignored) {
            }
         });
      } catch (Exception ignored) {
      }
      try {
         process.destroy();
         if (!process.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)) {
            process.destroyForcibly();
         }
      } catch (Exception ignored) {
         try {
            process.destroyForcibly();
         } catch (Exception alsoIgnored) {
         }
      }
   }

   private static void deleteQuietly(File file) {
      if (file == null || !file.exists()) return;
      File[] children = file.listFiles();
      if (children != null) {
         for (File child : children) deleteQuietly(child);
      }
      try {
         file.delete();
      } catch (Exception ignored) {
      }
   }

   private static void note(Consumer<String> log, String message) {
      if (log == null) return;
      try {
         log.accept(message);
      } catch (Exception ignored) {
      }
   }

   private static void sleep(long millis) {
      try {
         Thread.sleep(millis);
      } catch (InterruptedException ex) {
         Thread.currentThread().interrupt();
      }
   }
}

