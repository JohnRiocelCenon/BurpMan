package burp.auth;

import burp.api.montoya.MontoyaApi;

import java.awt.Window;
import java.util.function.Consumer;

/**
 * Runs an interactive OAuth 2.0 sign-in and returns the authorization response.
 *
 * <p>Strategies are tried in order of how little they ask of the user:
 * <ol>
 *   <li>a dedicated Chromium window whose address bar BurpMan reads over the DevTools protocol,
 *       which needs no proxy and works with any callback URL;</li>
 *   <li>a loopback HTTP listener, when the callback actually points at localhost;</li>
 *   <li>Burp's proxy history, when the browser is being proxied;</li>
 *   <li>asking the user to paste the redirected URL.</li>
 * </ol>
 */
final class OAuthInteractiveCapture {

   private OAuthInteractiveCapture() {
   }

   private static final int CHROMIUM_CAPTURE_TIMEOUT_SECONDS = 180;
   private static final int LOCAL_CAPTURE_TIMEOUT_SECONDS = 25;
   private static final int PROXY_CAPTURE_TIMEOUT_SECONDS = 20;
   private static final int PROXY_FALLBACK_TIMEOUT_SECONDS = 10;

   static final class Outcome {
      final String code;
      final String accessToken;
      final String failureReason;

      private Outcome(String code, String accessToken, String failureReason) {
         this.code = code;
         this.accessToken = accessToken;
         this.failureReason = failureReason;
      }

      boolean hasCode() {
         return this.code != null && !this.code.isEmpty();
      }

      boolean hasAccessToken() {
         return this.accessToken != null && !this.accessToken.isEmpty();
      }

      boolean cancelled() {
         return this.failureReason == null && !this.hasCode() && !this.hasAccessToken();
      }
   }

   private static Outcome success(OAuthCallbackParser.Result result) {
      return new Outcome(result.code, result.accessToken, null);
   }

   private static Outcome failure(String reason) {
      return new Outcome(null, null, reason);
   }

   private static final Outcome CANCELLED = new Outcome(null, null, null);

   /**
    * @param log optional progress sink, invoked off the EDT; may be null
    * @return the captured response; never null
    */
   static Outcome capture(MontoyaApi api,
                          Window owner,
                          String authorizationUrl,
                          String callbackUrl,
                          String configuredState,
                          boolean preferSystemBrowser,
                          Consumer<String> log) {
      String expectedState = usableState(configuredState);
      long startedAtMillis = System.currentTimeMillis();
      boolean browserAlreadyOpened = false;

      if (preferSystemBrowser) {
         note(log, "ℹ Using the system browser, as configured.");
      } else if (ChromiumOAuthBrowser.isAvailable()) {
         ChromiumOAuthBrowser.CaptureResult captured = ChromiumOAuthBrowser.captureAuthorizationResponse(
            authorizationUrl, callbackUrl, CHROMIUM_CAPTURE_TIMEOUT_SECONDS, log);
         browserAlreadyOpened = true;

         if (captured.succeeded()) {
            String stateProblem = verifyState(captured.response, expectedState);
            if (stateProblem != null) return failure(stateProblem);
            return success(captured.response);
         }
         note(log, "⚠ " + captured.failureReason);
         if (captured.failureReason != null && captured.failureReason.startsWith("Authorization server returned")) {
            // The provider gave a definite answer; retrying other transports cannot improve on it.
            return failure(captured.failureReason);
         }
      } else {
         note(log, "ℹ No Chromium-based browser found; using the system browser.");
      }

      if (!browserAlreadyOpened && OAuthBrowserCallbackServer.canAutoCapture(callbackUrl)) {
         try {
            browserAlreadyOpened = true;
            String code = OAuthBrowserCallbackServer.openBrowserAndAwaitCode(
               authorizationUrl, callbackUrl, LOCAL_CAPTURE_TIMEOUT_SECONDS);
            if (code != null && !code.isEmpty()) {
               return new Outcome(code, null, null);
            }
         } catch (Exception ex) {
            note(log, "⚠ Local callback listener failed: " + ex.getMessage());
         }
      }

      if (!browserAlreadyOpened) {
         try {
            BrowserLauncher.open(authorizationUrl);
            browserAlreadyOpened = true;
         } catch (Exception ex) {
            return failure("Could not open a browser: " + ex.getMessage());
         }
      }

      String proxied = captureFromProxy(api, callbackUrl, startedAtMillis, log);
      if (proxied != null && !proxied.isEmpty()) {
         return new Outcome(proxied, null, null);
      }

      note(log, "⌨ Waiting for the redirected URL to be pasted\u2026");
      OAuthCallbackParser.Result pasted = OAuthManualCodeDialog.prompt(owner, callbackUrl, expectedState);
      if (pasted == null) {
         return CANCELLED;
      }
      if (pasted.hasError()) {
         return failure("Authorization server returned " + pasted.errorMessage());
      }
      String stateProblem = verifyState(pasted, expectedState);
      if (stateProblem != null) return failure(stateProblem);
      return success(pasted);
   }

   private static String captureFromProxy(MontoyaApi api, String callbackUrl, long startedAtMillis, Consumer<String> log) {
      if (api == null) return null;
      if (OAuthProxyCallbackCapture.canCapture(callbackUrl)) {
         try {
            String code = OAuthProxyCallbackCapture.awaitCodeFromProxy(
               api, callbackUrl, PROXY_CAPTURE_TIMEOUT_SECONDS, startedAtMillis);
            if (code != null && !code.isEmpty()) {
               note(log, "✅ Captured the code from Burp's proxy history.");
               return code;
            }
         } catch (Exception ex) {
            note(log, "⚠ Proxy history lookup failed: " + ex.getMessage());
         }
      }
      try {
         String code = OAuthProxyCallbackCapture.awaitAnyCodeFromProxy(
            api, PROXY_FALLBACK_TIMEOUT_SECONDS, startedAtMillis);
         if (code != null && !code.isEmpty()) {
            note(log, "✅ Captured the code from Burp's proxy history.");
            return code;
         }
      } catch (Exception ex) {
         note(log, "⚠ Proxy history lookup failed: " + ex.getMessage());
      }
      return null;
   }

   /** A state value still containing a template marker was never sent, so it cannot be checked. */
   private static String usableState(String configuredState) {
      if (configuredState == null) return null;
      String s = configuredState.trim();
      if (s.isEmpty() || s.contains("{{")) return null;
      return s;
   }

   private static String verifyState(OAuthCallbackParser.Result result, String expectedState) {
      if (expectedState == null) return null;
      if (expectedState.equals(result.state)) return null;
      return "State mismatch: expected \"" + expectedState + "\" but the callback carried \""
         + (result.state == null ? "(none)" : result.state)
         + "\". The response was discarded because it may not belong to this sign-in.";
   }

   private static void note(Consumer<String> log, String message) {
      if (log == null) return;
      try {
         log.accept(message);
      } catch (Exception ignored) {
      }
   }
}
