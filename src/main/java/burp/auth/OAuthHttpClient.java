package burp.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

final class OAuthHttpClient {
   private OAuthHttpClient() {
   }

   static HttpRequestResponse sendRequestWithTimeout(MontoyaApi api, HttpRequest request, long timeoutMs) throws Exception {
      if (api == null) {
         throw new IllegalArgumentException("Montoya API is required");
      }
      if (request == null) {
         throw new IllegalArgumentException("HTTP request is required");
      }

      long waitMs = Math.max(1000L, timeoutMs);
      ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
         Thread t = new Thread(r, "oauth-http-request");
         t.setDaemon(true);
         return t;
      });

      Future<HttpRequestResponse> future = executor.submit(() -> burp.service.ProxyRouter.sendRequest(api, request));
      try {
         return future.get(waitMs, TimeUnit.MILLISECONDS);
      } catch (TimeoutException ex) {
         future.cancel(true);
         throw new TimeoutException("Timed out waiting for token endpoint after " + waitMs + " ms");
      } catch (ExecutionException ex) {
         Throwable cause = ex.getCause();
         if (cause instanceof Exception) {
            throw (Exception)cause;
         }
         throw new RuntimeException(cause);
      } finally {
         executor.shutdownNow();
      }
   }
}
