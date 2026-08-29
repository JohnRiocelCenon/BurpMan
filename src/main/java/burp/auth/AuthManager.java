package burp.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.models.PostmanCollection;
import burp.parser.VariableResolver;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public class AuthManager {
   private static final long AUTO_REFRESH_TIMEOUT_NOTICE_COOLDOWN_MS = 30000L;
   private final VariableResolver variableResolver;
   private final MontoyaApi api;
   private final OAuth2RequestFactory requestFactory;
   private PostmanCollection.Request tokenSourceRequest;
   private final List<OAuth2Config> oauth2Configs = new ArrayList<>();
   private volatile OAuth2Config preferredOAuth2Config;
   private final TokenInfo currentToken = new TokenInfo();
   private AuthManagerPanel panel;
   private boolean autoCaptureEnabled = false;
   private volatile boolean autoRefreshEnabled = false;
   private volatile long autoRefreshSkewSeconds = 30L;
   private volatile Consumer<Consumer<String>> autoRefreshFetcher;
   private final Object refreshLock = new Object();
   private final List<Consumer<String>> tokenChangeListeners = new CopyOnWriteArrayList<>();
   private PostmanCollection.Auth collectionAuth;
   private volatile long lastAutoRefreshTimeoutNoticeMillis = 0L;

   public void addTokenChangeListener(Consumer<String> l) {
      if (l != null) {
         this.tokenChangeListeners.add(l);
      }
   }

   public void removeTokenChangeListener(Consumer<String> l) {
      if (l != null) {
         this.tokenChangeListeners.remove(l);
      }
   }

   private void fireTokenChange() {
      String tok = this.currentToken.getAccessToken();

      for (Consumer<String> l : this.tokenChangeListeners) {
         try {
            l.accept(tok);
         } catch (Exception var5) {
         }
      }
   }

   public boolean isAutoRefreshEnabled() {
      return this.autoRefreshEnabled;
   }

   public void setAutoRefreshEnabled(boolean enabled) {
      this.autoRefreshEnabled = enabled;
   }

   public long getAutoRefreshSkewSeconds() {
      return this.autoRefreshSkewSeconds;
   }

   public void setAutoRefreshSkewSeconds(long s) {
      if (s >= 0L) {
         this.autoRefreshSkewSeconds = s;
      }
   }

   public void setAutoRefreshFetcher(Consumer<Consumer<String>> fetcher) {
      this.autoRefreshFetcher = fetcher;
   }

   public String ensureFreshTokenBlocking(long timeoutMs) {
      if (!this.autoRefreshEnabled) {
         return this.getAccessToken();
      }

      String current = this.getAccessToken();
      if (!this.isTokenExpiredOrAboutTo(current) || this.autoRefreshFetcher == null) {
         return current;
      }

      long waitMs = Math.max(1000L, timeoutMs);
      synchronized (this.refreshLock) {
         current = this.getAccessToken();
         if (!this.isTokenExpiredOrAboutTo(current)) {
            return current;
         }

         String[] fresh = new String[1];
         CountDownLatch latch = new CountDownLatch(1);
         boolean completed = false;

         try {
            this.autoRefreshFetcher.accept(token -> {
               fresh[0] = token;
               latch.countDown();
            });
            completed = latch.await(waitMs, TimeUnit.MILLISECONDS);
         } catch (Exception var8) {
         }

         if (!completed) {
            this.notifyAutoRefreshTimeout(waitMs);
         }

         if (fresh[0] != null && !fresh[0].isEmpty()) {
            this.setAccessToken(fresh[0]);
            return fresh[0];
         }
         return this.getAccessToken();
      }
   }

   private void notifyAutoRefreshTimeout(long timeoutMs) {
      long now = System.currentTimeMillis();
      if (now - this.lastAutoRefreshTimeoutNoticeMillis < AUTO_REFRESH_TIMEOUT_NOTICE_COOLDOWN_MS) {
         return;
      }
      this.lastAutoRefreshTimeoutNoticeMillis = now;

      String msg = "Auto-refresh timed out after " + timeoutMs + " ms. Continuing with current token.";
      try {
         this.api.logging().logToOutput("[Auth] " + msg);
      } catch (Exception var8) {
      }

      AuthManagerPanel currentPanel = this.panel;
      if (currentPanel != null) {
         javax.swing.SwingUtilities.invokeLater(
            () -> burp.ui.ToastManager.show(currentPanel, msg, burp.ui.ToastManager.Level.WARNING)
         );
      }
   }

   public void setTokenSourceRequest(PostmanCollection.Request request) {
      this.tokenSourceRequest = request;
   }

   public PostmanCollection.Request getTokenSourceRequest() {
      return this.tokenSourceRequest;
   }

   public void setPreferredOAuth2Config(OAuth2Config config) {
      this.preferredOAuth2Config = config;
   }

   public OAuth2Config getPreferredOAuth2Config() {
      OAuth2Config selected = this.preferredOAuth2Config;
      if (selected != null) {
         return selected;
      }
      return this.oauth2Configs.isEmpty() ? null : this.oauth2Configs.get(0);
   }

   public AuthManager(MontoyaApi api, VariableResolver variableResolver) {
      this.api = api;
      this.variableResolver = variableResolver;
      this.requestFactory = new OAuth2RequestFactory(variableResolver);
   }

   public void setCollectionAuth(PostmanCollection.Auth auth) {
      this.collectionAuth = auth;
   }

   public PostmanCollection.Auth getCollectionAuth() {
      return this.collectionAuth;
   }

   public void bindPanel(AuthManagerPanel panel) {
      this.panel = panel;
   }

   public AuthManagerPanel getPanel() {
      return this.panel;
   }

   private void refreshPanel() {
      this.fireTokenChange();
   }

   public void setOAuth2Configs(List<OAuth2Config> configs) {
      this.oauth2Configs.clear();
      if (configs == null) {
         this.refreshPanel();
      } else {
         int kept = 0;
         int unresolved = 0;

         for (OAuth2Config config : configs) {
            if (config != null) {
               String resolvedAccessTokenUrl = this.resolveWithCurrentVariables(config.accessTokenUrl);
               String resolvedClientId = this.resolveWithCurrentVariables(config.clientId);
               String resolvedClientSecret = this.resolveWithCurrentVariables(config.clientSecret);
               String resolvedScope = this.resolveWithCurrentVariables(config.scope);
               if (this.containsUnresolvedVariables(resolvedAccessTokenUrl)
                  || this.containsUnresolvedVariables(resolvedClientId)
                  || this.containsUnresolvedVariables(resolvedClientSecret)
                  || this.containsUnresolvedVariables(resolvedScope)) {
                  unresolved++;
                  this.api
                     .logging()
                     .logToOutput(
                        "[OAuth2] Config '"
                           + (config.name != null ? config.name : "?")
                           + "' has unresolved variables — keeping it (Edit OAuth2 / Edit Variables to fix). atUrl="
                           + resolvedAccessTokenUrl
                           + " cid="
                           + resolvedClientId
                           + " scope="
                           + resolvedScope
                     );
               }

               this.oauth2Configs.add(config);
               kept++;
            }
         }

         if (this.oauth2Configs.isEmpty()) {
            this.preferredOAuth2Config = null;
         } else if (this.preferredOAuth2Config == null || !this.oauth2Configs.contains(this.preferredOAuth2Config)) {
            this.preferredOAuth2Config = this.oauth2Configs.get(0);
         }

         if (kept == 0 && unresolved == 0) {
            this.api.logging().logToOutput("[OAuth2] No OAuth2 configs to register.");
         }

         this.refreshPanel();
      }
   }

   public List<OAuth2Config> getOAuth2Configs() {
      return new ArrayList<>(this.oauth2Configs);
   }

   public void sendTokenRequestToRepeater(OAuth2Config config) {
      if (config != null) {
         try {
            HttpRequest request = this.requestFactory.buildTokenRequest(config);
            this.api.repeater().sendToRepeater(request, "OAuth2 Token - " + this.safeName(config.name));
            this.api.logging().logToOutput("OAuth2 token request sent: " + config.accessTokenUrl);
         } catch (Exception var3) {
            this.api.logging().logToError("Failed to build OAuth2 request: " + var3.getMessage());
         }
      }
   }

   public void setAccessToken(String token) {
      this.currentToken.setAccessToken(token == null ? "" : token.trim());
      this.refreshPanel();
   }

   public String getAccessToken() {
      return this.currentToken.getAccessToken();
   }

   public boolean hasAccessToken() {
      return this.currentToken.hasAccessToken();
   }

   public long getAccessTokenExpiryEpochMs() {
      String token = this.getAccessToken();
      if (token == null || token.trim().isEmpty()) {
         return -1L;
      }

      long expiresAtMs = this.currentToken.getExpiresAtEpochMs();
      if (expiresAtMs > 0L) {
         return expiresAtMs;
      }

      long jwtExpSeconds = JwtUtils.getExpiryEpochSeconds(token);
      return jwtExpSeconds > 0L ? jwtExpSeconds * 1000L : -1L;
   }

   public boolean isAccessTokenExpiredOrNearExpiry() {
      return this.isTokenExpiredOrAboutTo(this.getAccessToken());
   }

   public String getAuthorizationHeaderValue() {
      return !this.hasAccessToken() ? null : this.currentToken.getTokenType() + " " + this.currentToken.getAccessToken();
   }

   public boolean extractAnyToken(String body) {
      if (body != null && !body.trim().isEmpty()) {
         try {
            JsonObject obj = (JsonObject)new Gson().fromJson(body, JsonObject.class);
            if (obj == null) {
               return false;
            } else {
               String token = null;
               if (this.hasString(obj, "access_token")) {
                  token = obj.get("access_token").getAsString();
               } else if (this.hasString(obj, "token")) {
                  token = obj.get("token").getAsString();
               } else if (this.hasString(obj, "jwt")) {
                  token = obj.get("jwt").getAsString();
               } else if (this.hasString(obj, "id_token")) {
                  token = obj.get("id_token").getAsString();
               }

               if (token != null && !token.trim().isEmpty()) {
                  this.currentToken.setAccessToken(token);
                  if (this.hasString(obj, "refresh_token")) {
                     this.currentToken.setRefreshToken(obj.get("refresh_token").getAsString());
                  }

                  if (this.hasString(obj, "token_type")) {
                     this.currentToken.setTokenType(obj.get("token_type").getAsString());
                  }

                  if (obj.has("expires_in") && !obj.get("expires_in").isJsonNull()) {
                     long expires = obj.get("expires_in").getAsLong();
                     this.currentToken.setExpiresAtEpochMs(System.currentTimeMillis() + expires * 1000L);
                  }

                  this.api.logging().logToOutput("Token auto-captured successfully.");
                  this.refreshPanel();
                  return true;
               } else {
                  return false;
               }
            }
         } catch (Exception var6) {
            this.api.logging().logToError("Token extraction failed: " + var6.getMessage());
            return false;
         }
      } else {
         return false;
      }
   }

   public boolean extractAccessTokenFromResponseBody(String body) {
      return this.extractAnyToken(body);
   }

   public boolean isAutoCaptureEnabled() {
      return this.autoCaptureEnabled;
   }

   public void setAutoCaptureEnabled(boolean autoCaptureEnabled) {
      this.autoCaptureEnabled = autoCaptureEnabled;
      this.refreshPanel();
   }

   public void reset() {
      if (this.oauth2Configs != null) {
         this.oauth2Configs.clear();
      }

      this.tokenSourceRequest = null;
      this.preferredOAuth2Config = null;
      this.collectionAuth = null;
      this.currentToken.clear();
      this.autoCaptureEnabled = false;
      this.autoRefreshEnabled = false;
      this.autoRefreshSkewSeconds = 30L;
      this.refreshPanel();
   }

   private boolean containsUnresolvedVariables(String value) {
      return value != null && value.contains("{{");
   }

   private boolean isTokenExpiredOrAboutTo(String token) {
      if (token != null && !token.trim().isEmpty()) {
         long expiresAtMs = this.currentToken.getExpiresAtEpochMs();
         if (expiresAtMs > 0L) {
            long skewMs = Math.max(0L, this.autoRefreshSkewSeconds) * 1000L;
            return System.currentTimeMillis() + skewMs >= expiresAtMs;
         } else {
            return JwtUtils.isExpiredOrAboutTo(token, this.autoRefreshSkewSeconds);
         }
      } else {
         return true;
      }
   }

   private String resolveWithCurrentVariables(String value) {
      if (value == null) {
         return null;
      } else if (this.variableResolver == null) {
         return value;
      } else {
         try {
            return this.variableResolver.resolve(value);
         } catch (Throwable var3) {
            return value;
         }
      }
   }

   private boolean hasString(JsonObject obj, String key) {
      return obj.has(key) && !obj.get(key).isJsonNull() && !obj.get(key).getAsString().trim().isEmpty();
   }

   private String safeName(String input) {
      return input != null && !input.trim().isEmpty() ? input.replaceAll("[\\r\\n\\t]", " ").trim() : "Token";
   }
}
