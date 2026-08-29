package burp.auth;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.parser.VariableResolver;
import burp.utils.HttpUtils;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class OAuth2RequestFactory {
   private static final String POSTMAN_CALLBACK_URL = "https://oauth.pstmn.io/v1/callback";
   private static final String POSTMAN_BROWSER_CALLBACK_URL = "https://oauth.pstmn.io/v1/browser-callback";
   private static final String DEFAULT_BROWSER_CALLBACK_URL = POSTMAN_BROWSER_CALLBACK_URL;
   private final VariableResolver resolver;
   private static final SecureRandom PKCE_RANDOM = new SecureRandom();

   public static class PkcePair {
      public final String verifier;
      public final String challenge;

      public PkcePair(String verifier, String challenge) {
         this.verifier = verifier;
         this.challenge = challenge;
      }
   }

   public OAuth2RequestFactory(VariableResolver resolver) {
      this.resolver = resolver;
   }

   public HttpRequest buildTokenRequest(OAuth2Config config) throws Exception {
      if (config == null || !config.isUsableForTokenRequest()) {
         throw new IllegalArgumentException("OAuth2 config is missing grant_type or access token URL.");
      }

      String resolvedUrl = this.resolver.resolve(config.accessTokenUrl);
      String clientId = this.resolver.resolve(config.clientId);
      String clientSecret = this.resolver.resolve(config.clientSecret);
      String scope = this.resolver.resolve(config.scope);
      if (clientId != null && clientId.contains("{{")) {
         throw new IllegalStateException("Unresolved client_id: " + clientId);
      } else if (clientSecret != null && clientSecret.contains("{{")) {
         throw new IllegalStateException("Unresolved client_secret");
      } else if (scope != null && scope.contains("{{")) {
         throw new IllegalStateException("Unresolved scope: " + scope);
      }

      boolean useBasicAuth = "header".equalsIgnoreCase(config.clientAuthenticationMethod)
         || "basic".equalsIgnoreCase(config.clientAuthenticationMethod);
      String authHeader = null;
      if (useBasicAuth) {
         String combined = clientId + ":" + clientSecret;
         String encoded = Base64.getEncoder().encodeToString(combined.getBytes(StandardCharsets.UTF_8));
         authHeader = "Basic " + encoded;
      }

      String body = this.buildFormBody(config, clientId, clientSecret, scope, useBasicAuth);
      HttpUtils.HostInfo hostInfo = HttpUtils.parseUrl(resolvedUrl);
      String path = this.extractPath(resolvedUrl);
      String rawRequest = this.buildRawRequest(path, hostInfo, body, authHeader);
      HttpService service = HttpService.httpService(hostInfo.host, hostInfo.port, hostInfo.useHttps);
      return HttpRequest.httpRequest(service, ByteArray.byteArray(rawRequest.getBytes(StandardCharsets.UTF_8)));
   }

   public String buildAuthorizationRequestUrl(OAuth2Config config) throws Exception {
      return this.buildAuthorizationRequestUrl(config, null);
   }

   public String buildAuthorizationRequestUrl(OAuth2Config config, String codeChallenge) throws Exception {
      if (config == null) {
         throw new IllegalArgumentException("OAuth2 config is required.");
      } else if (config.authUrl == null || config.authUrl.trim().isEmpty()) {
         throw new IllegalArgumentException("OAuth2 config is missing auth URL.");
      }

      String resolvedAuthUrl = this.resolver.resolve(config.authUrl);
      String clientId = this.resolver.resolve(config.clientId);
      String scope = this.resolver.resolve(config.scope);
      String redirectUri = this.resolveCallbackUrl(config, true);
      String state = this.resolver.resolve(config.state);
      String audience = this.resolveRawAttr(config, "audience");
      if (clientId != null && clientId.contains("{{")) {
         throw new IllegalStateException("Unresolved client_id: " + clientId);
      }

      List<String> params = new ArrayList<>();
      this.add(params, "response_type", "code");
      this.add(params, "client_id", clientId);
      this.add(params, "scope", scope);
      this.add(params, "redirect_uri", redirectUri);
      this.add(params, "state", state);
      this.add(params, "audience", audience);
      if (codeChallenge != null && !codeChallenge.trim().isEmpty()) {
         this.add(params, "code_challenge", codeChallenge.trim());
         this.add(params, "code_challenge_method", "S256");
      }
      String sep = resolvedAuthUrl.contains("?") ? "&" : "?";
      String qs = String.join("&", params);
      return qs.isEmpty() ? resolvedAuthUrl : resolvedAuthUrl + sep + qs;
   }

   public HttpRequest buildAuthorizationCodeTokenRequest(OAuth2Config config, String authorizationCode) throws Exception {
      return this.buildAuthorizationCodeTokenRequest(config, authorizationCode, null);
   }

   public HttpRequest buildAuthorizationCodeTokenRequest(OAuth2Config config, String authorizationCode, String codeVerifier) throws Exception {
      if (config == null) {
         throw new IllegalArgumentException("OAuth2 config is required.");
      } else if (authorizationCode == null || authorizationCode.trim().isEmpty()) {
         throw new IllegalArgumentException("Authorization code is required.");
      }

      String resolvedUrl = this.resolver.resolve(config.accessTokenUrl);
      if (resolvedUrl == null || resolvedUrl.trim().isEmpty()) {
         throw new IllegalArgumentException("OAuth2 config is missing access token URL.");
      }

      String clientId = this.resolver.resolve(config.clientId);
      String clientSecret = this.resolver.resolve(config.clientSecret);
      String scope = this.resolver.resolve(config.scope);
      String redirectUri = this.resolveCallbackUrl(config, true);
      if (clientId != null && clientId.contains("{{")) {
         throw new IllegalStateException("Unresolved client_id: " + clientId);
      } else if (clientSecret != null && clientSecret.contains("{{")) {
         throw new IllegalStateException("Unresolved client_secret");
      } else if (scope != null && scope.contains("{{")) {
         throw new IllegalStateException("Unresolved scope: " + scope);
      }

      boolean useBasicAuth = "header".equalsIgnoreCase(config.clientAuthenticationMethod)
         || "basic".equalsIgnoreCase(config.clientAuthenticationMethod);
      String authHeader = null;
      if (useBasicAuth) {
         String combined = clientId + ":" + clientSecret;
         String encoded = Base64.getEncoder().encodeToString(combined.getBytes(StandardCharsets.UTF_8));
         authHeader = "Basic " + encoded;
      }

      List<String> params = new ArrayList<>();
      this.add(params, "grant_type", "authorization_code");
      this.add(params, "code", authorizationCode.trim());
      this.add(params, "redirect_uri", redirectUri);
      this.add(params, "scope", scope);
      if (codeVerifier != null && !codeVerifier.trim().isEmpty()) {
         this.add(params, "code_verifier", codeVerifier.trim());
      }
      if (!useBasicAuth) {
         this.add(params, "client_id", clientId);
         this.add(params, "client_secret", clientSecret);
      }

      this.addResolved(params, "audience", config.audience);
      String body = String.join("&", params);
      HttpUtils.HostInfo hostInfo = HttpUtils.parseUrl(resolvedUrl);
      String path = this.extractPath(resolvedUrl);
      String rawRequest = this.buildRawRequest(path, hostInfo, body, authHeader);
      HttpService service = HttpService.httpService(hostInfo.host, hostInfo.port, hostInfo.useHttps);
      return HttpRequest.httpRequest(service, ByteArray.byteArray(rawRequest.getBytes(StandardCharsets.UTF_8)));
   }

   public boolean isBrowserInteractiveFlow(OAuth2Config config) {
      if (config == null) return false;
      String gt = this.normalizeGrantType(config.grantType);
      if ("authorization_code".equalsIgnoreCase(gt)) return true;
      String useBrowser = config.rawAttributes == null ? null : config.rawAttributes.get("useBrowser");
      return "true".equalsIgnoreCase(useBrowser);
   }

   public PkcePair generatePkcePair() {
      byte[] verifierBytes = new byte[32];
      PKCE_RANDOM.nextBytes(verifierBytes);
      String verifier = base64Url(verifierBytes);
      try {
         MessageDigest sha = MessageDigest.getInstance("SHA-256");
         String challenge = base64Url(sha.digest(verifier.getBytes(StandardCharsets.US_ASCII)));
         return new PkcePair(verifier, challenge);
      } catch (Exception ex) {
         throw new RuntimeException("Failed to generate PKCE challenge", ex);
      }
   }

   public String resolveBrowserCallbackUrl(OAuth2Config config) throws Exception {
      return this.resolveCallbackUrl(config, true);
   }

   private String buildFormBody(OAuth2Config config, String clientId, String clientSecret, String scope, boolean useBasicAuth) throws Exception {
      List<String> params = new ArrayList<>();
      this.add(params, "grant_type", this.normalizeGrantType(config.grantType));
      this.add(params, "scope", scope);
      if (!useBasicAuth) {
         this.add(params, "client_id", clientId);
         this.add(params, "client_secret", clientSecret);
      }

      this.addResolved(params, "username", config.username);
      this.addResolved(params, "password", config.password);
      this.addResolved(params, "audience", config.audience);
      this.addResolved(params, "state", config.state);
      this.addResolved(params, "redirect_uri", config.callbackUrl);
      String refreshToken = config.rawAttributes == null ? null : config.rawAttributes.get("refresh_token");
      if (refreshToken != null) {
         this.addResolved(params, "refresh_token", refreshToken);
      }

      return String.join("&", params);
   }

   private void addResolved(List<String> params, String key, String value) throws Exception {
      if (value != null && !value.trim().isEmpty()) {
         String resolved = this.resolver.resolve(value);
         if (resolved != null && !resolved.trim().isEmpty()) {
            this.add(params, key, resolved);
         }
      }
   }

   private void add(List<String> params, String key, String value) throws Exception {
      if (value != null && !value.trim().isEmpty()) {
         params.add(URLEncoder.encode(key, "UTF-8") + "=" + URLEncoder.encode(value, "UTF-8"));
      }
   }

   private String resolveCallbackUrl(OAuth2Config config, boolean browserFlow) throws Exception {
      String resolved = null;
      if (config != null && config.callbackUrl != null && !config.callbackUrl.trim().isEmpty()) {
         resolved = this.resolver.resolve(config.callbackUrl);
      }
      if (resolved == null || resolved.trim().isEmpty()) {
         String raw = this.firstNonBlank(
            this.resolveRawAttr(config, "callbackUrl"),
            this.resolveRawAttr(config, "redirect_uri"),
            this.resolveRawAttr(config, "redirectUri"),
            this.resolveRawAttr(config, "oauth2CallbackUrl"),
            this.resolveRawAttr(config, "oauth2Callback")
         );
         resolved = raw;
      }
      resolved = normalizePostmanBrowserCallback(resolved);
      if ((resolved == null || resolved.trim().isEmpty()) && browserFlow) {
         return DEFAULT_BROWSER_CALLBACK_URL;
      }
      return resolved;
   }

   private String firstNonBlank(String... values) {
      if (values == null) return null;
      for (String value : values) {
         if (value != null && !value.trim().isEmpty()) return value;
      }
      return null;
   }

   private static String normalizePostmanBrowserCallback(String callbackUrl) {
      if (callbackUrl == null || callbackUrl.trim().isEmpty()) return null;
      String raw = callbackUrl.trim();
      String lower = raw.toLowerCase(Locale.ROOT);
      String prefix = POSTMAN_CALLBACK_URL.toLowerCase(Locale.ROOT);
      if (!lower.startsWith(prefix)) return raw;
      String suffix = raw.substring(prefix.length());
      return POSTMAN_BROWSER_CALLBACK_URL + suffix;
   }

   private String normalizeGrantType(String grantType) {
      if (grantType == null) {
         return "";
      } else {
         String lower = grantType.trim().toLowerCase();
         switch (lower.hashCode()) {
            case 747792935:
               if (lower.equals("client credentials")) {
                  return "client_credentials";
               }
               break;
            case 1512972596:
               if (lower.equals("authorization code")) {
                  return "authorization_code";
               }
               break;
            case 1720023287:
               if (lower.equals("password credentials")) {
                  return "password";
               }
         }

         return grantType.trim();
      }
   }

   private String buildRawRequest(String path, HttpUtils.HostInfo hostInfo, String body, String authHeader) {
      StringBuilder raw = new StringBuilder();
      raw.append("POST ").append(path).append(" HTTP/1.1\r\n");
      raw.append("Host: ").append(this.buildHostHeader(hostInfo)).append("\r\n");
      if (authHeader != null) {
         raw.append("Authorization: ").append(authHeader).append("\r\n");
      }

      raw.append("Content-Type: application/x-www-form-urlencoded\r\n");
      raw.append("Content-Length: ").append(body.getBytes(StandardCharsets.UTF_8).length).append("\r\n");
      raw.append("\r\n");
      raw.append(body);
      return raw.toString();
   }

   private String extractPath(String url) {
      if (url == null) {
         return "/";
      } else {
         int protocolEnd = url.indexOf("://");
         int start = protocolEnd >= 0 ? url.indexOf(47, protocolEnd + 3) : url.indexOf(47);
         return start < 0 ? "/" : url.substring(start);
      }
   }

   private String buildHostHeader(HttpUtils.HostInfo hostInfo) {
      boolean defaultPort = hostInfo.useHttps && hostInfo.port == 443 || !hostInfo.useHttps && hostInfo.port == 80;
      return defaultPort ? hostInfo.host : hostInfo.host + ":" + hostInfo.port;
   }

   private String resolveRawAttr(OAuth2Config config, String key) {
      if (config == null || config.rawAttributes == null || key == null) return null;
      String value = config.rawAttributes.get(key);
      if (value == null) {
         for (Map.Entry<String, String> e : config.rawAttributes.entrySet()) {
            if (e.getKey() != null && key.equalsIgnoreCase(e.getKey())) {
               value = e.getValue();
               break;
            }
         }
      }

      if (value == null || value.trim().isEmpty()) return null;
      try {
         return this.resolver.resolve(value);
      } catch (Exception var5) {
         return value;
      }
   }

   private static String base64Url(byte[] data) {
      return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
   }
}
