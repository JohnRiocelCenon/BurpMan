package burp.auth;

import burp.auth.signers.ApiKeySigner;
import burp.auth.signers.AwsSigV4Signer;
import burp.auth.signers.DigestSigner;
import burp.auth.signers.EdgeGridSigner;
import burp.auth.signers.HawkSigner;
import burp.auth.signers.OAuth1Signer;
import burp.models.PostmanCollection;
import burp.parser.VariableResolver;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class AuthResolver {
   private final AuthManager authManager;
   private final VariableResolver variableResolver;
   private final Gson gson = new Gson();

   public AuthResolver(AuthManager authManager, VariableResolver variableResolver) {
      this.authManager = authManager;
      this.variableResolver = variableResolver;
   }

   public AuthDecision resolve(PostmanCollection.Request request, PostmanCollection.Auth effectiveAuth, byte[] bodyBytes) {
      String body = bodyBytes != null ? new String(bodyBytes, StandardCharsets.UTF_8) : "";
      PostmanCollection.Auth requestAuth = this.explicitAuthOrNull(request != null ? request.auth : null);
      PostmanCollection.Auth inheritedAuth = this.explicitAuthOrNull(effectiveAuth);
      if (requestAuth != null && requestAuth.type != null) {
         return this.resolvePostmanAuth(requestAuth, "Request-level auth", body, request);
      } else if (this.hasOAuthClientCredentialsInBody(body, request)) {
         return AuthDecision.bodyOAuth("OAuth credentials detected in body");
      } else if (inheritedAuth != null && inheritedAuth.type != null) {
         return this.resolvePostmanAuth(inheritedAuth, "Inherited auth", body, request);
      } else {
         return this.authManager != null && this.authManager.hasAccessToken()
            ? AuthDecision.bearer(this.authManager.getAccessToken(), "Runtime access token")
            : AuthDecision.none("No auth found");
      }
   }

   private AuthDecision resolvePostmanAuth(PostmanCollection.Auth auth, String source, String body, PostmanCollection.Request request) {
      String type = auth.type != null ? auth.type.trim().toLowerCase() : "";
      if (this.hasOAuthClientCredentialsInBody(body, request)) {
         return AuthDecision.bodyOAuth("OAuth credentials detected in body");
      } else if ("noauth".equals(type)) {
         return AuthDecision.none(source + " (hard noauth)");
      } else if ("bearer".equals(type)) {
         String token = this.extractAuthValue(auth.bearer, "token");
         return token != null && !token.trim().isEmpty()
            ? AuthDecision.bearer(this.resolve(token), source + ": bearer")
            : AuthDecision.none(source + ": blank bearer");
      } else if ("basic".equals(type)) {
         String username = this.extractAuthValue(auth.basic, "username");
         String password = this.extractAuthValue(auth.basic, "password");
         return AuthDecision.basic(this.resolve(username), this.resolve(password), source + ": basic");
      } else if ("apikey".equals(type)) {
         String key = this.resolve(this.extractAuthValue(auth.apikey, "key"));
         String value = this.resolve(this.extractAuthValue(auth.apikey, "value"));
         String inLoc = this.extractAuthValue(auth.apikey, "in");
         if (key != null && !key.trim().isEmpty()) {
            ApiKeySigner.Placement place = "query".equalsIgnoreCase(inLoc) ? ApiKeySigner.Placement.QUERY : ApiKeySigner.Placement.HEADER;
            return AuthDecision.withSigner(AuthDecision.Type.API_KEY, new ApiKeySigner(key, value, place), source + ": apikey");
         } else {
            return AuthDecision.none(source + ": blank apikey");
         }
      } else if ("digest".equals(type)) {
         String username = this.resolve(this.extractAuthValue(auth.digest, "username"));
         String password = this.resolve(this.extractAuthValue(auth.digest, "password"));
         String realm = this.resolve(this.extractAuthValue(auth.digest, "realm"));
         String nonce = this.resolve(this.extractAuthValue(auth.digest, "nonce"));
         String opaque = this.resolve(this.extractAuthValue(auth.digest, "opaque"));
         String algo = this.resolve(this.extractAuthValue(auth.digest, "algorithm"));
         String qop = this.resolve(this.extractAuthValue(auth.digest, "qop"));
         return AuthDecision.withSigner(AuthDecision.Type.DIGEST, new DigestSigner(username, password, realm, nonce, opaque, algo, qop), source + ": digest");
      } else if ("oauth1".equals(type)) {
         String consumerKey = this.resolve(this.extractAuthValue(auth.oauth1, "consumerKey"));
         String consumerSecret = this.resolve(this.extractAuthValue(auth.oauth1, "consumerSecret"));
         String token = this.resolve(this.extractAuthValue(auth.oauth1, "token"));
         String tokenSecret = this.resolve(this.extractAuthValue(auth.oauth1, "tokenSecret"));
         String realm = this.resolve(this.extractAuthValue(auth.oauth1, "realm"));
         String sigMethod = this.extractAuthValue(auth.oauth1, "signatureMethod");
         String addParamsTo = this.extractAuthValue(auth.oauth1, "addParamsToHeader");
         String includeBodyHash = this.extractAuthValue(auth.oauth1, "includeBodyHash");
         OAuth1Signer.SignatureMethod m;
         if (sigMethod == null) {
            m = OAuth1Signer.SignatureMethod.HMAC_SHA1;
         } else if (sigMethod.equalsIgnoreCase("HMAC-SHA256")) {
            m = OAuth1Signer.SignatureMethod.HMAC_SHA256;
         } else if (sigMethod.equalsIgnoreCase("PLAINTEXT")) {
            m = OAuth1Signer.SignatureMethod.PLAINTEXT;
         } else {
            m = OAuth1Signer.SignatureMethod.HMAC_SHA1;
         }

         OAuth1Signer.Placement p = "false".equalsIgnoreCase(addParamsTo) ? OAuth1Signer.Placement.QUERY : OAuth1Signer.Placement.HEADER;
         return AuthDecision.withSigner(
            AuthDecision.Type.OAUTH1,
            new OAuth1Signer(consumerKey, consumerSecret, token, tokenSecret, realm, m, p, "true".equalsIgnoreCase(includeBodyHash)),
            source + ": oauth1"
         );
      } else if ("awsv4".equals(type) || "awssigv4".equals(type)) {
         String accessKey = this.resolve(this.extractAuthValue(auth.awsv4, "accessKey"));
         String secretKey = this.resolve(this.extractAuthValue(auth.awsv4, "secretKey"));
         String sessionTok = this.resolve(this.extractAuthValue(auth.awsv4, "sessionToken"));
         String service = this.resolve(this.extractAuthValue(auth.awsv4, "service"));
         String region = this.resolve(this.extractAuthValue(auth.awsv4, "region"));
         return AuthDecision.withSigner(
            AuthDecision.Type.AWS_SIGV4,
            new AwsSigV4Signer(
               accessKey,
               secretKey,
               sessionTok,
               service == null ? "execute-api" : service,
               region == null ? "us-east-1" : region,
               "s3".equalsIgnoreCase(service)
            ),
            source + ": aws-sigv4"
         );
      } else if ("hawk".equals(type)) {
         String hawkId = this.resolve(this.extractAuthValue(auth.hawk, "authId"));
         String hawkKey = this.resolve(this.extractAuthValue(auth.hawk, "authKey"));
         String algorithm = this.extractAuthValue(auth.hawk, "algorithm");
         String ext = this.resolve(this.extractAuthValue(auth.hawk, "ext"));
         String app = this.resolve(this.extractAuthValue(auth.hawk, "app"));
         String dlg = this.resolve(this.extractAuthValue(auth.hawk, "dlg"));
         String includeHash = this.extractAuthValue(auth.hawk, "includePayloadHash");
         return AuthDecision.withSigner(
            AuthDecision.Type.HAWK, new HawkSigner(hawkId, hawkKey, algorithm, ext, app, dlg, "true".equalsIgnoreCase(includeHash)), source + ": hawk"
         );
      } else if ("edgegrid".equals(type)) {
         String clientToken = this.resolve(this.extractAuthValue(auth.edgegrid, "clientToken"));
         String accessToken = this.resolve(this.extractAuthValue(auth.edgegrid, "accessToken"));
         String clientSecret = this.resolve(this.extractAuthValue(auth.edgegrid, "clientSecret"));
         String nonce = this.resolve(this.extractAuthValue(auth.edgegrid, "nonce"));
         String ts = this.resolve(this.extractAuthValue(auth.edgegrid, "timestamp"));
         return AuthDecision.withSigner(
            AuthDecision.Type.EDGEGRID, new EdgeGridSigner(clientToken, accessToken, clientSecret, nonce, ts), source + ": edgegrid"
         );
      } else {
         return AuthDecision.none(source + ": unsupported auth type " + type);
      }
   }

   public boolean hasOAuthClientCredentialsInBody(String body, PostmanCollection.Request request) {
      if (body == null) {
         return false;
      } else {
         String lower = body.toLowerCase();
         int score = 0;
         boolean hasClientId = lower.contains("client_id=") || lower.contains("\"client_id\"");
         boolean hasClientSecret = lower.contains("client_secret=") || lower.contains("\"client_secret\"");
         if (hasClientId && hasClientSecret) {
            score += 5;
         }

         boolean hasGrantType = lower.contains("grant_type=") || lower.contains("\"grant_type\"");
         if (hasGrantType) {
            score += 4;
         }

         if (request != null && request.body != null && "urlencoded".equalsIgnoreCase(request.body.mode)) {
            score += 3;
         }

         boolean looksLikeTokenEndpoint = false;
         if (request != null && request.url != null) {
            String rawUrl = request.url.toString().toLowerCase();
            looksLikeTokenEndpoint = rawUrl.contains("/token") || rawUrl.contains("/oauth") || rawUrl.contains("/connect") || rawUrl.contains("access_token");
         }

         if (looksLikeTokenEndpoint) {
            score += 4;
         }

         String[] oauthKeys = new String[]{"scope", "audience", "resource"};

         for (String key : oauthKeys) {
            if (lower.contains(key)) {
               score++;
            }
         }

         boolean looksLikeBusinessPayload = lower.contains("searchparameters") || lower.contains("policy") || lower.contains("customer");
         if (looksLikeBusinessPayload) {
            score -= 4;
         }

         return score >= 7;
      }
   }

   private String resolve(String value) {
      return value == null ? null : this.variableResolver.resolve(value);
   }

    private PostmanCollection.Auth explicitAuthOrNull(PostmanCollection.Auth auth) {
       if (auth == null) return null;
       String t = auth.type;
       if (t == null) return null;
       String lower = t.trim().toLowerCase();
       if (lower.isEmpty() || "inherit".equals(lower) || "inherited".equals(lower)) return null;
       return auth;
    }

   private String extractAuthValue(Object authData, String key) {
      if (authData != null && key != null) {
         try {
            JsonElement element = this.gson.toJsonTree(authData);
            if (element.isJsonArray()) {
               for (JsonElement item : element.getAsJsonArray()) {
                  if (item.isJsonObject()) {
                     JsonObject obj = item.getAsJsonObject();
                     if (obj.has("key") && key.equalsIgnoreCase(obj.get("key").getAsString())) {
                        return obj.has("value") && !obj.get("value").isJsonNull() ? obj.get("value").getAsString() : null;
                     }
                  }
               }
            }

            if (element.isJsonObject()) {
               JsonObject obj = element.getAsJsonObject();
               if (obj.has(key) && !obj.get(key).isJsonNull()) {
                  return obj.get(key).getAsString();
               }
            }
         } catch (Exception var8) {
            if (authData instanceof Map) {
               Object v = ((Map)authData).get(key);
               return v != null ? v.toString() : null;
            }
         }

         return null;
      } else {
         return null;
      }
   }
}
