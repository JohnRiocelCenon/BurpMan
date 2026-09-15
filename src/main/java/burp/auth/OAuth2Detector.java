package burp.auth;

import burp.models.PostmanCollection;
import burp.parser.VariableResolver;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;

public class OAuth2Detector {
   private static final String POSTMAN_CALLBACK_URL = "https://oauth.pstmn.io/v1/callback";
   private static final String POSTMAN_BROWSER_CALLBACK_URL = "https://oauth.pstmn.io/v1/browser-callback";
   private static final String DEFAULT_BROWSER_CALLBACK_URL = POSTMAN_BROWSER_CALLBACK_URL;
   private final VariableResolver resolver;
   private final Gson gson = new Gson();

   public OAuth2Detector(VariableResolver resolver) {
      this.resolver = resolver;
   }

   public List<OAuth2Config> detect(PostmanCollection collection) {
      Map<String, OAuth2Config> uniqueConfigs = new LinkedHashMap<>();
      PostmanCollection.Auth rootAuth = collection != null ? collection.auth : null;
      this.walkItems(collection != null ? collection.item : null, "", rootAuth, uniqueConfigs);
      OAuth2Config rootConfig = this.normalizeOAuth2(
         rootAuth, "Collection", collection != null && collection.info != null ? collection.info.name : "Collection"
      );
      if (rootConfig != null) {
         uniqueConfigs.put(this.signature(rootConfig), rootConfig);
      }

      return new ArrayList<>(uniqueConfigs.values());
   }

   private void walkItems(List<PostmanCollection.Item> items, String path, PostmanCollection.Auth inheritedAuth, Map<String, OAuth2Config> uniqueConfigs) {
      if (items != null) {
         for (PostmanCollection.Item item : items) {
            if (item != null) {
               String itemName = item.name != null ? item.name : "Unnamed";
               String currentPath = path.isEmpty() ? itemName : path + "/" + itemName;
               PostmanCollection.Auth effectiveAuth = inheritedAuth;
               if (item.auth != null) {
                  effectiveAuth = item.auth;
                  String labelPath = item.isCollectionWrapper ? "Collection" : currentPath;
                  OAuth2Config folderConfig = this.normalizeOAuth2(item.auth, labelPath, itemName);
                  if (folderConfig != null) {
                     uniqueConfigs.put(this.signature(folderConfig), folderConfig);
                  }
               }

               if (item.request != null && item.request.auth != null) {
                  effectiveAuth = item.request.auth;
                  OAuth2Config config = this.normalizeOAuth2(effectiveAuth, currentPath, itemName);
                  if (config != null) {
                     uniqueConfigs.putIfAbsent(this.signature(config), config);
                  }
               }

               if (item.item != null && !item.item.isEmpty()) {
                  this.walkItems(item.item, currentPath, effectiveAuth, uniqueConfigs);
               }
            }
         }
      }
   }

   private OAuth2Config normalizeOAuth2(PostmanCollection.Auth auth, String path, String name) {
      if (auth != null && auth.type != null && "oauth2".equalsIgnoreCase(auth.type)) {
         OAuth2Config config = new OAuth2Config();
         config.name = name;
         config.path = path;
         this.collectOAuth2Attributes(auth.oauth2, config);
         config.grantType = this.firstNonBlank(this.attr(config, "grant_type"), this.attr(config, "grantType"), this.attr(config, "grant type"));
         // Some Postman exports omit grant_type but include useBrowser=true.
         // Default those to authorization_code so interactive browser login works.
         if ((config.grantType == null || config.grantType.trim().isEmpty())
            && "true".equalsIgnoreCase(this.attr(config, "useBrowser"))) {
            config.grantType = "authorization_code";
         }
         String rawAccessTokenUrl = this.firstNonBlank(
            this.attr(config, "accessTokenUrl"), this.attr(config, "access_token_url"), this.attr(config, "tokenUrl"), this.attr(config, "token_url")
         );
         String rawAuthUrl = this.firstNonBlank(this.attr(config, "authUrl"), this.attr(config, "authorizationUrl"), this.attr(config, "authorization_url"));
         String rawScope = this.attr(config, "scope");
         config.accessTokenUrl = rawAccessTokenUrl;
         config.authUrl = rawAuthUrl;
         String rawClientId = this.firstNonBlank(this.attr(config, "clientId"), this.attr(config, "client_id"));
         String rawClientSecret = this.firstNonBlank(this.attr(config, "clientSecret"), this.attr(config, "client_secret"));
         String clientIdVarName = extractVarName(rawClientId);
         String clientSecretVarName = extractVarName(rawClientSecret);
         String actualClientId = this.resolveSafe(rawClientId);
         String actualClientSecret = this.resolveSafe(rawClientSecret);
         String actualScope = this.resolveSafe(rawScope);
         String activeScope = this.resolver.getActiveScope();
         boolean hasActiveScope = activeScope != null && !activeScope.trim().isEmpty();
         Map<String, String> bootstrapVars = hasActiveScope
           ? this.resolver.getScopedVariables(activeScope)
           : this.resolver.getVariables();
         if (clientIdVarName == null && actualClientId != null && !actualClientId.isEmpty() && !bootstrapVars.containsKey("client_id")) {
           this.putBootstrapVariable("client_id", actualClientId, activeScope);
           bootstrapVars.put("client_id", actualClientId);
         }

         if (clientSecretVarName == null
            && actualClientSecret != null
            && !actualClientSecret.isEmpty()
            && !bootstrapVars.containsKey("client_secret")) {
           this.putBootstrapVariable("client_secret", actualClientSecret, activeScope);
           bootstrapVars.put("client_secret", actualClientSecret);
         }

         if (actualScope != null && !actualScope.isEmpty() && !bootstrapVars.containsKey("scope")) {
           this.putBootstrapVariable("scope", actualScope, activeScope);
           bootstrapVars.put("scope", actualScope);
         }

         String authMethod = this.attr(config, "client_authentication");
         if ("header".equalsIgnoreCase(authMethod) || "send_as_basic_auth_header".equalsIgnoreCase(authMethod)) {
            config.clientAuthenticationMethod = "header";
         } else if ("body".equalsIgnoreCase(authMethod)) {
            config.clientAuthenticationMethod = "body";
         } else {
            config.clientAuthenticationMethod = "client_credentials".equalsIgnoreCase(config.grantType) ? "header" : "body";
         }

         if (actualClientId != null) {
            // Keep per-config credential values instead of forcing every config
            // through a shared {{client_id}} variable (which cross-contaminates
            // request-level OAuth configs that use different clients).
            config.clientId = clientIdVarName != null ? "{{" + clientIdVarName + "}}" : rawClientId;
         } else {
            config.clientId = null;
         }

         if (actualClientSecret != null) {
            // Same isolation rule for secrets: preserve the request's own
            // value unless the source already used an explicit variable.
            config.clientSecret = clientSecretVarName != null ? "{{" + clientSecretVarName + "}}" : rawClientSecret;
         } else {
            config.clientSecret = null;
         }

         config.scope = rawScope != null ? rawScope : actualScope;
         config.username = this.attr(config, "username");
         config.password = this.attr(config, "password");
         config.audience = this.attr(config, "audience");
         config.state = this.attr(config, "state");
         config.callbackUrl = this.firstNonBlank(
            this.attr(config, "callbackUrl"),
            this.attr(config, "redirect_uri"),
            this.attr(config, "redirectUri"),
            this.attr(config, "oauth2CallbackUrl"),
            this.attr(config, "oauth2Callback")
         );
         config.callbackUrl = normalizePostmanBrowserCallback(config.callbackUrl);
         if ((config.callbackUrl == null || config.callbackUrl.trim().isEmpty())
            && "true".equalsIgnoreCase(this.attr(config, "useBrowser"))) {
            config.callbackUrl = DEFAULT_BROWSER_CALLBACK_URL;
         }
         return config;
      } else {
         return null;
      }
   }

   private void putBootstrapVariable(String key, String value, String activeScope) {
      if (key == null || value == null) {
         return;
      }
      if (activeScope != null && !activeScope.trim().isEmpty()) {
         this.resolver.putScopedVariable(activeScope, key, value);
      } else {
         this.resolver.addCustomVariable(key, value);
      }
   }

   private void collectOAuth2Attributes(Object oauth2Data, OAuth2Config config) {
      if (oauth2Data != null) {
         JsonElement element = this.gson.toJsonTree(oauth2Data);
         if (element.isJsonArray()) {
            for (JsonElement child : element.getAsJsonArray()) {
               if (child.isJsonObject()) {
                  JsonObject obj = child.getAsJsonObject();
                  if (obj.has("key")) {
                     String key = obj.get("key").getAsString();
                     JsonElement vEl = obj.has("value") ? obj.get("value") : null;
                     String value;
                     if (vEl != null && !vEl.isJsonNull()) {
                        if (!vEl.isJsonPrimitive()) {
                           continue;
                        }

                        value = vEl.getAsString();
                     } else {
                        value = "";
                     }

                     config.rawAttributes.put(key, value);
                  }
               }
            }
         } else if (element.isJsonObject()) {
            JsonObject obj = element.getAsJsonObject();

            for (Entry<String, JsonElement> entry : obj.entrySet()) {
               JsonElement v = entry.getValue();
               String value;
               if (v != null && !v.isJsonNull()) {
                  if (!v.isJsonPrimitive()) {
                     // Bruno's OpenCollection format nests what other formats keep flat, e.g.
                     // credentials.clientId. Skipping these left the config half-empty with no
                     // hint as to why, so they are flattened instead.
                     this.collectNestedOAuth2Attributes(entry.getKey(), v, config);
                     continue;
                  }

                  value = v.getAsString();
               } else {
                  value = "";
               }

               config.rawAttributes.put(entry.getKey(), value);
            }

            this.applyNestedOAuth2Aliases(config);
         }
      }
   }

   /** Records a nested value under its dotted path so nothing is silently lost. */
   private void collectNestedOAuth2Attributes(String path, JsonElement value, OAuth2Config config) {
      if (value == null || value.isJsonNull()) return;

      if (value.isJsonPrimitive()) {
         config.rawAttributes.put(path, value.getAsString());
         return;
      }

      if (value.isJsonObject()) {
         JsonObject obj = value.getAsJsonObject();
         // An empty object is how OpenCollection says "enabled with defaults", as in `pkce: {}`.
         if (obj.entrySet().isEmpty()) {
            config.rawAttributes.put(path, "true");
            return;
         }
         for (Entry<String, JsonElement> entry : obj.entrySet()) {
            this.collectNestedOAuth2Attributes(path + "." + entry.getKey(), entry.getValue(), config);
         }
         return;
      }

      if (value.isJsonArray()) {
         int index = 0;
         for (JsonElement child : value.getAsJsonArray()) {
            // Name/value pairs read better under their own name than under an index.
            if (child != null && child.isJsonObject()) {
               JsonObject childObj = child.getAsJsonObject();
               String name = childObj.has("name") && childObj.get("name").isJsonPrimitive()
                  ? childObj.get("name").getAsString() : null;
               if (name != null && !name.trim().isEmpty()) {
                  this.collectNestedOAuth2Attributes(path + "." + name.trim(), child, config);
                  index++;
                  continue;
               }
            }
            this.collectNestedOAuth2Attributes(path + "[" + index + "]", child, config);
            index++;
         }
      }
   }

   /**
    * Maps the nested OpenCollection names onto the flat ones the rest of the detector reads, so
    * a Bruno YAML collection yields the same config as the equivalent Postman or Bruno JSON
    * export. Existing flat keys always win, since they were stated explicitly.
    */
   private void applyNestedOAuth2Aliases(OAuth2Config config) {
      alias(config, "credentials.clientId", "clientId");
      alias(config, "credentials.clientSecret", "clientSecret");
      alias(config, "credentials.placement", "client_authentication");
      alias(config, "credentials.scope", "scope");
      alias(config, "tokenConfig.id", "credentialsId");
      alias(config, "tokenConfig.source", "tokenSource");
      alias(config, "tokenConfig.placement.header", "headerPrefix");
      alias(config, "settings.autoFetchToken", "autoFetchToken");
      alias(config, "settings.autoRefreshToken", "autoRefreshToken");
      // `flow` is OpenCollection's spelling of the grant type.
      alias(config, "flow", "grant_type");

      // `pkce: {}` means enabled with defaults. Inline empty maps can survive YAML parsing as
      // the literal text "{}", so normalise it rather than leaving that on screen.
      String pkce = config.rawAttributes.get("pkce");
      if (pkce != null) {
         String trimmed = pkce.trim();
         if (trimmed.isEmpty() || "{}".equals(trimmed) || "[]".equals(trimmed)) {
            config.rawAttributes.put("pkce", "true");
         }
      }

      // `tokenConfig.placement: {header: ...}` means send the token as a header.
      if (config.rawAttributes.containsKey("tokenConfig.placement.header")
         && !config.rawAttributes.containsKey("addTokenTo")) {
         config.rawAttributes.put("addTokenTo", "header");
      }
   }

   private static void alias(OAuth2Config config, String from, String to) {
      String value = config.rawAttributes.get(from);
      if (value == null) return;
      String existing = config.rawAttributes.get(to);
      if (existing != null && !existing.trim().isEmpty()) return;
      config.rawAttributes.put(to, value);
   }

   private String attr(OAuth2Config config, String key) {
      if (config.rawAttributes.containsKey(key)) {
         return config.rawAttributes.get(key);
      } else {
         for (Entry<String, String> entry : config.rawAttributes.entrySet()) {
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(key)) {
               return entry.getValue();
            }
         }

         return null;
      }
   }

   private static String extractVarName(String s) {
      if (s == null) {
         return null;
      } else {
         int a = s.indexOf("{{");
         int b = s.indexOf("}}", a + 2);
         if (a >= 0 && b >= 0) {
            String n = s.substring(a + 2, b).trim();
            return n.isEmpty() ? null : n;
         } else {
            return null;
         }
      }
   }

   private String firstNonBlank(String... values) {
      if (values == null) {
         return null;
      } else {
         for (String value : values) {
            if (value != null && !value.trim().isEmpty()) {
               return value;
            }
         }
         return null;
      }
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

   private String resolveSafe(String value) {
      if (value == null || value.isEmpty()) {
         return value;
      } else if (this.resolver == null) {
         return value;
      } else {
         try {
            return this.resolver.resolve(value);
         } catch (Throwable var3) {
            return value;
         }
      }
   }

   private String signature(OAuth2Config config) {
      return this.safe(config.accessTokenUrl) + "|" + this.safe(config.grantType) + "|" + this.safe(config.clientId) + "|" + this.safe(config.scope);
   }

   private String safe(String value) {
      return value == null ? "" : value.trim().toLowerCase();
   }
}
