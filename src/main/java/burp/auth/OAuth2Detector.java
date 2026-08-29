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
                     continue;
                  }

                  value = v.getAsString();
               } else {
                  value = "";
               }

               config.rawAttributes.put(entry.getKey(), value);
            }
         }
      }
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
