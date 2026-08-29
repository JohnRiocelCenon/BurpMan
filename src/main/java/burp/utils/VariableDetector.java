package burp.utils;

import burp.api.montoya.MontoyaApi;
import burp.models.PostmanCollection;
import burp.models.VariableAnalysis;
import burp.parser.VariableResolver;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VariableDetector {
   private static final Pattern VARIABLE_PATTERN = Pattern.compile("\\{\\{([^}]+)\\}\\}");
   private final VariableResolver resolver;
   private final MontoyaApi api;
   private static final Pattern PM_SET_PATTERN = Pattern.compile(
      "pm\\s*\\.\\s*(?:variables|environment|collectionVariables|globals)\\s*\\.\\s*set\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]"
   );
   private static final Pattern POSTMAN_SET_PATTERN = Pattern.compile("postman\\s*\\.\\s*setEnvironmentVariable\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]");
   private static final Pattern POSTMAN_GLOBAL_SET = Pattern.compile("postman\\s*\\.\\s*setGlobalVariable\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]");

   public VariableDetector(VariableResolver resolver) {
      this.resolver = resolver;
      this.api = null;
   }

   public VariableDetector(VariableResolver resolver, MontoyaApi api) {
      this.resolver = resolver;
      this.api = api;
   }

   public VariableAnalysis analyzeCollection(PostmanCollection collection) {
      Set<String> unresolvedVariables = new HashSet<>();
      int totalRequests = 0;
      int requestsWithVariables = 0;
      Set<String> scriptDefinedNames = this.collectScriptDefinedVariableNames(collection);
      if (this.api != null) {
         this.api.logging().logToOutput("DEBUG VariableDetector: script-defined names = " + scriptDefinedNames);
      }

      for (VariableDetector.RequestItem item : this.flattenRequests(collection.item, "")) {
         totalRequests++;
         Set<String> requestVariables = this.findVariablesInRequest(item.request);
         if (!requestVariables.isEmpty()) {
            requestsWithVariables++;

            for (String variable : requestVariables) {
               if (!this.isPostmanDynamicVariable(variable) && !scriptDefinedNames.contains(variable)) {
                  String testValue = "{{" + variable + "}}";
                  String resolved = this.resolver.resolve(testValue);
                  boolean isUnresolved = testValue.equals(resolved) || resolved == null || resolved.trim().isEmpty();
                  if (isUnresolved) {
                     unresolvedVariables.add(variable);
                  }
               }
            }
         }
      }

      if (this.api != null) {
         this.api
            .logging()
            .logToOutput(
               "DEBUG VariableDetector: Analysis complete - totalRequests="
                  + totalRequests
                  + ", requestsWithVariables="
                  + requestsWithVariables
                  + ", unresolvedVariables="
                  + unresolvedVariables
            );
      }

      return new VariableAnalysis(unresolvedVariables, totalRequests, requestsWithVariables);
   }

   public Set<String> findAllVariablesInCollection(PostmanCollection collection) {
      Set<String> variables = new HashSet<>();
      if (collection == null) {
         return variables;
      } else {
         if (collection.variable != null) {
            for (PostmanCollection.Variable variable : collection.variable) {
               if (variable != null && variable.key != null && !variable.key.trim().isEmpty()) {
                  variables.add(variable.key.trim());
               }
            }
         }

         if (collection.auth != null) {
            variables.addAll(this.findVariablesInAuth(collection.auth));
         }

         this.collectVariablesFromItems(collection.item, variables);
         return variables;
      }
   }

   private void collectVariablesFromItems(List<PostmanCollection.Item> items, Set<String> variables) {
      if (items != null) {
         for (PostmanCollection.Item item : items) {
            if (item != null) {
               if (item.auth != null) {
                  variables.addAll(this.findVariablesInAuth(item.auth));
               }

               if (item.request != null) {
                  variables.addAll(this.findVariablesInRequest(item.request));
               }

               if (item.item != null && !item.item.isEmpty()) {
                  this.collectVariablesFromItems(item.item, variables);
               }
            }
         }
      }
   }

   public Set<String> findVariablesInRequest(PostmanCollection.Request request) {
      Set<String> variables = new HashSet<>();
      String rawUrl = this.extractRawUrl(request.url);
      if (rawUrl != null) {
         Set<String> urlVars = this.extractVariables(rawUrl);
         variables.addAll(urlVars);
         if (this.api != null) {
            this.api.logging().logToOutput("DEBUG VariableDetector: URL variables=" + urlVars + " from rawUrl=" + rawUrl);
         }
      } else if (this.api != null) {
         this.api.logging().logToOutput("DEBUG VariableDetector: Could not extract raw URL from=" + request.url);
      }

      if (request.header != null) {
         for (PostmanCollection.Header header : request.header) {
            if (header.key != null) {
               variables.addAll(this.extractVariables(header.key));
            }

            if (header.value != null) {
               variables.addAll(this.extractVariables(header.value));
            }
         }
      }

      if (request.body != null) {
         if (request.body.raw != null) {
            Set<String> bodyVars = this.extractVariables(request.body.raw);
            variables.addAll(bodyVars);
            if (this.api != null && !bodyVars.isEmpty()) {
               this.api.logging().logToOutput("DEBUG VariableDetector: Raw body variables=" + bodyVars);
            }
         }

         if ("graphql".equals(request.body.mode) && request.body.graphql != null) {
            Set<String> graphqlVars = this.findVariablesInGraphQL(request.body.graphql);
            variables.addAll(graphqlVars);
            if (this.api != null) {
               this.api.logging().logToOutput("DEBUG VariableDetector: GraphQL body detected - found variables=" + graphqlVars);
            }
         }
      }

      if (request.auth != null) {
         variables.addAll(this.findVariablesInAuth(request.auth));
      }

      if (this.api != null) {
         this.api.logging().logToOutput("DEBUG VariableDetector: Total variables found in request=" + variables);
      }

      return variables;
   }

   public Set<String> findVariablesInGraphQL(PostmanCollection.GraphQL graphql) {
      Set<String> variables = new HashSet<>();
      if (graphql.query != null) {
         Set<String> queryVars = this.extractVariables(graphql.query);
         variables.addAll(queryVars);
         if (this.api != null) {
            this.api.logging().logToOutput("DEBUG VariableDetector: GraphQL query variables=" + queryVars);
         }
      }

      if (graphql.variables != null) {
         Set<String> variableVars = this.extractVariables(graphql.variables);
         variables.addAll(variableVars);
         if (this.api != null) {
            this.api.logging().logToOutput("DEBUG VariableDetector: GraphQL variables field variables=" + variableVars);
         }
      }

      if (this.api != null) {
         this.api.logging().logToOutput("DEBUG VariableDetector: Total GraphQL variables found=" + variables);
      }

      return variables;
   }

   public Set<String> findVariablesInAuth(PostmanCollection.Auth auth) {
      Set<String> variables = new HashSet<>();
      if (auth.bearer != null) {
         variables.addAll(this.extractVariablesFromAuthData(auth.bearer));
      }

      if (auth.basic != null) {
         variables.addAll(this.extractVariablesFromAuthData(auth.basic));
      }

      if (auth.apikey != null) {
         variables.addAll(this.extractVariablesFromAuthData(auth.apikey));
      }

      return variables;
   }

   private Set<String> extractVariablesFromAuthData(Object authData) {
      Set<String> variables = new HashSet<>();
      this.collectVariablesFromAnyObject(authData, variables);
      return variables;
   }

   private void collectVariablesFromAnyObject(Object data, Set<String> variables) {
      if (data != null) {
         if (data instanceof String) {
            variables.addAll(this.extractVariables((String)data));
         } else if (data instanceof Map) {
            Map<?, ?> map = (Map<?, ?>)data;

            for (Object value : map.values()) {
               this.collectVariablesFromAnyObject(value, variables);
            }
         } else if (data instanceof Iterable) {
            for (Object item : (Iterable)data) {
               this.collectVariablesFromAnyObject(item, variables);
            }
         } else if (!data.getClass().isArray()) {
            try {
               Gson gson = new Gson();
               JsonElement element = gson.toJsonTree(data);
               this.collectVariablesFromJsonElement(element, variables);
            } catch (Exception var8) {
               variables.addAll(this.extractVariables(data.toString()));
            }
         } else {
            Object[] array = (Object[])data;

            for (Object item : array) {
               this.collectVariablesFromAnyObject(item, variables);
            }
         }
      }
   }

   private void collectVariablesFromJsonElement(JsonElement element, Set<String> variables) {
      if (element != null && !element.isJsonNull()) {
         if (element.isJsonPrimitive()) {
            variables.addAll(this.extractVariables(element.getAsString()));
         } else if (element.isJsonArray()) {
            for (JsonElement item : element.getAsJsonArray()) {
               this.collectVariablesFromJsonElement(item, variables);
            }
         } else {
            if (element.isJsonObject()) {
               for (Entry<String, JsonElement> entry : element.getAsJsonObject().entrySet()) {
                  this.collectVariablesFromJsonElement(entry.getValue(), variables);
               }
            }
         }
      }
   }

   private Set<String> extractVariables(String text) {
      Set<String> variables = new HashSet<>();
      if (text == null) {
         return variables;
      } else {
         Matcher matcher = VARIABLE_PATTERN.matcher(text);

         while (matcher.find()) {
            variables.add(matcher.group(1));
         }

         return variables;
      }
   }

   private String extractRawUrl(Object urlData) {
      if (urlData == null) {
         return null;
      } else if (urlData instanceof String) {
         return (String)urlData;
      } else {
         try {
            Gson gson = new Gson();
            JsonElement element = gson.toJsonTree(urlData);
            if (element.isJsonObject()) {
               JsonObject urlObject = element.getAsJsonObject();
               if (urlObject.has("raw")) {
                  String rawUrl = urlObject.get("raw").getAsString();
                  if (this.api != null) {
                     this.api.logging().logToOutput("DEBUG VariableDetector: Successfully extracted raw URL=" + rawUrl);
                  }

                  return rawUrl;
               }
            }
         } catch (Exception var6) {
            if (this.api != null) {
               this.api.logging().logToOutput("DEBUG VariableDetector: Failed to parse URL object, error=" + var6.getMessage());
            }
         }

         return urlData.toString();
      }
   }

   private List<VariableDetector.RequestItem> flattenRequests(List<PostmanCollection.Item> items, String path) {
      List<VariableDetector.RequestItem> requests = new ArrayList<>();
      if (items == null) {
         return requests;
      } else {
         for (PostmanCollection.Item item : items) {
            String currentPath = path.isEmpty() ? item.name : path + "/" + item.name;
            if (item.request != null) {
               requests.add(new VariableDetector.RequestItem(item.name, currentPath, item.request));
            }

            if (item.item != null && !item.item.isEmpty()) {
               requests.addAll(this.flattenRequests(item.item, currentPath));
            }
         }

         return requests;
      }
   }

   public Map<String, String> generateVariableSuggestions(Set<String> variables) {
      Map<String, String> suggestions = new HashMap<>();

      for (String variable : variables) {
         String suggestion = this.suggestValueForVariable(variable);
         if (suggestion != null) {
            suggestions.put(variable, suggestion);
         }
      }

      return suggestions;
   }

   private boolean isPostmanDynamicVariable(String variable) {
      if (variable == null) {
         return false;
      } else {
         String raw = variable.trim();
         String lowered = raw.toLowerCase(Locale.ROOT);
         if (!"date.today".equals(lowered) && !"date.yesterday".equals(lowered) && !"date.tomorrow".equals(lowered)) {
            String name = raw;
            int colon = raw.indexOf(58);
            if (colon > 0) {
               name = raw.substring(0, colon);
            }

            int paren = name.indexOf(40);
            if (paren > 0) {
               name = name.substring(0, paren);
            }

            if (!name.startsWith("$")) {
               return false;
            } else {
               String v = name.toLowerCase();
               switch (v.hashCode()) {
                  case -2077802411:
                     if (v.equals("$isotimestamp")) {
                        return true;
                     }
                     break;
                  case -990300920:
                     if (v.equals("$randomlastname")) {
                        return true;
                     }
                     break;
                  case -751464351:
                     if (v.equals("$randomboolean")) {
                        return true;
                     }
                     break;
                  case -393451186:
                     if (v.equals("$randomip")) {
                        return true;
                     }
                     break;
                  case -342218219:
                     if (v.equals("$randomemail")) {
                        return true;
                     }
                     break;
                  case -149463988:
                     if (v.equals("$randomipv4")) {
                        return true;
                     }
                     break;
                  case -149102046:
                     if (v.equals("$randomuuid")) {
                        return true;
                     }
                     break;
                  case 36431021:
                     if (v.equals("$guid")) {
                        return true;
                     }
                     break;
                  case 687915176:
                     if (v.equals("$randomint")) {
                        return true;
                     }
                     break;
                  case 1148214102:
                     if (v.equals("$randomalphanumeric")) {
                        return true;
                     }
                     break;
                  case 1570574706:
                     if (v.equals("$timestamp")) {
                        return true;
                     }
                     break;
                  case 1685331330:
                     if (v.equals("$randompassword")) {
                        return true;
                     }
                     break;
                  case 1767599924:
                     if (v.equals("$randomfirstname")) {
                        return true;
                     }
                     break;
                  case 1800151169:
                     if (v.equals("$randomfullname")) {
                        return true;
                     }
               }

               return v.startsWith("$random") || v.startsWith("$timestamp");
            }
         } else {
            return true;
         }
      }
   }

   private Set<String> collectScriptDefinedVariableNames(PostmanCollection collection) {
      Set<String> names = new HashSet<>();
      if (collection == null) {
         return names;
      } else {
         this.scrapeEvents(collection.event, names);
         this.scrapeItemsRecursive(collection.item, names);
         return names;
      }
   }

   private void scrapeItemsRecursive(List<PostmanCollection.Item> items, Set<String> out) {
      if (items != null) {
         for (PostmanCollection.Item it : items) {
            if (it != null) {
               this.scrapeEvents(it.event, out);
               if (it.item != null) {
                  this.scrapeItemsRecursive(it.item, out);
               }
            }
         }
      }
   }

   private void scrapeEvents(List<PostmanCollection.Event> events, Set<String> out) {
      if (events != null) {
         for (PostmanCollection.Event ev : events) {
            if (ev != null && ev.script != null && ev.script.exec != null) {
               StringBuilder src = new StringBuilder();

               for (String line : ev.script.exec) {
                  src.append(line == null ? "" : line).append('\n');
               }

               String s = src.toString();
               this.scrapeAll(s, PM_SET_PATTERN, out);
               this.scrapeAll(s, POSTMAN_SET_PATTERN, out);
               this.scrapeAll(s, POSTMAN_GLOBAL_SET, out);
            }
         }
      }
   }

   private void scrapeAll(String src, Pattern p, Set<String> out) {
      Matcher m = p.matcher(src);

      while (m.find()) {
         String name = m.group(1);
         if (name != null && !name.trim().isEmpty()) {
            out.add(name.trim());
         }
      }
   }

   private String suggestValueForVariable(String variable) {
      String lowerVar = variable.toLowerCase();
      if (lowerVar.contains("url") || lowerVar.contains("host") || lowerVar.contains("domain")) {
         return "https://api.example.com";
      } else if (lowerVar.contains("base") && lowerVar.contains("url")) {
         return "https://api.example.com";
      } else if (lowerVar.contains("token") || lowerVar.contains("access")) {
         return "your_access_token_here";
      } else if (lowerVar.contains("key") && lowerVar.contains("api")) {
         return "your_api_key_here";
      } else if (lowerVar.contains("bearer")) {
         return "your_bearer_token";
      } else if (lowerVar.contains("id")) {
         return "12345";
      } else if (lowerVar.contains("env")) {
         return "production";
      } else {
         return lowerVar.contains("timeout") ? "5000" : null;
      }
   }

   private static class RequestItem {
      final String name;
      final String path;
      final PostmanCollection.Request request;

      RequestItem(String name, String path, PostmanCollection.Request request) {
         this.name = name;
         this.path = path;
         this.request = request;
      }
   }
}
