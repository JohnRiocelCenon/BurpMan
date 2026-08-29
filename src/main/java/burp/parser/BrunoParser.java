package burp.parser;

import burp.models.PostmanCollection;
import burp.models.PostmanEnvironment;
import com.google.gson.JsonElement;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.File;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BrunoParser {
   private static final Set<String> METHODS = new LinkedHashSet<>(Arrays.asList("get", "post", "put", "patch", "delete", "head", "options"));

   public PostmanCollection parseCollection(File input) throws Exception {
      PostmanCollection collection = new PostmanCollection();
      collection.info = new PostmanCollection.Info();
      collection.info.name = input.isDirectory() ? input.getName() : this.stripExtension(input.getName());
      collection.item = new ArrayList<>();
      collection.variable = new ArrayList<>();
      if (input.isDirectory()) {
         File collMeta = new File(input, "collection.bru");
         if (collMeta.isFile()) {
            this.applyCollectionMeta(collection, this.readFileUtf8(collMeta));
         }
         File openColl = new File(input, "opencollection.yml");
         if (openColl.isFile()) {
            BrunoYamlParser.applyCollectionMeta(collection, openColl);
         }

         this.parseDirectory(input, collection.item, collection);
      } else {
         CollectionFormatDetector.Format format = CollectionFormatDetector.detect(input);
         switch (format) {
            case BRUNO_COLLECTION_JSON:
               return this.parseBrunoCollectionJson(input);
            case BRUNO_OPENCOLLECTION_YAML:
               return BrunoYamlParser.parseBundledCollection(input);
            case BRUNO_REQUEST_BRU:
               String lower = input.getName().toLowerCase(Locale.ROOT);
               PostmanCollection.Item item;
               if (lower.endsWith(".yml") || lower.endsWith(".yaml")) {
                  item = BrunoYamlParser.parseRequestFile(input);
               } else {
                  item = this.parseRequestFile(input);
               }
               if (item != null) {
                  collection.item.add(item);
               }
               break;
            default:
               break;
         }
      }

      return collection;
   }

   public PostmanEnvironment parseEnvironment(File envFile) throws Exception {
      String lower = envFile.getName().toLowerCase(Locale.ROOT);
      if (lower.endsWith(".json")) {
         return this.parseJsonEnvironment(envFile);
      } else if (lower.endsWith(".yml") || lower.endsWith(".yaml")) {
         return BrunoYamlParser.parseEnvironment(envFile);
      } else {
         String content = this.readFileUtf8(envFile);
         Map<String, String> all = new LinkedHashMap<>();
         all.putAll(this.parseKeyValueBlock(content, "vars"));
         all.putAll(this.parseKeyValueBlock(content, "vars:secret"));
         // Fallback for plain-text env files (.env or extensionless like the
         // one Bruno CLI writes when you run `bru env export --output env.txt`,
         // or a hand-written key:value list). Recognized shapes:
         //   KEY: VALUE      (colon)
         //   KEY = VALUE     (equals with spaces)
         //   KEY=VALUE       (dotenv style)
         //   # comment       (skipped)
         //   [SECTION]       (skipped — some Bruno users group by env)
         // We only fall through here if the `vars { }` block-style parse
         // above found nothing, so real .bru env files still take priority.
         if (all.isEmpty()) {
            all.putAll(this.parseDotEnvContent(content));
         }
         return this.toEnvironment(this.stripExtension(envFile.getName()), all);
      }
   }

   /** Parses plain-text env files with {@code KEY: VALUE}, {@code KEY = VALUE},
    *  or {@code KEY=VALUE} lines. Ignores {@code #} comments, blank lines, and
    *  {@code [section]} headers. Values are trimmed and un-quoted if wrapped in
    *  matching {@code "..."} or {@code '...'} quotes. Duplicate keys keep the
    *  last-seen value (dotenv convention). */
   private Map<String, String> parseDotEnvContent(String content) {
      Map<String, String> out = new LinkedHashMap<>();
      if (content == null || content.isEmpty()) return out;
      for (String rawLine : content.split("\\R", -1)) {
         String line = rawLine.trim();
         if (line.isEmpty()) continue;
         if (line.startsWith("#") || line.startsWith(";") || line.startsWith("//")) continue;
         if (line.startsWith("[") && line.endsWith("]")) continue;
         // Strip trailing inline comment (only if preceded by whitespace, so
         // values containing `#` character like URLs with fragments are safe).
         int cut = -1;
         boolean inS = false, inD = false;
         for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"' && !inS) inD = !inD;
            else if (c == '\'' && !inD) inS = !inS;
            else if (c == '#' && !inS && !inD && i > 0 && Character.isWhitespace(line.charAt(i-1))) {
               cut = i; break;
            }
         }
         if (cut >= 0) line = line.substring(0, cut).trim();
         // Split on first `:` or `=` (whichever comes first, honoring quotes).
         int sep = -1;
         char sepCh = 0;
         boolean sIn = false, dIn = false;
         for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"' && !sIn) dIn = !dIn;
            else if (c == '\'' && !dIn) sIn = !sIn;
            else if ((c == ':' || c == '=') && !sIn && !dIn) {
               sep = i; sepCh = c; break;
            }
         }
         if (sep <= 0) continue;
         String key = line.substring(0, sep).trim();
         String val = line.substring(sep + 1).trim();
         if (key.isEmpty()) continue;
         if (val.length() >= 2) {
            char f = val.charAt(0), l = val.charAt(val.length() - 1);
            if ((f == '"' && l == '"') || (f == '\'' && l == '\'')) {
               val = val.substring(1, val.length() - 1);
            }
         }
         out.put(key, val);
      }
      return out;
   }

   private void applyCollectionMeta(PostmanCollection collection, String content) {
      Map<String, String> vars = new LinkedHashMap<>();
      vars.putAll(this.parseKeyValueBlock(content, "vars"));
      vars.putAll(this.parseKeyValueBlock(content, "vars:pre-request"));

      for (Entry<String, String> e : vars.entrySet()) {
         PostmanCollection.Variable v = new PostmanCollection.Variable();
         v.key = e.getKey();
         v.value = e.getValue();
         v.type = "text";
         collection.variable.add(v);
      }

      PostmanCollection.Auth auth = this.parseAuthFromContent(content);
      if (auth != null) {
         collection.auth = auth;
      }

      List<PostmanCollection.Event> events = this.parseScripts(content);
      if (!events.isEmpty()) {
         collection.event = events;
      }
   }

   private PostmanEnvironment parseJsonEnvironment(File file) throws Exception {
      Map<String, String> variables = new LinkedHashMap<>();

      try (FileReader reader = new FileReader(file)) {
         JsonElement element = JsonParser.parseReader(reader);
         if (element.isJsonObject()) {
            JsonObject object = element.getAsJsonObject();
            JsonObject source = null;
            if (object.has("vars") && object.get("vars").isJsonObject()) {
               source = object.getAsJsonObject("vars");
            } else if (object.has("variables") && object.get("variables").isJsonObject()) {
               source = object.getAsJsonObject("variables");
            }

            if (source != null) {
               for (Entry<String, JsonElement> entry : source.entrySet()) {
                  JsonElement value = entry.getValue();
                  variables.put(
                     entry.getKey(), value != null && !value.isJsonNull() ? (value.isJsonPrimitive() ? value.getAsString() : value.toString()) : ""
                  );
               }
            } else if (object.has("variables") && object.get("variables").isJsonArray()) {
               // Bruno v3.3.0 environment export format:
               //   { "name": "UAT",
               //     "variables": [ {"name":"...","value":"...","enabled":true,"secret":false} ],
               //     "info": { "type":"bruno-environment", ... } }
               for (JsonElement entry : object.getAsJsonArray("variables")) {
                  if (entry == null || !entry.isJsonObject()) continue;
                  JsonObject v = entry.getAsJsonObject();
                  String name = v.has("name") && !v.get("name").isJsonNull() ? v.get("name").getAsString() : null;
                  if (name == null || name.trim().isEmpty()) continue;
                  if (v.has("enabled") && !v.get("enabled").isJsonNull() && !v.get("enabled").getAsBoolean()) continue;
                  JsonElement val = v.get("value");
                  String s = val == null || val.isJsonNull() ? "" : (val.isJsonPrimitive() ? val.getAsString() : val.toString());
                  variables.put(name, s);
               }
            }
         }
      }

      return this.toEnvironment(this.stripExtension(file.getName()), variables);
   }

   private PostmanCollection parseBrunoCollectionJson(File file) throws Exception {
      try (FileReader reader = new FileReader(file)) {
         JsonElement element = JsonParser.parseReader(reader);
         if (!element.isJsonObject()) {
            throw new IllegalArgumentException("Not a Bruno collection JSON: " + file.getName());
         }

         JsonObject root = element.getAsJsonObject();
         JsonArray items = root.has("items") && root.get("items").isJsonArray() ? root.getAsJsonArray("items") : null;
         if (items == null) {
            throw new IllegalArgumentException("Not a Bruno collection JSON: " + file.getName());
         }

         PostmanCollection collection = new PostmanCollection();
         collection.info = new PostmanCollection.Info();
         collection.info.name = this.stringValue(root.get("name"));
         if (collection.info.name == null || collection.info.name.trim().isEmpty()) {
            collection.info.name = this.stripExtension(file.getName());
         }
         collection.item = new ArrayList<>();
         collection.variable = new ArrayList<>();
         // Collection-root `root.request.script` / `root.request.auth` — some
         // Bruno exports put the JWT-signing pre-request script at collection
         // level (not folder level). Cascade it into `collection.event`
         // so `getScriptsForPath` picks it up for every request.
         JsonObject collectionRootRequest = this.extractRootRequest(root);
         if (collectionRootRequest != null) {
            List<PostmanCollection.Event> collectionEvents = this.parseBrunoJsonScripts(collectionRootRequest, null);
            if (!collectionEvents.isEmpty()) {
               collection.event = collectionEvents;
            }
            PostmanCollection.Auth collectionAuth = this.parseBrunoAuth(collectionRootRequest.get("auth"));
            if (collectionAuth != null) {
               collection.auth = collectionAuth;
            }
         }
         this.parseBrunoJsonItems(items, collection.item);
         return collection;
      }
   }

   /** Bruno's JSON export nests folder-level and collection-level metadata under
    *  {@code root.request}. Returns that nested request object (or null if
    *  the wrapper isn't there). Used to cascade folder scripts + auth into
    *  the tree so JWT-signing pre-request blocks run for every child request. */
   private JsonObject extractRootRequest(JsonObject node) {
      if (node == null || !node.has("root")) {
         return null;
      }
      JsonElement rootElement = node.get("root");
      if (rootElement == null || !rootElement.isJsonObject()) {
         return null;
      }
      JsonObject rootObject = rootElement.getAsJsonObject();
      if (!rootObject.has("request") || !rootObject.get("request").isJsonObject()) {
         return null;
      }
      return rootObject.getAsJsonObject("request");
   }

   private void parseBrunoJsonItems(JsonArray items, List<PostmanCollection.Item> sink) {
      if (items == null || sink == null) {
         return;
      }

      for (JsonElement element : items) {
         if (element != null && element.isJsonObject()) {
            PostmanCollection.Item parsed = this.parseBrunoJsonItem(element.getAsJsonObject());
            if (parsed != null) {
               sink.add(parsed);
            }
         }
      }
   }

   private PostmanCollection.Item parseBrunoJsonItem(JsonObject object) {
      if (object == null) {
         return null;
      }

      JsonArray children = object.has("items") && object.get("items").isJsonArray() ? object.getAsJsonArray("items") : null;
      JsonObject requestObject = object.has("request") && object.get("request").isJsonObject() ? object.getAsJsonObject("request") : null;

      if (requestObject == null && children != null) {
         PostmanCollection.Item folder = new PostmanCollection.Item();
         folder.name = this.firstNonBlank(this.stringValue(object.get("name")), this.stringValue(object.get("filename")), "Folder");
         folder.item = new ArrayList<>();
         // Bruno folders can carry a folder-level `root.request.script` (typically
         // the JWT-signing pre-request block that every child request cascades
         // through) and a folder-level `root.request.auth` block ("inherit" auth
         // for children). Without this we lose the cascade and every child
         // request drops its Bearer token.
         JsonObject folderRootRequest = this.extractRootRequest(object);
         if (folderRootRequest != null) {
            List<PostmanCollection.Event> folderEvents = this.parseBrunoJsonScripts(folderRootRequest, null);
            if (!folderEvents.isEmpty()) {
               folder.event = folderEvents;
            }
            PostmanCollection.Auth folderAuth = this.parseBrunoAuth(folderRootRequest.get("auth"));
            if (folderAuth != null) {
               folder.auth = folderAuth;
            }
         }
         this.parseBrunoJsonItems(children, folder.item);
         return folder.item.isEmpty() ? null : folder;
      } else if (requestObject == null) {
         return null;
      } else {
         PostmanCollection.Item item = new PostmanCollection.Item();
         item.name = this.firstNonBlank(this.stringValue(object.get("name")), this.stringValue(object.get("filename")), "Request");
         item.request = new PostmanCollection.Request();
         item.request.method = this.firstNonBlank(this.stringValue(requestObject.get("method")), "GET").toUpperCase(Locale.ROOT);
         item.request.url = this.parseBrunoUrl(requestObject.get("url"));
         item.request.header = this.parseBrunoHeaders(requestObject.get("headers"));
         item.request.body = this.parseBrunoBody(requestObject.get("body"));
         item.request.auth = this.parseBrunoAuth(requestObject.get("auth"));
         item.request.description = this.stringValue(requestObject.get("docs"));

         List<PostmanCollection.Event> events = this.parseBrunoJsonScripts(requestObject, object);
         if (!events.isEmpty()) {
            item.event = events;
         }

         String docs = this.firstNonBlank(this.stringValue(object.get("docs")), this.stringValue(object.get("description")));
         if (docs != null) {
            item.description = docs;
         }

         return item;
      }
   }

   private String parseBrunoUrl(JsonElement urlElement) {
      if (urlElement == null || urlElement.isJsonNull()) {
         return "";
      }

      if (urlElement.isJsonPrimitive()) {
         return urlElement.getAsString();
      }

      if (!urlElement.isJsonObject()) {
         return urlElement.toString();
      }

      JsonObject object = urlElement.getAsJsonObject();
      String raw = this.stringValue(object.get("raw"));
      if (raw != null && !raw.trim().isEmpty()) {
         return raw.trim();
      }

      String protocol = this.stringValue(object.get("protocol"));
      String host = this.joinJsonStringArray(object.getAsJsonArray("host"), ".");
      String path = this.joinJsonStringArray(object.getAsJsonArray("path"), "/");
      StringBuilder url = new StringBuilder();
      if (protocol != null && !protocol.trim().isEmpty()) {
         url.append(protocol.trim()).append("://");
      }
      if (host != null) {
         url.append(host);
      }
      if (path != null && !path.isEmpty()) {
         if (!path.startsWith("/")) {
            url.append('/');
         }
         url.append(path);
      }

      String query = this.joinBrunoQuery(object.getAsJsonArray("query"));
      if (!query.isEmpty()) {
         url.append(url.indexOf("?") >= 0 ? "&" : "?").append(query);
      }

      return url.toString();
   }

   private List<PostmanCollection.Header> parseBrunoHeaders(JsonElement headersElement) {
      List<PostmanCollection.Header> headers = new ArrayList<>();
      if (headersElement == null || !headersElement.isJsonArray()) {
         return headers;
      }

      for (JsonElement element : headersElement.getAsJsonArray()) {
         if (element != null && element.isJsonObject()) {
            JsonObject headerObject = element.getAsJsonObject();
            PostmanCollection.Header header = new PostmanCollection.Header();
            header.key = this.stringValue(headerObject.get("name"));
            header.value = this.stringValue(headerObject.get("value"));
            header.disabled = headerObject.has("enabled") && !headerObject.get("enabled").isJsonNull() && !headerObject.get("enabled").getAsBoolean();
            header.type = this.stringValue(headerObject.get("type"));
            if (header.key != null && !header.key.trim().isEmpty()) {
               headers.add(header);
            }
         }
      }

      return headers;
   }

   private PostmanCollection.Body parseBrunoBody(JsonElement bodyElement) {
      if (bodyElement == null || !bodyElement.isJsonObject()) {
         return null;
      }

      JsonObject bodyObject = bodyElement.getAsJsonObject();
      String mode = this.stringValue(bodyObject.get("mode"));
      if (mode == null || mode.trim().isEmpty() || "none".equalsIgnoreCase(mode)) {
         return null;
      }

      if ("json".equalsIgnoreCase(mode) || "text".equalsIgnoreCase(mode) || "xml".equalsIgnoreCase(mode) || "sparql".equalsIgnoreCase(mode)) {
         String raw = this.stringValue(bodyObject.get(mode));
         if (raw == null || raw.trim().isEmpty()) {
            return null;
         }

         PostmanCollection.Body body = new PostmanCollection.Body();
         body.mode = "raw";
         body.raw = raw.trim();
         body.options = new PostmanCollection.Options();
         body.options.raw = new PostmanCollection.Raw();
         body.options.raw.language = "json".equalsIgnoreCase(mode) ? "json" : mode.toLowerCase(Locale.ROOT);
         return body;
      }

      if ("formUrlEncoded".equalsIgnoreCase(mode)) {
         JsonArray entries = bodyObject.has("formUrlEncoded") && bodyObject.get("formUrlEncoded").isJsonArray()
            ? bodyObject.getAsJsonArray("formUrlEncoded")
            : null;
         return this.parseBrunoFormEntries(entries, "urlencoded");
      }

      if ("multipartForm".equalsIgnoreCase(mode)) {
         JsonArray entries = bodyObject.has("multipartForm") && bodyObject.get("multipartForm").isJsonArray()
            ? bodyObject.getAsJsonArray("multipartForm")
            : null;
         return this.parseBrunoMultipartEntries(entries);
      }

      if ("file".equalsIgnoreCase(mode)) {
         PostmanCollection.Body body = new PostmanCollection.Body();
         body.mode = "formdata";
         body.formdata = new ArrayList<>();
         PostmanCollection.FormData file = new PostmanCollection.FormData();
         file.key = "file";
         file.type = "file";
         file.src = this.stringValue(bodyObject.get("file"));
         body.formdata.add(file);
         return body;
      }

      return null;
   }

   private PostmanCollection.Body parseBrunoFormEntries(JsonArray entries, String mode) {
      if (entries == null || !entries.isJsonArray()) {
         return null;
      }

      PostmanCollection.Body body = new PostmanCollection.Body();
      body.mode = mode;
      body.urlencoded = new ArrayList<>();
      for (JsonElement element : entries) {
         if (element != null && element.isJsonObject()) {
            JsonObject entry = element.getAsJsonObject();
            String key = this.stringValue(entry.get("name"));
            if (key == null || key.trim().isEmpty()) {
               continue;
            }

            PostmanCollection.UrlEncoded form = new PostmanCollection.UrlEncoded();
            form.key = key;
            form.value = this.stringValue(entry.get("value"));
            form.disabled = entry.has("enabled") && !entry.get("enabled").isJsonNull() && !entry.get("enabled").getAsBoolean();
            form.type = this.stringValue(entry.get("type"));
            body.urlencoded.add(form);
         }
      }

      return body.urlencoded.isEmpty() ? null : body;
   }

   private PostmanCollection.Body parseBrunoMultipartEntries(JsonArray entries) {
      if (entries == null || !entries.isJsonArray()) {
         return null;
      }

      PostmanCollection.Body body = new PostmanCollection.Body();
      body.mode = "formdata";
      body.formdata = new ArrayList<>();
      for (JsonElement element : entries) {
         if (element != null && element.isJsonObject()) {
            JsonObject entry = element.getAsJsonObject();
            String key = this.stringValue(entry.get("name"));
            if (key == null || key.trim().isEmpty()) {
               continue;
            }

            PostmanCollection.FormData form = new PostmanCollection.FormData();
            form.key = key;
            form.disabled = entry.has("enabled") && !entry.get("enabled").isJsonNull() && !entry.get("enabled").getAsBoolean();
            form.type = this.firstNonBlank(this.stringValue(entry.get("type")), "text");
            if ("file".equalsIgnoreCase(form.type)) {
               String src = this.firstNonBlank(this.stringValue(entry.get("src")), this.stringValue(entry.get("value")));
               form.src = src;
            } else {
               form.value = this.stringValue(entry.get("value"));
            }
            body.formdata.add(form);
         }
      }

      return body.formdata.isEmpty() ? null : body;
   }

   private PostmanCollection.Auth parseBrunoAuth(JsonElement authElement) {
      if (authElement == null || !authElement.isJsonObject()) {
         return null;
      }

      JsonObject authObject = authElement.getAsJsonObject();
      String mode = this.stringValue(authObject.get("mode"));
      if (mode == null || mode.trim().isEmpty() || "inherit".equalsIgnoreCase(mode)) {
         return null;
      }

      PostmanCollection.Auth auth = new PostmanCollection.Auth();
      auth.type = mode.toLowerCase(Locale.ROOT);
      switch (auth.type) {
         case "bearer":
            auth.bearer = this.authAttributes(new String[][]{{"token", this.extractAuthValue(authObject, "bearer", "token")}});
            break;
         case "basic":
            auth.basic = this.authAttributes(
               new String[][]{
                  {"username", this.extractAuthValue(authObject, "basic", "username")},
                  {"password", this.extractAuthValue(authObject, "basic", "password")}
               }
            );
            break;
         case "apikey":
         case "api-key":
            auth.apikey = this.authAttributes(
               new String[][]{
                  {"key", this.extractAuthValue(authObject, "apikey", "key")},
                  {"value", this.extractAuthValue(authObject, "apikey", "value")},
                  {"in", this.extractAuthValue(authObject, "apikey", "in")}
               }
            );
            break;
         default:
            break;
      }

      return auth;
   }

   private List<PostmanCollection.Event> parseBrunoJsonScripts(JsonObject requestObject, JsonObject itemObject) {
      List<PostmanCollection.Event> events = new ArrayList<>();
      if (requestObject != null) {
         JsonObject scriptObject = requestObject.has("script") && requestObject.get("script").isJsonObject()
            ? requestObject.getAsJsonObject("script")
            : null;
         // Bruno's collection.json export uses short-form "req"/"res" keys
         // (Bruno CLI ≥ 1.x) alongside the older long-form "pre-request"/"post-response"
         // shape. Both must be recognised or JWT-signing pre-request scripts (which
         // is how Bruno collections typically wire Authorization: Bearer) get
         // silently dropped and every request goes out unauthenticated.
         String pre = this.scriptText(scriptObject, "req", "pre-request", "preRequest", "prerequest");
         String post = this.scriptText(scriptObject, "res", "post-response", "postResponse", "postresponse");
         String tests = this.firstNonBlank(this.scriptText(scriptObject, "tests", "test"), this.stringValue(requestObject.get("tests")));

         String varsScript = this.brunoVarsToScript(requestObject.has("vars") && requestObject.get("vars").isJsonObject()
            ? requestObject.getAsJsonObject("vars")
            : null);
         if (varsScript != null && !varsScript.trim().isEmpty()) {
            events.add(this.scriptEvent("test", varsScript));
         }

         if (pre != null && !pre.trim().isEmpty()) {
            events.add(this.scriptEvent("prerequest", pre));
         }
         if (post != null && !post.trim().isEmpty()) {
            events.add(this.scriptEvent("test", post));
         }
         if (tests != null && !tests.trim().isEmpty()) {
            events.add(this.scriptEvent("test", tests));
         }
      }

      if (itemObject != null) {
         String itemTests = this.stringValue(itemObject.get("tests"));
         if (itemTests != null && !itemTests.trim().isEmpty()) {
            events.add(this.scriptEvent("test", itemTests));
         }
      }

      return events;
   }

   private String brunoVarsToScript(JsonObject varsObject) {
      if (varsObject == null || varsObject.entrySet().isEmpty()) {
         return null;
      }

      StringBuilder script = new StringBuilder();
      for (Entry<String, JsonElement> entry : varsObject.entrySet()) {
         JsonElement value = entry.getValue();
         if (value == null || !value.isJsonArray()) {
            continue;
         }

         for (JsonElement element : value.getAsJsonArray()) {
            if (element == null || !element.isJsonObject()) {
               continue;
            }

            JsonObject variable = element.getAsJsonObject();
            String enabled = this.stringValue(variable.get("enabled"));
            if ("false".equalsIgnoreCase(enabled)) {
               continue;
            }

            String name = this.stringValue(variable.get("name"));
            String expr = this.stringValue(variable.get("value"));
            if (name == null || name.trim().isEmpty() || expr == null || expr.trim().isEmpty()) {
               continue;
            }

            boolean local = variable.has("local") && !variable.get("local").isJsonNull() && variable.get("local").getAsBoolean();
            script.append(local ? "bru.setVar(" : "bru.setEnvVar(")
               .append(this.jsonStringLiteral(name.trim()))
               .append(", ")
               .append(expr.trim())
               .append(");\n");
         }
      }

      return script.length() == 0 ? null : script.toString();
   }

   private String scriptText(JsonObject scriptObject, String... keys) {
      if (scriptObject == null || keys == null) {
         return null;
      }

      for (String key : keys) {
         if (key == null || !scriptObject.has(key)) {
            continue;
         }

         JsonElement value = scriptObject.get(key);
         if (value == null || value.isJsonNull()) {
            continue;
         }

         if (value.isJsonPrimitive()) {
            return value.getAsString();
         }

         if (value.isJsonArray()) {
            StringBuilder script = new StringBuilder();
            for (JsonElement line : value.getAsJsonArray()) {
               if (line != null && !line.isJsonNull()) {
                  if (script.length() > 0) {
                     script.append('\n');
                  }
                  script.append(line.getAsString());
               }
            }
            if (script.length() > 0) {
               return script.toString();
            }
         }
      }

      return null;
   }

   private String extractAuthValue(JsonObject authObject, String section, String key) {
      if (authObject == null || section == null || key == null || !authObject.has(section) || !authObject.get(section).isJsonObject()) {
         return "";
      }

      JsonObject sectionObject = authObject.getAsJsonObject(section);
      return this.stringValue(sectionObject.get(key));
   }

   private String joinBrunoQuery(JsonArray queryArray) {
      if (queryArray == null || queryArray.size() == 0) {
         return "";
      }

      StringBuilder query = new StringBuilder();
      for (JsonElement element : queryArray) {
         if (element != null && element.isJsonObject()) {
            JsonObject queryObject = element.getAsJsonObject();
            String key = this.stringValue(queryObject.get("name"));
            if (key == null || key.trim().isEmpty()) {
               continue;
            }

            if (query.length() > 0) {
               query.append('&');
            }

            query.append(key).append('=').append(this.stringValue(queryObject.get("value")) == null ? "" : this.stringValue(queryObject.get("value")));
         }
      }

      return query.toString();
   }

   private String joinJsonStringArray(JsonArray array, String delimiter) {
      if (array == null || array.size() == 0) {
         return null;
      }

      StringBuilder out = new StringBuilder();
      for (JsonElement element : array) {
         if (element != null && !element.isJsonNull()) {
            if (out.length() > 0) {
               out.append(delimiter);
            }
            out.append(element.getAsString());
         }
      }

      return out.toString();
   }

   private String stringValue(JsonElement element) {
      if (element == null || element.isJsonNull()) {
         return null;
      }

      if (element.isJsonPrimitive()) {
         return element.getAsString();
      }

      return element.toString();
   }

   private String firstNonBlank(String... values) {
      if (values == null) {
         return null;
      }

      for (String value : values) {
         if (value != null && !value.trim().isEmpty()) {
            return value;
         }
      }

      return null;
   }

   private String jsonStringLiteral(String value) {
      if (value == null) {
         return "\"\"";
      }

      return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "\\r").replace("\n", "\\n") + "\"";
   }

   private PostmanEnvironment toEnvironment(String name, Map<String, String> variables) {
      PostmanEnvironment environment = new PostmanEnvironment();
      environment.name = name;
      environment.values = new ArrayList<>();

      for (Entry<String, String> entry : variables.entrySet()) {
         PostmanEnvironment.Value value = new PostmanEnvironment.Value();
         value.key = entry.getKey();
         value.value = entry.getValue();
         value.enabled = true;
         value.type = "text";
         environment.values.add(value);
      }

      return environment;
   }

   private void parseDirectory(File directory, List<PostmanCollection.Item> items, PostmanCollection rootCollection) throws Exception {
      File[] files = directory.listFiles();
      if (files != null) {
         Arrays.sort(files, Comparator.comparing(File::getName, String.CASE_INSENSITIVE_ORDER));
         List<int[]> seqMap = new ArrayList<>();
         List<PostmanCollection.Item> pendingRequests = new ArrayList<>();

         for (File file : files) {
            String name = file.getName();
            String lowerName = name.toLowerCase(Locale.ROOT);
            if (!name.equals(".git") && !name.equals("node_modules") && !name.equals(".DS_Store") && !name.equals(".gitignore")
               && (!file.isDirectory() || !name.equalsIgnoreCase("environments"))) {
               if (file.isDirectory()) {
                  PostmanCollection.Item folder = new PostmanCollection.Item();
                  folder.name = name;
                  folder.item = new ArrayList<>();
                  File folderMeta = new File(file, "folder.bru");
                  if (folderMeta.isFile()) {
                     this.applyFolderMeta(folder, this.readFileUtf8(folderMeta));
                  }
                  File folderYaml = new File(file, "folder.yml");
                  if (folderYaml.isFile()) {
                     BrunoYamlParser.applyFolderMeta(folder, folderYaml);
                  }

                  this.parseDirectory(file, folder.item, rootCollection);
                  if (!folder.item.isEmpty()) {
                     items.add(folder);
                  }
               } else if (lowerName.endsWith(".bru")
                  && !name.equalsIgnoreCase("collection.bru")
                  && !name.equalsIgnoreCase("folder.bru")
                  && !name.equalsIgnoreCase("environment.bru")) {
                  PostmanCollection.Item item = this.parseRequestFile(file);
                  if (item != null) {
                     int seq = this.readSeq(file);
                     pendingRequests.add(item);
                     seqMap.add(new int[]{pendingRequests.size() - 1, seq});
                  }
               } else if ((lowerName.endsWith(".yml") || lowerName.endsWith(".yaml"))
                  && !name.equalsIgnoreCase("folder.yml")
                  && !name.equalsIgnoreCase("folder.yaml")
                  && !name.equalsIgnoreCase("opencollection.yml")
                  && !name.equalsIgnoreCase("opencollection.yaml")
                  && !name.equalsIgnoreCase("collection.yml")
                  && !name.equalsIgnoreCase("collection.yaml")
                  && !name.equalsIgnoreCase("environment.yml")
                  && !name.equalsIgnoreCase("environment.yaml")) {
                  PostmanCollection.Item item = BrunoYamlParser.parseRequestFile(file);
                  if (item != null) {
                     int seq = BrunoYamlParser.readSeq(file);
                     pendingRequests.add(item);
                     seqMap.add(new int[]{pendingRequests.size() - 1, seq});
                  }
               }
            }
         }

         seqMap.sort((a, b) -> {
            int cmp = Integer.compare(a[1], b[1]);
            return cmp != 0 ? cmp : Integer.compare(a[0], b[0]);
         });

         for (int[] entry : seqMap) {
            items.add(pendingRequests.get(entry[0]));
         }
      }
   }

   private int readSeq(File file) {
      try {
         String content = this.readFileUtf8(file);
         String seq = this.parseKeyValueBlock(content, "meta").get("seq");
         if (seq != null && !seq.trim().isEmpty()) {
            return Integer.parseInt(seq.trim());
         }
      } catch (Exception var4) {
      }

      return Integer.MAX_VALUE;
   }

   private void applyFolderMeta(PostmanCollection.Item folder, String content) {
      PostmanCollection.Auth auth = this.parseAuthFromContent(content);
      if (auth != null) {
         folder.auth = auth;
      }

      List<PostmanCollection.Event> events = this.parseScripts(content);
      if (!events.isEmpty()) {
         folder.event = events;
      }
   }

   private PostmanCollection.Item parseRequestFile(File file) throws Exception {
      String content = this.readFileUtf8(file);
      Map<String, String> meta = this.parseKeyValueBlock(content, "meta");
      String method = null;
      Map<String, String> requestBlock = null;

      for (String candidate : METHODS) {
         String rawBlock = this.parseRawBlock(content, candidate);
         if (rawBlock != null) {
            Map<String, String> block = this.parseKeyValueBlock(content, candidate);
            if (block.containsKey("url")) {
               method = candidate.toUpperCase(Locale.ROOT);
               requestBlock = block;
               break;
            }
         }
      }

      if (method != null && requestBlock != null) {
         PostmanCollection.Item item = new PostmanCollection.Item();
         item.name = meta.getOrDefault("name", this.stripExtension(file.getName()));
         item.request = new PostmanCollection.Request();
         item.request.method = method;
         item.request.header = this.parseHeaders(content);
         String url = requestBlock.getOrDefault("url", "");
         Map<String, String> pathParams = this.parseKeyValueBlockWithDisabled(content, "params:path", null);
         Map<String, String> queryParams = this.parseKeyValueBlockWithDisabled(content, "params:query", null);
         url = this.applyPathParams(url, pathParams);
         url = this.appendQueryParams(url, queryParams);
         item.request.url = url;
         item.request.body = this.parseBody(content, requestBlock);
         PostmanCollection.Auth auth = this.parseAuthFromContent(content);
         if (auth == null) {
            String authType = requestBlock.get("auth");
            if (authType != null && authType.equalsIgnoreCase("none")) {
               auth = new PostmanCollection.Auth();
               auth.type = "noauth";
            } else if (authType != null && !authType.equalsIgnoreCase("inherit")) {
               auth = new PostmanCollection.Auth();
               auth.type = authType.toLowerCase(Locale.ROOT);
            }
         }

         item.request.auth = auth;
         List<PostmanCollection.Event> events = this.parseScripts(content);
         if (!events.isEmpty()) {
            item.event = events;
         }

         String docs = this.parseRawBlock(content, "docs");
         if (docs != null && !docs.trim().isEmpty()) {
            item.description = docs.trim();
         }

         return item;
      } else {
         return null;
      }
   }

   private String applyPathParams(String url, Map<String, String> pathParams) {
      if (url != null && pathParams != null && !pathParams.isEmpty()) {
         for (Entry<String, String> e : pathParams.entrySet()) {
            String placeholder = ":" + e.getKey();
            url = this.replacePathPlaceholder(url, placeholder, e.getValue());
         }

         return url;
      } else {
         return url;
      }
   }

   private String replacePathPlaceholder(String url, String placeholder, String value) {
      if (url == null) {
         return null;
      } else {
         int schemeIdx = url.indexOf("://");
         int searchFrom = 0;
         if (schemeIdx >= 0) {
            int pathIdx = url.indexOf(47, schemeIdx + 3);
            searchFrom = pathIdx >= 0 ? pathIdx : url.length();
         }

         StringBuilder out = new StringBuilder(url.substring(0, searchFrom));
         String tail = url.substring(searchFrom);
         int i = 0;

         while (i < tail.length()) {
            if (tail.startsWith(placeholder, i)) {
               int end = i + placeholder.length();
               char next = end < tail.length() ? tail.charAt(end) : 0;
               if (next == 0 || next == '/' || next == '?' || next == '#' || next == '&') {
                  out.append(value == null ? "" : value);
                  i = end;
                  continue;
               }
            }

            out.append(tail.charAt(i));
            i++;
         }

         return out.toString();
      }
   }

   private String appendQueryParams(String url, Map<String, String> queryParams) {
      if (url != null && queryParams != null && !queryParams.isEmpty()) {
         Set<String> existingKeys = new HashSet<>();
         int q = url.indexOf(63);
         if (q >= 0 && q < url.length() - 1) {
            String[] var8;
            for (String part : var8 = url.substring(q + 1).split("&")) {
               int eq = part.indexOf(61);
               String k = (eq < 0 ? part : part.substring(0, eq)).trim();
               if (!k.isEmpty()) {
                  existingKeys.add(k);
               }
            }
         }

         StringBuilder qs = new StringBuilder();

         for (Entry<String, String> e : queryParams.entrySet()) {
            if (e.getKey() != null && !existingKeys.contains(e.getKey().trim())) {
               if (qs.length() > 0) {
                  qs.append('&');
               }

               qs.append(e.getKey()).append('=').append(e.getValue() == null ? "" : e.getValue());
            }
         }

         return qs.length() == 0 ? url : url + (url.contains("?") ? "&" : "?") + qs.toString();
      } else {
         return url;
      }
   }

   private List<PostmanCollection.Header> parseHeaders(String content) {
      List<PostmanCollection.Header> headers = new ArrayList<>();
      Map<String, Boolean> disabledFlags = new LinkedHashMap<>();
      Map<String, String> entries = this.parseKeyValueBlockWithDisabled(content, "headers", disabledFlags);

      for (Entry<String, String> entry : entries.entrySet()) {
         PostmanCollection.Header header = new PostmanCollection.Header();
         header.key = entry.getKey();
         header.value = entry.getValue();
         header.disabled = Boolean.TRUE.equals(disabledFlags.get(entry.getKey()));
         headers.add(header);
      }

      return headers;
   }

   private PostmanCollection.Body parseBody(String content, Map<String, String> requestBlock) {
      String[][] rawBlocks = new String[][]{{"body:json", "json"}, {"body:text", "text"}, {"body:xml", "xml"}, {"body:sparql", "sparql"}};

      for (String[] rawBlock : rawBlocks) {
         String raw = this.parseRawBlock(content, rawBlock[0]);
         if (raw != null && !raw.trim().isEmpty()) {
            PostmanCollection.Body body = new PostmanCollection.Body();
            body.mode = "raw";
            body.raw = raw.trim();
            body.options = new PostmanCollection.Options();
            body.options.raw = new PostmanCollection.Raw();
            body.options.raw.language = rawBlock[1];
            return body;
         }
      }

      String graphqlBlock = this.parseRawBlock(content, "body:graphql");
      if (graphqlBlock != null && !graphqlBlock.trim().isEmpty()) {
         PostmanCollection.Body body = new PostmanCollection.Body();
         body.mode = "graphql";
         body.graphql = new PostmanCollection.GraphQL();
         String varsBlock = this.parseRawBlock(content, "body:graphql:vars");
         body.graphql.query = graphqlBlock.trim();
         body.graphql.variables = varsBlock == null ? null : varsBlock.trim();
         return body;
      } else {
         Map<String, Boolean> ueDisabled = new LinkedHashMap<>();
         Map<String, String> urlencoded = this.parseKeyValueBlockWithDisabled(content, "body:form-urlencoded", ueDisabled);
         if (!urlencoded.isEmpty()) {
            PostmanCollection.Body body = new PostmanCollection.Body();
            body.mode = "urlencoded";
            body.urlencoded = new ArrayList<>();

            for (Entry<String, String> e : urlencoded.entrySet()) {
               PostmanCollection.UrlEncoded ue = new PostmanCollection.UrlEncoded();
               ue.key = e.getKey();
               ue.value = e.getValue();
               ue.disabled = Boolean.TRUE.equals(ueDisabled.get(e.getKey()));
               ue.type = "text";
               body.urlencoded.add(ue);
            }

            return body;
         } else {
            List<PostmanCollection.FormData> multipart = this.parseMultipartFormBlock(content);
            if (multipart.isEmpty()) {
               return null;
            } else {
               PostmanCollection.Body body = new PostmanCollection.Body();
               body.mode = "formdata";
               body.formdata = multipart;
               return body;
            }
         }
      }
   }

   private List<PostmanCollection.FormData> parseMultipartFormBlock(String content) {
      List<PostmanCollection.FormData> out = new ArrayList<>();
      String raw = this.parseRawBlock(content, "body:multipart-form");
      if (raw == null) return out;

      String[] lines = raw.split("\\R", -1);
      int i = 0;
      while (i < lines.length) {
         String line = lines[i];
         i++;
         String trimmed = line.trim();
         if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("//")) continue;

         boolean disabled = false;
         if (trimmed.startsWith("~")) {
            disabled = true;
            trimmed = trimmed.substring(1).trim();
            if (trimmed.isEmpty()) continue;
         } else if (trimmed.startsWith("\\~")) {
            trimmed = trimmed.substring(1);
         }

         int colon = trimmed.indexOf(':');
         if (colon <= 0) continue;

         String key = trimmed.substring(0, colon).trim();
         String rest = trimmed.substring(colon + 1).trim();

         StringBuilder valBuf = new StringBuilder();
         String contentType = null;

         if (rest.startsWith("'''")) {
            String afterOpen = rest.substring(3);
            int sameLineClose = afterOpen.indexOf("'''");
            if (sameLineClose >= 0) {
               valBuf.append(afterOpen, 0, sameLineClose);
               String trailer = afterOpen.substring(sameLineClose + 3).trim();
               contentType = extractContentTypeAnnotation(trailer);
            } else {
               boolean firstLine = true;
               if (!afterOpen.isEmpty()) {
                  valBuf.append(afterOpen);
                  firstLine = false;
               }
               while (i < lines.length) {
                  String nx = lines[i];
                  i++;
                  int close = nx.indexOf("'''");
                  if (close >= 0) {
                     if (!firstLine) valBuf.append('\n');
                     valBuf.append(nx, 0, close);
                     String trailer = nx.substring(close + 3).trim();
                     contentType = extractContentTypeAnnotation(trailer);
                     break;
                  } else {
                     if (!firstLine) valBuf.append('\n');
                     else firstLine = false;
                     valBuf.append(nx);
                  }
               }
            }

            PostmanCollection.FormData fd = new PostmanCollection.FormData();
            fd.key = key;
            fd.type = "text";
            fd.value = valBuf.toString();
            fd.disabled = disabled;
            fd.contentType = contentType;
            out.add(fd);
         } else {
            String val = rest;
            contentType = extractContentTypeAnnotation(val);
            if (contentType != null) {
               int at = val.lastIndexOf("@contentType(");
               val = val.substring(0, at).trim();
            }

            PostmanCollection.FormData fd = new PostmanCollection.FormData();
            fd.key = key;
            fd.disabled = disabled;
            fd.contentType = contentType;
            if (val.startsWith("@file(") && val.endsWith(")")) {
               fd.type = "file";
               String inner = val.substring("@file(".length(), val.length() - 1);
               if (inner.contains("|")) {
                  String[] parts = inner.split("\\|");
                  List<String> paths = new ArrayList<>();
                  for (String p : parts) {
                     String t = p.trim();
                     if (!t.isEmpty()) paths.add(t);
                  }
                  fd.src = paths;
               } else {
                  fd.src = inner;
               }
            } else if (val.isEmpty() && contentType != null) {
               fd.type = "file";
               fd.src = "";
            } else {
               fd.type = "text";
               fd.value = this.unquote(val);
            }
            out.add(fd);
         }
      }
      return out;
   }

   private static String extractContentTypeAnnotation(String s) {
      if (s == null || s.isEmpty()) return null;
      Matcher m = CONTENT_TYPE_ANNOTATION.matcher(s);
      if (m.find()) return m.group(1).trim();
      return null;
   }

   private static final Pattern CONTENT_TYPE_ANNOTATION = Pattern.compile("@contentType\\(([^)]*)\\)\\s*$");

   private PostmanCollection.Auth parseAuthFromContent(String content) {
      String[] types = new String[]{"bearer", "basic", "apikey", "digest", "awsv4", "oauth2"};

      for (String type : types) {
         String block = this.parseRawBlock(content, "auth:" + type);
         if (block != null) {
            Map<String, String> kv = this.parseKeyValueBlock(content, "auth:" + type);
            PostmanCollection.Auth auth = new PostmanCollection.Auth();
            auth.type = type;
            switch (type.hashCode()) {
               case -1411271163:
                  if (type.equals("apikey")) {
                     auth.apikey = this.authAttributes(
                        new String[][]{
                           {"key", kv.getOrDefault("key", "")},
                           {"value", kv.getOrDefault("value", "")},
                           {"in", kv.getOrDefault("placement", kv.getOrDefault("in", "header"))}
                        }
                     );
                  }
                  break;
               case -1393032351:
                  if (type.equals("bearer")) {
                     auth.bearer = this.authAttributes(new String[][]{{"token", kv.getOrDefault("token", "")}});
                  }
                  break;
               case -1023949701:
                  if (type.equals("oauth2")) {
                     auth.oauth2 = this.authAttributes(
                        new String[][]{
                           {"grant_type", kv.getOrDefault("grant_type", "")},
                           {"accessTokenUrl", kv.getOrDefault("access_token_url", "")},
                           {"clientId", kv.getOrDefault("client_id", "")},
                           {"clientSecret", kv.getOrDefault("client_secret", "")},
                           {"scope", kv.getOrDefault("scope", "")},
                           {"username", kv.getOrDefault("username", "")},
                           {"password", kv.getOrDefault("password", "")}
                        }
                     );
                  }
                  break;
               case 93508654:
                  if (type.equals("basic")) {
                     auth.basic = this.authAttributes(
                        new String[][]{{"username", kv.getOrDefault("username", "")}, {"password", kv.getOrDefault("password", "")}}
                     );
                  }
            }

            return auth;
         }
      }

      return null;
   }

   private List<PostmanCollection.AuthAttribute> authAttributes(String[][] values) {
      List<PostmanCollection.AuthAttribute> attributes = new ArrayList<>();

      for (String[] value : values) {
         PostmanCollection.AuthAttribute attribute = new PostmanCollection.AuthAttribute();
         attribute.key = value[0];
         attribute.value = value[1];
         attribute.type = "string";
         attributes.add(attribute);
      }

      return attributes;
   }

   private List<PostmanCollection.Event> parseScripts(String content) {
      List<PostmanCollection.Event> events = new ArrayList<>();
      String pre = this.parseRawBlock(content, "script:pre-request");
      String post = this.parseRawBlock(content, "script:post-response");
      String tests = this.parseRawBlock(content, "tests");
      if (pre != null && !pre.trim().isEmpty()) {
         events.add(this.scriptEvent("prerequest", pre));
      }

      if (post != null && !post.trim().isEmpty()) {
         events.add(this.scriptEvent("test", post));
      }

      if (tests != null && !tests.trim().isEmpty()) {
         events.add(this.scriptEvent("test", tests));
      }

      return events;
   }

   private PostmanCollection.Event scriptEvent(String listen, String body) {
      PostmanCollection.Event event = new PostmanCollection.Event();
      event.listen = listen;
      event.script = new PostmanCollection.Script();
      event.script.type = "text/javascript";
      event.script.exec = Arrays.asList(body.split("\\R", -1));
      return event;
   }

   private String parseRawBlock(String content, String blockName) {
      if (content != null && blockName != null) {
         Pattern headerPattern = Pattern.compile("(?m)^[ \\t]*" + Pattern.quote(blockName) + "[ \\t]*\\{", 1);
         Matcher m = headerPattern.matcher(content);
         if (!m.find()) {
            return null;
         } else {
            int braceStart = m.end() - 1;
            int depth = 1;
            int i = braceStart + 1;
            int n = content.length();
            boolean inStr = false;
            char strQuote = '"';
            boolean esc = false;
            boolean inLineComment = false;
            boolean inBlockComment = false;
            int contentStart = i;

            while (i < n) {
               char c = content.charAt(i);
               if (inLineComment) {
                  if (c == '\n') {
                     inLineComment = false;
                  }

                  i++;
               } else if (inBlockComment) {
                  if (c == '*' && i + 1 < n && content.charAt(i + 1) == '/') {
                     inBlockComment = false;
                     i += 2;
                  } else {
                     i++;
                  }
               } else {
                  if (inStr) {
                     if (esc) {
                        esc = false;
                     } else if (c == '\\') {
                        esc = true;
                     } else if (c == strQuote) {
                        inStr = false;
                     } else if (c == '\n' || c == '\r') {
                        inStr = false;
                        esc = false;
                     }
                  } else {
                     if (c == '\'' && i + 2 < n && content.charAt(i + 1) == '\'' && content.charAt(i + 2) == '\'') {
                        i += 3;
                        while (i + 2 < n) {
                           if (content.charAt(i) == '\'' && content.charAt(i + 1) == '\'' && content.charAt(i + 2) == '\'') {
                              i += 3;
                              break;
                           }
                           i++;
                        }
                        continue;
                     }

                     if (c == '/' && i + 1 < n) {
                        char nx = content.charAt(i + 1);
                        if (nx == '/') {
                           inLineComment = true;
                           i += 2;
                           continue;
                        }

                        if (nx == '*') {
                           inBlockComment = true;
                           i += 2;
                           continue;
                        }
                     }

                     if (c == '"' || c == '\'') {
                        inStr = true;
                        strQuote = c;
                     } else if (c == '{') {
                        depth++;
                     } else if (c == '}') {
                        if (--depth == 0) {
                           String inner = content.substring(contentStart, i);
                           if (inner.startsWith("\r\n")) {
                              inner = inner.substring(2);
                           } else if (inner.startsWith("\n")) {
                              inner = inner.substring(1);
                           }

                           if (inner.endsWith("\r\n")) {
                              inner = inner.substring(0, inner.length() - 2);
                           } else if (inner.endsWith("\n")) {
                              inner = inner.substring(0, inner.length() - 1);
                           }

                           return inner;
                        }
                     }
                  }

                  i++;
               }
            }

            return null;
         }
      } else {
         return null;
      }
   }

   private Map<String, String> parseKeyValueBlock(String content, String blockName) {
      return this.parseKeyValueBlockWithDisabled(content, blockName, null);
   }

   private Map<String, String> parseKeyValueBlockWithDisabled(String content, String blockName, Map<String, Boolean> disabledOut) {
      Map<String, String> result = new LinkedHashMap<>();
      String raw = this.parseRawBlock(content, blockName);
      if (raw == null) {
         return result;
      } else {
         String[] lines = raw.split("\\R", -1);

         for (String rawLine : lines) {
            String trimmed = rawLine.trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("#") && !trimmed.startsWith("//")) {
               boolean disabled = false;
               if (trimmed.startsWith("~")) {
                  disabled = true;
                  trimmed = trimmed.substring(1).trim();
                  if (trimmed.isEmpty() || disabledOut == null) {
                     continue;
                  }
               } else if (trimmed.startsWith("\\~")) {
                  trimmed = trimmed.substring(1);
               }

               int colonIndex = trimmed.indexOf(58);
               if (colonIndex > 0) {
                  String key = trimmed.substring(0, colonIndex).trim();
                  String value = this.unquote(trimmed.substring(colonIndex + 1).trim());
                  if (disabledOut != null && result.containsKey(key)) {
                     boolean prevDisabled = Boolean.TRUE.equals(disabledOut.get(key));
                     if (!prevDisabled && disabled) {
                        continue;
                     }
                  }

                  result.put(key, value);
                  if (disabledOut != null) {
                     disabledOut.put(key, disabled);
                  }
               }
            }
         }

         return result;
      }
   }

   private String unquote(String value) {
      if (value == null) {
         return null;
      } else {
         String trimmed = value.trim();
         if (trimmed.length() < 2 || (!trimmed.startsWith("\"") || !trimmed.endsWith("\"")) && (!trimmed.startsWith("'") || !trimmed.endsWith("'"))) {
            return trimmed;
         } else {
            String inner = trimmed.substring(1, trimmed.length() - 1);
            return inner.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t").replace("\\\"", "\"").replace("\\\\", "\\");
         }
      }
   }

   private String stripExtension(String name) {
      int dot = name.lastIndexOf(46);
      return dot > 0 ? name.substring(0, dot) : name;
   }

   private String readFileUtf8(File file) throws Exception {
      return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
   }
}
