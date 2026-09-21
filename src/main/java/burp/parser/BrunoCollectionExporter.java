package burp.parser;

import burp.models.PostmanCollection;
import burp.models.PostmanEnvironment;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Writes a collection out as a Bruno OpenCollection 1.0.0 directory.
 *
 * <p>The counterpart to {@link BrunoYamlParser}: a folder holding {@code opencollection.yml}, one
 * {@code .yml} per request, nested folders as subdirectories, and any environments under
 * {@code environments/}. That is the layout Bruno opens directly, so a collection imported from
 * Postman can be handed to a team that uses Bruno.
 */
public final class BrunoCollectionExporter {

   /** Everything written, so the caller can report it. */
   public static final class Result {
      public final File root;
      public final int requests;
      public final int folders;
      public final int environments;

      Result(File root, int requests, int folders, int environments) {
         this.root = root;
         this.requests = requests;
         this.folders = folders;
         this.environments = environments;
      }

      public String summary() {
         return requests + " request" + (requests == 1 ? "" : "s")
            + ", " + folders + " folder" + (folders == 1 ? "" : "s")
            + ", " + environments + " environment" + (environments == 1 ? "" : "s");
      }
   }

   /** Turns a collection name into a folder name every filesystem accepts. */
   public static String folderNameFor(String collectionName) {
      return YamlWriter.safeFileName(collectionName, "Exported Collection");
   }

   private int requestCount;
   private int folderCount;

   public Result exportTo(PostmanCollection collection, File targetDir) throws IOException {
      return exportTo(collection, targetDir, null);
   }

   /**
    * @param environments environments to write alongside the requests; may be null or empty
    */
   public Result exportTo(PostmanCollection collection, File targetDir,
                          List<PostmanEnvironment> environments) throws IOException {
      if (collection == null) throw new IllegalArgumentException("collection is required");
      if (targetDir == null) throw new IllegalArgumentException("target directory is required");

      this.requestCount = 0;
      this.folderCount = 0;

      if (!targetDir.isDirectory() && !targetDir.mkdirs()) {
         throw new IOException("Could not create " + targetDir.getAbsolutePath());
      }

      String name = collection.info != null && collection.info.name != null
         && !collection.info.name.trim().isEmpty()
         ? collection.info.name.trim()
         : "Exported Collection";

      write(new File(targetDir, "opencollection.yml"), collectionRoot(name, collection));
      writeItems(collection.item, targetDir, 1);

      int envCount = writeEnvironments(environments, targetDir);
      return new Result(targetDir, this.requestCount, this.folderCount, envCount);
   }

   private String collectionRoot(String name, PostmanCollection collection) {
      YamlWriter y = new YamlWriter();
      y.field(0, "opencollection", "1.0.0").blank();
      y.open(0, "info").field(1, "name", name);

      List<PostmanCollection.Variable> vars = collection.variable;
      if (vars != null && !vars.isEmpty()) {
         boolean opened = false;
         for (PostmanCollection.Variable v : vars) {
            if (v == null || v.key == null || v.key.trim().isEmpty()) continue;
            if (!opened) {
               y.open(0, "vars");
               opened = true;
            }
            y.itemField(1, "name", v.key);
            y.field(2, "value", v.value == null ? "" : v.value);
         }
      }

      PostmanCollection.Auth auth = collection.auth;
      if (auth != null && auth.type != null && !auth.type.trim().isEmpty()) {
         y.open(0, "auth");
         writeAuthBody(y, auth, 1);
      }

      y.field(0, "bundled", false);
      y.open(0, "extensions").open(1, "bruno").open(2, "ignore");
      y.indentedListItem(3, "node_modules");
      y.indentedListItem(3, ".git");
      return y.text();
   }

   private void writeItems(List<PostmanCollection.Item> items, File dir, int startSeq) throws IOException {
      if (items == null) return;
      List<String> usedNames = new ArrayList<>();
      int seq = startSeq;
      for (PostmanCollection.Item item : items) {
         if (item == null) continue;

         if (item.request != null) {
            String fileName = YamlWriter.uniqueName(
               YamlWriter.safeFileName(item.name, "Request"), usedNames);
            write(new File(dir, fileName + ".yml"), requestFile(item, seq));
            this.requestCount++;
            seq++;
            continue;
         }

         if (item.item != null && !item.item.isEmpty()) {
            String folderName = YamlWriter.uniqueName(
               YamlWriter.safeFileName(item.name, "Folder"), usedNames);
            File sub = new File(dir, folderName);
            if (!sub.isDirectory() && !sub.mkdirs()) {
               throw new IOException("Could not create " + sub.getAbsolutePath());
            }
            // A collection wrapper is an artefact of importing several files at once; it has no
            // meaning in Bruno, so its metadata is skipped while its children are kept.
            if (!item.isCollectionWrapper) {
               write(new File(sub, "folder.yml"), folderFile(item, seq));
            }
            this.folderCount++;
            seq++;
            writeItems(item.item, sub, 1);
         }
      }
   }

   private String folderFile(PostmanCollection.Item item, int seq) {
      YamlWriter y = new YamlWriter();
      y.open(0, "info");
      y.field(1, "name", item.name == null ? "Folder" : item.name);
      y.field(1, "type", "folder");
      y.field(1, "seq", seq);

      boolean hasHeaders = item.request != null && item.request.header != null
         && !item.request.header.isEmpty();
      boolean hasAuth = item.request != null && item.request.auth != null
         && item.request.auth.type != null && !item.request.auth.type.trim().isEmpty();
      if (hasHeaders || hasAuth) {
         y.blank().open(0, "request");
         if (hasHeaders) writeHeaders(y, item.request.header, 1);
         if (hasAuth) {
            y.open(1, "auth");
            writeAuthBody(y, item.request.auth, 2);
         }
      }

      String docs = firstNonBlank(item.description,
         item.request == null ? null : item.request.description);
      if (docs != null) {
         y.blank().field(0, "docs", docs);
      }
      return y.text();
   }

   private String requestFile(PostmanCollection.Item item, int seq) {
      PostmanCollection.Request r = item.request;
      YamlWriter y = new YamlWriter();

      y.open(0, "info");
      y.field(1, "name", item.name == null ? "Request" : item.name);
      y.field(1, "type", "http");
      y.field(1, "seq", seq);
      y.blank();

      y.open(0, "http");
      y.field(1, "method", r.method == null ? "GET" : r.method.toUpperCase(Locale.ROOT));
      y.field(1, "url", urlOf(r));

      if (r.header != null && !r.header.isEmpty()) {
         writeHeaders(y, r.header, 1);
      }
      writeBody(y, r.body, 1);

      if (r.auth != null && r.auth.type != null && !r.auth.type.trim().isEmpty()) {
         if ("noauth".equalsIgnoreCase(r.auth.type) || "none".equalsIgnoreCase(r.auth.type)) {
            y.field(1, "auth", "none");
         } else {
            y.open(1, "auth");
            writeAuthBody(y, r.auth, 2);
         }
      }

      writeScripts(y, item);

      y.blank().open(0, "settings");
      y.field(1, "encodeUrl", true);
      y.field(1, "timeout", 0);
      y.field(1, "followRedirects", true);
      y.field(1, "maxRedirects", 5);

      String docs = firstNonBlank(item.description, r.description);
      if (docs != null) {
         y.blank().field(0, "docs", docs);
      }
      return y.text();
   }

   /** Prefers the original {{var}} template over a URL already resolved for display. */
   private static String urlOf(PostmanCollection.Request r) {
      if (r.rawUrlTemplate != null && !r.rawUrlTemplate.trim().isEmpty()) {
         return r.rawUrlTemplate;
      }
      return r.url == null ? "" : String.valueOf(r.url);
   }

   private void writeHeaders(YamlWriter y, List<PostmanCollection.Header> headers, int indent) {
      List<PostmanCollection.Header> usable = new ArrayList<>();
      for (PostmanCollection.Header h : headers) {
         if (h != null && h.key != null && !h.key.trim().isEmpty()) usable.add(h);
      }
      if (usable.isEmpty()) return;
      y.open(indent, "headers");
      for (PostmanCollection.Header h : usable) {
         y.itemField(indent + 1, "name", h.key);
         y.field(indent + 2, "value", h.value == null ? "" : h.value);
         if (h.disabled) y.field(indent + 2, "disabled", true);
         if (notBlank(h.description)) y.field(indent + 2, "description", h.description);
      }
   }

   private void writeBody(YamlWriter y, PostmanCollection.Body body, int indent) {
      if (body == null || body.mode == null) return;
      String mode = body.mode.toLowerCase(Locale.ROOT);

      if ("raw".equals(mode)) {
         if (!notBlank(body.raw)) return;
         y.open(indent, "body");
         y.field(indent + 1, "type", rawLanguage(body));
         y.field(indent + 1, "data", body.raw);
         return;
      }

      if ("urlencoded".equals(mode) && body.urlencoded != null && !body.urlencoded.isEmpty()) {
         y.open(indent, "body");
         y.field(indent + 1, "type", "form-urlencoded");
         y.open(indent + 1, "data");
         for (PostmanCollection.UrlEncoded u : body.urlencoded) {
            if (u == null || u.key == null || u.key.trim().isEmpty()) continue;
            y.itemField(indent + 2, "name", u.key);
            y.field(indent + 3, "value", u.value == null ? "" : u.value);
            if (u.disabled) y.field(indent + 3, "disabled", true);
         }
         return;
      }

      if ("formdata".equals(mode) && body.formdata != null && !body.formdata.isEmpty()) {
         y.open(indent, "body");
         y.field(indent + 1, "type", "multipart-form");
         y.open(indent + 1, "data");
         for (PostmanCollection.FormData f : body.formdata) {
            if (f == null || f.key == null || f.key.trim().isEmpty()) continue;
            y.itemField(indent + 2, "name", f.key);
            boolean isFile = "file".equalsIgnoreCase(f.type);
            y.field(indent + 3, "type", isFile ? "file" : "text");
            if (isFile) {
               String src = f.getSrcAsString();
               y.field(indent + 3, "value", src == null ? "" : src);
            } else {
               y.field(indent + 3, "value", f.value == null ? "" : f.value);
            }
            if (f.disabled) y.field(indent + 3, "disabled", true);
            if (notBlank(f.contentType)) y.field(indent + 3, "contentType", f.contentType);
         }
         return;
      }

      if ("graphql".equals(mode) && body.graphql != null) {
         y.open(indent, "body");
         y.field(indent + 1, "type", "graphql");
         y.open(indent + 1, "data");
         y.field(indent + 2, "query", body.graphql.query == null ? "" : body.graphql.query);
         if (notBlank(body.graphql.variables)) {
            y.field(indent + 2, "variables", body.graphql.variables);
         }
         return;
      }

      if ("file".equals(mode) && body.file != null && notBlank(body.file.src)) {
         y.open(indent, "body");
         y.field(indent + 1, "type", "file");
         y.field(indent + 1, "data", body.file.src);
      }
   }

   private static String rawLanguage(PostmanCollection.Body body) {
      String lang = body.options != null && body.options.raw != null ? body.options.raw.language : null;
      if (notBlank(lang)) {
         String l = lang.toLowerCase(Locale.ROOT);
         if (l.equals("json") || l.equals("xml") || l.equals("text") || l.equals("sparql")) return l;
      }
      // Guessing from the payload beats defaulting everything to text, since the type drives
      // how Bruno highlights and how the Content-Type is inferred.
      String raw = body.raw == null ? "" : body.raw.trim();
      if (raw.startsWith("{") || raw.startsWith("[")) return "json";
      if (raw.startsWith("<")) return "xml";
      return "text";
   }

   private void writeAuthBody(YamlWriter y, PostmanCollection.Auth auth, int indent) {
      String type = auth.type == null ? "" : auth.type.toLowerCase(Locale.ROOT);
      switch (type) {
         case "bearer":
            y.field(indent, "type", "bearer");
            y.field(indent, "token", attr(auth.bearer, "token"));
            return;
         case "basic":
            y.field(indent, "type", "basic");
            y.field(indent, "username", attr(auth.basic, "username"));
            y.field(indent, "password", attr(auth.basic, "password"));
            return;
         case "apikey":
         case "api-key":
            y.field(indent, "type", "apikey");
            y.field(indent, "key", attr(auth.apikey, "key"));
            y.field(indent, "value", attr(auth.apikey, "value"));
            y.field(indent, "placement", firstNonBlank(attr(auth.apikey, "in"), "header"));
            return;
         case "digest":
            y.field(indent, "type", "digest");
            y.field(indent, "username", attr(auth.digest, "username"));
            y.field(indent, "password", attr(auth.digest, "password"));
            return;
         case "oauth2":
            writeOAuth2(y, auth, indent);
            return;
         case "inherit":
            y.field(indent, "type", "inherit");
            return;
         default:
            y.field(indent, "type", type.isEmpty() ? "none" : type);
      }
   }

   /**
    * Writes OAuth2 back into the nested shape OpenCollection uses, i.e. the client id under
    * {@code credentials} rather than at the top level.
    */
   private void writeOAuth2(YamlWriter y, PostmanCollection.Auth auth, int indent) {
      y.field(indent, "type", "oauth2");
      java.util.Map<String, String> a = flatten(auth.oauth2);

      String flow = firstNonBlank(a.get("flow"), a.get("grant_type"), a.get("grantType"));
      y.field(indent, "flow", flow);
      y.field(indent, "authorizationUrl",
         firstNonBlank(a.get("authorizationUrl"), a.get("authUrl"), a.get("authorization_url")));
      y.field(indent, "accessTokenUrl",
         firstNonBlank(a.get("accessTokenUrl"), a.get("access_token_url"), a.get("tokenUrl")));
      y.field(indent, "callbackUrl", firstNonBlank(a.get("callbackUrl"), a.get("callback_url")));

      String clientId = firstNonBlank(a.get("credentials.clientId"), a.get("clientId"), a.get("client_id"));
      String clientSecret = firstNonBlank(a.get("credentials.clientSecret"), a.get("clientSecret"), a.get("client_secret"));
      String placement = firstNonBlank(a.get("credentials.placement"), a.get("client_authentication"));
      if (clientId != null || clientSecret != null || placement != null) {
         y.open(indent, "credentials");
         y.field(indent + 1, "clientId", clientId);
         y.field(indent + 1, "clientSecret", clientSecret);
         y.field(indent + 1, "placement", placement);
      }

      y.field(indent, "scope", a.get("scope"));
      y.field(indent, "username", a.get("username"));
      y.field(indent, "password", a.get("password"));

      String pkce = a.get("pkce");
      if (pkce != null && !"false".equalsIgnoreCase(pkce.trim())) {
         // An empty map is how OpenCollection says "enabled with defaults".
         y.literal(indent, "pkce", "{}");
      }

      String credentialsId = firstNonBlank(a.get("tokenConfig.id"), a.get("credentialsId"));
      String tokenSource = firstNonBlank(a.get("tokenConfig.source"), a.get("tokenSource"));
      if (credentialsId != null || tokenSource != null) {
         y.open(indent, "tokenConfig");
         y.field(indent + 1, "id", credentialsId);
         y.field(indent + 1, "source", tokenSource);
      }

      String autoFetch = firstNonBlank(a.get("settings.autoFetchToken"), a.get("autoFetchToken"));
      String autoRefresh = firstNonBlank(a.get("settings.autoRefreshToken"), a.get("autoRefreshToken"));
      if (autoFetch != null || autoRefresh != null) {
         y.open(indent, "settings");
         y.booleanish(indent + 1, "autoFetchToken", autoFetch);
         y.booleanish(indent + 1, "autoRefreshToken", autoRefresh);
      }
   }

   /** Reads an oauth2 blob, whether it arrived as a map or as a list of key/value pairs. */
   @SuppressWarnings("unchecked")
   private static java.util.Map<String, String> flatten(Object oauth2) {
      java.util.Map<String, String> out = new java.util.LinkedHashMap<>();
      if (oauth2 instanceof java.util.Map) {
         for (java.util.Map.Entry<Object, Object> e : ((java.util.Map<Object, Object>) oauth2).entrySet()) {
            if (e.getKey() == null || e.getValue() == null) continue;
            flattenInto(out, String.valueOf(e.getKey()), e.getValue());
         }
      } else if (oauth2 instanceof List) {
         for (Object entry : (List<Object>) oauth2) {
            if (!(entry instanceof java.util.Map)) continue;
            java.util.Map<Object, Object> m = (java.util.Map<Object, Object>) entry;
            Object k = m.get("key");
            Object v = m.get("value");
            if (k != null && v != null) out.put(String.valueOf(k), String.valueOf(v));
         }
      }
      return out;
   }

   @SuppressWarnings("unchecked")
   private static void flattenInto(java.util.Map<String, String> out, String path, Object value) {
      if (value instanceof java.util.Map) {
         java.util.Map<Object, Object> m = (java.util.Map<Object, Object>) value;
         if (m.isEmpty()) {
            out.put(path, "true");
            return;
         }
         for (java.util.Map.Entry<Object, Object> e : m.entrySet()) {
            if (e.getKey() == null) continue;
            flattenInto(out, path + "." + e.getKey(), e.getValue());
         }
         return;
      }
      if (value != null) out.put(path, String.valueOf(value));
   }

   private void writeScripts(YamlWriter y, PostmanCollection.Item item) {
      if (item.event == null || item.event.isEmpty()) return;

      List<String[]> scripts = new ArrayList<>();
      for (PostmanCollection.Event e : item.event) {
         if (e == null || e.script == null || e.script.exec == null) continue;
         String code = String.join("\n", e.script.exec).trim();
         if (code.isEmpty()) continue;
         String listen = e.listen == null ? "" : e.listen.toLowerCase(Locale.ROOT);
         scripts.add(new String[]{
            "prerequest".equals(listen) ? "before-request" : "after-response", code});
      }
      if (scripts.isEmpty()) return;

      y.blank().open(0, "runtime").open(1, "scripts");
      for (String[] s : scripts) {
         y.itemField(2, "type", s[0]);
         y.field(3, "code", s[1]);
      }
   }

   private int writeEnvironments(List<PostmanEnvironment> environments, File targetDir) throws IOException {
      if (environments == null || environments.isEmpty()) return 0;

      File envDir = new File(targetDir, "environments");
      List<String> used = new ArrayList<>();
      int written = 0;
      for (PostmanEnvironment env : environments) {
         if (env == null) continue;
         if (!envDir.isDirectory() && !envDir.mkdirs()) {
            throw new IOException("Could not create " + envDir.getAbsolutePath());
         }
         String fileName = YamlWriter.uniqueName(
            YamlWriter.safeFileName(env.name, "Environment"), used);

         YamlWriter y = new YamlWriter();
         y.field(0, "name", env.name == null ? fileName : env.name);
         if (env.values != null && !env.values.isEmpty()) {
            y.open(0, "variables");
            for (PostmanEnvironment.Value v : env.values) {
               if (v == null || v.key == null || v.key.trim().isEmpty()) continue;
               boolean secret = "secret".equalsIgnoreCase(v.type);
               if (secret) {
                  y.itemField(1, "secret", "true");
                  y.field(2, "name", v.key);
               } else {
                  y.itemField(1, "name", v.key);
               }
               // A secret with no value is how Bruno records one whose value is withheld.
               if (!secret || notBlank(v.value)) {
                  y.field(secret ? 2 : 2, "value", v.value == null ? "" : v.value);
               }
               if (!v.enabled) y.field(2, "disabled", true);
            }
         }
         write(new File(envDir, fileName + ".yml"), y.text());
         written++;
      }
      return written;
   }

   private static void write(File target, String content) throws IOException {
      Files.write(target.toPath(), content.getBytes(StandardCharsets.UTF_8));
   }

   private static String attr(Object attributes, String key) {
      java.util.Map<String, String> flat = flatten(attributes);
      return flat.get(key);
   }

   private static boolean notBlank(String s) {
      return s != null && !s.trim().isEmpty();
   }

   private static String firstNonBlank(String... values) {
      if (values == null) return null;
      for (String v : values) {
         if (notBlank(v)) return v;
      }
      return null;
   }
}
