package burp.openapi;

import burp.models.PostmanCollection;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.File;
import java.io.FileReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;

public final class OpenApiImporter {
   private final Gson gson = new GsonBuilder().setPrettyPrinting().create();
   private static final String[] METHODS = new String[]{"get", "post", "put", "delete", "patch", "head", "options"};

   public PostmanCollection importFile(File file) throws Exception {
      if (file != null && file.isFile()) {
         String name = file.getName().toLowerCase(Locale.ROOT);
         if (!name.endsWith(".yaml") && !name.endsWith(".yml")) {
            try (Reader r = new FileReader(file)) {
               JsonElement root = JsonParser.parseReader(r);
               if (root == null || !root.isJsonObject()) {
                  throw new IllegalArgumentException("Not a JSON object: " + file);
               }

               return this.convert(root.getAsJsonObject());
            }
         } else {
            throw new IllegalArgumentException(
               "YAML import is not bundled — convert the spec to JSON first (e.g. https://www.json2yaml.com/convert-yaml-to-json) and re-import."
            );
         }
      } else {
         throw new IllegalArgumentException("Not a readable file: " + file);
      }
   }

   public PostmanCollection importFrom(String pathOrUrl) throws Exception {
      return this.importFile(new File(pathOrUrl));
   }

   public PostmanCollection convert(JsonObject root) {
      PostmanCollection col = new PostmanCollection();
      col.info = new PostmanCollection.Info();
      col.info.schema = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json";
      col.item = new ArrayList<>();
      col.variable = new ArrayList<>();
      JsonObject info = optObject(root, "info");
      col.info.name = info != null && info.has("title") ? info.get("title").getAsString() : "Imported OpenAPI";
      col.info.description = info != null && info.has("description") && !info.get("description").isJsonNull() ? info.get("description").getAsString() : null;
      String baseUrl = this.extractBaseUrl(root);
      PostmanCollection.Variable bv = new PostmanCollection.Variable();
      bv.key = "baseUrl";
      bv.value = baseUrl;
      bv.type = "string";
      col.variable.add(bv);
      Map<String, PostmanCollection.Item> folders = new LinkedHashMap<>();
      JsonObject paths = optObject(root, "paths");
      if (paths != null) {
         for (Entry<String, JsonElement> entry : paths.entrySet()) {
            String urlPath = entry.getKey();
            if (entry.getValue().isJsonObject()) {
               JsonObject pathItem = entry.getValue().getAsJsonObject();

               for (String method : METHODS) {
                  if (pathItem.has(method) && pathItem.get(method).isJsonObject()) {
                     JsonObject op = pathItem.getAsJsonObject(method);
                     this.addOperation(folders, urlPath, method.toUpperCase(Locale.ROOT), op, pathItem);
                  }
               }
            }
         }
      }

      col.item.addAll(folders.values());
      return col;
   }

   private void addOperation(Map<String, PostmanCollection.Item> folders, String urlPath, String httpMethod, JsonObject op, JsonObject pathItem) {
      JsonArray tags = optArray(op, "tags");
      String groupName;
      if (tags != null && tags.size() > 0) {
         groupName = tags.get(0).getAsString();
      } else {
         String p = urlPath.replaceAll("^/+", "");
         int slash = p.indexOf(47);
         groupName = slash < 0 ? (p.isEmpty() ? "default" : p) : p.substring(0, slash);
      }

      PostmanCollection.Item folder = folders.get(groupName);
      if (folder == null) {
         folder = new PostmanCollection.Item();
         folder.name = groupName;
         folder.item = new ArrayList<>();
         folders.put(groupName, folder);
      }

      PostmanCollection.Item leaf = new PostmanCollection.Item();
      leaf.name = op.has("summary") && !op.get("summary").isJsonNull() ? op.get("summary").getAsString() : httpMethod + " " + urlPath;
      leaf.description = op.has("description") && !op.get("description").isJsonNull() ? op.get("description").getAsString() : null;
      PostmanCollection.Request request = new PostmanCollection.Request();
      request.method = httpMethod;
      PostmanCollection.Url url = new PostmanCollection.Url();
      url.raw = "{{baseUrl}}" + urlPath;
      url.host = new ArrayList<>();
      url.host.add("{{baseUrl}}");
      url.path = new ArrayList<>();

      String[] body;
      for (String seg : body = urlPath.replaceAll("^/+", "").split("/")) {
         if (!seg.isEmpty()) {
            url.path.add(seg);
         }
      }

      List<PostmanCollection.Query> query = new ArrayList<>();
      List<PostmanCollection.Variable> pathVars = new ArrayList<>();
      List<PostmanCollection.Header> headers = new ArrayList<>();
      this.collectParams(optArray(pathItem, "parameters"), query, pathVars, headers);
      this.collectParams(optArray(op, "parameters"), query, pathVars, headers);
      if (!query.isEmpty()) {
         url.query = query;
      }

      if (!pathVars.isEmpty()) {
         url.variable = pathVars;
      }

      if (!headers.isEmpty()) {
         request.header = headers;
      }

      request.url = url;
      JsonObject bodyx = optObject(op, "requestBody");
      if (bodyx != null) {
         JsonObject content = optObject(bodyx, "content");
         if (content != null) {
            String mediaTypeName;
            JsonObject mt;
            if (content.has("application/json") && content.get("application/json").isJsonObject()) {
               mediaTypeName = "application/json";
               mt = content.getAsJsonObject("application/json");
            } else if (!content.entrySet().isEmpty()) {
               Entry<String, JsonElement> first = (Entry<String, JsonElement>)content.entrySet().iterator().next();
               mediaTypeName = first.getKey();
               mt = first.getValue().isJsonObject() ? first.getValue().getAsJsonObject() : null;
            } else {
               mediaTypeName = "application/json";
               mt = null;
            }

            if (mt != null) {
               String example;
               if (mt.has("example") && !mt.get("example").isJsonNull()) {
                  example = mt.get("example").toString();
               } else if (mt.has("schema") && mt.get("schema").isJsonObject()) {
                  example = this.exampleFor(mt.getAsJsonObject("schema"));
               } else {
                  example = "{}";
               }

               PostmanCollection.Body b = new PostmanCollection.Body();
               b.mode = "raw";
               b.raw = example;
               PostmanCollection.Options opts = new PostmanCollection.Options();
               PostmanCollection.Raw raw = new PostmanCollection.Raw();
               raw.language = mediaTypeName.contains("json") ? "json" : (mediaTypeName.contains("xml") ? "xml" : "text");
               opts.raw = raw;
               b.options = opts;
               request.body = b;
               if (request.header == null) {
                  request.header = new ArrayList<>();
               }

               boolean hasCt = false;

               for (PostmanCollection.Header h : request.header) {
                  if (h != null && h.key != null && h.key.equalsIgnoreCase("Content-Type")) {
                     hasCt = true;
                     break;
                  }
               }

               if (!hasCt) {
                  PostmanCollection.Header hx = new PostmanCollection.Header();
                  hx.key = "Content-Type";
                  hx.value = mediaTypeName;
                  request.header.add(hx);
               }
            }
         }
      }

      leaf.request = request;
      folder.item.add(leaf);
   }

   private void collectParams(
      JsonArray params, List<PostmanCollection.Query> query, List<PostmanCollection.Variable> pathVars, List<PostmanCollection.Header> headers
   ) {
      if (params != null) {
         for (JsonElement el : params) {
            if (el.isJsonObject()) {
               JsonObject p = el.getAsJsonObject();
               String name = optString(p, "name");
               String in = optString(p, "in");
               String desc = optString(p, "description");
               if (name != null && in != null) {
                  String example = this.exampleFor(optObject(p, "schema"));
                  if ("query".equalsIgnoreCase(in)) {
                     PostmanCollection.Query q = new PostmanCollection.Query();
                     q.key = name;
                     q.value = example;
                     q.description = desc;
                     query.add(q);
                  } else if ("path".equalsIgnoreCase(in)) {
                     PostmanCollection.Variable v = new PostmanCollection.Variable();
                     v.key = name;
                     v.value = example;
                     v.description = desc;
                     pathVars.add(v);
                  } else if ("header".equalsIgnoreCase(in)) {
                     PostmanCollection.Header h = new PostmanCollection.Header();
                     h.key = name;
                     h.value = example;
                     h.description = desc;
                     headers.add(h);
                  }
               }
            }
         }
      }
   }

   private String extractBaseUrl(JsonObject root) {
      JsonArray servers = optArray(root, "servers");
      if (servers != null && servers.size() > 0 && servers.get(0).isJsonObject()) {
         String u = optString(servers.get(0).getAsJsonObject(), "url");
         if (u != null) {
            return u.replaceAll("/+$", "");
         }
      }

      String host = optString(root, "host");
      String basePath = optString(root, "basePath");
      JsonArray schemes = optArray(root, "schemes");
      String scheme = schemes != null && schemes.size() > 0 ? schemes.get(0).getAsString() : "https";
      return host != null ? (scheme + "://" + host + (basePath == null ? "" : basePath)).replaceAll("/+$", "") : "";
   }

   private String exampleFor(JsonObject schema) {
      if (schema == null) {
         return "";
      } else if (schema.has("example") && !schema.get("example").isJsonNull()) {
         return schema.get("example").toString();
      } else if (schema.has("default") && !schema.get("default").isJsonNull()) {
         return schema.get("default").toString();
      } else {
         String type = optString(schema, "type");
         if (type == null) {
            type = "string";
         }

         switch (type.hashCode()) {
            case -1034364087:
               if (type.equals("number")) {
                  return "0.0";
               }
               break;
            case -1023368385:
               if (type.equals("object")) {
                  JsonObject props = optObject(schema, "properties");
                  if (props != null && !props.entrySet().isEmpty()) {
                     StringBuilder sb = new StringBuilder("{");
                     boolean first = true;

                     for (Entry<String, JsonElement> e : props.entrySet()) {
                        if (!first) {
                           sb.append(",");
                        }

                        sb.append("\"").append(e.getKey()).append("\":");
                        JsonObject child = e.getValue().isJsonObject() ? e.getValue().getAsJsonObject() : null;
                        String childType = child == null ? "string" : optString(child, "type");
                        String inner = this.exampleFor(child);
                        if ("string".equals(childType) || childType == null) {
                           sb.append("\"").append(inner.replace("\"", "\\\"")).append("\"");
                        } else if (inner != null && !inner.isEmpty()) {
                           sb.append(inner);
                        } else {
                           sb.append("null");
                        }

                        first = false;
                     }

                     sb.append("}");
                     return sb.toString();
                  }

                  return "{}";
               }
               break;
            case 64711720:
               if (type.equals("boolean")) {
                  return "false";
               }
               break;
            case 93090393:
               if (type.equals("array")) {
                  return "[" + this.exampleFor(optObject(schema, "items")) + "]";
               }
               break;
            case 1958052158:
               if (type.equals("integer")) {
                  return "0";
               }
         }

         JsonArray enums = optArray(schema, "enum");
         return enums != null && enums.size() > 0 ? enums.get(0).getAsString() : "string";
      }
   }

   private static JsonObject optObject(JsonObject parent, String key) {
      if (parent != null && parent.has(key)) {
         JsonElement el = parent.get(key);
         return el.isJsonObject() ? el.getAsJsonObject() : null;
      } else {
         return null;
      }
   }

   private static JsonArray optArray(JsonObject parent, String key) {
      if (parent != null && parent.has(key)) {
         JsonElement el = parent.get(key);
         return el.isJsonArray() ? el.getAsJsonArray() : null;
      } else {
         return null;
      }
   }

   private static String optString(JsonObject parent, String key) {
      if (parent != null && parent.has(key)) {
         JsonElement el = parent.get(key);
         return el.isJsonNull() ? null : el.getAsString();
      } else {
         return null;
      }
   }
}
