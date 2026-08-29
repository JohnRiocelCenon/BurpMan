package burp.parser;

import com.google.gson.JsonElement;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.File;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class CollectionFormatDetector {
   private CollectionFormatDetector() {
   }

   public static CollectionFormatDetector.Format detect(File file) {
      if (file == null || !file.exists()) {
         return CollectionFormatDetector.Format.UNKNOWN;
      } else if (file.isDirectory()) {
         return detectDirectory(file);
      } else {
         String name = file.getName().toLowerCase(Locale.ROOT);

         try {
            if (looksLikeJson(file)) {
               CollectionFormatDetector.Format jsonFormat = detectJsonFile(file);
               if (jsonFormat != CollectionFormatDetector.Format.UNKNOWN) {
                  return jsonFormat;
               }
            }

            if (name.endsWith(".bru")) {
               return detectBruFile(file);
            }

            if (name.endsWith(".json")) {
               return detectJsonFile(file);
            }

            if (name.endsWith(".yml") || name.endsWith(".yaml")) {
               return detectYamlFile(file);
            }

            // Bruno's plain-text .env format — dotenv-style KEY=VALUE or
            // KEY: VALUE lines, with # comments. Recognized by extension
            // (.env / .env.local / .env.uat) OR by content sniff (no
            // extension file like "env 7" that Bruno CLI writes when you
            // do bru env export). We only return an ENV format here to
            // avoid mis-detecting a scripted .txt as an env file — the
            // sniff requires at least 2 KEY: VALUE lines.
            if (looksLikeDotEnvName(name) || looksLikeDotEnvContent(file)) {
               return CollectionFormatDetector.Format.BRUNO_ENVIRONMENT_BRU;
            }
         } catch (Exception var3) {
            return CollectionFormatDetector.Format.UNKNOWN;
         }

         return CollectionFormatDetector.Format.UNKNOWN;
      }
   }

   /** True for filenames like {@code .env}, {@code env}, {@code .env.uat},
    *  {@code prod.env}, {@code env 7} — anything Bruno CLI or a user is
    *  likely to name a dotenv-style export. */
   private static boolean looksLikeDotEnvName(String lowerName) {
      if (lowerName == null || lowerName.isEmpty()) return false;
      if (lowerName.equals(".env") || lowerName.equals("env")) return true;
      if (lowerName.startsWith(".env.")) return true;
      if (lowerName.endsWith(".env")) return true;
      if (lowerName.startsWith("env ") || lowerName.startsWith("env.") || lowerName.startsWith("env_")) return true;
      if (lowerName.matches("(?i)^env\\d*$")) return true;
      if (lowerName.matches("(?i)^env[\\s._-]+.+$")) return true;
      return false;
   }

   /** Content sniff for plain-text env files. Requires at least 2 lines that
    *  match {@code KEY: VALUE} or {@code KEY=VALUE} (comments/section headers
    *  don't count), and no lines that look like JSON, YAML, or Bruno .bru
    *  block syntax. Skips files that look like scripts or documentation. */
   private static boolean looksLikeDotEnvContent(File file) throws Exception {
      String content = readFileUtf8(file);
      if (content == null) return false;
      String trimmed = content.trim();
      if (trimmed.isEmpty()) return false;
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) return false;
      int kvCount = 0;
      int nonKvCount = 0;
      for (String rawLine : content.split("\\R", -1)) {
         String line = rawLine.trim();
         if (line.isEmpty()) continue;
         if (line.startsWith("#") || line.startsWith(";") || line.startsWith("//")) continue;
         if (line.startsWith("[") && line.endsWith("]")) continue;
         // Bruno-.bru-style block openers disqualify.
         if (line.matches("(?i)^(vars|vars:secret|meta|headers|body|auth|script|post-response|tests|get|post|put|delete|patch|head|options)\\s*\\{$")) return false;
         if (line.startsWith("}")) return false;
         // KEY: VALUE or KEY = VALUE or KEY=VALUE — allow hyphens, dots,
         // underscores in the key (Bruno collection var names use these).
         if (line.matches("^[A-Za-z_][A-Za-z0-9_.\\-]*\\s*[:=].*$")) {
            kvCount++;
         } else {
            nonKvCount++;
         }
      }
      return kvCount >= 2 && kvCount > nonKvCount;
   }

   /** Detect Bruno v3.x YAML files by structure. {@code opencollection.yml}
    *  is the collection root; {@code folder.yml} is folder metadata; env
    *  files have {@code variables:} at the top level; request files have
    *  {@code http:} block with {@code method:}. A single-file bundled
    *  export starts with {@code opencollection: 1.0.0} at column 0 and
    *  contains an {@code items:} array. */
   private static CollectionFormatDetector.Format detectYamlFile(File file) throws Exception {
      String fname = file.getName().toLowerCase(Locale.ROOT);
      if (fname.equals("opencollection.yml") || fname.equals("opencollection.yaml")
         || fname.equals("collection.yml") || fname.equals("collection.yaml")) {
         return CollectionFormatDetector.Format.BRUNO_COLLECTION_FOLDER;
      }
      String content = readFileUtf8(file);
      String lower = content.toLowerCase(Locale.ROOT);
      // Single-file bundled OpenCollection export (any filename). The
      // {@code opencollection:} key must appear at column 0 to avoid
      // false positives from a nested key with the same name.
      if (lower.startsWith("opencollection:") || lower.contains("\nopencollection:")) {
         return CollectionFormatDetector.Format.BRUNO_OPENCOLLECTION_YAML;
      }
      if (lower.contains("\nvariables:") || lower.startsWith("variables:")
         || lower.contains("\nvars:") || lower.startsWith("vars:")) {
         if (!lower.contains("\nhttp:") && !lower.startsWith("http:")) {
            return CollectionFormatDetector.Format.BRUNO_ENVIRONMENT_BRU;
         }
      }
      if (lower.contains("\nhttp:") || lower.startsWith("http:")) {
         return CollectionFormatDetector.Format.BRUNO_REQUEST_BRU;
      }
      return CollectionFormatDetector.Format.UNKNOWN;
   }

   private static boolean looksLikeJson(File file) throws Exception {
      String content = readFileUtf8(file).trim();
      return content.startsWith("{") || content.startsWith("[");
   }

   private static CollectionFormatDetector.Format detectDirectory(File dir) {
      if (new File(dir, "bruno.json").exists() || new File(dir, "opencollection.yml").exists()) {
         return CollectionFormatDetector.Format.BRUNO_COLLECTION_FOLDER;
      } else if (containsBruRequest(dir)) {
         return CollectionFormatDetector.Format.BRUNO_COLLECTION_FOLDER;
      } else {
         return containsPostmanCollectionJson(dir) ? CollectionFormatDetector.Format.POSTMAN_COLLECTION_FOLDER : CollectionFormatDetector.Format.UNKNOWN;
      }
   }

   private static boolean containsBruRequest(File dir) {
      File[] files = dir.listFiles();
      if (files == null) {
         return false;
      } else {
         for (File file : files) {
            if (file.isDirectory()) {
               String name = file.getName();
               if (!name.equals("environments") && !name.equals(".git") && !name.equals("node_modules") && containsBruRequest(file)) {
                  return true;
               }
            } else if (file.getName().toLowerCase(Locale.ROOT).endsWith(".bru")) {
               try {
                  if (detectBruFile(file) == CollectionFormatDetector.Format.BRUNO_REQUEST_BRU) {
                     return true;
                  }
               } catch (Exception var7) {
               }
            }
         }

         return false;
      }
   }

   private static boolean containsPostmanCollectionJson(File dir) {
      File[] files = dir.listFiles();
      if (files == null) {
         return false;
      } else {
         for (File file : files) {
            if (file.isDirectory()) {
               String name = file.getName();
               if (!name.equals(".git") && !name.equals("node_modules") && !name.equals("target") && containsPostmanCollectionJson(file)) {
                  return true;
               }
            } else if (file.getName().toLowerCase(Locale.ROOT).endsWith(".json")) {
               try {
                  if (detectJsonFile(file) == CollectionFormatDetector.Format.POSTMAN_COLLECTION_JSON) {
                     return true;
                  }
               } catch (Exception var7) {
               }
            }
         }

         return false;
      }
   }

   private static CollectionFormatDetector.Format detectBruFile(File file) throws Exception {
      String content = readFileUtf8(file);
      String lower = content.toLowerCase(Locale.ROOT);
      String fname = file.getName().toLowerCase(Locale.ROOT);
      if (fname.equals("environment.bru")) {
         return CollectionFormatDetector.Format.BRUNO_ENVIRONMENT_BRU;
      } else if (!fname.equals("collection.bru") && !fname.equals("folder.bru")) {
         Pattern methodHeader = Pattern.compile("(?m)^[ \\t]*(get|post|put|patch|delete|head|options)[ \\t]*\\{");
         Matcher m = methodHeader.matcher(lower);

         while (m.find()) {
            int after = m.end();
            int closingBrace = findMatchingBrace(content, m.end() - 1);
            if (closingBrace < 0) {
               closingBrace = content.length();
            }

            String inside = content.substring(after, Math.min(closingBrace, content.length()));
            if (inside.toLowerCase(Locale.ROOT).contains("url:")) {
               return CollectionFormatDetector.Format.BRUNO_REQUEST_BRU;
            }
         }

         return lower.matches("(?s).*\\R?\\s*vars(:secret)?\\s*\\{.*")
            ? CollectionFormatDetector.Format.BRUNO_ENVIRONMENT_BRU
            : CollectionFormatDetector.Format.UNKNOWN;
      } else {
         return CollectionFormatDetector.Format.BRUNO_REQUEST_BRU;
      }
   }

   private static int findMatchingBrace(String s, int openIndex) {
      int depth = 0;
      boolean inStr = false;
      char q = '"';
      boolean esc = false;

      for (int i = openIndex; i < s.length(); i++) {
         char c = s.charAt(i);
         if (inStr) {
            if (esc) {
               esc = false;
            } else if (c == '\\') {
               esc = true;
            } else if (c == q) {
               inStr = false;
            }
         } else if (c == '"' || c == '\'') {
            inStr = true;
            q = c;
         } else if (c == '{') {
            depth++;
         } else if (c == '}') {
            if (--depth == 0) {
               return i;
            }
         }
      }

      return -1;
   }

   private static CollectionFormatDetector.Format detectJsonFile(File file) throws Exception {
      try (FileReader reader = new FileReader(file)) {
         JsonElement element = JsonParser.parseReader(reader);
         if (!element.isJsonObject()) {
            return CollectionFormatDetector.Format.UNKNOWN;
         }

         JsonObject object = element.getAsJsonObject();
         if (object.has("info") && object.has("item")) {
            return CollectionFormatDetector.Format.POSTMAN_COLLECTION_JSON;
         }

         if (looksLikeBrunoCollectionJson(object)) {
           return CollectionFormatDetector.Format.BRUNO_COLLECTION_JSON;
         }

         if (object.has("collection") && object.get("collection").isJsonObject()) {
            JsonObject collection = object.getAsJsonObject("collection");
            if (collection.has("info") && collection.has("item")) {
               return CollectionFormatDetector.Format.POSTMAN_COLLECTION_JSON;
            }
         }

         if (object.has("values") && object.get("values").isJsonArray()) {
            return CollectionFormatDetector.Format.POSTMAN_ENVIRONMENT_JSON;
         }

         return object.has("vars") || object.has("variables") ? CollectionFormatDetector.Format.BRUNO_ENVIRONMENT_JSON : CollectionFormatDetector.Format.UNKNOWN;
      }
   }

   private static boolean looksLikeBrunoCollectionJson(JsonObject object) {
      if (object == null || !object.has("items") || !object.get("items").isJsonArray()) {
         return false;
      }

      // Canonical Bruno export marker.
      if (object.has("brunoConfig")) {
         return true;
      }

      // Additional structural fallback for Bruno JSON exports that may not
      // include brunoConfig but still contain Bruno-style request entries.
      JsonArray items = object.getAsJsonArray("items");
      for (JsonElement itemEl : items) {
         if (itemEl == null || !itemEl.isJsonObject()) continue;
         JsonObject item = itemEl.getAsJsonObject();
         if (item.has("request") && item.get("request").isJsonObject()) {
            JsonObject req = item.getAsJsonObject("request");
            if (req.has("url") || req.has("method") || req.has("auth")) {
               return true;
            }
         }
         if (item.has("items") && item.get("items").isJsonArray()) {
            return true;
         }
         if (item.has("type")) {
            String t = String.valueOf(item.get("type")).toLowerCase(Locale.ROOT);
            if (t.contains("http") || t.contains("folder")) {
               return true;
            }
         }
      }

      if (object.has("exportedUsing")) {
         String exporter = String.valueOf(object.get("exportedUsing")).toLowerCase(Locale.ROOT);
         if (exporter.contains("bruno")) {
            return true;
         }
      }

      return false;
   }

   private static String readFileUtf8(File file) throws Exception {
      return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
   }

   public static enum Format {
      POSTMAN_COLLECTION_JSON,
      POSTMAN_COLLECTION_FOLDER,
      POSTMAN_ENVIRONMENT_JSON,
      BRUNO_COLLECTION_JSON,
      BRUNO_COLLECTION_FOLDER,
      BRUNO_OPENCOLLECTION_YAML,
      BRUNO_REQUEST_BRU,
      BRUNO_ENVIRONMENT_BRU,
      BRUNO_ENVIRONMENT_JSON,
      UNKNOWN;
   }
}
