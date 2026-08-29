package burp.parser;

import burp.models.PostmanCollection;
import burp.models.PostmanEnvironment;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class PostmanParser {
   private final Gson gson = new GsonBuilder().setPrettyPrinting().create();
   private final BrunoParser brunoParser = new BrunoParser();

   public PostmanCollection parseCollection(File file) throws Exception {
      if (file != null && file.isDirectory()) {
         CollectionFormatDetector.Format format = CollectionFormatDetector.detect(file);
         switch (format) {
            case POSTMAN_COLLECTION_FOLDER:
               return this.parsePostmanCollectionFolder(file);
            case POSTMAN_ENVIRONMENT_JSON:
            default:
               throw new IllegalArgumentException("Unsupported or unrecognized collection folder: " + file.getAbsolutePath());
            case BRUNO_COLLECTION_FOLDER:
               return this.brunoParser.parseCollection(file);
         }
      } else {
         CollectionFormatDetector.Format format = CollectionFormatDetector.detect(file);
         switch (format) {
         case BRUNO_COLLECTION_JSON:
            return this.brunoParser.parseCollection(file);
         case POSTMAN_COLLECTION_JSON:
            return this.parsePostmanCollectionJson(file);
         case POSTMAN_COLLECTION_FOLDER:
            return this.parsePostmanCollectionFolder(file);
         case POSTMAN_ENVIRONMENT_JSON:
            case BRUNO_ENVIRONMENT_BRU:
            case BRUNO_ENVIRONMENT_JSON:
               throw new IllegalArgumentException("Selected file appears to be an environment, not a collection: " + file.getName());
         case BRUNO_COLLECTION_FOLDER:
         case BRUNO_OPENCOLLECTION_YAML:
         case BRUNO_REQUEST_BRU:
              return this.brunoParser.parseCollection(file);
            default:
               PostmanCollection fallback = this.tryParseUnknownJsonCollection(file);
               if (fallback != null) {
                  return fallback;
               }
               throw new IllegalArgumentException("Unsupported or unrecognized collection format: " + file.getAbsolutePath());
         }
      }
   }

   public PostmanEnvironment parseEnvironment(File file) throws Exception {
      if (file == null) {
         return null;
      } else {
         CollectionFormatDetector.Format format = CollectionFormatDetector.detect(file);
         switch (format) {
            case POSTMAN_COLLECTION_JSON:
            case POSTMAN_COLLECTION_FOLDER:
            case BRUNO_COLLECTION_FOLDER:
            case BRUNO_OPENCOLLECTION_YAML:
            case BRUNO_REQUEST_BRU:
               throw new IllegalArgumentException("Selected file appears to be a collection/request, not an environment: " + file.getName());
            case POSTMAN_ENVIRONMENT_JSON:
               try (FileReader reader = new FileReader(file)) {
                  return (PostmanEnvironment)this.gson.fromJson(reader, PostmanEnvironment.class);
               }
            case BRUNO_ENVIRONMENT_BRU:
            case BRUNO_ENVIRONMENT_JSON:
               return this.brunoParser.parseEnvironment(file);
            default:
               throw new IllegalArgumentException("Unsupported or unrecognized environment format: " + file.getAbsolutePath());
         }
      }
   }

   private PostmanCollection parsePostmanCollectionFolder(File folder) throws Exception {
      List<File> collectionFiles = new ArrayList<>();
      this.collectPostmanCollectionFiles(folder, collectionFiles);
      if (collectionFiles.isEmpty()) {
         throw new IllegalArgumentException("No Postman collection JSON files found in folder: " + folder.getAbsolutePath());
      } else {
         PostmanCollection merged = new PostmanCollection();
         merged.info = new PostmanCollection.Info();
         merged.info.name = folder.getName();
         merged.item = new ArrayList<>();
         merged.variable = new ArrayList<>();
         int loaded = 0;
         Map<String, Integer> nameCounts = new HashMap<>();

         for (File collectionFile : collectionFiles) {
            PostmanCollection collection;
            try {
               collection = this.parsePostmanCollectionJson(collectionFile);
            } catch (Exception var13) {
               continue;
            }

            if (collection != null && collection.info != null) {
               String baseName = collection.info.name != null && !collection.info.name.trim().isEmpty()
                  ? collection.info.name.trim()
                  : this.stripJsonSuffix(collectionFile.getName());
               String collectionName = baseName;
               Integer prev = nameCounts.get(baseName);
               if (prev != null) {
                  int next = prev + 1;
                  nameCounts.put(baseName, next);
                  collectionName = baseName + " (" + next + ")";
               } else {
                  nameCounts.put(baseName, 1);
               }

               PostmanCollection.Item collectionFolder = new PostmanCollection.Item();
               collectionFolder.name = collectionName;
               collectionFolder.item = (List<PostmanCollection.Item>)(collection.item != null ? collection.item : new ArrayList<>());
               collectionFolder.isCollectionWrapper = true;
               if (collection.auth != null) {
                  collectionFolder.auth = collection.auth;
               }

               if (collection.variable != null) {
                  merged.variable.addAll(collection.variable);
               }

               merged.item.add(collectionFolder);
               loaded++;
            }
         }

         if (loaded == 0) {
            throw new IllegalArgumentException("No valid Postman collections found in folder: " + folder.getAbsolutePath());
         } else {
            return merged;
         }
      }
   }

   private void collectPostmanCollectionFiles(File directory, List<File> collectionFiles) throws Exception {
      File[] files = directory.listFiles();
      if (files != null) {
         Arrays.sort(files, Comparator.comparing(File::getName, String.CASE_INSENSITIVE_ORDER));

         for (File file : files) {
            if (file.isDirectory()) {
               String name = file.getName();
               if (!name.equals(".git") && !name.equals("node_modules") && !name.equals("target")) {
                  this.collectPostmanCollectionFiles(file, collectionFiles);
               }
            } else {
               String lower = file.getName().toLowerCase(Locale.ROOT);
               if (lower.endsWith(".json") && !lower.endsWith(".postman_environment.json")) {
                  collectionFiles.add(file);
               }
            }
         }
      }
   }

   private PostmanCollection parsePostmanCollectionJson(File file) throws Exception {
      try (FileReader reader = new FileReader(file)) {
         JsonElement element = JsonParser.parseReader(reader);
         if (!element.isJsonObject()) {
            throw new IllegalArgumentException("Not a Postman collection: " + file.getName());
         }

         JsonObject jsonObject = element.getAsJsonObject();
         PostmanCollection collection;
         if (jsonObject.has("collection") && jsonObject.get("collection").isJsonObject()) {
            collection = (PostmanCollection)this.gson.fromJson(jsonObject.getAsJsonObject("collection"), PostmanCollection.class);
         } else {
            if (!jsonObject.has("info") || !jsonObject.has("item")) {
               throw new IllegalArgumentException("Not a Postman collection: " + file.getName());
            }

            collection = (PostmanCollection)this.gson.fromJson(jsonObject, PostmanCollection.class);
         }

         if (collection.item == null) {
            collection.item = new ArrayList<>();
         }

         if (collection.variable == null) {
            collection.variable = new ArrayList<>();
         }

         if (collection.info == null) {
            collection.info = new PostmanCollection.Info();
            collection.info.name = this.stripJsonSuffix(file.getName());
         } else if (collection.info.name == null || collection.info.name.trim().isEmpty()) {
            collection.info.name = this.stripJsonSuffix(file.getName());
         }

         return collection;
      }
   }

   private PostmanCollection tryParseUnknownJsonCollection(File file) throws Exception {
      if (file == null) return null;
      String lowerName = file.getName().toLowerCase(Locale.ROOT);
      if (!lowerName.endsWith(".json")) return null;

      try (FileReader reader = new FileReader(file)) {
         JsonElement element = JsonParser.parseReader(reader);
         if (!element.isJsonObject()) {
            return null;
         }
         JsonObject root = element.getAsJsonObject();

         if (looksLikeBrunoJsonCollection(root)) {
            return this.brunoParser.parseCollection(file);
         }
         if (looksLikePostmanCollection(root)) {
            return this.parsePostmanCollectionJson(file);
         }
      } catch (Exception ignore) {
         // Keep the original "unsupported format" error path if fallback
         // inspection fails.
      }

      return null;
   }

   private boolean looksLikePostmanCollection(JsonObject root) {
      if (root == null) return false;
      if (root.has("info") && root.has("item")) return true;
      if (root.has("collection") && root.get("collection").isJsonObject()) {
         JsonObject nested = root.getAsJsonObject("collection");
         return nested.has("info") && nested.has("item");
      }
      return false;
   }

   private boolean looksLikeBrunoJsonCollection(JsonObject root) {
      if (root == null) return false;
      if (root.has("brunoConfig") && root.has("items") && root.get("items").isJsonArray()) {
         return true;
      }
      if (root.has("items") && root.get("items").isJsonArray()) {
         JsonElement first = root.getAsJsonArray("items").size() > 0
                 ? root.getAsJsonArray("items").get(0)
                 : null;
         if (first != null && first.isJsonObject()) {
            JsonObject fo = first.getAsJsonObject();
            if (fo.has("request") || fo.has("items") || fo.has("type")) {
               return true;
            }
         }
      }
      if (root.has("exportedUsing")) {
         String exporter = String.valueOf(root.get("exportedUsing")).toLowerCase(Locale.ROOT);
         if (exporter.contains("bruno")) return true;
      }
      return false;
   }

   private String stripJsonSuffix(String fileName) {
      if (fileName == null) {
         return "Unnamed Collection";
      } else if (fileName.toLowerCase(Locale.ROOT).endsWith(".postman_collection.json")) {
         return fileName.substring(0, fileName.length() - ".postman_collection.json".length());
      } else {
         return fileName.toLowerCase(Locale.ROOT).endsWith(".json") ? fileName.substring(0, fileName.length() - ".json".length()) : fileName;
      }
   }
}
