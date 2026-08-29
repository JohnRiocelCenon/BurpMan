package burp.parser;

import burp.models.PostmanCollection;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;

public final class CollectionExporter {
   private final Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create();

   public void exportTo(PostmanCollection collection, File target) throws IOException {
      if (collection == null) {
         throw new IllegalArgumentException("collection is required");
      } else if (target == null) {
         throw new IllegalArgumentException("target file is required");
      } else {
         ensureSchema(collection);
         try (Writer w = new FileWriter(target)) {
            this.gson.toJson(collection, w);
         }
      }
   }

   public String toJson(PostmanCollection collection) {
      if (collection == null) {
         return "{}";
      } else {
         ensureSchema(collection);
         return this.gson.toJson(collection);
      }
   }

   private static void ensureSchema(PostmanCollection collection) {
      if (collection.info == null) {
         collection.info = new PostmanCollection.Info();
      }

      if (collection.info.name == null || collection.info.name.trim().isEmpty()) {
         collection.info.name = "Exported Collection";
      }

      if (collection.info.schema == null || collection.info.schema.trim().isEmpty()) {
         collection.info.schema = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json";
      }
   }
}
