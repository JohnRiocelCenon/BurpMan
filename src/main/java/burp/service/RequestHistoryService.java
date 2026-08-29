package burp.service;

import burp.models.ExecutedRequest;
import burp.models.RequestHistory;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;

public class RequestHistoryService {
   private final RequestHistory history;
   private final File persistenceFile;
   private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

   public RequestHistoryService(RequestHistory history, File persistenceDir) {
      this.history = history;
      this.persistenceFile = new File(persistenceDir, "request_history.json");

      try {
         this.loadFromDisk();
      } catch (Exception var4) {
         System.err.println("Failed to load history from disk: " + var4.getMessage());
      }
   }

   public void loadFromDisk() {
      if (this.persistenceFile.exists()) {
         try {
            String content = new String(Files.readAllBytes(this.persistenceFile.toPath()), StandardCharsets.UTF_8);
            List<ExecutedRequest> requests = Arrays.asList((ExecutedRequest[])this.gson.fromJson(content, ExecutedRequest[].class));

            for (int i = requests.size() - 1; i >= 0; i--) {
               this.history.add(requests.get(i));
            }
         } catch (JsonSyntaxException | IOException var4) {
            System.err.println("Error loading history: " + var4.getMessage());
         }
      }
   }

   public void saveToDisk() {
      try {
         List<ExecutedRequest> requests = this.history.getAll();
         String json = this.gson.toJson(requests);
         this.persistenceFile.getParentFile().mkdirs();
         Files.write(this.persistenceFile.toPath(), json.getBytes(StandardCharsets.UTF_8));
      } catch (IOException var3) {
         System.err.println("Error saving history: " + var3.getMessage());
      }
   }

   public void prune() {
      if (this.history.size() > 100) {
         List<ExecutedRequest> all = this.history.getAll();
         this.history.clear();

         for (int i = Math.max(0, all.size() - 100); i < all.size(); i++) {
            this.history.add(all.get(i));
         }
      }
   }

   public String exportAsJson() {
      return this.gson.toJson(this.history.getAll());
   }
}
