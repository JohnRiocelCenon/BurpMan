package burp.models;

import burp.service.ScriptExecutor;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public class ScriptContext {
   private PostmanCollection.Request request;
   private ExecutedRequest executedRequest;
   private Map<String, String> environmentVariables = new HashMap<>();
   private Map<String, String> collectionVariables = new HashMap<>();
   private Map<String, String> globalVariables = new HashMap<>();
   private StringBuilder consoleOutput = new StringBuilder();

   public PostmanCollection.Request getRequest() {
      return this.request;
   }

   public void setRequest(PostmanCollection.Request request) {
      this.request = request;
   }

   public ExecutedRequest getExecutedRequest() {
      return this.executedRequest;
   }

   public void setExecutedRequest(ExecutedRequest executedRequest) {
      this.executedRequest = executedRequest;
   }

   public Map<String, String> getEnvironmentVariables() {
      return this.environmentVariables;
   }

   public void setEnvironmentVariables(Map<String, String> vars) {
      this.environmentVariables = vars;
   }

   public Map<String, String> getCollectionVariables() {
      return this.collectionVariables;
   }

   public void setCollectionVariables(Map<String, String> vars) {
      this.collectionVariables = vars;
   }

   public Map<String, String> getGlobalVariables() {
      return this.globalVariables;
   }

   public void setVariable(String key, String value) {
      this.globalVariables.put(key, value);
   }

   public String getVariable(String key) {
      if (this.globalVariables.containsKey(key)) {
         return this.globalVariables.get(key);
      } else if (this.environmentVariables.containsKey(key)) {
         return this.environmentVariables.get(key);
      } else {
         return this.collectionVariables.containsKey(key) ? this.collectionVariables.get(key) : null;
      }
   }

   public void log(String message) {
      this.consoleOutput.append(message).append("\n");

      try {
         Consumer<String> sink = ScriptExecutor.UI_LOG;
         if (sink != null) {
            sink.accept(message);
         }
      } catch (Throwable var3) {
      }
   }

   public String getConsoleOutput() {
      return this.consoleOutput.toString();
   }

   public void clearConsoleOutput() {
      this.consoleOutput = new StringBuilder();
   }
}
