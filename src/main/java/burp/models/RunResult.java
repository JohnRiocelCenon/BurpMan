package burp.models;

import java.util.ArrayList;
import java.util.List;

public final class RunResult {
   public final String runId;
   public final int iteration;
   public final String path;
   public final String name;
   public final String method;
   public final String url;
   public int statusCode;
   public String statusText;
   public long durationMs;
   public long sizeBytes;
   public String error;
   public String responseBody;
   public List<PostmanCollection.Header> responseHeaders;
   public List<PostmanCollection.Header> requestHeaders;
   public String requestBody;
   public final List<ExecutedRequest.TestResult> tests = new ArrayList<>();

   public RunResult(String runId, int iteration, String path, String name, String method, String url) {
      this.runId = runId;
      this.iteration = iteration;
      this.path = path;
      this.name = name;
      this.method = method;
      this.url = url;
   }

   public boolean isPassed() {
      return this.error == null && this.statusCode >= 200 && this.statusCode < 300 && !this.hasFailedTest();
   }

   public boolean isFailed() {
      return this.error != null || this.statusCode > 0 && (this.statusCode < 200 || this.statusCode >= 400) || this.hasFailedTest();
   }

   public boolean isSkipped() {
      return this.statusCode == 0 && this.error == null;
   }

   public boolean hasFailedTest() {
      for (ExecutedRequest.TestResult t : this.tests) {
         if (!t.passed) {
            return true;
         }
      }

      return false;
   }
}
