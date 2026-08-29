package burp.models;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ExecutedRequest {
   private final String id;
   private final long timestamp;
   private final String method;
   private final String url;
   private final List<PostmanCollection.Header> requestHeaders;
   private final String requestBody;
   private int statusCode;
   private String statusText;
   private List<PostmanCollection.Header> responseHeaders;
   private String responseBody;
   private long durationMs;
   private String contentType;
   private String error;
   private Map<String, String> extractedVariables;
   private List<ExecutedRequest.TestResult> testResults;

   public ExecutedRequest(String id, long timestamp, String method, String url, List<PostmanCollection.Header> requestHeaders, String requestBody) {
      this.id = id;
      this.timestamp = timestamp;
      this.method = method;
      this.url = url;
      this.requestHeaders = requestHeaders;
      this.requestBody = requestBody;
      this.extractedVariables = new HashMap<>();
      this.statusCode = 0;
   }

   public String getId() {
      return this.id;
   }

   public long getTimestamp() {
      return this.timestamp;
   }

   public String getMethod() {
      return this.method;
   }

   public String getUrl() {
      return this.url;
   }

   public List<PostmanCollection.Header> getRequestHeaders() {
      return this.requestHeaders;
   }

   public String getRequestBody() {
      return this.requestBody;
   }

   public int getStatusCode() {
      return this.statusCode;
   }

   public String getStatusText() {
      return this.statusText;
   }

   public List<PostmanCollection.Header> getResponseHeaders() {
      return this.responseHeaders;
   }

   public String getResponseBody() {
      return this.responseBody;
   }

   public long getDurationMs() {
      return this.durationMs;
   }

   public String getContentType() {
      return this.contentType;
   }

   public String getError() {
      return this.error;
   }

   public Map<String, String> getExtractedVariables() {
      return this.extractedVariables;
   }

   public List<ExecutedRequest.TestResult> getTestResults() {
      return this.testResults;
   }

   public void setStatusCode(int statusCode) {
      this.statusCode = statusCode;
   }

   public void setStatusText(String statusText) {
      this.statusText = statusText;
   }

   public void setResponseHeaders(List<PostmanCollection.Header> responseHeaders) {
      this.responseHeaders = responseHeaders;
   }

   public void setResponseBody(String responseBody) {
      this.responseBody = responseBody;
   }

   public void setDurationMs(long durationMs) {
      this.durationMs = durationMs;
   }

   public void setContentType(String contentType) {
      this.contentType = contentType;
   }

   public void setError(String error) {
      this.error = error;
   }

   public void setExtractedVariables(Map<String, String> extractedVariables) {
      this.extractedVariables = extractedVariables;
   }

   public void setTestResults(List<ExecutedRequest.TestResult> testResults) {
      this.testResults = testResults;
   }

   public boolean isSuccess() {
      return this.error == null && this.statusCode >= 200 && this.statusCode < 300;
   }

   public static class TestResult {
      public String name;
      public boolean passed;
      public String error;

      public TestResult(String name, boolean passed, String error) {
         this.name = name;
         this.passed = passed;
         this.error = error;
      }
   }
}
