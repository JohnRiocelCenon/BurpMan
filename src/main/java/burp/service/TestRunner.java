package burp.service;

import burp.models.ExecutedRequest;
import java.util.ArrayList;
import java.util.List;

public class TestRunner {
   private List<ExecutedRequest.TestResult> results = new ArrayList<>();

   public void test(String name, boolean passed, String error) {
      this.results.add(new ExecutedRequest.TestResult(name, passed, error));
   }

   public List<ExecutedRequest.TestResult> getResults() {
      return new ArrayList<>(this.results);
   }

   public void clear() {
      this.results.clear();
   }

   public String getSummary() {
      if (this.results.isEmpty()) {
         return "No tests run";
      } else {
         long passed = this.results.stream().filter(t -> t.passed).count();
         long total = this.results.size();
         return passed + "/" + total + " tests passed";
      }
   }

   public boolean allPassed() {
      return this.results.stream().allMatch(t -> t.passed);
   }
}
