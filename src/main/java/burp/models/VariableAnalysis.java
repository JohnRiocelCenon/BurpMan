package burp.models;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class VariableAnalysis {
   private final Set<String> unresolvedVariables;
   private final int totalRequests;
   private final int requestsWithVariables;
   private final VariableAnalysis.VariableImpact impact;

   public VariableAnalysis(Set<String> unresolvedVariables, int totalRequests, int requestsWithVariables) {
      this.unresolvedVariables = unresolvedVariables;
      this.totalRequests = totalRequests;
      this.requestsWithVariables = requestsWithVariables;
      this.impact = this.calculateImpact();
   }

   private VariableAnalysis.VariableImpact calculateImpact() {
      if (this.unresolvedVariables.isEmpty()) {
         return VariableAnalysis.VariableImpact.NONE;
      } else {
         double percentage = (double)this.requestsWithVariables / this.totalRequests;
         if (percentage < 0.25) {
            return VariableAnalysis.VariableImpact.LOW;
         } else {
            return percentage < 0.75 ? VariableAnalysis.VariableImpact.MEDIUM : VariableAnalysis.VariableImpact.HIGH;
         }
      }
   }

   private VariableAnalysis buildVariableAnalysisFromPreviews(List<RequestPreview> previews) {
      Set<String> unresolvedVariables = new HashSet<>();
      int totalRequests = previews != null ? previews.size() : 0;
      int requestsWithVariables = 0;
      if (previews != null) {
         for (RequestPreview preview : previews) {
            if (preview != null && preview.hasUnresolvedVariables()) {
               requestsWithVariables++;
               unresolvedVariables.addAll(preview.getUnresolvedVariables());
            }
         }
      }

      return new VariableAnalysis(unresolvedVariables, totalRequests, requestsWithVariables);
   }

   public Set<String> getUnresolvedVariables() {
      return this.unresolvedVariables;
   }

   public int getTotalRequests() {
      return this.totalRequests;
   }

   public int getRequestsWithVariables() {
      return this.requestsWithVariables;
   }

   public VariableAnalysis.VariableImpact getImpact() {
      return this.impact;
   }

   public boolean hasVariables() {
      return !this.unresolvedVariables.isEmpty();
   }

   public String getImpactDescription() {
      switch (this.impact) {
         case NONE:
            return "No variables detected";
         case LOW:
            return "Few requests affected (" + this.requestsWithVariables + "/" + this.totalRequests + ")";
         case MEDIUM:
            return "Some requests affected (" + this.requestsWithVariables + "/" + this.totalRequests + ")";
         case HIGH:
            return "Most requests affected (" + this.requestsWithVariables + "/" + this.totalRequests + ")";
         default:
            return "Unknown impact";
      }
   }

   public static enum VariableImpact {
      NONE,
      LOW,
      MEDIUM,
      HIGH;
   }
}
