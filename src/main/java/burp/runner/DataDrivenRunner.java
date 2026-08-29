package burp.runner;

import burp.models.AnalyzedRequest;
import burp.parser.VariableResolver;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

public final class DataDrivenRunner {
   private final VariableResolver resolver;
   private final DataIterator data;
   private final String iterationVarName;

   public DataDrivenRunner(VariableResolver resolver, DataIterator data) {
      this(resolver, data, "iteration");
   }

   public DataDrivenRunner(VariableResolver resolver, DataIterator data, String iterationVarName) {
      if (resolver == null) {
         throw new IllegalArgumentException("resolver is required");
      } else if (data == null) {
         throw new IllegalArgumentException("data is required");
      } else {
         this.resolver = resolver;
         this.data = data;
         this.iterationVarName = iterationVarName == null ? "iteration" : iterationVarName;
      }
   }

   public void run(List<AnalyzedRequest> requests, DataDrivenRunner.IterationAction action) {
      if (requests != null && !requests.isEmpty() && action != null) {
         this.data.reset();

         for (int iter = 0; this.data.hasNext(); iter++) {
            Map<String, String> row = this.data.next();
            Map<String, String> prior = new LinkedHashMap<>();

            for (String key : row.keySet()) {
               prior.put(key, this.resolver.getVariables().get(key));
            }

            String priorIterationVar = this.resolver.getVariables().get(this.iterationVarName);

            try {
               for (Entry<String, String> e : row.entrySet()) {
                  this.resolver.addCustomVariable(e.getKey(), e.getValue());
               }

               this.resolver.addCustomVariable(this.iterationVarName, Integer.toString(iter));

               for (AnalyzedRequest r : requests) {
                  action.apply(r, iter, row);
               }
            } finally {
               for (Entry<String, String> e : prior.entrySet()) {
                  if (e.getValue() == null) {
                     this.resolver.removeCustomVariable(e.getKey());
                  } else {
                     this.resolver.addCustomVariable(e.getKey(), e.getValue());
                  }
               }

               if (priorIterationVar == null) {
                  this.resolver.removeCustomVariable(this.iterationVarName);
               } else {
                  this.resolver.addCustomVariable(this.iterationVarName, priorIterationVar);
               }
            }
         }
      }
   }

   public int iterationCount() {
      return this.data.size();
   }

   public interface IterationAction {
      void apply(AnalyzedRequest var1, int var2, Map<String, String> var3);
   }
}
