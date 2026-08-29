package burp.codegen;

import java.util.Map.Entry;

public final class JavaHttpClient5Generator implements CodeGenerator {
   @Override
   public String label() {
      return "Java — Apache HttpClient 5";
   }

   @Override
   public String fileExtension() {
      return "java";
   }

   @Override
   public String generate(GenRequest req) {
      StringBuilder sb = new StringBuilder();
      sb.append("import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;\n");
      sb.append("import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;\n");
      sb.append("import org.apache.hc.client5.http.impl.classic.HttpClients;\n");
      sb.append("import org.apache.hc.core5.http.io.entity.EntityUtils;\n");
      sb.append("import org.apache.hc.core5.http.io.entity.StringEntity;\n");
      sb.append("import org.apache.hc.core5.http.ContentType;\n");
      sb.append("import java.net.URI;\n\n");
      sb.append("public class ApiRequest {\n");
      sb.append("    public static void main(String[] args) throws Exception {\n");
      sb.append("        try (CloseableHttpClient client = HttpClients.createDefault()) {\n");
      sb.append("            HttpUriRequestBase request = new HttpUriRequestBase(\n");
      sb.append("                    ").append(JavaOkHttpGenerator.javaString(req.method)).append(",\n");
      sb.append("                    new URI(").append(JavaOkHttpGenerator.javaString(req.url)).append("));\n");

      for (Entry<String, String> e : req.headers.entrySet()) {
         sb.append("            request.addHeader(")
            .append(JavaOkHttpGenerator.javaString(e.getKey()))
            .append(", ")
            .append(JavaOkHttpGenerator.javaString(e.getValue()))
            .append(");\n");
      }

      if (req.body != null && !req.body.isEmpty()) {
         sb.append("            request.setEntity(new StringEntity(\n");
         sb.append("                    ").append(JavaOkHttpGenerator.javaString(req.body)).append(",\n");
         sb.append("                    ContentType.APPLICATION_JSON));\n");
      }

      sb.append("            client.execute(request, response -> {\n");
      sb.append("                System.out.println(response.getCode());\n");
      sb.append("                System.out.println(EntityUtils.toString(response.getEntity()));\n");
      sb.append("                return null;\n");
      sb.append("            });\n");
      sb.append("        }\n");
      sb.append("    }\n");
      sb.append("}\n");
      return sb.toString();
   }
}
