package burp.codegen;

import java.util.Map.Entry;

public final class CSharpHttpClientGenerator implements CodeGenerator {
   @Override
   public String label() {
      return "C# — HttpClient";
   }

   @Override
   public String fileExtension() {
      return "cs";
   }

   @Override
   public String generate(GenRequest req) {
      StringBuilder sb = new StringBuilder();
      sb.append("using System;\n");
      sb.append("using System.Net.Http;\n");
      sb.append("using System.Text;\n");
      sb.append("using System.Threading.Tasks;\n\n");
      sb.append("public class ApiRequest {\n");
      sb.append("    public static async Task Main() {\n");
      sb.append("        using var client = new HttpClient();\n");
      sb.append("        var request = new HttpRequestMessage(new HttpMethod(").append(csStr(req.method)).append("), ").append(csStr(req.url)).append(");\n");

      for (Entry<String, String> e : req.headers.entrySet()) {
         String k = e.getKey().toLowerCase();
         if (!k.equals("content-type") && !k.equals("content-length")) {
            sb.append("        request.Headers.TryAddWithoutValidation(").append(csStr(e.getKey())).append(", ").append(csStr(e.getValue())).append(");\n");
         }
      }

      if (req.body != null && !req.body.isEmpty()) {
         String ct = req.headers.getOrDefault("Content-Type", req.headers.getOrDefault("content-type", "application/json"));
         sb.append("        request.Content = new StringContent(").append(csStr(req.body)).append(", Encoding.UTF8, ").append(csStr(ct)).append(");\n");
      }

      sb.append("\n        var response = await client.SendAsync(request);\n");
      sb.append("        Console.WriteLine((int)response.StatusCode);\n");
      sb.append("        Console.WriteLine(await response.Content.ReadAsStringAsync());\n");
      sb.append("    }\n");
      sb.append("}\n");
      return sb.toString();
   }

   private static String csStr(String s) {
      return s == null ? "null" : "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r") + "\"";
   }
}
