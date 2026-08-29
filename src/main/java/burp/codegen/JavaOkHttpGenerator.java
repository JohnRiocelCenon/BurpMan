package burp.codegen;

import java.util.Map.Entry;

public final class JavaOkHttpGenerator implements CodeGenerator {
   @Override
   public String label() {
      return "Java — OkHttp";
   }

   @Override
   public String fileExtension() {
      return "java";
   }

   @Override
   public String generate(GenRequest req) {
      StringBuilder sb = new StringBuilder();
      sb.append("import okhttp3.*;\n");
      sb.append("import java.io.IOException;\n\n");
      sb.append("public class ApiRequest {\n");
      sb.append("    public static void main(String[] args) throws IOException {\n");
      sb.append("        OkHttpClient client = new OkHttpClient();\n\n");
      if (req.body != null && !req.body.isEmpty()) {
         String mediaType = req.headers.getOrDefault("Content-Type", req.headers.getOrDefault("content-type", "application/json"));
         sb.append("        MediaType mediaType = MediaType.parse(").append(javaString(mediaType)).append(");\n");
         sb.append("        RequestBody body = RequestBody.create(").append(javaString(req.body)).append(", mediaType);\n\n");
      } else if (!req.formFields.isEmpty()) {
         sb.append("        FormBody.Builder formBuilder = new FormBody.Builder();\n");

         for (String[] kv : req.formFields) {
            sb.append("        formBuilder.add(").append(javaString(kv[0])).append(", ").append(javaString(kv[1])).append(");\n");
         }

         sb.append("        RequestBody body = formBuilder.build();\n\n");
      }

      sb.append("        Request request = new Request.Builder()\n");
      sb.append("            .url(").append(javaString(req.url)).append(")\n");

      for (Entry<String, String> e : req.headers.entrySet()) {
         sb.append("            .addHeader(").append(javaString(e.getKey())).append(", ").append(javaString(e.getValue())).append(")\n");
      }

      if (req.hasBody()) {
         sb.append("            .method(").append(javaString(req.method)).append(", body)\n");
      } else {
         sb.append("            .method(").append(javaString(req.method)).append(", null)\n");
      }

      sb.append("            .build();\n\n");
      sb.append("        try (Response response = client.newCall(request).execute()) {\n");
      sb.append("            System.out.println(response.code());\n");
      sb.append("            System.out.println(response.body().string());\n");
      sb.append("        }\n");
      sb.append("    }\n");
      sb.append("}\n");
      return sb.toString();
   }

   static String javaString(String s) {
      if (s == null) {
         return "null";
      } else {
         StringBuilder sb = new StringBuilder("\"");

         for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
               case '\t':
                  sb.append("\\t");
                  break;
               case '\n':
                  sb.append("\\n");
                  break;
               case '\r':
                  sb.append("\\r");
                  break;
               case '"':
                  sb.append("\\\"");
                  break;
               case '\\':
                  sb.append("\\\\");
                  break;
               default:
                  sb.append(c);
            }
         }

         sb.append("\"");
         return sb.toString();
      }
   }
}
