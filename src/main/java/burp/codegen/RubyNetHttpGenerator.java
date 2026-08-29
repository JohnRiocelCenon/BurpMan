package burp.codegen;

import java.util.Map.Entry;

public final class RubyNetHttpGenerator implements CodeGenerator {
   @Override
   public String label() {
      return "Ruby — Net::HTTP";
   }

   @Override
   public String fileExtension() {
      return "rb";
   }

   @Override
   public String generate(GenRequest req) {
      StringBuilder sb = new StringBuilder();
      sb.append("require 'uri'\n");
      sb.append("require 'net/http'\n\n");
      sb.append("url = URI(").append(rbStr(req.url)).append(")\n");
      sb.append("http = Net::HTTP.new(url.host, url.port)\n");
      if (req.url.startsWith("https:")) {
         sb.append("http.use_ssl = true\n");
      }

      sb.append("\n");
      String reqClass = "Net::HTTP::" + capitalize(req.method.toLowerCase());
      sb.append("request = ").append(reqClass).append(".new(url)\n");

      for (Entry<String, String> e : req.headers.entrySet()) {
         sb.append("request[").append(rbStr(e.getKey())).append("] = ").append(rbStr(e.getValue())).append("\n");
      }

      if (req.body != null && !req.body.isEmpty()) {
         sb.append("request.body = ").append(rbStr(req.body)).append("\n");
      }

      sb.append("\nresponse = http.request(request)\n");
      sb.append("puts response.code\n");
      sb.append("puts response.body\n");
      return sb.toString();
   }

   private static String rbStr(String s) {
      return s == null ? "nil" : "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("#{", "\\#{") + "\"";
   }

   private static String capitalize(String s) {
      return s != null && !s.isEmpty() ? Character.toUpperCase(s.charAt(0)) + s.substring(1) : s;
   }
}
