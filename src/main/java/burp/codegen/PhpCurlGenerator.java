package burp.codegen;

import java.util.Map.Entry;

public final class PhpCurlGenerator implements CodeGenerator {
   @Override
   public String label() {
      return "PHP — cURL";
   }

   @Override
   public String fileExtension() {
      return "php";
   }

   @Override
   public String generate(GenRequest req) {
      StringBuilder sb = new StringBuilder();
      sb.append("<?php\n\n");
      sb.append("$curl = curl_init();\n\n");
      sb.append("curl_setopt_array($curl, [\n");
      sb.append("    CURLOPT_URL => ").append(phpStr(req.url)).append(",\n");
      sb.append("    CURLOPT_RETURNTRANSFER => true,\n");
      sb.append("    CURLOPT_CUSTOMREQUEST => ").append(phpStr(req.method)).append(",\n");
      if (req.body != null && !req.body.isEmpty()) {
         sb.append("    CURLOPT_POSTFIELDS => ").append(phpStr(req.body)).append(",\n");
      }

      if (!req.headers.isEmpty()) {
         sb.append("    CURLOPT_HTTPHEADER => [\n");

         for (Entry<String, String> e : req.headers.entrySet()) {
            sb.append("        ").append(phpStr(e.getKey() + ": " + e.getValue())).append(",\n");
         }

         sb.append("    ],\n");
      }

      sb.append("]);\n\n");
      sb.append("$response = curl_exec($curl);\n");
      sb.append("$status = curl_getinfo($curl, CURLINFO_HTTP_CODE);\n");
      sb.append("curl_close($curl);\n\n");
      sb.append("echo $status . PHP_EOL;\n");
      sb.append("echo $response;\n");
      return sb.toString();
   }

   private static String phpStr(String s) {
      return s == null ? "''" : "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'";
   }
}
