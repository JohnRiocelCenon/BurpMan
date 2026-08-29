package burp.utils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

public class FormatUtils {
   private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();
   private static final Gson compactGson = new Gson();

   public static String prettyPrintJson(String json) {
      try {
         JsonElement je = JsonParser.parseString(json);
         return gson.toJson(je);
      } catch (Exception var2) {
         return json;
      }
   }

   public static String minifyJson(String json) {
      try {
         JsonElement je = JsonParser.parseString(json);
         return compactGson.toJson(je);
      } catch (Exception var2) {
         return json;
      }
   }

   public static String prettyPrintXml(String xml) {
      try {
         return formatXml(xml);
      } catch (Exception var2) {
         return xml;
      }
   }

   private static String formatXml(String xml) {
      StringBuilder sb = new StringBuilder();
      int indent = 0;
      boolean inTag = false;

      for (int i = 0; i < xml.length(); i++) {
         char c = xml.charAt(i);
         if (c == '<') {
            if (!inTag) {
               inTag = true;
               if (i + 1 < xml.length() && xml.charAt(i + 1) == '/') {
                  indent--;
               }

               if (sb.length() > 0 && sb.charAt(sb.length() - 1) != '\n') {
                  sb.append("\n");
               }

               for (int j = 0; j < indent; j++) {
                  sb.append("  ");
               }
            }
         } else if (c == '>') {
            sb.append(c);
            inTag = false;
            if (i + 1 < xml.length() && xml.charAt(i + 1) == '<' && i + 2 < xml.length() && xml.charAt(i + 2) != '/') {
               indent++;
            }
         } else {
            sb.append(c);
         }
      }

      return sb.toString();
   }

   public static String autoFormat(String content, String contentType) {
      if (contentType == null) {
         contentType = "";
      }

      String lowerType = contentType.toLowerCase();
      if (lowerType.contains("application/json") || lowerType.contains("json")) {
         return prettyPrintJson(content);
      } else if (!lowerType.contains("application/xml") && !lowerType.contains("text/xml") && !lowerType.contains("xml")) {
         if (content.trim().startsWith("{") || content.trim().startsWith("[")) {
            try {
               return prettyPrintJson(content);
            } catch (Exception var5) {
            }
         }

         if (content.trim().startsWith("<")) {
            try {
               return prettyPrintXml(content);
            } catch (Exception var4) {
            }
         }

         return content;
      } else {
         return prettyPrintXml(content);
      }
   }

   public static boolean isValidJson(String json) {
      try {
         JsonParser.parseString(json);
         return true;
      } catch (Exception var2) {
         return false;
      }
   }

   public static boolean isValidXml(String xml) {
      try {
         return xml.trim().startsWith("<") && xml.trim().endsWith(">");
      } catch (Exception var2) {
         return false;
      }
   }

   public static String formatBytes(long bytes) {
      if (bytes < 1024L) {
         return bytes + " B";
      } else {
         return bytes < 1048576L ? String.format("%.2f KB", bytes / 1024.0) : String.format("%.2f MB", bytes / 1048576.0);
      }
   }
}
