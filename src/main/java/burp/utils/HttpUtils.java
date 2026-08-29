package burp.utils;

import java.net.URL;
import java.util.regex.Pattern;

public class HttpUtils {
   private static final Pattern VARIABLE_PATTERN = Pattern.compile("\\{\\{(.+?)\\}\\}");

   public static HttpUtils.HostInfo parseUrl(String urlString) {
      if (urlString == null || urlString.isEmpty()) {
         return new HttpUtils.HostInfo("localhost", 80, false);
      } else if (VARIABLE_PATTERN.matcher(urlString).find()) {
         return parseUrlWithVariables(urlString);
      } else {
         try {
            URL url = new URL(urlString);
            String host = url.getHost();
            int port = url.getPort();
            boolean useHttps = "https".equalsIgnoreCase(url.getProtocol());
            if (port == -1) {
               port = useHttps ? 443 : 80;
            }

            return new HttpUtils.HostInfo(host, port, useHttps);
         } catch (Exception var5) {
            return parseUrlWithVariables(urlString);
         }
      }
   }

   private static HttpUtils.HostInfo parseUrlWithVariables(String urlString) {
      String host = "localhost";

      try {
         String withoutProtocol = urlString;
         if (urlString.contains("://")) {
            withoutProtocol = urlString.substring(urlString.indexOf("://") + 3);
         }

         int slashIndex = withoutProtocol.indexOf(47);
         int colonIndex = withoutProtocol.indexOf(58);
         int endIndex = withoutProtocol.length();
         if (slashIndex != -1 && colonIndex != -1) {
            endIndex = Math.min(slashIndex, colonIndex);
         } else if (slashIndex != -1) {
            endIndex = slashIndex;
         } else if (colonIndex != -1) {
            endIndex = colonIndex;
         }

         String hostPart = withoutProtocol.substring(0, endIndex);
         if (VARIABLE_PATTERN.matcher(hostPart).find()) {
            host = hostPart;
         } else if (!hostPart.isEmpty()) {
            host = hostPart;
         }
      } catch (Exception var7) {
      }

      return new HttpUtils.HostInfo(host, 80, false);
   }

   public static String getStatusText(int statusCode) {
      switch (statusCode) {
         case 100:
            return "Continue";
         case 101:
            return "Switching Protocols";
         case 200:
            return "OK";
         case 201:
            return "Created";
         case 202:
            return "Accepted";
         case 204:
            return "No Content";
         case 206:
            return "Partial Content";
         case 300:
            return "Multiple Choices";
         case 301:
            return "Moved Permanently";
         case 302:
            return "Found";
         case 304:
            return "Not Modified";
         case 307:
            return "Temporary Redirect";
         case 308:
            return "Permanent Redirect";
         case 400:
            return "Bad Request";
         case 401:
            return "Unauthorized";
         case 403:
            return "Forbidden";
         case 404:
            return "Not Found";
         case 405:
            return "Method Not Allowed";
         case 409:
            return "Conflict";
         case 410:
            return "Gone";
         case 429:
            return "Too Many Requests";
         case 500:
            return "Internal Server Error";
         case 501:
            return "Not Implemented";
         case 502:
            return "Bad Gateway";
         case 503:
            return "Service Unavailable";
         case 504:
            return "Gateway Timeout";
         default:
            return "Unknown";
      }
   }

   public static class HostInfo {
      public final String host;
      public final int port;
      public final boolean useHttps;

      public HostInfo(String host, int port, boolean useHttps) {
         this.host = host;
         this.port = port;
         this.useHttps = useHttps;
      }
   }
}
