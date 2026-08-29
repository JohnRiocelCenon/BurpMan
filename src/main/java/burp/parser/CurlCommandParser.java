package burp.parser;

import burp.models.PostmanCollection;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public final class CurlCommandParser {
   public PostmanCollection.Request parse(String input) {
      if (input == null) {
         throw new IllegalArgumentException("empty command");
      } else {
         String cmd = input.trim();
         if (cmd.startsWith("$ ")) {
            cmd = cmd.substring(2).trim();
         }

         if (cmd.regionMatches(true, 0, "curl", 0, 4) && (cmd.length() == 4 || Character.isWhitespace(cmd.charAt(4)))) {
            cmd = cmd.substring(4).trim();
         }

         cmd = cmd.replace("\\\n", " ").replace("\\\r\n", " ").replace("\r", " ");
         List<String> tokens = tokenize(cmd);
         if (tokens.isEmpty()) {
            throw new IllegalArgumentException("no command found");
         } else {
            PostmanCollection.Request req = new PostmanCollection.Request();
            req.method = null;
            req.header = new ArrayList<>();
            List<String[]> formFields = new ArrayList<>();
            boolean isMultipart = false;
            boolean isUrlencoded = false;
            StringBuilder rawBody = new StringBuilder();
            String url = null;
            boolean forceGet = false;

            for (int i = 0; i < tokens.size(); i++) {
               String t = tokens.get(i);
               if (!t.isEmpty()) {
                  if ("-X".equals(t) || "--request".equals(t)) {
                     if (++i < tokens.size()) {
                        req.method = tokens.get(i).toUpperCase();
                     }
                  } else if ("-H".equals(t) || "--header".equals(t)) {
                     if (++i < tokens.size()) {
                        addHeader(req, tokens.get(i));
                     }
                  } else if ("-d".equals(t) || "--data".equals(t) || "--data-raw".equals(t) || "--data-ascii".equals(t) || "--data-binary".equals(t)) {
                     if (++i < tokens.size()) {
                        if (rawBody.length() > 0) {
                           rawBody.append('&');
                        }

                        rawBody.append(tokens.get(i));
                     }
                  } else if ("--data-urlencoded".equals(t)) {
                     if (++i < tokens.size()) {
                        isUrlencoded = true;
                        String kv = tokens.get(i);
                        int eq = kv.indexOf(61);
                        if (eq >= 0) {
                           formFields.add(new String[]{kv.substring(0, eq), kv.substring(eq + 1)});
                        } else {
                           formFields.add(new String[]{kv, ""});
                        }
                     }
                  } else if ("-F".equals(t) || "--form".equals(t)) {
                     if (++i < tokens.size()) {
                        isMultipart = true;
                        String kv = tokens.get(i);
                        int eq = kv.indexOf(61);
                        if (eq >= 0) {
                           formFields.add(new String[]{kv.substring(0, eq), kv.substring(eq + 1)});
                        } else {
                           formFields.add(new String[]{kv, ""});
                        }
                     }
                  } else if ("-u".equals(t) || "--user".equals(t)) {
                     if (++i < tokens.size()) {
                        String userPass = tokens.get(i);
                        String encoded = Base64.getEncoder().encodeToString(userPass.getBytes(StandardCharsets.UTF_8));
                        addHeader(req, "Authorization: Basic " + encoded);
                     }
                  } else if ("-b".equals(t) || "--cookie".equals(t)) {
                     if (++i < tokens.size()) {
                        addHeader(req, "Cookie: " + tokens.get(i));
                     }
                  } else if ("-A".equals(t) || "--user-agent".equals(t)) {
                     if (++i < tokens.size()) {
                        addHeader(req, "User-Agent: " + tokens.get(i));
                     }
                  } else if ("-e".equals(t) || "--referer".equals(t)) {
                     if (++i < tokens.size()) {
                        addHeader(req, "Referer: " + tokens.get(i));
                     }
                  } else if ("--url".equals(t)) {
                     if (++i < tokens.size()) {
                        url = tokens.get(i);
                     }
                  } else if ("-G".equals(t) || "--get".equals(t)) {
                     forceGet = true;
                  } else if (t.startsWith("-") && !looksLikeUrl(t)) {
                     if (i + 1 < tokens.size() && !tokens.get(i + 1).startsWith("-") && consumesValue(t)) {
                        i++;
                     }
                  } else if (url == null || looksLikeUrl(t)) {
                     url = t;
                  }
               }
            }

            if (url != null && !url.isEmpty()) {
               req.url = url;
               if (req.method == null) {
                  if (forceGet) {
                     req.method = "GET";
                  } else if (rawBody.length() <= 0 && formFields.isEmpty()) {
                     req.method = "GET";
                  } else {
                     req.method = "POST";
                  }
               }

               if (isMultipart) {
                  req.body = new PostmanCollection.Body();
                  req.body.mode = "formdata";
                  req.body.formdata = new ArrayList<>();

                  for (String[] kv : formFields) {
                     PostmanCollection.FormData fd = new PostmanCollection.FormData();
                     fd.key = kv[0];
                     fd.value = kv[1];
                     fd.type = "text";
                     req.body.formdata.add(fd);
                  }
               } else if (isUrlencoded) {
                  req.body = new PostmanCollection.Body();
                  req.body.mode = "urlencoded";
                  req.body.urlencoded = new ArrayList<>();

                  for (String[] kv : formFields) {
                     PostmanCollection.UrlEncoded ue = new PostmanCollection.UrlEncoded();
                     ue.key = kv[0];
                     ue.value = kv[1];
                     req.body.urlencoded.add(ue);
                  }
               } else if (rawBody.length() > 0) {
                  req.body = new PostmanCollection.Body();
                  req.body.mode = "raw";
                  req.body.raw = rawBody.toString();
                  String contentType = headerValue(req, "Content-Type");
                  if (contentType != null) {
                     PostmanCollection.Options opts = new PostmanCollection.Options();
                     PostmanCollection.Raw raw = new PostmanCollection.Raw();
                     if (contentType.contains("json")) {
                        raw.language = "json";
                     } else if (contentType.contains("xml")) {
                        raw.language = "xml";
                     } else if (contentType.contains("html")) {
                        raw.language = "html";
                     } else {
                        raw.language = "text";
                     }

                     opts.raw = raw;
                     req.body.options = opts;
                  }
               }

               return req;
            } else {
               throw new IllegalArgumentException("could not find URL in command");
            }
         }
      }
   }

   private static void addHeader(PostmanCollection.Request req, String headerLine) {
      if (headerLine != null) {
         int colon = headerLine.indexOf(58);
         if (colon >= 0) {
            PostmanCollection.Header h = new PostmanCollection.Header();
            h.key = headerLine.substring(0, colon).trim();
            h.value = headerLine.substring(colon + 1).trim();
            if (req.header == null) {
               req.header = new ArrayList<>();
            }

            req.header.removeIf(existing -> existing != null && existing.key != null && existing.key.equalsIgnoreCase(h.key));
            req.header.add(h);
         }
      }
   }

   private static String headerValue(PostmanCollection.Request req, String name) {
      if (req.header != null && name != null) {
         for (PostmanCollection.Header h : req.header) {
            if (h != null && h.key != null && name.equalsIgnoreCase(h.key)) {
               return h.value;
            }
         }

         return null;
      } else {
         return null;
      }
   }

   private static boolean looksLikeUrl(String s) {
      if (s == null) {
         return false;
      } else {
         String low = s.toLowerCase();
         return low.startsWith("http://") || low.startsWith("https://") || low.startsWith("ws://") || low.startsWith("wss://");
      }
   }

   private static boolean consumesValue(String flag) {
      if (flag == null) {
         return false;
      } else {
         switch (flag.hashCode()) {
            case -2081040344:
               if (flag.equals("--upload-file")) {
                  return true;
               }
               break;
            case -1811617716:
               if (flag.equals("--resolve")) {
                  return true;
               }
               break;
            case -1616754482:
               if (flag.equals("--proxy")) {
                  return true;
               }
               break;
            case -1475467810:
               if (flag.equals("--connect-timeout")) {
                  return true;
               }
               break;
            case 1470:
               if (flag.equals("-K")) {
                  return true;
               }
               break;
            case 1474:
               if (flag.equals("-O")) {
                  return true;
               }
               break;
            case 1479:
               if (flag.equals("-T")) {
                  return true;
               }
               break;
            case 1506:
               if (flag.equals("-o")) {
                  return true;
               }
               break;
            case 1515:
               if (flag.equals("-x")) {
                  return true;
               }
               break;
            case 43005119:
               if (flag.equals("--key")) {
                  return true;
               }
               break;
            case 377680694:
               if (flag.equals("--max-time")) {
                  return true;
               }
               break;
            case 1031963938:
               if (flag.equals("--cacert")) {
                  return true;
               }
               break;
            case 1045221602:
               if (flag.equals("--config")) {
                  return true;
               }
               break;
            case 1332920260:
               if (flag.equals("--cert")) {
                  return true;
               }
               break;
            case 1394501281:
               if (flag.equals("--output")) {
                  return true;
               }
         }

         return false;
      }
   }

   private static List<String> tokenize(String s) {
      List<String> out = new ArrayList<>();
      if (s == null) {
         return out;
      } else {
         StringBuilder cur = new StringBuilder();
         boolean inSingle = false;
         boolean inDouble = false;
         boolean any = false;

         for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inSingle) {
               if (c == '\'') {
                  inSingle = false;
               } else {
                  cur.append(c);
               }
            } else if (inDouble) {
               if (c == '"') {
                  inDouble = false;
               } else {
                  if (c == '\\' && i + 1 < s.length()) {
                     char n = s.charAt(i + 1);
                     if (n == '"' || n == '\\' || n == '$' || n == '`') {
                        cur.append(n);
                        i++;
                        continue;
                     }
                  }

                  cur.append(c);
               }
            } else if (c == '\'') {
               inSingle = true;
               any = true;
            } else if (c == '"') {
               inDouble = true;
               any = true;
            } else if (c == '\\' && i + 1 < s.length()) {
               cur.append(s.charAt(i + 1));
               i++;
               any = true;
            } else if (Character.isWhitespace(c)) {
               if (cur.length() > 0 || any) {
                  out.add(cur.toString());
                  cur.setLength(0);
                  any = false;
               }
            } else {
               cur.append(c);
               any = true;
            }
         }

         if (cur.length() > 0 || any) {
            out.add(cur.toString());
         }

         return out;
      }
   }
}
