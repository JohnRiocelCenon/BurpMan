package burp.utils;

import burp.api.montoya.MontoyaApi;
import burp.auth.AuthDecision;
import burp.auth.AuthManager;
import burp.auth.AuthResolver;
import burp.models.PostmanCollection;
import burp.parser.VariableResolver;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RequestBuilder {
   private final AuthManager authManager;
   private final MontoyaApi api;
   private final VariableResolver resolver;
   private AuthDecision lastAuthDecision;
   private final boolean debugMode = true;

   public RequestBuilder(MontoyaApi api, VariableResolver resolver) {
      this(api, resolver, null);
   }

   public AuthDecision getLastAuthDecision() {
      return this.lastAuthDecision;
   }

   public RequestBuilder(MontoyaApi api, VariableResolver resolver, AuthManager authManager) {
      this.api = api;
      this.resolver = resolver;
      this.authManager = authManager;
   }

   public byte[] buildRequest(PostmanCollection.Request request) throws Exception {
      return this.buildRequest(request, null);
   }

   public byte[] buildRequest(PostmanCollection.Request request, PostmanCollection.Auth effectiveAuth) throws Exception {
      List<String> headers = new ArrayList<>();
      String resolvedUrl = this.getResolvedUrl(request.url);
      String method = request.method != null ? request.method : "GET";
      String path = this.buildPath(request.url, resolvedUrl);
      path = percentEncodeIllegalRequestTargetChars(path);

      headers.add(method + " " + path + " HTTP/1.1");
      String host = this.buildHost(request.url, resolvedUrl);
      headers.add("Host: " + host);
      System.out.println("DEBUG: Auto-generated Host header: " + host);
      if (request.header != null) {
         for (PostmanCollection.Header header : request.header) {
            if (!header.disabled && header.key != null && header.value != null) {
               String key = this.resolver.resolve(header.key);
               String value = this.resolver.resolve(header.value);
               if (key != null) {
                  if (value == null) {
                     value = "";
                  }

                  key = key.trim();
                  value = value.trim();
                  if (key.startsWith("~")) {
                     this.api.logging().logToOutput("DEBUG: Skipped disabled Bruno-style header: " + key);
                  } else {
                     if (key.startsWith("\\~")) {
                        key = key.substring(1);
                     }

                     if (value.startsWith("\\~")) {
                        value = value.substring(1);
                     }

                     if (!key.isEmpty() && !key.contains(":")) {
                        this.api.logging().logToOutput("DEBUG: Processing custom header: " + key + ": " + value);
                        if (!"Host".equalsIgnoreCase(key)) {
                           headers.add(key + ": " + value);
                           this.api.logging().logToOutput("DEBUG: Added custom header: " + key + ": " + value);
                        } else {
                           this.api.logging().logToOutput("DEBUG: Skipped Host header: " + key + ": " + value);
                        }
                     } else {
                        this.api.logging().logToOutput("DEBUG: Skipped malformed header name: " + key);
                     }
                  }
               }
            }
         }
      }

      byte[] body = this.buildBody(request.body, headers);
      AuthResolver authResolver = new AuthResolver(this.authManager, this.resolver);
      AuthDecision authDecision = authResolver.resolve(request, effectiveAuth, body);
      this.lastAuthDecision = authDecision;
      boolean hasExplicitAuthorizationHeader = this.hasHeader(headers, "Authorization");
      this.applyAuthDecision(headers, authDecision, hasExplicitAuthorizationHeader, method, resolvedUrl, body);
      if (!this.hasHeader(headers, "Content-Length")) {
         headers.add("Content-Length: " + body.length);
      }

      for (String headerLine : headers) {
         if (headerLine.toLowerCase().startsWith("authorization:") && headerLine.toLowerCase().startsWith("authorization:") && headerLine.contains("{{")) {
            this.api.logging().logToOutput("⚠️ Unresolved Authorization allowed → " + headerLine);
         }
      }

      byte[] headerBytes = (String.join("\r\n", headers) + "\r\n\r\n").getBytes(StandardCharsets.UTF_8);
      ByteArrayOutputStream full = new ByteArrayOutputStream(headerBytes.length + body.length);
      full.write(headerBytes);
      full.write(body);
      return full.toByteArray();
   }

   private void applyAuthDecision(List<String> headers, AuthDecision decision, boolean hasExplicitAuthorizationHeader) {
      this.applyAuthDecision(headers, decision, hasExplicitAuthorizationHeader, "GET", "", new byte[0]);
   }

   private void applyAuthDecision(
      List<String> headers, AuthDecision decision, boolean hasExplicitAuthorizationHeader, String method, String fullUrl, byte[] body
   ) {
      if (decision != null) {
         if (hasExplicitAuthorizationHeader) {
            this.api.logging().logToOutput("DEBUG AuthDecision skipped because explicit Authorization header already exists.");
         } else {
            switch (decision.type) {
               case NONE:
               case BODY_OAUTH:
                  this.removeAuthorizationHeaders(headers);
                  return;
               case BEARER:
                  if (decision.bearerToken != null && !decision.bearerToken.trim().isEmpty()) {
                     this.removeAuthorizationHeaders(headers);
                     headers.add("Authorization: Bearer " + decision.bearerToken);
                  }

                  return;
               case BASIC:
                  if (decision.username != null && decision.password != null) {
                     this.removeAuthorizationHeaders(headers);
                     String credentials = decision.username + ":" + decision.password;
                     String encoded = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
                     headers.add("Authorization: Basic " + encoded);
                  }

                  return;
               case DIGEST:
               case OAUTH1:
               case AWS_SIGV4:
               case HAWK:
               case EDGEGRID:
               case API_KEY:
                  if (decision.signer != null) {
                     try {
                        decision.signer.sign(method, fullUrl, headers, body == null ? new byte[0] : body);
                     } catch (Exception var9) {
                        if (this.api != null) {
                           this.api
                              .logging()
                              .logToError("[" + decision.type + "] signer failed: " + var9.getClass().getSimpleName() + ": " + var9.getMessage());
                        }
                     }
                  }

                  return;
               case ASAP:
               case NTLM:
                  return;
            }
         }
      }
   }

   private void removeAuthorizationHeaders(List<String> headers) {
      if (headers != null) {
         headers.removeIf(h -> h != null && h.toLowerCase().startsWith("authorization:"));
      }
   }

   private String stripLineCommentsPreserveStrings(String input) {
      if (input != null && !input.isEmpty()) {
         StringBuilder out = new StringBuilder(input.length());
         int n = input.length();
         boolean inString = false;
         boolean escaped = false;

         for (int i = 0; i < n; i++) {
            char c = input.charAt(i);
            if (inString) {
               out.append(c);
               if (c == '\\' && !escaped) {
                  escaped = true;
               } else {
                  if (c == '"' && !escaped) {
                     inString = false;
                  }

                  escaped = false;
               }
            } else if (c == '"') {
               inString = true;
               out.append(c);
            } else if (c == '/' && i + 1 < n && input.charAt(i + 1) == '/') {
               int j = i + 2;

               while (j < n && input.charAt(j) != '\n' && input.charAt(j) != '\r') {
                  j++;
               }

               i = j - 1;
            } else if (c == '/' && i + 1 < n && input.charAt(i + 1) == '*') {
               int j = i + 2;

               while (j + 1 < n && (input.charAt(j) != '*' || input.charAt(j + 1) != '/')) {
                  j++;
               }

               i = Math.min(n - 1, j + 1);
            } else {
               out.append(c);
            }
         }

         return out.toString();
      } else {
         return input;
      }
   }

   private boolean hasHeader(List<String> headers, String headerName) {
      String prefix = headerName.toLowerCase() + ":";

      for (String header : headers) {
         if (header.toLowerCase().startsWith(prefix)) {
            return true;
         }
      }

      return false;
   }

   private String getResolvedUrl(Object urlData) {
      if (urlData == null) {
         return null;
      } else if (urlData instanceof String) {
         return this.applyPathVariablesFromResolver(this.resolver.resolve((String)urlData));
      } else {
         PostmanCollection.Url url = this.parseUrlObject(urlData);
         if (url == null) {
            return null;
         }
         if (url.raw == null) {
            return null;
         }
         String resolvedRaw = this.resolver.resolve(url.raw);
         return this.applyPathVariables(resolvedRaw, url);
      }
   }

   private String buildPath(Object urlData, String resolvedUrl) throws UnsupportedEncodingException {
      if (urlData == null) {
         return "/";
      } else if (resolvedUrl != null) {
         return this.extractPathFromUrl(resolvedUrl);
      } else if (urlData instanceof String) {
         String urlString = this.resolver.resolve((String)urlData);
         return this.extractPathFromUrl(urlString);
      } else {
         PostmanCollection.Url url = this.parseUrlObject(urlData);
         if (url == null) {
            return "/";
         } else {
            Map<String, String> pathVars = this.buildPathVariableMap(url);
            StringBuilder path = new StringBuilder();
            if (url.path != null && !url.path.isEmpty()) {
               path.append("/");
               List<String> resolvedPaths = new ArrayList<>();

               for (String segment : url.path) {
                  String resolvedSegment = this.resolver.resolve(segment);
                  resolvedSegment = this.resolvePathSegmentVariable(resolvedSegment, pathVars);
                  resolvedPaths.add(resolvedSegment);
               }

               path.append(String.join("/", resolvedPaths));
            } else {
               if (url.raw != null) {
                  String resolved = this.applyPathVariables(this.resolver.resolve(url.raw), url);
                  return this.extractPathFromUrl(resolved);
               }

               path.append("/");
            }

            if (url.query != null && !url.query.isEmpty()) {
               List<String> queryParts = new ArrayList<>();

               for (PostmanCollection.Query query : url.query) {
                  if (!query.disabled && query.key != null) {
                     String key = URLEncoder.encode(this.resolver.resolve(query.key), "UTF-8");
                     String value = query.value != null ? URLEncoder.encode(this.resolver.resolve(query.value), "UTF-8") : "";
                     queryParts.add(key + "=" + value);
                  }
               }

               if (!queryParts.isEmpty()) {
                  String pathStr = path.toString();
                  if (pathStr.contains("?")) {
                     path.append("&");
                  } else {
                     path.append("?");
                  }

                  path.append(String.join("&", queryParts));
               }
            }

            return path.toString();
         }
      }
   }

   private Map<String, String> buildPathVariableMap(PostmanCollection.Url url) {
      Map<String, String> vars = new LinkedHashMap<>();
      if (url == null || url.variable == null) {
         return vars;
      }
      for (PostmanCollection.Variable v : url.variable) {
         if (v == null || v.key == null || v.key.trim().isEmpty()) continue;
         String key = v.key.trim();
         String value = v.value;
         if (value != null) {
            value = this.resolver.resolve(value);
         }
         vars.put(key, value == null ? "" : value);
      }
      return vars;
   }

   private String resolvePathSegmentVariable(String segment, Map<String, String> pathVars) {
      if (segment == null || !segment.startsWith(":")) return segment;
      String key = segment.substring(1);
      if (key.isEmpty()) return segment;
      String mapped = pathVars.get(key);
      if (mapped != null) return mapped;
      String fallback = this.resolver.resolve("{{" + key + "}}");
      if (fallback != null && !fallback.equals("{{" + key + "}}")) {
         return fallback;
      }
      return segment;
   }

   private String applyPathVariables(String input, PostmanCollection.Url url) {
      if (input == null || input.isEmpty()) return input;
      String out = input;
      Map<String, String> vars = this.buildPathVariableMap(url);
      for (Map.Entry<String, String> en : vars.entrySet()) {
         String key = en.getKey();
         if (key == null || key.isEmpty()) continue;
         String value = en.getValue() == null ? "" : en.getValue();
         out = out.replaceAll("(?<=/):" + Pattern.quote(key) + "(?=([/?#]|$))",
             Matcher.quoteReplacement(value));
      }
      return this.applyPathVariablesFromResolver(out);
   }

   private String applyPathVariablesFromResolver(String input) {
      if (input == null || input.isEmpty()) return input;
      Pattern p = Pattern.compile("(?<=/):([A-Za-z0-9_-]+)(?=([/?#]|$))");
      Matcher m = p.matcher(input);
      StringBuffer sb = new StringBuffer();
      while (m.find()) {
         String key = m.group(1);
         String fallback = this.resolver.resolve("{{" + key + "}}");
         String replacement = fallback;
         if (fallback == null || fallback.equals("{{" + key + "}}")) {
            replacement = m.group(0);
         }
         m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
      }
      m.appendTail(sb);
      return sb.toString();
   }

   /**
    * Percent-encodes characters that must not appear literally in a request
    * target.
    *
    * <p>A raw space would split the request line and break HTTP framing, and
    * CR/LF would allow header injection, so they cannot be sent as-is. The
    * previous behaviour was to delete them, which keeps the request well-formed
    * but silently changes what was asked for: an OAuth {@code scope=openid ciam}
    * went out as {@code scope=openidciam} and the server rejected it as an
    * invalid scope — a failure that looks like a server or credentials problem
    * rather than a client-side edit.
    *
    * <p>Encoding preserves the value instead. If it really is wrong the server
    * can say so, and the request line stays unambiguous either way.
    */
   static String percentEncodeIllegalRequestTargetChars(String path) {
      if (path == null || path.isEmpty()) {
         return path;
      }

      boolean needsEncoding = false;
      for (int i = 0; i < path.length(); i++) {
         if (isIllegalInRequestTarget(path.charAt(i))) {
            needsEncoding = true;
            break;
         }
      }
      if (!needsEncoding) {
         return path;
      }

      StringBuilder out = new StringBuilder(path.length() + 16);
      for (int i = 0; i < path.length(); i++) {
         char c = path.charAt(i);
         if (!isIllegalInRequestTarget(c)) {
            out.append(c);
            continue;
         }
         // Encode the UTF-8 bytes, so non-ASCII separators such as U+2028
         // survive as a valid multi-byte escape rather than a lone '?'.
         byte[] bytes = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
         for (byte b : bytes) {
            out.append('%');
            out.append(Character.toUpperCase(Character.forDigit((b >> 4) & 0xF, 16)));
            out.append(Character.toUpperCase(Character.forDigit(b & 0xF, 16)));
         }
      }
      return out.toString();
   }

   private static boolean isIllegalInRequestTarget(char c) {
      return c == ' ' || c == '\t' || c == '\r' || c == '\n'
             || c == '\u2028' || c == '\u2029' || c == '\u0085';
   }

   private String extractPathFromUrl(String urlString) {
      if (urlString != null && !urlString.trim().isEmpty()) {
         try {
            urlString = urlString.trim();
            if (!urlString.contains("://")) {
               int firstSlash = urlString.indexOf(47);
               if (firstSlash > 0) {
                  return urlString.substring(firstSlash);
               } else if (!urlString.contains(".") && !urlString.contains("{{")) {
                  return urlString.startsWith("/") ? urlString : "/" + urlString;
               } else {
                  return "/";
               }
            } else {
               URL url = new URL(urlString);
               String path = url.getPath();
               if (path == null || path.isEmpty()) {
                  path = "/";
               }

               if (url.getQuery() != null) {
                  path = path + "?" + url.getQuery();
               }

               return path;
            }
         } catch (Exception var4) {
            return "/";
         }
      } else {
         return "/";
      }
   }

   private String buildHost(Object urlData, String resolvedUrl) {
      if (urlData == null) {
         return "localhost";
      } else {
         boolean hasUnresolvedVariables = this.hostPartHasUnresolvedVariables(resolvedUrl);
         if (resolvedUrl != null && !hasUnresolvedVariables && !resolvedUrl.trim().isEmpty()) {
            HttpUtils.HostInfo hostInfo = HttpUtils.parseUrl(resolvedUrl);
            return this.buildHostWithPort(hostInfo.host, hostInfo.port, hostInfo.useHttps);
         } else if (resolvedUrl != null && !hasUnresolvedVariables && !resolvedUrl.trim().isEmpty()) {
            HttpUtils.HostInfo hostInfo = HttpUtils.parseUrl(resolvedUrl);
            return this.buildHostWithPort(hostInfo.host, hostInfo.port, hostInfo.useHttps);
         } else {
            PostmanCollection.Url url = this.parseUrlObject(urlData);
            if (url != null) {
               if (url.host != null && !url.host.isEmpty()) {
                  String host = String.join(".", url.host);
                  if (url.port != null && !url.port.isEmpty()) {
                     host = host + ":" + url.port;
                  }

                  this.api.logging().logToOutput("DEBUG buildHost: Final host from object=" + host);
                  return host;
               }

               if (url.raw != null) {
                  String originalUrl = url.raw;
                  HttpUtils.HostInfo hostInfo = HttpUtils.parseUrl(originalUrl);
                  this.api.logging().logToOutput("DEBUG buildHost: Raw URL hostInfo.host=" + hostInfo.host);
                  return this.buildHostWithPort(hostInfo.host, hostInfo.port, hostInfo.useHttps);
               }
            }

            if (urlData instanceof String) {
               String urlString = (String)urlData;
               HttpUtils.HostInfo hostInfo = HttpUtils.parseUrl(urlString);
               return this.buildHostWithPort(hostInfo.host, hostInfo.port, hostInfo.useHttps);
            } else {
               return "localhost";
            }
         }
      }
   }

   private boolean hostPartHasUnresolvedVariables(String urlString) {
      if (urlString != null && !urlString.trim().isEmpty()) {
         String hostPart = this.extractHostPartForResolutionCheck(urlString);
         return hostPart == null || hostPart.trim().isEmpty() || hostPart.matches(".*\\{\\{[^}]+\\}\\}.*");
      } else {
         return true;
      }
   }

   private String extractHostPartForResolutionCheck(String urlString) {
      if (urlString == null) {
         return null;
      } else {
         String value = urlString.trim();
         int protocolIndex = value.indexOf("://");
         if (protocolIndex >= 0) {
            value = value.substring(protocolIndex + 3);
         }

         int slashIndex = value.indexOf(47);
         if (slashIndex >= 0) {
            value = value.substring(0, slashIndex);
         }

         int questionIndex = value.indexOf(63);
         if (questionIndex >= 0) {
            value = value.substring(0, questionIndex);
         }

         return value.trim();
      }
   }

   private String buildHostWithPort(String host, int port, boolean useHttps) {
      boolean isDefaultPort = useHttps && port == 443 || !useHttps && port == 80;
      return isDefaultPort ? host : host + ":" + port;
   }

   private String extractAuthValue(Object authData, String key) {
      if (authData == null) {
         return null;
      } else {
         Gson gson = new Gson();

         try {
            JsonElement element = gson.toJsonTree(authData);
            if (element.isJsonArray()) {
               for (JsonElement item : element.getAsJsonArray()) {
                  if (item.isJsonObject()) {
                     JsonObject obj = item.getAsJsonObject();
                     if (obj.has("key") && obj.get("key").getAsString().equals(key)) {
                        return obj.has("value") ? obj.get("value").getAsString() : null;
                     }
                  }
               }
            } else if (element.isJsonObject()) {
               JsonObject obj = element.getAsJsonObject();
               if (obj.has(key)) {
                  return obj.get(key).getAsString();
               }
            }
         } catch (Exception var9) {
            if (authData instanceof Map) {
               Map<?, ?> map = (Map<?, ?>)authData;
               Object value = map.get(key);
               return value != null ? value.toString() : null;
            }
         }

         return null;
      }
   }

   private String getExistingContentType(List<String> headers) {
      if (headers == null) {
         return null;
      } else {
         for (String header : headers) {
            if (header != null && header.toLowerCase().startsWith("content-type:")) {
               return header.substring(header.indexOf(58) + 1).trim();
            }
         }

         return null;
      }
   }

   private boolean isJsonBody(PostmanCollection.Body body, String contentType) {
      if (body != null
         && body.options != null
         && body.options.raw != null
         && body.options.raw.language != null
         && "json".equalsIgnoreCase(body.options.raw.language)) {
         return true;
      } else if (contentType != null && contentType.toLowerCase().contains("json")) {
         return true;
      } else {
         if (body != null && body.raw != null) {
            String t = body.raw.trim();
            if (t.length() >= 2) {
               char a = t.charAt(0);
               char z = t.charAt(t.length() - 1);
               if (a == '{' && z == '}' || a == '[' && z == ']') {
                  return true;
               }
            }
         }

         return false;
      }
   }

   private String makeJsonSafeForUnresolvedVariables(String jsonBody) {
      return jsonBody != null && !jsonBody.isEmpty() ? jsonBody.replaceAll("(?<!\\\")\\{\\{([^}]+)\\}\\}(?!\\\")", "\\\"{{$1}}\\\"") : jsonBody;
   }

   private byte[] buildBody(PostmanCollection.Body body, List<String> headers) throws Exception {
      if (body == null) {
         return new byte[0];
      } else {
         String var3 = body.mode;
         switch (body.mode.hashCode()) {
            case 112680:
               if (var3.equals("raw") && body.raw != null) {
                  String resolved = this.resolver.resolve(body.raw);
                  String contentType = this.getExistingContentType(headers);
                  if (contentType == null) {
                     contentType = this.guessContentType(body);
                     headers.add("Content-Type: " + contentType);
                  }

                  if (this.isJsonBody(body, contentType)) {
                     resolved = this.stripLineCommentsPreserveStrings(resolved);
                  }

                  return resolved.getBytes(StandardCharsets.UTF_8);
               }
               break;
            case 280343529:
               if (var3.equals("graphql") && body.graphql != null) {
                  return this.buildGraphQLBody(body.graphql, headers);
               }
               break;
            case 474151534:
               if (var3.equals("formdata") && body.formdata != null) {
                  String boundary = "----WebKitFormBoundary" + this.generateBoundary();
                  this.setContentType(headers, "multipart/form-data; boundary=" + boundary);
                  return this.buildMultipartBody(body.formdata, boundary);
               }
               break;
            case 523932863:
               if (var3.equals("urlencoded") && body.urlencoded != null) {
                  List<String> params = new ArrayList<>();

                  for (PostmanCollection.UrlEncoded param : body.urlencoded) {
                     if (!param.disabled && param.key != null) {
                        String key = URLEncoder.encode(this.resolver.resolve(param.key), "UTF-8");
                        String value = param.value != null ? URLEncoder.encode(this.resolver.resolve(param.value), "UTF-8") : "";
                        params.add(key + "=" + value);
                     }
                  }

                  this.setContentType(headers, "application/x-www-form-urlencoded");
                  return String.join("&", params).getBytes(StandardCharsets.UTF_8);
               }
         }

         return new byte[0];
      }
   }

   private byte[] buildGraphQLBody(PostmanCollection.GraphQL graphql, List<String> headers) {
      if (graphql == null) {
         return new byte[0];
      } else {
         this.api.logging().logToOutput("DEBUG GraphQL: Building GraphQL body");

         try {
            Gson gson = new GsonBuilder().serializeNulls().create();
            JsonObject body = new JsonObject();
            if (graphql.query != null) {
               String resolvedQuery = this.resolver.resolve(graphql.query);
               body.addProperty("query", resolvedQuery);
            }

            if (graphql.variables != null && !graphql.variables.trim().isEmpty()) {
               try {
                  String variablesString = graphql.variables.trim();
                  this.api.logging().logToOutput("DEBUG GraphQL: Cleaned variables string=" + variablesString);
                  JsonElement variablesElement = (JsonElement)gson.fromJson(variablesString, JsonElement.class);
                  this.api.logging().logToOutput("DEBUG GraphQL: Parsed variables element=" + variablesElement);
                  if (variablesString.contains("{{") && variablesString.contains("}}")) {
                     String variablesJson = gson.toJson(variablesElement);
                     String resolvedVariablesJson = this.resolver.resolve(variablesJson);
                     JsonElement finalVariables = (JsonElement)gson.fromJson(resolvedVariablesJson, JsonElement.class);
                     body.add("variables", finalVariables);
                     this.api.logging().logToOutput("DEBUG GraphQL: Variables had Postman vars, resolved to=" + finalVariables);
                  } else {
                     body.add("variables", variablesElement);
                     this.api.logging().logToOutput("DEBUG GraphQL: No Postman vars, using original=" + variablesElement);
                  }
               } catch (Exception var11) {
                  this.api.logging().logToOutput("DEBUG GraphQL: Variables parsing failed, trying fallback: " + var11.getMessage());

                  try {
                     String cleanVariables = graphql.variables.replaceAll("\\s+", " ").trim();
                     String resolvedVariables = this.resolver.resolve(cleanVariables);
                     JsonElement variablesElementx = (JsonElement)gson.fromJson(resolvedVariables, JsonElement.class);
                     body.add("variables", variablesElementx);
                  } catch (Exception var10) {
                     this.api.logging().logToOutput("DEBUG GraphQL: All variables parsing failed, using empty object: " + var10.getMessage());
                     body.add("variables", new JsonObject());
                  }
               }
            } else {
               body.add("variables", new JsonObject());
            }

            if (!this.hasContentType(headers)) {
               headers.add("Content-Type: application/json");
            }

            String finalBody = gson.toJson(body);
            this.api.logging().logToOutput("DEBUG GraphQL: Final JSON body=" + finalBody);
            return finalBody.getBytes(StandardCharsets.UTF_8);
         } catch (Exception var12) {
            this.api.logging().logToOutput("DEBUG GraphQL: Complete failure in buildGraphQLBody: " + var12.getMessage());
            return new byte[0];
         }
      }
   }

   private byte[] buildMultipartBody(List<PostmanCollection.FormData> formData, String boundary) {
      ByteArrayOutputStream out = new ByteArrayOutputStream();

      try {
         for (PostmanCollection.FormData field : formData) {
            if (field == null || field.disabled || field.key == null || field.key.trim().isEmpty()) continue;
            writeAscii(out, "--" + boundary + "\r\n");
            String resolvedKey = this.resolver.resolve(field.key);
            String overrideCt = field.contentType != null && !field.contentType.trim().isEmpty()
               ? field.contentType.trim() : null;
            if ("file".equalsIgnoreCase(field.type)) {
               String rawSrc = field.getSrcAsString();
               String resolvedSrc = rawSrc == null ? null : this.resolver.resolve(rawSrc);
               byte[] fileBytes = readMultipartFileBytes(resolvedSrc, resolvedKey);
               String filename = filenameFromPath(resolvedSrc);
               String mime = overrideCt != null ? overrideCt : detectMimeType(resolvedSrc, filename);
               writeAscii(out, "Content-Disposition: form-data; name=\"" + safeMultipartToken(resolvedKey)
                  + "\"; filename=\"" + safeMultipartToken(filename) + "\"\r\n");
               writeAscii(out, "Content-Type: " + mime + "\r\n\r\n");
               out.write(fileBytes);
            } else {
               writeAscii(out, "Content-Disposition: form-data; name=\"" + safeMultipartToken(resolvedKey) + "\"\r\n");
               if (overrideCt != null) {
                  writeAscii(out, "Content-Type: " + overrideCt + "\r\n");
               }
               writeAscii(out, "\r\n");
               String resolvedValue = field.value != null ? this.resolver.resolve(field.value) : "";
               writeAscii(out, resolvedValue);
            }
            writeAscii(out, "\r\n");
         }
         writeAscii(out, "--" + boundary + "--\r\n");
         return out.toByteArray();
      } catch (Exception e) {
         throw new RuntimeException("Failed to build multipart body: " + e.getMessage(), e);
      }
   }

   private static void writeAscii(ByteArrayOutputStream out, String text) throws java.io.IOException {
      out.write((text == null ? "" : text).getBytes(StandardCharsets.UTF_8));
   }

   private static String safeMultipartToken(String value) {
      if (value == null) return "";
      return value.replace("\"", "");
   }

   private static String filenameFromPath(String path) {
      if (path == null || path.trim().isEmpty()) return "upload.bin";
      try {
         return new File(path).getName();
      } catch (Exception ignore) {
         return path;
      }
   }

   private static byte[] readMultipartFileBytes(String path, String fieldName) throws Exception {
      if (path == null || path.trim().isEmpty()) {
         throw new Exception("missing file path for form-data field '" + fieldName + "'");
      }
      Path p = Path.of(path);
      if (!Files.exists(p)) {
         throw new Exception("file not found for form-data field '" + fieldName + "': " + path);
      }
      if (!Files.isRegularFile(p)) {
         throw new Exception("not a file for form-data field '" + fieldName + "': " + path);
      }
      return Files.readAllBytes(p);
   }

   private static String detectMimeType(String path, String filename) {
      try {
         if (path != null && !path.trim().isEmpty()) {
            String detected = Files.probeContentType(Path.of(path));
            if (detected != null && !detected.trim().isEmpty()) return detected;
         }
      } catch (Exception ignore) {}
      String lower = filename == null ? "" : filename.toLowerCase();
      if (lower.endsWith(".pdf")) return "application/pdf";
      if (lower.endsWith(".json")) return "application/json";
      if (lower.endsWith(".txt")) return "text/plain";
      if (lower.endsWith(".csv")) return "text/csv";
      if (lower.endsWith(".xml")) return "application/xml";
      return "application/octet-stream";
   }

   private boolean hasContentType(List<String> headers) {
      return headers.stream().anyMatch(h -> h.toLowerCase().startsWith("content-type:"));
   }

   private void setContentType(List<String> headers, String value) {
      if (headers == null || value == null) return;
      headers.removeIf(h -> h != null && h.toLowerCase().startsWith("content-type:"));
      headers.add("Content-Type: " + value);
   }

   private String guessContentType(PostmanCollection.Body body) {
      if (body.options != null && body.options.raw != null && body.options.raw.language != null) {
         String var2 = body.options.raw.language;
         switch (body.options.raw.language.hashCode()) {
            case 118807:
               if (var2.equals("xml")) {
                  return "application/xml";
               }
               break;
            case 3213227:
               if (var2.equals("html")) {
                  return "text/html";
               }
               break;
            case 3271912:
               if (var2.equals("json")) {
                  return "application/json";
               }
               break;
            case 188995949:
               if (var2.equals("javascript")) {
                  return "application/javascript";
               }
         }

         return "text/plain";
      } else {
         return body.raw != null && this.isGraphQLQuery(body.raw) ? "application/json" : "text/plain";
      }
   }

   private boolean isGraphQLQuery(String body) {
      if (body == null) {
         return false;
      } else {
         String lowerBody = body.toLowerCase().trim();
         return lowerBody.contains("\"query\"")
            || lowerBody.contains("\"mutation\"")
            || lowerBody.contains("\"subscription\"")
            || lowerBody.startsWith("query ")
            || lowerBody.startsWith("mutation ")
            || lowerBody.startsWith("subscription ");
      }
   }

   private String generateBoundary() {
      return Long.toHexString(System.currentTimeMillis());
   }

   private PostmanCollection.Url parseUrlObject(Object urlData) {
      if (urlData == null) {
         return null;
      } else {
         try {
            Gson gson = new Gson();
            JsonElement element = gson.toJsonTree(urlData);
            if (element.isJsonObject()) {
               return (PostmanCollection.Url)gson.fromJson(element, PostmanCollection.Url.class);
            }
         } catch (Exception var4) {
         }

         return null;
      }
   }
}
