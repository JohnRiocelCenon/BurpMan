package burp.models;

import java.util.List;

public class PostmanCollection {
   public PostmanCollection.Info info;
   public List<PostmanCollection.Item> item;
   public List<PostmanCollection.Variable> variable;
   public PostmanCollection.Auth auth;
   public List<PostmanCollection.Event> event;
   public transient boolean analyzed = false;

   public static class Auth {
      public String type;
      public Object bearer;
      public Object basic;
      public Object apikey;
      public Object oauth2;
      public Object digest;
      public Object oauth1;
      public Object awsv4;
      public Object hawk;
      public Object ntlm;
      public Object edgegrid;
      public Object asap;
   }

   public static class AuthAttribute {
      public String key;
      public String value;
      public String type;
   }

   public static class Body {
      public String mode;
      public String raw;
      public List<PostmanCollection.FormData> formdata;
      public List<PostmanCollection.UrlEncoded> urlencoded;
      public PostmanCollection.Options options;
      public PostmanCollection.File file;
      public PostmanCollection.GraphQL graphql;
   }

   public static class Event {
      public String listen;
      public PostmanCollection.Script script;
   }

   public static class Example {
      public String name;
      public Object originalRequest;
      public String status;
      public int code;
      public String _postman_previewlanguage;
      public List<PostmanCollection.Header> header;
      public String body;
      public long responseTime;
   }

   public static class File {
      public String src;
   }

   public static class FormData {
      public String key;
      public String value;
      public String type;
      public Object src;
      public boolean disabled;
      public String description;
      public String contentType;

      public String getSrcAsString() {
         if (this.src == null) {
            return null;
         } else if (this.src instanceof String) {
            String s = ((String)this.src).trim();
            return s.isEmpty() || "[]".equals(s) ? null : s;
         } else {
            if (this.src instanceof List) {
               List<?> srcList = (List<?>)this.src;
               if (!srcList.isEmpty()) {
                  Object first = srcList.get(0);
                  if (first == null) return null;
                  String s = first.toString().trim();
                  return s.isEmpty() || "[]".equals(s) ? null : s;
               }
               return null;
            } else if (this.src.getClass().isArray()) {
               Object[] srcArray = (Object[])this.src;
               if (srcArray.length > 0) {
                  Object first = srcArray[0];
                  if (first == null) return null;
                  String s = first.toString().trim();
                  return s.isEmpty() || "[]".equals(s) ? null : s;
               }
               return null;
            }

            String s = this.src.toString().trim();
            return s.isEmpty() || "[]".equals(s) ? null : s;
         }
      }
   }

   public static class GraphQL {
      public String query;
      public String variables;
   }

   public static class Header {
      public String key;
      public String value;
      public String type;
      public boolean disabled;
      public String description;
   }

   public static class Info {
      public String name;
      public String _postman_id;
      public String description;
      public String schema;
   }

   public static class Item {
      public String name;
      public PostmanCollection.Request request;
      public List<PostmanCollection.Item> item;
      public String description;
      public List<PostmanCollection.Event> event;
      public PostmanCollection.Auth auth;
      public List<PostmanCollection.Example> response;
      public transient boolean isCollectionWrapper = false;
      public transient boolean analyzed = false;
      public transient boolean pendingAnalyze = false;
   }

   public static class Options {
      public PostmanCollection.Raw raw;
   }

   public static class Query {
      public String key;
      public String value;
      public boolean disabled;
      public String description;
   }

   public static class Raw {
      public String language;
   }

   public static class Request {
      public String method;
      public List<PostmanCollection.Header> header;
      public PostmanCollection.Body body;
      public Object url;
      public PostmanCollection.Auth auth;
      public String description;
      public transient String rawUrlTemplate;
      public transient boolean userAdded;
   }

   public static class Script {
      public String type;
      public List<String> exec;
   }

   public static class Url {
      public String raw;
      public String protocol;
      public List<String> host;
      public List<String> path;
      public List<PostmanCollection.Query> query;
      public String port;
      public List<PostmanCollection.Variable> variable;
   }

   public static class UrlEncoded {
      public String key;
      public String value;
      public boolean disabled;
      public String description;
      public String type;
   }

   public static class Variable {
      public String key;
      public String value;
      public String type;
      public String description;
   }
}
