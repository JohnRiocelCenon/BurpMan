package burp.auth;

import java.util.LinkedHashMap;
import java.util.Map;

public class FolderAuthOverride {
   public FolderAuthOverride.Type type = FolderAuthOverride.Type.INHERIT;
   public final Map<String, String> attrs = new LinkedHashMap<>();

   public String get(String k) {
      return this.attrs.get(k);
   }

   public void put(String k, String v) {
      if (v != null) {
         this.attrs.put(k, v);
      }
   }

   public static enum Type {
      NO_AUTH("No Auth"),
      INHERIT("Inherit auth from parent"),
      BEARER("Bearer Token"),
      BASIC("Basic Auth"),
      DIGEST("Digest Auth"),
      APIKEY("API Key"),
      OAUTH1("OAuth 1.0"),
      OAUTH2("OAuth 2.0"),
      JWT_BEARER("JWT Bearer"),
      HAWK("Hawk Authentication"),
      AWS("AWS Signature"),
      NTLM("NTLM Authentication"),
      AKAMAI("Akamai EdgeGrid"),
      ASAP("ASAP (Atlassian)");

      public final String label;

      private Type(String label) {
         this.label = label;
      }

      public static FolderAuthOverride.Type fromLabel(String label) {
         FolderAuthOverride.Type[] var4;
         for (FolderAuthOverride.Type t : var4 = values()) {
            if (t.label.equals(label)) {
               return t;
            }
         }

         return INHERIT;
      }
   }
}
