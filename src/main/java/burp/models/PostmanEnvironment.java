package burp.models;

import java.util.List;

public class PostmanEnvironment {
   public String id;
   public String name;
   public List<PostmanEnvironment.Value> values;

   public static class Value {
      public String key;
      public String value;
      public boolean enabled;
      public String type;
   }
}
