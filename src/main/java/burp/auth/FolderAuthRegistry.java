package burp.auth;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

public class FolderAuthRegistry {
   private final Map<String, FolderAuthOverride> overrides = new LinkedHashMap<>();
   private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

   private static String normalizePath(String folderPath) {
      if (folderPath == null) return null;
      String p = folderPath.trim().replace('\\', '/');
      while (p.contains("//")) p = p.replace("//", "/");
      if (p.startsWith("/")) p = p.substring(1);
      if (p.endsWith("/") && p.length() > 1) p = p.substring(0, p.length() - 1);
      if (p.equalsIgnoreCase("Workspace")) return "";
      String prefix = "Workspace/";
      if (p.regionMatches(true, 0, prefix, 0, prefix.length())) {
         return p.substring(prefix.length());
      }
      return p;
   }

   private void migrateLegacyWorkspaceKeys() {
      if (this.overrides.isEmpty()) return;
      java.util.List<String> keys = new java.util.ArrayList<>(this.overrides.keySet());
      for (String key : keys) {
         String normalized = normalizePath(key);
         if (normalized == null || normalized.equals(key)) continue;
         FolderAuthOverride value = this.overrides.remove(key);
         if (value == null) continue;
         this.overrides.putIfAbsent(normalized, value);
      }
   }

   public void addChangeListener(Runnable r) {
      if (r != null) {
         this.listeners.add(r);
      }
   }

   private void fire() {
      for (Runnable r : this.listeners) {
         try {
            r.run();
         } catch (Exception var4) {
         }
      }
   }

   public void set(String folderPath, FolderAuthOverride override) {
      String key = normalizePath(folderPath);
      if (key != null) {
         this.migrateLegacyWorkspaceKeys();
         if (override != null && override.type != FolderAuthOverride.Type.INHERIT) {
            this.overrides.put(key, override);
         } else {
            this.overrides.remove(key);
         }

         this.fire();
      }
   }

   public FolderAuthOverride get(String folderPath) {
      this.migrateLegacyWorkspaceKeys();
      return this.overrides.get(normalizePath(folderPath));
   }

   public FolderAuthOverride resolve(String folderPath) {
      this.migrateLegacyWorkspaceKeys();
      String startPath = normalizePath(folderPath);
      if (startPath == null) {
         return null;
      } else {
         String p = startPath;

         while (true) {
            FolderAuthOverride o = this.overrides.get(p);
            if (o != null && o.type != FolderAuthOverride.Type.INHERIT) {
               return o;
            }

            int slash = p.lastIndexOf(47);
            if (slash < 0) {
               if (!p.isEmpty()) {
                  FolderAuthOverride root = this.overrides.get("");
                  if (root != null && root.type != FolderAuthOverride.Type.INHERIT) {
                     return root;
                  }
               }

               return null;
            }

            p = p.substring(0, slash);
         }
      }
   }

   public void clear() {
      this.overrides.clear();
      this.fire();
   }

   public Set<String> keys() {
      this.migrateLegacyWorkspaceKeys();
      return new HashSet<>(this.overrides.keySet());
   }

   public void remove(String folderPath) {
      String key = normalizePath(folderPath);
      this.migrateLegacyWorkspaceKeys();
      if (key != null && this.overrides.remove(key) != null) {
         this.fire();
      }
   }
}
