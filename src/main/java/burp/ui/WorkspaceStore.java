package burp.ui;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.Reader;
import java.io.Writer;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class WorkspaceStore {
   private static final Type WORKSPACE_LIST_TYPE = (new TypeToken<List<WorkspaceStore.Workspace>>() {}).getType();
   private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
   private final File storeFile;
   private final Map<String, WorkspaceStore.Workspace> workspaces = new LinkedHashMap<>();

   public WorkspaceStore() {
      this(defaultStoreFile());
   }

   public WorkspaceStore(File storeFile) {
      this.storeFile = storeFile;
      this.load();
   }

   private static File defaultStoreFile() {
      // Prefer a visible folder so users can actually see their saved
      // workspace list in Explorer. Handles corporate machines where
      // Documents lives under OneDrive - <Company>/. Priority:
      //   1) %OneDriveCommercial%/Documents/BurpMan-Workspaces/
      //   2) %OneDrive%/Documents/BurpMan-Workspaces/
      //   3) %USERPROFILE%/Documents/BurpMan-Workspaces/
      //   4) %USERPROFILE%/BurpMan-Workspaces/
      //
      // The "-Workspaces" suffix avoids collision with any BurpMan source
      // repo checkout in the same Documents folder.
      File dir = pickBaseDir();
      if (!dir.exists()) {
         dir.mkdirs();
      }
      return new File(dir, "workspaces.json");
   }

   private static File pickBaseDir() {
      // Corporate OneDrive
      String odc = System.getenv("OneDriveCommercial");
      File cand = oneDriveDocuments(odc);
      if (cand != null) return cand;
      // Personal OneDrive
      String od = System.getenv("OneDrive");
      cand = oneDriveDocuments(od);
      if (cand != null) return cand;
      // Plain Documents under home
      String home = System.getProperty("user.home", ".");
      File docs = new File(home, "Documents");
      if (docs.isDirectory()) {
         return new File(docs, "BurpMan-Workspaces");
      }
      // Bare home fallback
      return new File(home, "BurpMan-Workspaces");
   }

   private static File oneDriveDocuments(String oneDriveRoot) {
      if (oneDriveRoot == null || oneDriveRoot.isEmpty()) return null;
      File base = new File(oneDriveRoot);
      if (!base.isDirectory()) return null;
      File docs = new File(base, "Documents");
      if (!docs.isDirectory()) return null;
      return new File(docs, "BurpMan-Workspaces");
   }

   // $VF: Could not inline inconsistent finally blocks
   // Please report this to the Vineflower issue tracker, at https://github.com/Vineflower/vineflower/issues with a copy of the class file (if you have the rights to distribute it!)
   private void load() {
      if (this.storeFile.exists()) {
         try {
            Throwable var1 = null;
            Object var2 = null;

            try {
               Reader r = new FileReader(this.storeFile);

               try {
                  List<WorkspaceStore.Workspace> list = (List<WorkspaceStore.Workspace>)GSON.fromJson(r, WORKSPACE_LIST_TYPE);
                  if (list != null) {
                     for (WorkspaceStore.Workspace w : list) {
                        if (w != null && w.name != null) {
                           if (w.collectionPaths == null) {
                              w.collectionPaths = new ArrayList<>();
                           }

                           if (w.environmentPaths == null) {
                              w.environmentPaths = new ArrayList<>();
                           }

                           this.workspaces.put(w.name, w);
                        }
                     }

                     return;
                  }
               } finally {
                  if (r != null) {
                     r.close();
                  }
               }
            } catch (Throwable var14) {
               if (var1 == null) {
                  var1 = var14;
               } else if (var1 != var14) {
                  var1.addSuppressed(var14);
               }

               throw var1;
            }
         } catch (Throwable var15) {
         }
      }
   }

   // $VF: Could not inline inconsistent finally blocks
   // Please report this to the Vineflower issue tracker, at https://github.com/Vineflower/vineflower/issues with a copy of the class file (if you have the rights to distribute it!)
   public void save() {
      try {
         File parent = this.storeFile.getParentFile();
         if (parent != null && !parent.exists()) {
            parent.mkdirs();
         }

         Throwable var2 = null;
         Object var3 = null;

         try {
            Writer w = new FileWriter(this.storeFile);

            try {
               GSON.toJson(new ArrayList<>(this.workspaces.values()), WORKSPACE_LIST_TYPE, w);
            } finally {
               if (w != null) {
                  w.close();
               }
            }
         } catch (Throwable var12) {
            if (var2 == null) {
               var2 = var12;
            } else if (var2 != var12) {
               var2.addSuppressed(var12);
            }

            throw var2;
         }
      } catch (Throwable var13) {
      }
   }

   public WorkspaceStore.Workspace getDefault() {
      WorkspaceStore.Workspace w = this.workspaces.get("Default");
      if (w == null) {
         w = new WorkspaceStore.Workspace();
         w.name = "Default";
         this.workspaces.put("Default", w);
      }

      return w;
   }

   public List<String> getWorkspaceNames() {
      return new ArrayList<>(this.workspaces.keySet());
   }

   public WorkspaceStore.Workspace get(String name) {
      return name == null ? null : this.workspaces.get(name);
   }

   public void recordSession(List<String> collectionPaths, List<String> environmentPaths, String activeEnvPath, String activeRequestKey) {
      WorkspaceStore.Workspace w = this.getDefault();
      w.collectionPaths = collectionPaths == null ? new ArrayList<>() : new ArrayList<>(collectionPaths);
      w.environmentPaths = environmentPaths == null ? new ArrayList<>() : new ArrayList<>(environmentPaths);
      w.activeEnvironmentPath = activeEnvPath;
      w.activeRequestKey = activeRequestKey;
      w.savedAtEpochMs = System.currentTimeMillis();
      this.save();
   }

   public static final class Workspace {
      public String name = "Default";
      public List<String> collectionPaths = new ArrayList<>();
      public List<String> environmentPaths = new ArrayList<>();
      public String activeEnvironmentPath;
      public String activeRequestKey;
      public long savedAtEpochMs;
   }
}
