package burp.ui;

import burp.util.Diag;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Persists the user's workspace list — which collections and environments were
 * open, and which request was selected.
 *
 * <p>This class was previously recovered from a compiled jar by a decompiler
 * and carried its artefacts: unreachable {@code Throwable} juggling, and a
 * {@code save()} that truncated the file before serialising. That last detail
 * was a real data-loss bug — a failure part-way through writing left the user
 * with an empty or half-written {@code workspaces.json} and no way back. Both
 * methods are now written from intent, and saves go through a temporary file
 * so the previous contents survive any failure.
 */
public final class WorkspaceStore {

    private static final Type WORKSPACE_LIST_TYPE =
        new TypeToken<List<Workspace>>() {}.getType();

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private final File storeFile;
    private final Map<String, Workspace> workspaces = new LinkedHashMap<>();

    public WorkspaceStore() {
        this(defaultStoreFile());
    }

    public WorkspaceStore(File storeFile) {
        this.storeFile = storeFile;
        load();
    }

    // ---------------------------------------------------------------
    // Location
    // ---------------------------------------------------------------

    /**
     * Picks a folder the user can actually find in Explorer, handling
     * corporate machines where Documents lives under {@code OneDrive - Co/}.
     * The {@code -Workspaces} suffix avoids colliding with a BurpMan source
     * checkout sitting in the same Documents folder.
     */
    private static File defaultStoreFile() {
        File dir = pickBaseDir();
        if (!dir.exists() && !dir.mkdirs()) {
            Diag.log("could not create workspace folder: " + dir);
        }
        return new File(dir, "workspaces.json");
    }

    private static File pickBaseDir() {
        File corporate = oneDriveDocuments(System.getenv("OneDriveCommercial"));
        if (corporate != null) return corporate;

        File personal = oneDriveDocuments(System.getenv("OneDrive"));
        if (personal != null) return personal;

        String home = System.getProperty("user.home", ".");
        File docs = new File(home, "Documents");
        if (docs.isDirectory()) return new File(docs, "BurpMan-Workspaces");

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

    // ---------------------------------------------------------------
    // Persistence
    // ---------------------------------------------------------------

    private void load() {
        if (!storeFile.exists()) return;

        try (Reader reader = Files.newBufferedReader(storeFile.toPath(), StandardCharsets.UTF_8)) {
            List<Workspace> stored = GSON.fromJson(reader, WORKSPACE_LIST_TYPE);
            if (stored == null) return;

            for (Workspace w : stored) {
                if (w == null || w.name == null) continue;
                // Gson leaves absent arrays null; normalise so callers can
                // always iterate without a null check.
                if (w.collectionPaths == null) w.collectionPaths = new ArrayList<>();
                if (w.environmentPaths == null) w.environmentPaths = new ArrayList<>();
                workspaces.put(w.name, w);
            }
        } catch (IOException | RuntimeException e) {
            // A corrupt or unreadable store must not stop the extension from
            // loading — the user simply starts from an empty workspace list.
            Diag.warn("reading workspaces from " + storeFile, e);
        }
    }

    /**
     * Writes the workspace list atomically.
     *
     * <p>Serialisation happens into a sibling temporary file which then
     * replaces the original, so a failure mid-write leaves the previous list
     * intact rather than truncating it.
     */
    public void save() {
        Path target = storeFile.toPath();
        Path temp = null;
        try {
            Path parent = target.getParent();
            if (parent != null) Files.createDirectories(parent);

            temp = Files.createTempFile(parent, "workspaces", ".tmp");
            try (Writer writer = Files.newBufferedWriter(temp, StandardCharsets.UTF_8)) {
                GSON.toJson(new ArrayList<>(workspaces.values()), WORKSPACE_LIST_TYPE, writer);
            }

            try {
                Files.move(temp, target,
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                // Some network and OneDrive-backed volumes refuse atomic moves.
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
            }
            temp = null;
        } catch (IOException | RuntimeException e) {
            Diag.warn("saving workspaces to " + storeFile, e);
        } finally {
            if (temp != null) {
                try {
                    Files.deleteIfExists(temp);
                } catch (IOException e) {
                    Diag.warn("removing temporary workspace file", e);
                }
            }
        }
    }

    // ---------------------------------------------------------------
    // Accessors
    // ---------------------------------------------------------------

    public Workspace getDefault() {
        return workspaces.computeIfAbsent("Default", name -> {
            Workspace w = new Workspace();
            w.name = name;
            return w;
        });
    }

    public List<String> getWorkspaceNames() {
        return new ArrayList<>(workspaces.keySet());
    }

    public Workspace get(String name) {
        return name == null ? null : workspaces.get(name);
    }

    public void recordSession(List<String> collectionPaths,
                              List<String> environmentPaths,
                              String activeEnvPath,
                              String activeRequestKey) {
        Workspace w = getDefault();
        w.collectionPaths = collectionPaths == null
            ? new ArrayList<>() : new ArrayList<>(collectionPaths);
        w.environmentPaths = environmentPaths == null
            ? new ArrayList<>() : new ArrayList<>(environmentPaths);
        w.activeEnvironmentPath = activeEnvPath;
        w.activeRequestKey = activeRequestKey;
        w.savedAtEpochMs = System.currentTimeMillis();
        save();
    }

    /** One saved session: which files were open and what was selected. */
    public static final class Workspace {
        public String name = "Default";
        public List<String> collectionPaths = new ArrayList<>();
        public List<String> environmentPaths = new ArrayList<>();
        public String activeEnvironmentPath;
        public String activeRequestKey;
        public long savedAtEpochMs;
    }
}
