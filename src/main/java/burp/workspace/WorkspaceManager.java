package burp.workspace;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;

/**
 * Materializes a Bruno-style workspace folder for a collection.
 *
 * <p>Bruno keeps a collection folder on disk that contains
 * {@code .env}, {@code environments/}, and per-request {@code .bru} files.
 * BurpMan users often import a single JSON (Postman export, Bruno CLI export,
 * OpenAPI conversion) that has none of that structure — so switching between
 * envs, sharing secrets between requests, and persisting configuration
 * between sessions is painful.
 *
 * <p>This class gives every imported collection (including single-file
 * imports) a stable persistent home under a visible folder like
 * {@code ~/Documents/BurpMan-Workspaces/&lt;safeName&gt;/} (or
 * {@code ~/BurpMan-Workspaces/&lt;safeName&gt;/} if there's no Documents
 * folder) with the same shape Bruno uses:
 *
 * <pre>
 *   ~/Documents/BurpMan-Workspaces/
 *     PDP_2026_PenTest_1/           &lt;- workspace root
 *       .env                        &lt;- dotenv secrets (starts empty w/ header)
 *       environments/               &lt;- per-env .yml/.bru files
 *       README.md                   &lt;- explains the layout to the user
 * </pre>
 *
 * <p>The auto-discovery in {@code ImporterPanel} then picks up whatever
 * files the user (or another tool) drops here — no need to re-import each
 * time.
 *
 * <p>All operations are idempotent and best-effort: existing files are
 * never overwritten, and IO errors return null instead of throwing.
 */
public final class WorkspaceManager {

    private WorkspaceManager() { /* static-only */ }

    /**
     * Returns (creating if needed) the Bruno-style workspace folder for the
     * given collection source. The source may be a JSON file, a folder, or
     * any other path — the workspace is keyed by the sanitized display name.
     *
     * <p>If the source is already a directory that contains a
     * {@code .env} or {@code environments/} subfolder, that directory is
     * returned as-is (the user already has a Bruno-shaped workspace on disk
     * and we should not duplicate their files under {@code ~/.burpman}).
     *
     * @param source the imported collection file or folder (may be null)
     * @return the workspace root, or null if IO failed / source was null
     */
    public static File getOrCreateWorkspace(File source) {
        if (source == null) return null;
        try {
            // If the source is already a Bruno-shaped folder, use it directly.
            if (source.isDirectory()) {
                File dotenv = new File(source, ".env");
                File envs = new File(source, "environments");
                if (dotenv.isFile() || envs.isDirectory()) {
                    return source;
                }
            }

            Path root = defaultWorkspaceRoot();
            if (root == null) return null;

            String name = deriveWorkspaceName(source);
            Path ws = root.resolve(name);
            Files.createDirectories(ws);

            // Pre-create the folder shape Bruno uses.
            Path envsDir = ws.resolve("environments");
            if (!Files.isDirectory(envsDir)) {
                Files.createDirectories(envsDir);
            }

            // Note: no auto `.env` seed — dotenv is one optional format,
            // not a default. Users can drop a `.env` file at the workspace
            // root themselves; env auto-discovery will pick it up.

            Path readme = ws.resolve("README.md");
            if (!Files.exists(readme)) {
                String body = "# BurpMan Workspace - " + name + "\n\n"
                    + "This folder holds the Bruno-style environment files for the collection\n"
                    + "**" + safeSourceLabel(source) + "**.\n\n"
                    + "## Layout\n\n"
                    + "- `environments/` - per-environment variable files\n"
                    + "  (matches Bruno's `ENVIRONMENTS` panel). Supported formats:\n"
                    + "  `.yml`, `.yaml`, `.bru`, `.json`. One file per environment.\n"
                    + "- `.env` (optional) - dotenv-style secrets (matches Bruno's\n"
                    + "  `.ENV FILES` panel). Format: `KEY=VALUE` or `KEY: VALUE`,\n"
                    + "  `#` for comments.\n\n"
                    + "## How BurpMan uses this\n\n"
                    + "Whenever you re-open the collection above in BurpMan, every file\n"
                    + "in `environments/` and any non-empty `.env` here is auto-added to\n"
                    + "the Environment dropdown. Switch between them like you would in\n"
                    + "Bruno's own sidebar - no manual Add... clicks needed.\n\n"
                    + "You can also just drop new `.yml` files into `environments/`\n"
                    + "from Windows Explorer; BurpMan will pick them up on the next load.\n";
                Files.write(readme, body.getBytes(StandardCharsets.UTF_8));
            }

            return ws.toFile();
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /**
     * Returns the base workspace directory. Uses a visible location under
     * {@code Documents/BurpMan-Workspaces/} so users can actually see and
     * browse the folder in Explorer/Finder instead of hunting through a
     * hidden {@code .burpman} directory. The {@code -Workspaces} suffix
     * keeps it clearly distinct from any {@code BurpMan} source repo
     * checkout in the same Documents folder.
     *
     * <p>Path priority (first match wins) — designed to work for both
     * personal machines and corporate machines with OneDrive-redirected
     * Documents folders (common in Microsoft-managed tenants like
     * Manulife, etc.):
     *
     * <ol>
     *   <li>{@code %OneDriveCommercial%/Documents/BurpMan-Workspaces/}
     *       — corporate OneDrive (e.g. {@code C:\Users\<u>\OneDrive - <Company>\Documents}).</li>
     *   <li>{@code %OneDrive%/Documents/BurpMan-Workspaces/}
     *       — personal / consumer OneDrive.</li>
     *   <li>{@code %USERPROFILE%/Documents/BurpMan-Workspaces/}
     *       — plain Documents (also handles GPO-redirected Documents that
     *       point at OneDrive under the hood).</li>
     *   <li>{@code %USERPROFILE%/BurpMan-Workspaces/}
     *       — bare home fallback when no Documents folder exists (rare;
     *       macOS/Linux without a Documents dir).</li>
     * </ol>
     */
    public static Path defaultWorkspaceRoot() {
        try {
            // 1) Corporate OneDrive first — this is the common case on
            //    managed enterprise Windows machines.
            String oneDriveCommercial = System.getenv("OneDriveCommercial");
            Path p = oneDriveDocumentsChild(oneDriveCommercial);
            if (p != null) return p;

            // 2) Personal / consumer OneDrive.
            String oneDrive = System.getenv("OneDrive");
            p = oneDriveDocumentsChild(oneDrive);
            if (p != null) return p;

            // 3) Plain Documents under home.
            String home = System.getProperty("user.home");
            if (home == null || home.isEmpty()) {
                home = System.getProperty("java.io.tmpdir");
            }
            if (home == null || home.isEmpty()) return null;

            Path documents = Paths.get(home, "Documents");
            if (Files.isDirectory(documents)) {
                return documents.resolve("BurpMan-Workspaces");
            }

            // 4) Bare home fallback (macOS/Linux without Documents).
            return Paths.get(home, "BurpMan-Workspaces");
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * If {@code oneDriveRoot} points to an existing folder that has a
     * {@code Documents/} subfolder, return
     * {@code <oneDriveRoot>/Documents/BurpMan-Workspaces}. Otherwise null.
     */
    private static Path oneDriveDocumentsChild(String oneDriveRoot) {
        if (oneDriveRoot == null || oneDriveRoot.isEmpty()) return null;
        try {
            Path base = Paths.get(oneDriveRoot);
            if (!Files.isDirectory(base)) return null;
            Path docs = base.resolve("Documents");
            if (!Files.isDirectory(docs)) return null;
            return docs.resolve("BurpMan-Workspaces");
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * Turns a source path into a filesystem-safe folder name. Collisions are
     * possible but rare - two collections with the same base name will share
     * a workspace, which mirrors how the user probably thinks about them.
     */
    public static String deriveWorkspaceName(File source) {
        String raw = source.getName();
        if (raw == null || raw.isEmpty()) raw = "collection";
        String lower = raw.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".json") || lower.endsWith(".yaml") || lower.endsWith(".yml")
            || lower.endsWith(".bru")) {
            int dot = raw.lastIndexOf('.');
            if (dot > 0) raw = raw.substring(0, dot);
        }
        if (raw.toLowerCase(Locale.ROOT).endsWith(".postman_collection")) {
            raw = raw.substring(0, raw.length() - ".postman_collection".length());
        }
        StringBuilder sb = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '-' || c == '_' || c == '.') {
                sb.append(c);
            } else if (Character.isWhitespace(c)) {
                sb.append('_');
            } else {
                sb.append('_');
            }
        }
        String safe = sb.toString().replaceAll("_+", "_").replaceAll("^[._-]+|[._-]+$", "");
        if (safe.isEmpty()) safe = "collection";
        if (safe.length() > 80) safe = safe.substring(0, 80);
        return safe;
    }

    /**
     * Peek at the first ~8 KB of a JSON/YAML collection file and try to
     * extract the collection's <b>display name</b> (the {@code info.name}
     * field in Postman JSON, the {@code name} field in Bruno's
     * {@code bruno.json}, or the {@code name:} key in an OpenCollection
     * YAML). Returns {@code null} if the file doesn't obviously look like
     * a collection.
     *
     * <p>This is a shallow regex scan — we don't parse the whole file for
     * speed. Falls back to the filename in the caller if this returns null.
     */
    public static String peekCollectionName(File source) {
        if (source == null || !source.isFile()) return null;
        try (java.io.InputStream in = new java.io.FileInputStream(source)) {
            byte[] buf = new byte[8192];
            int n = in.read(buf);
            if (n <= 0) return null;
            String head = new String(buf, 0, n, StandardCharsets.UTF_8);
            // Postman JSON: "info": { "name": "..." }
            java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "\"info\"\\s*:\\s*\\{[^}]*?\"name\"\\s*:\\s*\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"",
                java.util.regex.Pattern.DOTALL).matcher(head);
            if (m.find()) return unescapeJson(m.group(1));
            // Bruno bruno.json: top-level { "name": "..." }
            m = java.util.regex.Pattern.compile(
                "^\\s*\\{[^}]*?\"name\"\\s*:\\s*\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"",
                java.util.regex.Pattern.DOTALL).matcher(head);
            if (m.find()) return unescapeJson(m.group(1));
            // OpenCollection YAML: top-level "name: ..." (unquoted or quoted)
            m = java.util.regex.Pattern.compile(
                "(?m)^\\s*name\\s*:\\s*[\"']?([^\"'\\r\\n#]+?)[\"']?\\s*(?:#.*)?$")
                .matcher(head);
            if (m.find()) {
                String val = m.group(1).trim();
                if (!val.isEmpty()) return val;
            }
            return null;
        } catch (java.io.IOException | RuntimeException e) {
            return null;
        }
    }

    private static String unescapeJson(String s) {
        if (s == null) return null;
        return s.replace("\\\"", "\"")
                .replace("\\\\", "\\")
                .replace("\\n", "\n")
                .replace("\\t", "\t")
                .replace("\\r", "\r")
                .replace("\\/", "/");
    }

    /**
     * Sanitize a user-facing collection name into something safe for a
     * filesystem folder, but preserving spaces and hyphens so the folder
     * still reads naturally. Unlike {@link #deriveWorkspaceName(File)}
     * this does <b>not</b> collapse spaces into underscores — so an
     * {@code info.name} of {@code "PDP - Prod"} becomes the folder
     * {@code "PDP - Prod"}.
     */
    public static String sanitizeFolderName(String raw) {
        if (raw == null || raw.trim().isEmpty()) return "collection";
        String s = raw.trim();
        // Strip characters Windows forbids: \ / : * ? " < > |
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' || c == '/' || c == ':' || c == '*' || c == '?'
                || c == '"' || c == '<' || c == '>' || c == '|') {
                sb.append(' ');
            } else if (c < 0x20) {
                // control chars — skip
            } else {
                sb.append(c);
            }
        }
        String safe = sb.toString().replaceAll("\\s+", " ").trim();
        // Trim trailing dots/spaces (Windows quirk).
        while (safe.endsWith(".") || safe.endsWith(" ")) {
            safe = safe.substring(0, safe.length() - 1);
        }
        if (safe.isEmpty()) safe = "collection";
        if (safe.length() > 80) safe = safe.substring(0, 80).trim();
        return safe;
    }

    /**
     * Create (or reuse) a Bruno-style workspace folder at an <b>explicit</b>
     * location + name. Handles Bruno-style de-duplication: if
     * {@code <location>/<name>} already exists as a BurpMan workspace
     * (has {@code README.md} + {@code environments/}), that folder is
     * returned as-is. If it exists but is <b>not</b> a BurpMan workspace,
     * a suffixed name is tried (e.g. {@code "PDP - 1"}, {@code "PDP - 2"})
     * until an unused slot is found — matching Bruno's own behaviour.
     *
     * <p>The workspace shape (empty {@code .env}, {@code environments/}
     * folder, {@code README.md} explainer) is the same as
     * {@link #getOrCreateWorkspace(File)}.
     *
     * @param location parent directory (created if missing)
     * @param requestedName folder name to use for the workspace
     * @return the workspace root, or null if IO failed
     */
    public static File getOrCreateWorkspaceAt(File location, String requestedName) {
        if (location == null || requestedName == null) return null;
        try {
            String base = sanitizeFolderName(requestedName);
            Path parent = location.toPath();
            Files.createDirectories(parent);
            Path chosen = parent.resolve(base);
            if (Files.isDirectory(chosen) && !isEmptyOrOurs(chosen)) {
                // Not our folder — de-dupe with Bruno-style " - 1" suffix.
                for (int i = 1; i < 1000; i++) {
                    Path candidate = parent.resolve(base + " - " + i);
                    if (!Files.exists(candidate)) {
                        chosen = candidate;
                        break;
                    }
                    if (Files.isDirectory(candidate) && isEmptyOrOurs(candidate)) {
                        chosen = candidate;
                        break;
                    }
                }
            }
            Files.createDirectories(chosen);
            seedWorkspaceShape(chosen, requestedName);
            return chosen.toFile();
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /** True if the folder is empty OR already contains our marker files
     *  (README.md + environments/ subfolder). Used by
     *  {@link #getOrCreateWorkspaceAt(File, String)} to decide whether to
     *  reuse or bump to a " - 1" suffix. */
    private static boolean isEmptyOrOurs(Path folder) {
        try {
            try (java.util.stream.Stream<Path> stream = Files.list(folder)) {
                if (!stream.findAny().isPresent()) return true;
            }
            // Non-empty — check for our markers.
            if (Files.isRegularFile(folder.resolve("README.md"))
                && Files.isDirectory(folder.resolve("environments"))) {
                return true;
            }
            // Also consider it "ours" if it has just .env or environments/
            // (from a partial previous import).
            if (Files.isRegularFile(folder.resolve(".env"))
                || Files.isDirectory(folder.resolve("environments"))) {
                return true;
            }
        } catch (IOException ignore) { }
        return false;
    }

    /** Create the standard workspace shape ({@code .env}, {@code environments/},
     *  {@code README.md}) inside an existing folder. Idempotent — existing
     *  files are left alone. */
    private static void seedWorkspaceShape(Path ws, String displayName) throws IOException {
        Path envsDir = ws.resolve("environments");
        if (!Files.isDirectory(envsDir)) {
            Files.createDirectories(envsDir);
        }
        // Note: we do NOT auto-create a `.env` file — dotenv is only one
        // format option, not a default. Users who want dotenv-style secrets
        // can drop a `.env` file at the workspace root themselves; it will
        // be picked up by env auto-discovery on the next load/rescan.
        Path readme = ws.resolve("README.md");
        if (!Files.exists(readme)) {
            String body = "# BurpMan Workspace - " + displayName + "\n\n"
                + "This folder holds the Bruno-style environment files for the collection\n"
                + "**" + displayName + "**.\n\n"
                + "## Layout\n\n"
                + "- `environments/` - per-environment variable files (`.yml`, `.bru`, `.json`).\n"
                + "- `.env` (optional) - dotenv-style secrets (matches Bruno's `.ENV FILES` panel).\n\n"
                + "Whenever you re-open the collection above in BurpMan, every file\n"
                + "in `environments/` and any non-empty `.env` here is auto-added to\n"
                + "the Environment dropdown.\n";
            Files.write(readme, body.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static String safeSourceLabel(File source) {
        if (source == null) return "(unknown)";
        try {
            return source.getAbsolutePath().replace("\\", "/");
        } catch (RuntimeException e) {
            return source.getName();
        }
    }

    /**
     * Return the folder the user has explicitly linked to this workspace as
     * an additional source of environment files. The link is persisted in
     * {@code <workspace>/.brunoLink} — despite the name, the target can be
     * any folder (Bruno collection, another BurpMan workspace, a shared
     * team folder, etc.). Returns {@code null} when there's no link or the
     * saved path no longer exists.
     *
     * <p>We deliberately do NOT auto-scan common paths for a matching
     * collection name: many users don't use Bruno at all, and guessing risks
     * pulling in envs from the wrong project. The link is always an explicit
     * user action (see {@code ImporterPanel.linkExternalFolder}).
     *
     * @param workspace the BurpMan workspace folder (may hold a saved
     *                        {@code .brunoLink} pointer). May be null.
     */
    public static File findLinkedBrunoFolder(File workspace) {
        if (workspace == null || !workspace.isDirectory()) return null;
        File link = new File(workspace, ".brunoLink");
        if (!link.isFile()) return null;
        try {
            String saved = new String(Files.readAllBytes(link.toPath()),
                StandardCharsets.UTF_8).trim();
            if (saved.isEmpty()) return null;
            File f = new File(saved);
            return f.isDirectory() ? f : null;
        } catch (IOException e) {
            return null;
        }
    }

    /** True when the folder looks like an env source — has
     *  {@code .env}, {@code environments/}, {@code bruno.json}, or a
     *  {@code collection.bru}. Used by the manual-link picker to sanity-check
     *  the user's selection. */
    public static boolean isBrunoCollectionFolder(File f) {
        if (f == null || !f.isDirectory()) return false;
        if (new File(f, ".env").isFile()) return true;
        if (new File(f, "environments").isDirectory()) return true;
        if (new File(f, "bruno.json").isFile()) return true;
        if (new File(f, "collection.bru").isFile()) return true;
        if (new File(f, "opencollection.yml").isFile()) return true;
        return false;
    }

    /** Persist the user's explicit link to an external env-source folder
     *  inside the BurpMan workspace as {@code .brunoLink}. Best-effort. */
    public static boolean saveBrunoLink(File workspace, File externalFolder) {
        if (workspace == null || !workspace.isDirectory()) return false;
        if (externalFolder == null || !externalFolder.isDirectory()) return false;
        try {
            Path link = workspace.toPath().resolve(".brunoLink");
            Files.write(link,
                externalFolder.getAbsolutePath().getBytes(StandardCharsets.UTF_8));
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** Create a new empty environment file inside
     *  {@code <workspace>/environments/} in the requested format
     *  ({@code "bru"} or {@code "yml"}). Returns the created file, or
     *  {@code null} if the workspace is missing or the name collides. */
    public static File createEmptyEnvironment(File workspace, String rawName, String format) {
        if (workspace == null || !workspace.isDirectory()) return null;
        if (rawName == null || rawName.trim().isEmpty()) return null;
        String fmt = format == null ? "bru" : format.trim().toLowerCase(Locale.ROOT);
        if (!fmt.equals("bru") && !fmt.equals("yml") && !fmt.equals("yaml")) fmt = "bru";
        try {
            File envs = new File(workspace, "environments");
            if (!envs.isDirectory()) envs.mkdirs();
            String safe = rawName.trim().replaceAll("[^A-Za-z0-9._\\- ]+", "_");
            if (safe.isEmpty()) safe = "environment";
            File out = new File(envs, safe + "." + fmt);
            if (out.exists()) return null;
            String body;
            if (fmt.equals("bru")) {
                body = "vars {\n"
                    + "  base-url: https://api.example.com\n"
                    + "}\n\n"
                    + "vars:secret [\n"
                    + "  api-token\n"
                    + "]\n";
            } else {
                body = "vars:\n"
                    + "  base-url: https://api.example.com\n"
                    + "secret:\n"
                    + "  - api-token\n";
            }
            Files.write(out.toPath(), body.getBytes(StandardCharsets.UTF_8));
            return out;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /**
     * Extract Bruno-JSON-embedded environments into
     * {@code <workspace>/environments/*.{bru,yml}}. This is what makes the
     * "Environments" section of a Bruno JSON export actually usable:
     * without it, the user imports a JSON with 7 embedded environments
     * and sees an empty environments/ folder because BurpMan's tree
     * parser ignores the top-level {@code "environments"} array.
     *
     * <p>Bruno JSON export shape:
     * <pre>
     *   { "name": "PDP", "version": "1", "items": [...],
     *     "environments": [
     *       {
     *         "variables": [ ... ],
     *         "name": "0-Local"
     *       },
     *       ...
     *     ]
     *   }
     * </pre>
     *
     * <p>Uses a minimal hand-rolled JSON scanner (same approach as
     * {@link #peekCollectionName(File)}) so we don't need a full JSON
     * parser dependency. Handles JSON string escapes via
     * {@link #unescapeJson(String)}.
     *
     * @param source    the Bruno JSON export file
     * @param workspace the target BurpMan workspace folder (must have an
     *                  {@code environments/} subfolder already)
     * @param format    {@code "bru"} or {@code "yaml"} — output file format
     * @return the number of environments written. Files that already exist
     *         are skipped (idempotent), so subsequent imports are safe.
     */
    public static int extractBrunoEnvsFromJson(File source, File workspace, String format) {
        if (source == null || !source.isFile()) return 0;
        if (workspace == null || !workspace.isDirectory()) return 0;
        String fmt = (format == null ? "bru" : format.trim().toLowerCase(Locale.ROOT));
        if (fmt.equals("yml")) fmt = "yaml";
        if (!fmt.equals("bru") && !fmt.equals("yaml")) fmt = "bru";
        File envsDir = new File(workspace, "environments");
        if (!envsDir.isDirectory() && !envsDir.mkdirs()) return 0;

        String body;
        try {
            byte[] all = Files.readAllBytes(source.toPath());
            body = new String(all, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return 0;
        }

        int envsIdx = findTopLevelKey(body, "environments");
        if (envsIdx < 0) return 0;
        int arrStart = body.indexOf('[', envsIdx);
        if (arrStart < 0) return 0;
        int arrEnd = matchingBracket(body, arrStart);
        if (arrEnd < 0) return 0;

        int count = 0;
        int cursor = arrStart + 1;
        while (cursor < arrEnd) {
            // Find the next '{' at the current depth (skipping whitespace/commas).
            int objStart = -1;
            for (int i = cursor; i < arrEnd; i++) {
                char c = body.charAt(i);
                if (c == '{') { objStart = i; break; }
                if (c == ']') break;
                // Skip anything else (whitespace, commas, newlines).
            }
            if (objStart < 0) break;
            int objEnd = matchingBracket(body, objStart);
            if (objEnd < 0 || objEnd > arrEnd) break;
            String envJson = body.substring(objStart, objEnd + 1);
            // The env's own `name` is at the TOP level of the env object
            // (not inside the nested `variables` array). Find it by
            // depth-tracked scan so we ignore variable names.
            String envName = extractTopLevelStringValue(envJson, "name");
            if (envName != null && !envName.isEmpty()) {
                File out = writeExtractedEnv(envsDir, envName, envJson, fmt);
                if (out != null) count++;
            }
            cursor = objEnd + 1;
        }
        return count;
    }

    private static int findTopLevelKey(String body, String key) {
        String needle = "\"" + key + "\"";
        int idx = 0;
        int depth = 0;
        int inString = 0;
        while (idx < body.length()) {
            char c = body.charAt(idx);
            if (inString != 0) {
                if (c == '\\') { idx += 2; continue; }
                if (c == '"') inString = 0;
                idx++;
                continue;
            }
            if (c == '"') {
                if (depth == 1 && body.regionMatches(idx, needle, 0, needle.length())) {
                    return idx;
                }
                inString = 1;
                idx++;
                continue;
            }
            if (c == '{' || c == '[') depth++;
            else if (c == '}' || c == ']') depth--;
            idx++;
        }
        return -1;
    }

    private static int matchingBracket(String body, int openIdx) {
        char open = body.charAt(openIdx);
        char close = (open == '{') ? '}' : ']';
        int depth = 0;
        boolean inString = false;
        for (int i = openIdx; i < body.length(); i++) {
            char c = body.charAt(i);
            if (inString) {
                if (c == '\\') { i++; continue; }
                if (c == '"') inString = false;
                continue;
            }
            if (c == '"') { inString = true; continue; }
            if (c == open) depth++;
            else if (c == close) {
                depth--;
                if (depth == 0) return i;
            }
        }
        return -1;
    }

    private static String extractStringValue(String json, String key) {
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
            "\"" + java.util.regex.Pattern.quote(key) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        java.util.regex.Matcher m = p.matcher(json);
        if (m.find()) return unescapeJson(m.group(1));
        return null;
    }

    /** Extract a top-level string value from a JSON object literal. Unlike
     *  {@link #extractStringValue(String, String)} this only matches the
     *  key when it appears at depth 1 (the object's immediate children),
     *  skipping over anything nested inside sub-objects or sub-arrays. Used
     *  to grab e.g. an env's own {@code "name"} without picking up a
     *  variable's {@code "name"} inside the nested {@code "variables"} array. */
    private static String extractTopLevelStringValue(String json, String key) {
        String needle = "\"" + key + "\"";
        int i = 0;
        int depth = 0;
        boolean inString = false;
        int len = json.length();
        while (i < len) {
            char c = json.charAt(i);
            if (inString) {
                if (c == '\\') { i += 2; continue; }
                if (c == '"') inString = false;
                i++;
                continue;
            }
            if (c == '"') {
                if (depth == 1 && json.regionMatches(i, needle, 0, needle.length())) {
                    // Position after the closing quote of the key.
                    int afterKey = i + needle.length();
                    // Skip whitespace + colon + whitespace.
                    int j = afterKey;
                    while (j < len && Character.isWhitespace(json.charAt(j))) j++;
                    if (j < len && json.charAt(j) == ':') j++;
                    while (j < len && Character.isWhitespace(json.charAt(j))) j++;
                    if (j < len && json.charAt(j) == '"') {
                        // Read the quoted string value.
                        int valStart = j + 1;
                        StringBuilder sb = new StringBuilder();
                        boolean escaped = false;
                        for (int k = valStart; k < len; k++) {
                            char v = json.charAt(k);
                            if (escaped) { sb.append(v); escaped = false; continue; }
                            if (v == '\\') { sb.append(v); escaped = true; continue; }
                            if (v == '"') return unescapeJson(sb.toString());
                            sb.append(v);
                        }
                        return null;
                    }
                    // Value isn't a string — skip to next occurrence.
                    i = afterKey;
                    continue;
                }
                inString = true;
                i++;
                continue;
            }
            if (c == '{' || c == '[') depth++;
            else if (c == '}' || c == ']') depth--;
            i++;
        }
        return null;
    }

    private static File writeExtractedEnv(File envsDir, String envName, String envJson, String fmt) {
        String safe = sanitizeFolderName(envName);
        if (safe == null || safe.isEmpty()) safe = envName.replaceAll("[^A-Za-z0-9._\\- ]+", "_");
        if (safe.isEmpty()) return null;
        File out = new File(envsDir, safe + (fmt.equals("yaml") ? ".yml" : ".bru"));
        if (out.exists()) return null;

        java.util.List<String[]> vars = extractVarsArray(envJson);
        StringBuilder body = new StringBuilder();
        if (fmt.equals("bru")) {
            java.util.List<String[]> plain = new java.util.ArrayList<>();
            java.util.List<String[]> secret = new java.util.ArrayList<>();
            for (String[] v : vars) {
                if ("true".equalsIgnoreCase(v[3])) secret.add(v);
                else plain.add(v);
            }
            body.append("vars {\n");
            for (String[] v : plain) {
                if (!"true".equalsIgnoreCase(v[2])) body.append("  ~");
                else body.append("  ");
                body.append(v[0]).append(": ").append(v[1] == null ? "" : v[1]).append("\n");
            }
            body.append("}\n");
            if (!secret.isEmpty()) {
                body.append("\nvars:secret [\n");
                for (String[] v : secret) {
                    body.append("  ").append(v[0]).append("\n");
                }
                body.append("]\n");
            }
        } else {
            body.append("vars:\n");
            for (String[] v : vars) {
                body.append("  ").append(v[0]).append(": ")
                    .append(v[1] == null ? "" : v[1]).append("\n");
            }
            java.util.List<String> secretNames = new java.util.ArrayList<>();
            for (String[] v : vars) if ("true".equalsIgnoreCase(v[3])) secretNames.add(v[0]);
            if (!secretNames.isEmpty()) {
                body.append("secret:\n");
                for (String n : secretNames) body.append("  - ").append(n).append("\n");
            }
        }
        try {
            Files.write(out.toPath(), body.toString().getBytes(StandardCharsets.UTF_8));
            return out;
        } catch (IOException e) {
            return null;
        }
    }

    /** Extract the {@code variables} array from a Bruno env JSON object.
     *  Returns rows of {@code [name, value, enabled, secret]}. */
    private static java.util.List<String[]> extractVarsArray(String envJson) {
        java.util.List<String[]> out = new java.util.ArrayList<>();
        int varsIdx = envJson.indexOf("\"variables\"");
        if (varsIdx < 0) return out;
        int arrStart = envJson.indexOf('[', varsIdx);
        if (arrStart < 0) return out;
        int arrEnd = matchingBracket(envJson, arrStart);
        if (arrEnd < 0) return out;
        int cursor = arrStart + 1;
        while (cursor < arrEnd) {
            int objStart = -1;
            for (int i = cursor; i < arrEnd; i++) {
                char c = envJson.charAt(i);
                if (c == '{') { objStart = i; break; }
                if (c == ']') { objStart = -1; break; }
            }
            if (objStart < 0) break;
            int objEnd = matchingBracket(envJson, objStart);
            if (objEnd < 0) break;
            String varJson = envJson.substring(objStart, objEnd + 1);
            String name = extractStringValue(varJson, "name");
            String value = extractStringValue(varJson, "value");
            String enabled = extractBooleanValue(varJson, "enabled");
            String secret = extractBooleanValue(varJson, "secret");
            if (name != null && !name.isEmpty()) {
                out.add(new String[] {
                    name,
                    value == null ? "" : value,
                    enabled == null ? "true" : enabled,
                    secret == null ? "false" : secret
                });
            }
            cursor = objEnd + 1;
        }
        return out;
    }

    private static String extractBooleanValue(String json, String key) {
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
            "\"" + java.util.regex.Pattern.quote(key) + "\"\\s*:\\s*(true|false)");
        java.util.regex.Matcher m = p.matcher(json);
        if (m.find()) return m.group(1);
        return null;
    }
}
