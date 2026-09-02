package burp;
import burp.auth.AuthManager;
import burp.auth.OAuth2Config;
import burp.auth.OAuth2Detector;
import burp.models.*;
import burp.parser.*;
import burp.ui.*;
import burp.utils.*;
import burp.api.montoya.MontoyaApi;
import com.google.gson.*;
import javax.swing.*;
import java.io.File;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import burp.auth.JwtEndpointCandidate;
import burp.auth.JwtStaticTokenDetector;
import burp.auth.JwtEndpointDetector;
import burp.auth.ScriptTokenSourceDetector;
import java.awt.Color;

public class PostmanImporter {
    private final MontoyaApi api;
    private final ImporterPanel ui;
    private PostmanCollection currentCollection;
    private final PostmanParser parser;
    private final VariableResolver variableResolver;
    private final RequestBuilder requestBuilder;
    private final AuthManager authManager;
    private final VariableDetector variableDetector; // Added variable detector
    private final Set<String> existingTabs = ConcurrentHashMap.newKeySet();
    private final boolean debugMode = false; // Set to true for verbose import diagnostics
    private ImportResult lastImportResult; // Store last import result for retry functionality
    private boolean variablesAlreadyResolved = false; // Flag to prevent double dialog
    private List<RequestPreview> lastGeneratedPreviews = new ArrayList<>();
    private final JwtEndpointDetector jwtDetector = new JwtEndpointDetector();
    private final ScriptTokenSourceDetector scriptTokenSourceDetector = new ScriptTokenSourceDetector();
    private final JwtStaticTokenDetector staticDetector = new JwtStaticTokenDetector();
    private final Map<String, String> tokenValueToVar = new HashMap<>();
    private final Map<String, String> hostValueToVar = new HashMap<>();
    private final burp.auth.FolderAuthRegistry folderAuthRegistry = new burp.auth.FolderAuthRegistry();
    private final burp.service.CookieJar cookieJar = new burp.service.CookieJar();
    {
        // Publish our single CookieJar instance to the script bridge so
        // Bruno's `bru.cookies.jar().clear()` actually wipes captured
        // session cookies. Without this, scripts call clear() and it
        // returns silently while iPlanetDirectoryPro / OAuth state
        // cookies keep being replayed, breaking multi-step auth chains.
        burp.service.RhinoScriptEngine.SCRIPT_COOKIE_JAR.set(cookieJar);
    }
    private CollectionTreeBuilder treeBuilder;
    private CollectionTreeNode currentCollectionTree;

    public PostmanCollection getCurrentCollection() {
        return currentCollection;
    }

    /** Re-apply current collection variables into the live resolver.
     *  Used when env/globals are reloaded so collection-only vars
     *  (e.g. host1 placeholders) remain defined. */
    public void reapplyCollectionVariablesForCurrentCollection() {
        addCollectionVariablesPreservingCurrent(currentCollection);
    }

    /**
     * Rebuild ONLY the tree from the in-memory merged collection — does NOT
     * re-run JWT/OAuth detection. Used by + Add Collection so newly-added
     * collections show up immediately but their analyzed status stays
     * unchecked until the user explicitly clicks Analyze on them.
     */
    public void rebuildTreeOnly() {
        try {
            if (currentCollection == null || currentCollection.item == null) return;
            SwingUtilities.invokeLater(() -> {
                try {
                    List<AnalyzedRequest> analyzed = new ArrayList<>();
                    flattenToAnalyzedRequests(currentCollection.item, "", analyzed,
                            currentCollection.info != null ? currentCollection.info.name : "Collection");
                    CollectionTreeNode root = buildCollectionTree(analyzed);
                    if (root != null) {
                        ui.getTreePanel().loadCollection(root);
                        ui.appendLog("🌳 Tree rebuilt — " + analyzed.size()
                                + " requests across all loaded collections (new collections NOT yet analyzed)");
                    }
                } catch (Exception e) {
                    ui.appendLog("⚠ Rebuild failed: " + e.getMessage());
                }
            });
        } catch (Exception e) {
            ui.appendLog("⚠ Rebuild failed: " + e.getMessage());
        }
    }

    private void markAllCollectionsAnalyzed() {
        if (currentCollection == null) return;
        currentCollection.analyzed = true;
        if (currentCollection.item == null) return;
        for (PostmanCollection.Item it : currentCollection.item) {
            if (it != null && it.isCollectionWrapper) it.analyzed = true;
        }
        try { if (ui != null && ui.getTreePanel() != null) ui.getTreePanel().repaint(); } catch (Exception ignore) {}
    }

    /**
     * Rebuild the tree + re-run JWT/OAuth detection from the in-memory merged
     * collection WITHOUT showing the "Select Requests to Import" preview
     * dialog. Used after + Add Collection appends a new top-level item.
     */
    public void rebuildTreeAndAnalyze() {
        try {
            if (currentCollection == null || currentCollection.item == null) return;

            // Re-run JWT + OAuth detection against the merged collection so
            // Auth Manager picks up endpoints from the newly-added one.
            try {
                refreshAuthDetectionFromCurrentCollection();
            } catch (Exception ignore) {}

            // Re-seed folder-auth registry from the full workspace so oauth2/
            // apikey/bearer folder overrides all survive tree rebuilds.
            try {
                seedFolderAuthFullWorkspace();
            } catch (Exception ignore) {}

            SwingUtilities.invokeLater(() -> {
                try {
                    List<AnalyzedRequest> analyzed = new ArrayList<>();
                    flattenToAnalyzedRequests(currentCollection.item, "", analyzed,
                            currentCollection.info != null ? currentCollection.info.name : "Collection");
                    CollectionTreeNode root = buildCollectionTree(analyzed);
                    if (root != null) {
                        ui.getTreePanel().loadCollection(root);
                        ui.appendLog("🌳 Tree rebuilt — " + analyzed.size() + " requests across all loaded collections");
                    }
                } catch (Exception e) {
                    ui.appendLog("⚠ Rebuild failed: " + e.getMessage());
                }
            });
        } catch (Exception e) {
            ui.appendLog("⚠ Rebuild failed: " + e.getMessage());
        }
    }

    /** Recompute Auth Manager candidates from the in-memory workspace collection. */
    public void refreshAuthDetectionFromCurrentCollection() {
        try {
            if (currentCollection == null) return;
            List<JwtEndpointCandidate> jwt = detectTokenSourceCandidates(currentCollection, variableResolver);
            List<String> stat = staticDetector.detect(currentCollection, variableResolver);
            ui.updateAuthDetectionFull(authManager.getOAuth2Configs(), jwt, stat);
        } catch (Exception ex) {
            ui.appendLog("⚠ Auth candidate refresh failed: " + ex.getMessage());
        }
    }

    private List<JwtEndpointCandidate> detectTokenSourceCandidates(
            PostmanCollection collection,
            VariableResolver resolver) {
        List<JwtEndpointCandidate> urlCandidates = jwtDetector.detect(collection, resolver);
        List<JwtEndpointCandidate> scriptCandidates = scriptTokenSourceDetector.detect(collection, resolver);
        java.util.LinkedHashMap<String, JwtEndpointCandidate> merged = new java.util.LinkedHashMap<>();
        mergeTokenSourceCandidates(merged, urlCandidates);
        mergeTokenSourceCandidates(merged, scriptCandidates);
        java.util.List<JwtEndpointCandidate> out = new java.util.ArrayList<>(merged.values());
        out.sort((a, b) -> Integer.compare(b.score, a.score));
        return out;
    }

    private void mergeTokenSourceCandidates(
            java.util.Map<String, JwtEndpointCandidate> sink,
            java.util.List<JwtEndpointCandidate> source) {
        if (source == null) return;
        for (JwtEndpointCandidate cand : source) {
            if (cand == null || cand.request == null) continue;
            String key = tokenSourceCandidateKey(cand);
            JwtEndpointCandidate existing = sink.get(key);
            if (existing == null || shouldReplaceTokenSourceCandidate(existing, cand)) {
                sink.put(key, cand);
            }
        }
    }

    private String tokenSourceCandidateKey(JwtEndpointCandidate cand) {
        if (cand == null) return "";
        String method = cand.method == null ? "" : cand.method.trim().toUpperCase(java.util.Locale.ROOT);
        String url = cand.url == null ? "" : cand.url.trim();
        String path = cand.path == null ? "" : cand.path.trim();
        return method + "|" + url + "|" + path;
    }

    private boolean shouldReplaceTokenSourceCandidate(
            JwtEndpointCandidate existing,
            JwtEndpointCandidate incoming) {
        if (existing == null) return true;
        if (incoming == null) return false;
        if (incoming.fromScriptSendRequest && !existing.fromScriptSendRequest) return true;
        if (!incoming.fromScriptSendRequest && existing.fromScriptSendRequest) return false;
        boolean incomingScript = incoming.confidence != null
                && incoming.confidence.toUpperCase(java.util.Locale.ROOT).contains("SCRIPT");
        boolean existingScript = existing.confidence != null
                && existing.confidence.toUpperCase(java.util.Locale.ROOT).contains("SCRIPT");
        if (incomingScript && !existingScript) return true;
        if (!incomingScript && existingScript) return false;
        return incoming.score > existing.score;
    }

    private String forcedAnalyzeScope = null;
    public void setAnalyzeScope(String topWrapper) { this.forcedAnalyzeScope = topWrapper; }

    /**
     * Copy every workspace-global variable into the named collection's scope
     * so the new collection is isolated from any subsequent global edits.
     * Idempotent: existing scope entries are NOT overwritten.
     */
    private void snapshotGlobalsIntoScope(String wrapperName) {
        if (wrapperName == null || wrapperName.isEmpty()) return;
        try {
            java.util.Map<String, String> globals = variableResolver.getVariables();
            java.util.Map<String, String> existing = variableResolver.getScopedVariables(wrapperName);
            for (java.util.Map.Entry<String, String> e : globals.entrySet()) {
                String k = e.getKey();
                if (k == null) continue;
                // Skip per-collection token variants belonging to OTHER
                // collections — those leak the wrong token if copied.
                String lk = k.toLowerCase();
                if (lk.startsWith("token_") || lk.startsWith("bearer_")) continue;
                // OAuth bootstrap keys are collection-specific in many
                // real-world workspaces. Copying them into every new scope
                // leaks stale values (e.g. previous collection's {{scope}}).
                if ("scope".equals(lk) || "client_id".equals(lk)
                        || "client_secret".equals(lk) || "grant_type".equals(lk)) {
                    continue;
                }
                if (!existing.containsKey(k)) {
                    variableResolver.putScopedVariable(wrapperName, k, e.getValue());
                }
            }
        } catch (Exception ignore) {}
    }

    /**
     * Remove a top-level collection wrapper from the workspace by name.
     * Returns true if a wrapper was removed. Also clears any per-collection
     * variable scope and folder-auth registrations beneath it.
     */
    public boolean removeCollection(String wrapperName) {
        if (wrapperName == null || currentCollection == null
                || currentCollection.item == null) return false;
        String wanted = wrapperName.trim();
        if (wanted.isEmpty()) return false;
        boolean removed = false;
        String removedName = wanted;
        java.util.Iterator<PostmanCollection.Item> it = currentCollection.item.iterator();
        while (it.hasNext()) {
            PostmanCollection.Item w = it.next();
            if (w != null && w.name != null && wanted.equals(w.name)) {
                it.remove();
                removed = true;
                removedName = w.name;
                break;
            }
        }
        if (!removed) return false;
        try { variableResolver.clearScope(removedName); } catch (Exception ignore) {}
        try {
            // Clear any folder-auth overrides that lived under this wrapper.
            for (String key : new java.util.ArrayList<>(folderAuthRegistry.keys())) {
                if (key != null && (key.equals(removedName) || key.startsWith(removedName + "/"))) {
                    folderAuthRegistry.remove(key);
                }
            }
        } catch (Exception ignore) {}
        ui.appendLog("🗑️ Removed collection: " + removedName);
        try { rebuildTreeOnly(); } catch (Exception ignore) {}
        try { refreshAuthDetectionFromCurrentCollection(); } catch (Exception ignore) {}
        return true;
    }

    /**
     * Force {@code currentCollection} into "workspace" shape: a single root
     * with all top-level items being collection-wrappers. If it already has
     * any non-wrapper items at the root, promote them under a single wrapper
     * named after the original collection. Idempotent.
     */
    public void ensureWorkspaceShape() {
        if (currentCollection == null) return;
        if (currentCollection.item == null) currentCollection.item = new java.util.ArrayList<>();
        if (currentCollection.item.isEmpty()) return;
        boolean alreadyWorkspace = true;
        for (PostmanCollection.Item it : currentCollection.item) {
            if (it == null || !it.isCollectionWrapper) { alreadyWorkspace = false; break; }
        }
        if (alreadyWorkspace) return;
        String origName = (currentCollection.info != null && currentCollection.info.name != null
                && !currentCollection.info.name.isEmpty())
                ? currentCollection.info.name
                : "Collection";
        PostmanCollection.Item origWrapper = new PostmanCollection.Item();
        origWrapper.name = origName;
        origWrapper.item = currentCollection.item;
        origWrapper.isCollectionWrapper = true;
        origWrapper.analyzed = currentCollection.analyzed;
        origWrapper.pendingAnalyze = !currentCollection.analyzed;
        if (currentCollection.auth != null) origWrapper.auth = currentCollection.auth;
        currentCollection.item = new java.util.ArrayList<>();
        currentCollection.item.add(origWrapper);
        try {
            if (currentCollection.info != null) currentCollection.info.name = "Workspace";
        } catch (Exception ignore) {}
        currentCollection.auth = null;
        // Snapshot whatever's in globals right now into the new wrapper's
        // scope so this collection becomes self-contained.
        snapshotGlobalsIntoScope(origWrapper.name);
    }

    /**
     * Create a brand-new empty top-level collection wrapper in the current
     * workspace. The new collection is intentionally pending analysis.
     */
    public void createEmptyCollection(String name) {
        if (name == null || name.trim().isEmpty()) return;
        String collectionName = name.trim();
        if (currentCollection == null) {
            currentCollection = new PostmanCollection();
            currentCollection.info = new PostmanCollection.Info();
            currentCollection.info.name = "Workspace";
            currentCollection.item = new ArrayList<>();
        }
        if (currentCollection.item == null) currentCollection.item = new ArrayList<>();
        ensureWorkspaceShape();
        PostmanCollection.Item wrapper = new PostmanCollection.Item();
        wrapper.name = collectionName;
        wrapper.item = new ArrayList<>();
        wrapper.isCollectionWrapper = true;
        wrapper.analyzed = false;
        wrapper.pendingAnalyze = true;
        currentCollection.item.add(wrapper);
        snapshotGlobalsIntoScope(collectionName);
    }

    /**
     * Append an extra collection (file, folder, or Bruno dir) into the
     * already-loaded workspace WITHOUT replacing the existing tree. Each new
     * top-level item is wrapped as a synthetic collection-folder so the
     * Postman-style "click a collection in the tree" navigation continues to
     * work and the JWT detector / Auth Manager scope filter can isolate it.
     *
     * Returns the number of items appended (0 if the file couldn't be parsed).
     */
    public int appendCollection(java.io.File extraFile) throws Exception {
        if (extraFile == null) return 0;
        PostmanCollection extra = parser.parseCollection(extraFile);
        if (extra == null) return 0;

        // First-ever import — just take the parsed collection wholesale.
        if (currentCollection == null) {
            currentCollection = extra;
            return extra.item == null ? 0 : extra.item.size();
        }

        // If currentCollection is still a single un-wrapped collection (i.e. its
        // own items are not collection wrappers), promote it to a workspace by
        // wrapping its existing items under a wrapper named after itself. This
        // prevents the newly-appended collection from becoming a child of the
        // first one in the tree.
        if (currentCollection.item == null) {
            currentCollection.item = new java.util.ArrayList<>();
        }
        boolean alreadyWorkspace = !currentCollection.item.isEmpty();
        for (PostmanCollection.Item it : currentCollection.item) {
            if (it == null || !it.isCollectionWrapper) { alreadyWorkspace = false; break; }
        }
        if (!alreadyWorkspace) {
            String origName = (currentCollection.info != null && currentCollection.info.name != null
                    && !currentCollection.info.name.isEmpty())
                    ? currentCollection.info.name
                    : "Collection";
            PostmanCollection.Item origWrapper = new PostmanCollection.Item();
            origWrapper.name = origName;
            origWrapper.item = currentCollection.item;
            origWrapper.isCollectionWrapper = true;
            // Preserve the original collection's analyzed state across the
            // promotion — only mark the wrapper if the user (or load path)
            // had already run auth analysis on it.
            origWrapper.analyzed = currentCollection.analyzed;
            if (currentCollection.auth != null) origWrapper.auth = currentCollection.auth;
            currentCollection.item = new java.util.ArrayList<>();
            currentCollection.item.add(origWrapper);
            // Rename the synthetic workspace root so the tree doesn't keep the
            // first collection's old name as the umbrella label.
            try {
                if (currentCollection.info != null) {
                    currentCollection.info.name = "Workspace";
                }
            } catch (Exception ignore) {}
            // Original collection's root auth no longer applies workspace-wide.
            currentCollection.auth = null;
        }
        if (extra.item == null) extra.item = new java.util.ArrayList<>();

        String extraName = (extra.info != null && extra.info.name != null && !extra.info.name.isEmpty())
                ? extra.info.name
                : stripExt(extraFile.getName());

        int added = 0;
        // If the extra was itself a multi-collection folder import, its top-
        // level items are ALREADY collection-wrappers. Merge them straight in.
        boolean allWrappers = !extra.item.isEmpty();
        for (PostmanCollection.Item it : extra.item) {
            if (it == null || !it.isCollectionWrapper) { allWrappers = false; break; }
        }
        if (allWrappers) {
            for (PostmanCollection.Item it : extra.item) {
                if (it != null) {
                    it.name = uniquifyCollectionName(it.name);
                    it.pendingAnalyze = true;
                    snapshotGlobalsIntoScope(it.name);
                }
                currentCollection.item.add(it);
                added++;
            }
        } else {
            // Wrap the new collection's items under a synthetic collection
            // folder so it shows up as its own root in the tree.
            PostmanCollection.Item wrapper = new PostmanCollection.Item();
            wrapper.name = uniquifyCollectionName(extraName);
            wrapper.item = extra.item;
            wrapper.isCollectionWrapper = true;
            wrapper.pendingAnalyze = true;
            if (extra.auth != null) wrapper.auth = extra.auth;
            currentCollection.item.add(wrapper);
            snapshotGlobalsIntoScope(wrapper.name);
            added = 1;
        }

        // Merge variables (if extra defines any).
        if (extra.variable != null && !extra.variable.isEmpty()) {
            if (currentCollection.variable == null) {
                currentCollection.variable = new java.util.ArrayList<>();
            }
            currentCollection.variable.addAll(extra.variable);
        }
        return added;
    }

    private static String stripExt(String name) {
        if (name == null) return "";
        int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot) : name;
    }

    /**
     * Returns a name that doesn't collide with any existing top-level
     * collection in currentCollection. Appends " (2)", " (3)", ... as needed.
     */
    private String uniquifyCollectionName(String desired) {
        if (desired == null || desired.isEmpty()) desired = "Collection";
        if (currentCollection == null || currentCollection.item == null) return desired;
        java.util.Set<String> taken = new java.util.HashSet<>();
        for (PostmanCollection.Item it : currentCollection.item) {
            if (it != null && it.name != null) taken.add(it.name);
        }
        if (!taken.contains(desired)) return desired;
        int n = 2;
        while (taken.contains(desired + " (" + n + ")")) n++;
        return desired + " (" + n + ")";
    }

    public PostmanImporter(MontoyaApi api) {
        this.api = api;
        this.parser = new PostmanParser();
        this.variableResolver = new VariableResolver();
        this.authManager = new AuthManager(api, variableResolver);
        this.requestBuilder = new RequestBuilder(api, variableResolver, authManager);
        this.variableDetector = new VariableDetector(variableResolver, api); // Pass API for logging
        this.treeBuilder = new CollectionTreeBuilder();
        this.ui = new ImporterPanel(this, authManager);
        // Wire script engine diagnostics into the in-app log so users see
        // [pm.sendRequest], Rhino errors, and console.log output from real
        // Postman scripts. Without this hook, those messages would only
        // reach BurpMan-scripts.log on disk.
        burp.service.ScriptExecutor.UI_LOG = msg -> {
            try { ui.appendLog(msg); } catch (Throwable ignore) {}
        };
        // ATOR-style: register fetcher that refreshes JWT from the currently-selected token source request.
        this.authManager.setAutoRefreshFetcher(callback -> {
            PostmanCollection.Request src = authManager.getTokenSourceRequest();
            if (src == null) { callback.accept(null); return; }
            autoFetchFromJwt(src, callback);
        });
    }
    public enum AuthSource {
        REQUEST,
        FOLDER,
        COLLECTION,
        HEADER,
        NONE
    }
    public File getSelectedCollection() {
        return ui.getSelectedCollection();
    }
    
    public File getSelectedEnvironment() {
        return ui.getSelectedEnvironment();
    }

    /** Optional Postman "globals" file. Same JSON shape as environment but
     *  scoped globally (lower precedence than env). */
    private File globalsFile;
    public void setGlobalsFile(File f) { this.globalsFile = f; }
    public File getGlobalsFile() { return globalsFile; }

    /** Return cascaded [preRequestScript, testScript] (collection-root +
     *  every ancestor folder + the request itself, concatenated in execution
     *  order). */
    public String[] getScriptsForPath(String requestPath) {
        StringBuilder pre = new StringBuilder();
        StringBuilder post = new StringBuilder();
        if (currentCollection != null) {
            pre.append(burp.models.AnalyzedRequest.extractScriptFromEvents(currentCollection.event, "prerequest"));
            post.append(burp.models.AnalyzedRequest.extractScriptFromEvents(currentCollection.event, "test"));
        }
        if (requestPath == null || requestPath.isEmpty() || currentCollection == null) {
            return new String[]{ pre.toString(), post.toString() };
        }
        // Walk the tree by prefix-matching item names against the remaining
        // path. Splitting on '/' would break for items whose own name
        // contains a slash (e.g. "01 - pm.environment.set / get") because
        // the leaf would never match a single segment.
        java.util.List<PostmanCollection.Item> level = currentCollection.item;
        String remaining = requestPath;
        while (remaining != null && !remaining.isEmpty() && level != null) {
            PostmanCollection.Item match = null;
            String matchedName = null;
            for (PostmanCollection.Item it : level) {
                if (it == null || it.name == null) continue;
                String name = it.name;
                if (remaining.equals(name)) {
                    match = it;
                    matchedName = name;
                    break;
                }
                if (remaining.startsWith(name + "/")) {
                    if (match == null || name.length() > matchedName.length()) {
                        match = it;
                        matchedName = name;
                    }
                }
            }
            if (match == null) break;
            pre.append(burp.models.AnalyzedRequest.extractScriptFromEvents(match.event, "prerequest"));
            post.append(burp.models.AnalyzedRequest.extractScriptFromEvents(match.event, "test"));
            if (remaining.equals(matchedName)) {
                break;
            }
            remaining = remaining.substring(matchedName.length() + 1); // skip the '/'
            level = match.item;
        }
        return new String[]{ pre.toString(), post.toString() };
    }

    /** Cascaded list of post-response scripts, one entry per Event. Used by
     *  the runner so each Bruno block (post-response + tests) executes as its
     *  own Rhino call — a crash in one doesn't undo writes from the other,
     *  and identical local declarations (`let authId` etc.) don't collide. */
    public java.util.List<String> getCascadedTestScripts(String requestPath) {
        java.util.List<String> out = new java.util.ArrayList<>();
        if (currentCollection != null) {
            collectEventBodies(currentCollection.event, "test", out);
        }
        if (requestPath == null || requestPath.isEmpty() || currentCollection == null) {
            return out;
        }
        // Same prefix-matching walker as getScriptsForPath so item names
        // containing '/' (e.g. "01 - pm.environment.set / get") still
        // resolve to the right leaf instead of bailing on the first
        // un-matched segment.
        java.util.List<PostmanCollection.Item> level = currentCollection.item;
        String remaining = requestPath;
        while (remaining != null && !remaining.isEmpty() && level != null) {
            PostmanCollection.Item match = null;
            String matchedName = null;
            for (PostmanCollection.Item it : level) {
                if (it == null || it.name == null) continue;
                String name = it.name;
                if (remaining.equals(name)) {
                    match = it;
                    matchedName = name;
                    break;
                }
                if (remaining.startsWith(name + "/")) {
                    if (match == null || name.length() > matchedName.length()) {
                        match = it;
                        matchedName = name;
                    }
                }
            }
            if (match == null) break;
            collectEventBodies(match.event, "test", out);
            if (remaining.equals(matchedName)) break;
            remaining = remaining.substring(matchedName.length() + 1);
            level = match.item;
        }
        return out;
    }

    private static void collectEventBodies(java.util.List<PostmanCollection.Event> events,
                                           String listenType,
                                           java.util.List<String> sink) {
        if (events == null) return;
        for (PostmanCollection.Event ev : events) {
            if (ev == null || ev.script == null || ev.script.exec == null) continue;
            if (!listenType.equalsIgnoreCase(ev.listen)) continue;
            StringBuilder body = new StringBuilder();
            for (String line : ev.script.exec) body.append(line == null ? "" : line).append('\n');
            String s = body.toString();
            if (!s.trim().isEmpty()) sink.add(s);
        }
    }

    public AuthManager getAuthManager() {
        return authManager;
        }

    public burp.service.CookieJar getCookieJar() {
        return cookieJar;
    }

    public void showManualVariablesDialog() {
        ui.showManualVariablesDialog();
    }
    public JPanel getMainPanel() {
        return ui.getPanel();
    }
    
    public MontoyaApi getMontoyaApi() {
        return api;
    }
    
    public burp.auth.FolderAuthRegistry getFolderAuthRegistry() {
        return folderAuthRegistry;
    }
    
    public void clearEnvironmentVariables() {
        variableResolver.clearAllVariables();
        if (debugMode) {
            api.logging().logToOutput("Environment variables cleared");
        }
    }
    public void fullReset() {

        // ✅ Variables
        variableResolver.clearAllVariables();
        tokenValueToVar.clear();
        hostValueToVar.clear();
        // ✅ Collection + preview cache
        currentCollection = null;
        lastGeneratedPreviews.clear();
    
        // ✅ Flags
        variablesAlreadyResolved = false;
    
        // ✅ AuthManager
        if (authManager != null) {
            authManager.reset();
        }

        // ✅ Cookie jar — stale session cookies (iPlanetDirectoryPro,
        //    OAuth state, ASP.NET_SessionId, etc.) survive Restart otherwise
        //    and get replayed on the next Run, which reuses an expired
        //    session and breaks CIAM / OIDC auth chains.
        if (cookieJar != null) {
            cookieJar.clear();
        }
    
        // ✅ Tabs
        existingTabs.clear();
    
        // ✅ UI deep reset
// ✅ UI deep reset
        ui.clearAllUI();

        // ✅ 🔥 ADD THIS LINE (CRITICAL)
        currentCollectionTree = null;
    
        api.logging().logToOutput("Restart Complete");
    }
    public Set<String> getDetectedCollectionVariables() {
        try {
            // ✅ Primary source: Preview/Analyze-generated RequestPreview objects.
            // This ensures Edit Variables uses the same variables seen during Preview.
            Set<String> variablesFromPreview = getAllVariablesFromLastPreviews();
    
            if (!variablesFromPreview.isEmpty()) {
                return variablesFromPreview;
            }
    
            // ✅ Fallback: If preview has not run yet, parse/scan the current collection.
            PostmanCollection collection = currentCollection;
    
            if (collection == null && getSelectedCollection() != null) {
                collection = parser.parseCollection(getSelectedCollection());
                currentCollection = collection;
            }
    
            if (collection == null) {
                return Collections.emptySet();
            }
    
            VariableDetector detector = new VariableDetector(variableResolver, api);
    
            // Return all variables, not only unresolved variables.
            return detector.findAllVariablesInCollection(collection);
    
        } catch (Exception e) {
            if (debugMode) {
                api.logging().logToError("Failed to detect collection variables: " + e.getMessage());
            }
    
            return Collections.emptySet();
        }
    }
    public VariableResolver getVariableResolver() {
        return variableResolver;
    }

    public MontoyaApi getApi() {
        return api;
    }

    /** Collection-root auth (e.g. OAuth2 set at the top level), or null. */
    public PostmanCollection.Auth getCollectionRootAuth() {
        if (currentCollection == null) return null;
        if (currentCollection.auth != null) return currentCollection.auth;
        // Workspace mode: root auth was moved onto the wrapper(s). When there
        // is exactly one wrapper, treat its auth as the effective root so
        // single-collection imports behave the same as before workspace
        // promotion (Postman parity).
        if (currentCollection.item != null && currentCollection.item.size() == 1) {
            PostmanCollection.Item only = currentCollection.item.get(0);
            if (only != null && only.isCollectionWrapper && only.auth != null) {
                return only.auth;
            }
        }
        return null;
    }

    /** Find an OAuth2 config previously detected for the given folder path. */
    public OAuth2Config findOAuth2ConfigForPath(String folderPath) {
        if (authManager == null) return null;
        java.util.List<OAuth2Config> configs = authManager.getOAuth2Configs();
        if (configs == null || configs.isEmpty()) return null;
        String key = folderPath == null ? "" : folderPath;
        // Prefer exact path match, fall back to first usable config.
        for (OAuth2Config c : configs) {
            if (c != null && key.equalsIgnoreCase(c.path == null ? "" : c.path)) return c;
        }
        // For collection root the detector tags path = "Collection"
        if (key.isEmpty()) {
            for (OAuth2Config c : configs) {
                if (c != null && "Collection".equalsIgnoreCase(c.path)) return c;
            }
        }
        return configs.get(0);
    }
    
    /** Refresh the variables panel UI from the current resolver state. */
    public void refreshVariablesUi() {
        try {
            ui.refreshVariables(variableResolver.getVariables());
        } catch (Exception ignore) { }
    }
    
    public void retryFailedRequests(String destination) {
        if (lastImportResult == null || lastImportResult.failedRequestDetails.isEmpty()) {
            ui.appendLog("No failed requests to retry.");
            return;
        }
        
        SwingWorker<ImportResult, String> worker = new SwingWorker<ImportResult, String>() {
            @Override
            protected ImportResult doInBackground() throws Exception {
                ImportResult retryResult = new ImportResult();
                retryResult.collectionName = lastImportResult.collectionName + " (Retry)";
                retryResult.totalRequests = lastImportResult.failedRequestDetails.size();
                
                publish("Retrying " + retryResult.totalRequests + " failed requests...");
                
                for (int i = 0; i < lastImportResult.failedRequestDetails.size(); i++) {
                    if (isCancelled()) break;
                    
                    ImportResult.FailedRequestInfo failedInfo = lastImportResult.failedRequestDetails.get(i);
                    
                    try {
                        // Cast the stored request data back to RequestItem
                        if (failedInfo.requestData instanceof RequestItem) {
                            RequestItem item = (RequestItem) failedInfo.requestData;
                            processRequest(item, destination);
                            retryResult.successCount++;
                            publish("✓ Retry successful: " + failedInfo.name);
                        } else {
                            throw new Exception("Invalid request data stored for retry");
                        }
                    } catch (Exception e) {
                        retryResult.failedRequestDetails.add(new ImportResult.FailedRequestInfo(
                            failedInfo.name, failedInfo.path, e.getMessage(), failedInfo.requestData));
                        retryResult.failedRequests.add(failedInfo.name + ": " + e.getMessage());
                        publish("✗ Retry failed: " + failedInfo.name + " - " + e.getMessage());
                    }
                    
                    setProgress((i + 1) * 100 / retryResult.totalRequests);
                }
                
                return retryResult;
            }
            
            @Override
            protected void process(List<String> chunks) {
                for (String message : chunks) {
                    ui.appendLog(message);
                }
            }
            
            @Override
            protected void done() {
                try {
                    ImportResult retryResult = get();
                    
                    // Merge retry results with original results
                    ImportResult mergedResult = mergeRetryResults(lastImportResult, retryResult);
                    lastImportResult = mergedResult; // Update for future retries
                    
                    ui.showImportSummary(mergedResult);
                    
                    if (retryResult.successCount > 0) {
                        ui.appendLog("\n🎉 Retry completed! " + retryResult.successCount + 
                                   " previously failed requests are now successful.");
                    }
                } catch (Exception e) {
                    ui.showError("Retry failed: " + e.getMessage());
                }
                ui.setImportComplete();
            }
        };
        // ✅ ✅ ✅ BUILD TREE HERE

        worker.addPropertyChangeListener(evt -> {
            if ("progress".equals(evt.getPropertyName())) {
                ui.updateProgress((Integer) evt.getNewValue());
            }
        });
        
        ui.setImportInProgress();
        worker.execute();
    }

    public void sendOAuthToRepeater(
        burp.api.montoya.http.message.requests.HttpRequest request
        ) {
            try {
                api.repeater().sendToRepeater(request, "OAuth2 Token Request");
            } catch (Exception e) {
                ui.appendLog("OAuth2 Repeater failed: " + e.getMessage());
            }
        }

    /**
     * Lightweight: parse the collection file and display the tree in the UI
     * WITHOUT running auth analysis or firing scripted requests. This lets the
     * user right-click a folder and pick "Analyze this Folder" before doing a
     * full Analyze on the entire collection.
     */
    public void loadCollectionTreeOnly(File collectionFile) {
        if (collectionFile == null) return;
        try {
            PostmanCollection collection = parser.parseCollection(collectionFile);
            if (collection == null) {
                ui.appendLog("⚠ Could not parse collection for tree preview.");
                return;
            }
            currentCollection = collection;
            ensureWorkspaceShape();
            // Mark every collection wrapper as pendingAnalyze so a click on
            // Analyze will loop through each one in its own strict scope.
            try {
                if (currentCollection.item != null) {
                    for (PostmanCollection.Item w : currentCollection.item) {
                        if (w != null && w.isCollectionWrapper && !w.analyzed) {
                            w.pendingAnalyze = true;
                        }
                    }
                }
            } catch (Exception ignore) {}
            try { authManager.setCollectionAuth(collection.auth); } catch (Exception ignore) {}
            List<AnalyzedRequest> analyzed = new ArrayList<>();
            if (collection.item != null) {
                flattenToAnalyzedRequests(collection.item, "", analyzed,
                    collection.info != null ? collection.info.name : "Collection");
            }
            CollectionTreeNode root = buildCollectionTree(analyzed);
            SwingUtilities.invokeLater(() -> {
                if (root != null) {
                    ui.getTreePanel().loadCollection(root);
                    ui.appendLog("📂 Tree loaded with " + analyzed.size()
                        + " request(s). Right-click a folder to Analyze it, or click Analyze to scan the full collection.");
                } else {
                    ui.appendLog("⚠ Tree not built: collection is empty.");
                }
            });
        } catch (Exception e) {
            ui.appendLog("⚠ Failed to load tree preview: " + e.getMessage());
        }
    }

    public void analyzeAuthFromFiles(File collectionFile, File environmentFile) {

        try {

            if (collectionFile == null) {
                ui.appendLog("❌ No collection selected for Auth analysis");
                return;
            }

            ui.appendLog("🔍 Running Auth analysis...");

            // ✅ Parse collection
            PostmanCollection collection = currentCollection;

            if (collection == null) {
                collection = parser.parseCollection(collectionFile);
                currentCollection = collection;
            }
            authManager.setCollectionAuth(collection.auth);
            tokenValueToVar.clear();
            // ✅ STEP 1 — RESET VARIABLES (but preserve user-entered values)
            java.util.Map<String, String> userSnapshot =
                new java.util.LinkedHashMap<>();
            // STRICT ISOLATION: route detected variables into a specific
            // collection's scope when:
            //   (a) caller explicitly forced a scope (right-click Analyze), OR
            //   (b) one or more collection wrappers are pendingAnalyze
            //       (auto-analyze after + Add Collection / folder import).
            //       When multiple wrappers are pending we loop and analyze each
            //       into its own scope sequentially.
            String autoScope = forcedAnalyzeScope;
            java.util.List<String> multiPending = new java.util.ArrayList<>();
            if (autoScope == null) {
                if (currentCollection != null && currentCollection.item != null) {
                    for (PostmanCollection.Item it : currentCollection.item) {
                        if (it != null && it.isCollectionWrapper && it.pendingAnalyze && !it.analyzed) {
                            multiPending.add(it.name);
                        }
                    }
                }
                if (multiPending.size() == 1) {
                    autoScope = multiPending.get(0);
                    multiPending.clear();
                }
            }

            // If multiple wrappers are pending, recurse — analyze each one in
            // its own strict scope, then return so the outer call doesn't
            // double-process anything.
            if (autoScope == null && !multiPending.isEmpty()) {
                ui.appendLog("🎯 Analyzing " + multiPending.size() + " collections (strict per-collection scopes)...");
                for (String wname : multiPending) {
                    try {
                        forcedAnalyzeScope = wname;
                        analyzeAuthFromFiles(collectionFile, environmentFile);
                    } finally {
                        forcedAnalyzeScope = null;
                    }
                }
                return;
            }
            final boolean strictScoped = autoScope != null && !autoScope.isEmpty();
            if (strictScoped) {
                variableResolver.setActiveScope(autoScope);
                ui.appendLog("🔒 Analyze writing to scope [" + autoScope + "] (strict isolation)");
                // Preserve only this scope's prior values. Pulling the full
                // global map here leaks previous collections' OAuth vars
                // (notably {{scope}}) into the active collection.
                userSnapshot.putAll(variableResolver.getScopedVariables(autoScope));
            } else {
                userSnapshot.putAll(variableResolver.getVariables());
                variableResolver.clearAllVariables();
            }

            // ✅ STEP 2 — LOAD ENV
            if (environmentFile != null) {
                PostmanEnvironment env = parser.parseEnvironment(environmentFile);
                variableResolver.addEnvironmentVariables(env);
                ui.appendLog("✅ Environment variables loaded");
            }

            // ✅ STEP 2b — LOAD GLOBALS (lower precedence; env keys win).
            if (globalsFile != null) {
                try {
                    PostmanEnvironment globals = parser.parseEnvironment(globalsFile);
                    variableResolver.addGlobalsVariables(globals);
                    ui.appendLog("🌐 Globals loaded from: " + globalsFile.getName());
                } catch (Exception gx) {
                    ui.appendLog("⚠ Failed to load globals: " + gx.getMessage());
                }
            }

            // ✅ STEP 3 — LOAD COLLECTION VARIABLES
            addCollectionVariablesPreservingCurrent(collection);

            // STRICT ISOLATION: when analyzing into a single collection scope,
            // restrict token/host registration to ONLY that wrapper's items so
            // we don't accidentally re-register other collections' tokens
            // (which would land in the active scope and leak between collections).
            PostmanCollection analysisTarget = collection;
            if (strictScoped && currentCollection != null && currentCollection.item != null) {
                PostmanCollection.Item match = null;
                for (PostmanCollection.Item w : currentCollection.item) {
                    if (w != null && w.isCollectionWrapper && autoScope.equals(w.name)) {
                        match = w; break;
                    }
                }
                if (match != null) {
                    PostmanCollection scoped = new PostmanCollection();
                    scoped.info = collection.info;
                    scoped.auth = match.auth;
                    scoped.variable = collection.variable;
                    scoped.item = match.item != null
                            ? new java.util.ArrayList<>(match.item)
                            : new java.util.ArrayList<>();
                    analysisTarget = scoped;
                }
            }

            // ✅ ✅ ✅ STEP 4 — NORMALIZE JWT EARLY (CRITICAL FIX)
            normalizeJwt(analysisTarget, variableResolver,false);
            // ✅ NEW: register tokens early (including folder auth)
            registerAllTokens(analysisTarget);
            // Seed folder-auth registry from the FULL workspace so tree-path
            // keys (e.g. "WrapperName/UAT") match exactly what the UI uses.
            seedFolderAuthFullWorkspace();

            // ✅ Auto-convert hosts silently during Auth analysis
            promptAndConvertHosts(analysisTarget, variableResolver, false);

            // Restore user-entered values that were captured before the reset.
            // This re-applies anything the user typed in Edit Variables (e.g. token_*),
            // overriding any blank/auto-detected value but only if the user value is non-empty.
            if (userSnapshot != null && !userSnapshot.isEmpty()) {
                int restored = 0;
                for (java.util.Map.Entry<String, String> e : userSnapshot.entrySet()) {
                    String v = e.getValue();
                    if (v != null && !v.isEmpty()) {
                        if (strictScoped) {
                            variableResolver.putScopedVariable(autoScope, e.getKey(), v);
                        } else {
                            variableResolver.addCustomVariable(e.getKey(), v);
                        }
                        restored++;
                    }
                }
                if (restored > 0) ui.appendLog("♻️ Restored " + restored + " user variable value(s) after Analyze.");
            }

            // ✅ refresh UI after registration
            ui.refreshVariables(variableResolver.getVariables());

            boolean converted = normalizeJwt(analysisTarget, variableResolver,false);

            if (converted) {

                Map<String, String> vars = variableResolver.getVariables();

                // ✅ ensure token exists even for null/empty
                if (!vars.containsKey("token") ||
                    vars.get("token") == null ||
                    vars.get("token").isEmpty()) {

                }

                ui.appendLog("✅ JWT converted to {{token}}");
            }

            // ✅ ✅ ✅ STEP 5 — FORCE UI TO SEE TOKEN (CRITICAL FIX)
            ui.refreshVariables(variableResolver.getVariables());


            // ✅ STEP 6 — OAuth detection
            detectAndOfferOAuth2(collection, variableResolver);

            // ✅ STEP 7 — JWT endpoint detection
            List<JwtEndpointCandidate> jwtCandidates =
                    detectTokenSourceCandidates(collection, variableResolver);

            // ✅ STEP 8 — Static JWT detection
            List<String> staticTokens =
                    staticDetector.detect(collection, variableResolver);

            // ✅ ✅ STEP 9 — UPDATE UI AFTER EVERYTHING IS READY
            ui.updateAuthDetectionFull(
                    authManager.getOAuth2Configs(),
                    jwtCandidates,
                    staticTokens
            );

            ui.appendLog("✅ Auth analysis complete (resolved endpoints)");

            // Determine which collection wrappers were newly added via
            // + Add Collection and not yet analyzed. If any are pending,
            // scope this Analyze run to ONLY those (don't re-fire siblings).
            // If the caller forced a specific scope (e.g. user clicked a
            // collection in the tree), use that instead.
            final java.util.Set<String> pendingWrappers = new java.util.HashSet<>();
            final boolean hasWrappers;
            {
                boolean hw = false;
                if (currentCollection != null && currentCollection.item != null) {
                    for (PostmanCollection.Item it : currentCollection.item) {
                        if (it != null && it.isCollectionWrapper) {
                            hw = true;
                            if (forcedAnalyzeScope != null) {
                                if (forcedAnalyzeScope.equals(it.name)) {
                                    pendingWrappers.add(it.name == null ? "" : it.name);
                                }
                            } else if (it.pendingAnalyze && !it.analyzed) {
                                pendingWrappers.add(it.name == null ? "" : it.name);
                            }
                        }
                    }
                }
                hasWrappers = hw;
            }
            final boolean scopeToPending = hasWrappers && !pendingWrappers.isEmpty();

            // Mark wrappers as analyzed so the tree renderer shows ✓.
            // Scoped run → mark only the pending ones; full run → mark all.
            try {
                if (scopeToPending) {
                    for (PostmanCollection.Item it : currentCollection.item) {
                        if (it != null && it.isCollectionWrapper
                                && pendingWrappers.contains(it.name == null ? "" : it.name)) {
                            it.analyzed = true;
                            it.pendingAnalyze = false;
                        }
                    }
                    if (ui != null && ui.getTreePanel() != null) ui.getTreePanel().repaint();
                } else {
                    markAllCollectionsAnalyzed();
                    if (currentCollection != null && currentCollection.item != null) {
                        for (PostmanCollection.Item it : currentCollection.item) {
                            if (it != null) it.pendingAnalyze = false;
                        }
                    }
                }
            } catch (Exception ignore) {}

            // ✅ ✅ BUILD AND DISPLAY COLLECTION TREE
            SwingUtilities.invokeLater(() -> {
                try {
                    // Flatten collection into AnalyzedRequest list for tree display
                    List<AnalyzedRequest> analyzed = new ArrayList<>();
                    
                    if (currentCollection != null && currentCollection.item != null) {
                        flattenToAnalyzedRequests(currentCollection.item, "", analyzed, 
                            currentCollection.info != null ? currentCollection.info.name : "Collection");
                    }
                    
                    CollectionTreeNode root = buildCollectionTree(analyzed);
                    if (root != null) {
                        ui.getTreePanel().loadCollection(root);
                        ui.appendLog("✅ Collection tree built and displayed with " + analyzed.size() + " requests");
                    } else {
                        ui.appendLog("⚠ Tree not built: collection is empty or null");
                    }

                    // Option A: Analyze is STATIC ONLY. Tree + variables are
                    // populated, but the script chain (token endpoints, etc.)
                    // does NOT fire automatically. Instead, surface a "Run
                    // Scripts" banner above the tree so the user can opt-in.
                    // Rationale:
                    //   • Avoids long Analyze times on big collections.
                    //   • Lets the user inspect resolved hosts/vars first.
                    //   • Keeps Burp's request log clean unless the user
                    //     actually wants to capture tokens.
                    if (!analyzed.isEmpty()) {
                        java.util.List<AnalyzedRequest> toFire = analyzed;
                        if (scopeToPending) {
                            toFire = new java.util.ArrayList<>();
                            for (AnalyzedRequest ar : analyzed) {
                                if (ar == null) continue;
                                String p = ar.getPath();
                                if (p == null) continue;
                                int slash = p.indexOf('/');
                                String head = slash >= 0 ? p.substring(0, slash) : p;
                                if (pendingWrappers.contains(head)) toFire.add(ar);
                            }
                            ui.appendLog("🎯 Analyze scoped to newly-added collections: "
                                    + pendingWrappers + " (" + toFire.size() + " request(s))");
                        }
                        // Count requests with pre/post-scripts so we know
                        // whether to surface the banner at all. Static-only
                        // collections (no scripts) just see the tree, no CTA.
                        int scriptedCount = 0;
                        for (AnalyzedRequest ar : toFire) {
                            if (ar == null) continue;
                            try {
                                String[] s = getScriptsForPath(ar.getPath());
                                boolean hasPre  = s != null && s.length > 0
                                        && s[0] != null && !s[0].trim().isEmpty();
                                boolean hasPost = s != null && s.length > 1
                                        && s[1] != null && !s[1].trim().isEmpty();
                                if (hasPre || hasPost) scriptedCount++;
                            } catch (Exception ignore) {}
                        }
                        if (scriptedCount > 0) {
                            final java.util.List<AnalyzedRequest> finalToFire = toFire;
                            ui.appendLog("📜 Analyze: detected " + scriptedCount
                                    + " scripted request(s). Click ▶ Run Scripts to fetch tokens.");
                            ui.showRunScriptsBanner(scriptedCount, "Run Scripts",
                                () -> runAnalyzedBatch(finalToFire, "Run Scripts"));
                        } else {
                            ui.appendLog("ℹ️ Analyze: no scripted requests detected — tree-only mode.");
                            ui.hideRunScriptsBanner();
                        }
                    }
                } catch (Exception e) {
                    ui.appendLog("⚠ Failed to build tree: " + e.getMessage());
                }
            });

        } catch (Exception e) {
            String msg = e.getMessage();
            ui.appendLog("❌ Auth analysis failed: " + (msg != null ? msg : e.getClass().getSimpleName()));
            java.io.StringWriter sw = new java.io.StringWriter();
            e.printStackTrace(new java.io.PrintWriter(sw));
            ui.appendLog(sw.toString());
            api.logging().logToError("Auth analysis failed: " + sw.toString());
        } finally {
            // Always clear the analyze-time active scope so the resolver
            // returns to global mode after analysis ends.
            try { variableResolver.clearActiveScope(); } catch (Exception ignore) {}
        }
    }

    /**
     * Fire every request in the loaded collection that has a pre-request or
     * post-response script. Runs the pre-script, sends the built request to
     * Repeater (and over the wire to capture a response), then runs the
     * post-script with that response so {{token}} and other cascading vars
     * get populated. Mirrors the "Analyze Collection [run-…]" preview flow
     * from the prior build.
     */
    public void runScriptedAnalyze(java.io.File collectionFile, java.io.File environmentFile) {
        try {
            PostmanCollection collection = currentCollection;
            if (collection == null && collectionFile != null) {
                collection = parser.parseCollection(collectionFile);
                currentCollection = collection;
            }
            if (collection == null) {
                ui.appendLog("ℹ️ Analyze Collection: no collection loaded.");
                return;
            }

            final java.util.List<AnalyzedRequest> analyzed = new java.util.ArrayList<>();
            String collectionName = collection.info != null ? collection.info.name : "Collection";
            String collPre  = AnalyzedRequest.extractScriptFromEvents(collection.event, "prerequest");
            String collPost = AnalyzedRequest.extractScriptFromEvents(collection.event, "test");
            flattenWithScripts(collection.item, "", analyzed, collectionName, collPre, collPost);

            int scripted = 0, unscripted = 0;
            for (AnalyzedRequest ar : analyzed) {
                if (hasAnyScript(ar)) scripted++; else unscripted++;
            }
            if (scripted == 0) {
                ui.appendLog("ℹ️ Analyze Collection: no scripted requests detected — nothing to fire.");
                return;
            }
            final int scriptedCount = scripted;
            final int unscriptedCount = unscripted;

            final String runId = "run-" + System.currentTimeMillis();
            ui.appendLog("════════════════════════════════════════");
            ui.appendLog("▶️ Analyze Collection [" + runId + "]: firing " + scriptedCount
                    + " scripted request(s) (skipping " + unscriptedCount
                    + " unscripted, NOT added to site map)…");
            ui.appendLog("ℹ️ Tip: check Run Results for per-request status, tests, and bodies.");

            new Thread(() -> {
                int sent = 0;
                try {
                    for (AnalyzedRequest ar : analyzed) {
                        if (!hasAnyScript(ar)) continue;

                        String pre  = ar.getPreScript();
                        String post = ar.getPostScript();

                        // 1) Pre-request script
                        if (pre != null && !pre.trim().isEmpty()) {
                            try {
                                burp.service.ScriptExecutor.runAndApply(pre, variableResolver, null, ar.getRequest());
                            } catch (Throwable t) {
                                ui.appendLog("⚠ Pre-script error for " + ar.getName() + ": " + t.getMessage());
                            }
                            ui.appendLog("📜 Pre-request script ran for " + ar.getName());
                        }

                        // 2) Build + send to Repeater (logs FINAL REQUEST BEFORE BUILDER…)
                        RequestItem ri = new RequestItem(ar.getName(), ar.getPath(),
                                ar.getRequest(), ar.getCollectionName());
                        try {
                            processRequest(ri, "repeater", true);
                            sent++;
                        } catch (Exception px) {
                            ui.appendLog("⚠ Send failed for " + ar.getName() + ": " + px.getMessage());
                        }

                        // 3) Fire over the wire to capture a real response for the post-script
                        burp.models.ExecutedRequest response = fireForScript(ar);

                        // 4) Post-response script (gets response context)
                        if (post != null && !post.trim().isEmpty()) {
                            try {
                                PostmanCollection.Request postRequestContext =
                                        ScriptRequestContextBuilder.fromTemplate(
                                                ar.getRequest(),
                                                variableResolver,
                                                response != null ? response.getUrl() : null);
                                burp.service.ScriptExecutor.runAndApply(
                                        post,
                                        variableResolver,
                                        response,
                                        postRequestContext != null ? postRequestContext : ar.getRequest());
                            } catch (Throwable t) {
                                ui.appendLog("⚠ Post-script error for " + ar.getName() + ": " + t.getMessage());
                            }
                            ui.appendLog("📜 Post-response script ran for " + ar.getName());
                        }

                        // 5) Push updated vars back to the UI so {{token}} cascades are visible
                        ui.refreshVariables(variableResolver.getVariables());
                    }
                    ui.appendLog("✅ Analyze Collection complete: " + sent + "/" + scriptedCount
                            + " request(s) staged in Repeater");
                    ui.refreshVariables(variableResolver.getVariables());
                } catch (Throwable t) {
                    ui.appendLog("❌ Analyze Collection error: " + t.getMessage());
                }
            }, "auto-run-preview").start();
        } catch (Exception e) {
            ui.appendLog("❌ runScriptedAnalyze failed: " + e.getMessage());
        }
    }

    private static boolean hasAnyScript(AnalyzedRequest ar) {
        return (ar.getPreScript()  != null && !ar.getPreScript().trim().isEmpty())
            || (ar.getPostScript() != null && !ar.getPostScript().trim().isEmpty());
    }

    private void flattenWithScripts(java.util.List<PostmanCollection.Item> items, String path,
                                    java.util.List<AnalyzedRequest> out, String collectionName,
                                    String ancestorPre, String ancestorPost) {
        if (items == null) return;
        for (PostmanCollection.Item it : items) {
            if (it == null) continue;
            String name = it.name != null ? it.name : "Unnamed";
            String currentPath = path.isEmpty() ? name : path + "/" + name;
            String ownPre  = AnalyzedRequest.extractScriptFromEvents(it.event, "prerequest");
            String ownPost = AnalyzedRequest.extractScriptFromEvents(it.event, "test");
            if (it.request != null) {
                AnalyzedRequest ar = new AnalyzedRequest(name, currentPath, it.request,
                        collectionName, extractRawUrl(it.request.url));
                ar.setPreScript(ancestorPre + ownPre);
                ar.setPostScript(ancestorPost + ownPost);
                out.add(ar);
            }
            if (it.item != null && !it.item.isEmpty()) {
                flattenWithScripts(it.item, currentPath, out, collectionName,
                        ancestorPre + ownPre, ancestorPost + ownPost);
            }
        }
    }

    private burp.models.ExecutedRequest fireForScript(AnalyzedRequest ar) {
        try {
            RequestBuilder freshBuilder = new RequestBuilder(api, variableResolver, authManager);
            byte[] raw;
            PostmanCollection.Auth effectiveAuth = ar.getRequest().auth;
            if (hasAuthorizationHeader(ar.getRequest())) {
                raw = freshBuilder.buildRequest(ar.getRequest());
            } else {
                raw = freshBuilder.buildRequest(ar.getRequest(), effectiveAuth);
            }
            String rawUrl = extractRawUrl(ar.getRequest().url);
            if (rawUrl == null) return null;
            String resolvedUrl = variableResolver.resolve(rawUrl);
            HttpUtils.HostInfo hi = HttpUtils.parseUrl(resolvedUrl);

            // Inject the session cookie for this host if we captured one
            // from a prior request in the same run. Without this, stateful
            // auth flows (CIAM, ForgeRock, Salesforce sessions) break after
            // step 1 because subsequent steps don't carry the session ID.
            String cookieHeader = cookieJar.buildCookieHeader(hi.host);
            if (cookieHeader != null && !cookieHeader.isEmpty()) {
                // Splice "Cookie: <value>" before the empty line that ends headers.
                raw = injectHeaderIfMissing(raw, "Cookie", cookieHeader);
            }

            burp.api.montoya.http.HttpService svc =
                    burp.api.montoya.http.HttpService.httpService(hi.host, hi.port, hi.useHttps);
            burp.api.montoya.http.message.requests.HttpRequest req =
                    burp.api.montoya.http.message.requests.HttpRequest.httpRequest(svc,
                            burp.api.montoya.core.ByteArray.byteArray(raw));
            long t0 = System.currentTimeMillis();
            burp.api.montoya.http.message.HttpRequestResponse resp = burp.service.ProxyRouter.sendRequest(api, req);
            long durationMs = System.currentTimeMillis() - t0;

            burp.models.ExecutedRequest er = new burp.models.ExecutedRequest(
                    java.util.UUID.randomUUID().toString(),
                    System.currentTimeMillis(),
                    ar.getRequest() != null ? ar.getRequest().method : "GET",
                    resolvedUrl, null, null);
            er.setDurationMs(durationMs);
            if (resp != null && resp.response() != null) {
                er.setStatusCode(resp.response().statusCode());
                er.setResponseBody(resp.response().bodyToString());
                // Capture response headers — needed for the Run Results
                // tab and for cookie-jar Set-Cookie absorption below.
                java.util.List<PostmanCollection.Header> respHeaders = new java.util.ArrayList<>();
                try {
                    for (burp.api.montoya.http.message.HttpHeader h : resp.response().headers()) {
                        PostmanCollection.Header rh = new PostmanCollection.Header();
                        rh.key = h.name();
                        rh.value = h.value();
                        respHeaders.add(rh);
                    }
                } catch (Throwable ignore) {}
                er.setResponseHeaders(respHeaders);
                // Absorb Set-Cookie so the next request in this run can
                // send the session cookie back. This is what makes CIAM /
                // session-auth chains work in Run Scripts.
                try { cookieJar.capture(hi.host, respHeaders); }
                catch (Throwable ignore) {}
            }
            return er;
        } catch (Throwable t) {
            ui.appendLog("⚠ Preview fetch failed for " + ar.getName() + ": " + t.getMessage());
            return null;
        }
    }

    /** Splice a header into a raw HTTP request bytes blob just before the
     *  empty line that terminates the header section. If the header already
     *  exists (case-insensitive), the raw bytes are returned untouched.
     *  Used to inject Cookie: from the cookie jar on Run Scripts requests. */
    private static byte[] injectHeaderIfMissing(byte[] raw, String headerName, String headerValue) {
        if (raw == null || headerName == null || headerValue == null) return raw;
        String s = new String(raw, java.nio.charset.StandardCharsets.UTF_8);
        // End-of-headers marker. HTTP/1.1 always uses CRLF; tolerate LF too.
        int eoh = s.indexOf("\r\n\r\n");
        String sep = "\r\n";
        if (eoh < 0) { eoh = s.indexOf("\n\n"); sep = "\n"; }
        if (eoh < 0) return raw;
        String headerBlock = s.substring(0, eoh);
        // Case-insensitive presence check on the header name at line start.
        String lower = headerBlock.toLowerCase();
        String needle = "\n" + headerName.toLowerCase() + ":";
        if (lower.startsWith(headerName.toLowerCase() + ":") || lower.contains(needle)) {
            return raw;
        }
        String body = s.substring(eoh);
        String newHeaders = headerBlock + sep + headerName + ": " + headerValue;
        return (newHeaders + body).getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private void detectAndOfferOAuth2(PostmanCollection collection, VariableResolver resolver) {
        try {
            OAuth2Detector oauth2Detector = new OAuth2Detector(resolver);
            List<OAuth2Config> oauth2Configs = oauth2Detector.detect(collection);
    
            authManager.setOAuth2Configs(oauth2Configs);
    
            if (oauth2Configs == null || oauth2Configs.isEmpty()) {
                ui.appendLog("No OAuth2 config detected.");
                return;
            }
    
            ui.appendLog("Detected " + oauth2Configs.size() + " OAuth2 config(s).");
    
            ui.appendLog("Oauth2 Configs in the Auth Panel");
            
    
        } catch (Exception e) {
            ui.appendLog("OAuth2 detection failed: " + e.getMessage());
            api.logging().logToError("OAuth2 detection failed: " + e.getMessage());
        }
    }
    private PostmanCollection.Auth resolveEffectiveAuthForRequest(RequestItem item) {

        if (item == null || item.request == null) {
            return currentCollection != null ? currentCollection.auth : null;
        }

        // Request-level auth wins, including noauth.
        if (item.request.auth != null) {
            return item.request.auth;
        }

        PostmanCollection.Auth folderAuth = resolveFolderAuthObject(item.path);

        if (folderAuth != null) {
            return folderAuth;
        }

        return currentCollection != null ? currentCollection.auth : null;
    }


    public PostmanCollection.Auth resolveFolderAuthObject(String path) {

        if (path == null || currentCollection == null || currentCollection.item == null) {
            return null;
        }

        String[] parts = path.split("/");
        java.util.List<PostmanCollection.Item> items = currentCollection.item;
        PostmanCollection.Auth nearest = null;

        // Walk down the path and keep the closest (deepest) ancestor auth.
        // This matches Postman inheritance where child folder auth overrides
        // collection/wrapper auth.
        for (String part : parts) {
            if (items == null) {
                return nearest;
            }

            PostmanCollection.Item matched = null;

            for (PostmanCollection.Item i : items) {
                if (i != null && part.equals(i.name)) {
                    matched = i;
                    break;
                }
            }

            if (matched == null) {
                return nearest;
            }

            if (matched.auth != null) {
                nearest = matched.auth;
            }

            items = matched.item;
        }

        return nearest;
    }

    /** Like resolveFolderAuthObject but returns the auth ONLY if it's set on
     *  the exact node referenced by `path`. Used by the editor so children
     *  display "Inherit auth from parent" instead of their parent's bearer. */
    public PostmanCollection.Auth resolveFolderAuthObjectExact(String path) {
        if (path == null || currentCollection == null || currentCollection.item == null) return null;
        String[] parts = path.split("/");
        java.util.List<PostmanCollection.Item> items = currentCollection.item;
        PostmanCollection.Item matched = null;
        for (String part : parts) {
            if (items == null) return null;
            matched = null;
            for (PostmanCollection.Item i : items) {
                if (i != null && part.equals(i.name)) { matched = i; break; }
            }
            if (matched == null) return null;
            items = matched.item;
        }
        return matched != null ? matched.auth : null;
    }
    private boolean normalizeJwt(
            PostmanCollection collection,
            VariableResolver resolver,
            boolean silent) {

        if (collection == null) {
            return false;
        }

        if (!hasAnyJwt(collection, resolver)) {
            return false;
        }

        // No popup. Always normalize silently.
        normalizeJwtToVariable(collection);
        return true;
    }
    private boolean hasAnyJwt(
            PostmanCollection collection,
            VariableResolver resolver) {

        return checkJwt(collection.item, collection.auth);
    }
    private boolean checkJwt(
            List<PostmanCollection.Item> items,
            PostmanCollection.Auth inheritedAuth) {

        if (items == null) return false;


        for (PostmanCollection.Item item : items) {

            PostmanCollection.Auth currentAuth =
                    (item.request != null && item.request.auth != null)
                            ? item.request.auth
                            : (item.auth !=null
                                ? item.auth
                                : inheritedAuth);
            // HEADER
            if (item.request != null && item.request.header != null) {

                for (PostmanCollection.Header h : item.request.header) {

                    if (h != null &&
                            !h.disabled &&
                            "Authorization".equalsIgnoreCase(h.key) &&
                            h.value != null &&
                            h.value.toLowerCase().startsWith("bearer") &&
                            !h.value.contains("{{")) {

                        String token = h.value.replaceFirst("(?i)bearer", "").trim();

                        if (!token.contains("{{")) {

                            return true;
                        
                        }
                    }
                }
            }
            // AUTH OBJECT
            if (currentAuth != null &&
                "bearer".equalsIgnoreCase(currentAuth.type) &&
                currentAuth.bearer != null) {
        
            try {
                if (currentAuth.bearer instanceof List) {
        
                    List<?> list = (List<?>) currentAuth.bearer;
        
                    for (Object o : list) {
        
                        if (o instanceof PostmanCollection.AuthAttribute) {
        
                            PostmanCollection.AuthAttribute v =
                                    (PostmanCollection.AuthAttribute) o;
        
                            if (v != null &&
                                    v.value != null &&
                                    !v.value.contains("{{")) {
        
                                String token = v.value.trim();
        
                                if (!token.contains("{{")) {

                                    return true;
                                
                                }
                            }
                        }
                    }
                }
        
            } catch (Exception ignored) {}
        }

            if (checkJwt(item.item, currentAuth)) return true;
        }

        return false;
    }
    
    public void autoFetchFromJwt(PostmanCollection.Request req) {
        autoFetchFromJwt(req, null);
    }

    public void autoFetchFromJwt(PostmanCollection.Request req, java.util.function.Consumer<String> onToken) {

        new Thread(() -> {
    
            try {
                PostmanCollection.Request tokenFetchRequest = normalizeTokenSourceRequestForWire(req);
                if (tokenFetchRequest == null) {
                    SwingUtilities.invokeLater(() -> {
                        ui.appendLog("❌ Cannot AutoFetch: token source request is empty");
                        if (onToken != null) onToken.accept(null);
                    });
                    return;
                }

                byte[] raw = requestBuilder.buildRequest(tokenFetchRequest);
    
                String rawUrl = extractRawUrl(tokenFetchRequest.url);
                String resolved = variableResolver.resolve(rawUrl);
    
                // ✅ Prevent unresolved URLs
                if (resolved == null || resolved.contains("{{")) {
                    SwingUtilities.invokeLater(() ->
                            ui.appendLog("❌ Cannot AutoFetch: unresolved variables → " + resolved)
                    );
                    return;
                }
    
                HttpUtils.HostInfo host = HttpUtils.parseUrl(resolved);
    
                burp.api.montoya.http.HttpService svc =
                        burp.api.montoya.http.HttpService.httpService(
                                host.host, host.port, host.useHttps
                        );
    
                burp.api.montoya.http.message.requests.HttpRequest httpRequest =
                        burp.api.montoya.http.message.requests.HttpRequest
                                .httpRequest(svc,
                                        burp.api.montoya.core.ByteArray.byteArray(raw));
    
                // ✅ Send request
                burp.api.montoya.http.message.HttpRequestResponse resp =
                        burp.service.ProxyRouter.sendRequest(api, httpRequest);
    
                if (resp != null && resp.response() != null) {
    
                    // ✅ Add to Burp Site Map (visible in Target tab)
                    api.siteMap().add(resp);
    
    
                    // ✅ Extract token
                    boolean ok = authManager.extractAnyToken(
                            resp.response().bodyToString()
                    );
    
                    SwingUtilities.invokeLater(() -> {
                        if (ok) {
                            ui.appendLog("✅ Token extracted successfully");
                    
                            // ✅ 🔥 NEW — update token UI
                            String token = authManager.getAccessToken();
                            if (token != null) {
                                ui.updateTokenArea(token);   // ✅ NEW METHOD
                            }
                            if (onToken != null) onToken.accept(token);
                    
                        } else {
                            ui.appendLog("❌ No token found");
                            if (onToken != null) onToken.accept(null);
                        }
                    });
                } else {
                    SwingUtilities.invokeLater(() -> {
                        if (onToken != null) onToken.accept(null);
                    });
                }
    
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    ui.appendLog("AutoFetch failed: " + e.getMessage());
                    if (onToken != null) onToken.accept(null);
                });
            }
    
        }).start();
    }
    private Set<String> getAllVariablesFromLastPreviews() {
        Set<String> variables = new HashSet<>();
    
        if (lastGeneratedPreviews == null || lastGeneratedPreviews.isEmpty()) {
            return variables;
        }
    
        for (RequestPreview preview : lastGeneratedPreviews) {
            if (preview != null && preview.getAllVariables() != null) {
                variables.addAll(preview.getAllVariables());
            }
        }
    
        return variables;
    }
    public void sendJwtToRepeater(PostmanCollection.Request req) {

        try {
            PostmanCollection.Request tokenFetchRequest = normalizeTokenSourceRequestForWire(req);
            if (tokenFetchRequest == null) {
                ui.appendLog("Send to Repeater failed: token source request is empty");
                return;
            }

            byte[] raw = requestBuilder.buildRequest(tokenFetchRequest);
    
            String rawUrl = extractRawUrl(tokenFetchRequest.url);
            String resolved = variableResolver.resolve(rawUrl);
    
            HttpUtils.HostInfo host = HttpUtils.parseUrl(resolved);
    
            burp.api.montoya.http.HttpService svc =
                    burp.api.montoya.http.HttpService.httpService(
                            host.host, host.port, host.useHttps
                    );
    
            burp.api.montoya.http.message.requests.HttpRequest httpRequest =
                    burp.api.montoya.http.message.requests.HttpRequest
                            .httpRequest(svc,
                                    burp.api.montoya.core.ByteArray.byteArray(raw));
    
            api.repeater().sendToRepeater(httpRequest, "JWT Fetch");
    
        } catch (Exception e) {
            ui.appendLog("Send to Repeater failed: " + e.getMessage());
        }
    }
     
    
    private ImportResult mergeRetryResults(ImportResult original, ImportResult retry) {
        ImportResult merged = new ImportResult();
        merged.collectionName = original.collectionName;
        merged.totalRequests = original.totalRequests;
        merged.successCount = original.successCount + retry.successCount;
        
        // Only keep requests that failed in the retry
        merged.failedRequests.addAll(retry.failedRequests);
        merged.failedRequestDetails.addAll(retry.failedRequestDetails);
        
        return merged;
    }
    
    // New method for generating previews
    public void showPreview(File collectionFile, File environmentFile) {
        // Reset variable resolution flag for new preview
        variablesAlreadyResolved = false;
        
        SwingWorker<List<RequestPreview>, String> worker = new SwingWorker<List<RequestPreview>, String>() {
            @Override
            protected List<RequestPreview> doInBackground() throws Exception {
                publish("Analyzing collection...");
                
                // Parse collection
                PostmanCollection collection = currentCollection;

                if (collection == null) {
                    collection = parser.parseCollection(collectionFile);
                    currentCollection = collection;
                }
                
                // Parse environment if provided
                VariableResolver tempResolver = variableResolver;

                if (environmentFile != null) {
                    publish("Loading environment variables...");
                    PostmanEnvironment environment = parser.parseEnvironment(environmentFile);
                    tempResolver.addEnvironmentVariables(environment);
                }
                
                addCollectionVariablesPreservingCurrent(collection);

                // ✅ Apply existing manual/custom variables last so they override env/collection values.
                for (Map.Entry<String, String> entry : variableResolver.getVariables().entrySet()) {
                    tempResolver.addCustomVariable(entry.getKey(), entry.getValue());
                }
                
                // ✅ Auth detection must use the same resolver as Preview.
                detectAndOfferOAuth2(collection, tempResolver);
                                
                // ✅ Auto-convert hosts silently (no dialog)
                promptAndConvertHosts(collection, tempResolver, false);
                
                
                List<JwtEndpointCandidate> jwtCandidates = detectTokenSourceCandidates(collection, tempResolver);
                List<String> staticTokens = staticDetector.detect(collection, tempResolver);
                
                ui.updateAuthDetectionFull(
                        authManager.getOAuth2Configs(),
                        jwtCandidates,
                        staticTokens
                );
                // Analyze variables
                publish("Analyzing variables...");
                VariableDetector tempDetector = new VariableDetector(tempResolver, api);
                VariableAnalysis variableAnalysis = tempDetector.analyzeCollection(collection);
                for (Map.Entry<String, String> entry : variableResolver.getVariables().entrySet()) {
                    tempResolver.addCustomVariable(entry.getKey(), entry.getValue());
                }
                
                // Generate previews with variable information
                publish("Generating request previews...");
                return generatePreviews(collection, tempResolver, tempDetector, variableAnalysis);
            }
            
            @Override
            protected void process(List<String> chunks) {
                for (String message : chunks) {
                    ui.appendLog(message);
                }
            }
            
            @Override
            protected void done() {
                try {
                    List<RequestPreview> previews = get();

                    // ✅ Cache analysis previews so Edit Variables can reuse the same result.
                    lastGeneratedPreviews = previews != null ? previews : new ArrayList<>();
                    
                    ui.appendLog("Analysis complete. Checking for variables...");
                    
                    // Check if we need to handle variables first
                    checkAndHandleVariables(previews, collectionFile, environmentFile);
                    List<AnalyzedRequest> analyzed = new ArrayList<>();

                    for (RequestPreview p : lastGeneratedPreviews) {
                        if (p != null && p.getRequest() != null) {
                        analyzed.add(new AnalyzedRequest(
                            p.getName(),
                            p.getPath(),
                            p.getRequest(),
                            currentCollection != null && currentCollection.info != null
                                ? currentCollection.info.name
                                : "Collection",
                            p.getUrl()  // ✅ REQUIRED
                        ));
                        }
                    }

                    CollectionTreeNode root = buildCollectionTree(analyzed);

                    if (root != null && ui.getTreePanel() != null) {
                        ui.getTreePanel().loadCollection(root);
                    } else {
                        ui.appendLog("⚠ Tree not built: collection is empty or null");
                    }
                    // ✅ ✅ ✅ END

                } catch (Exception e) {
                    ui.showError("Preview failed: " + e.getMessage());
                    ui.appendLog("Preview error: " + e.getMessage());
                }
            }
        };
        
        worker.execute();
    }
    private void checkAndHandleVariables(List<RequestPreview> previews, File collectionFile, File environmentFile) {
        // Check if there are any unresolved variables across all requests
        boolean hasUnresolvedVariables = previews.stream()
            .anyMatch(RequestPreview::hasUnresolvedVariables);
        
        if (hasUnresolvedVariables) {
            api.logging().logToOutput("🎉🎉🎉 SHOWING PREVIEW VARIABLE DIALOG NOW! 🎉🎉🎉");
            // Show variable resolution dialog regardless of environment file
            showVariableResolutionDialog(previews, collectionFile, environmentFile);
        } else {
            api.logging().logToOutput("❌❌❌ PREVIEW: NO VARIABLES DETECTED - SHOWING SELECTION DIALOG ❌❌❌");
            // Proceed directly to selection dialog
            showSelectionDialog(previews, collectionFile, environmentFile);
        }
    }
    private VariableAnalysis buildVariableAnalysisFromPreviews(List<RequestPreview> previews) {
        Set<String> unresolvedVariables = new HashSet<>();
        int totalRequests = previews != null ? previews.size() : 0;
        int requestsWithVariables = 0;
    
        if (previews != null) {
            for (RequestPreview preview : previews) {
                if (preview != null && preview.hasUnresolvedVariables()) {
                    requestsWithVariables++;
                    unresolvedVariables.addAll(preview.getUnresolvedVariables());
                }
            }
        }
    
        return new VariableAnalysis(
            unresolvedVariables,
            totalRequests,
            requestsWithVariables
        );
    }
    private void showVariableResolutionDialog(List<RequestPreview> previews, File collectionFile, File environmentFile) {
        SwingUtilities.invokeLater(() -> {
            try {
                // ✅ Reuse Preview results instead of re-analyzing collection.
                VariableAnalysis analysis = buildVariableAnalysisFromPreviews(previews);
    
                if (analysis.hasVariables()) {
                    VariableResolutionDialog dialog = new VariableResolutionDialog(
                            ui.getPanel(),
                            analysis,
                            variableDetector
                    );
    
                    if (dialog.showDialog()) {
                        handleVariableResolution(dialog, previews, collectionFile, environmentFile);
                    } else {
                        ui.appendLog("Variable resolution cancelled by user.");
                        return;
                    }
                } else {
                    showSelectionDialog(previews, collectionFile, environmentFile);
                }
            } catch (Exception e) {
                ui.showError("Variable analysis failed: " + e.getMessage());
            }
        });
    }
    
    private void handleVariableResolution(VariableResolutionDialog dialog, List<RequestPreview> previews, 
                                         File collectionFile, File environmentFile) {
        switch (dialog.getChoice()) {
            case UPLOAD_ENVIRONMENT:
                // Use the selected environment file
                File newEnvironmentFile = dialog.getSelectedEnvironmentFile();
                ui.appendLog("Environment file selected: " + newEnvironmentFile.getName());
                
                // Regenerate previews with new environment
                regeneratePreviewsWithEnvironment(collectionFile, newEnvironmentFile);
                break;
                
            case MANUAL_ENTRY:
                // Apply manual variables to resolver
                Map<String, String> manualVars = dialog.getManualVariables();
                for (Map.Entry<String, String> entry : manualVars.entrySet()) {
                    variableResolver.addCustomVariable(entry.getKey(), entry.getValue());
                }
                ui.appendLog("Applied " + manualVars.size() + " manual variables.");
                
                // Regenerate previews with new variables
                regeneratePreviewsWithCurrentResolver(collectionFile, environmentFile);
                break;
                
            case IGNORE_CONTINUE:
                ui.appendLog("Continuing with unresolved variables (requests may fail).");
                showSelectionDialog(previews, collectionFile, environmentFile);
                break;
                
            case SKIP_VARIABLE_REQUESTS:
                // Filter out requests with unresolved variables
                List<RequestPreview> filteredPreviews = previews.stream()
                    .filter(p -> !p.hasUnresolvedVariables())
                    .collect(java.util.stream.Collectors.toList());
                
                ui.appendLog("Filtered to " + filteredPreviews.size() + " requests without variables.");
                showSelectionDialog(filteredPreviews, collectionFile, environmentFile);
                break;
        }
    }
    
    private void regeneratePreviewsWithEnvironment(File collectionFile, File environmentFile) {
        // Restart the preview process with the new environment file
        showPreview(collectionFile, environmentFile);
    }
    
    private void regeneratePreviewsWithCurrentResolver(File collectionFile, File environmentFile) {
        // Regenerate previews with current resolver state
        showPreview(collectionFile, environmentFile);
    }
    
    private List<RequestPreview> generatePreviews(PostmanCollection collection, VariableResolver resolver, 
                                                 VariableDetector detector, VariableAnalysis analysis) {
        List<RequestPreview> previews = new ArrayList<>();
        generatePreviewsRecursive(collection.item, "", previews, resolver, detector, collection.auth);
        return previews;
    }
    private void normalizeJwtToVariable(PostmanCollection collection) {
        String rootName = (collection.info != null && collection.info.name != null)
            ? collection.info.name : "collection";
        walkAndNormalize(collection.item, collection.auth, rootName);
    }
    private boolean hasBearerValue(PostmanCollection.Auth auth) {

        if (auth == null || !"bearer".equalsIgnoreCase(auth.type)){
            return false;
        }
        if (!(auth.bearer instanceof List)){
            return true;
        }
    
        List<?> list = (List<?>) auth.bearer;
    
        for (Object o : list) {
    
            if (o instanceof PostmanCollection.AuthAttribute) {
                return true;
    
            }
        }
    
        return true;
    }
    
    private void walkAndNormalize(
            List<PostmanCollection.Item> items,
            PostmanCollection.Auth inheritedAuth,
            String folderContext) {

        if (items == null) return;

        for (PostmanCollection.Item item : items) {

            PostmanCollection.Auth currentAuth =
                    (item.request != null && item.request.auth != null)
                    ? item.request.auth
                    : (item.auth !=null
                        ? item.auth
                        : inheritedAuth);

            // Track per-folder context for token naming.
            String childFolderContext = folderContext;
            if (item.request == null && item.name != null && !item.name.trim().isEmpty()) {
                childFolderContext = (folderContext == null || folderContext.isEmpty())
                    ? item.name
                    : folderContext + "_" + item.name;
            }

            // ✅ =========================
            // ✅ HEADER CHECK
            // ✅ =========================
            if (item.request != null && item.request.header != null) {

                for (PostmanCollection.Header h : item.request.header) {

                    if (h != null &&
                        !h.disabled &&
                        "Authorization".equalsIgnoreCase(h.key) &&
                        h.value != null &&
                        h.value.toLowerCase(java.util.Locale.ROOT).startsWith("bearer")) {

                        String token = h.value.replaceFirst("(?i)bearer", "").trim();

                        // ✅ 1. NULL OR EMPTY
                        if (token.equalsIgnoreCase("null") || token.isEmpty()) {
                            continue;
                        }

                        // ✅ 2. JWT OR LONG TOKEN (FIX ✅)
                        if (!token.contains("{{")) {

                            // ✅ expiry only if real JWT
                            if (token.split("\\.").length == 3 && isJwtExpired(token)) {
                                ui.appendLog("⚠️ Warning: Detected expired JWT");
                            }

                            String varName = registerUniqueToken(token, folderContext);
                            h.value = "Bearer {{" + varName + "}}";
                        }
                    }
                }
            }

            // ✅ =========================
            // ✅ AUTH OBJECT CHECK
            // ✅ =========================
            if (currentAuth != null &&
                "bearer".equalsIgnoreCase(currentAuth.type) &&
                currentAuth.bearer != null) {

                try {
                    if (currentAuth.bearer instanceof List) {

                        List<?> list = (List<?>) currentAuth.bearer;

                        for (Object o : list) {

                            if (o instanceof PostmanCollection.AuthAttribute) {

                                PostmanCollection.AuthAttribute v =
                                        (PostmanCollection.AuthAttribute) o;

                                if (v != null &&
                                    v.value != null &&
                                    !v.value.contains("{{")) {

                                    String token = v.value.trim();

                                    // ✅ 1. NULL / EMPTY
                                    if (token.equalsIgnoreCase("null") || token.isEmpty()) {
                                        continue;
                                    }

                                    // ✅ 2. JWT OR LONG TOKEN (FIX ✅)
                                    if (!token.contains("{{")) {

                                        if (token.split("\\.").length == 3 && isJwtExpired(token)) {
                                            ui.appendLog("⚠️ Warning: Detected expired JWT");
                                        }
                                        // For folder-level auth, use child context (= folder's path)
                                        String ctx = (item.request == null) ? childFolderContext : folderContext;
                                        String varName = registerUniqueToken(token, ctx);
                                        v.value = "{{" + varName + "}}";
                                    }
                                }
                            }
                        }
                    }

                } catch (Exception ignored) {}
            }

            // ✅ ✅ RECURSION
            walkAndNormalize(item.item, currentAuth, childFolderContext);
        }
    }
    private boolean isJwtExpired(String jwt) {
        try {
            String payload = jwt.split("\\.")[1];
            String decoded = new String(java.util.Base64.getDecoder().decode(payload));
    
            com.google.gson.JsonObject obj =
                new com.google.gson.Gson().fromJson(decoded, com.google.gson.JsonObject.class);
    
            long exp = obj.get("exp").getAsLong();
            long now = System.currentTimeMillis() / 1000;
    
            return now >= exp;
        } catch (Exception e) {
            return false;
        }
    }
    private void registerAllTokens(PostmanCollection collection) {
        String rootName = (collection.info != null && collection.info.name != null)
            ? collection.info.name : "collection";
        collectTokensRecursive(collection.item, collection.auth, rootName);
    }

    /** Seed folder-auth registry from the FULL workspace (preserves tree-path
     *  keys like "WrapperName/UAT") so it doesn't get clobbered when analyze
     *  runs against a scoped subtree. */
    private void seedFolderAuthFullWorkspace() {
        try {
            if (currentCollection == null) return;
            seedFolderAuthFromCollection(currentCollection,
                    currentCollection.info != null ? currentCollection.info.name : "collection");
        } catch (Exception ignore) {}
    }

    /** Populate FolderAuthRegistry from collection/folder-level auth in the imported JSON. */
    private void seedFolderAuthFromCollection(PostmanCollection collection, String rootName) {
        try {
            // Clear previous registry so per-import state doesn't leak between loads.
            folderAuthRegistry.clear();
            // The tree's root node has parent==null, so its name is NOT included in
            // CollectionTreePanel.nodePathKey(). Top-level child paths are just "ChildName".
            // Therefore we register the collection-level auth under "" (and rootName for
            // backwards compatibility with single-collection imports where users right-click
            // the visible root).
            burp.auth.FolderAuthOverride rootOv = toOverride(collection.auth);
            if (rootOv != null) {
                folderAuthRegistry.set("", rootOv);
                if (rootName != null) folderAuthRegistry.set(rootName, rootOv);
            }
            // Recurse with empty parent path so nested folders match nodePathKey output.
            seedFolderAuthRecursive(collection.item, "");
        } catch (Exception e) {
            api.logging().logToOutput("seedFolderAuthFromCollection error: " + e.getMessage());
        }
    }

    private void seedFolderAuthRecursive(List<PostmanCollection.Item> items, String parentPath) {
        if (items == null) return;
        for (PostmanCollection.Item item : items) {
            if (item.request != null) continue; // only folders
            String name = (item.name == null || item.name.trim().isEmpty()) ? "folder" : item.name;
            String path = parentPath.isEmpty() ? name : parentPath + "/" + name;
            burp.auth.FolderAuthOverride ov = toOverride(item.auth);
            if (ov != null) {
                folderAuthRegistry.set(path, ov);
            }
            seedFolderAuthRecursive(item.item, path);
        }
    }

    /** Map a Postman Auth block to our FolderAuthOverride model. Returns null for unset/noauth. */
    private burp.auth.FolderAuthOverride toOverride(PostmanCollection.Auth auth) {
        if (auth == null || auth.type == null) return null;
        String t = auth.type.toLowerCase();
        if ("noauth".equals(t)) {
            burp.auth.FolderAuthOverride ov = new burp.auth.FolderAuthOverride();
            ov.type = burp.auth.FolderAuthOverride.Type.NO_AUTH;
            return ov;
        }
        if ("bearer".equals(t) || "oauth2".equals(t) || "jwt".equals(t)) {
            String token = extractBearer(auth);
            // For oauth2, extractBearer returns null because the type is not "bearer".
            // Use {{token}} as a placeholder so FolderAuthRegistry.resolve returns a
            // non-null override; the resolver will substitute the active access token
            // at request-build time.
            if (token == null) {
                if ("oauth2".equals(t)) {
                    token = "{{token}}";
                } else {
                    return null;
                }
            }
            burp.auth.FolderAuthOverride ov = new burp.auth.FolderAuthOverride();
            ov.type = "jwt".equals(t)
                ? burp.auth.FolderAuthOverride.Type.JWT_BEARER
                : ("oauth2".equals(t)
                    ? burp.auth.FolderAuthOverride.Type.OAUTH2
                    : burp.auth.FolderAuthOverride.Type.BEARER);
            ov.put("token", token);
            return ov;
        }
        if ("basic".equals(t)) {
            String u = extractAuthAttr(auth.basic, "username");
            String p = extractAuthAttr(auth.basic, "password");
            if (u == null && p == null) return null;
            burp.auth.FolderAuthOverride ov = new burp.auth.FolderAuthOverride();
            ov.type = burp.auth.FolderAuthOverride.Type.BASIC;
            if (u != null) ov.put("username", u);
            if (p != null) ov.put("password", p);
            return ov;
        }
        if ("apikey".equals(t)) {
            String k = extractAuthAttr(auth.apikey, "key");
            String v = extractAuthAttr(auth.apikey, "value");
            String in = extractAuthAttr(auth.apikey, "in");
            burp.auth.FolderAuthOverride ov = new burp.auth.FolderAuthOverride();
            ov.type = burp.auth.FolderAuthOverride.Type.APIKEY;
            if (k != null) ov.put("key", k);
            if (v != null) ov.put("value", v);
            ov.put("addTo", "query".equalsIgnoreCase(in) ? "query" : "header");
            return ov;
        }
        return null;
    }

    /** Extract a named attribute value from a Postman auth block (List or Map style). */
    @SuppressWarnings("unchecked")
    private String extractAuthAttr(Object block, String name) {
        if (block == null || name == null) return null;
        try {
            if (block instanceof List) {
                for (Object o : (List<Object>) block) {
                    if (o instanceof java.util.Map) {
                        java.util.Map<String, Object> m = (java.util.Map<String, Object>) o;
                        Object k = m.get("key");
                        if (k != null && name.equalsIgnoreCase(String.valueOf(k))) {
                            Object v = m.get("value");
                            return v == null ? null : String.valueOf(v);
                        }
                    }
                }
            } else if (block instanceof java.util.Map) {
                Object v = ((java.util.Map<String, Object>) block).get(name);
                return v == null ? null : String.valueOf(v);
            }
        } catch (Exception ignore) { }
        return null;
    }
    
    private void collectTokensRecursive(
        List<PostmanCollection.Item> items,
        PostmanCollection.Auth inheritedAuth,
        String folderContext
    ) {
        if (items == null) return;
    
        for (PostmanCollection.Item item : items) {
    
            PostmanCollection.Auth currentAuth =
                (item.request != null && item.request.auth != null)
                    ? item.request.auth
                    : (item.auth != null ? item.auth : inheritedAuth);
    
            String requestName = item.name;
            
            // If this item is a folder (no request), append its name to the folder context.
            // This way nested folders produce names like token_<collection>_<subfolder>.
            String childFolderContext = folderContext;
            if (item.request == null && item.name != null && !item.name.trim().isEmpty()) {
                childFolderContext = (folderContext == null || folderContext.isEmpty())
                    ? item.name
                    : folderContext + "_" + item.name;
            }
    
            // ✅ 1. HEADER TOKENS
            if (item.request != null && item.request.header != null) {
                for (PostmanCollection.Header h : item.request.header) {
    
                    if (h == null || h.disabled || h.value == null) continue;
    
                    if ("authorization".equalsIgnoreCase(h.key)
                        && h.value.toLowerCase().startsWith("bearer")) {
    
                        String token = h.value.replaceFirst("(?i)bearer", "").trim();
    
                        processTokenForRegistration(token, requestName, folderContext);
                    }
                }
            }
    
            // ✅ 2. AUTH OBJECT (REQUEST / FOLDER / COLLECTION INHERITED)
            String token = extractBearer(currentAuth);
    
            if (token != null && !token.trim().isEmpty()) {
                // For folder-level auth, use the child context (= folder's own path);
                // for request-level auth, use the parent path.
                String ctx = (item.request == null) ? childFolderContext : folderContext;
                processTokenForRegistration(token, requestName, ctx);
            }
    
            // ✅ recurse with the (possibly updated) folder context
            collectTokensRecursive(item.item, currentAuth, childFolderContext);
        }
    }
    private void processTokenForRegistration(String token, String requestName, String folderContext) {

        if (token == null || token.trim().isEmpty()) return;
    
        // ✅ CASE 1: already variable → DO NOT TOUCH
        if (token.contains("{{")) {
    
            String varName = token.replace("{{", "").replace("}}", "").trim();
    

            return;
        }
    
        // ✅ CASE 2: raw token → register
        registerUniqueToken(token, folderContext);
    }
    
    private static String sanitizeForVarName(String s) {
        if (s == null) return "";
        // Lowercase, strip non-alphanumeric (keep underscore), collapse multiple underscores
        String cleaned = s.toLowerCase().replaceAll("[^a-z0-9]+", "_");
        // Trim leading/trailing underscores
        cleaned = cleaned.replaceAll("^_+|_+$", "");
        return cleaned;
    }
    
    private String registerUniqueToken(String token) {
        return registerUniqueToken(token, null);
    }
    
    private String registerUniqueToken(String token, String folderContext) {

        Map<String, String> vars = variableResolver.getVariables();
    
        // ✅ already variable
        if (token.contains("{{")) {
            return token.replace("{{", "").replace("}}", "").trim();
        }
    
        // ✅ ✅ IMPORTANT: check existing mapping FIRST
        if (tokenValueToVar.containsKey(token)) {
            return tokenValueToVar.get(token);
        }
    
        // ✅ check resolver values
        for (Map.Entry<String, String> e : vars.entrySet()) {
            if (token.equals(e.getValue())) {
                tokenValueToVar.put(token, e.getKey()); // ✅ store mapping
                return e.getKey();
            }
        }
    
        // Build a descriptive var name based on the folder/collection it came from.
        String suffix = sanitizeForVarName(folderContext);
        String name = suffix.isEmpty() ? "token" : "token_" + suffix;

        if (vars.containsKey(name)) {
            int i = 1;

            do {
                name = (suffix.isEmpty() ? "token" : "token_" + suffix) + i;
                i++;
            } while (vars.containsKey(name));
        }
            
        variableResolver.addCustomVariable(name, token);
    
        // ✅ ✅ STORE MAPPING HERE
        tokenValueToVar.put(token, name);
    
        ui.appendLog("🔐 Registered token → {{" + name + "}}");
    
        return name;
    }
    private void generatePreviewsRecursive(List<PostmanCollection.Item> items, String path, 
                                         List<RequestPreview> previews, VariableResolver resolver, 
                                         VariableDetector detector, PostmanCollection.Auth inheritedAuth
                                        ) {
        // Add null check to prevent NullPointerException
        if (items == null) {
            return;
        }
        
        for (PostmanCollection.Item item : items) {
            PostmanCollection.Auth currentAuth =
            (item.request != null && item.request.auth != null)
                    ? item.request.auth
                    : (item.auth != null
                            ? item.auth
                            : inheritedAuth);
            String currentPath = path.isEmpty() ? item.name : path + "/" + item.name;
            
            if (item.request != null) {
                AuthSource source = resolveAuthSource(item, currentAuth, item.request);
                RequestPreview preview = createRequestPreview(item, currentPath, resolver, detector, currentAuth, source);
                previews.add(preview);
            }
            
            if (item.item != null && !item.item.isEmpty()) {
                generatePreviewsRecursive(item.item, currentPath, previews, resolver, detector, currentAuth);
            }
        }
    }
    public void addCustomVariables(java.util.Map<String, String> variables) {
        if (variables == null || variables.isEmpty()) {
            ui.appendLog("No manual variables provided.");
            return;
        }

        ui.appendLog("DEBUG addCustomVariables received size = " + variables.size());
        ui.appendLog("DEBUG addCustomVariables received map = " + variables);

        int addedCount = 0;

        for (java.util.Map.Entry<String, String> entry : variables.entrySet()) {
            if (entry == null || entry.getKey() == null) {
                continue;
            }

            String key = entry.getKey().trim();
            String value = entry.getValue() != null ? entry.getValue() : "";

            if (key.isEmpty()) {
                continue;
            }

            variableResolver.addCustomVariable(key, value);
            addedCount++;

            String logLine = "Manual variable added/updated: " + key + " = " + value;

            if (debugMode) {
                api.logging().logToOutput(logLine);
            }

            ui.appendLog(logLine);
        }

        ui.appendLog("Applied " + addedCount + " manual variable(s). Manual variables override environment/collection values.");
        ui.appendLog("Current variables snapshot: " + variableResolver.getVariables());
    }
    
    public java.util.Map<String, String> importEnvironmentFile(File envFile) throws Exception {
        if (envFile == null) {
            ui.appendLog("No environment file provided.");
            return java.util.Collections.emptyMap();
        }

        PostmanEnvironment env = parser.parseEnvironment(envFile);
        if (env == null || env.values == null || env.values.isEmpty()) {
            ui.appendLog("No variables found in environment file: " + envFile.getName());
            return java.util.Collections.emptyMap();
        }

        int added = 0;
        java.util.Map<String, String> addedVars = new java.util.LinkedHashMap<>();
        for (PostmanEnvironment.Value v : env.values) {
            if (v == null || v.key == null) continue;
            if (!v.enabled) continue;
            String key = v.key.trim();
            String val = v.value != null ? v.value : "";
            if (key.isEmpty()) continue;
            variableResolver.addCustomVariable(key, val);
            addedVars.put(key, val);
            added++;
        }

        ui.appendLog("Imported " + added + " environment variable(s) from " + envFile.getName());
        return addedVars;
    }

     public boolean saveEnvironmentFile(File envFile, java.util.Map<String, String> vars) throws Exception {
        if (vars == null) {
            ui.appendLog("No variables to save.");
            return false;
        }

        if (envFile == null) {
            throw new IllegalArgumentException("envFile cannot be null");
        }

        burp.models.PostmanEnvironment env = new burp.models.PostmanEnvironment();
        env.id = java.util.UUID.randomUUID().toString();
        String name = envFile.getName();
        if (name.toLowerCase().endsWith(".json")) {
            name = name.substring(0, name.length() - 5);
        }
        env.name = name;
        env.values = new java.util.ArrayList<>();

        for (java.util.Map.Entry<String, String> e : vars.entrySet()) {
            if (e.getKey() == null) continue;
            burp.models.PostmanEnvironment.Value v = new burp.models.PostmanEnvironment.Value();
            v.key = e.getKey();
            v.value = e.getValue() != null ? e.getValue() : "";
            v.enabled = true;
            v.type = "text";
            env.values.add(v);
        }

        com.google.gson.Gson gson = new com.google.gson.GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(env);
        java.nio.file.Files.write(envFile.toPath(), json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        ui.appendLog("Saved environment file: " + envFile.getAbsolutePath());
        return true;
    }
    
    public java.util.Map<String, String> getCurrentVariablesSnapshot() {
        return variableResolver.getVariables();
    }
    private boolean hasAuthorizationHeader(PostmanCollection.Request request) {
        if (request == null || request.header == null) {
            return false;
        }
    
        for (PostmanCollection.Header header : request.header) {
            if (header == null || header.disabled) {
                continue;
            }
    
            if (header.key != null &&
                "Authorization".equalsIgnoreCase(header.key.trim())) {
                return true;
            }
        }
    
        return false;
    }
    
    private void addAuthorizationHeaderIfMissing(PostmanCollection.Request request) {
        if (request == null || hasAuthorizationHeader(request)) {
            return;
        }
    
        if (request.header == null) {
            request.header = new ArrayList<>();
        }
    
        PostmanCollection.Header authHeader = new PostmanCollection.Header();
        authHeader.key = "Authorization";
        authHeader.value = "Bearer {{token}}";
        authHeader.type = "text";
        authHeader.disabled = false;
    
        request.header.add(authHeader);
    }
    
    private Map<String, String> promptForAuthorizationToken() {
        Set<String> variables = new HashSet<>();
        variables.add("token");
    
        ManualVariableEntryDialog dialog = new ManualVariableEntryDialog(
            ui.getPanel(),
            variables,
            variableDetector,
            this
        );
    
        if (dialog.showDialog()) {
            return dialog.getVariables();
        }
    
        return Collections.emptyMap();
    }

    private RequestPreview createRequestPreview(PostmanCollection.Item item, String path, 
                                              VariableResolver resolver, VariableDetector detector, PostmanCollection.Auth inheritedAuth, AuthSource authSource) {
        PostmanCollection.Request request = item.request;
        
        // Resolve URL for preview
        String url = "Unknown URL";
        String rawUrl = null;
        try {
            rawUrl = extractRawUrl(request.url);
            if (rawUrl != null) {
                url = resolver.resolve(rawUrl);
            }
        } catch (Exception e) {
            url = "Error resolving URL: " + e.getMessage();
        }
        
        // Check for various features
        //boolean hasAuth = request.auth != null && "bearer".equalsIgnoreCase(request.auth.type) && request.auth.bearer != null;
        boolean hasAuth = authSource != AuthSource.NONE;

        String authDisplay;

        switch (authSource) {
            case REQUEST: authDisplay = "✔ (Request)"; break;
            case FOLDER: authDisplay = "✔ (Folder)"; break;
            case COLLECTION: authDisplay = "✔ (Collection)"; break;
            case HEADER: authDisplay = "✔ (Header)"; break;
            default: authDisplay = "❌"; break;
        }

        // ✅ ADD THIS BLOCK (OAuth Body Detection)
        if (hasOAuthBodyCredentials(request)) {

            hasAuth = true;  // ✅ treat as auth-enabled

            authDisplay = "🧾 OAuth Body";  // ✅ UI indicator (your key improvement)
        }

// ✅ Resolve inherited auth (same logic as normalization)
        boolean hasHeaders = request.header != null && !request.header.isEmpty();
        boolean hasBody = hasRequestBody(request);
        boolean hasAuthorizationHeader = hasAuthorizationHeader(request);
        boolean missingAuthorizationHeader = !hasAuthorizationHeader;
        String method = request.method != null ? request.method : "GET";
        String description = request.description != null ? request.description : "";

        // Detect unresolved variables in this specific request
        Set<String> requestVariables = detector.findVariablesInRequest(request);
        Set<String> unresolvedVariables = new HashSet<>();
        
       for (String variable : requestVariables) {

           // Skip Postman dynamic variables (built-in, always resolved)
           if (isPostmanDynamicVariable(variable)) {
               continue;
           }

           String testValue = "{{" + variable + "}}";
           String resolved = resolver.resolve(testValue);

           // ✅ Only variables missing from resolver are unresolved.
           // ✅ Variables that exist in resolver are still editable, but not "broken".
           boolean existsInResolver = resolver.getVariables().containsKey(variable);
           boolean isUnresolved = !existsInResolver;

           if (isUnresolved) {
               unresolvedVariables.add(variable);
           }
       }
        
        // Enhanced GraphQL detection and naming
        String displayName = item.name;
        if (isGraphQLRequest(request)) {
            String operation = extractGraphQLOperation(request.body.raw);
            if (operation != null) {
                displayName = item.name + " [GraphQL: " + operation + "]";
            } else {
                displayName = item.name + " [GraphQL]";
            }
        }
        
        return new RequestPreview(
            displayName,
            path,
            method,
            url,
            description,
            hasAuth,
            hasHeaders,
            hasBody,
            unresolvedVariables,
            requestVariables,
            missingAuthorizationHeader,
            authDisplay,
            request   // ✅ ✅ ✅ THIS FIXES EVERYTHING
        );

        //return new RequestPreview(displayName, path, method, url, description, hasAuth, hasHeaders, hasBody, unresolvedVariables);
    }
    
    private void showSelectionDialog(List<RequestPreview> previews, File collectionFile, File environmentFile) {
        SwingUtilities.invokeLater(() -> {
            RequestSelectionDialog dialog = new RequestSelectionDialog(previews, this, ui.getPanel());
            
            if (dialog.showDialog()) {
                List<RequestPreview> selectedPreviews = dialog.getSelectedRequests();
                if (!selectedPreviews.isEmpty()) {
                    ui.appendLog("Starting import of " + selectedPreviews.size() + " selected requests...");
                    String destination = ui.getSelectedDestination();
                    importSelectedRequests(collectionFile, environmentFile, selectedPreviews, destination);
                } else {
                    ui.appendLog("No requests selected for import.");
                }
            } else {
                ui.appendLog("Import cancelled by user.");
            }
        });
    }
    
    public void importSelectedRequests(File collectionFile, File environmentFile, List<RequestPreview> selectedPreviews) {
        importSelectedRequests(collectionFile, environmentFile, selectedPreviews, "repeater");
    }
    
    public void importSelectedRequests(File collectionFile, File environmentFile, List<RequestPreview> selectedPreviews, String destination) {
        boolean needsToken = selectedPreviews != null &&
        selectedPreviews.stream()
            .anyMatch(RequestPreview::shouldAddAuthorizationHeader);
    
    if (needsToken) {
        String existingToken = variableResolver.getVariables().get("token");
    
        if (existingToken == null || existingToken.trim().isEmpty()) {
            Map<String, String> tokenVariable = promptForAuthorizationToken();
    
            if (tokenVariable == null ||
                tokenVariable.isEmpty() ||
                !tokenVariable.containsKey("token")) {
    
                ui.appendLog("Authorization token was not provided. Import cancelled.");
                ui.setImportComplete();
                return;
            }
    
            addCustomVariables(tokenVariable);
        }
    }
        Set<String> selectedPaths = new HashSet<>();
        Set<String> addAuthPaths = new HashSet<>();
        
        for (RequestPreview preview : selectedPreviews) {
            selectedPaths.add(preview.getPath());
        
            if (preview.shouldAddAuthorizationHeader()) {
                addAuthPaths.add(preview.getPath());
            }
        }
        
        SwingWorker<ImportResult, String> worker = new SwingWorker<ImportResult, String>() {
            @Override
            protected ImportResult doInBackground() throws Exception {
                ImportResult result = new ImportResult();
                
                try {
                    // Parse collection
                    publish("Using current analyzed collection...");

                    PostmanCollection collection = currentCollection;

                    if (collection == null) {
                        collection = parser.parseCollection(collectionFile);
                        currentCollection = collection;
                    }

                    result.collectionName = collection.info != null
                            ? collection.info.name
                            : "Imported Collection";
                    // Parse environment if provided
                    if (environmentFile != null) {
                        publish("Parsing environment file...");
                        PostmanEnvironment environment = parser.parseEnvironment(environmentFile);
                        variableResolver.addEnvironmentVariables(environment);
                    }
                    
                    
                    // Flatten all requests
                    java.util.List<RequestItem> requests = flattenRequests(collection.item, "", collection.info != null ? collection.info.name : null);
                    
                    // Filter to only selected requests
                    List<RequestItem> selectedRequests = new ArrayList<>();
                    for (RequestItem item : requests) {
                        if (selectedPaths.contains(item.path)) {
                    
                            if (addAuthPaths.contains(item.path)) {
                                addAuthorizationHeaderIfMissing(item.request);
                            }
                    
                            selectedRequests.add(item);
                        }
                    }
                    result.totalRequests = selectedRequests.size();
                    publish("Processing " + selectedRequests.size() + " selected requests...");
                    
                    // Process each selected request
                    for (int i = 0; i < selectedRequests.size(); i++) {
                        if (isCancelled()) break;
                        
                        RequestItem item = selectedRequests.get(i);
                        try {
                            processRequest(item, destination);
                            result.successCount++;
                            publish("✓ Imported: " + item.name);
                        } catch (Exception e) {
                            result.failedRequestDetails.add(new ImportResult.FailedRequestInfo(
                                item.name, item.path, e.getMessage(), item));
                            result.failedRequests.add(item.name + ": " + e.getMessage());
                            publish("✗ Failed: " + item.name + " - " + e.getMessage());
                        }
                        
                        setProgress((i + 1) * 100 / selectedRequests.size());
                    }
                    
                } catch (Exception e) {
                    result.error = e.getMessage();
                    publish("Fatal error: " + e.getMessage());
                }
                
                return result;
            }
            
            @Override
            protected void process(List<String> chunks) {
                for (String message : chunks) {
                    ui.appendLog(message);
                }
            }
            
            @Override
            protected void done() {
                try {
                    ImportResult result = get();
                    lastImportResult = result; // Store for retry functionality
                    ui.showImportSummary(result);
                } catch (Exception e) {
                    ui.showError("Import failed: " + e.getMessage());
                }
                ui.setImportComplete();
            }
        };
        
        worker.addPropertyChangeListener(evt -> {
            if ("progress".equals(evt.getPropertyName())) {
                ui.updateProgress((Integer) evt.getNewValue());
            }
        });
        
        ui.setImportInProgress();
        worker.execute();
    }
    
    public void importCollection(File collectionFile, File environmentFile) {
        importCollection(collectionFile, environmentFile, "repeater");
    }
    
    public void importCollection(File collectionFile, File environmentFile, String destination) {
        // Reset variable resolution flag for new import
        variablesAlreadyResolved = false;
        
        if (debugMode) {
            api.logging().logToOutput("DEBUG PostmanImporter: Starting importCollection with destination=" + destination);
            api.logging().logToOutput("DEBUG PostmanImporter: collectionFile=" + collectionFile);
            api.logging().logToOutput("DEBUG PostmanImporter: environmentFile=" + environmentFile);
        }
        
        // First check for variables, similar to showPreview
        SwingWorker<List<RequestPreview>, String> worker = new SwingWorker<List<RequestPreview>, String>() {
            @Override
            protected List<RequestPreview> doInBackground() throws Exception {
                if (debugMode) {
                    api.logging().logToOutput("DEBUG PostmanImporter: SwingWorker started - analyzing collection");
                }
                
                publish("Analyzing collection...");
                
                // Parse collection
                PostmanCollection collection = currentCollection;
                if (collection == null) {
                    collection = parser.parseCollection(collectionFile);
                    currentCollection = collection;
                }

                // Parse environment if provided
                VariableResolver tempResolver = variableResolver;
                if (environmentFile != null) {
                    publish("Loading environment variables...");
                    PostmanEnvironment environment = parser.parseEnvironment(environmentFile);
                    tempResolver.addEnvironmentVariables(environment);
                }
                
                // Add collection variables
                addCollectionVariablesPreservingCurrent(collection);
                for (Map.Entry<String, String> entry : variableResolver.getVariables().entrySet()) {
                    tempResolver.addCustomVariable(entry.getKey(), entry.getValue());
                }
                detectAndOfferOAuth2(collection, tempResolver);
                                
                // ✅ Auto-convert hosts silently (no dialog)
                promptAndConvertHosts(collection, tempResolver, false);
                
                List<JwtEndpointCandidate> jwtCandidates = detectTokenSourceCandidates(collection, tempResolver);
                List<String> staticTokens = staticDetector.detect(collection, tempResolver);
                
                ui.updateAuthDetectionFull(
                        authManager.getOAuth2Configs(),
                        jwtCandidates,
                        staticTokens
                );
                
                // Analyze variables
                publish("Analyzing variables...");
                VariableDetector tempDetector = new VariableDetector(tempResolver, api);
                VariableAnalysis variableAnalysis = tempDetector.analyzeCollection(collection);
                
                // Generate previews with variable information
                publish("Generating request previews...");
                return generatePreviews(collection, tempResolver, tempDetector, variableAnalysis);
            }
            
            @Override
            protected void process(List<String> chunks) {
                for (String message : chunks) {
                    ui.appendLog(message);
                }
            }
            
            @Override
            protected void done() {
                try {
                    List<RequestPreview> previews = get();

                    // ✅ Cache preview results so Analyze/Edit Variables can reuse the same source of truth.
                    lastGeneratedPreviews = previews != null ? previews : new ArrayList<>();
                    
                    ui.appendLog("Preview generated successfully. Found " + previews.size() + " requests.");
                    // ✅ ✅ ✅ BUILD TREE HERE ALSO
                    List<AnalyzedRequest> analyzed = new ArrayList<>();

                    for (RequestPreview p : lastGeneratedPreviews) {
                        if (p != null && p.getRequest() != null) {
                        analyzed.add(new AnalyzedRequest(
                        p.getName(),
                        p.getPath(),
                        p.getRequest(),
                        currentCollection != null && currentCollection.info != null
                            ? currentCollection.info.name
                            : "Collection",
                        p.getUrl()  // ✅ REQUIRED
                    ));
                        }
                    }

                    CollectionTreeNode root = buildCollectionTree(analyzed);

                    if (root != null && ui.getTreePanel() != null) {
                        ui.getTreePanel().loadCollection(root);
                    } else {
                        ui.appendLog("⚠ Tree not built: collection is empty or null");
                    }

                    // ✅ ✅ ✅ END
                    
                    // Check if we need to show variable resolution dialog first
                    checkAndHandleVariables(previews, collectionFile, environmentFile);
                } catch (Exception e) {
                    ui.showError("Import failed: " + e.getMessage());
                    ui.appendLog("Import error: " + e.getMessage());
                    ui.setImportComplete();
                }
            }
        };
        
        ui.setImportInProgress();
        worker.execute();
    }
    
    private void flattenToAnalyzedRequests(List<PostmanCollection.Item> items, String path,
                                           List<AnalyzedRequest> analyzed, String collectionName) {
        if (items == null) return;
        
        for (PostmanCollection.Item item : items) {
            String itemName = item.name != null ? item.name : "Unnamed";
            String currentPath = path.isEmpty() ? itemName : path + "/" + itemName;
            
            if (item.request != null) {
                analyzed.add(new AnalyzedRequest(
                    itemName,
                    currentPath,
                    item.request,
                    collectionName,
                    extractRawUrl(item.request.url)
                ));
            }
            
            if (item.item != null && !item.item.isEmpty()) {
                flattenToAnalyzedRequests(item.item, currentPath, analyzed, collectionName);
            }
        }
    }
    
    private java.util.List<RequestItem> flattenRequests(java.util.List<PostmanCollection.Item> items, String path, String collectionName) {
        java.util.List<RequestItem> requests = new java.util.ArrayList<>();
        if (items == null) {
            return requests;
        }
    
        for (PostmanCollection.Item item : items) {
            String itemName = item.name != null ? item.name : "Unnamed Request";
            String currentPath = path.isEmpty() ? itemName : path + "/" + itemName;
    
            if (item.request != null) {
                requests.add(new RequestItem(itemName, currentPath, item.request, collectionName));
            }
    
            if (item.item != null && !item.item.isEmpty()) {
                requests.addAll(flattenRequests(item.item, currentPath, collectionName));
            }
        }
        return requests;
    }
    private AuthSource resolveAuthSource(
            PostmanCollection.Item item,
            PostmanCollection.Auth effectiveAuth,
            PostmanCollection.Request request) {

        // ✅ 1. HEADER (highest visibility in actual request)
        if (request != null && request.header != null) {
            for (PostmanCollection.Header h : request.header) {
                if (h != null &&
                    !h.disabled &&
                    h.key != null &&
                    "authorization".equalsIgnoreCase(h.key) &&
                    h.value != null &&
                    h.value.toLowerCase().startsWith("bearer")) {

                    return AuthSource.HEADER;
                }
            }
        }

        // ✅ 2. REQUEST-level auth
        if (item.request != null && item.request.auth != null) {
            if (hasBearerValue(item.request.auth)) {
                return AuthSource.REQUEST;
            }
        }

        // ✅ 3. FOLDER-level auth
        if (item.auth != null) {
            if (hasBearerValue(item.auth)) {
                return AuthSource.FOLDER;
            }
        }

        // ✅ 4. COLLECTION-level auth
        if (effectiveAuth != null  && "bearer".equalsIgnoreCase(effectiveAuth.type)) {
            if (hasBearerValue(effectiveAuth)) {
                return AuthSource.COLLECTION;
            }
        }

        return AuthSource.NONE;
    }
    private String buildRepeaterTabName(RequestItem item) {
        String method = "GET";
        if (item.request != null && item.request.method != null && !item.request.method.trim().isEmpty()) {
            method = item.request.method.trim().toUpperCase();
        }
    
        java.util.List<String> pathParts = splitPathParts(item.path);
    
        String requestName = item.name != null && !item.name.trim().isEmpty()
                ? item.name.trim()
                : (!pathParts.isEmpty() ? pathParts.get(pathParts.size() - 1) : "Imported Request");
    
        if (!pathParts.isEmpty() && pathParts.get(pathParts.size() - 1).equalsIgnoreCase(requestName)) {
            pathParts.remove(pathParts.size() - 1);
        }
    
        String folderName = chooseBestFolderForCompactTab(pathParts);
    
        java.util.List<String> parts = new java.util.ArrayList<>();
        parts.add(method);
    
        if (folderName != null && !folderName.trim().isEmpty()) {
            parts.add(folderName);
        }
    
        parts.add(requestName);
    
        java.util.List<String> cleanedParts = new java.util.ArrayList<>();
        String previous = null;
    
        for (String part : parts) {
            String cleaned = sanitizeTabNamePart(part);
            if (cleaned.isEmpty()) {
                continue;
            }
            if (previous != null && previous.equalsIgnoreCase(cleaned)) {
                continue;
            }
            cleanedParts.add(cleaned);
            previous = cleaned;
        }
    
        String tabName = String.join(" - ", cleanedParts);
    
        int maxLength = 55;
        if (tabName.length() > maxLength) {
            tabName = shortenTabName(method, folderName, requestName, maxLength);
        }
    
        return tabName.isEmpty() ? method + " - Imported Request" : tabName;
    }
    
    private java.util.List<String> splitPathParts(String path) {
        java.util.List<String> parts = new java.util.ArrayList<>();
        if (path == null || path.trim().isEmpty()) {
            return parts;
        }
    
        String[] rawParts = path.split("/");
        for (String rawPart : rawParts) {
            String cleaned = sanitizeTabNamePart(rawPart);
            if (!cleaned.isEmpty()) {
                parts.add(cleaned);
            }
        }
        return parts;
    }
    
    private String chooseBestFolderForCompactTab(java.util.List<String> pathParts) {
        if (pathParts == null || pathParts.isEmpty()) {
            return null;
        }
    
        // Direct parent folder is compact and usually most useful.
        return pathParts.get(pathParts.size() - 1);
    }
    
    private String shortenTabName(String method, String folderName, String requestName, int maxLength) {
        String folder = abbreviateKnownFolderName(sanitizeTabNamePart(folderName));
        String request = sanitizeTabNamePart(requestName);
    
        String candidate;
        if (folder != null && !folder.isEmpty()) {
            candidate = method + " - " + folder + " - " + request;
        } else {
            candidate = method + " - " + request;
        }
    
        if (candidate.length() <= maxLength) {
            return candidate;
        }
    
        int fixedLength = method.length() + 3;
        if (folder != null && !folder.isEmpty()) {
            fixedLength += folder.length() + 3;
        }
    
        int availableForRequest = Math.max(12, maxLength - fixedLength - 3);
        request = truncateMiddle(request, availableForRequest);
    
        if (folder != null && !folder.isEmpty()) {
            candidate = method + " - " + folder + " - " + request;
        } else {
            candidate = method + " - " + request;
        }
    
        if (candidate.length() > maxLength) {
            candidate = candidate.substring(0, maxLength - 3) + "...";
        }
    
        return candidate;
    }
    
    private String abbreviateKnownFolderName(String folderName) {
        if (folderName == null) {
            return "";
        }
    
        String folder = folderName.trim();
    
        if (folder.equalsIgnoreCase("Generate Tokens - Authorization")) {
            return "Tokens";
        }
    
        if (folder.length() > 18) {
            return truncateMiddle(folder, 18);
        }
    
        return folder;
    }
    private boolean isExplicitlyBlankAuth(PostmanCollection.Request request) {

        if (request == null || request.header == null) return false;
    
        for (PostmanCollection.Header h : request.header) {
    
            if (h == null || h.disabled) continue;
    
            if ("authorization".equalsIgnoreCase(h.key)) {
    
                if (h.value == null) return true;
    
                String v = h.value.replace("Bearer", "").trim();
    
                return v.isEmpty(); // ✅ THIS IS THE KEY
            }
        }
    
        return false;
    }
    private String truncateMiddle(String value, int maxLength) {
        if (value == null) {
            return "";
        }
    
        String text = value.trim();
        if (text.length() <= maxLength) {
            return text;
        }
    
        if (maxLength <= 6) {
            return text.substring(0, Math.max(0, maxLength - 3)) + "...";
        }
    
        int keepStart = (maxLength - 3) / 2;
        int keepEnd = maxLength - 3 - keepStart;
        return text.substring(0, keepStart) + "..." + text.substring(text.length() - keepEnd);
    }
    
    private String sanitizeTabNamePart(String input) {
        if (input == null) {
            return "";
        }
    
        String cleaned = input.trim();
        cleaned = cleaned.replaceAll("\\s+", " ");
        cleaned = cleaned.replace('\\', ' ');
        cleaned = cleaned.replace('/', ' ');
        cleaned = cleaned.replaceAll("[\\p{Cntrl}]", "");
        cleaned = cleaned.replaceAll("\\s*-\\s*-\\s*", " - ");
        return cleaned.trim();
    }
    private boolean isNoAuthRequest(PostmanCollection.Request request) {
        return request != null
                && request.auth != null
                && request.auth.type != null
                && "noauth".equalsIgnoreCase(request.auth.type);
    }
    /**
     * Fires every scripted request in the supplied list through the preview
     * pipeline (no site map, runs pre/post scripts). Shows a progress dialog
     * and supports Stop. Used by both "Analyze Collection" and the per-folder
     * "Analyze Folder" right-click action.
     */
    public void runAnalyzedBatch(java.util.List<AnalyzedRequest> analyzed, String label) {
        runAnalyzedBatch(analyzed, label, true);
    }

    /**
     * @param scriptedOnly when true, only fires requests that have pre/post scripts.
     *                    when false, fires every request (used by "Run (Preview)").
     */
    public void runAnalyzedBatch(java.util.List<AnalyzedRequest> analyzed, String label, boolean scriptedOnly) {
        if (analyzed == null || analyzed.isEmpty()) {
            ui.appendLog("ℹ️ " + label + ": nothing to run.");
            return;
        }
        if (currentCollection == null) {
            ui.appendLog("⚠ " + label + ": load a collection first.");
            return;
        }
        final java.util.List<AnalyzedRequest> toRun = new java.util.ArrayList<>();
        int skipped = 0;
        for (AnalyzedRequest ar : analyzed) {
            if (!scriptedOnly) { toRun.add(ar); continue; }
            String[] scripts = null;
            try { scripts = getScriptsForPath(ar.getPath()); } catch (Exception ignore) {}
            boolean hasPre = scripts != null && scripts.length > 0
                    && scripts[0] != null && !scripts[0].trim().isEmpty();
            boolean hasPost = scripts != null && scripts.length > 1
                    && scripts[1] != null && !scripts[1].trim().isEmpty();
            if (hasPre || hasPost) toRun.add(ar);
            else skipped++;
        }
        if (toRun.isEmpty()) {
            ui.appendLog("ℹ️ " + label + ": no scripted requests detected — nothing to fire.");
            try { refreshAuthDetectionFromCurrentCollection(); } catch (Exception ignore) {}
            return;
        }
        final int skippedFinal = skipped;
        String runId = "run-" + System.currentTimeMillis();
        final String runIdFinal = runId;
        // Surface the new run in the Run Results tab (Postman/Bruno-style)
        // and switch the right pane to it so the user immediately sees rows
        // stream in instead of having to click over from another tab.
        try {
            burp.ui.RunResultsPanel resultsPanel = ui.getRunResultsPanel();
            if (resultsPanel != null) resultsPanel.startRun(runId, toRun.size());
            ui.showRunResultsTab();
        } catch (Exception ignore) {}
        ui.appendLog("════════════════════════════════════════");
        ui.appendLog("▶️ " + label + " [" + runId + "]: firing "
            + toRun.size() + (scriptedOnly ? " scripted" : "") + " request(s)"
            + (scriptedOnly ? " (skipping " + skippedFinal + " unscripted, NOT added to site map)" : " (NOT added to site map)")
            + "…");
        // Diagnostic — list each request path so user can confirm scope.
        try {
            StringBuilder sb = new StringBuilder("    Scope:");
            int n = 0;
            for (AnalyzedRequest ar : toRun) {
                if (ar == null) continue;
                sb.append("\n      • ").append(ar.getPath() != null ? ar.getPath() : ar.getName());
                if (++n >= 30) { sb.append("\n      … (+").append(toRun.size() - n).append(" more)"); break; }
            }
            ui.appendLog(sb.toString());
        } catch (Exception ignore) {}
        ui.appendLog("ℹ️ Tip: close stale Repeater tabs before reading results.");
        try { ui.persistCurrentRequestEditsForRun(); } catch (Exception ignore) {}
        try { ui.clearRequestEditCache(); } catch (Exception ignore) {}
        try { ui.updateProgress(0); } catch (Exception ignore) {}

        java.awt.Window owner = null;
        try {
            owner = javax.swing.SwingUtilities.getWindowAncestor(ui.getPanel());
        } catch (Exception ignore) {}
        final burp.ui.AutoRunProgressDialog dlg =
            new burp.ui.AutoRunProgressDialog(owner, toRun.size());
        try { dlg.setTitle(label); } catch (Exception ignore) {}
        dlg.setOnCancel(() -> requestAnalyzeStop());
        if (owner != null) dlg.setLocationRelativeTo(owner);
        analyzeStopRequested = false;
        dlg.setVisible(true);

        final String labelF = label;
        Thread worker = new Thread(() -> {
            analyzeWorkerThread = Thread.currentThread();
            int sent = 0;
            int total = toRun.size();

            // Token-reuse cache: temporarily flip any "forceNewToken*" flags
            // to "false" so the FIRST request's pre-script fetches tokens, and
            // subsequent requests reuse them from the resolver. Restored in
            // the finally block so a Stop/error never leaks this override into
            // the user's collection state or into any OTHER collection.
            // Convention-based — works for any Postman script that uses the
            // standard "forceNewToken" (or similar) flag.
            final java.util.regex.Pattern FORCE_TOKEN_RE =
                java.util.regex.Pattern.compile("(?i)force.*token.*");
            // Per-scope snapshots so we restore each scope to its original.
            // Key: scope name ("" = global pool). Value: var name → original.
            final java.util.Map<String, java.util.Map<String, String>> tokenCacheSnapshot =
                new java.util.LinkedHashMap<>();
            try {
                // Collect candidate scopes: every distinct scope across toRun
                // (handles multi-collection edge cases) plus the global pool.
                java.util.LinkedHashSet<String> scopes = new java.util.LinkedHashSet<>();
                for (AnalyzedRequest ar : toRun) {
                    if (ar == null) continue;
                    String s = scopeFromPath(ar.getPath());
                    if (s != null && !s.isEmpty()) scopes.add(s);
                }
                int flippedCount = 0;
                // Global pool first (forceNewToken often lives at workspace level)
                java.util.Map<String, String> globals = variableResolver.getVariables();
                java.util.Map<String, String> globalSnap = new java.util.HashMap<>();
                if (globals != null) {
                    for (java.util.Map.Entry<String, String> e : new java.util.HashMap<>(globals).entrySet()) {
                        if (e.getKey() == null) continue;
                        if (FORCE_TOKEN_RE.matcher(e.getKey()).matches()
                                && e.getValue() != null
                                && "true".equalsIgnoreCase(e.getValue().trim())) {
                            globalSnap.put(e.getKey(), e.getValue());
                            variableResolver.putGlobalVariable(e.getKey(), "false");
                            flippedCount++;
                        }
                    }
                }
                if (!globalSnap.isEmpty()) tokenCacheSnapshot.put("", globalSnap);
                // Per-scope flips (does NOT touch other collections' scopes)
                for (String s : scopes) {
                    java.util.Map<String, String> sv = variableResolver.getScopedVariables(s);
                    if (sv == null || sv.isEmpty()) continue;
                    java.util.Map<String, String> snap = new java.util.HashMap<>();
                    for (java.util.Map.Entry<String, String> e : new java.util.HashMap<>(sv).entrySet()) {
                        if (e.getKey() == null) continue;
                        if (FORCE_TOKEN_RE.matcher(e.getKey()).matches()
                                && e.getValue() != null
                                && "true".equalsIgnoreCase(e.getValue().trim())) {
                            snap.put(e.getKey(), e.getValue());
                            sv.put(e.getKey(), "false");
                            flippedCount++;
                        }
                    }
                    if (!snap.isEmpty()) tokenCacheSnapshot.put(s, snap);
                }
                if (flippedCount > 0) {
                    ui.appendLog("⚡ Token cache: reusing tokens across this Analyze run ("
                        + flippedCount + " forceNewToken flag(s) temporarily set to false; "
                        + "originals restored when run ends or stops).");
                }

                for (int idx = 0; idx < total; idx++) {
                    if (analyzeStopRequested || dlg.isCancelled()) {
                        ui.appendLog("⏹ " + labelF + " stopped by user at " + idx + "/" + total);
                        try { ui.reenableAnalyzeButton(); } catch (Exception ignore) {}
                        break;
                    }
                    AnalyzedRequest req = toRun.get(idx);
                    int pctStart = (int) Math.round((idx * 100.0) / total);
                    dlg.update(pctStart, idx + 1, total, req != null ? req.getName() : "");
                    long startMs = System.currentTimeMillis();
                    // Build a RunResult shell that gets populated below — pushed
                    // into the Run Results tab whether the send succeeds or not.
                    burp.models.RunResult rr = null;
                    try {
                        String resolvedUrlPreview = null;
                        try {
                            String raw = extractRawUrl(req.getRequest().url);
                            resolvedUrlPreview = raw == null ? "" : variableResolver.resolve(raw);
                        } catch (Exception ignore) {}
                        rr = new burp.models.RunResult(
                            runIdFinal, 1,
                            req.getPath(), req.getName(),
                            req.getRequest() != null ? req.getRequest().method : "GET",
                            resolvedUrlPreview);
                    } catch (Exception ignore) {}
                    try {
                        runAnalyzedAsPreview(req, true);
                        sent++;
                        // Pull the response captured by processRequest's
                        // existing wire-send. Re-firing via fireForScript()
                        // here would build a SECOND request without re-running
                        // the pre-script — auth headers would be missing →
                        // 403/401. The Run Results panel needs the same
                        // response the Repeater tab sees.
                        burp.models.ExecutedRequest response = consumeLastProcessedRequest();
                        if (rr != null) {
                            rr.durationMs = System.currentTimeMillis() - startMs;
                            if (response != null) {
                                rr.statusCode = response.getStatusCode();
                                rr.responseBody = response.getResponseBody();
                                rr.responseHeaders = response.getResponseHeaders();
                                rr.sizeBytes = response.getResponseBody() == null
                                    ? 0L : response.getResponseBody().length();
                                if (response.getTestResults() != null
                                        && !response.getTestResults().isEmpty()) {
                                    rr.tests.addAll(response.getTestResults());
                                }
                            } else {
                                rr.error = "No response captured";
                            }
                        }
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        ui.appendLog("⏹ " + labelF + " stopped by user at " + idx + "/" + total);
                        if (rr != null) rr.error = "Cancelled by user";
                        try {
                            burp.ui.RunResultsPanel p = ui.getRunResultsPanel();
                            if (p != null && rr != null) p.addResult(rr);
                        } catch (Exception ignore) {}
                        break;
                    } catch (Exception ex) {
                        if (analyzeStopRequested) break;
                        ui.appendLog("⚠ Preview failed for "
                            + (req != null ? req.getName() : "?") + ": " + ex.getMessage());
                        if (rr != null) {
                            rr.error = ex.getMessage();
                            rr.durationMs = System.currentTimeMillis() - startMs;
                        }
                    }
                    // Push the result regardless of success — the Run Results
                    // tab needs to show errors too.
                    try {
                        burp.ui.RunResultsPanel p = ui.getRunResultsPanel();
                        if (p != null && rr != null) p.addResult(rr);
                    } catch (Exception ignore) {}
                    // Honour bru.setNextRequest() from the post-response
                    // script. Real Bruno skips intervening requests when
                    // the script asks to jump to a named target — used by
                    // CIAM / OIDC flows to short-circuit MFA when the
                    // server returns an early tokenId.  Empty value =
                    // STOP run after this request (Bruno's documented
                    // semantics for {@code setNextRequest(null)}).
                    String nextReq = burp.service.RhinoScriptEngine
                        .NEXT_REQUEST_THREADLOCAL.get();
                    if (nextReq != null) {
                        burp.service.RhinoScriptEngine
                            .NEXT_REQUEST_THREADLOCAL.remove();
                        if (nextReq.isEmpty()) {
                            ui.appendLog("⏭ " + (req != null ? req.getName() : "?")
                                + " → bru.setNextRequest(null) — stopping run.");
                            break;
                        }
                        // Find the next request in toRun that matches the
                        // requested name (case-sensitive, like Bruno).
                        int jumpTo = -1;
                        for (int j = idx + 1; j < total; j++) {
                            AnalyzedRequest cand = toRun.get(j);
                            if (cand != null && nextReq.equals(cand.getName())) {
                                jumpTo = j;
                                break;
                            }
                        }
                        if (jumpTo > idx + 1) {
                            int skipCount = jumpTo - idx - 1;
                            ui.appendLog("⏭ " + (req != null ? req.getName() : "?")
                                + " → bru.setNextRequest(\"" + nextReq + "\") — skipping "
                                + skipCount + " request(s).");
                            // Push skipped rows into Run Results so the
                            // user can see what got bypassed.
                            try {
                                burp.ui.RunResultsPanel p = ui.getRunResultsPanel();
                                if (p != null) {
                                    for (int j = idx + 1; j < jumpTo; j++) {
                                        AnalyzedRequest sk = toRun.get(j);
                                        if (sk == null) continue;
                                        burp.models.RunResult skipRR =
                                            new burp.models.RunResult(
                                                runIdFinal, 1, sk.getPath(),
                                                sk.getName(),
                                                sk.getRequest() != null
                                                    ? sk.getRequest().method : "GET",
                                                "(skipped by setNextRequest)");
                                        skipRR.error = "Skipped by setNextRequest";
                                        p.addResult(skipRR);
                                    }
                                }
                            } catch (Exception ignore) {}
                            idx = jumpTo - 1; // for-loop will ++ to jumpTo
                        } else if (jumpTo < 0) {
                            ui.appendLog("⚠ bru.setNextRequest(\"" + nextReq
                                + "\") — target not found in remaining run; continuing.");
                        }
                    }
                    if (analyzeStopRequested) {
                        ui.appendLog("⏹ " + labelF + " stopped by user at " + (idx + 1) + "/" + total);
                        break;
                    }
                    int pct = (int) Math.round(((idx + 1) * 100.0) / total);
                    try { ui.updateProgress(pct); } catch (Exception ignore) {}
                    dlg.update(pct, idx + 1, total, req != null ? req.getName() : "");
                    // Throttle variable refresh: only every 10th request (still refresh at end).
                    if ((idx + 1) % 10 == 0) {
                        try { ui.refreshVariables(variableResolver.getVariables()); }
                        catch (Exception ignore) {}
                    }
                }
                ui.appendLog("✅ " + labelF + " complete: "
                    + sent + "/" + total + " request(s) executed");
                try {
                    burp.ui.RunResultsPanel p = ui.getRunResultsPanel();
                    if (p != null) p.finishRun();
                } catch (Exception ignore) {}
                try { ui.updateProgress(100); } catch (Exception ignore) {}
                dlg.finishAndClose();
            } finally {
                // ALWAYS restore the forceNewToken originals — even on Stop,
                // exception, or normal completion. This is what guarantees
                // OTHER collections are never affected.
                try {
                    for (java.util.Map.Entry<String, java.util.Map<String, String>> scopeEntry
                            : tokenCacheSnapshot.entrySet()) {
                        String scope = scopeEntry.getKey();
                        java.util.Map<String, String> snap = scopeEntry.getValue();
                        if (snap == null || snap.isEmpty()) continue;
                        if (scope == null || scope.isEmpty()) {
                            for (java.util.Map.Entry<String, String> en : snap.entrySet()) {
                                variableResolver.putGlobalVariable(en.getKey(), en.getValue());
                            }
                        } else {
                            java.util.Map<String, String> sv = variableResolver.getScopedVariables(scope);
                            if (sv != null) {
                                for (java.util.Map.Entry<String, String> en : snap.entrySet()) {
                                    sv.put(en.getKey(), en.getValue());
                                }
                            }
                        }
                    }
                    if (!tokenCacheSnapshot.isEmpty()) {
                        ui.appendLog("🔄 Token cache: restored forceNewToken flag(s) to original values.");
                    }
                } catch (Throwable ignore) {}
                try { ui.refreshVariables(variableResolver.getVariables()); }
                catch (Exception ignore) {}
                try { refreshAuthDetectionFromCurrentCollection(); } catch (Exception ignore) {}
                try { ui.clearRequestEditCache(); } catch (Exception ignore) {}
                analyzeWorkerThread = null;
            }
        }, "auto-run-preview");
        worker.start();
    }

    public void runAnalyzedAsPreview(AnalyzedRequest analyzedRequest, boolean withAuth) throws Exception {
        if (analyzeStopRequested) throw new InterruptedException("Analyze stopped");
        if (analyzedRequest == null || analyzedRequest.getRequest() == null) {
            throw new Exception("Invalid request");
        }
        if (currentCollection == null) {
            throw new Exception("No collection loaded — run Analyze first");
        }
        String name = analyzedRequest.getName() != null ? analyzedRequest.getName() : "";
        String path = analyzedRequest.getPath() != null ? analyzedRequest.getPath() : "";
        // Deep-clone via Gson so processRequest's in-place rewrites don't mutate
        // the analyzed tree's source object.
        PostmanCollection.Request orig = analyzedRequest.getRequest();
        PostmanCollection.Request clone;
        try {
            com.google.gson.Gson gson = new com.google.gson.Gson();
            clone = gson.fromJson(gson.toJsonTree(orig), PostmanCollection.Request.class);
        } catch (Exception e) {
            clone = orig;
        }
        RequestItem item = new RequestItem(name, path, clone);
        // Activate this request's collection scope so {{token}} etc. resolve
        // from per-collection user overrides instead of the global pool.
        String prevScope = variableResolver.getActiveScope();
        try {
            variableResolver.setActiveScope(scopeFromPath(path));
            processRequest(item, "preview", withAuth);
        } finally {
            variableResolver.setActiveScope(prevScope);
        }
    }

    /**
     * Backs {@code bru.runRequest(path)} — finds a request by path or name in
     * the loaded collection and runs it inline, pre-script and post-script
     * included, returning its response.
     *
     * <p>Matching is forgiving because scripts address requests the way a human
     * would: a full path ({@code "Auth/CIAM/initialize"}), a path relative to
     * the collection wrapper, or a bare name. Case-insensitive, since a script
     * written against a folder later renamed in case alone should still work.
     */
    private Object runRequestByPath(String requestPath) throws Exception {
        if (currentCollection == null || requestPath == null) return null;
        String want = requestPath.trim().replace('\\', '/');
        if (want.isEmpty()) return null;

        java.util.List<RequestItem> all = flattenRequests(
            currentCollection.item, "",
            currentCollection.info != null ? currentCollection.info.name : null);

        RequestItem match = null;
        for (RequestItem it : all) {
            if (it.path != null && it.path.equalsIgnoreCase(want)) { match = it; break; }
        }
        if (match == null) {
            // Paths carry the collection wrapper as their first segment, but a
            // script inside the collection writes paths relative to it.
            for (RequestItem it : all) {
                if (it.path == null) continue;
                int slash = it.path.indexOf('/');
                String relative = slash >= 0 ? it.path.substring(slash + 1) : it.path;
                if (relative.equalsIgnoreCase(want)) { match = it; break; }
            }
        }
        if (match == null) {
            for (RequestItem it : all) {
                if (it.path != null && it.path.toLowerCase(java.util.Locale.ROOT)
                        .endsWith("/" + want.toLowerCase(java.util.Locale.ROOT))) { match = it; break; }
            }
        }
        if (match == null) {
            for (RequestItem it : all) {
                if (it.name != null && it.name.equalsIgnoreCase(want)) { match = it; break; }
            }
        }
        if (match == null) return null;

        ui.appendLog("↪ bru.runRequest(\"" + want + "\") → " + match.path);
        AnalyzedRequest ar = new AnalyzedRequest(
            match.name, match.path, match.request,
            currentCollection.info != null ? currentCollection.info.name : "Collection",
            null);
        runAnalyzedAsPreview(ar, true);
        burp.models.ExecutedRequest response = consumeLastProcessedRequest();
        if (response != null) {
            ui.appendLog("↩ bru.runRequest(\"" + match.name + "\") → HTTP "
                + response.getStatusCode());
        }
        // Non-null even without a response, so the caller can tell "ran" from
        // "no such request" — the latter is a typo the author needs to see.
        return response != null ? response : Boolean.TRUE;
    }

    /** Extract the collection-wrapper name (top-level path segment) from a
     *  request's full path, used as the variable scope key. */
    private static String scopeFromPath(String path) {
        if (path == null || path.isEmpty()) return null;
        int slash = path.indexOf('/');
        return slash >= 0 ? path.substring(0, slash) : path;
    }

    /**
     * Headers inherited from the collection and every folder above
     * {@code requestPath}, outermost first.
     *
     * <p>Mirrors {@link #getScriptsForPath}'s prefix-matching walk so an item
     * whose own name contains a slash still resolves.
     */
    public java.util.List<PostmanCollection.Header> getHeadersForPath(String requestPath) {
        java.util.List<PostmanCollection.Header> out = new java.util.ArrayList<>();
        if (currentCollection == null) return out;
        if (currentCollection.folderHeaders != null) out.addAll(currentCollection.folderHeaders);
        if (requestPath == null || requestPath.isEmpty()) return out;

        java.util.List<PostmanCollection.Item> level = currentCollection.item;
        String remaining = requestPath;
        while (remaining != null && !remaining.isEmpty() && level != null) {
            PostmanCollection.Item match = null;
            String matchedName = null;
            for (PostmanCollection.Item it : level) {
                if (it == null || it.name == null) continue;
                String name = it.name;
                if (remaining.equals(name)) { match = it; matchedName = name; break; }
                if (remaining.startsWith(name + "/")
                        && (match == null || name.length() > matchedName.length())) {
                    match = it;
                    matchedName = name;
                }
            }
            if (match == null) break;
            if (match.folderHeaders != null) out.addAll(match.folderHeaders);
            if (remaining.equals(matchedName)) break;
            remaining = remaining.substring(matchedName.length() + 1);
            level = match.item;
        }
        return out;
    }

    /**
     * Adds inherited folder headers to {@code request}, without displacing
     * anything the request sets itself.
     *
     * <p>Nearest wins: a request's own header beats its folder's, and an inner
     * folder beats an outer one. A disabled inherited header is skipped rather
     * than added switched-off, so it cannot later be re-enabled by accident.
     */
    private void applyInheritedHeaders(PostmanCollection.Request request, String path) {
        if (request == null) return;
        java.util.List<PostmanCollection.Header> inherited = getHeadersForPath(path);
        if (inherited.isEmpty()) return;

        if (request.header == null) request.header = new java.util.ArrayList<>();
        java.util.Set<String> present = new java.util.HashSet<>();
        for (PostmanCollection.Header h : request.header) {
            if (h != null && h.key != null) present.add(h.key.trim().toLowerCase(java.util.Locale.ROOT));
        }

        int added = 0;
        // Walk inner-to-outer so the nearest declaration of a repeated header
        // is the one that lands.
        for (int i = inherited.size() - 1; i >= 0; i--) {
            PostmanCollection.Header src = inherited.get(i);
            if (src == null || src.key == null || src.key.trim().isEmpty()) continue;
            if (src.disabled) continue;
            String key = src.key.trim().toLowerCase(java.util.Locale.ROOT);
            if (!present.add(key)) continue;
            PostmanCollection.Header copy = new PostmanCollection.Header();
            copy.key = src.key;
            copy.value = src.value;
            copy.description = src.description;
            copy.disabled = false;
            request.header.add(copy);
            added++;
        }
        if (added > 0) {
            ui.appendLog("🧬 Inherited " + added + " folder header(s) for " + path);
        }
    }

    private void processRequest(RequestItem item, String destination) throws Exception {
        processRequest(item, destination, false);
    }
    
    private void processRequest(RequestItem item, String destination, boolean withAuth) throws Exception {
        if (analyzeStopRequested) throw new InterruptedException("Stopped");
        // Install the request runner here rather than only in the batch worker,
        // so bru.runRequest() behaves identically whether the user pressed Run
        // or sent this one request on its own. Saved and restored because a
        // script's runRequest() re-enters this method.
        burp.service.RhinoScriptEngine.RequestRunner previousRunner =
            burp.service.RhinoScriptEngine.REQUEST_RUNNER_THREADLOCAL.get();
        burp.service.RhinoScriptEngine.REQUEST_RUNNER_THREADLOCAL.set(this::runRequestByPath);
        try {
            processRequestInner(item, destination, withAuth);
        } finally {
            if (previousRunner == null) {
                burp.service.RhinoScriptEngine.REQUEST_RUNNER_THREADLOCAL.remove();
            } else {
                burp.service.RhinoScriptEngine.REQUEST_RUNNER_THREADLOCAL.set(previousRunner);
            }
        }
    }

    private void processRequestInner(RequestItem item, String destination, boolean withAuth) throws Exception {
        // Fold in folder/collection headers first, so the pre-request script
        // sees the same request the server will.
        try {
            applyInheritedHeaders(item.request, item.path);
        } catch (Exception e) {
            ui.appendLog("⚠️ Folder header inheritance failed for " + item.name + ": " + e.getMessage());
        }
        // --- Pre-request scripts (cascaded collection→folder→request) ---
        String[] cascadedScripts = null;
        try {
            cascadedScripts = getScriptsForPath(item.path);
            if (cascadedScripts != null && cascadedScripts.length > 0
                    && cascadedScripts[0] != null && !cascadedScripts[0].isEmpty()) {
                burp.service.ScriptExecutor.runAndApply(cascadedScripts[0], variableResolver, null, item.request);
                ui.appendLog("📜 Pre-request script ran for " + item.name);
            }
        } catch (Throwable t) {
            ui.appendLog("⚠️ Pre-request script error for " + item.name + ": " + t.getMessage());
        }

        // ✅ Honor FolderAuthRegistry override (set via Auth Manager / Folder Auth editor)
        // path looks like "Collection/Folder/Subfolder/Request" — strip the request leaf.
        burp.auth.FolderAuthOverride folderOverride = null;
        try {
            String regKey = item.path == null ? "" : item.path;
            int slash = regKey.lastIndexOf('/');
            if (slash >= 0) regKey = regKey.substring(0, slash);
            folderOverride = folderAuthRegistry.resolve(regKey);
            if (folderOverride != null) {
                ui.appendLog("🔍 Folder override (run): " + regKey + " → " + folderOverride.type.label);
            }
        } catch (Exception ignore) {}
        // If user explicitly chose No Auth on this folder, force-disable auth for the run.
        if (folderOverride != null && folderOverride.type == burp.auth.FolderAuthOverride.Type.NO_AUTH) {
            withAuth = false;
            if (item.request != null && item.request.header != null) {
                item.request.header.removeIf(h ->
                    h != null && h.key != null && "Authorization".equalsIgnoreCase(h.key.trim()));
            }
            ui.appendLog("🚫 Folder = No Auth → stripping Authorization for " + item.name);
        }

        String token = null;

        // ✅ If withAuth is false, skip all auth injection
        if (!withAuth) {
            token = null;
        } else {
            // ✅ 1. REQUEST AUTH
            if (item.request != null && item.request.auth != null) {
                token = extractBearer(item.request.auth);
            }

            // ✅ 2. FOLDER AUTH
            if (token == null) {
                token = resolveFolderAuth(item);
            }
        }

        // ✅ Compute auth skip flags once, after request/folder auth resolution.
        boolean isExplicitlyBlank = token != null && token.isEmpty();
        boolean isNoAuthRequest = isNoAuthRequest(item.request);
        boolean isOAuthBodyRequest = hasOAuthBodyCredentials(item.request);
        // If the request has its OWN explicit auth block (not inherited),
        // honor it even on token endpoints. RFC 8693 token-exchange, for
        // example, requires a Bearer of the calling client's credentials
        // even though the URL is /oauth2/token and the body has grant_type.
        // Postman sends the Authorization header in that case; matching that.
        boolean hasOwnRequestAuth = item.request != null
                && item.request.auth != null
                && item.request.auth.type != null
                && !"noauth".equalsIgnoreCase(item.request.auth.type.trim())
                && extractBearer(item.request.auth) != null
                && !extractBearer(item.request.auth).trim().isEmpty();
        boolean skipAuth = isExplicitlyBlank || isNoAuthRequest
                || (isOAuthBodyRequest && !hasOwnRequestAuth)
                || !withAuth;

        ui.appendLog("🔎 auth-decision → " + item.name
                + " token=" + (token == null ? "<null>" : (token.isEmpty() ? "<empty>" : "<set>"))
                + " isExplicitlyBlank=" + isExplicitlyBlank
                + " isNoAuthRequest=" + isNoAuthRequest
                + " isOAuthBodyRequest=" + isOAuthBodyRequest
                + " hasOwnRequestAuth=" + hasOwnRequestAuth
                + " → skipAuth=" + skipAuth);

        // ✅ 3. COLLECTION AUTH
        // Only inherit collection auth for normal API requests.
        // Do NOT inherit for noauth or OAuth token endpoints.
        if (token == null
                && currentCollection != null
                && !isExplicitlyBlankAuth(item.request)
                && !isNoAuthRequest
                && !isOAuthBodyRequest) {

            String rawToken = extractBearer(currentCollection.auth);

            if (rawToken != null && !rawToken.trim().isEmpty()) {

                String varName;

                if (rawToken.contains("{{")) {
                    varName = rawToken.replace("{{", "").replace("}}", "").trim();
                } else {
                    varName = registerUniqueToken(rawToken);
                }

                token = "{{" + varName + "}}";

                ui.appendLog("🔐 Collection auth used → " + item.name);
                ui.appendLog("🔐 Collection token normalized → " + token);
            }
        }

        // ✅ 4. VARIABLE fallback
        if (token == null
                && !skipAuth
                && !isExplicitlyBlankAuth(item.request)) {

            token = variableResolver.getVariables().get("token");
        }

        // ✅ 5. AuthManager fallback
        if (token == null
                && !skipAuth
                && authManager != null
                && authManager.hasAccessToken()) {

            token = authManager.getAccessToken();
        }

        // continue with skipAuth block / normal auth injection / builder...

        // ✅ ✅ HANDLE BLANK AUTH OBJECT
        // ✅ ✅ HANDLE NOAUTH / OAUTH TOKEN / EXPLICIT BLANK
    if (skipAuth) {

        if (item.request.header == null) {
            item.request.header = new ArrayList<>();
        }

        List<PostmanCollection.Header> filteredHeaders = new ArrayList<>();

        for (PostmanCollection.Header h : item.request.header) {
            if (h == null || h.disabled) continue;

            if (!"authorization".equalsIgnoreCase(h.key)) {
                filteredHeaders.add(h);
            }
        }

        item.request.header = filteredHeaders;

        if (isExplicitlyBlank) {
            ui.appendLog("⛔ Preserving explicit blank auth → " + item.name);

            PostmanCollection.Header blankHeader = new PostmanCollection.Header();
            blankHeader.key = "Authorization";
            blankHeader.value = "Bearer";
            blankHeader.disabled = false;

            item.request.header.add(blankHeader);
        } else {
            ui.appendLog("⛔ Skipping inherited Authorization → " + item.name);
        }

        item.request.auth = null;
    }

        // ✅ ✅ NORMAL AUTH INJECTION
    if (!skipAuth && token != null && shouldOverrideAuth(item.request, token)) {

            if (item.request.header == null) {
                item.request.header = new ArrayList<>();
            }

            List<PostmanCollection.Header> filteredHeaders = new ArrayList<>();

            for (PostmanCollection.Header h : item.request.header) {
                if (h == null || h.disabled) continue;

                String key = h.key != null ? h.key.trim().toLowerCase() : "";

                if (!"authorization".equals(key)) {
                    filteredHeaders.add(h);
                }
            }

            item.request.header = filteredHeaders;

            // ✅ Remove auth object
            item.request.auth = null;

            String varName;

            if (token.contains("{{")) {
                varName = token.replace("{{", "").replace("}}", "").trim();
            } else {
                varName = tokenValueToVar.get(token);
                if (varName == null) {
                    varName = registerUniqueToken(token);
                }
            }

            PostmanCollection.Header authHeader = new PostmanCollection.Header();
            authHeader.key = "Authorization";
            authHeader.value = "Bearer {{" + varName + "}}";
            authHeader.disabled = false;

            item.request.header.add(authHeader);

            ui.appendLog("✅ FINAL AUTH APPLIED → " + item.name);
        }

        // ✅ DEBUG OUTPUT
        ui.appendLog("----- FINAL REQUEST BEFORE BUILDER: " + item.name + " -----");

        if (item.request.header != null) {
            for (PostmanCollection.Header h : item.request.header) {
                if (h != null && !h.disabled) {
                    ui.appendLog("HEADER → " + h.key + ": " + h.value);
                }
            }
        } else {
            ui.appendLog("No headers found");
        }

        if (item.request.auth != null) {
            ui.appendLog("AUTH OBJECT → type=" + item.request.auth.type);
        } else {
            ui.appendLog("AUTH OBJECT → null");
        }

        ui.appendLog("-----------------------------------------------------");

        // ✅ BUILD AND SEND
        RequestBuilder freshBuilder = new RequestBuilder(api, variableResolver, authManager);

        PostmanCollection.Auth effectiveAuth = resolveEffectiveAuthForRequest(item);
        if (skipAuth) {
            effectiveAuth = null;
        }


        ensureTokenFromSourceIfNeeded(item.request, effectiveAuth);

        // ✅ When withAuth=false, strip any Authorization header on the request
        // so "Run (Preview, no Auth)" actually fires unauthenticated.
        if (!withAuth && item.request != null && item.request.header != null) {
            int before = item.request.header.size();
            item.request.header.removeIf(h ->
                h != null && h.key != null && "Authorization".equalsIgnoreCase(h.key.trim()));
            if (item.request.header.size() < before) {
                ui.appendLog("🚫 No-Auth: stripped Authorization header for " + item.name);
            }
        }

        // ✅ Force-override hardcoded Authorization: Bearer <literal> with {{token}}
        // when the user has applied a token via Auth Manager. This makes
        // Run (Preview) / Analyze pick up token edits even on collections whose
        // headers were never normalized through the Import preview flow.
        if (withAuth) {
            String currentToken = null;
            try {
                Map<String, String> vars = variableResolver.getVariables();
                if (vars != null) currentToken = vars.get("token");
            } catch (Exception ignore) {}
            if (currentToken == null || currentToken.trim().isEmpty()) {
                try {
                    String amTok = authManager != null ? authManager.getAccessToken() : null;
                    if (amTok != null && !amTok.trim().isEmpty()) {
                        currentToken = amTok.trim();
                        variableResolver.addCustomVariable("token", currentToken);
                        ui.appendLog("🔐 Seeded {{token}} from Auth Manager");
                    }
                } catch (Exception ignore) {}
            } else {
                // Prefer the freshest Auth Manager token if it differs
                try {
                    String amTok = authManager != null ? authManager.getAccessToken() : null;
                    if (amTok != null && !amTok.trim().isEmpty()
                            && !amTok.trim().equals(currentToken)) {
                        currentToken = amTok.trim();
                        variableResolver.addCustomVariable("token", currentToken);
                    }
                } catch (Exception ignore) {}
            }
            // Propagate to every {{token_*}} variable so per-folder placeholders
            // pick up the user's freshly-applied token.
            if (currentToken != null && !currentToken.trim().isEmpty()) {
                try {
                    Map<String, String> vars = variableResolver.getVariables();
                    if (vars != null) {
                        java.util.List<String> names = new java.util.ArrayList<>(vars.keySet());
                        for (String n : names) {
                            if (n != null && n.startsWith("token_")) {
                                String v = vars.get(n);
                                if (v == null || !v.equals(currentToken)) {
                                    variableResolver.addCustomVariable(n, currentToken);
                                }
                            }
                        }
                    }
                } catch (Exception ignore) {}
            }
            // Rewrite literal Bearer headers to {{token}}
            if (currentToken != null && !currentToken.trim().isEmpty()
                    && item.request != null && item.request.header != null) {
                for (PostmanCollection.Header h : item.request.header) {
                    if (h == null || h.disabled || h.key == null) continue;
                    if (!"Authorization".equalsIgnoreCase(h.key.trim())) continue;
                    String v = h.value == null ? "" : h.value.trim();
                    if (v.toLowerCase(java.util.Locale.ROOT).startsWith("bearer")) {
                        String literal = v.replaceFirst("(?i)bearer", "").trim();
                        if (!literal.isEmpty() && !literal.contains("{{")) {
                            h.value = "Bearer {{token}}";
                            ui.appendLog("🔁 Overriding hardcoded Bearer with {{token}} for " + item.name);
                        }
                    }
                }
            }
        }

        // Removed verbose pre-build debug dump of the entire variable map —
        // it printed 50+ env vars on every request during Run Scripts and
        // pinned the EDT. Token/token1 status is captured by the post-script
        // var-write summary; the full set is visible in Edit Variables.

        byte[] request;

        if (hasAuthorizationHeader(item.request)) {
            ui.appendLog("✅ Existing Authorization header found. Building from request headers only.");
            request = freshBuilder.buildRequest(item.request);
        } else {
            request = freshBuilder.buildRequest(item.request, effectiveAuth);
        }

        String rawUrl = extractRawUrl(item.request.url);

        if (rawUrl == null) {
            throw new Exception("Unable to extract URL from request");
        }

        String resolvedUrl = variableResolver.resolve(rawUrl);

        HttpUtils.HostInfo hostInfo = HttpUtils.parseUrl(resolvedUrl);

        String tabName = generateUniqueTabName(buildRepeaterTabName(item));

        burp.api.montoya.http.message.HttpRequestResponse capturedResponse = null;

        boolean repeaterTabCreated = false;
        switch (destination.toLowerCase()) {

            case "repeater":
                sendToRepeater(hostInfo, request, tabName);
                repeaterTabCreated = true;
                break;

            case "sitemap":
                sendToSitemap(hostInfo, request, item.name);
                capturedResponse = lastSitemapResponse;
                break;

            case "both":
                sendToRepeater(hostInfo, request, tabName);
                repeaterTabCreated = true;

                int delayMs = ui.getDelayMs();
                if (delayMs > 0) {
                    Thread.sleep(delayMs);
                }

                sendToSitemap(hostInfo, request, item.name);
                capturedResponse = lastSitemapResponse;
                break;

            case "preview":
                // Fires the request via Montoya so post-scripts can run, but
                // does NOT add to site map or Repeater.
                try {
                    fetchForPreview(hostInfo, request, item.name);
                    capturedResponse = lastSitemapResponse;
                } catch (Throwable t) {
                    ui.appendLog("⚠️ Preview fetch failed for " + item.name + ": " + t.getMessage()
                        + " — continuing without post-script.");
                }
                break;

            default:
                sendToRepeater(hostInfo, request, tabName);
                repeaterTabCreated = true;
                break;
        }

        if (repeaterTabCreated) {
            existingTabs.add(tabName);
        }

        // --- Post-response scripts ---
        try {
            if (capturedResponse != null && capturedResponse.response() != null) {
                // Always convert the captured response so runAnalyzedBatch can
                // read it from lastProcessedRequest — populates the Run Results
                // tab without firing the request a second time (which would
                // skip the pre-script and lose auth headers → 403).
                burp.models.ExecutedRequest er = toExecutedRequest(item, capturedResponse);
                this.lastProcessedRequest = er;
                // Auto-capture common OAuth token fields from JSON responses.
                // Postman exports frequently mask Authorization headers as the
                // literal "******" string; substituting that back to
                // "Bearer {{access_token}}" only works if the variable is
                // populated. Real Postman workspaces populate it via post-test
                // scripts (which this collection also does — but under
                // different variable names like "ciam.test.oidc.token").
                // Auto-capture provides a defensive fallback that ALWAYS
                // populates the common {{access_token}} / {{token}} vars
                // regardless of what the user's scripts choose to name them.
                autoCaptureCommonTokens(er);
                // Diagnostic: dump captured response headers when the script
                // reads a redirect Location (CIAM authorize / OAuth flows).
                try {
                    java.util.List<PostmanCollection.Header> dh = er.getResponseHeaders();
                    int hc = (dh == null) ? -1 : dh.size();
                    String loc = null;
                    if (dh != null) {
                        for (PostmanCollection.Header h : dh) {
                            if (h != null && h.key != null
                                    && "location".equalsIgnoreCase(h.key.trim())) {
                                loc = h.value;
                                break;
                            }
                        }
                    }
                    ui.appendLog("🔎 [post-script ctx] " + item.name
                        + " status=" + er.getStatusCode()
                        + " headers=" + hc
                        + " location=" + (loc == null ? "<absent>"
                            : (loc.length() > 120 ? loc.substring(0, 120) + "…" : loc)));
                } catch (Throwable ignore) {}
                // Run each post-response Event as its own script call. Bruno
                // collections often have separate `script:post-response` and
                // `tests` blocks that both declare `let authId = ...` — when
                // concatenated, Rhino crashes mid-script and the partial
                // env-var writes get clobbered by the mini-interpreter
                // fallback running the same broken script from scratch. Per-
                // event execution isolates each block: a crash in one doesn't
                // undo the variable writes the other already committed.
                java.util.List<String> perEventScripts =
                    getCascadedTestScripts(item.path);
                if (perEventScripts != null && !perEventScripts.isEmpty()) {
                    PostmanCollection.Request scriptRequestContext =
                        ScriptRequestContextBuilder.fromTemplate(
                            item.request, variableResolver, resolvedUrl);
                    java.util.List<burp.models.ExecutedRequest.TestResult> testSink =
                        new java.util.ArrayList<>();
                    burp.service.RhinoScriptEngine.TEST_RESULTS_THREADLOCAL.set(testSink);
                    try {
                        for (String s : perEventScripts) {
                            if (s == null || s.trim().isEmpty()) continue;
                            try {
                                burp.service.ScriptExecutor.runAndApply(
                                    s,
                                    variableResolver,
                                    er,
                                    scriptRequestContext != null ? scriptRequestContext : item.request);
                            } catch (Throwable inner) {
                                ui.appendLog("⚠ post-script chunk error for "
                                    + item.name + ": " + inner.getMessage());
                            }
                        }
                    } finally {
                        burp.service.RhinoScriptEngine.TEST_RESULTS_THREADLOCAL.remove();
                    }
                    if (!testSink.isEmpty()) {
                        er.setTestResults(testSink);
                    }
                    ui.appendLog("📜 Post-response script ran for " + item.name);
                }
            } else if (cascadedScripts != null && cascadedScripts.length > 1
                    && cascadedScripts[1] != null && !cascadedScripts[1].isEmpty()) {
                ui.appendLog("ℹ️ Post-response script skipped for " + item.name
                    + " (no captured response — destination=" + destination + ")");
            }
        } catch (Throwable t) {
            ui.appendLog("⚠️ Post-response script error for " + item.name + ": " + t.getMessage());
        } finally {
            lastSitemapResponse = null;
        }
    }

    private burp.api.montoya.http.message.HttpRequestResponse lastSitemapResponse;
    /** Latest ExecutedRequest captured by the most recent processRequest() call.
     *  Used by runAnalyzedBatch to populate the Run Results panel without
     *  having to fire the request a second time (which would skip the
     *  pre-request script and produce a 403/401 without auth headers). */
    private volatile burp.models.ExecutedRequest lastProcessedRequest;
    public burp.models.ExecutedRequest consumeLastProcessedRequest() {
        burp.models.ExecutedRequest r = lastProcessedRequest;
        lastProcessedRequest = null;
        return r;
    }
    private volatile boolean analyzeStopRequested = false;
    private volatile Thread analyzeWorkerThread = null;
    public void requestAnalyzeStop() {
        analyzeStopRequested = true;
        Thread t = analyzeWorkerThread;
        if (t != null) t.interrupt();
    }

    private burp.models.ExecutedRequest toExecutedRequest(RequestItem item,
            burp.api.montoya.http.message.HttpRequestResponse rr) {
        burp.models.ExecutedRequest er = new burp.models.ExecutedRequest(
                java.util.UUID.randomUUID().toString(),
                System.currentTimeMillis(),
                item.request != null ? item.request.method : "GET",
                item.request != null && item.request.url != null ? item.request.url.toString() : "",
                null,
                null);
        try {
            burp.api.montoya.http.message.responses.HttpResponse resp = rr.response();
            if (resp != null) {
                er.setStatusCode(resp.statusCode());
                er.setResponseBody(resp.bodyToString());
                java.util.List<PostmanCollection.Header> respHdrs = new java.util.ArrayList<>();
                for (burp.api.montoya.http.message.HttpHeader h : resp.headers()) {
                    PostmanCollection.Header ph = new PostmanCollection.Header();
                    ph.key = h.name();
                    ph.value = h.value();
                    respHdrs.add(ph);
                }
                er.setResponseHeaders(respHdrs);
            }
        } catch (Throwable ignore) { }
        return er;
    }

    private void fetchForPreview(HttpUtils.HostInfo hostInfo, byte[] request, String requestName) throws Exception {
        burp.api.montoya.http.HttpService httpService = burp.api.montoya.http.HttpService.httpService(
            hostInfo.host, hostInfo.port, hostInfo.useHttps);
        try {
            // Inject Cookie header from the jar if a prior request in this run
            // captured one for this host. Stateful auth chains (CIAM,
            // ForgeRock, OIDC session cookies) require this — without it the
            // second step always 401s because the session is forgotten.
            byte[] reqBytes = request;
            try {
                String cookieHeader = cookieJar.buildCookieHeader(hostInfo.host);
                if (cookieHeader != null && !cookieHeader.isEmpty()) {
                    reqBytes = injectHeaderIfMissing(reqBytes, "Cookie", cookieHeader);
                }
            } catch (Throwable ignore) {}

            burp.api.montoya.http.message.requests.HttpRequest httpRequest =
                burp.api.montoya.http.message.requests.HttpRequest.httpRequest(httpService,
                    burp.api.montoya.core.ByteArray.byteArray(reqBytes));
            burp.api.montoya.http.message.HttpRequestResponse response = burp.service.ProxyRouter.sendRequest(api, httpRequest);
            this.lastSitemapResponse = response;
            if (response != null && response.response() != null) {
                short code = response.response().statusCode();
                api.logging().logToOutput("Preview: " + requestName + " -> HTTP " + code + " (NOT added to site map)");
                // Absorb Set-Cookie so the next request in this run can
                // carry the session cookie back. Mirror the data shape
                // CookieJar expects (PostmanCollection.Header list).
                try {
                    java.util.List<PostmanCollection.Header> rh = new java.util.ArrayList<>();
                    for (burp.api.montoya.http.message.HttpHeader h : response.response().headers()) {
                        PostmanCollection.Header e = new PostmanCollection.Header();
                        e.key = h.name();
                        e.value = h.value();
                        rh.add(e);
                    }
                    cookieJar.capture(hostInfo.host, rh);
                } catch (Throwable ignore) {}
            }
            int delayMs = ui.getDelayMs();
            if (delayMs > 0) Thread.sleep(delayMs);
        } catch (Exception e) {
            StringBuilder full = new StringBuilder();
            full.append(e.getClass().getSimpleName());
            if (e.getMessage() != null) full.append(": ").append(e.getMessage());
            throw new Exception("Preview fetch failed: " + full);
        }
    }

    private void sendToRepeater(HttpUtils.HostInfo hostInfo, byte[] request, String tabName) {
        // Create HTTP service
        burp.api.montoya.http.HttpService httpService = burp.api.montoya.http.HttpService.httpService(
            hostInfo.host,
            hostInfo.port,
            hostInfo.useHttps
        );
        
        // Create HTTP request from raw bytes
        burp.api.montoya.http.message.requests.HttpRequest httpRequest = 
            burp.api.montoya.http.message.requests.HttpRequest.httpRequest(httpService, 
                burp.api.montoya.core.ByteArray.byteArray(request));
        
        // Send to repeater with tab name
        api.repeater().sendToRepeater(httpRequest, tabName);
    }
    private void ensureTokenFromSourceIfNeeded(
            PostmanCollection.Request targetRequest,
            PostmanCollection.Auth targetEffectiveAuth
    ) {
        try {
            if (authManager == null) return;

            // ✅ If token already exists, no need to fetch
            if (authManager.hasAccessToken()) {
                return;
            }

            // ✅ Token source must be configured first
            PostmanCollection.Request tokenSource = authManager.getTokenSourceRequest();

            if (tokenSource == null) {
                return;
            }

            // ✅ Prevent infinite recursion
            if (tokenSource == targetRequest) {
                return;
            }

            // ✅ Do not auto-fetch for explicit noauth target requests
            if (targetRequest != null
                    && targetRequest.auth != null
                    && "noauth".equalsIgnoreCase(targetRequest.auth.type)) {
                return;
            }

            // ✅ Only auto-fetch when target request expects Bearer auth
            if (targetEffectiveAuth == null
                    || targetEffectiveAuth.type == null
                    || !"bearer".equalsIgnoreCase(targetEffectiveAuth.type)) {
                return;
            }

            ui.appendLog("🔑 Auto-fetching token from delegated token source...");

            RequestBuilder builder = new RequestBuilder(api, variableResolver, authManager);

            PostmanCollection.Request normalizedTokenSource = normalizeTokenSourceRequestForWire(tokenSource);
            if (normalizedTokenSource == null) {
                ui.appendLog("❌ Token source request is empty");
                return;
            }

            PostmanCollection.Auth tokenSourceAuth = normalizedTokenSource.auth;

            byte[] raw = builder.buildRequest(normalizedTokenSource, tokenSourceAuth);

            String rawUrl = extractRawUrl(normalizedTokenSource.url);

            if (rawUrl == null) {
                ui.appendLog("❌ Token source URL missing");
                return;
            }

            String resolvedUrl = variableResolver.resolve(rawUrl);

            HttpUtils.HostInfo hostInfo = HttpUtils.parseUrl(resolvedUrl);

            burp.api.montoya.http.HttpService service =
                    burp.api.montoya.http.HttpService.httpService(
                            hostInfo.host,
                            hostInfo.port,
                            hostInfo.useHttps
                    );

            burp.api.montoya.http.message.requests.HttpRequest httpRequest =
                    burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                            service,
                            burp.api.montoya.core.ByteArray.byteArray(raw)
                    );

            burp.api.montoya.http.message.HttpRequestResponse response =
                    burp.service.ProxyRouter.sendRequest(api, httpRequest);

            if (response == null || response.response() == null) {
                ui.appendLog("❌ Token source returned no response");
                return;
            }

            boolean extracted = authManager.extractAnyToken(
                    response.response().bodyToString()
            );

            if (extracted) {
                ui.appendLog("✅ Token auto-fetched successfully");

                String token = authManager.getAccessToken();

                if (token != null) {
                    ui.updateTokenArea(token);
                }

            } else {
                ui.appendLog("❌ Token source response did not contain a token");
            }

        } catch (Exception e) {
            ui.appendLog("❌ Auto-fetch token source failed: " + e.getMessage());
        }
    }
    private String findExistingTokenVariable(String token) {

        Map<String, String> vars = variableResolver.getVariables();
    
        for (Map.Entry<String, String> e : vars.entrySet()) {
            if (token.equals(e.getValue())) {
                return e.getKey();
            }
        }
    
        return null;
    }
    
    private boolean shouldOverrideAuth(PostmanCollection.Request request, String newToken) {

        if (request == null || request.header == null) {
            return true;
        }
    
        for (PostmanCollection.Header h : request.header) {
    
            if (h == null || h.disabled) continue;
    
            if ("authorization".equalsIgnoreCase(h.key)) {
    
                if (h.value == null) return true;
    
                String resolved = variableResolver.resolve(h.value).trim();
    
                // ✅ Case 1: unresolved
                if (resolved.contains("{{") || resolved.isEmpty()) {
                    return true;
                }
    
                // ✅ Case 2: already correct → DO NOT TOUCH
                if (resolved.equalsIgnoreCase("Bearer " + newToken)) {
                    return false;
                }
    
                // ✅ Case 3: different → override
                return true;
            }
        }
    
        return true;
    }
    
    
    private void sendToSitemap(HttpUtils.HostInfo hostInfo, byte[] request, String requestName) throws Exception {
        // Create HTTP service
        burp.api.montoya.http.HttpService httpService = burp.api.montoya.http.HttpService.httpService(
            hostInfo.host,
            hostInfo.port,
            hostInfo.useHttps
        );
        
        // Debug logging
        if (debugMode) {
            api.logging().logToOutput("DEBUG: Creating sitemap request for " + requestName);
            api.logging().logToOutput("DEBUG: Host: " + hostInfo.host + ", Port: " + hostInfo.port + ", HTTPS: " + hostInfo.useHttps);
        }
        
        try {
            // Make actual HTTP request to populate sitemap
            if (debugMode) {
                api.logging().logToOutput("DEBUG: Making HTTP request to " + hostInfo.host);
            }
            burp.api.montoya.http.message.requests.HttpRequest httpRequest = 
                burp.api.montoya.http.message.requests.HttpRequest.httpRequest(httpService, 
                    burp.api.montoya.core.ByteArray.byteArray(request));
            burp.api.montoya.http.message.HttpRequestResponse response = burp.service.ProxyRouter.sendRequest(api, httpRequest);
            this.lastSitemapResponse = response;

            if (response != null) {
                if (debugMode) {
                    api.logging().logToOutput("DEBUG: Received response for " + requestName);
                }

                if (response.response() != null) {
                    // Add to sitemap through HTTP history
                    api.siteMap().add(response);
                    short statusCode = response.response().statusCode();
                    api.logging().logToOutput("Sitemap: " + requestName + " -> HTTP " + statusCode);
                    
                    if (debugMode) {
                        api.logging().logToOutput("DEBUG: Added " + requestName + " to sitemap");
                        // Also log the URL for verification
                        String url = response.request().url();
                        api.logging().logToOutput("DEBUG: Sitemap URL: " + url);
                    }
                } else {
                    api.logging().logToOutput("DEBUG: Response was null for " + requestName);
                }
            } else {
                api.logging().logToOutput("DEBUG: No response received for " + requestName);
            }
            
            // Add configurable delay to be respectful to the target server
            int delayMs = ui.getDelayMs();
            if (delayMs > 0) {
                Thread.sleep(delayMs);
            }
            
        } catch (Exception e) {
            // Check for specific network error types and provide clean error messages
            String errorMsg;
            if (e.getCause() instanceof java.net.UnknownHostException || 
                e.getMessage().contains("UnknownHostException")) {
                // Extract hostname from the exception for cleaner error message
                String hostname = extractHostnameFromError(e.getMessage());
                if (hostname != null) {
                    errorMsg = "DNS resolution failed for hostname: " + hostname + " (VPN/internal network required?)";
                } else {
                    errorMsg = "Hostname not accessible - check network connectivity or VPN connection";
                }
                api.logging().logToError("Sitemap connectivity issue for " + requestName + ": " + errorMsg);
            } else if (e.getCause() instanceof java.net.ConnectException || 
                       e.getMessage().contains("ConnectException")) {
                errorMsg = "Connection refused or timeout - service may be down or firewalled";
                api.logging().logToError("Sitemap connection failed for " + requestName + ": " + errorMsg);
            } else {
                errorMsg = "Request failed: " + extractCleanErrorMessage(e);
                api.logging().logToError("Failed to send " + requestName + " to sitemap: " + errorMsg);
            }
            throw new Exception(errorMsg);
        }
    }
    public String extractBearer(PostmanCollection.Auth auth) {
        if (auth == null || !"bearer".equalsIgnoreCase(auth.type)) {
            return null;
        }
    
        if (!(auth.bearer instanceof List)) return null;
    
        for (Object o : (List<?>) auth.bearer) {
    
            String value = null;
    
            if (o instanceof PostmanCollection.AuthAttribute) {
                value = ((PostmanCollection.AuthAttribute) o).value;
            } else if (o instanceof Map) {
                Object v = ((Map<?, ?>) o).get("value");
                if (v != null) value = v.toString();
            }
    
            // ✅ DO NOT RESOLVE
            if (value == null) return null;

            String trimmed = value.trim();
            
            // ✅ IMPORTANT: detect explicit blank
            if (trimmed.isEmpty()) {
                return ""; // ✅ NOT null — means explicitly blank
            }
            
            return trimmed;
        }
    
        return null;
    }

    /**
     * Pull a usable bearer-style access token out of any auth block — supports
     * "bearer" (token attr) and "oauth2" (accessToken attr). Returns null if
     * nothing is available. Does NOT resolve {{vars}}; caller should resolve.
     */
    public String extractAccessTokenFromAuth(PostmanCollection.Auth auth) {
        if (auth == null || auth.type == null) return null;
        String t = auth.type.toLowerCase();
        if ("bearer".equals(t)) {
            return extractBearer(auth);
        }
        if ("oauth2".equals(t)) {
            // Postman stores the last-fetched token as oauth2.accessToken
            String tok = extractAuthAttr(auth.oauth2, "accessToken");
            if (tok != null && !tok.trim().isEmpty()) return tok.trim();
            // Many packs store only tokenName (e.g. "apimExtToken"), and the
            // live value is in variables. Return a template so callers can
            // resolve it via VariableResolver in the active scope.
            String tokenName = extractAuthAttr(auth.oauth2, "tokenName");
            if (tokenName != null && !tokenName.trim().isEmpty()) {
                String tn = tokenName.trim();
                return tn.contains("{{") ? tn : "{{" + tn + "}}";
            }
            return null;
        }
        return null;
    }
    
    
    private String resolveFolderAuth(RequestItem item) {

 

        String path = item.path;
    
        if (path == null) return null;
    
     
    
        String[] parts = path.split("/");
    
        List<PostmanCollection.Item> items = currentCollection.item;
    
     
    
        for (String part : parts) {
    
     
    
            if (items == null) return null;
    
     
    
            for (PostmanCollection.Item i : items) {
    
     
    
                if (part.equals(i.name)) {
    
     
    
                    if (i.auth != null && "bearer".equalsIgnoreCase(i.auth.type)) {
    
     
    
                        String token = extractBearer(i.auth);
    
     
    
                        if (token != null && !token.trim().isEmpty()) {
    
     
                            if (token.contains("{{")) {
    
                                ui.appendLog("🔐 Folder auth (variable) → " + token);
    
                                return token.trim();
    
                            }
    
     
    
                            ui.appendLog("🔐 Folder auth (raw) → " + item.name);
    
                            return token.trim();  // ✅ RAW TOKEN ONLY
    
                        }
    
                    }
    
     
    
                    items = i.item;
    
                    break;
    
                }
    
            }
    
        }
    
     
    
        return null;
    
    }
    
    

    private PostmanCollection.Item findCollectionItemByPath(String path) {

        String[] parts = path.split("/");
    
        List<PostmanCollection.Item> items = currentCollection.item;
        PostmanCollection.Item current = null;
    
        for (String part : parts) {
    
            if (items == null) return null;
    
            for (PostmanCollection.Item i : items) {
    
                if (part.equals(i.name)) {
                    current = i;
                    items = i.item;
                    break;
                }
            }
        }
    
        return current;
    }
    private PostmanCollection.Request findTokenSourceRequestForAutoFetch() {
        try {
            // ✅ Only use explicitly selected token source.
            if (authManager != null &&
                    authManager.getTokenSourceRequest() != null) {

                ui.appendLog("🔑 AutoFetch using selected token source.");
                return authManager.getTokenSourceRequest();
            }

            // ✅ SECURITY: Do not auto-detect token endpoint.
            // User must explicitly choose/check the token source first.
            ui.appendLog("❌ AutoFetch blocked: no token source selected. Please check/select the token endpoint first.");
            return null;

        } catch (Exception e) {
            ui.appendLog("❌ Failed to get token source: " + e.getMessage());
            return null;
        }
    }
    private PostmanCollection.Item getParentItem(PostmanCollection.Item item) {
            // Optional: implement parent tracking later
            return null;
        }
        private String generateUniqueTabName(String baseName) {
            String tabName = baseName;
            int counter = 1;
            
            while (existingTabs.contains(tabName)) {
                tabName = baseName + " (" + counter++ + ")";
            }
            
            return tabName;
        }
        public void autoFetchTokenIntoField(
            javax.swing.JTextField tokenField,
            javax.swing.JButton fetchButton
    ) {
        new Thread(() -> {
            try {
                SwingUtilities.invokeLater(() -> {
                    if (fetchButton != null) {
                        fetchButton.setEnabled(false);
                        fetchButton.setText("...");
                    }
                });

                PostmanCollection.Request tokenSource =
                        findTokenSourceRequestForAutoFetch();

                if (tokenSource == null) {
                    SwingUtilities.invokeLater(() -> {
                        ui.appendLog("❌ AutoFetch blocked: please check/select the token endpoint first.");

                        JOptionPane.showMessageDialog(
                                ui.getPanel(),
                                "Please check/select the token endpoint first before using AutoFetch.",
                                "Token Source Required",
                                JOptionPane.WARNING_MESSAGE
                        );

                        if (fetchButton != null) {
                            fetchButton.setEnabled(true);
                            fetchButton.setText("🔑");
                        }
                    });
                    return;
                }

                ui.appendLog("🔑 AutoFetch: sending token request...");

                RequestBuilder builder =
                        new RequestBuilder(api, variableResolver, authManager);

                PostmanCollection.Request normalizedTokenSource =
                        normalizeTokenSourceRequestForWire(tokenSource);
                if (normalizedTokenSource == null) {
                    SwingUtilities.invokeLater(() -> {
                        ui.appendLog("❌ AutoFetch failed: token source request is empty.");
                        if (fetchButton != null) {
                            fetchButton.setEnabled(true);
                            fetchButton.setText("🔑");
                        }
                    });
                    return;
                }

                // ✅ Do not inherit collection Bearer for token endpoint.
                byte[] raw =
                        builder.buildRequest(normalizedTokenSource, null);

                String rawUrl =
                        extractRawUrl(normalizedTokenSource.url);

                if (rawUrl == null) {
                    SwingUtilities.invokeLater(() -> {
                        ui.appendLog("❌ AutoFetch failed: token source URL missing.");

                        if (fetchButton != null) {
                            fetchButton.setEnabled(true);
                            fetchButton.setText("🔑");
                        }
                    });
                    return;
                }

                String resolvedUrl =
                        variableResolver.resolve(rawUrl);

                HttpUtils.HostInfo hostInfo =
                        HttpUtils.parseUrl(resolvedUrl);

                burp.api.montoya.http.HttpService service =
                        burp.api.montoya.http.HttpService.httpService(
                                hostInfo.host,
                                hostInfo.port,
                                hostInfo.useHttps
                        );

                burp.api.montoya.http.message.requests.HttpRequest httpRequest =
                        burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                                service,
                                burp.api.montoya.core.ByteArray.byteArray(raw)
                        );

                burp.api.montoya.http.message.HttpRequestResponse response =
                        burp.service.ProxyRouter.sendRequest(api, httpRequest);

                if (response == null || response.response() == null) {
                    SwingUtilities.invokeLater(() -> {
                        ui.appendLog("❌ AutoFetch failed: no response from token endpoint.");

                        if (fetchButton != null) {
                            fetchButton.setEnabled(true);
                            fetchButton.setText("🔑");
                        }
                    });
                    return;
                }

                boolean extracted =
                        authManager.extractAnyToken(
                                response.response().bodyToString()
                        );

                String fetchedToken =
                        authManager.getAccessToken();

                SwingUtilities.invokeLater(() -> {
                    if (extracted &&
                            fetchedToken != null &&
                            !fetchedToken.trim().isEmpty()) {

                        tokenField.setText(fetchedToken.trim());
                        tokenField.setForeground(burp.ui.UITheme.foreground());

                        ui.updateTokenArea(fetchedToken.trim());

                        ui.appendLog("✅ AutoFetch token populated into {{token}} field.");
                    } else {
                        ui.appendLog("❌ AutoFetch completed but no token was extracted.");
                    }

                    if (fetchButton != null) {
                        fetchButton.setEnabled(true);
                        fetchButton.setText("🔑");
                    }
                });

            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    ui.appendLog("❌ AutoFetch failed: " + ex.getMessage());

                    if (fetchButton != null) {
                        fetchButton.setEnabled(true);
                        fetchButton.setText("🔑");
                    }
                });
            }
        }).start();
    }
    public String extractRawUrl(Object urlData) {
        if (urlData == null) return null;
        
        String raw = null;
        // Handle string URL format
        if (urlData instanceof String) {
            raw = (String) urlData;
        } else {
            // Handle Url object format
            try {
                Gson gson = new Gson();
                JsonElement element = gson.toJsonTree(urlData);
                if (element.isJsonObject()) {
                    JsonObject urlObject = element.getAsJsonObject();
                    if (urlObject.has("raw")) {
                        raw = urlObject.get("raw").getAsString();
                    }
                }
            } catch (Exception e) {
                // If parsing fails, return null
            }
        }
        if (raw == null) return null;
        // Strip newlines/CRs that Postman's URL editor inserts as visual
        // line-breaks (e.g. between query params). They are NEVER part of
        // a real HTTP URL; leaving them in produces malformed requests
        // (server returns 400 Bad Request) and renders ugly in the URL bar.
        if (raw.indexOf('\n') >= 0 || raw.indexOf('\r') >= 0) {
            raw = raw.replace("\r", "").replace("\n", "");
        }
        return raw;
    }
    
    private String extractHostnameFromError(String errorMessage) {
        // Try to extract hostname from UnknownHostException message
        // Example: "java.lang.RuntimeException: java.net.UnknownHostException: hostname.example.com"
        if (errorMessage.contains("UnknownHostException")) {
            String[] parts = errorMessage.split("UnknownHostException:");
            if (parts.length > 1) {
                String hostname = parts[1].trim();
                // Remove any trailing text that might be part of the exception
                int spaceIndex = hostname.indexOf(' ');
                if (spaceIndex > 0) {
                    hostname = hostname.substring(0, spaceIndex);
                }
                return hostname;
            }
        }
        return null;
    }
    
    private String extractCleanErrorMessage(Exception e) {
        String message = e.getMessage();
        if (message == null) {
            return e.getClass().getSimpleName();
        }
        
        // Clean up common exception chain patterns
        if (message.startsWith("java.lang.RuntimeException:")) {
            message = message.substring("java.lang.RuntimeException:".length()).trim();
        }
        if (message.startsWith("java.net.")) {
            int colonIndex = message.indexOf(':');
            if (colonIndex > 0) {
                message = message.substring(colonIndex + 1).trim();
            }
        }
        
        return message.isEmpty() ? e.getClass().getSimpleName() : message;
    }
    private boolean hasRequestBody(PostmanCollection.Request request) {

        if (request == null || request.body == null) {
            return false;
        }

        PostmanCollection.Body body = request.body;

        if (body.raw != null && !body.raw.trim().isEmpty()) {
            return true;
        }

        if (body.urlencoded != null && !body.urlencoded.isEmpty()) {
            return true;
        }

        if (body.formdata != null && !body.formdata.isEmpty()) {
            return true;
        }

        if (body.graphql != null) {
            return true;
        }

        return false;
    }

    /**
     * Auto-capture common OAuth token fields from a JSON response into
     * ambient {@code {{access_token}}} / {@code {{token}}} / {@code {{id_token}}} /
     * {@code {{refresh_token}}} variables.
     * <p>
     * Postman collection exports frequently mask literal Authorization header
     * values to the string {@code "******"} for privacy. When such a header
     * is on a request, BurpMan substitutes it with {@code "Bearer {{access_token}}"}
     * so the token actually flows on the wire. That substitution only works
     * if the {@code access_token} variable has been populated somehow —
     * either by the user's own post-test scripts (which write to arbitrary
     * variable names like {@code ciam.test.oidc.token}) or by THIS method,
     * which watches every response body for well-known OAuth field names
     * and stashes them into the standard names.
     * <p>
     * Only writes if the field is present and non-empty, so it doesn't
     * clobber a good value with a null one on the next non-token response.
     */
    private void autoCaptureCommonTokens(burp.models.ExecutedRequest er) {
        if (er == null) return;
        String body = null;
        try { body = er.getResponseBody(); } catch (Throwable ignore) {}
        if (body == null || body.isEmpty()) return;
        String trimmed = body.trim();
        if (trimmed.isEmpty() || (trimmed.charAt(0) != '{' && trimmed.charAt(0) != '[')) return;
        try {
            com.google.gson.JsonElement root = com.google.gson.JsonParser.parseString(trimmed);
            if (!root.isJsonObject()) return;
            com.google.gson.JsonObject obj = root.getAsJsonObject();
            String[] fields = { "access_token", "id_token", "refresh_token", "token" };
            for (String f : fields) {
                if (obj.has(f) && obj.get(f).isJsonPrimitive()) {
                    String v = obj.get(f).getAsString();
                    if (v != null && !v.isEmpty()) {
                        variableResolver.getVariables().put(f, v);
                        ui.appendLog("🔐 auto-captured {{" + f + "}} from response ("
                            + (v.length() > 24 ? v.substring(0, 12) + "…" + v.substring(v.length()-8) : v)
                            + ")");
                    }
                }
            }
        } catch (Throwable ignore) {}
    }

    private boolean hasOAuthBodyCredentials(PostmanCollection.Request request) {

        if (request == null || request.body == null) {
            return false;
        }

        String rawUrl = extractRawUrl(request.url);
        String lowerUrl = rawUrl != null ? rawUrl.toLowerCase(java.util.Locale.ROOT) : "";

        boolean looksLikeTokenEndpoint = isLikelyTokenEndpointUrl(lowerUrl);

        if (!looksLikeTokenEndpoint) {
            return false;
        }

        return hasOAuthBodyMarkers(request.body);
    }

    private PostmanCollection.Request normalizeTokenSourceRequestForWire(PostmanCollection.Request request) {
        if (request == null) {
            return null;
        }
        Gson gson = new Gson();
        PostmanCollection.Request normalized = gson.fromJson(gson.toJson(request), PostmanCollection.Request.class);
        normalizeTokenSourceRequestForWireInPlace(normalized);
        return normalized;
    }

    private void normalizeTokenSourceRequestForWireInPlace(PostmanCollection.Request request) {
        if (request == null) {
            return;
        }

        String rawUrl = extractRawUrl(request.url);
        String lowerUrl = rawUrl != null ? rawUrl.toLowerCase(java.util.Locale.ROOT) : "";
        boolean tokenLikeUrl = isLikelyTokenEndpointUrl(lowerUrl);
        boolean oauthBody = hasOAuthBodyMarkers(request.body);
        boolean hasBody = hasRequestBody(request);
        if (!tokenLikeUrl && !oauthBody) {
            return;
        }

        if (tokenLikeUrl && hasBody
                && (request.method == null || request.method.trim().isEmpty() || "GET".equalsIgnoreCase(request.method))) {
            request.method = "POST";
        }

        if (request.body != null) {
            PostmanCollection.Body body = request.body;

            if ("formdata".equalsIgnoreCase(body.mode) && body.formdata != null && !body.formdata.isEmpty()) {
                List<PostmanCollection.UrlEncoded> converted = new ArrayList<>();
                for (PostmanCollection.FormData fd : body.formdata) {
                    if (fd == null || fd.disabled || fd.key == null || fd.key.trim().isEmpty()) {
                        continue;
                    }
                    PostmanCollection.UrlEncoded ue = new PostmanCollection.UrlEncoded();
                    ue.key = fd.key;
                    if ("file".equalsIgnoreCase(fd.type)) {
                        String src = fd.getSrcAsString();
                        ue.value = (src == null || src.isEmpty()) ? "" : "@" + src;
                    } else {
                        ue.value = fd.value;
                    }
                    converted.add(ue);
                }
                if (!converted.isEmpty()) {
                    body.urlencoded = converted;
                    body.mode = "urlencoded";
                }
            }

            if ("raw".equalsIgnoreCase(body.mode)
                    && body.raw != null
                    && !body.raw.trim().isEmpty()
                    && isLikelyRawUrlEncodedTokenBody(body, request)) {
                List<PostmanCollection.UrlEncoded> parsed = parseUrlEncodedPairs(body.raw);
                if (!parsed.isEmpty()) {
                    body.urlencoded = parsed;
                    body.mode = "urlencoded";
                }
            }

            if ((body.mode == null || body.mode.trim().isEmpty()) && body.urlencoded != null && !body.urlencoded.isEmpty()) {
                body.mode = "urlencoded";
            }
        }

        if (request.body != null && "urlencoded".equalsIgnoreCase(request.body.mode)) {
            ensureContentTypeHeader(request, "application/x-www-form-urlencoded");
        }
    }

    private static boolean isLikelyTokenEndpointUrl(String lowerUrl) {
        if (lowerUrl == null) {
            return false;
        }
        return lowerUrl.contains("/token")
            || lowerUrl.contains("oauth/token")
            || lowerUrl.contains("oauth2/token")
            || lowerUrl.contains("/oauth2/")
            || lowerUrl.contains("login.microsoftonline.com")
            || lowerUrl.contains("login.windows.net")
            || lowerUrl.contains("/connect/token");
    }

    private static boolean hasOAuthBodyMarkers(PostmanCollection.Body body) {
        if (body == null) {
            return false;
        }

        boolean hasClientId = false;
        boolean hasClientSecret = false;
        boolean hasGrantType = false;

        if (body.urlencoded != null && !body.urlencoded.isEmpty()) {
            for (PostmanCollection.UrlEncoded p : body.urlencoded) {
                if (p == null || p.disabled || p.key == null) {
                    continue;
                }
                String key = p.key.trim();
                if ("client_id".equalsIgnoreCase(key)) hasClientId = true;
                if ("client_secret".equalsIgnoreCase(key)) hasClientSecret = true;
                if ("grant_type".equalsIgnoreCase(key)) hasGrantType = true;
            }
        }

        if (body.formdata != null && !body.formdata.isEmpty()) {
            for (PostmanCollection.FormData p : body.formdata) {
                if (p == null || p.disabled || p.key == null) {
                    continue;
                }
                String key = p.key.trim();
                if ("client_id".equalsIgnoreCase(key)) hasClientId = true;
                if ("client_secret".equalsIgnoreCase(key)) hasClientSecret = true;
                if ("grant_type".equalsIgnoreCase(key)) hasGrantType = true;
            }
        }

        if (body.raw != null) {
            String lower = body.raw.toLowerCase(java.util.Locale.ROOT);
            if (lower.contains("grant_type")) hasGrantType = true;
            if (lower.contains("client_id")) hasClientId = true;
            if (lower.contains("client_secret")) hasClientSecret = true;
        }

        // Token endpoints are reliably identified by grant_type alone
        // (client_id/client_secret are optional for some grant types like
        // refresh_token or PKCE flows).
        return hasGrantType || (hasClientId && hasClientSecret);
    }

    private static List<PostmanCollection.UrlEncoded> parseUrlEncodedPairs(String rawBody) {
        List<PostmanCollection.UrlEncoded> out = new ArrayList<>();
        if (rawBody == null || rawBody.trim().isEmpty()) {
            return out;
        }
        String[] pairs = rawBody.split("&");
        for (String pair : pairs) {
            if (pair == null || pair.isEmpty()) {
                continue;
            }
            int idx = pair.indexOf('=');
            String keyPart = idx >= 0 ? pair.substring(0, idx) : pair;
            String valPart = idx >= 0 ? pair.substring(idx + 1) : "";
            String key = decodeFormComponent(keyPart);
            if (key == null || key.trim().isEmpty()) {
                continue;
            }
            PostmanCollection.UrlEncoded ue = new PostmanCollection.UrlEncoded();
            ue.key = key;
            ue.value = decodeFormComponent(valPart);
            ue.disabled = false;
            out.add(ue);
        }
        return out;
    }

    private static boolean isLikelyRawUrlEncodedTokenBody(PostmanCollection.Body body, PostmanCollection.Request request) {
        if (body == null || body.raw == null) {
            return false;
        }

        String raw = body.raw.trim();
        if (raw.isEmpty()) {
            return false;
        }

        String explicitType = findContentTypeHeader(request);
        if (explicitType != null && explicitType.toLowerCase(java.util.Locale.ROOT).contains("application/x-www-form-urlencoded")) {
            return true;
        }

        if (looksLikeJsonBody(raw) || looksLikeXmlBody(raw)) {
            return false;
        }

        if (!raw.contains("=")) {
            return false;
        }

        int validPairs = 0;
        for (String pair : raw.split("&")) {
            if (pair == null || pair.trim().isEmpty()) {
                continue;
            }
            int idx = pair.indexOf('=');
            if (idx <= 0) {
                return false;
            }
            String key = pair.substring(0, idx).trim();
            if (key.isEmpty()) {
                return false;
            }
            if (key.indexOf('{') >= 0 || key.indexOf('}') >= 0 || key.indexOf('"') >= 0 || key.indexOf(':') >= 0) {
                return false;
            }
            validPairs++;
        }
        return validPairs > 0;
    }

    private static String findContentTypeHeader(PostmanCollection.Request request) {
        if (request == null || request.header == null) {
            return null;
        }
        for (PostmanCollection.Header h : request.header) {
            if (h == null || h.key == null || h.value == null) {
                continue;
            }
            if ("content-type".equalsIgnoreCase(h.key.trim())) {
                return h.value.trim();
            }
        }
        return null;
    }

    private static boolean looksLikeJsonBody(String raw) {
        if (raw == null) return false;
        String t = raw.trim();
        return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"));
    }

    private static boolean looksLikeXmlBody(String raw) {
        if (raw == null) return false;
        String t = raw.trim();
        return t.startsWith("<") && t.contains(">");
    }

    private static String decodeFormComponent(String value) {
        try {
            return java.net.URLDecoder.decode(value == null ? "" : value, "UTF-8");
        } catch (Exception ignore) {
            return value == null ? "" : value;
        }
    }

    private static void ensureContentTypeHeader(PostmanCollection.Request request, String contentTypeValue) {
        if (request == null) {
            return;
        }
        if (request.header == null) {
            request.header = new ArrayList<>();
        }
        for (PostmanCollection.Header header : request.header) {
            if (header == null || header.key == null) {
                continue;
            }
            if ("content-type".equalsIgnoreCase(header.key.trim())) {
                header.value = contentTypeValue;
                return;
            }
        }
        PostmanCollection.Header h = new PostmanCollection.Header();
        h.key = "Content-Type";
        h.value = contentTypeValue;
        request.header.add(h);
    }

    private boolean isGraphQLRequest(PostmanCollection.Request request) {
        // Check if this is a GraphQL request
        if (request.body == null || request.body.raw == null) {
            return false;
        }
        
        // Check URL for /graphql endpoint
        String rawUrl = extractRawUrl(request.url);
        boolean hasGraphQLEndpoint = rawUrl != null && rawUrl.toLowerCase().contains("/graphql");
        
        // Check body for GraphQL query patterns
        String body = request.body.raw.toLowerCase().trim();
        boolean hasGraphQLQuery = body.contains("\"query\"") || 
                                 body.contains("\"mutation\"") || 
                                 body.contains("\"subscription\"") ||
                                 body.startsWith("query ") ||
                                 body.startsWith("mutation ") ||
                                 body.startsWith("subscription ");
        
        return hasGraphQLEndpoint || hasGraphQLQuery;
    }
    
    private String extractGraphQLOperation(String rawBody) {
        if (rawBody == null) return null;
        
        try {
            // Try to parse as JSON to extract operation name
            Gson gson = new Gson();
            JsonElement element = gson.fromJson(rawBody, JsonElement.class);
            
            if (element.isJsonObject()) {
                JsonObject queryObj = element.getAsJsonObject();
                if (queryObj.has("query")) {
                    String query = queryObj.get("query").getAsString();
                    return extractOperationFromQuery(query);
                }
            }
        } catch (Exception e) {
            // If JSON parsing fails, try text-based extraction
            return extractOperationFromQuery(rawBody);
        }
        
        return null;
    }
    private void addCollectionVariablesPreservingCurrent(PostmanCollection collection) {
    if (collection == null) {
        return;
    }

    Map<String, String> existing = new LinkedHashMap<>(variableResolver.getVariables());

    variableResolver.addCollectionVariables(collection);

    for (Map.Entry<String, String> entry : existing.entrySet()) {
        variableResolver.addCustomVariable(entry.getKey(), entry.getValue());
    }
    }
    
    private String extractOperationFromQuery(String query) {
        if (query == null) return null;
        
        // Look for operation name patterns like "query GetUser" or "mutation CreateUser"
        String[] patterns = {"query ", "mutation ", "subscription "};
        
        for (String pattern : patterns) {
            int index = query.toLowerCase().indexOf(pattern);
            if (index >= 0) {
                String afterPattern = query.substring(index + pattern.length()).trim();
                
                // Extract operation name (first word after operation type)
                String[] words = afterPattern.split("[\\s\\(\\{]");
                if (words.length > 0 && !words[0].trim().isEmpty()) {
                    String operationType = pattern.trim();
                    String operationName = words[0].trim();
                    return operationType + " " + operationName;
                }
                
                // If no name found, just return the operation type
                return pattern.trim();
            }
        }
        
        return null;
    }
    
    private static class RequestItem {
        final String name;
        final String path;
        final PostmanCollection.Request request;
        final String collectionName;
    
        RequestItem(String name, String path, PostmanCollection.Request request) {
            this(name, path, request, null);
        }
    
        RequestItem(String name, String path, PostmanCollection.Request request, String collectionName) {
            this.name = name;
            this.path = path;
            this.request = request;
            this.collectionName = collectionName;
        }
    }
    
    private boolean isPostmanDynamicVariable(String variable) {
        if (!variable.startsWith("$")) {
            return false;
        }
        
        String var = variable.toLowerCase();
        return var.equals("$guid") || 
               var.startsWith("$guid:") ||
               var.equals("$timestamp") ||
               var.startsWith("$timestamp") ||
               var.equals("$isotimestamp") ||
               var.equals("$randomint") ||
               var.startsWith("$randomint(");
    }
    private java.util.Map<String, java.util.List<RequestItem>> detectHardcodedHosts(PostmanCollection collection) {
        java.util.Map<String, java.util.List<RequestItem>> map = new java.util.LinkedHashMap<>();
        if (collection == null || collection.item == null) return map;

        java.util.List<RequestItem> requests = flattenRequests(collection.item, "", collection.info != null ? collection.info.name : null);
        for (RequestItem item : requests) {
            try {
                String rawUrl = extractRawUrl(item.request.url);
                if (rawUrl == null) continue;
                // Skip if already contains a variable
                if (rawUrl.contains("{{")) continue;

                String hostVal = null;
                try {
                    String toParse = rawUrl;
                    if (!toParse.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*")) {
                        toParse = "http://" + toParse;
                    }
                    java.net.URI uri = new java.net.URI(toParse);
                    String host = uri.getHost();
                    int port = uri.getPort();
                    if (host != null && !host.trim().isEmpty()) {
                        hostVal = host;
                        if (port != -1) hostVal += ":" + port;
                    } else {
                        // fallback regex to extract leading host[:port]
                        java.util.regex.Matcher m = java.util.regex.Pattern.compile("^([^/\\s:]+(?::\\d+)?)").matcher(rawUrl);
                        if (m.find()) hostVal = m.group(1);
                    }
                } catch (Exception ex) {
                    java.util.regex.Matcher m = java.util.regex.Pattern.compile("^([^/\\s:]+(?::\\d+)?)").matcher(rawUrl);
                    if (m.find()) hostVal = m.group(1);
                }

                if (hostVal == null || hostVal.trim().isEmpty()) continue;

                java.util.List<RequestItem> list = map.get(hostVal);
                if (list == null) {
                    list = new java.util.ArrayList<>();
                    map.put(hostVal, list);
                }
                list.add(item);
            } catch (Exception ignored) {}
        }

        return map;
    }

    private boolean promptAndConvertHosts(PostmanCollection collection, VariableResolver resolver) {
        return promptAndConvertHosts(collection, resolver, true);
    }

    private boolean promptAndConvertHosts(PostmanCollection collection, VariableResolver resolver, boolean showPrompt) {
        java.util.Map<String, java.util.List<RequestItem>> candidates = detectHardcodedHosts(collection);
        if (candidates.isEmpty()) return false;
        if (showPrompt) {
        StringBuilder sb = new StringBuilder();
        sb.append("Detected hardcoded hosts in collection:\n\n");
        for (java.util.Map.Entry<String, java.util.List<RequestItem>> e : candidates.entrySet()) {
            sb.append(e.getKey()).append(" -> ").append(e.getValue().size()).append(" requests\n");
            int c = 0;
            for (RequestItem r : e.getValue()) {
                if (c++ >= 3) break;
                sb.append("  - ").append(r.path).append("\n");
            }
            if (e.getValue().size() > 3) sb.append("  ...\n");
        }
        sb.append("\nConvert these hosts into variables (recommended)?");

        final int[] choice = new int[1];
        try {
            SwingUtilities.invokeAndWait(() -> {
                JTextArea area = new JTextArea(sb.toString());
                area.setEditable(false);
                area.setLineWrap(true);
                area.setWrapStyleWord(true);
                JScrollPane pane = new JScrollPane(area);
                Object[] options = {"Convert All (Recommended)", "Skip"};
                choice[0] = JOptionPane.showOptionDialog(ui.getPanel(), pane, "Convert Hosts to Variables", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);
            });
        } catch (Exception e) {
            return false;
        }

        if (choice[0] != 0) return false;
    }

        for (java.util.Map.Entry<String, java.util.List<RequestItem>> e : candidates.entrySet()) {
            String hostValue = e.getKey();
            String varName = registerUniqueHost(hostValue);
            resolver.addCustomVariable(varName, hostValue);

            int applied = 0;
            for (RequestItem item : e.getValue()) {
                String newRaw = replaceHostInRequestUrl(item.request, varName);
                if (newRaw != null) applied++;
            }

            ui.appendLog("Converted host " + hostValue + " -> {{" + varName + "}} applied to " + applied + " requests");
        }

        return true;
    }

    private String registerUniqueHost(String hostValue) {
        java.util.Map<String, String> vars = variableResolver.getVariables();

        if (hostValueToVar.containsKey(hostValue)) {
            String name = hostValueToVar.get(hostValue);
            ensureCollectionVariable(name, hostValue);
            return name;
        }

        for (java.util.Map.Entry<String, String> e : vars.entrySet()) {
            if (hostValue.equals(e.getValue())) {
                hostValueToVar.put(hostValue, e.getKey());
                ensureCollectionVariable(e.getKey(), hostValue);
                return e.getKey();
            }
        }

        int i = 1;
        String name;
        do {
            name = "host" + i;
            i++;
        } while (vars.containsKey(name));

        variableResolver.addCustomVariable(name, hostValue);
        // Hosts are workspace-wide: also mirror into globals so they're shared
        // across all collections (not isolated per-scope) and host1/host2/host3
        // numbering stays consistent regardless of which collection is analyzing.
        try { variableResolver.putGlobalVariable(name, hostValue); } catch (Exception ignore) {}
        hostValueToVar.put(hostValue, name);
        ensureCollectionVariable(name, hostValue);
        ui.appendLog("🌐 Registered host variable → {{" + name + "}}");
        return name;
    }

    private void ensureCollectionVariable(String key, String value) {
        if (key == null || key.trim().isEmpty() || currentCollection == null) return;
        if (currentCollection.variable == null) {
            currentCollection.variable = new java.util.ArrayList<>();
        }
        for (PostmanCollection.Variable v : currentCollection.variable) {
            if (v == null || v.key == null) continue;
            if (key.equals(v.key)) {
                if ((v.value == null || v.value.isEmpty()) && value != null) {
                    v.value = value;
                }
                return;
            }
        }
        PostmanCollection.Variable v = new PostmanCollection.Variable();
        v.key = key;
        v.value = value == null ? "" : value;
        v.type = "string";
        currentCollection.variable.add(v);
    }

    private String replaceHostInRequestUrl(PostmanCollection.Request request, String varName) {
        if (request == null) return null;
        try {
            String rawUrl = extractRawUrl(request.url);
            if (rawUrl == null) return null;
            boolean hadScheme = rawUrl.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*");
            String toParse = rawUrl;
            if (!hadScheme) {
                toParse = "http://" + rawUrl;
            }
            java.net.URI uri = new java.net.URI(toParse);
            String pathAndRest = "";
            if (uri.getPath() != null) pathAndRest += uri.getPath();
            if (uri.getQuery() != null) pathAndRest += "?" + uri.getQuery();
            if (uri.getFragment() != null) pathAndRest += "#" + uri.getFragment();

            String newRaw;
            if (hadScheme) {
                String scheme = uri.getScheme();
                newRaw = scheme + "://" + "{{" + varName + "}}" + pathAndRest;
            } else {
                newRaw = "{{" + varName + "}}" + pathAndRest;
            }

            // Replace url object with raw string to keep it simple
            request.url = newRaw;
            return newRaw;
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Build a tree representation of the collection with hierarchy
        */
    public CollectionTreeNode buildCollectionTree(List<AnalyzedRequest> requests) {

        // ✅ FIX #3 — HARD STOP when no collection
        if (currentCollection == null) {
            currentCollectionTree = null;
            return null;
        }

        // ✅ FIX #5 — EMPTY COLLECTION GUARD
        if (currentCollection.item == null || currentCollection.item.isEmpty()) {
            currentCollectionTree = null;
            return null;
        }

        // Always show the workspace as the root — promote any un-wrapped
        // items into a synthetic wrapper before rendering.
        try { ensureWorkspaceShape(); } catch (Exception ignore) {}

        CollectionTreeNode root = treeBuilder.buildTree(currentCollection, requests);
        this.currentCollectionTree = root;
        // Seed folder auth registry from the full workspace using the oauth2-
        // aware converter so inheritance stays stable after tree rebuilds.
        try {
            seedFolderAuthFullWorkspace();
        } catch (Exception ignore) { }
        return root;
    }

    private void seedFolderAuth(java.util.List<PostmanCollection.Item> items, String parentPath) {
        if (items == null) return;
        for (PostmanCollection.Item it : items) {
            if (it == null) continue;
            String name = it.name == null ? "" : it.name;
            String path = parentPath.isEmpty() ? name : parentPath + "/" + name;
            // Folder-level auth (item has children → it's a folder)
            if (it.item != null && !it.item.isEmpty()) {
                if (it.auth != null) {
                    burp.auth.FolderAuthOverride ov = convertAuthToOverride(it.auth);
                    if (ov != null) folderAuthRegistry.set(path, ov);
                }
                seedFolderAuth(it.item, path);
            }
        }
    }

    private burp.auth.FolderAuthOverride convertAuthToOverride(PostmanCollection.Auth a) {
        if (a == null || a.type == null) return null;
        burp.auth.FolderAuthOverride ov = new burp.auth.FolderAuthOverride();
        String t = a.type.toLowerCase();
        if ("noauth".equals(t)) {
            ov.type = burp.auth.FolderAuthOverride.Type.NO_AUTH;
            return ov;
        }
        if ("bearer".equals(t)) {
            ov.type = burp.auth.FolderAuthOverride.Type.BEARER;
            String token = extractBearerTokenFromAuth(a);
            if (token != null) ov.put("token", token);
            return ov;
        }
        if ("basic".equals(t)) {
            ov.type = burp.auth.FolderAuthOverride.Type.BASIC;
            return ov;
        }
        return null;
    }

    private String extractBearerTokenFromAuth(PostmanCollection.Auth a) {
        try {
            Object b = a.bearer;
            if (b instanceof java.util.List) {
                for (Object e : (java.util.List<?>) b) {
                    if (e instanceof java.util.Map) {
                        java.util.Map<?, ?> m = (java.util.Map<?, ?>) e;
                        Object k = m.get("key"); Object v = m.get("value");
                        if (k != null && "token".equalsIgnoreCase(k.toString()) && v != null) {
                            return v.toString();
                        }
                    }
                }
            }
        } catch (Exception ignore) { }
        return null;
    }
    /**
     * Get the current collection tree
     */
    public CollectionTreeNode getCurrentCollectionTree() {
        if (currentCollection == null 
            || currentCollection.item == null 
            || currentCollection.item.isEmpty()) {

            return null;
        }

        return currentCollectionTree;
    }
    
    /**
     * Send a single analyzed request to Burp Repeater with optional auth.
     * Uses the same resolution path as the click handler in ImporterPanel:
     * variable resolution + FolderAuthRegistry override + Content-Type derivation.
     */
    public void sendRequestToRepeater(AnalyzedRequest analyzedRequest, boolean withAuth) throws Exception {
        burp.api.montoya.http.message.requests.HttpRequest httpReq = buildHttpRequestForSend(analyzedRequest, withAuth);
        if (httpReq == null) throw new Exception("Failed to build request");
        String tabName = (analyzedRequest.getRequest() != null && analyzedRequest.getRequest().method != null
                ? analyzedRequest.getRequest().method.toUpperCase() : "REQ")
                + " - " + analyzedRequest.getName();
        api.repeater().sendToRepeater(httpReq, tabName);
        ui.appendLog("➡️ Sent to Repeater: " + analyzedRequest.getName() + (withAuth ? " (with auth)" : ""));
    }

    /**
     * Build a Montoya HttpRequest from an AnalyzedRequest, applying variable
     * resolution, FolderAuthRegistry override, Content-Type derivation, etc.
     * Used by sendRequestToRepeater and sendRequestToTool.
     */
    private burp.api.montoya.http.message.requests.HttpRequest buildHttpRequestForSend(
            AnalyzedRequest analyzedRequest, boolean withAuth) throws Exception {

        if (analyzedRequest == null || analyzedRequest.getRequest() == null) {
            throw new Exception("Invalid request");
        }

        PostmanCollection.Request orig = analyzedRequest.getRequest();
        VariableResolver resolver = variableResolver;

        // Clone request so we don't mutate the analyzed source
        PostmanCollection.Request clone = new PostmanCollection.Request();
        clone.method = orig.method;

        String urlStr = orig.url != null ? extractRawUrl(orig.url) : "";
        if (urlStr == null) urlStr = "";
        clone.url = resolver != null ? resolver.resolve(urlStr) : urlStr;

        // Headers
        clone.header = new ArrayList<>();
        if (orig.header != null) {
            for (PostmanCollection.Header h : orig.header) {
                if (h == null || h.key == null || h.key.trim().isEmpty()) continue;
                if (h.disabled) continue;
                PostmanCollection.Header nh = new PostmanCollection.Header();
                nh.key = resolver != null ? resolver.resolve(h.key) : h.key;
                nh.value = resolver != null ? resolver.resolve(h.value) : h.value;
                clone.header.add(nh);
            }
        }

        // Body
        if (orig.body != null) {
            clone.body = new PostmanCollection.Body();
            clone.body.mode = orig.body.mode;
            // Only copy body.raw when mode is actually raw (or unknown). If a
            // script left body.raw set on a formdata/urlencoded request, the
            // downstream loadRequest/wire-builder would mis-route to the raw
            // branch and drop the structured entries.
            String origMode = orig.body.mode == null ? "" : orig.body.mode.toLowerCase();
            if (!"formdata".equals(origMode) && !"urlencoded".equals(origMode)) {
                clone.body.raw = resolver != null ? resolver.resolve(orig.body.raw) : orig.body.raw;
            }
            clone.body.options = orig.body.options;
            if (orig.body.graphql != null) {
                clone.body.graphql = new PostmanCollection.GraphQL();
                clone.body.graphql.query = resolver != null
                    ? resolver.resolve(orig.body.graphql.query)
                    : orig.body.graphql.query;
                clone.body.graphql.variables = resolver != null
                    ? resolver.resolve(orig.body.graphql.variables)
                    : orig.body.graphql.variables;
            }
            if (orig.body.urlencoded != null) {
                clone.body.urlencoded = new ArrayList<>();
                for (PostmanCollection.UrlEncoded ue : orig.body.urlencoded) {
                    PostmanCollection.UrlEncoded copy = new PostmanCollection.UrlEncoded();
                    copy.key = resolver != null ? resolver.resolve(ue.key) : ue.key;
                    copy.value = resolver != null ? resolver.resolve(ue.value) : ue.value;
                    copy.disabled = ue.disabled;
                    clone.body.urlencoded.add(copy);
                }
            }
            if (orig.body.formdata != null) {
                clone.body.formdata = new ArrayList<>();
                for (PostmanCollection.FormData fd : orig.body.formdata) {
                    PostmanCollection.FormData copy = new PostmanCollection.FormData();
                    copy.key = resolver != null ? resolver.resolve(fd.key) : fd.key;
                    copy.value = resolver != null ? resolver.resolve(fd.value) : fd.value;
                    copy.type = fd.type;
                    copy.src = fd.src;
                    copy.disabled = fd.disabled;
                    clone.body.formdata.add(copy);
                }
            }
        }

        boolean isTokenEndpoint = hasOAuthBodyCredentials(orig);
        String urlLower = clone.url == null ? "" : clone.url.toString().toLowerCase();
        boolean looksLikeTokenEndpoint = isTokenEndpoint
            || isLikelyTokenEndpointUrl(urlLower);

        if (looksLikeTokenEndpoint) {
            normalizeTokenSourceRequestForWireInPlace(clone);
        }

        if (withAuth && !looksLikeTokenEndpoint) {
            // Apply FolderAuthRegistry override based on the request's path.
            // AnalyzedRequest.path uses "/" as separator, matching FolderAuthRegistry keys.
            String regKey = "";
            String reqPath = analyzedRequest.getPath();
            if (reqPath != null && !reqPath.isEmpty()) {
                int slash = reqPath.lastIndexOf('/');
                regKey = slash >= 0 ? reqPath.substring(0, slash) : "";
            }
            burp.auth.FolderAuthOverride ov = folderAuthRegistry.resolve(regKey);
            ui.appendLog("🔍 Repeater auth lookup: path=\"" + regKey + "\" → "
                + (ov == null ? "none" : ov.type.label));

            // Check if the request itself already has a real Authorization
            boolean hasOwnAuth = false;
            for (PostmanCollection.Header h : clone.header) {
                if ("authorization".equalsIgnoreCase(h.key)
                    && h.value != null && !h.value.trim().isEmpty()
                    && !h.value.contains("{{")) { hasOwnAuth = true; break; }
            }
            if (!hasOwnAuth && ov != null) {
                clone.header.removeIf(h -> "authorization".equalsIgnoreCase(h.key));
                burp.auth.FolderAuthApplier.apply(ov, clone);
            } else if (!hasOwnAuth) {
                // Fallback: request.auth bearer if present
                String reqToken = extractBearer(orig.auth);
                if (reqToken != null && !reqToken.isEmpty()) {
                    clone.header.removeIf(h -> "authorization".equalsIgnoreCase(h.key));
                    PostmanCollection.Header ah = new PostmanCollection.Header();
                    ah.key = "Authorization";
                    ah.value = "Bearer " + reqToken;
                    clone.header.add(ah);
                }
            }

            // Final variable pass (in case applier wrote {{token}} from override)
            if (resolver != null) {
                for (PostmanCollection.Header h : clone.header) {
                    if (h.value != null) h.value = resolver.resolve(h.value);
                }
            }
        }

        // Strip any leftover Authorization on token endpoints
        if (looksLikeTokenEndpoint) {
            clone.header.removeIf(h -> "authorization".equalsIgnoreCase(h.key));
        }

        // Auto Content-Type from body
        if (clone.body != null && clone.body.mode != null) {
            boolean hasCt = false;
            for (PostmanCollection.Header h : clone.header) {
                // Skip disabled headers — Bruno's ~Content-Type: application/xml
                // is a commented-out declaration. If we treated it as present,
                // we'd skip auto-injection and the wire would go out with no
                // Content-Type at all (disabled headers aren't serialized).
                if (h == null || h.disabled) continue;
                if (h.key != null && "content-type".equalsIgnoreCase(h.key.trim())) { hasCt = true; break; }
            }
            if (!hasCt) {
                String ct = null;
                String mode = clone.body.mode.toLowerCase();
                if ("raw".equals(mode)) {
                    String lang = (clone.body.options != null && clone.body.options.raw != null)
                        ? clone.body.options.raw.language : null;
                    if (lang != null) {
                        switch (lang.toLowerCase()) {
                            case "json": ct = "application/json"; break;
                            case "xml": ct = "application/xml"; break;
                            case "html": ct = "text/html"; break;
                            case "javascript": ct = "application/javascript"; break;
                            default: ct = "text/plain"; break;
                        }
                    } else if (clone.body.raw != null) {
                        String s = clone.body.raw.trim();
                        if (s.startsWith("{") || s.startsWith("[")) ct = "application/json";
                        else if (s.startsWith("<")) ct = "application/xml";
                    }
                } else if ("urlencoded".equals(mode)) ct = "application/x-www-form-urlencoded";
                else if ("formdata".equals(mode)) ct = "multipart/form-data";
                else if ("graphql".equals(mode)) ct = "application/json";
                if (ct != null) {
                    PostmanCollection.Header h = new PostmanCollection.Header();
                    h.key = "Content-Type";
                    h.value = ct;
                    clone.header.add(h);
                }
            }
        }

        // Build raw HTTP request and hand off to Burp Repeater
        java.net.URL parsedUrl = new java.net.URL(clone.url.toString());
        String host = parsedUrl.getHost();
        int port = parsedUrl.getPort();
        boolean isHttps = "https".equalsIgnoreCase(parsedUrl.getProtocol());
        if (port == -1) port = isHttps ? 443 : 80;
        String path = parsedUrl.getPath();
        if (parsedUrl.getQuery() != null) path += "?" + parsedUrl.getQuery();
        if (path.isEmpty()) path = "/";

        StringBuilder raw = new StringBuilder();
        raw.append(clone.method != null ? clone.method : "GET").append(' ').append(path).append(" HTTP/1.1\r\n");
        raw.append("Host: ").append(host).append("\r\n");
        boolean hasCl = false;
        for (PostmanCollection.Header h : clone.header) {
            if (h.key == null || h.value == null) continue;
            if ("host".equalsIgnoreCase(h.key)) continue;
            if ("content-length".equalsIgnoreCase(h.key)) hasCl = true;
            raw.append(h.key).append(": ").append(h.value).append("\r\n");
        }

        // Build body bytes
        byte[] bodyBytes = new byte[0];
        if (clone.body != null) {
            String bodyStr = null;
            if ("urlencoded".equalsIgnoreCase(clone.body.mode) && clone.body.urlencoded != null) {
                StringBuilder sb = new StringBuilder();
                for (PostmanCollection.UrlEncoded ue : clone.body.urlencoded) {
                    if (ue.disabled) continue;
                    if (sb.length() > 0) sb.append('&');
                    sb.append(java.net.URLEncoder.encode(ue.key == null ? "" : ue.key, "UTF-8"));
                    sb.append('=');
                    sb.append(java.net.URLEncoder.encode(ue.value == null ? "" : ue.value, "UTF-8"));
                }
                bodyStr = sb.toString();
            } else if ("graphql".equalsIgnoreCase(clone.body.mode) && clone.body.graphql != null) {
                StringBuilder sb2 = new StringBuilder();
                sb2.append("{\"query\":");
                sb2.append(jsonStringLiteral(clone.body.graphql.query == null ? "" : clone.body.graphql.query));
                String vars = clone.body.graphql.variables;
                if (vars != null && !vars.trim().isEmpty()) {
                    sb2.append(",\"variables\":");
                    String t = vars.trim();
                    boolean looksJson = (t.startsWith("{") && t.endsWith("}"))
                                     || (t.startsWith("[") && t.endsWith("]"));
                    sb2.append(looksJson ? t : jsonStringLiteral(vars));
                }
                sb2.append("}");
                bodyStr = sb2.toString();
            } else if (clone.body.raw != null) {
                bodyStr = clone.body.raw;
            }
            if (bodyStr != null) bodyBytes = bodyStr.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }
        // PUT/POST/PATCH/DELETE always need Content-Length, even when body is
        // empty — many servers reject these methods without it.
        String method = clone.method == null ? "GET" : clone.method.toUpperCase();
        boolean needCl = "POST".equals(method) || "PUT".equals(method)
                      || "PATCH".equals(method) || "DELETE".equals(method)
                      || bodyBytes.length > 0;
        if (!hasCl && needCl) raw.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
        raw.append("\r\n");

        byte[] head = raw.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] full = new byte[head.length + bodyBytes.length];
        System.arraycopy(head, 0, full, 0, head.length);
        System.arraycopy(bodyBytes, 0, full, head.length, bodyBytes.length);

        burp.api.montoya.http.HttpService svc = burp.api.montoya.http.HttpService.httpService(host, port, isHttps);
        burp.api.montoya.http.message.requests.HttpRequest httpReq =
            burp.api.montoya.http.message.requests.HttpRequest.httpRequest(svc, burp.api.montoya.core.ByteArray.byteArray(full));
        return httpReq;
    }

    /**
     * Send a request to Intruder or Organizer using the same build pipeline.
     * tool ∈ {"intruder","organizer","repeater"}.
     */
    public void sendRequestToTool(AnalyzedRequest analyzedRequest, boolean withAuth, String tool) throws Exception {
        if (tool == null) tool = "repeater";
        String t = tool.trim().toLowerCase();
        if ("repeater".equals(t)) {
            sendRequestToRepeater(analyzedRequest, withAuth);
            return;
        }
        burp.api.montoya.http.message.requests.HttpRequest httpReq = buildHttpRequestForSend(analyzedRequest, withAuth);
        if (httpReq == null) throw new Exception("Failed to build request");
        String label = (analyzedRequest.getRequest() != null && analyzedRequest.getRequest().method != null
                ? analyzedRequest.getRequest().method.toUpperCase() : "REQ")
                + " - " + analyzedRequest.getName();
        switch (t) {
            case "intruder":
                api.intruder().sendToIntruder(httpReq);
                ui.appendLog("➡️ Sent to Intruder: " + label + (withAuth ? " (with auth)" : ""));
                break;
            case "organizer":
                api.organizer().sendToOrganizer(httpReq);
                ui.appendLog("➡️ Sent to Organizer: " + label + (withAuth ? " (with auth)" : ""));
                break;
            default:
                throw new Exception("Unknown tool: " + tool);
        }
    }

    private void __unused_legacy_sendRequestToRepeaterTail() {
    }

    /**
     * Logging method for tree panel
     */
    public void log(String message) {
        ui.appendLog(message);
    }

    private static String jsonStringLiteral(String s) {
        if (s == null) return "\"\"";
        StringBuilder b = new StringBuilder(s.length() + 8);
        b.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        b.append('"');
        return b.toString();
    }

}