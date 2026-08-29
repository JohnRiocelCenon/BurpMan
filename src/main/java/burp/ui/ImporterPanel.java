package burp.ui;

import burp.PostmanImporter;
import burp.models.PostmanCollection;
import burp.models.ImportResult;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.auth.AuthManager;
import burp.auth.AuthManagerPanel;
import burp.auth.JwtEndpointCandidate;
import burp.auth.OAuth2Config;

public class ImporterPanel {
    private final PostmanImporter importer;
    private final JPanel mainPanel;
    private JTextArea logArea;  // Removed final
    private JProgressBar progressBar;  // Removed final
    private JButton importButton;  // Removed final
    private JButton runPreviewButton;
    private JButton previewButton;  // Added preview button field
    private JButton retryButton;   // Added retry button field
    private JButton cancelButton;  // Removed final
    private JButton recentBtn;     // ▾ button next to Browse for recent files
    private JTextField collectionField;  // Removed final
    private JTextField environmentField;  // legacy field (now hidden/optional)
    private File selectedGlobals;
    private JComboBox<EnvOption> environmentCombo;
    private final java.util.List<EnvOption> loadedEnvironments = new java.util.ArrayList<>();

    /** Buttons revealed only inside the Advanced popup. */
    private JButton advancedOpenApiBtn;
    private JButton advancedExportBtn;
    private JButton advancedSaveEnvBtn;

    /** Wrapper for the environment dropdown items. */
    private static class EnvOption {
        final java.io.File file;     // null = "No Environment"
        final String displayName;
        EnvOption(java.io.File f, String name) { this.file = f; this.displayName = name; }
        @Override public String toString() { return displayName; }
    }
    private ButtonGroup destinationGroup;  // Added for destination selection
    private JRadioButton repeaterOption;
    private JRadioButton sitemapOption;
    private JRadioButton bothOption;
    private final AuthManager authManager;
    private File selectedCollection;
    private File selectedEnvironment;
    /** Bruno-style workspace folder for the currently-loaded collection.
     *  Persistent home under ~/Documents/BurpMan-Workspaces/&lt;name&gt;/
     *  (or ~/BurpMan-Workspaces/&lt;name&gt;/ on non-Windows) that holds
     *  {@code .env} and {@code environments/} for the collection so envs
     *  survive across sessions even when the source is a single JSON. */
    private File currentWorkspace;
    private JPanel overviewPanel;
    private JLabel overviewCollectionName;
    private JLabel overviewLocation;
    private JLabel overviewWorkspace;
    private JLabel overviewEnvsSummary;
    /** Bruno-style ENVIRONMENTS list rendered inside the Overview tab —
     *  radio buttons for each loaded env plus a "(none)" option, split
     *  into "ENVIRONMENTS" and ".ENV FILES" sections. Rebuilt on every
     *  {@link #refreshOverviewPanel()} call. */
    private JPanel overviewEnvsList;
    private JLabel overviewLinkedFolder;
    private JLabel overviewRequestCount;
    /** Sticky per-session import-dialog preferences. Populated from the
     *  first successful Import Collection dialog and used to prefill the
     *  Location and File Format fields on subsequent imports so the user
     *  doesn't have to re-enter them every time. */
    private String preferredImportLocation;
    private String preferredEnvFormat = "bru";
    /** Bruno-style always-on {@code .env} overlay. Discovered {@code .env}
     *  files sit in {@link #dotenvFiles} (never in {@link #environmentCombo}
     *  — that's for mutually-exclusive flat environments only), and at
     *  most ONE is active at a time via {@link #activeDotEnvFile}. This
     *  matches Bruno's model: pick one env, pick one `.env` overlay,
     *  both stay active simultaneously.
     *
     *  <p>Users can still add multiple {@code .env} files (e.g.
     *  {@code .env}, {@code .env.uat}, {@code .env.prod}) and swap
     *  between them like a radio, but only the currently-selected one
     *  contributes {@code process.env.*} values. */
    private final java.util.List<File> dotenvFiles = new java.util.ArrayList<>();
    private File activeDotEnvFile;
    private AuthManagerPanel authManagerPanel;
    private CollectionTreePanel treePanel;
    private RequestBuilderPanel builderPanel;
    private burp.ui.AppToolbar appToolbarField;
    private burp.ui.RequestTabsPanel requestTabsPanel;
    private burp.ui.SnippetPanel snippetPanel;
    private burp.ui.ConsolePanel consolePanel;
    private burp.models.RequestHistory requestHistory;
    private ResponsePanel responsePanel;
    private RunResultsPanel runResultsPanel;
    /** Postman-style open-requests tab strip above the single shared builder. */
    private burp.ui.OpenRequestTabsStrip openTabsStrip;
    /** Persistent workspace store — loaded collection / env paths roundtripped
     *  to ~/.burpman/workspaces.json so a Burp restart keeps the user's setup. */
    private final burp.ui.WorkspaceStore workspaceStore = new burp.ui.WorkspaceStore();
    /** Right-side tabbed pane (Auth Manager / Request Builder / History /
     *  Run Results / Cookies). Stored so showRunResultsTab() can switch
     *  to it programmatically when a Run Scripts batch starts. */
    private JTabbedPane rightTabbedPaneField;
    // Per-request edit cache: keyed by full path (folder + name); preserves user edits when
    // switching between requests in the tree.
    private final java.util.Map<String, burp.models.PostmanCollection.Request> requestEditCache =
        java.util.Collections.synchronizedMap(new java.util.LinkedHashMap<String, burp.models.PostmanCollection.Request>(64, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(java.util.Map.Entry<String, burp.models.PostmanCollection.Request> eldest) {
                return size() > 200;
            }
        });
    /** Reverse index from cache key -> underlying collection request object. */
    private final java.util.Map<String, burp.models.PostmanCollection.Request> requestSourceByKey =
        java.util.Collections.synchronizedMap(new java.util.HashMap<>());
    private String currentLoadedKey = null;
    /** True while {@code builderPanel.loadRequest()} is running so the
     *  live edit-cache save (wired in via {@link RequestBuilderPanel#addEditListener})
     *  doesn't persist the *previous* request's tail-end edits under the
     *  *new* request's key during the clear→reload cycle. */
    private volatile boolean suppressEditCacheSave = false;
    /** Per-request response cache: keyed by full path; preserves last-received
     *  HTTP response so switching back to a request restores its prior result
     *  instead of showing a blank pane. Mirrors Postman behavior. */
    private final java.util.Map<String, burp.models.ExecutedRequest> requestResponseCache =
        java.util.Collections.synchronizedMap(new java.util.LinkedHashMap<String, burp.models.ExecutedRequest>(64, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(java.util.Map.Entry<String, burp.models.ExecutedRequest> eldest) {
                return size() > 200;
            }
        });
    private burp.models.CollectionTreeNode currentClickedNode = null;
    private burp.models.PostmanCollection.Request currentPmRequest = null;
    /** Keys explicitly saved by the user via the Builder's Save button —
     *  these snapshots survive automatic cache clears (post-script var changes,
     *  Edit Variables refresh, etc). */
    private final java.util.Set<String> savedKeys = java.util.Collections.synchronizedSet(new java.util.HashSet<>());
    /** Drop cached request snapshots that the user has NOT explicitly Saved. */
    private void clearUnsavedCache() {
        synchronized (requestEditCache) {
            requestEditCache.keySet().removeIf(k -> !savedKeys.contains(k));
        }
    }

    /**
     * Postman path-variable bridge:
     * raw URL may use /:country with values in url.variable[].
     * Convert those to template/literal form so resolver and UI can render/send correctly.
     */
    private static String normalizePostmanPathTemplate(String rawUrl, Object originalUrlObject) {
        if (rawUrl == null || rawUrl.isEmpty()) return rawUrl;
        PostmanCollection.Url u = tryParseUrlObject(originalUrlObject);
        if (u == null || u.variable == null || u.variable.isEmpty()) return rawUrl;
        String out = rawUrl;
        for (PostmanCollection.Variable v : u.variable) {
            if (v == null || v.key == null || v.key.trim().isEmpty()) continue;
            String key = v.key.trim();
            String value = v.value == null || v.value.trim().isEmpty() ? "{{" + key + "}}" : v.value.trim();
            out = out.replaceAll("(?<=/):" + Pattern.quote(key) + "(?=([/?#]|$))",
                    Matcher.quoteReplacement(value));
        }
        return out;
    }

    private static PostmanCollection.Url tryParseUrlObject(Object urlObject) {
        if (urlObject == null) return null;
        if (urlObject instanceof PostmanCollection.Url) {
            return (PostmanCollection.Url) urlObject;
        }
        try {
            Gson gson = new Gson();
            JsonElement el = gson.toJsonTree(urlObject);
            if (el != null && el.isJsonObject()) {
                return gson.fromJson(el, PostmanCollection.Url.class);
            }
        } catch (Exception ignore) {}
        return null;
    }

    /** Build a collision-safe cache key for the currently focused request.
     *  Large imported packs can contain duplicate request names in the same
     *  folder; include request identity so Builder/response caches never alias. */
    private String buildRequestCacheKey(
            burp.models.AnalyzedRequest analyzedRequest,
            burp.models.CollectionTreeNode clickedNode) {
        String reqName = "";
        String folderPath = "";

        try {
            if (clickedNode != null) {
                reqName = clickedNode.toString();
                javax.swing.tree.TreeNode parent = clickedNode.getParent();
                if (parent instanceof burp.models.CollectionTreeNode) {
                    folderPath = CollectionTreePanel.nodePathKey((burp.models.CollectionTreeNode) parent);
                }
            }
        } catch (Exception ignore) { }

        if ((reqName == null || reqName.isEmpty()) && analyzedRequest != null && analyzedRequest.getName() != null) {
            reqName = analyzedRequest.getName();
        }

        if ((folderPath == null || folderPath.isEmpty()) && analyzedRequest != null && analyzedRequest.getPath() != null) {
            String p = analyzedRequest.getPath().replace('\\', '/');
            int slash = p.lastIndexOf('/');
            if (slash > 0) folderPath = p.substring(0, slash);
        }

        int reqIdentity = 0;
        try {
            if (clickedNode != null
                    && clickedNode.getRawItem() != null
                    && clickedNode.getRawItem().request != null) {
                reqIdentity = System.identityHashCode(clickedNode.getRawItem().request);
            } else if (analyzedRequest != null && analyzedRequest.getRequest() != null) {
                reqIdentity = System.identityHashCode(analyzedRequest.getRequest());
            }
        } catch (Exception ignore) { }

        StringBuilder key = new StringBuilder();
        if (folderPath != null && !folderPath.isEmpty()) key.append(folderPath);
        key.append('/').append(reqName == null ? "" : reqName);
        if (reqIdentity != 0) key.append('#').append(reqIdentity);
        return key.toString();
    }

    public ImporterPanel(PostmanImporter importer) {
        this(importer, importer.getAuthManager());
    }
    public File getSelectedCollection() {
        return selectedCollection;
    }
    
    public File getSelectedEnvironment() {
        return selectedEnvironment;
    }
    private burp.ui.FolderAuthEditorPanel folderEditorRef;
    public void updateAuthDetectionFull(
        java.util.List<OAuth2Config> oauth,
        java.util.List<JwtEndpointCandidate> jwt,
        java.util.List<String> staticTokens) {

        authManagerPanel.updateJwtDetection(jwt, staticTokens);
        if (folderEditorRef != null) folderEditorRef.setJwtCandidates(jwt);
    }
    public ImporterPanel(PostmanImporter importer, AuthManager authManager) {
        this.importer = importer;
        this.authManager = authManager;
        this.mainPanel = createUI();
        if (this.startupZoomScale < 0.999f) {
            try { applyZoomScale(this.startupZoomScale); } catch (Exception ignore) {}
        }
        // Persistence disabled - user request. Re-enable later if needed.
        // try { restoreLastWorkspace(); } catch (Throwable ignore) {}
    }
    public void clearAllUI() {

        // ✅ Clear logs
        logArea.setText("");
    
        // ✅ Reset progress
        progressBar.setValue(0);
    
        // ✅ Clear JWT + OAuth panel
        if (authManagerPanel != null) {
            authManagerPanel.clear(); // ✅ MUST exist (next step)
        }

        // ✅ Reset the Request Builder so the Send button isn't stuck on
        //    "Stop" after a Restart, and stale URL/headers are cleared.
        if (builderPanel != null) {
            try { builderPanel.clearBuilder(); } catch (Exception ignore) {}
        }

        // ✅ Hide the "Run Scripts" banner — it pins to the tree from a
        //    prior analyze and otherwise survives Restart / Clear.
        hideRunScriptsBanner();

        // ✅ Drop the collection + workspace state so the Overview tab
        //    shows "(not loaded)" everywhere after Restart instead of
        //    leaking the previous session's PDP folder path.
        selectedCollection = null;
        currentWorkspace = null;
        selectedEnvironment = null;
        if (loadedEnvironments != null) loadedEnvironments.clear();
        // Also drop .env overlays so Restart doesn't leak process.env.*
        // values from the previous workspace into the next one.
        if (dotenvFiles != null) dotenvFiles.clear();
        activeDotEnvFile = null;
        try {
            burp.parser.VariableResolver r = importer.getVariableResolver();
            if (r != null) r.clearProcessEnvVariables();
        } catch (Exception ignore) {}
        if (environmentCombo != null) {
            try {
                environmentCombo.removeAllItems();
                environmentCombo.addItem(new EnvOption(null, "— No Environment —"));
                environmentCombo.setSelectedIndex(0);
            } catch (Exception ignore) {}
        }
        if (collectionField != null) collectionField.setText("");
        if (previewButton != null) previewButton.setEnabled(false);
        if (importButton != null) importButton.setEnabled(false);
        // ✅ Empty the collection tree so old requests don't linger.
        if (treePanel != null) {
            try { treePanel.clearTree(); } catch (Exception ignore) {}
        }
        try { refreshOverviewPanel(); } catch (Exception ignore) {}

        appendLog("🔄 UI fully reset");
    }
    
    private JButton setVarsButton;
    private JPanel rightCardHostRef;
    /** Banner that surfaces "Run Scripts" CTA after Analyze finds pre/post-scripts. */
    private JPanel runScriptsBanner;
    private JLabel runScriptsBannerLabel;
    private JButton runScriptsBannerButton;
    private JButton runScriptsBannerDismiss;
    private float uiZoomScale = 1.0f;
    private float startupZoomScale = 1.0f;
    private final java.util.Map<java.awt.Component, java.awt.Font> zoomBaseFonts =
            new java.util.WeakHashMap<>();
    private void setRightTabsVisible(JTabbedPane tabs, boolean show) {
        if (rightCardHostRef == null) return;
        ((CardLayout) rightCardHostRef.getLayout())
                .show(rightCardHostRef, show ? "TABS" : "WORKSPACE");
    }

    private void installZoomShortcuts(JComponent root) {
        if (root == null) return;
        int modifier = UndoSupport.getMenuShortcutMaskCompat();
        javax.swing.InputMap im = root.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
        javax.swing.ActionMap am = root.getActionMap();
        im.put(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_EQUALS, modifier), "burpman-zoom-in");
        im.put(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_EQUALS, modifier | java.awt.event.InputEvent.SHIFT_DOWN_MASK), "burpman-zoom-in");
        im.put(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ADD, modifier), "burpman-zoom-in");
        im.put(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_MINUS, modifier), "burpman-zoom-out");
        im.put(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_SUBTRACT, modifier), "burpman-zoom-out");
        im.put(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_0, modifier), "burpman-zoom-reset");

        am.put("burpman-zoom-in", new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent e) { applyZoomScale(uiZoomScale + 0.10f); }
        });
        am.put("burpman-zoom-out", new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent e) { applyZoomScale(uiZoomScale - 0.10f); }
        });
        am.put("burpman-zoom-reset", new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent e) { applyZoomScale(1.0f); }
        });
    }

    private void applyZoomScale(float requestedScale) {
        float clamped = Math.max(0.70f, Math.min(1.80f, requestedScale));
        if (Math.abs(clamped - uiZoomScale) < 0.001f) return;
        uiZoomScale = clamped;
        if (mainPanel != null) {
            scaleFontsRecursive(mainPanel);
            mainPanel.revalidate();
            mainPanel.repaint();
        }
        appendLog(String.format(java.util.Locale.ROOT, "🔎 UI zoom %.0f%% (Ctrl +/- , Ctrl+0 reset)", uiZoomScale * 100f));
    }

    private void scaleFontsRecursive(java.awt.Component c) {
        if (c == null) return;
        java.awt.Font current = c.getFont();
        if (current != null) {
            java.awt.Font base = zoomBaseFonts.get(c);
            if (base == null) {
                float safe = (uiZoomScale <= 0f ? 1f : uiZoomScale);
                float baseSize = current.getSize2D() / safe;
                if (baseSize <= 0f) baseSize = current.getSize2D();
                base = current.deriveFont(current.getStyle(), baseSize);
                zoomBaseFonts.put(c, base);
            }
            float target = Math.max(8f, base.getSize2D() * uiZoomScale);
            if (Math.abs(current.getSize2D() - target) > 0.10f || current.getStyle() != base.getStyle()) {
                c.setFont(base.deriveFont(base.getStyle(), target));
            }
        }
        if (c instanceof JTable) {
            JTable t = (JTable) c;
            int targetRow = Math.max(18, Math.round(22f * uiZoomScale));
            if (t.getRowHeight() != targetRow) t.setRowHeight(targetRow);
        }
        if (c instanceof java.awt.Container) {
            for (java.awt.Component child : ((java.awt.Container) c).getComponents()) {
                scaleFontsRecursive(child);
            }
        }
    }
    private JPanel buildWorkspaceOverview() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(UITheme.surface());
        JPanel center = new JPanel();
        center.setLayout(new BoxLayout(center, BoxLayout.Y_AXIS));
        center.setOpaque(false);
        center.setBorder(BorderFactory.createEmptyBorder(40, 40, 40, 40));

        JLabel title = new JLabel("Workspace");
        title.setFont(UITheme.boldFont(22f));
        title.setForeground(UITheme.ACCENT);
        title.setAlignmentX(Component.LEFT_ALIGNMENT);

        JTextArea sub = new JTextArea(
                "Select a collection, folder, or request from the left tree to start working.\n"
                + "Use \"+ Add Collection\" to import another Postman/Bruno collection into this workspace.");
        sub.setEditable(false);
        sub.setOpaque(false);
        sub.setLineWrap(true);
        sub.setWrapStyleWord(true);
        sub.setFont(UITheme.baseFont().deriveFont(Font.PLAIN, 13f));
        sub.setForeground(UITheme.subtleText());
        sub.setAlignmentX(Component.LEFT_ALIGNMENT);
        sub.setBorder(BorderFactory.createEmptyBorder(10, 0, 20, 0));

        JTextArea tips = new JTextArea(
                "Tips\n"
                + "  • Right-click a collection → Analyze this Collection (auth scan) to scan only it.\n"
                + "  • Open Edit Variables and pick a Collection scope to override host/token per-collection.\n"
                + "  • Drag-and-drop requests in the tree to reorder them.\n"
                + "  • Right-click → Remove Collection from Workspace to unload one.");
        tips.setEditable(false);
        tips.setOpaque(false);
        tips.setLineWrap(true);
        tips.setWrapStyleWord(true);
        tips.setFont(UITheme.baseFont().deriveFont(Font.PLAIN, 12f));
        tips.setForeground(UITheme.foreground());
        tips.setAlignmentX(Component.LEFT_ALIGNMENT);

        center.add(title);
        center.add(sub);
        center.add(tips);
        p.add(center, BorderLayout.NORTH);
        return p;
    }
    private JPanel createUI() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        Dimension screenSize = null;
        boolean compactDisplay = false;
        try {
            screenSize = Toolkit.getDefaultToolkit().getScreenSize();
            // Compact mode should apply only to genuinely small displays.
            // Large screens (including high-DPI scaled desktops) should keep
            // full-size UI by default.
            compactDisplay = screenSize != null && (
                    screenSize.width <= 1280
                    || screenSize.height <= 720
                    || (screenSize.width <= 1366 && screenSize.height <= 820)
            );
        } catch (Exception ignore) {}
        this.startupZoomScale = 1.0f;
        if (compactDisplay) {
            boolean verySmall = screenSize != null
                    && (screenSize.height <= 720 || screenSize.width <= 1200);
            this.startupZoomScale = verySmall ? 0.82f : 0.90f;
        }
        final boolean compactDisplayFinal = compactDisplay;
        // On compact displays we still want *some* preferred width so the
        // Postman-style two-column layout doesn't collapse, but we must NOT
        // enforce a minimum wider than the actual Burp panel — otherwise a
        // horizontal scrollbar chops the tabs off (see 1366x768 screenshot
        // bug). Compute a target that's ~90% of the screen width MINUS an
        // allowance for Burp's own chrome (tab strip, side padding, the
        // extension host's borders). Cap at 1100 so ultra-narrow modes
        // don't force scroll on 1024x768 either.
        final int chromeAllowance = 220;
        final int compactMinWidth = compactDisplay
                ? Math.min(1100, Math.max(760,
                    (screenSize != null ? screenSize.width : 1200) - chromeAllowance))
                : 0;
        final int compactMinHeight = compactDisplay
                ? (screenSize != null ? Math.max(560, screenSize.height - 180) : 620)
                : 0;

        // Legacy header preserved per user preference — old branded strip
        // with the Workspace toggle. The new top toolbar was removed because
        // it duplicated the Workspace box buttons. All actions remain
        // available via the Workspace box below + tree context menu.
        burp.ui.AppToolbar appToolbar = null;
        this.appToolbarField = null;

        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.X_AXIS));
        headerPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, UITheme.ACCENT),
                BorderFactory.createEmptyBorder(4, 10, 4, 10)));
        headerPanel.setBackground(UITheme.surface());
        headerPanel.setOpaque(true);

        JLabel titleLabel = new JLabel("BurpMan");
        titleLabel.setFont(UITheme.boldFont(13f));
        titleLabel.setForeground(UITheme.ACCENT);

        JLabel helpLabel = new JLabel("  •  Postman-style collection runner");
        helpLabel.setFont(UITheme.baseFont().deriveFont(Font.PLAIN, 11f));
        helpLabel.setForeground(UITheme.subtleText());

        headerPanel.add(titleLabel);
        headerPanel.add(helpLabel);
        headerPanel.add(Box.createHorizontalGlue());

        // Collapsible Workspace toggle — keep common controls visible by default.
        final boolean[] wsShown = { true };
        final JButton wsToggle = UITheme.button("▾ Workspace", UITheme.BtnStyle.GHOST);
        wsToggle.setFont(UITheme.baseFont().deriveFont(Font.PLAIN, 11f));
        wsToggle.setMargin(new Insets(2, 8, 2, 8));
        wsToggle.setToolTipText("Show/Hide the workspace (collection picker, environment, etc.)");
        headerPanel.add(wsToggle);
        headerPanel.setBackground(UITheme.surface());
        headerPanel.setOpaque(true);

        // Main content
        //
        // Implements Scrollable so the wrapping JScrollPane (contentScroll)
        // always sizes the panel to the viewport WIDTH and HEIGHT — Postman /
        // Bruno UX. The outer scroll pane never scrolls; internal panels
        // (params/headers tables, request body editor, response viewer tabs)
        // manage their own overflow via their own JScrollPanes.
        //
        // Why fill viewport height (not "shrink to fit content"):
        //   mainSplitPane's preferred height is dominated by
        //   builderResponseSplit (VERTICAL_SPLIT), whose preferred = sum of
        //   builder + response preferred heights. Each of those is easily
        //   400–600 px because they wrap tabbed panes over text editors.
        //   If the outer scroll pane tries to size contentPanel to that
        //   preferred, the response panel gets pushed below the viewport
        //   (user sees only the request builder with huge whitespace below
        //   the headers/params table). Filling viewport instead squeezes
        //   the split back to the viewport height so adaptSplits below can
        //   clamp the divider to keep BOTH halves materially visible.
        class ContentPanel extends JPanel implements Scrollable {
            ContentPanel() { super(new BorderLayout(10, 10)); }

            @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
            @Override public int getScrollableUnitIncrement(Rectangle vr, int orientation, int direction) { return 16; }
            @Override public int getScrollableBlockIncrement(Rectangle vr, int orientation, int direction) {
                return orientation == SwingConstants.VERTICAL ? vr.height : vr.width;
            }
            /** Always fit the viewport WIDTH — never a horizontal scrollbar on the outer pane. */
            @Override public boolean getScrollableTracksViewportWidth() { return true; }
            /** Always fit the viewport HEIGHT — Postman/Bruno-style fixed viewport. */
            @Override public boolean getScrollableTracksViewportHeight() { return true; }
        }
        JPanel contentPanel = new ContentPanel();
        contentPanel.setBorder(BorderFactory.createEmptyBorder(8, 10, 0, 10));

        // File selection panel — visible by default (legacy layout).
        JPanel filePanel = new JPanel(new GridBagLayout());
        filePanel.setBorder(UITheme.titled("Workspace"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(2, 5, 2, 5);

        // Collection file
        gbc.gridx = 0; gbc.gridy = 0;
        filePanel.add(new JLabel("Collection:"), gbc);

        gbc.gridx = 1; gbc.weightx = 1.0;
        collectionField = new JTextField();
        collectionField.setEditable(false);
        filePanel.add(collectionField, gbc);

        gbc.gridx = 2; gbc.weightx = 0;
        JPanel browseGroup = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        browseGroup.setOpaque(false);
        JButton browseCollectionBtn = UITheme.button("Browse…", UITheme.BtnStyle.GHOST);
        browseCollectionBtn.setToolTipText("Pick a Postman / Bruno collection file or folder");
        browseCollectionBtn.addActionListener(e -> selectCollectionFile());
        browseGroup.add(browseCollectionBtn);
        recentBtn = UITheme.button("▾", UITheme.BtnStyle.GHOST);
        recentBtn.setToolTipText("Recent collections");
        recentBtn.addActionListener(e -> showRecentMenu(recentBtn));
        browseGroup.add(recentBtn);

        JButton importOpenApiBtn = UITheme.button("OpenAPI…", UITheme.BtnStyle.GHOST);
        importOpenApiBtn.setToolTipText("Import an OpenAPI 3 / Swagger 2 JSON spec as a collection");
        importOpenApiBtn.addActionListener(e -> importFromOpenApi());
        this.advancedOpenApiBtn = importOpenApiBtn;
        // Moved to the Advanced popup (see createUI wiring).

        JButton saveCollectionBtn = UITheme.button("📤 Export…", UITheme.BtnStyle.GHOST);
        saveCollectionBtn.setToolTipText("Export the live collection to a NEW .postman_collection.json file (the original is never overwritten)");
        saveCollectionBtn.addActionListener(e -> saveCurrentCollection());
        this.advancedExportBtn = saveCollectionBtn;
        // Moved to the Advanced popup.

        filePanel.add(browseGroup, gbc);

        // Environment dropdown
        gbc.gridx = 0; gbc.gridy = 1;
        filePanel.add(new JLabel("Environment:"), gbc);

        gbc.gridx = 1; gbc.weightx = 1.0;
        environmentCombo = new JComboBox<>();
        environmentCombo.addItem(new EnvOption(null, "— No Environment —"));
        environmentCombo.addActionListener(e -> onEnvironmentSelected());
        // Cap combo box's natural width via a prototype so long env
        // display names don't force the enclosing GridBag row wider than
        // the Burp panel — otherwise the popup ends up wider than the
        // window and Swing pushes the heavyweight popup out to the left
        // of the extension pane (see 1366x768 screenshot). Prototype is
        // sized for a typical Bruno env name like "5-UAT-CAE".
        environmentCombo.setPrototypeDisplayValue(
            new EnvOption(null, "— XXXXXXXXXXXXXXXXXXXXX —"));
        environmentCombo.setMaximumRowCount(10);
        // Force the popup to match the combo's current width — prevents
        // heavyweight Swing popups from escaping the extension pane on
        // multi-monitor setups. Swing normally sizes popups to the widest
        // item; we override to force width = combo width.
        environmentCombo.addPopupMenuListener(new javax.swing.event.PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent e) {
                try {
                    Object popup = environmentCombo.getUI()
                        .getAccessibleChild(environmentCombo, 0);
                    if (popup instanceof javax.swing.JPopupMenu) {
                        javax.swing.JPopupMenu pm = (javax.swing.JPopupMenu) popup;
                        Dimension size = pm.getPreferredSize();
                        int width = environmentCombo.getWidth();
                        if (width > 0) {
                            pm.setPreferredSize(new Dimension(width, size.height));
                            pm.setPopupSize(new Dimension(width, size.height));
                        }
                    }
                } catch (Exception ignore) {}
            }
            @Override public void popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent e) {}
            @Override public void popupMenuCanceled(javax.swing.event.PopupMenuEvent e) {}
        });
        // Also install a renderer that ellipsizes long names so items
        // never demand more horizontal space than the combo has.
        environmentCombo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value,
                    int index, boolean isSelected, boolean cellHasFocus) {
                Component c = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (c instanceof JLabel && value instanceof EnvOption) {
                    JLabel l = (JLabel) c;
                    EnvOption opt = (EnvOption) value;
                    l.setText(opt.displayName == null ? "(env)" : opt.displayName);
                    // Full path (or filename) as tooltip when hovering
                    // a truncated row — keeps the info accessible.
                    if (opt.file != null) l.setToolTipText(opt.file.getAbsolutePath());
                }
                return c;
            }
        });
        filePanel.add(environmentCombo, gbc);

        environmentField = new JTextField();
        environmentField.setEditable(false);
        environmentField.setVisible(false);

        gbc.gridx = 2; gbc.weightx = 0;
        JButton browseEnvBtn = UITheme.button("Add…", UITheme.BtnStyle.GHOST);
        browseEnvBtn.setToolTipText("Add an environment file to the dropdown");
        browseEnvBtn.addActionListener(e -> selectEnvironmentFile());
        filePanel.add(browseEnvBtn, gbc);

        gbc.gridx = 3; gbc.weightx = 0;
        JButton exportEnvBtn = UITheme.button("📤 Save Env…", UITheme.BtnStyle.GHOST);
        exportEnvBtn.setToolTipText("Export current environment variables (incl. live script writes) to a NEW .postman_environment.json file. The original is never overwritten.");
        exportEnvBtn.addActionListener(e -> exportCurrentEnvironment());
        this.advancedSaveEnvBtn = exportEnvBtn;
        // Moved to the Advanced popup (see createUI wiring).

        gbc.gridx = 3; gbc.weightx = 0;
        JButton clearVarsBtn = UITheme.button("Clear", UITheme.BtnStyle.GHOST);
        clearVarsBtn.setToolTipText("Clear loaded environments and variables");
        clearVarsBtn.addActionListener(e -> clearEnvironmentVariables());
        filePanel.add(clearVarsBtn, gbc);

        gbc.gridx = 3; gbc.gridy = 0; gbc.weightx = 0;
        JButton restartApp = UITheme.button("Restart", UITheme.BtnStyle.DANGER);
        restartApp.addActionListener(e -> {
            importer.fullReset();
            restartApp();
        });
        filePanel.add(restartApp, gbc);

        // Hidden destination radio (older code paths still read it)
        destinationGroup = new ButtonGroup();
        repeaterOption = new JRadioButton("Repeater", true);
        destinationGroup.add(repeaterOption);

        progressBar = new JProgressBar(0, 100);
        progressBar.setVisible(false);

        JPanel northPanel = new JPanel(new BorderLayout(10, 10));
        northPanel.add(filePanel, BorderLayout.NORTH);
        authManagerPanel = new AuthManagerPanel(authManager, importer);
        authManager.bindPanel(authManagerPanel);
        
        contentPanel.add(northPanel, BorderLayout.NORTH);

        // Wire the Workspace collapse toggle now that filePanel exists.
        wsToggle.addActionListener(e -> {
            wsShown[0] = !wsShown[0];
            boolean show = wsShown[0];
            filePanel.setVisible(show);
            wsToggle.setText((show ? "▾" : "▸") + " Workspace");
            northPanel.revalidate();
            northPanel.repaint();
        });
        // Apply initial state adaptively: on compact displays, start with the
        // workspace panel collapsed so request/editor controls stay reachable.
        wsShown[0] = !compactDisplay;
        filePanel.setVisible(wsShown[0]);
        wsToggle.setText((wsShown[0] ? "▾" : "▸") + " Workspace");
        
        // Log area
        logArea = new JTextArea(15, 50);
        logArea.setEditable(false);
        logArea.setFont(UITheme.monoFont());
        logArea.setBackground(UITheme.surface());
        logArea.setForeground(UITheme.foreground());
        logArea.setMargin(new Insets(6, 8, 6, 8));
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(UITheme.titled("Logs"));
        JButton clearLogInTabBtn = UITheme.button("Clear Log", UITheme.BtnStyle.GHOST);
        clearLogInTabBtn.setToolTipText("Clear log output in this tab");
        clearLogInTabBtn.addActionListener(e -> logArea.setText(""));
        JPanel logTools = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 2));
        logTools.setOpaque(false);
        logTools.add(clearLogInTabBtn);
        logPanel.add(logTools, BorderLayout.NORTH);
        logPanel.add(scrollPane, BorderLayout.CENTER);
        
        JPanel authWrapper = new JPanel(new BorderLayout());
        authWrapper.add(authManagerPanel, BorderLayout.CENTER);
        
        // Avoid fixed vertical minimums so the pane can shrink on small screens.
        authWrapper.setMinimumSize(new Dimension(0, 0));
        
        // ✅ Create tree panel
        treePanel = new CollectionTreePanel(importer);
        treePanel.setAddCollectionListener(this::addAdditionalCollection);
        treePanel.setImportEnvironmentListener(this::selectEnvironmentFile);
        treePanel.setCreateEmptyCollectionListener(this::createEmptyCollection);
        
        // ✅ MAKE AUTH PANEL NORMAL SIZE (it's in its own tab now)
        authWrapper.setMinimumSize(new Dimension(0, 0));
        
        // Reference holder for lambda access
        final JTabbedPane[] rightTabbedPaneRef = new JTabbedPane[1];
        final JPanel[] builderCardHostRef = new JPanel[1];
        
        // ✅ CREATE POSTMAN COMPONENTS
        burp.models.RequestHistory requestHistory = new burp.models.RequestHistory();
        this.requestHistory = requestHistory;
        burp.service.RequestExecutor requestExecutor = new burp.service.RequestExecutor(importer.getMontoyaApi());
        // Wire up variable resolver so {{variables}} get replaced when sending
        requestExecutor.setVariableResolver(importer.getVariableResolver());
        // Share the cookie jar so Set-Cookie is captured and Cookie header is auto-sent
        requestExecutor.setCookieJar(importer.getCookieJar());
        // ATOR-style auto-refresh of expired JWTs on outbound requests
        requestExecutor.setAuthManager(importer.getAuthManager());
        
        // Request Builder
        RequestBuilderPanel builderPanel = new RequestBuilderPanel(requestExecutor, requestHistory);
        this.builderPanel = builderPanel;
        builderPanel.setAuthManager(importer.getAuthManager());

        // Live edit-cache save: persist a snapshot on every URL/body/header/
        // script keystroke so switching tabs, focusing another panel, or any
        // refresh path can never wipe in-flight edits.
        // Live edit-cache hook DISABLED — it polluted the cache when
        // programmatic loads (setText / setScripts) fired document events
        // between the loadRequest call and currentLoadedKey assignment.
        // Reverted to the simpler save-on-switch model in the tree-click
        // handler, which captures snapshots cleanly when switching requests.
        // builderPanel.addEditListener(() -> { ... });

        // When the user clicks Apply in Auth Manager, push the fresh token into
        // the Request Builder's Authorization tab so what the user SEES matches
        // what will actually be sent. Without this, the Bearer Token field
        // keeps showing the stale value captured at import time.
        if (authManagerPanel != null) {
            authManagerPanel.setOnTokenApplied(token -> {
                javax.swing.SwingUtilities.invokeLater(() -> {
                    try { builderPanel.applyBearerToken(token); } catch (Exception ignore) {}
                    try { if (folderEditorRef != null) folderEditorRef.applyBearerToken(token); } catch (Exception ignore) {}
                });
            });
        }

        // Postman-like auto-refresh: when AuthManager's token changes (e.g. after
        // "Get New Access Token" in the OAuth2 dialog), simply refresh the
        // currently-loaded request's headers via the inheritedAuthSupplier
        // pipeline. We do NOT touch the Authorization tab's auth-type combo
        // here — the type stays whatever the source declared (OAuth2/Bearer/
        // Inherit). The supplier reads AuthManager.getAccessToken() at sync
        // time, so headers will pick up the new token automatically.
        try {
            burp.auth.AuthManager am = importer.getAuthManager();
            if (am != null) {
                am.addTokenChangeListener(token -> {
                    if (token == null || token.isEmpty()) return;
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        // Mirror into the visible Token area in Auth Manager
                        try { if (authManagerPanel != null) authManagerPanel.setToken(token); } catch (Exception ignore) {}
                        // Push into {{token}} and per-folder token_* vars so any
                        // request that templates "Bearer {{token_xxx}}" picks it up.
                        try {
                            java.util.Map<String, String> vars = new java.util.LinkedHashMap<>();
                            vars.put("token", token);
                            try {
                                java.util.Set<String> known = importer.getDetectedCollectionVariables();
                                if (known != null) {
                                    for (String name : known) {
                                        if (name != null && name.startsWith("token_")) vars.put(name, token);
                                    }
                                }
                            } catch (Exception ignore) {}
                            importer.addCustomVariables(vars);
                        } catch (Exception ignore) {}
                        // Re-render the current request's Authorization header via
                        // the supplier pipeline. This DOES NOT change the auth type;
                        // it just substitutes the fresh token into the inherited
                        // "Bearer <token>" header value.
                        try { builderPanel.syncInheritedAuth(); } catch (Exception ignore) {}
                        // Refresh the Edit Variables snapshot
                        try {
                            burp.parser.VariableResolver r = importer.getVariableResolver();
                            if (r != null) refreshVariables(r.getVariables());
                        } catch (Exception ignore) {}
                    });
                });
            }
        } catch (Exception ignore) {}

        // After every Send, drop stale Builder snapshots and refresh the
        // variables panel so the next tree click re-resolves against the
        // updated variable map (e.g. a post-script that just set {{token}}).
        builderPanel.setPostSendListener(() -> {
            // Manual in-app requests should persist their latest edits even
            // when unsaved cache entries are dropped after Send.
            try {
                if (builderPanel != null && currentLoadedKey != null) {
                    burp.models.PostmanCollection.Request source = requestSourceByKey.get(currentLoadedKey);
                    if (isUserAddedRequest(source)) {
                        burp.models.PostmanCollection.Request snap = builderPanel.getCurrentSnapshot();
                        if (snap != null) applySnapshotToSourceRequest(source, snap);
                    }
                }
            } catch (Exception ignore) {}
            // Cache the response RIGHT NOW under the current key, before we
            // null currentLoadedKey below for the edit-cache reset. Without
            // this, switching tree nodes after a Send loses the response
            // because the save-on-switch hook (line ~833) sees a null key
            // and bails. This is the "result clears when I navigate" bug.
            try {
                if (currentLoadedKey != null && responsePanel != null) {
                    burp.models.ExecutedRequest resp = responsePanel.getCurrentResponse();
                    if (resp != null) requestResponseCache.put(currentLoadedKey, resp);
                }
            } catch (Throwable ignore) {}

            try {
                clearUnsavedCache();
                if (currentLoadedKey != null && !savedKeys.contains(currentLoadedKey)) {
                    currentLoadedKey = null;
                }
            } catch (Exception ignore) {}
            try {
                burp.parser.VariableResolver r = importer.getVariableResolver();
                if (r != null) refreshVariables(r.getVariables());
            } catch (Exception ignore) {}
        });

        // Save button on the Builder: persist the current snapshot under the
        // active tree-node key so it survives switching nodes and variable
        // refreshes until the user explicitly edits or reloads.
        builderPanel.setSaveListener(() -> {
            try {
                if (currentLoadedKey != null) {
                    burp.models.PostmanCollection.Request snap = builderPanel.getCurrentSnapshot();
                    requestEditCache.put(currentLoadedKey, snap);
                    savedKeys.add(currentLoadedKey);

                    // Push edits back into the underlying collection request so
                    // the tree node label and any later previews reflect the
                    // current method/url/headers/auth/body.
                    if (currentPmRequest != null && snap != null) {
                        applySnapshotToSourceRequest(currentPmRequest, snap);
                    }
                    if (currentClickedNode != null && snap != null && snap.method != null) {
                        currentClickedNode.setMethod(snap.method);
                        try {
                            javax.swing.JTree t = treePanel != null ? treePanel.getTree() : null;
                            if (t != null) {
                                javax.swing.tree.DefaultTreeModel m =
                                    (javax.swing.tree.DefaultTreeModel) t.getModel();
                                m.nodeChanged(currentClickedNode);
                            }
                        } catch (Exception ignore) {}
                    }
                    appendLog("Saved request edits: " + currentLoadedKey);
                    try { importer.refreshAuthDetectionFromCurrentCollection(); } catch (Exception ignore) {}
                }
            } catch (Exception ignore) {}
        });
        
        // Response Viewer
        ResponsePanel responsePanel = new ResponsePanel();
        this.responsePanel = responsePanel;
        
        // Connect builder's response display to external response panel
        builderPanel.setExternalResponsePanel(responsePanel);
        
        // Request History
        RequestHistoryPanel historyPanel = new RequestHistoryPanel(requestHistory, builderPanel, requestExecutor);
        
        // ✅ CONNECT TREE CLICKS TO BUILDER (Postman-like behavior)
        treePanel.setRequestNodeClickListener((request, clickedNode) -> {
            burp.models.PostmanCollection.Request pmRequest = null;
            if (clickedNode != null && clickedNode.getRawItem() != null) {
                pmRequest = clickedNode.getRawItem().request;
            }
            if (pmRequest == null && request != null) {
                pmRequest = request.getRequest();
            }
            if (pmRequest == null) return;
            currentClickedNode = clickedNode;
            currentPmRequest = pmRequest;

            // Mirror scope into Auth Manager — use the request's parent folder
            // (or root collection) so only endpoints from this branch show up.
            try {
                if (authManagerPanel != null) {
                    String fullPath = burp.ui.CollectionTreePanel.nodePathKey(clickedNode);
                    String parent = fullPath;
                    int slash = parent == null ? -1 : parent.lastIndexOf('/');
                    if (slash >= 0) parent = parent.substring(0, slash);
                    if (parent == null || parent.isEmpty()) parent = fullPath;
                    authManagerPanel.setScopeFilter(parent);
                    // Activate the variable resolver scope for this request's
                    // top-level collection so previews use per-collection vars.
                    String top = fullPath == null ? null
                            : (fullPath.contains("/") ? fullPath.substring(0, fullPath.indexOf('/')) : fullPath);
                    importer.getVariableResolver().setActiveScope(top);
                }
            } catch (Exception ignore) {}
            
            // Clone request to avoid modifying original
            burp.models.PostmanCollection.Request clone = new burp.models.PostmanCollection.Request();
            burp.parser.VariableResolver resolver = importer.getVariableResolver();
            
            // Resolve URL — use extractRawUrl to handle both String and Map/Url object cases.
            // We resolve eagerly so the URL field shows the FULL resolved URL
            // (Postman-style highlighting of substituted spans happens in UrlBar,
            // which receives both the raw template and resolves it with spans).
            String urlStr = pmRequest.url != null ? importer.extractRawUrl(pmRequest.url) : "";
            if (urlStr == null) urlStr = "";
            String rawTemplate = normalizePostmanPathTemplate(urlStr, pmRequest.url);
            clone.url = resolver != null ? resolver.resolve(rawTemplate) : rawTemplate;
            // Stash the RAW template on the clone so the builder can pass it
            // to UrlBar for per-span highlighting.
            clone.rawUrlTemplate = rawTemplate;
            
            // Method
            clone.method = pmRequest.method;
            // Preserve the request's own auth (e.g. {type:"noauth"}) so the
            // Authorization tab shows it correctly instead of falling back to Inherit.
            clone.auth = pmRequest.auth;
            
            // Resolve headers (skip empty ones)
            clone.header = new java.util.ArrayList<>();
            if (pmRequest.header != null) {
                for (burp.models.PostmanCollection.Header h : pmRequest.header) {
                    // Skip empty/blank headers
                    if (h.key == null || h.key.trim().isEmpty()) continue;
                    
                    burp.models.PostmanCollection.Header newH = new burp.models.PostmanCollection.Header();
                    newH.key = resolver != null ? resolver.resolve(h.key) : h.key;
                    newH.value = resolver != null ? resolver.resolve(h.value) : h.value;
                    newH.disabled = h.disabled;
                    clone.header.add(newH);
                }
            }
            
            // Skip auth injection for token endpoints (OAuth2 token, login providers)
            String urlLower = (clone.url == null ? "" : clone.url.toString()).toLowerCase();
            boolean looksLikeTokenEndpoint =
                urlLower.contains("/oauth2/token")
                || urlLower.contains("/oauth/token")
                || urlLower.contains("/connect/token")
                || urlLower.endsWith("/token")
                || urlLower.contains("login.microsoftonline.com")
                || urlLower.contains("login.windows.net")
                || urlLower.contains("/authorize")
                || urlLower.contains("/auth/realms");
            
            // Add Authorization header from AuthManager only when the request explicitly
            // wants bearer auth, or already has an Authorization header that's empty / a
            // placeholder. Don't inject on plain unauthenticated requests.
            boolean isNoAuth = pmRequest.auth != null && "noauth".equalsIgnoreCase(pmRequest.auth.type);
            boolean wantsBearer = pmRequest.auth != null
                && ("bearer".equalsIgnoreCase(pmRequest.auth.type)
                    || "oauth2".equalsIgnoreCase(pmRequest.auth.type));
            
            // Find existing Authorization header (if any)
            burp.models.PostmanCollection.Header existingAuth = null;
            for (burp.models.PostmanCollection.Header h : clone.header) {
                if ("authorization".equalsIgnoreCase(h.key)) { existingAuth = h; break; }
            }
            boolean authIsPlaceholder = existingAuth != null
                && (existingAuth.value == null
                    || existingAuth.value.trim().isEmpty()
                    || existingAuth.value.trim().equalsIgnoreCase("Bearer")
                    || existingAuth.value.trim().equalsIgnoreCase("Bearer null")
                    || existingAuth.value.contains("{{"));
            
            if (!isNoAuth && !looksLikeTokenEndpoint && (wantsBearer || authIsPlaceholder)) {
                String authHeader = null;
                
                // Try AuthManager first (for fetched tokens)
                try {
                    authHeader = authManager.getAuthorizationHeaderValue();
                } catch (Exception ex) {
                    // continue
                }
                
                // Fallback: try variable {{token}} from environment
                if (authHeader == null || authHeader.isEmpty()) {
                    try {
                        if (resolver != null) {
                            String tokenVal = resolver.resolve("{{token}}");
                            if (tokenVal != null && !tokenVal.isEmpty() && !tokenVal.equals("{{token}}")) {
                                authHeader = "Bearer " + tokenVal;
                            }
                        }
                    } catch (Exception ex) {
                        // continue
                    }
                }
                
                if (authHeader != null && !authHeader.isEmpty()) {
                    if (existingAuth != null) {
                        // Only overwrite if the existing one is a placeholder
                        if (authIsPlaceholder) existingAuth.value = authHeader;
                    } else {
                        burp.models.PostmanCollection.Header authH = new burp.models.PostmanCollection.Header();
                        authH.key = "Authorization";
                        authH.value = authHeader;
                        clone.header.add(authH);
                    }
                }
            }
            
            // Token endpoints should never carry an Authorization header — strip any leftover
            if (looksLikeTokenEndpoint) {
                clone.header.removeIf(h -> "authorization".equalsIgnoreCase(h.key));
            }
            
            // Apply folder/collection auth override (Postman-style "Edit Auth" on a folder).
            // The override takes effect when the request itself doesn't have an explicit auth
            // header (i.e. the request is "Inherit auth from parent" in Postman terms).
            if (!looksLikeTokenEndpoint) {
                burp.auth.FolderAuthRegistry reg = importer.getFolderAuthRegistry();
                if (reg != null && clickedNode != null) {
                    // Walk up from the clicked request node to find the nearest ancestor folder/collection key
                    javax.swing.tree.TreeNode parent = clickedNode.getParent();
                    String parentKey = parent instanceof burp.models.CollectionTreeNode
                        ? CollectionTreePanel.nodePathKey((burp.models.CollectionTreeNode) parent)
                        : "";
                    burp.auth.FolderAuthOverride ov = reg.resolve(parentKey);
                    if (ov != null) {
                        // Only apply if the request has no explicit Authorization already
                        boolean hasOwnAuth = false;
                        for (burp.models.PostmanCollection.Header h : clone.header) {
                            if ("authorization".equalsIgnoreCase(h.key)
                                && h.value != null && !h.value.trim().isEmpty()
                                && !h.value.contains("{{")) { hasOwnAuth = true; break; }
                        }
                        if (!hasOwnAuth) {
                            // Strip placeholder auth then apply override
                            clone.header.removeIf(h -> "authorization".equalsIgnoreCase(h.key));
                            burp.auth.FolderAuthApplier.apply(ov, clone);
                        }
                    }
                }
            }
            
            // Final pass: resolve {{vars}} in all header values and URL (folder-auth
            // applier may have written e.g. "Bearer {{token}}" from the inherited override).
            if (resolver != null) {
                for (burp.models.PostmanCollection.Header h : clone.header) {
                    if (h.value != null) h.value = resolver.resolve(h.value);
                    if (h.key != null) h.key = resolver.resolve(h.key);
                }
                if (clone.url != null) {
                    clone.url = resolver.resolve(clone.url.toString());
                }
            }
            
            // Preserve raw body templates ({{var}}) in the editor so users can
            // clearly see editable variables. Request send path still resolves.
            if (pmRequest.body != null) {
                clone.body = new burp.models.PostmanCollection.Body();
                clone.body.mode = pmRequest.body.mode;
                // Only copy body.raw when mode is actually raw (or unknown). A script
                // or a rogue mutation can leave body.raw set on a formdata/urlencoded
                // request, and loadRequest's RAW branch would then pre-empt the
                // formdata/urlencoded branch and drop the structured entries.
                String cloneMode = pmRequest.body.mode == null ? "" : pmRequest.body.mode.toLowerCase();
                if (!"formdata".equals(cloneMode) && !"urlencoded".equals(cloneMode)) {
                    clone.body.raw = pmRequest.body.raw;
                }
                
                // Keep GraphQL query/variables raw for the same variable-visibility reason.
                if (pmRequest.body.graphql != null) {
                    clone.body.graphql = new burp.models.PostmanCollection.GraphQL();
                    clone.body.graphql.query = pmRequest.body.graphql.query;
                    clone.body.graphql.variables = pmRequest.body.graphql.variables;
                }
                
                // Also clone urlencoded entries (OAuth token requests etc.) with variable resolution
                if (pmRequest.body.urlencoded != null) {
                    clone.body.urlencoded = new java.util.ArrayList<>();
                    for (burp.models.PostmanCollection.UrlEncoded ue : pmRequest.body.urlencoded) {
                        burp.models.PostmanCollection.UrlEncoded copy = new burp.models.PostmanCollection.UrlEncoded();
                        copy.key = resolver != null ? resolver.resolve(ue.key) : ue.key;
                        copy.value = resolver != null ? resolver.resolve(ue.value) : ue.value;
                        copy.disabled = ue.disabled;
                        clone.body.urlencoded.add(copy);
                    }
                }
                
                // Also clone formdata entries
                if (pmRequest.body.formdata != null) {
                    clone.body.formdata = new java.util.ArrayList<>();
                    for (burp.models.PostmanCollection.FormData fd : pmRequest.body.formdata) {
                        burp.models.PostmanCollection.FormData copy = new burp.models.PostmanCollection.FormData();
                        copy.key = resolver != null ? resolver.resolve(fd.key) : fd.key;
                        copy.value = resolver != null ? resolver.resolve(fd.value) : fd.value;
                        copy.type = fd.type;
                        copy.src = fd.src;
                        copy.disabled = fd.disabled;
                        clone.body.formdata.add(copy);
                    }
                }
            }
            
            // Auto-add Content-Type when the body implies one but the headers don't declare it
            // (Postman shows this as an implicit header derived from body type/language).
            if (clone.body != null && clone.body.mode != null) {
                boolean hasContentType = false;
                for (burp.models.PostmanCollection.Header h : clone.header) {
                    // Skip disabled headers — Bruno's ~Content-Type: application/xml
                    // is a commented-out declaration that must not veto the body-
                    // derived Content-Type (the wire wouldn't carry the disabled
                    // header anyway).
                    if (h == null || h.disabled) continue;
                    if (h.key != null && "content-type".equalsIgnoreCase(h.key.trim())) {
                        hasContentType = true; break;
                    }
                }
                if (!hasContentType) {
                    String ct = null;
                    String mode = clone.body.mode.toLowerCase();
                    if ("raw".equals(mode)) {
                        String lang = null;
                        if (clone.body.options != null && clone.body.options.raw != null) {
                            lang = clone.body.options.raw.language;
                        }
                        if (lang != null) {
                            switch (lang.toLowerCase()) {
                                case "json": ct = "application/json"; break;
                                case "xml":  ct = "application/xml"; break;
                                case "html": ct = "text/html"; break;
                                case "javascript": ct = "application/javascript"; break;
                                default: ct = "text/plain"; break;
                            }
                        } else if (clone.body.raw != null) {
                            String s = clone.body.raw.trim();
                            if (s.startsWith("{") || s.startsWith("[")) ct = "application/json";
                            else if (s.startsWith("<")) ct = "application/xml";
                        }
                    } else if ("urlencoded".equals(mode)) {
                        ct = "application/x-www-form-urlencoded";
                    } else if ("formdata".equals(mode)) {
                        // Don't insert a boundaryless Content-Type — the Builder's send path
                        // generates one with a boundary when assembling the multipart body.
                        ct = null;
                    } else if ("graphql".equals(mode)) {
                        ct = "application/json";
                    }
                    if (ct != null) {
                        burp.models.PostmanCollection.Header h = new burp.models.PostmanCollection.Header();
                        h.key = "Content-Type";
                        h.value = ct;
                        clone.header.add(h);
                    }
                }
            }
            
            // Compute request context + cache key. Cache key includes request
            // identity to avoid collisions when large packs contain duplicate
            // request names under the same folder.
            String reqNameForKey = clickedNode != null ? clickedNode.toString()
                    : (request.getName() == null ? "" : request.getName());
            String folderPathForKey = "";
            try {
                javax.swing.tree.TreeNode parent2 = clickedNode != null ? clickedNode.getParent() : null;
                if (parent2 instanceof burp.models.CollectionTreeNode) {
                    folderPathForKey = CollectionTreePanel.nodePathKey((burp.models.CollectionTreeNode) parent2);
                }
            } catch (Exception ignore) { }
            if ((folderPathForKey == null || folderPathForKey.isEmpty()) && request.getPath() != null) {
                String p = request.getPath().replace('\\', '/');
                int slash = p.lastIndexOf('/');
                if (slash > 0) folderPathForKey = p.substring(0, slash);
            }
            String newKey = buildRequestCacheKey(request, clickedNode);
            requestSourceByKey.put(newKey, pmRequest);

            // Snapshot the OUTGOING request's response into the cache BEFORE
            // anything touches currentLoadedKey or replaces the response pane.
            // Mirrors Postman behavior — clicking back to a request you sent
            // already shows its prior response.
            if (responsePanel != null && currentLoadedKey != null && !currentLoadedKey.equals(newKey)) {
                try {
                    burp.models.ExecutedRequest prev = responsePanel.getCurrentResponse();
                    if (prev != null) requestResponseCache.put(currentLoadedKey, prev);
                } catch (Throwable ignore) {}
            }

            // Snapshot the OUTGOING request's edits to the edit cache, but
            // ONLY when actually switching to a different request. Same-key
            // re-click is a no-op so caret/selection survive.
            //
            // IMPORTANT: this is a PASSIVE snapshot (preserves caret + in-flight
            // typing while you click around the tree). It must NOT be promoted
            // to `savedKeys` — that set is reserved for *explicit* Save-button
            // saves. Promoting here would defeat `clearUnsavedCache()` which
            // runs after every script Send to flush stale resolved values
            // (e.g. when re-running an auth script switches the user, the
            // Profile request must re-resolve {{token}} on the next click
            // instead of replaying the previous user's cached snapshot).
            if (currentLoadedKey != null && !currentLoadedKey.equals(newKey)) {
                try {
                    burp.models.PostmanCollection.Request snap = builderPanel.getCurrentSnapshot();
                    requestEditCache.put(currentLoadedKey, snap);
                    burp.models.PostmanCollection.Request source = requestSourceByKey.get(currentLoadedKey);
                    if (isUserAddedRequest(source) && snap != null) {
                        applySnapshotToSourceRequest(source, snap);
                    }
                } catch (Exception ignore) { }
            }

            // Same-node click → no reload (would discard caret position + can
            // accidentally restore a stale cached snapshot). But still force
            // the right pane back to the request view: users often click a
            // folder (shows FOLDER auth card) then click the same request
            // again, and they expect the builder card to reappear instantly.
            if (currentLoadedKey != null && currentLoadedKey.equals(newKey)) {
                setRightTabsVisible(rightTabbedPaneRef[0], true);
                int rbIdx = rightTabbedPaneRef[0].indexOfTab("Request Builder");
                if (rbIdx >= 0) rightTabbedPaneRef[0].setSelectedIndex(rbIdx);
                if (builderCardHostRef[0] != null) {
                    ((CardLayout) builderCardHostRef[0].getLayout()).show(builderCardHostRef[0], "REQUEST");
                }
                return;
            }

            // If we have cached edits for this request, restore them; otherwise load the resolved clone.
            // Suppress live edit-cache save during the clear→reload cycle so the
            // intermediate "blank" state doesn't get persisted to the new key.
            burp.models.PostmanCollection.Request cached = requestEditCache.get(newKey);
            suppressEditCacheSave = true;
            try {
                if (cached != null) {
                    builderPanel.loadRequest(cached);
                } else {
                    builderPanel.loadRequest(clone);
                }
            } finally {
                suppressEditCacheSave = false;
            }
            // Push cascaded pre/post scripts onto the builder so they run on Send.
            try {
                String[] scripts = importer.getScriptsForPath(request.getPath());
                builderPanel.setScripts(scripts != null && scripts.length > 0 ? scripts[0] : null,
                                        scripts != null && scripts.length > 1 ? scripts[1] : null);
            } catch (Exception ignore) { }
            // Refresh the snippet panel for this request so the Code tab
            // shows curl/Python/JS/etc. for what the user is editing.
            try {
                if (snippetPanel != null) snippetPanel.setRequest(clone, request.getName());
            } catch (Exception ignore) { }
            // Also open the request in the multi-tab workspace so users who
            // prefer Postman's "many open requests" workflow see it there.
            try {
                if (requestTabsPanel != null) requestTabsPanel.openRequest(request);
            } catch (Exception ignore) { }

            // Now that the snapshot is safely persisted under the OLD key,
            // load the INCOMING request's cached response (or clear the pane).
            if (responsePanel != null) {
                try {
                    burp.models.ExecutedRequest cachedResp = requestResponseCache.get(newKey);
                    if (cachedResp != null) {
                        responsePanel.displayResponse(cachedResp);
                    } else {
                        responsePanel.clear();
                    }
                } catch (Throwable ignore) {
                    try { responsePanel.clear(); } catch (Throwable ignore2) {}
                }
            }

            // Also reflect this request in the open-tabs strip above the
            // builder so the user can quickly switch between recently-opened
            // requests. Single click on the tab re-routes to this handler.
            try {
                if (openTabsStrip != null) openTabsStrip.openOrFocus(newKey, request);
            } catch (Exception ignore) { }

            currentLoadedKey = newKey;
            // Tell the builder which folder/request this came from so Send to Repeater
            // can produce a "METHOD - FOLDER - NAME" tab title.
            try {
                builderPanel.setSourceContext(folderPathForKey, reqNameForKey);
                // Show "Inherit auth from parent" detail = the resolved registry override (if any)
                try {
                    burp.auth.FolderAuthRegistry reg = importer.getFolderAuthRegistry();
                    final String resolvePath = folderPathForKey == null ? "" : folderPathForKey;
                    final String urlLowerForAuth = clone.url == null ? "" : clone.url.toString().toLowerCase();
                    final boolean isTokenEndpointAuth =
                            urlLowerForAuth.contains("/oauth2/token")
                            || urlLowerForAuth.contains("/oauth/token")
                            || urlLowerForAuth.contains("/connect/token")
                            || urlLowerForAuth.endsWith("/token")
                            || urlLowerForAuth.contains("login.microsoftonline.com")
                            || urlLowerForAuth.contains("login.windows.net");
                    String desc = "No Auth";  // default when no ancestor has an override
                    if (!isTokenEndpointAuth && reg != null && !resolvePath.isEmpty()) {
                        burp.auth.FolderAuthOverride ov = reg.resolve(resolvePath);
                        if (ov != null && ov.type != null) desc = ov.type.label;
                    }
                    // Fall back to walking the ancestor chain (collection root,
                    // wrapper, parent folders) for any auth declared in the
                    // imported collection JSON. This catches OAuth2/Bearer set
                    // at the CAT wrapper or any intermediate folder.
                    if (!isTokenEndpointAuth && "No Auth".equals(desc) && importer != null) {
                        try {
                            burp.models.PostmanCollection.Auth ancestorAuth =
                                    (resolvePath == null || resolvePath.isEmpty())
                                            ? importer.getCollectionRootAuth()
                                            : importer.resolveFolderAuthObject(resolvePath);
                            if (ancestorAuth == null) {
                                ancestorAuth = importer.getCollectionRootAuth();
                            }
                            if (ancestorAuth != null && ancestorAuth.type != null && !ancestorAuth.type.isEmpty()) {
                                String t = ancestorAuth.type.toLowerCase();
                                if ("oauth2".equals(t))      desc = "OAuth 2.0";
                                else if ("bearer".equals(t)) desc = "Bearer Token";
                                else if ("basic".equals(t))  desc = "Basic Auth";
                                else if ("apikey".equals(t)) desc = "API Key";
                                else if ("noauth".equals(t)) desc = "No Auth";
                                else                          desc = ancestorAuth.type;
                            }
                        } catch (Throwable ignore) { }
                    }
                    builderPanel.setInheritedAuthDescription(desc);
                    // Supplier so the builder can apply inherited auth to headers (null for token endpoints)
                    builderPanel.setInheritedAuthSupplier(() -> {
                        if (isTokenEndpointAuth) return null;
                        // 1. Folder/request-level override wins
                        burp.auth.FolderAuthOverride ov = reg == null ? null : reg.resolve(resolvePath);
                        if (ov != null && ov.type != null
                                && ov.type != burp.auth.FolderAuthOverride.Type.INHERIT) {
                            return ov;
                        }
                        // 2. Walk ancestors via importer to find inherited auth.
                        //    In workspace mode currentCollection.auth is null but the
                        //    wrapper holds the OAuth2 auth — getCollectionRootAuth
                        //    falls back to the single wrapper's auth when needed.
                        burp.models.PostmanCollection.Auth ancestorAuth = null;
                        try {
                            ancestorAuth = (resolvePath == null || resolvePath.isEmpty())
                                    ? importer.getCollectionRootAuth()
                                    : importer.resolveFolderAuthObject(resolvePath);
                            if (ancestorAuth == null) ancestorAuth = importer.getCollectionRootAuth();
                        } catch (Throwable ignore) { }
                        // 3. Synthesize override from ancestor auth, populated with the
                        //    freshest token (AuthManager → {{token}} → bearer literal → oauth2.accessToken).
                        try {
                            burp.models.PostmanCollection.Auth root = ancestorAuth;
                            if (root == null || root.type == null || root.type.isEmpty()) return null;
                            String t = root.type.toLowerCase();
                            burp.auth.FolderAuthOverride synth = new burp.auth.FolderAuthOverride();
                            String latest = null;
                            try {
                                burp.auth.AuthManager am = importer.getAuthManager();
                                if (am != null && am.hasAccessToken()) latest = am.getAccessToken();
                            } catch (Throwable ignore) { }
                            if (latest == null || latest.isEmpty()) {
                                try {
                                    String v = importer.getVariableResolver().getVariables().get("token");
                                    if (v != null && !v.isEmpty() && !v.contains("{{")) latest = v;
                                } catch (Throwable ignore) { }
                            }
                            if ("oauth2".equals(t) || "bearer".equals(t) || "jwt".equals(t)) {
                                synth.type = "oauth2".equals(t)
                                        ? burp.auth.FolderAuthOverride.Type.OAUTH2
                                        : burp.auth.FolderAuthOverride.Type.BEARER;
                                if (latest == null || latest.isEmpty()) {
                                    // Try the bearer literal stored on the auth (might be {{token_xxx}})
                                    // For oauth2, also reads oauth2.accessToken (Postman-stored token).
                                    try {
                                        String raw = importer.extractAccessTokenFromAuth(root);
                                        if (raw != null && !raw.isEmpty()) {
                                            if (raw.contains("{{")) {
                                                String resolved = importer.getVariableResolver().resolve(raw);
                                                if (resolved != null && !resolved.contains("{{")) latest = resolved;
                                            } else {
                                                latest = raw;
                                            }
                                        }
                                    } catch (Throwable ignore) { }
                                }
                                if (latest != null && !latest.isEmpty()) synth.put("token", latest);
                                return synth;
                            }
                        } catch (Throwable ignore) { }
                        return ov;
                    });
                } catch (Exception ignore) { }
            } catch (Exception ignore) { }
            // (Response cache snapshot/restore already done at the top of this
            // handler — before currentLoadedKey gets overwritten.)
            // Auto-switch to Builder tab when clicking a request
            {
                int rbIdx = rightTabbedPaneRef[0].indexOfTab("Request Builder");
                if (rbIdx >= 0) rightTabbedPaneRef[0].setSelectedIndex(rbIdx);
            }
            // Coming from workspace view → restore the request tabs.
            setRightTabsVisible(rightTabbedPaneRef[0], true);
            // Swap CardLayout back to the request view (in case a folder was previously shown)
            if (builderCardHostRef[0] != null) {
                ((CardLayout) builderCardHostRef[0].getLayout()).show(builderCardHostRef[0], "REQUEST");
            }
        });
        
        // ✅ BUILD TABBED RIGHT PANEL
        JTabbedPane rightTabbedPane = new JTabbedPane();
        rightTabbedPane.setFont(UITheme.boldFont(12f));
        rightTabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        
        // TAB 1: Request Builder OR Folder Auth editor (CardLayout swap)
        JPanel builderCardHost = new JPanel(new CardLayout());
        JSplitPane builderResponseSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, builderPanel, responsePanel);
        builderResponseSplit.setResizeWeight(0.5);
        builderResponseSplit.setContinuousLayout(true);
        burp.ui.FolderAuthEditorPanel folderEditor =
                new burp.ui.FolderAuthEditorPanel(importer.getFolderAuthRegistry(), importer.getAuthManager(), importer);
        folderEditorRef = folderEditor;

        // Open-requests tab strip REMOVED — it leaked stale tabs across
        // collection switches and the deep-iteration tree match (which used
        // identity comparison on AnalyzedRequest.getRequest()) routed clicks
        // to the wrong request after a re-import. Postman's tab system is
        // tightly coupled to their data model; the cost of a faithful port
        // outweighs the benefit when our tree already gives single-click
        // navigation. Field kept nullable so existing null-guards stay safe.
        openTabsStrip = null;

        builderCardHost.add(builderResponseSplit, "REQUEST");
        builderCardHost.add(folderEditor, "FOLDER");

        // TAB 0: Overview — Bruno-style collection landing page with
        // location, workspace path, env summary, request count, and
        // action links (Add env, Link folder, New env, Rescan, Open
        // workspace). Keeps the top workspace bar minimal while giving
        // users a richer landing spot for one-click actions.
        overviewPanel = buildOverviewPanel();
        rightTabbedPane.addTab("Overview", overviewPanel);

        rightTabbedPane.addTab("Request Builder", builderCardHost);

        // TAB 2: Auth Manager
        rightTabbedPane.addTab("Auth Manager", authWrapper);
        
        // Wire folder/collection clicks to swap the card and load the editor
        treePanel.setFolderNodeClickListener((node, path, isCollection) -> {
            String name = node != null ? node.toString() : "";
            // Workspace root has no path — show a friendly empty state and
            // hide the per-request tabs that don't apply at workspace level.
            boolean isWorkspaceRoot = (path == null || path.isEmpty())
                    && (node != null && node.getParent() == null);
            setRightTabsVisible(rightTabbedPaneRef[0], !isWorkspaceRoot);
            if (isWorkspaceRoot) {
                try { if (authManagerPanel != null) authManagerPanel.setScopeFilter(null); } catch (Exception ignore) {}
                try { importer.getVariableResolver().clearActiveScope(); } catch (Exception ignore) {}
                return;
            }
            folderEditor.loadFor(path, name, isCollection);
            ((CardLayout) builderCardHost.getLayout()).show(builderCardHost, "FOLDER");
            {
                int rbIdx = rightTabbedPaneRef[0].indexOfTab("Request Builder");
                if (rbIdx >= 0) rightTabbedPaneRef[0].setSelectedIndex(rbIdx);
            }
            // Mirror the scope into Auth Manager so its endpoint table only
            // shows JWT candidates that belong to the clicked collection/folder.
            try { if (authManagerPanel != null) authManagerPanel.setScopeFilter(path); } catch (Exception ignore) {}
            // Switch the variable resolver to this collection's scope so
            // {{token}} previews / sends use per-collection overrides.
            try {
                String topScope = (path == null || path.isEmpty())
                        ? null
                        : (path.contains("/") ? path.substring(0, path.indexOf('/')) : path);
                importer.getVariableResolver().setActiveScope(topScope);
                refreshVariables(importer.getVariableResolver().getVariables());
            } catch (Exception ignore) {}
        });
        // Card-swap reference for the existing request-click handler to use
        builderCardHostRef[0] = builderCardHost;

        // When folder/collection auth changes, re-sync the currently loaded request's headers
        try {
            importer.getFolderAuthRegistry().addChangeListener(() ->
                SwingUtilities.invokeLater(() -> {
                    try { builderPanel.syncInheritedAuth(); } catch (Exception ignore) {}
                })
            );
        } catch (Exception ignore) { }
        
        // TAB 3: Request History
        rightTabbedPane.addTab("History", historyPanel);

        // TAB 4: Run Results — Postman/Bruno-style runner output
        runResultsPanel = new RunResultsPanel();
        runResultsPanel.setCookieJar(importer.getCookieJar());
        rightTabbedPane.addTab("Run Results", runResultsPanel);

        // Cookie jar tab — captured cookies, editable/removable.
        // Live-update the tab title with the current cookie count so users
        // can see at a glance whether there is session state to clear.
        final burp.service.CookieJar cookieJarRef = importer.getCookieJar();
        final int cookiesTabIndex = rightTabbedPane.getTabCount();
        rightTabbedPane.addTab("Cookies", new burp.ui.CookieJarPanel(cookieJarRef));
        final javax.swing.JTabbedPane rightTabsRef = rightTabbedPane;
        final Runnable refreshCookiesTitle = () -> {
            if (cookieJarRef == null) return;
            int count = 0;
            try { count = cookieJarRef.getAll().size(); } catch (Exception ignore) {}
            final String title = count > 0 ? "Cookies (" + count + ")" : "Cookies";
            SwingUtilities.invokeLater(() -> {
                if (cookiesTabIndex < rightTabsRef.getTabCount()) {
                    rightTabsRef.setTitleAt(cookiesTabIndex, title);
                }
            });
        };
        if (cookieJarRef != null) {
            cookieJarRef.addChangeListener(refreshCookiesTitle);
        }
        refreshCookiesTitle.run();

        // Logs tab (requested order: after Cookies)
        rightTabbedPane.addTab("Logs", logPanel);

        // ─── Postman-style: removed the redundant 🗂 Workspace (Tabs),
        // 📋 Code, 🖥 Console right-pane tabs. They duplicated existing UI:
        //   - "🗂 Workspace" duplicated the single Request Builder above.
        //   - "📋 Code" duplicated the tree right-click "Copy as code" submenu.
        //   - "🖥 Console" duplicated script/log visibility already covered by the Logs tab.
        // Keep the panel fields nullable so other code paths that null-check
        // them (e.g. snippetPanel.setRequest in tree-click handler) skip
        // gracefully instead of NPE'ing.
        requestTabsPanel = null;
        snippetPanel = null;
        consolePanel = null;

        // Save reference for tab switching from listener
        rightTabbedPaneRef[0] = rightTabbedPane;
        rightTabbedPaneField = rightTabbedPane;

        // Wrap tabs + a workspace placeholder in a CardLayout so we can hide
        // request-level UI when the user clicks the Workspace root.
        final JPanel rightCardHost = new JPanel(new CardLayout());
        rightCardHost.add(rightTabbedPane, "TABS");
        rightCardHost.add(buildWorkspaceOverview(), "WORKSPACE");
        rightCardHostRef = rightCardHost;
        // Default — show tabs (no workspace selection at startup).
        ((CardLayout) rightCardHost.getLayout()).show(rightCardHost, "TABS");

        // Tree container (Run Scripts CTA now renders under Request Builder
        // Save row instead of above the tree).
        JPanel treeContainer = new JPanel(new BorderLayout());
        treeContainer.add(treePanel, BorderLayout.CENTER);

        // ✅ MAIN SPLIT (TREE LEFT, TABS RIGHT)
        JSplitPane mainSplitPane = new JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            treeContainer,
            rightCardHost
        );
        
        mainSplitPane.setResizeWeight(0.25); // Tree takes ~25%, rest takes ~75%
        mainSplitPane.setContinuousLayout(true);
        mainSplitPane.setOneTouchExpandable(true);
        // Minimums are additive and drive the whole panel's floor width.
        // On a 1366px screen with ~1280px usable for us, tree(170) +
        // right(220) + splits + borders = 400+ px consumed before any
        // content — leaving barely 880 for tabs, which cuts them off.
        // Lower everything to a floor that still keeps content readable
        // but lets the parent scrollpane shrink cleanly.
        treeContainer.setMinimumSize(new Dimension(compactDisplay ? 110 : 150, 100));
        rightCardHost.setMinimumSize(new Dimension(compactDisplay ? 180 : 220, 100));
        authWrapper.setMinimumSize(new Dimension(100, 70));
        logPanel.setMinimumSize(new Dimension(100, 70));
        builderPanel.setMinimumSize(new Dimension(100, 70));
        responsePanel.setMinimumSize(new Dimension(100, 70));

        // Adaptive divider setup: set sensible initial ratios and clamp on
        // resize so small screens keep both panes visible.
        final int[] lastBuilderTarget = new int[] { -1 };
        Runnable adaptSplits = () -> {
            try {
                int w = Math.max(1, mainSplitPane.getWidth());
                // Thresholds tuned for narrower screens: at 900-1280px the
                // tree needs to stay compact so tabs on the right have room
                // to breathe. Above 1400 we can afford wider.
                int treeMin = w < 900 ? 110 : (w < 1280 ? 140 : (w < 1500 ? 170 : 210));
                int rightMin = w < 900 ? 320 : (w < 1280 ? 380 : 420);
                int maxTree = Math.max(treeMin, w - rightMin);
                int cur = mainSplitPane.getDividerLocation();
                if (cur <= 0) {
                    double leftRatio = w < 900 ? 0.18 : (w < 1280 ? 0.20 : (w < 1500 ? 0.22 : 0.24));
                    mainSplitPane.setDividerLocation(leftRatio);
                } else {
                    int clamped = Math.max(treeMin, Math.min(cur, maxTree));
                    if (clamped != cur) mainSplitPane.setDividerLocation(clamped);
                }
            } catch (Exception ignore) {}
            try {
                int h = Math.max(1, builderResponseSplit.getHeight());
                // Content-driven divider: builder takes only as much vertical
                // room as the current inner tab (URL bar + Params/Headers/Body
                // rows + a small pad) actually needs. That leaves the response
                // panel with the bulk of the viewport — Postman/Bruno UX —
                // instead of a 50/50 split that pushes the response below the
                // fold when the body is small.
                int builderTarget;
                if (builderPanel != null) {
                    builderTarget = builderPanel.getContentBasedBuilderHeight(h);
                } else {
                    builderTarget = h < 620 ? 220 : 260;
                }
                int builderFloor = 130;
                int responseMin = Math.max(h < 620 ? 150 : 180, (int) Math.round(h * 0.34));
                int maxBuilder = Math.max(builderFloor, h - responseMin);
                builderTarget = Math.max(builderFloor, Math.min(builderTarget, maxBuilder));

                int cur = builderResponseSplit.getDividerLocation();
                boolean targetShifted = lastBuilderTarget[0] < 0
                        || Math.abs(builderTarget - lastBuilderTarget[0]) >= 24;
                if (cur <= 0) {
                    builderResponseSplit.setDividerLocation(builderTarget);
                } else if (targetShifted) {
                    // Content just changed (tab switch, edit) — snap to the
                    // new content-based target so the user immediately sees
                    // a well-sized layout.
                    builderResponseSplit.setDividerLocation(builderTarget);
                } else {
                    // Preserve user's manual drag but keep both halves visible.
                    int clamped = Math.max(builderFloor, Math.min(cur, maxBuilder));
                    if (clamped != cur) builderResponseSplit.setDividerLocation(clamped);
                }
                lastBuilderTarget[0] = builderTarget;
            } catch (Exception ignore) {}
        };
        SwingUtilities.invokeLater(adaptSplits);
        mainSplitPane.addComponentListener(new ComponentAdapter() {
            @Override public void componentResized(ComponentEvent e) { adaptSplits.run(); }
        });
        builderResponseSplit.addComponentListener(new ComponentAdapter() {
            @Override public void componentResized(ComponentEvent e) { adaptSplits.run(); }
        });
        if (builderPanel != null) {
            builderPanel.addLayoutHintListener(() -> SwingUtilities.invokeLater(adaptSplits));
        }
        
        contentPanel.add(mainSplitPane, BorderLayout.CENTER);
    
        
        // ----- Advanced toolbar (collapsible — hidden by default) -----
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.Y_AXIS));
        buttonPanel.setOpaque(false);
        // Keep inner content visible; the outer scroll wrapper is what toggles.
        buttonPanel.setVisible(true);

        previewButton = UITheme.button("Preview Requests", UITheme.BtnStyle.GHOST);
        previewButton.addActionListener(e -> startPreview());
        previewButton.setEnabled(false);

        importButton = UITheme.button("Import Collection", UITheme.BtnStyle.ACCENT);
        importButton.addActionListener(e -> startImport());
        importButton.setEnabled(false);

        retryButton = UITheme.button("Retry", UITheme.BtnStyle.GHOST);
        retryButton.addActionListener(e -> startRetry());
        retryButton.setEnabled(false);
        retryButton.setToolTipText("Retry failed request");

        cancelButton = UITheme.button("Cancel", UITheme.BtnStyle.DANGER);
        cancelButton.setEnabled(false);

        JButton editEnvBtn = UITheme.button("Edit Env", UITheme.BtnStyle.GHOST);
        editEnvBtn.addActionListener(e -> {
            EnvironmentEditor editor = new EnvironmentEditor(importer);
            editor.showDialog(mainPanel);
        });

        final JButton engineModeBtn = UITheme.button("", UITheme.BtnStyle.GHOST);
        final Runnable refreshEngineBtn = () -> {
            burp.service.ScriptExecutor.EngineMode mode =
                burp.service.ScriptExecutor.getPreferredEngineMode();
            boolean rh = burp.service.ScriptExecutor.isRhinoRuntimeAvailable();
            boolean na = burp.service.ScriptExecutor.isNashornRuntimeAvailable();
            if (!na && mode == burp.service.ScriptExecutor.EngineMode.NASHORN) {
                mode = burp.service.ScriptExecutor.EngineMode.AUTO;
                burp.service.ScriptExecutor.setPreferredEngineMode(mode);
            }
            engineModeBtn.setText("Engine: " + displayEngineMode(mode));
            String cycle = na ? "Auto -> Full -> Legacy" : "Auto -> Full";
            String tooltip = "Cycle script engine mode (" + cycle + "). "
                    + "Full engine: " + (rh ? "available" : "missing");
            if (na) {
                tooltip += ", Legacy JS: available";
            } else {
                tooltip += ". Legacy JS runtime is not bundled in this build.";
            }
            engineModeBtn.setToolTipText(tooltip);
        };
        engineModeBtn.addActionListener(e -> {
            burp.service.ScriptExecutor.EngineMode cur =
                burp.service.ScriptExecutor.getPreferredEngineMode();
            boolean na = burp.service.ScriptExecutor.isNashornRuntimeAvailable();
            if (!na && cur == burp.service.ScriptExecutor.EngineMode.NASHORN) {
                cur = burp.service.ScriptExecutor.EngineMode.AUTO;
                burp.service.ScriptExecutor.setPreferredEngineMode(cur);
            }
            burp.service.ScriptExecutor.EngineMode next;
            switch (cur) {
                case RHINO:
                    next = na
                            ? burp.service.ScriptExecutor.EngineMode.NASHORN
                            : burp.service.ScriptExecutor.EngineMode.AUTO;
                    break;
                case NASHORN:
                    next = burp.service.ScriptExecutor.EngineMode.AUTO;
                    break;
                case AUTO:
                default:
                    next = burp.service.ScriptExecutor.EngineMode.RHINO;
                    break;
            }
            burp.service.ScriptExecutor.setPreferredEngineMode(next);
            refreshEngineBtn.run();
            appendLog("⚙ Script engine mode set to " + displayEngineMode(next));
        });
        refreshEngineBtn.run();

        // Legacy run controls are still available, but hidden by default for
        // the newer Postman-like workflow where import/send is tree-first.
        final JPanel legacyRunCorePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        legacyRunCorePanel.setOpaque(false);
        legacyRunCorePanel.setBorder(UITheme.titled("Legacy Run Core"));
        legacyRunCorePanel.add(previewButton);
        legacyRunCorePanel.add(retryButton);
        legacyRunCorePanel.add(cancelButton);
        legacyRunCorePanel.add(importButton);
        legacyRunCorePanel.add(editEnvBtn);
        legacyRunCorePanel.setVisible(false);
        final JLabel legacyLabel = new JLabel("Legacy ");
        legacyLabel.setFont(UITheme.baseFont().deriveFont(11f));
        legacyLabel.setForeground(UITheme.subtleText());
        final CollectionTreePanel.IosToggleSwitch legacyToggle = new CollectionTreePanel.IosToggleSwitch(false);
        legacyToggle.setToolTipText(
                "<html>When ON: show legacy run controls (Preview, Retry, Cancel, Import Collection).<br/>"
                        + "When OFF: hide them and keep the modern tree-first flow.</html>");
        legacyToggle.addChangeListener(e -> {
            legacyRunCorePanel.setVisible(legacyToggle.isOn());
            buttonPanel.revalidate();
            buttonPanel.repaint();
        });
        JPanel legacyToggleBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        legacyToggleBox.setOpaque(false);
        legacyToggleBox.add(legacyLabel);
        legacyToggleBox.add(legacyToggle);

        JPanel commonGroup = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        commonGroup.setOpaque(false);
        commonGroup.setBorder(UITheme.titled("Common"));
        commonGroup.add(legacyToggleBox);
        buttonPanel.add(commonGroup);

        JPanel runtimeGroup = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        runtimeGroup.setOpaque(false);
        runtimeGroup.setBorder(UITheme.titled("Script Runtime"));
        runtimeGroup.add(engineModeBtn);
        buttonPanel.add(runtimeGroup);

        JPanel ioGroup = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        ioGroup.setOpaque(false);
        ioGroup.setBorder(UITheme.titled("Import / Export"));
        if (advancedOpenApiBtn != null) ioGroup.add(advancedOpenApiBtn);
        if (advancedExportBtn != null) ioGroup.add(advancedExportBtn);
        if (advancedSaveEnvBtn != null) ioGroup.add(advancedSaveEnvBtn);
        ioGroup.setVisible(ioGroup.getComponentCount() > 0);
        buttonPanel.add(ioGroup);

        JPanel powerGroup = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        powerGroup.setOpaque(false);
        powerGroup.setBorder(UITheme.titled("Power Tools"));
        try {
            if (treePanel != null) {
                JButton curlBtn = treePanel.takeCurlButton();
                if (curlBtn != null) powerGroup.add(curlBtn);
                JButton wsBtn = treePanel.takeWsButton();
                if (wsBtn != null) powerGroup.add(wsBtn);
                JPanel multiBox = treePanel.takeMultiBox();
                if (multiBox != null) powerGroup.add(multiBox);
            }
        } catch (Throwable ignore) {}
        powerGroup.setVisible(powerGroup.getComponentCount() > 0);
        buttonPanel.add(powerGroup);
        buttonPanel.add(legacyRunCorePanel);

        // Keep the top header fixed but make the main workspace scrollable on
        // short displays so tabs/splits never get clipped off-screen.
        // Stack the toolbar above the legacy header so both are visible.
        // appToolbar can be null if FlatLaf was missing or its handlers
        // constructor failed — in that case skip it gracefully.
        // appToolbar is intentionally null — legacy header restored above.
        // northStack kept for layout symmetry but contains only the headerPanel.
        JPanel northStack = new JPanel(new BorderLayout(0, 0));
        if (appToolbar != null) northStack.add(appToolbar, BorderLayout.NORTH);
        northStack.add(headerPanel, BorderLayout.CENTER);
        panel.add(northStack, BorderLayout.NORTH);
        JScrollPane contentScroll = new JScrollPane(
                contentPanel,
                JScrollPane.VERTICAL_SCROLLBAR_NEVER,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        contentScroll.setBorder(BorderFactory.createEmptyBorder());
        contentScroll.getVerticalScrollBar().setUnitIncrement(14);
        contentScroll.getHorizontalScrollBar().setUnitIncrement(14);
        contentScroll.setWheelScrollingEnabled(true);
        if (compactDisplay) {
            contentScroll.getVerticalScrollBar().setBlockIncrement(72);
            contentScroll.getHorizontalScrollBar().setBlockIncrement(72);
        }
        panel.add(contentScroll, BorderLayout.CENTER);

        // Advanced controls now open as a popup from the Request Builder row.
        final JScrollPane advancedScroll = new JScrollPane(
                buttonPanel,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        advancedScroll.setBorder(BorderFactory.createEmptyBorder());
        advancedScroll.getViewport().setOpaque(false);
        advancedScroll.setOpaque(false);
        advancedScroll.getVerticalScrollBar().setUnitIncrement(12);

        final JPopupMenu advancedPopup = new JPopupMenu();
        advancedPopup.setLayout(new BorderLayout());
        advancedPopup.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UITheme.border()),
                BorderFactory.createEmptyBorder(6, 6, 6, 6)));
        advancedPopup.setOpaque(true);
        advancedPopup.setBackground(UITheme.surface());
        advancedPopup.add(advancedScroll, BorderLayout.CENTER);

        final JButton builderAdvancedBtn = UITheme.button("Advanced ▾", UITheme.BtnStyle.GHOST);
        builderAdvancedBtn.setToolTipText("Open advanced controls popup.");
        builderAdvancedBtn.setPreferredSize(new Dimension(110, 38));
        builderAdvancedBtn.setMinimumSize(new Dimension(110, 38));
        final JButton builderEditVarsBtn = UITheme.button("Edit Variables", UITheme.BtnStyle.GHOST);
        builderEditVarsBtn.setToolTipText("Open the variables editor dialog");
        builderEditVarsBtn.setPreferredSize(new Dimension(132, 38));
        builderEditVarsBtn.setMinimumSize(new Dimension(132, 38));
        builderEditVarsBtn.addActionListener(e -> showManualVariablesDialog());
        java.awt.event.ActionListener showAdvancedPopup = e -> {
            if (!(e.getSource() instanceof JComponent)) return;
            JComponent source = (JComponent) e.getSource();
            if (advancedPopup.isVisible() && advancedPopup.getInvoker() == source) {
                advancedPopup.setVisible(false);
                return;
            }
            if (advancedPopup.isVisible()) advancedPopup.setVisible(false);
            buttonPanel.revalidate();
            buttonPanel.repaint();
            Dimension pref = buttonPanel.getPreferredSize();
            int popupW = Math.max(520, Math.min(860, pref.width + 28));
            int popupH = Math.max(220, Math.min(420, pref.height + 20));
            advancedScroll.setPreferredSize(new Dimension(popupW, popupH));
            int x = Math.min(0, source.getWidth() - popupW);
            java.awt.Component root = SwingUtilities.getRoot(source);
            if (root instanceof JComponent) {
                JComponent rootComp = (JComponent) root;
                Point srcInRoot = SwingUtilities.convertPoint(source, 0, 0, rootComp);
                int clampedX = Math.max(0, Math.min(srcInRoot.x, Math.max(0, rootComp.getWidth() - popupW)));
                x = clampedX - srcInRoot.x;
            }
            advancedPopup.show(source, x, source.getHeight() + 2);
        };
        builderAdvancedBtn.addActionListener(showAdvancedPopup);
        // Keep Advanced hidden by default. Reveal/toggle via Ctrl+Shift+/.
        final boolean[] advancedBtnVisible = new boolean[] { false };
        Runnable applyBuilderButtons = () -> {
            if (builderPanel == null) return;
            builderPanel.setPreSaveControls(
                    builderEditVarsBtn,
                    advancedBtnVisible[0] ? builderAdvancedBtn : null
            );
        };
        applyBuilderButtons.run();
        int advancedShortcutMask = UndoSupport.getMenuShortcutMaskCompat()
                | java.awt.event.InputEvent.SHIFT_DOWN_MASK;
        InputMap rootIm = panel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
        ActionMap rootAm = panel.getActionMap();
        rootIm.put(
                KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_SLASH, advancedShortcutMask),
                "burpman-toggle-advanced-button"
        );
        rootIm.put(
                KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_DIVIDE, advancedShortcutMask),
                "burpman-toggle-advanced-button"
        );
        rootAm.put("burpman-toggle-advanced-button", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                advancedBtnVisible[0] = !advancedBtnVisible[0];
                if (!advancedBtnVisible[0] && advancedPopup.isVisible()) {
                    advancedPopup.setVisible(false);
                }
                applyBuilderButtons.run();
                appendLog("🧰 Advanced button "
                        + (advancedBtnVisible[0] ? "shown" : "hidden")
                        + " (Ctrl+Shift+/)");
            }
        });

        JPanel footerPanel = new JPanel(new BorderLayout());
        footerPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, UITheme.border()),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)));
        footerPanel.setBackground(UITheme.surface());
        footerPanel.setOpaque(true);

        JLabel creditLabel = new JLabel("BurpMan v1.0.0  •  by John Riocel Cenon");
        creditLabel.setFont(UITheme.baseFont().deriveFont(Font.PLAIN, 11f));
        creditLabel.setForeground(UITheme.subtleText());
        creditLabel.setToolTipText("https://github.com/JohnRiocelCenon/BurpMan");
        footerPanel.add(creditLabel, BorderLayout.WEST);

        panel.add(footerPanel, BorderLayout.SOUTH);
        installZoomShortcuts(panel);

        return panel;
    }
    public void showManualVariablesDialog() {

        try {

            // Build scope options: Workspace (global) + each collection wrapper.
            final java.util.List<String> scopeNames = new java.util.ArrayList<>();
            scopeNames.add("Workspace (global)");
            try {
                burp.models.PostmanCollection cc = importer.getCurrentCollection();
                if (cc != null && cc.item != null) {
                    for (burp.models.PostmanCollection.Item it : cc.item) {
                        if (it != null && it.isCollectionWrapper && it.name != null) {
                            scopeNames.add("Collection: " + it.name);
                        }
                    }
                }
            } catch (Exception ignore) {}

            final JComboBox<String> scopeCombo = new JComboBox<>(scopeNames.toArray(new String[0]));
            // Default to currently active scope if any.
            String active = importer.getVariableResolver().getActiveScope();
            if (active != null && !active.isEmpty()) {
                String want = "Collection: " + active;
                for (int i = 0; i < scopeNames.size(); i++) {
                    if (scopeNames.get(i).equals(want)) { scopeCombo.setSelectedIndex(i); break; }
                }
            }

            final java.util.function.Function<String, String> scopeKey = label -> {
                if (label == null || label.startsWith("Workspace")) return null;
                return label.startsWith("Collection: ") ? label.substring("Collection: ".length()) : null;
            };

            // ✅ Load existing variables using old logic
            String existingText =
                    buildExistingVariablesText();

            Map<String, String> currentVars =
                    parseManualVariables(existingText);

            // If a collection scope is active, show ONLY that collection's
            // variables (strict isolation). Don't overlay detected names
            // from other collections — those would appear as phantom empty rows.
            String initialScope = scopeKey.apply((String) scopeCombo.getSelectedItem());
            if (initialScope != null) {
                currentVars = new java.util.LinkedHashMap<>(
                        importer.getVariableResolver().getScopedVariables(initialScope));
            }

            if (currentVars == null ||
                    currentVars.isEmpty()) {
                currentVars = new java.util.LinkedHashMap<>();
            }

            // ✅ Build table model
            String[] columns = {
                    "Variable",
                    "Value"
            };

            java.util.List<String> keys =
                    new ArrayList<>(
                            currentVars.keySet()
                    );

            Collections.sort(keys);

            Object[][] data =
                    new Object[keys.size()][2];

            for (int i = 0; i < keys.size(); i++) {

                String key = keys.get(i);

                data[i][0] = key;
                data[i][1] = currentVars.get(key);
            }

            // Snapshot original keys so we can detect deletions on OK.
            final java.util.Set<String> originalKeys = new java.util.HashSet<>(currentVars.keySet());
            // Holds the scope the table was last loaded for. Initialised to
            // the value selected when the dialog opened.
            final String[] tableScopeRef = { initialScope };
            final java.util.Set<String>[] originalKeysRef = new java.util.Set[]{ originalKeys };

            JTable table =
                    new JTable(
                            new javax.swing.table.DefaultTableModel(data, columns) {
                                @Override
                                public Class<?> getColumnClass(int col) { return String.class; }
                            }
                    );

            // Helper to reload the table's rows from a given scope key (null = global).
            final java.util.function.Consumer<String> reloadForScope = scope -> {
                java.util.Map<String, String> rows = new java.util.LinkedHashMap<>();
                if (scope != null) {
                    // Strict isolation — show only THIS collection's variables.
                    rows.putAll(importer.getVariableResolver().getScopedVariables(scope));
                } else {
                    java.util.Map<String, String> globals = parseManualVariables(buildExistingVariablesText());
                    if (globals != null) rows.putAll(globals);
                }
                java.util.List<String> ks = new ArrayList<>(rows.keySet());
                Collections.sort(ks);
                javax.swing.table.DefaultTableModel m =
                        (javax.swing.table.DefaultTableModel) table.getModel();
                m.setRowCount(0);
                for (String k : ks) m.addRow(new Object[]{ k, rows.get(k) });
                originalKeysRef[0] = new java.util.HashSet<>(rows.keySet());
                tableScopeRef[0] = scope;
            };

            scopeCombo.addActionListener(ev -> {
                if (table.isEditing()) table.getCellEditor().stopCellEditing();
                String s = scopeKey.apply((String) scopeCombo.getSelectedItem());
                reloadForScope.accept(s);
            });

            // ✅ Commit edits when focus leaves the cell.
            table.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);

            table.setFillsViewportHeight(true);

            table.setRowHeight(26);

            table.getTableHeader()
                    .setReorderingAllowed(false);

            table.setAutoResizeMode(
                    JTable.AUTO_RESIZE_LAST_COLUMN
            );

            // ✅ Column widths
            table.getColumnModel()
                    .getColumn(0)
                    .setPreferredWidth(220);

            table.getColumnModel()
                    .getColumn(1)
                    .setPreferredWidth(420);

            JScrollPane scrollPane =
                    new JScrollPane(table);

            scrollPane.setPreferredSize(
                    new Dimension(720, 360)
            );

            // ✅ Add / Remove variable buttons
            JButton addRowBtn = new JButton("➕ Add Variable");
            JButton removeRowBtn = new JButton("➖ Remove Selected");
            addRowBtn.addActionListener(ev -> {
                if (table.isEditing()) table.getCellEditor().stopCellEditing();
                javax.swing.table.DefaultTableModel m =
                        (javax.swing.table.DefaultTableModel) table.getModel();
                m.addRow(new Object[]{"", ""});
                int newRow = m.getRowCount() - 1;
                table.setRowSelectionInterval(newRow, newRow);
                table.editCellAt(newRow, 0);
                java.awt.Component editor = table.getEditorComponent();
                if (editor != null) editor.requestFocusInWindow();
            });
            removeRowBtn.addActionListener(ev -> {
                if (table.isEditing()) table.getCellEditor().stopCellEditing();
                int row = table.getSelectedRow();
                if (row >= 0) {
                    javax.swing.table.DefaultTableModel m =
                            (javax.swing.table.DefaultTableModel) table.getModel();
                    m.removeRow(row);
                }
            });
            JPanel rowButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
            rowButtons.add(addRowBtn);
            rowButtons.add(removeRowBtn);

            // ✅ Header
            JLabel titleLabel =
                    new JLabel("Edit Variables");

            titleLabel.setFont(
                    titleLabel.getFont()
                            .deriveFont(Font.BOLD, 16f)
            );

            JLabel helpLabel =
                    new JLabel(
                            "Workspace = shared by all collections. " +
                            "Collection scope overrides Workspace for that collection only."
                    );
            helpLabel.setFont(helpLabel.getFont().deriveFont(Font.PLAIN, 11f));
            helpLabel.setForeground(new Color(0x666666));

            JPanel scopeRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            scopeRow.add(new JLabel("Scope:"));
            scopeRow.add(scopeCombo);

            JPanel headerPanel =
                    new JPanel(
                            new BorderLayout(0, 6)
                    );

            headerPanel.add(
                    titleLabel,
                    BorderLayout.NORTH
            );

            headerPanel.add(scopeRow, BorderLayout.CENTER);
            headerPanel.add(helpLabel, BorderLayout.SOUTH);

            // ✅ Main panel
            JPanel panel =
                    new JPanel(
                            new BorderLayout(10, 10)
                    );

            panel.setBorder(
                    BorderFactory.createEmptyBorder(
                            12,
                            12,
                            12,
                            12
                    )
            );

            panel.add(
                    headerPanel,
                    BorderLayout.NORTH
            );

            panel.add(
                    scrollPane,
                    BorderLayout.CENTER
            );

            panel.add(rowButtons, BorderLayout.SOUTH);

            int result =
                    JOptionPane.showConfirmDialog(
                            mainPanel,
                            panel,
                            "Edit Variables",
                            JOptionPane.OK_CANCEL_OPTION,
                            JOptionPane.PLAIN_MESSAGE
                    );

            if (result ==
                    JOptionPane.OK_OPTION) {

                // ✅ CRITICAL:
                // Commit active JTable cell edit before reading values.
                if (table.isEditing()) {
                    table.getCellEditor().stopCellEditing();
                }

                // ✅ Build variable map directly from JTable.
                // Do NOT convert to text and parse again.
                java.util.Map<String, String> variables =
                        new java.util.LinkedHashMap<>();

                for (int i = 0;
                        i < table.getRowCount();
                        i++) {

                    Object keyObj =
                            table.getValueAt(i, 0);

                    Object valObj =
                            table.getValueAt(i, 1);

                    if (keyObj == null) {
                        continue;
                    }

                    String key =
                            keyObj.toString().trim();

                    String value =
                            valObj != null
                                    ? valObj.toString()
                                    : "";

                    if (!key.isEmpty()) {

                        variables.put(
                                key,
                                value
                        );

                        appendLog(
                                "Edit Variables submitted: " +
                                        key +
                                        " = " +
                                        value
                        );
                    }
                }

                if (variables.isEmpty()) {

                    appendLog(
                            "No variable values were submitted from Edit Variables table."
                    );
                }

                // Apply deletions — any original key absent from the final
                // table state is now removed from the appropriate scope.
                int removedCount = 0;
                final String writeScope = tableScopeRef[0];
                for (String origKey : originalKeysRef[0]) {
                    if (!variables.containsKey(origKey)) {
                        if (writeScope != null) {
                            importer.getVariableResolver().removeScopedVariable(writeScope, origKey);
                        } else {
                            importer.getVariableResolver().removeCustomVariable(origKey);
                        }
                        appendLog("🗑️ Removed variable" +
                                (writeScope != null ? " [" + writeScope + "]" : "") + ": " + origKey);
                        removedCount++;
                    }
                }

                if (variables.isEmpty() && removedCount == 0) {
                    return;
                }

                if (!variables.isEmpty()) {
                    if (writeScope != null) {
                        // Strict scoped write — every row goes into this
                        // collection's private scope verbatim.
                        for (java.util.Map.Entry<String,String> e : variables.entrySet()) {
                            importer.getVariableResolver().putScopedVariable(
                                    writeScope, e.getKey(), e.getValue() == null ? "" : e.getValue());
                        }
                        appendLog("📌 Wrote " + variables.size() + " var(s) to scope [" + writeScope + "]");
                    } else {
                        importer.addCustomVariables(variables);
                    }

                    // If the user edited a token-style variable, push the new
                    // value straight into the Request Builder's Authorization
                    // tab so the visible Bearer field matches what will be
                    // sent (mirrors the Auth Manager Apply behaviour).
                    try {
                        String freshToken = null;
                        // Prefer the generic {{token}} if present, otherwise
                        // fall back to the first token_* entry the user touched.
                        if (variables.containsKey("token")) {
                            freshToken = variables.get("token");
                        } else {
                            for (java.util.Map.Entry<String,String> e : variables.entrySet()) {
                                String k = e.getKey();
                                if (k != null && k.toLowerCase().startsWith("token")) {
                                    freshToken = e.getValue();
                                    break;
                                }
                            }
                        }
                        if (freshToken != null && !freshToken.isEmpty() && builderPanel != null) {
                            final String tk = freshToken;
                            javax.swing.SwingUtilities.invokeLater(() -> {
                                try { builderPanel.applyBearerToken(tk); } catch (Exception ignore) {}
                                try { if (folderEditorRef != null) folderEditorRef.applyBearerToken(tk); } catch (Exception ignore) {}
                            });
                        }
                    } catch (Exception ignore) {}
                }

                // Variables changed — drop cached unsaved snapshots so the
                // next tree click re-resolves with the new values, and
                // re-trigger the current selection so Auth/Headers refresh.
                try {
                    clearUnsavedCache();
                    if (currentLoadedKey != null && !savedKeys.contains(currentLoadedKey)) {
                        currentLoadedKey = null;
                    }
                    javax.swing.JTree t = treePanel != null ? treePanel.getTree() : null;
                    javax.swing.tree.TreePath sel = t != null ? t.getSelectionPath() : null;
                    if (t != null && sel != null) {
                        t.clearSelection();
                        t.setSelectionPath(sel);
                    }
                } catch (Exception ignore) { }

                // ✅ Force refresh flow after editing variables
                appendLog("✅ Variables updated.");
            }

        } catch (Exception e) {

            JOptionPane.showMessageDialog(
                    mainPanel,
                    "Error editing variables: "
                            + e.getMessage()
            );
        }
    }
    
    private String buildExistingVariablesText() {

        try {

            // ✅ 1. Get detected variables (from collection)
            Set<String> detectedVariables =
                    new HashSet<>();

            Set<String> detected =
                    importer.getDetectedCollectionVariables();

            if (detected != null) {
                detectedVariables.addAll(detected);
            }

            // ✅ 2. Get ALL current variables from resolver
            Map<String, String> currentVariables =
                importer.getVariableResolver().getVariables();

            // ✅ 3. Merge resolver variables (like token)
            if (currentVariables != null) {
                detectedVariables.addAll(
                        currentVariables.keySet()
                );
            }

            if (detectedVariables.isEmpty()) {
                return "";
            }

            // ✅ 4. Sort keys
            java.util.List<String> sorted =
                    new ArrayList<>(detectedVariables);

            Collections.sort(sorted);

            StringBuilder builder =
                    new StringBuilder();

            // ✅ 5. Build key=value format
            for (String key : sorted) {

                if (key != null && key.startsWith("$")) {
                    continue;
                }

                String value = "";

                if (currentVariables != null &&
                        currentVariables.containsKey(key)) {

                    value = currentVariables.get(key);
                }

                builder.append(key)
                        .append("=")
                        .append(value != null ? value : "")
                        .append("\n");
            }

            return builder.toString();

        } catch (Exception e) {

            return "";
        }
    }
    
    private java.util.Map<String, String> parseManualVariables(String input) {
        java.util.Map<String, String> variables = new java.util.LinkedHashMap<>();
    
        if (input == null || input.trim().isEmpty()) {
            return variables;
        }
    
        String[] lines = input.split("\\R");
        for (String line : lines) {
            if (line == null) {
                continue;
            }
    
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("//")) {
                continue;
            }
    
            int separatorIndex = trimmed.indexOf('=');
            if (separatorIndex <= 0) {
                appendLog("Skipped invalid variable line: " + trimmed);
                continue;
            }
    
            String key = trimmed.substring(0, separatorIndex).trim();
            String value = trimmed.substring(separatorIndex + 1);
    
            if (!key.isEmpty()) {
                variables.put(key, value);
            }
        }
    
        return variables;
    }
    
    /**
     * Append a second/third/... collection to the currently loaded workspace
     * without wiping the existing tree (Postman-style multi-workspace).
     */
    /** Prompts for a name and creates a brand-new empty collection in
     *  the workspace (no file on disk). User can then add requests via
     *  the right-click "Add Request here…" menu. */
    private void createEmptyCollection() {
        String name = (String) JOptionPane.showInputDialog(mainPanel,
                "Name for the new collection:",
                "New Empty Collection",
                JOptionPane.PLAIN_MESSAGE,
                null, null, "New Collection");
        if (name == null || name.trim().isEmpty()) return;
        try {
            importer.createEmptyCollection(name.trim());
            try { importer.rebuildTreeOnly(); } catch (Exception ignore) {}
            appendLog("📁 Created new empty collection: " + name.trim());
            try {
                burp.ui.ToastManager.show(mainPanel,
                        "Created collection: " + name.trim(),
                        burp.ui.ToastManager.Level.SUCCESS);
            } catch (Throwable ignore) {}
            appendLog("ℹ️ Right-click '" + name.trim() + "' → 'Add Request here…' to add requests");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(mainPanel,
                    "Failed to create collection: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void addAdditionalCollection() {
        boolean firstLoad = importer.getCurrentCollection() == null;
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
        chooser.setFileFilter(new FileNameExtensionFilter(
                "Postman JSON / Bruno .bru / Bruno .yml / collection folder", "json", "bru", "yml", "yaml"));
        chooser.setAcceptAllFileFilterUsed(true);
        chooser.setDialogTitle(firstLoad ? "Add Collection" : "Add Additional Collection");
        if (chooser.showOpenDialog(mainPanel) != JFileChooser.APPROVE_OPTION) return;
        java.io.File extra = chooser.getSelectedFile();
        if (extra == null) return;
        try {
            if (firstLoad) {
                // Treat as the primary collection: load tree without forcing the
                // import preview dialog.
                selectedCollection = extra;
                collectionField.setText(extra.getAbsolutePath());
                previewButton.setEnabled(true);
                importButton.setEnabled(true);
                appendLog("Selected collection input: " + extra.getAbsolutePath());
                autoLoadGlobalsNear(extra);
                importer.loadCollectionTreeOnly(extra);
                if (authManagerPanel != null) authManagerPanel.resetUI();
                burp.ui.ToastManager.show(mainPanel,
                        "Loaded collection", burp.ui.ToastManager.Level.SUCCESS);
                return;
            }
            int added = importer.appendCollection(extra);
            if (added <= 0) {
                JOptionPane.showMessageDialog(mainPanel,
                        "No collections were found in:\n" + extra.getAbsolutePath(),
                        "Nothing Added", JOptionPane.WARNING_MESSAGE);
                return;
            }
            appendLog("➕ Added " + added + " collection(s) from: " + extra.getAbsolutePath());
            burp.parser.VariableResolver r = importer.getVariableResolver();
            java.util.Map<String, String> snap = r == null ? null : r.getVariables();
            // Rebuild the tree immediately (no preview dialog) so the new collection
            // is visible right away. User can then right-click → Analyze.
            try { importer.rebuildTreeOnly(); } catch (Exception ignore) {}
            if (authManagerPanel != null) authManagerPanel.reenableAnalyzeButton();
            if (snap != null) refreshVariables(snap);
            burp.ui.ToastManager.show(mainPanel,
                    "Added " + added + " collection(s)", burp.ui.ToastManager.Level.SUCCESS);
        } catch (Exception ex) {
            appendLog("❌ Failed to add collection: " + ex.getMessage());
            JOptionPane.showMessageDialog(mainPanel,
                    "Failed to add collection:\n" + ex.getMessage(),
                    "Add Collection Failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void selectCollectionFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
        chooser.setFileFilter(new FileNameExtensionFilter(
                "Auto-detect: Postman JSON/folder, Bruno .bru/.yml/folder",
                "json",
                "bru",
                "yml",
                "yaml"
        ));
        chooser.setAcceptAllFileFilterUsed(true);
        chooser.setDialogTitle("Select Collection or Collection Folder - Auto Detect Format");

        if (chooser.showOpenDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
            loadCollectionFromFile(chooser.getSelectedFile());
        }
    }

    /** Pick an OpenAPI 3.x / Swagger 2 spec (JSON or YAML) and convert it to a
     *  PostmanCollection in memory, then load it through the normal pipeline. */
    private void importFromOpenApi() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setFileFilter(new FileNameExtensionFilter(
                "OpenAPI 3.x / Swagger 2 (JSON or YAML)", "json", "yaml", "yml"));
        chooser.setDialogTitle("Import OpenAPI / Swagger Spec");
        if (chooser.showOpenDialog(mainPanel) != JFileChooser.APPROVE_OPTION) return;

        java.io.File spec = chooser.getSelectedFile();
        if (spec == null) return;

        new Thread(() -> {
            try {
                appendLog("📥 Importing OpenAPI spec: " + spec.getAbsolutePath());
                burp.openapi.OpenApiImporter imp = new burp.openapi.OpenApiImporter();
                burp.models.PostmanCollection collection = imp.importFile(spec);

                // Write to a temp .postman_collection.json so the existing
                // load pipeline (PostmanParser, AuthManager binding, tree
                // builder, variable detector) takes over unchanged.
                java.io.File tmp = java.io.File.createTempFile(
                        spec.getName().replaceAll("\\W+", "_") + "_",
                        ".postman_collection.json");
                tmp.deleteOnExit();
                try (java.io.FileWriter w = new java.io.FileWriter(tmp)) {
                    new com.google.gson.GsonBuilder().setPrettyPrinting().create()
                            .toJson(collection, w);
                }
                SwingUtilities.invokeLater(() -> {
                    loadCollectionFromFile(tmp);
                    appendLog("✅ Imported OpenAPI '" + collection.info.name
                            + "' as " + collection.item.size() + " folder(s)");
                    burp.ui.ToastManager.show(mainPanel,
                            "OpenAPI spec imported", burp.ui.ToastManager.Level.SUCCESS);
                });
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> {
                    appendLog("❌ OpenAPI import failed: " + t.getMessage());
                    JOptionPane.showMessageDialog(mainPanel,
                            "OpenAPI import failed:\n" + t.getMessage(),
                            "Import Failed", JOptionPane.ERROR_MESSAGE);
                });
            }
        }, "BurpMan-OpenApiImporter").start();
    }

    /** Load a collection file (used by both Browse and Recent menu). */
    private void loadCollectionFromFile(File f) {
        if (f == null) return;
        selectedCollection = f;
        collectionField.setText(selectedCollection.getAbsolutePath());
        previewButton.setEnabled(true);
        importButton.setEnabled(true);
        if (authManagerPanel != null) authManagerPanel.resetUI();
        // Hide stale "Run Scripts" banner from prior collection; the next
        // analyze will surface it again if scripts are present.
        hideRunScriptsBanner();
        appendLog("Selected collection input: " + selectedCollection.getAbsolutePath());
        appendLog("Format will be auto-detected during preview/import.");
        autoLoadGlobalsNear(selectedCollection);
        autoDiscoverBrunoEnvsNear(selectedCollection);
        // Ensure every imported collection has a Bruno-shaped workspace on
        // disk. Ask the user for Name / Location / Format via a Bruno-style
        // Import Collection dialog the first time we see a source, then
        // reuse the resulting folder on subsequent loads. When a workspace
        // already exists at the collection's expected default location we
        // reuse it silently (no dialog spam on reopen).
        java.io.File workspace = provisionWorkspaceForImport(selectedCollection);
        if (workspace != null) {
            currentWorkspace = workspace;
            if (!workspace.equals(selectedCollection)) {
                appendLog("📁 Bruno workspace: " + workspace.getAbsolutePath()
                    + "  (drop .env or environments/*.yml here to persist envs)");

                // ✨ Extract Bruno-JSON-embedded environments (the top-level
                // "environments" array) into <workspace>/environments/*.bru
                // so they show up in the Environment dropdown and the
                // Overview tab. Idempotent — files that already exist are
                // skipped.
                try {
                    int written = burp.workspace.WorkspaceManager
                        .extractBrunoEnvsFromJson(selectedCollection, workspace, preferredEnvFormat);
                    if (written > 0) {
                        appendLog("🌱 Extracted " + written + " environment"
                            + (written == 1 ? "" : "s") + " from the Bruno JSON export.");
                    }
                } catch (Exception ex) {
                    appendLog("⚠ Could not extract embedded envs: " + ex.getMessage());
                }

                autoDiscoverBrunoEnvsNear(workspace);
            }
            // Honor a previously-saved link so users don't have to pick
            // the external folder every time they reopen the collection.
            java.io.File linked = burp.workspace.WorkspaceManager.findLinkedBrunoFolder(workspace);
            if (linked != null) {
                appendLog("🔗 Linked env source: " + linked.getAbsolutePath());
                autoDiscoverBrunoEnvsNear(linked);
            }
        }
        addToRecent(selectedCollection);
        refreshOverviewPanel();
        try { importer.loadCollectionTreeOnly(selectedCollection); } catch (Exception ignore) {}
        persistWorkspaceSnapshot();

        // Auto-analyze in the background (Postman/Bruno-style — no manual
        // "Analyze" click required). Runs OAuth2/JWT detection + any
        // collection-level pre-request scripts so tokens are populated by
        // the time the user clicks the first request. Failures are silent —
        // the manual Analyze button in Auth Manager remains as a fallback.
        final java.io.File envForAnalyze = selectedEnvironment;
        new Thread(() -> {
            try {
                Thread.sleep(150); // let the tree finish rendering first
                importer.analyzeAuthFromFiles(selectedCollection, envForAnalyze);
                SwingUtilities.invokeLater(() -> {
                    try { if (authManagerPanel != null) authManagerPanel.reenableAnalyzeButton(); }
                    catch (Exception ignore) {}
                });
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> appendLog(
                        "ℹ Auto-analyze skipped: " + t.getMessage()
                        + " — click Analyze in Auth Manager to retry."));
            }
        }, "BurpMan-AutoAnalyze").start();
    }

    // ----- Save collection (export live model back to JSON) -----------------

    /** Snapshot the current loaded collection paths + environment selection
     *  to ~/Documents/BurpMan-Workspaces/workspaces.json so the next Burp
     *  restart can offer to reload them. Best-effort — IO failures are silent. */
    private void persistWorkspaceSnapshot() {
        try {
            java.util.List<String> collections = new java.util.ArrayList<>();
            if (selectedCollection != null) collections.add(selectedCollection.getAbsolutePath());

            java.util.List<String> envs = new java.util.ArrayList<>();
            String activeEnv = null;
            if (environmentCombo != null) {
                for (int i = 0; i < environmentCombo.getItemCount(); i++) {
                    Object item = environmentCombo.getItemAt(i);
                    if (item instanceof EnvOption) {
                        EnvOption eo = (EnvOption) item;
                        if (eo.file != null) {
                            String path = eo.file.getAbsolutePath();
                            envs.add(path);
                        }
                    }
                }
            }
            if (selectedEnvironment != null) activeEnv = selectedEnvironment.getAbsolutePath();

            // Persistence disabled - user request.
            // workspaceStore.recordSession(collections, envs, activeEnv, null);
        } catch (Throwable ignore) {}
    }

    /** Restore the last persisted workspace: load the saved collection and
     *  any environments, then select the previously-active environment.
     *  Called once during panel construction. */
    private void restoreLastWorkspace() {
        try {
            burp.ui.WorkspaceStore.Workspace w = workspaceStore.getDefault();
            if (w == null) return;
            if (w.collectionPaths != null && !w.collectionPaths.isEmpty()) {
                File f = new File(w.collectionPaths.get(0));
                if (f.exists()) {
                    SwingUtilities.invokeLater(() -> loadCollectionFromFile(f));
                }
            }
            if (w.environmentPaths != null) {
                for (String p : w.environmentPaths) {
                    File ef = new File(p);
                    if (!ef.exists()) continue;
                    SwingUtilities.invokeLater(() -> {
                        try { importer.importEnvironmentFile(ef); }
                        catch (Throwable ignore) {}
                    });
                }
            }
            if (w.activeEnvironmentPath != null) {
                final String want = w.activeEnvironmentPath;
                SwingUtilities.invokeLater(() -> {
                    if (environmentCombo == null) return;
                    for (int i = 0; i < environmentCombo.getItemCount(); i++) {
                        Object item = environmentCombo.getItemAt(i);
                        if (item instanceof EnvOption) {
                            EnvOption eo = (EnvOption) item;
                            if (eo.file != null && want.equals(eo.file.getAbsolutePath())) {
                                environmentCombo.setSelectedIndex(i);
                                return;
                            }
                        }
                    }
                });
            }
        } catch (Throwable ignore) {}
    }

    /** Write the in-memory collection back to a .postman_collection.json file.
     *  Lets tree edits (add/duplicate/rename/delete request, body changes,
     *  header changes) survive a restart. Defaults the suggested path to the
     *  originally-loaded collection file. */
    private void saveCurrentCollection() {
        burp.models.PostmanCollection coll = importer == null ? null : importer.getCurrentCollection();
        if (coll == null) {
            JOptionPane.showMessageDialog(mainPanel,
                    "No collection loaded — Browse one first.",
                    "Nothing to export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Collection (does NOT overwrite the original)");
        chooser.setFileFilter(new FileNameExtensionFilter(
                "Postman Collection JSON (*.postman_collection.json, *.json)",
                "json"));

        // Default filename: based on the original (or collection name) with
        // an "-edited-<timestamp>" suffix so we never propose overwriting
        // the user's source file.
        String stamp = new java.text.SimpleDateFormat("yyyyMMdd-HHmmss")
                .format(new java.util.Date());
        String base;
        java.io.File dir;
        if (selectedCollection != null && selectedCollection.isFile()) {
            String orig = selectedCollection.getName();
            String stem = orig.toLowerCase().endsWith(".postman_collection.json")
                    ? orig.substring(0, orig.length() - ".postman_collection.json".length())
                    : (orig.toLowerCase().endsWith(".json")
                            ? orig.substring(0, orig.length() - ".json".length())
                            : orig);
            base = stem + "-edited-" + stamp + ".postman_collection.json";
            dir = selectedCollection.getParentFile();
        } else {
            String name = coll.info != null && coll.info.name != null
                    ? coll.info.name.replaceAll("[^A-Za-z0-9._-]+", "_")
                    : "collection";
            base = name + "-edited-" + stamp + ".postman_collection.json";
            dir = null;
        }
        if (dir != null) chooser.setCurrentDirectory(dir);
        chooser.setSelectedFile(new java.io.File(base));

        if (chooser.showSaveDialog(mainPanel) != JFileChooser.APPROVE_OPTION) return;

        java.io.File target = chooser.getSelectedFile();
        if (target == null) return;
        if (!target.getName().toLowerCase().endsWith(".json")) {
            target = new java.io.File(target.getAbsolutePath() + ".postman_collection.json");
        }

        // Refuse to overwrite the loaded source file — Save is export-only.
        if (selectedCollection != null && selectedCollection.isFile()) {
            try {
                if (target.getCanonicalFile().equals(selectedCollection.getCanonicalFile())) {
                    JOptionPane.showMessageDialog(mainPanel,
                            "Export cannot overwrite the original collection file.\n\n"
                                    + "Please choose a different file name.",
                            "Cannot overwrite original", JOptionPane.WARNING_MESSAGE);
                    return;
                }
            } catch (Exception ignore) {
                // Path canonicalization failed — fall through to the generic
                // overwrite confirm below.
            }
        }

        // Generic overwrite confirm for any pre-existing destination.
        if (target.exists()) {
            int ok = JOptionPane.showConfirmDialog(mainPanel,
                    "Overwrite " + target.getName() + "?",
                    "Confirm overwrite", JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE);
            if (ok != JOptionPane.YES_OPTION) return;
        }

        try {
            new burp.parser.CollectionExporter().exportTo(coll, target);
            appendLog("💾 Exported collection: " + target.getAbsolutePath());
            burp.ui.ToastManager.show(mainPanel,
                    "Exported: " + target.getName(),
                    burp.ui.ToastManager.Level.SUCCESS);
        } catch (Exception ex) {
            appendLog("❌ Export failed: " + ex.getMessage());
            JOptionPane.showMessageDialog(mainPanel,
                    "Export failed:\n" + ex.getMessage(),
                    "Export Failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    /** Export the live environment (incl. any vars written by pre/post scripts
     *  since load) to a NEW .postman_environment.json file. The original env
     *  file is never overwritten — same export-only contract as Save Collection. */
    private void exportCurrentEnvironment() {
        burp.parser.VariableResolver resolver = importer == null ? null : importer.getVariableResolver();
        if (resolver == null) {
            JOptionPane.showMessageDialog(mainPanel,
                    "No variables loaded.",
                    "Nothing to export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // Prefer the env-scoped vars when an environment was loaded; fall back
        // to the flat merged map (matches what scripts see via pm.environment).
        java.util.Map<String, String> envVars;
        try {
            String active = resolver.getActiveScope();
            if (active != null && !active.isEmpty()) {
                envVars = resolver.getScopedVariables(active);
            } else if (selectedEnvironment != null) {
                envVars = new java.util.LinkedHashMap<>(resolver.getVariables());
            } else {
                envVars = new java.util.LinkedHashMap<>(resolver.getVariables());
            }
        } catch (Throwable t) {
            envVars = new java.util.LinkedHashMap<>(resolver.getVariables());
        }

        if (envVars == null || envVars.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel,
                    "The current environment has no variables to export.",
                    "Nothing to export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Environment (does NOT overwrite the original)");
        chooser.setFileFilter(new FileNameExtensionFilter(
                "Postman Environment JSON (*.postman_environment.json, *.json)",
                "json"));

        String stamp = new java.text.SimpleDateFormat("yyyyMMdd-HHmmss")
                .format(new java.util.Date());
        java.io.File suggestedDir = null;
        String baseName;
        if (selectedEnvironment != null && selectedEnvironment.isFile()) {
            String orig = selectedEnvironment.getName();
            String stem = orig.toLowerCase().endsWith(".postman_environment.json")
                    ? orig.substring(0, orig.length() - ".postman_environment.json".length())
                    : (orig.toLowerCase().endsWith(".json")
                            ? orig.substring(0, orig.length() - ".json".length())
                            : orig);
            baseName = stem + "-edited-" + stamp + ".postman_environment.json";
            suggestedDir = selectedEnvironment.getParentFile();
        } else {
            baseName = "environment-" + stamp + ".postman_environment.json";
        }
        if (suggestedDir != null) chooser.setCurrentDirectory(suggestedDir);
        chooser.setSelectedFile(new java.io.File(baseName));

        if (chooser.showSaveDialog(mainPanel) != JFileChooser.APPROVE_OPTION) return;

        java.io.File target = chooser.getSelectedFile();
        if (target == null) return;
        if (!target.getName().toLowerCase().endsWith(".json")) {
            target = new java.io.File(target.getAbsolutePath() + ".postman_environment.json");
        }

        // Refuse to overwrite the loaded source env file.
        if (selectedEnvironment != null && selectedEnvironment.isFile()) {
            try {
                if (target.getCanonicalFile().equals(selectedEnvironment.getCanonicalFile())) {
                    JOptionPane.showMessageDialog(mainPanel,
                            "Export cannot overwrite the original environment file.\n\n"
                                    + "Please choose a different file name.",
                            "Cannot overwrite original", JOptionPane.WARNING_MESSAGE);
                    return;
                }
            } catch (Exception ignore) {}
        }
        if (target.exists()) {
            int ok = JOptionPane.showConfirmDialog(mainPanel,
                    "Overwrite " + target.getName() + "?",
                    "Confirm overwrite", JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE);
            if (ok != JOptionPane.YES_OPTION) return;
        }

        // Build a Postman v2 environment object — same shape PostmanParser reads.
        burp.models.PostmanEnvironment env = new burp.models.PostmanEnvironment();
        env.id = java.util.UUID.randomUUID().toString();
        String envName;
        if (selectedEnvironment != null) {
            String n = selectedEnvironment.getName();
            int dot = n.indexOf('.');
            envName = (dot > 0 ? n.substring(0, dot) : n) + " (edited)";
        } else {
            envName = "Exported Environment";
        }
        env.name = envName;
        env.values = new java.util.ArrayList<>();
        for (java.util.Map.Entry<String, String> e : envVars.entrySet()) {
            burp.models.PostmanEnvironment.Value v = new burp.models.PostmanEnvironment.Value();
            v.key = e.getKey();
            v.value = e.getValue() == null ? "" : e.getValue();
            v.enabled = true;
            v.type = "default";
            env.values.add(v);
        }

        try {
            com.google.gson.Gson gson = new com.google.gson.GsonBuilder()
                    .setPrettyPrinting()
                    .disableHtmlEscaping()
                    .create();
            try (java.io.FileWriter w = new java.io.FileWriter(target)) {
                gson.toJson(env, w);
            }
            appendLog("📤 Exported environment (" + env.values.size()
                    + " vars): " + target.getAbsolutePath());
            burp.ui.ToastManager.show(mainPanel,
                    "Exported: " + target.getName(),
                    burp.ui.ToastManager.Level.SUCCESS);
        } catch (Exception ex) {
            appendLog("❌ Env export failed: " + ex.getMessage());
            JOptionPane.showMessageDialog(mainPanel,
                    "Export failed:\n" + ex.getMessage(),
                    "Export Failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    // ----- Recent files (persisted via java.util.prefs) ---------------------
    private static final String RECENT_PREF_KEY = "burpman.recentCollections";
    private static final int RECENT_MAX = 5;

    private java.util.List<String> loadRecent() {
        java.util.List<String> out = new java.util.ArrayList<>();
        try {
            java.util.prefs.Preferences p = java.util.prefs.Preferences.userNodeForPackage(ImporterPanel.class);
            String raw = p.get(RECENT_PREF_KEY, "");
            if (raw != null && !raw.isEmpty()) {
                for (String s : raw.split("\\|")) {
                    if (s != null && !s.isEmpty()) out.add(s);
                }
            }
        } catch (Throwable ignore) {}
        return out;
    }

    private void saveRecent(java.util.List<String> list) {
        try {
            java.util.prefs.Preferences p = java.util.prefs.Preferences.userNodeForPackage(ImporterPanel.class);
            p.put(RECENT_PREF_KEY, String.join("|", list));
        } catch (Throwable ignore) {}
    }

    private void addToRecent(File f) {
        if (f == null) return;
        String path = f.getAbsolutePath();
        java.util.List<String> list = loadRecent();
        list.remove(path); // dedupe
        list.add(0, path);
        while (list.size() > RECENT_MAX) list.remove(list.size() - 1);
        saveRecent(list);
    }

    private void showRecentMenu(JComponent anchor) {
        java.util.List<String> list = loadRecent();
        JPopupMenu menu = new JPopupMenu();
        if (list.isEmpty()) {
            JMenuItem empty = new JMenuItem("No recent collections");
            empty.setEnabled(false);
            menu.add(empty);
        } else {
            for (String path : list) {
                File f = new File(path);
                String label = f.getName() + "    (" + (f.getParent() == null ? "" : f.getParent()) + ")";
                JMenuItem item = new JMenuItem(label);
                item.setToolTipText(path);
                item.addActionListener(ev -> {
                    if (!f.exists()) {
                        appendLog("⚠ Recent file no longer exists: " + path);
                        return;
                    }
                    loadCollectionFromFile(f);
                });
                menu.add(item);
            }
            menu.addSeparator();
            JMenuItem clear = new JMenuItem("Clear recent");
            clear.addActionListener(ev -> saveRecent(new java.util.ArrayList<>()));
            menu.add(clear);
        }
        menu.show(anchor, 0, anchor.getHeight());
    }
    public void refreshVariables(Map<String, String> vars) {
        // Trimmed log line — used to dump the entire variable map (often 50+
        // entries × hundreds of chars each), which paint-stalled the UI on
        // every script var-write. The Edit Variables dialog and per-request
        // tooltip already show the full set; the log just confirms a refresh
        // happened.
        int n = vars == null ? 0 : vars.size();
        String tok = vars == null ? null : vars.get("token");
        String tokPrev = tok == null ? "—"
                : tok.length() > 24 ? tok.substring(0, 24) + "…(" + tok.length() + ")" : tok;
        appendLog("🔄 Variables refreshed (" + n + " var(s), token=" + tokPrev + ")");
        // Live-update the Request Builder's URL bar so an edited variable
        // (e.g. {{baseUrl}}) is reflected immediately in the currently
        // loaded request — Postman behavior.
        if (builderPanel != null) {
            try { builderPanel.refreshFromVariables(); } catch (Exception ignore) {}
        }
    }
    
    /** Auto-discover a Postman globals JSON next to the given file
     *  (same directory). A globals file is identified by either:
     *    - a name containing "globals" + ".json", or
     *    - a JSON object with "_postman_variable_scope":"globals"
     *  Loaded silently into the resolver. Lower precedence than env. */
    /** Preference key controlling whether globals files in the collection's
     *  directory are auto-loaded. Off by default — many users have stray
     *  test/dev globals files (e.g. with sentinel "should-lose" values) that
     *  silently shadow real env vars. Users can opt-in via Advanced Options
     *  → Load Globals... or by setting this pref to true. */
    private static boolean isAutoGlobalsEnabled() {
        try {
            return java.util.prefs.Preferences.userNodeForPackage(ImporterPanel.class)
                    .getBoolean("burpman.autoLoadGlobals", false);
        } catch (Throwable t) { return false; }
    }

    private void autoLoadGlobalsNear(File anchor) {
        if (anchor == null) return;
        if (!isAutoGlobalsEnabled()) return; // opt-in only
        try {
            File dir = anchor.isDirectory() ? anchor : anchor.getParentFile();
            if (dir == null || !dir.isDirectory()) return;
            File[] candidates = dir.listFiles((d, n) -> n != null && n.toLowerCase().endsWith(".json"));
            if (candidates == null) return;
            File chosen = null;
            for (File f : candidates) {
                if (isGlobalsFile(f)) { chosen = f; break; }
            }
            if (chosen == null) return;
            if (selectedGlobals != null && chosen.getAbsolutePath().equals(selectedGlobals.getAbsolutePath())) {
                return; // already loaded
            }
            burp.parser.VariableResolver r = importer.getVariableResolver();
            burp.models.PostmanEnvironment globals = new burp.parser.PostmanParser().parseEnvironment(chosen);
            if (r != null && globals != null) {
                r.addGlobalsVariables(globals);
                refreshVariables(r.getVariables());
            }
            selectedGlobals = chosen;
            importer.setGlobalsFile(chosen);
            int count = (globals != null && globals.values != null) ? globals.values.size() : 0;
            appendLog("🌐 Auto-loaded globals: " + chosen.getName() + " (" + count + " var(s))");
        } catch (Exception ignore) {
            // silent — globals are optional
        }
    }

    private boolean isGlobalsFile(File f) {
        if (f == null || !f.isFile()) return false;
        String name = f.getName().toLowerCase();
        if (name.contains("globals")) return true;
        // Sniff JSON for _postman_variable_scope == "globals"
        try (java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader(f))) {
            char[] buf = new char[4096];
            StringBuilder sb = new StringBuilder();
            int total = 0; int n;
            while (total < 8192 && (n = br.read(buf)) > 0) { sb.append(buf, 0, n); total += n; }
            String head = sb.toString();
            return head.contains("\"_postman_variable_scope\"")
                && head.contains("\"globals\"");
        } catch (Exception ignore) {
            return false;
        }
    }

    /** Bruno-style auto-discovery: when a collection folder (or a file inside
     *  a collection folder) is loaded, look at the collection root for:
     *   - {@code .env} (dotenv-style secrets — same as Bruno's ".ENV FILES"
     *     panel in the sidebar), and
     *   - {@code environments/} folder containing {@code *.bru} or
     *     {@code *.yml}/{@code *.yaml} files (Bruno's "ENVIRONMENTS" panel).
     *  Each discovered file is added to the environment dropdown so the user
     *  can switch between them like they would in Bruno.
     *
     *  Anchor may be either:
     *   - the collection folder itself (typical for Bruno imports), or
     *   - a single file inside it (e.g. a top-level JSON collection sitting
     *     next to an {@code environments/} sibling).
     *
     *  If the user has no environment currently selected, the first discovered
     *  env is auto-picked so they don't get "0 vars" surprise on first Send.
     *  Silent no-op when there's nothing to discover. */
    private void autoDiscoverBrunoEnvsNear(File anchor) {
        if (anchor == null) return;
        try {
            File root = anchor.isDirectory() ? anchor : anchor.getParentFile();
            if (root == null || !root.isDirectory()) return;

            // Discover .env files (always-on overlays) and flat environment
            // files (dropdown-selectable) separately — they follow different
            // activation models (checkbox vs radio) so we track them
            // in different collections. See fields `dotenvFiles` and
            // `loadedEnvironments`.
            java.util.List<File> discoveredEnvs = new java.util.ArrayList<>();
            java.util.List<File> discoveredDotenvs = new java.util.ArrayList<>();

            // 1) .env at collection root (Bruno's dotenv secrets file)
            File dotenv = new File(root, ".env");
            if (dotenv.isFile()) discoveredDotenvs.add(dotenv);

            // 2) environments/*.bru | *.yml | *.yaml | *.json (flat envs)
            File envsFolder = new File(root, "environments");
            if (envsFolder.isDirectory()) {
                File[] envFiles = envsFolder.listFiles((d, n) -> {
                    if (n == null) return false;
                    String lower = n.toLowerCase(java.util.Locale.ROOT);
                    return lower.endsWith(".bru")
                        || lower.endsWith(".yml")
                        || lower.endsWith(".yaml")
                        || lower.endsWith(".json");
                });
                if (envFiles != null) {
                    java.util.Arrays.sort(envFiles,
                        java.util.Comparator.comparing(File::getName, String.CASE_INSENSITIVE_ORDER));
                    for (File e : envFiles) {
                        // Skip the shared shape files if they somehow live there.
                        String lower = e.getName().toLowerCase(java.util.Locale.ROOT);
                        if (lower.equals("environment.bru") || lower.equals("environment.yml")
                            || lower.equals("environment.yaml")) continue;
                        discoveredEnvs.add(e);
                    }
                }
            }

            if (discoveredEnvs.isEmpty() && discoveredDotenvs.isEmpty()) return;

            // Register .env files into the always-on overlay bucket.
            int newDotenvCount = 0;
            for (File f : discoveredDotenvs) {
                boolean already = false;
                for (File existing : dotenvFiles) {
                    if (existing.getAbsolutePath().equalsIgnoreCase(f.getAbsolutePath())) {
                        already = true; break;
                    }
                }
                if (already) continue;
                dotenvFiles.add(f);
                // Auto-activate the workspace's own .env — matches Bruno
                // (its .env auto-loads when you open the collection).
                // Only one .env is active at a time; the LAST one seen
                // during discovery wins, which is deterministic since we
                // add discoveredDotenvs in a stable order.
                activeDotEnvFile = f;
                newDotenvCount++;
            }

            // Register flat environments into the dropdown.
            EnvOption firstNewlyAdded = null;
            int newEnvCount = 0;
            for (File f : discoveredEnvs) {
                boolean already = false;
                for (EnvOption o : loadedEnvironments) {
                    if (o.file != null
                        && o.file.getAbsolutePath().equalsIgnoreCase(f.getAbsolutePath())) {
                        already = true; break;
                    }
                }
                if (already) continue;
                EnvOption opt = new EnvOption(f, prettyEnvLabel(f));
                loadedEnvironments.add(opt);
                if (environmentCombo != null) environmentCombo.addItem(opt);
                if (firstNewlyAdded == null) firstNewlyAdded = opt;
                newEnvCount++;
            }

            if (newEnvCount > 0) {
                appendLog("🌿 Auto-discovered " + newEnvCount + " Bruno environment file(s) — "
                    + "pick one from the Environment dropdown to activate.");
            }
            if (newDotenvCount > 0) {
                appendLog("🔐 Auto-loaded " + newDotenvCount + " .env overlay file(s) — "
                    + "process.env.* placeholders now resolve.");
                // Wire the .env values into the resolver's process.env.*
                // namespace immediately so newly-loaded envs see them.
                applyProcessEnvOverlay();
            }

            // Auto-select the first newly-added env only when nothing was
            // active before (i.e. the user hasn't manually picked one yet).
            if (firstNewlyAdded != null
                && selectedEnvironment == null
                && environmentCombo != null) {
                environmentCombo.setSelectedItem(firstNewlyAdded); // fires onEnvironmentSelected
            }
        } catch (Exception ignore) {
            // Silent — env auto-discovery is best-effort.
        }
    }

    /** Merge the active {@code .env} file into the resolver under the
     *  Bruno {@code process.env.*} namespace. Clears the previous overlay
     *  first, then re-adds the active file so swapping between {@code .env}
     *  files replaces the process.env.* map cleanly. Called after any
     *  change to {@link #activeDotEnvFile} (import, activate, remove).
     *  Safe to call repeatedly — idempotent.
     *
     *  <p>The overlay is always-on: it survives environment swaps and
     *  {@link burp.parser.VariableResolver#clearAllVariables} calls issued
     *  by {@link #onEnvironmentSelected} because we re-apply it right
     *  after the flat env re-load. */
    private void applyProcessEnvOverlay() {
        try {
            burp.parser.VariableResolver r = importer.getVariableResolver();
            if (r == null) return;
            r.clearProcessEnvVariables();
            if (activeDotEnvFile != null && activeDotEnvFile.isFile()) {
                try {
                    burp.models.PostmanEnvironment env =
                        new burp.parser.PostmanParser().parseEnvironment(activeDotEnvFile);
                    if (env != null) r.addProcessEnvVariables(env);
                } catch (Exception ignore) {}
            }
            refreshVariables(r.getVariables());
        } catch (Exception ignore) {}
    }

    /** Human-friendly env label. Strips extension and returns just the file
     *  name (e.g. {@code "4-UAT-CAC.yml"} → {@code "4-UAT-CAC"};
     *  {@code ".env"} stays {@code ".env"}). */
    private String prettyEnvLabel(File f) {
        if (f == null) return "(env)";
        String n = f.getName();
        if (n.equalsIgnoreCase(".env")) return ".env";
        int dot = n.lastIndexOf('.');
        return dot > 0 ? n.substring(0, dot) : n;
    }

    /** Build the Bruno-style Overview tab — collection name header,
     *  location + workspace path + env summary + request count + action
     *  buttons (Add… / Link folder / New env / Rescan / Open workspace).
     *  Populated dynamically by {@link #refreshOverviewPanel()} whenever
     *  the collection or environment set changes. */
    private JPanel buildOverviewPanel() {
        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(UITheme.surface());
        root.setBorder(BorderFactory.createEmptyBorder(24, 32, 24, 32));

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBackground(UITheme.surface());
        content.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Header: collection name
        overviewCollectionName = new JLabel("(no collection loaded)");
        overviewCollectionName.setFont(overviewCollectionName.getFont().deriveFont(Font.BOLD, 22f));
        overviewCollectionName.setForeground(UITheme.foreground());
        overviewCollectionName.setAlignmentX(Component.LEFT_ALIGNMENT);
        content.add(overviewCollectionName);
        content.add(Box.createRigidArea(new Dimension(0, 4)));

        JLabel subtitle = new JLabel("Postman-style collection runner  •  Bruno-shaped workspace");
        subtitle.setForeground(UITheme.subtleText());
        subtitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        content.add(subtitle);
        content.add(Box.createRigidArea(new Dimension(0, 20)));

        // Location row
        overviewLocation = new JLabel("Load a collection to see its location.");
        content.add(makeOverviewRow("📁", "Location",
            "Path to the imported collection on disk", overviewLocation, null));
        content.add(Box.createRigidArea(new Dimension(0, 12)));

        // Workspace row (with Open button)
        overviewWorkspace = new JLabel("Load a collection to see its workspace.");
        JButton openWs = UITheme.button("Open in Explorer", UITheme.BtnStyle.GHOST);
        openWs.addActionListener(e -> openCurrentWorkspaceInExplorer());
        content.add(makeOverviewRow("🗂", "Workspace",
            "Bruno-shaped folder for this collection's envs (auto-created)",
            overviewWorkspace, openWs));
        content.add(Box.createRigidArea(new Dimension(0, 12)));

        // Environments row (with Add / New buttons + Bruno-style list of
        // all discovered envs, click a radio to activate).
        overviewEnvsSummary = new JLabel("0 environments loaded");
        overviewEnvsList = new JPanel();
        overviewEnvsList.setLayout(new BoxLayout(overviewEnvsList, BoxLayout.Y_AXIS));
        overviewEnvsList.setOpaque(false);
        overviewEnvsList.setAlignmentX(Component.LEFT_ALIGNMENT);
        // Wrap in a scroll pane so the Overview tab doesn't grow unboundedly
        // when a collection has many environments (e.g. PDP has 7 flat envs
        // plus a .env). Caps at ~240 px tall then scrolls; that leaves room
        // for the Linked folder / Requests / Getting started rows below.
        JScrollPane envsScroll = new JScrollPane(overviewEnvsList,
            JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
            JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        envsScroll.setBorder(BorderFactory.createEmptyBorder());
        envsScroll.setOpaque(false);
        envsScroll.getViewport().setOpaque(false);
        envsScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        envsScroll.setPreferredSize(new Dimension(360, 240));
        envsScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 260));
        envsScroll.getVerticalScrollBar().setUnitIncrement(16);
        JPanel envsValue = new JPanel();
        envsValue.setLayout(new BoxLayout(envsValue, BoxLayout.Y_AXIS));
        envsValue.setOpaque(false);
        envsValue.setAlignmentX(Component.LEFT_ALIGNMENT);
        overviewEnvsSummary.setAlignmentX(Component.LEFT_ALIGNMENT);
        envsValue.add(overviewEnvsSummary);
        envsValue.add(Box.createRigidArea(new Dimension(0, 4)));
        envsValue.add(envsScroll);
        JButton addEnvBtn = UITheme.button("Add env…", UITheme.BtnStyle.GHOST);
        addEnvBtn.setToolTipText("Pick an existing .env / .yml / .bru file to add");
        addEnvBtn.addActionListener(e -> selectEnvironmentFile());
        JButton newEnvBtn = UITheme.button("+ New env", UITheme.BtnStyle.GHOST);
        newEnvBtn.setToolTipText("Create a new empty environment in the workspace (asks bru vs yml)");
        newEnvBtn.addActionListener(e -> createNewEnvironmentInWorkspace());
        JPanel envBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        envBtns.setOpaque(false);
        envBtns.add(addEnvBtn);
        envBtns.add(newEnvBtn);
        content.add(makeOverviewRow("🌐", "Environments",
            "Click a radio to activate. Files in environments/ appear on top; .env files below.",
            envsValue, envBtns));
        content.add(Box.createRigidArea(new Dimension(0, 12)));

        // Linked folder row (with Link / Rescan buttons)
        overviewLinkedFolder = new JLabel("(none — envs stored in workspace only)");
        JButton linkBtn = UITheme.button("Link folder…", UITheme.BtnStyle.GHOST);
        linkBtn.setToolTipText("Point BurpMan at any folder that already contains .env or environments/. Path is remembered next time.");
        linkBtn.addActionListener(e -> linkExternalFolder());
        JButton rescanBtn = UITheme.button("Rescan", UITheme.BtnStyle.GHOST);
        rescanBtn.setToolTipText("Re-read workspace + linked folders — pick up files you dropped in from Explorer");
        rescanBtn.addActionListener(e -> rescanEnvironments());
        JPanel linkBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        linkBtns.setOpaque(false);
        linkBtns.add(linkBtn);
        linkBtns.add(rescanBtn);
        content.add(makeOverviewRow("🔗", "Linked folder",
            "Optional — link a shared folder or someone else's collection so its envs auto-load next time",
            overviewLinkedFolder, linkBtns));
        content.add(Box.createRigidArea(new Dimension(0, 12)));

        // Requests row
        overviewRequestCount = new JLabel("0 requests");
        content.add(makeOverviewRow("📨", "Requests",
            "Total requests parsed from the collection tree",
            overviewRequestCount, null));
        content.add(Box.createRigidArea(new Dimension(0, 20)));

        // Documentation area
        JLabel docTitle = new JLabel("Getting started");
        docTitle.setFont(docTitle.getFont().deriveFont(Font.BOLD, 16f));
        docTitle.setForeground(UITheme.foreground());
        docTitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        content.add(docTitle);
        content.add(Box.createRigidArea(new Dimension(0, 6)));

        JEditorPane doc = new JEditorPane("text/html",
            "<html><body style='font-family:sans-serif;font-size:11px;color:"
                + toHex(UITheme.foreground()) + ";'>"
                + "<p>BurpMan gives every collection a Bruno-shaped workspace folder under "
                + "<code>~/Documents/BurpMan-Workspaces/&lt;name&gt;/</code> so environments persist across sessions.</p>"
                + "<ol>"
                + "<li><b>Add env…</b> — pick an existing <code>.env</code>, <code>.bru</code>, <code>.yml</code>, or <code>.json</code> "
                + "environment file. BurpMan copies it into the workspace on your behalf, so next time you open this collection "
                + "the env is already in the dropdown.</li>"
                + "<li><b>+ New env</b> — create an empty environment file inside the workspace. You'll be asked "
                + "whether you want the Bruno <code>.bru</code> format or the YAML <code>.yml</code> format, then the file opens "
                + "in your default editor so you can fill it in.</li>"
                + "<li><b>Link folder…</b> — if your envs already live somewhere (a shared folder, "
                + "an existing Bruno collection, a git-tracked repo), link that folder once and BurpMan will auto-load its envs "
                + "every time you open this collection. The link is stored in <code>&lt;workspace&gt;/.brunoLink</code>.</li>"
                + "<li><b>Open in Explorer</b> — reveals the workspace so you can drop <code>.env</code> or "
                + "<code>environments/*.yml</code> files in directly. Hit <b>Rescan</b> to pick them up without reloading.</li>"
                + "</ol>"
                + "<p style='color:" + toHex(UITheme.subtleText()) + ";'>Tip: variables inside <code>{{braces}}</code> in the "
                + "URL bar go <span style='color:#178A46;'>green</span> when resolved, "
                + "<span style='color:#E68200;'>amber</span> when defined but empty, and "
                + "<span style='color:#C13232;'>red</span> when undefined.</p>"
                + "</body></html>");
        doc.setEditable(false);
        doc.setOpaque(false);
        doc.setBorder(BorderFactory.createEmptyBorder());
        doc.setAlignmentX(Component.LEFT_ALIGNMENT);
        doc.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
        content.add(doc);
        content.add(Box.createVerticalGlue());

        JScrollPane scroll = new JScrollPane(content);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        root.add(scroll, BorderLayout.CENTER);
        return root;
    }

    /** One horizontal row in the Overview tab: [icon] Label / description /
     *  value + optional actions on the right. */
    private JPanel makeOverviewRow(String emoji, String label, String description,
                                    JComponent value, JComponent actions) {
        JPanel row = new JPanel();
        row.setLayout(new BoxLayout(row, BoxLayout.X_AXIS));
        row.setOpaque(false);
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        row.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0));

        JLabel icon = new JLabel(emoji);
        icon.setFont(icon.getFont().deriveFont(22f));
        icon.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 12));
        icon.setVerticalAlignment(SwingConstants.TOP);
        row.add(icon);

        JPanel text = new JPanel();
        text.setLayout(new BoxLayout(text, BoxLayout.Y_AXIS));
        text.setOpaque(false);
        JLabel head = new JLabel(label);
        head.setFont(head.getFont().deriveFont(Font.BOLD, 13f));
        head.setForeground(UITheme.foreground());
        head.setAlignmentX(Component.LEFT_ALIGNMENT);
        text.add(head);

        if (description != null && !description.isEmpty()) {
            JLabel desc = new JLabel(description);
            desc.setFont(desc.getFont().deriveFont(Font.PLAIN, 10.5f));
            desc.setForeground(UITheme.subtleText());
            desc.setAlignmentX(Component.LEFT_ALIGNMENT);
            text.add(desc);
        }

        if (value != null) {
            value.setAlignmentX(Component.LEFT_ALIGNMENT);
            if (value instanceof JLabel) {
                ((JLabel) value).setForeground(UITheme.foreground());
                value.setFont(value.getFont().deriveFont(Font.PLAIN, 12f));
            }
            text.add(Box.createRigidArea(new Dimension(0, 2)));
            text.add(value);
        }
        row.add(text);

        row.add(Box.createHorizontalGlue());
        if (actions != null) {
            actions.setAlignmentY(Component.TOP_ALIGNMENT);
            row.add(actions);
        }
        // Prevent BoxLayout on the outer content from vertically stretching
        // this row past its natural size — otherwise rows above the envs
        // list snap open when the whole panel is taller than needed.
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, row.getPreferredSize().height));
        return row;
    }

    /** Repaint the Overview tab with the latest collection/workspace/env
     *  state. Safe to call from any thread — hops to EDT internally. */
    private void refreshOverviewPanel() {
        SwingUtilities.invokeLater(() -> {
            try {
                if (overviewCollectionName == null) return;
                String collName = "(no collection loaded)";
                int reqCount = 0;
                try {
                    burp.models.PostmanCollection cc = importer == null
                        ? null : importer.getCurrentCollection();
                    if (cc != null) {
                        if (cc.info != null && cc.info.name != null && !cc.info.name.isEmpty()) {
                            collName = cc.info.name;
                        }
                        reqCount = countAllRequests(cc.item);
                    }
                } catch (Exception ignore) {}
                overviewCollectionName.setText(collName);
                overviewRequestCount.setText(reqCount + " request" + (reqCount == 1 ? "" : "s"));

                overviewLocation.setText(selectedCollection == null
                    ? "(not loaded)" : selectedCollection.getAbsolutePath());
                overviewWorkspace.setText(currentWorkspace == null
                    ? "(will be created when you load a collection)"
                    : currentWorkspace.getAbsolutePath());

                int envCount = loadedEnvironments == null ? 0 : loadedEnvironments.size();
                String active = selectedEnvironment == null
                    ? "none selected" : "active: " + selectedEnvironment.getName();
                overviewEnvsSummary.setText(envCount + " environment"
                    + (envCount == 1 ? "" : "s") + " loaded  •  " + active);

                rebuildEnvsList();

                java.io.File linked = burp.workspace.WorkspaceManager
                    .findLinkedBrunoFolder(currentWorkspace);
                overviewLinkedFolder.setText(linked == null
                    ? "(none — envs stored in workspace only)"
                    : linked.getAbsolutePath());
            } catch (Exception ignore) {}
        });
    }

    /** Rebuild the Bruno-style ENVIRONMENTS / .ENV FILES list inside the
     *  Overview tab. Both sections behave as radios: ENVIRONMENTS are
     *  sourced from {@link #loadedEnvironments} (dropdown-driven, mutually
     *  exclusive), and .ENV FILES are sourced from {@link #dotenvFiles}
     *  with at most one active at a time via {@link #activeDotEnvFile}
     *  — matches Bruno's model (one env + one always-on {@code .env}).
     *  The two selections are independent of each other, so swapping
     *  the flat env doesn't touch the {@code .env} overlay. Shows a ✓
     *  next to whichever env / .env is currently active. */
    private void rebuildEnvsList() {
        if (overviewEnvsList == null) return;
        overviewEnvsList.removeAll();

        // ENVIRONMENTS: flat, mutually-exclusive (dropdown-driven).
        java.util.List<EnvOption> envs = new java.util.ArrayList<>();
        if (loadedEnvironments != null) {
            for (EnvOption opt : loadedEnvironments) {
                if (opt == null || opt.file == null) continue;
                // Belt-and-braces guard: skip any .env that leaked into
                // the flat-envs bucket (e.g. from an older workspace
                // snapshot before the split).
                if (isDotEnvFile(opt.file)) continue;
                envs.add(opt);
            }
        }
        overviewEnvsList.add(makeEnvSectionHeader("ENVIRONMENTS", envs.size()));
        if (envs.isEmpty()) {
            overviewEnvsList.add(makeEnvEmptyHint("No environments yet — use Add env… or + New env"));
        } else {
            for (EnvOption opt : envs) {
                overviewEnvsList.add(makeEnvListRow(opt));
            }
        }
        overviewEnvsList.add(Box.createRigidArea(new Dimension(0, 10)));

        // .ENV FILES: independent, always-on overlays (checkboxes).
        overviewEnvsList.add(makeDotEnvSectionHeader(dotenvFiles.size()));
        if (dotenvFiles.isEmpty()) {
            overviewEnvsList.add(makeEnvEmptyHint("No .env yet — click + Add .env or drop one in the workspace root"));
        } else {
            for (File f : dotenvFiles) {
                overviewEnvsList.add(makeDotEnvListRow(f));
            }
        }

        overviewEnvsList.revalidate();
        overviewEnvsList.repaint();
    }

    private boolean isDotEnvFile(java.io.File f) {
        if (f == null) return false;
        String n = f.getName();
        if (n == null) return false;
        String lower = n.toLowerCase(java.util.Locale.ROOT);
        return lower.equals(".env") || lower.startsWith(".env.");
    }

    /** Bruno-style ".ENV FILES" section header with an inline "+ Add" button.
     *  Clicking + Add opens a file chooser filtered to {@code .env*} files and
     *  registers the picked file as an always-on overlay. */
    private JPanel makeDotEnvSectionHeader(int count) {
        JPanel h = new JPanel(new BorderLayout());
        h.setOpaque(false);
        h.setAlignmentX(Component.LEFT_ALIGNMENT);
        h.setBorder(BorderFactory.createEmptyBorder(2, 0, 2, 0));
        // Constrain height so BoxLayout doesn't let this row stretch when
        // the .env list is small — matches makeEnvSectionHeader below.
        h.setMaximumSize(new Dimension(Integer.MAX_VALUE, 22));
        h.setPreferredSize(new Dimension(320, 22));
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        left.setOpaque(false);
        JLabel caret = new JLabel("▾");
        caret.setForeground(UITheme.subtleText());
        JLabel name = new JLabel(".ENV FILES");
        name.setFont(name.getFont().deriveFont(Font.BOLD, 11f));
        name.setForeground(UITheme.ACCENT);
        JLabel countLbl = new JLabel(count > 0 ? " " + count : "");
        countLbl.setFont(countLbl.getFont().deriveFont(Font.PLAIN, 10f));
        countLbl.setForeground(UITheme.subtleText());
        left.add(caret);
        left.add(name);
        left.add(countLbl);
        h.add(left, BorderLayout.WEST);

        JButton addBtn = new JButton("+ Add .env");
        addBtn.setFont(addBtn.getFont().deriveFont(Font.PLAIN, 10.5f));
        addBtn.setFocusPainted(false);
        addBtn.setMargin(new Insets(2, 6, 2, 6));
        addBtn.setToolTipText("Add a .env file as an always-on overlay (provides {{process.env.KEY}} values)");
        addBtn.addActionListener(e -> pickAndAddDotEnvFile());
        h.add(addBtn, BorderLayout.EAST);
        return h;
    }

    /** Bruno-style section header like "▾ ENVIRONMENTS  3" in accent color. */
    private JPanel makeEnvSectionHeader(String title, int count) {
        JPanel h = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        h.setOpaque(false);
        h.setAlignmentX(Component.LEFT_ALIGNMENT);
        h.setBorder(BorderFactory.createEmptyBorder(2, 0, 2, 0));
        // Constrain height so BoxLayout doesn't stretch this row and push
        // the .ENV FILES section off the bottom of the Overview tab.
        h.setMaximumSize(new Dimension(Integer.MAX_VALUE, 22));
        h.setPreferredSize(new Dimension(320, 22));
        JLabel caret = new JLabel("▾");
        caret.setForeground(UITheme.subtleText());
        JLabel name = new JLabel(title);
        name.setFont(name.getFont().deriveFont(Font.BOLD, 11f));
        name.setForeground(UITheme.ACCENT);
        JLabel countLbl = new JLabel(count > 0 ? " " + count : "");
        countLbl.setFont(countLbl.getFont().deriveFont(Font.PLAIN, 10f));
        countLbl.setForeground(UITheme.subtleText());
        h.add(caret);
        h.add(name);
        h.add(countLbl);
        return h;
    }

    private JLabel makeEnvEmptyHint(String txt) {
        JLabel l = new JLabel("  " + txt);
        l.setFont(l.getFont().deriveFont(Font.ITALIC, 10.5f));
        l.setForeground(UITheme.subtleText());
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        l.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 0));
        // Prevent BoxLayout from vertically stretching this hint label.
        l.setMaximumSize(new Dimension(Integer.MAX_VALUE, 22));
        return l;
    }

    /** Clickable row for a single environment — name on the left, ✓ on
     *  the right if this is the active env. Click anywhere in the row
     *  to activate it (fires {@code environmentCombo.setSelectedItem}
     *  which cascades through the normal activation logic). */
    private JPanel makeEnvListRow(EnvOption opt) {
        JPanel row = new JPanel(new BorderLayout(6, 0));
        row.setOpaque(true);
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        row.setBorder(BorderFactory.createEmptyBorder(4, 10, 4, 8));

        boolean isActive = selectedEnvironment != null
            && opt.file != null
            && selectedEnvironment.getAbsolutePath()
                .equalsIgnoreCase(opt.file.getAbsolutePath());

        // Highlight the active row like Bruno's sidebar.
        row.setBackground(isActive ? UITheme.ghostHover() : UITheme.surface());

        JLabel name = new JLabel(opt.displayName == null ? opt.file.getName() : opt.displayName);
        name.setFont(name.getFont().deriveFont(Font.PLAIN, 12f));
        name.setForeground(UITheme.foreground());
        row.add(name, BorderLayout.WEST);

        // Right-side controls: ✎ Edit button (opens in OS editor) + ✓ active mark.
        JPanel rightBox = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        rightBox.setOpaque(false);
        JButton editBtn = new JButton("✎ Edit");
        editBtn.setFont(editBtn.getFont().deriveFont(Font.PLAIN, 11f));
        editBtn.setToolTipText("Edit " + opt.file.getName() + " in-app (save re-parses on the active env)");
        editBtn.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
        editBtn.setFocusPainted(false);
        editBtn.setOpaque(false);
        editBtn.setContentAreaFilled(false);
        editBtn.setForeground(UITheme.subtleText());
        editBtn.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR));
        editBtn.addActionListener(e -> openEnvFileInAppEditor(opt.file));
        rightBox.add(editBtn);
        if (isActive) {
            JLabel check = new JLabel("✓");
            check.setFont(check.getFont().deriveFont(Font.BOLD, 13f));
            check.setForeground(UITheme.SUCCESS);
            rightBox.add(check);
        }
        row.add(rightBox, BorderLayout.EAST);

        // Constrain the row's height so BoxLayout doesn't stretch it.
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
        row.setPreferredSize(new Dimension(320, 28));

        // Click anywhere in the row (except the Edit button) toggles activation.
        row.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR));
        java.awt.event.MouseAdapter clickHandler = new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                if (environmentCombo == null) return;
                if (isActive) {
                    environmentCombo.setSelectedIndex(0);
                } else {
                    environmentCombo.setSelectedItem(opt);
                }
            }
            @Override public void mouseEntered(java.awt.event.MouseEvent e) {
                if (!isActive) row.setBackground(UITheme.ghostHover());
            }
            @Override public void mouseExited(java.awt.event.MouseEvent e) {
                if (!isActive) row.setBackground(UITheme.surface());
            }
        };
        row.addMouseListener(clickHandler);
        name.addMouseListener(clickHandler);

        return row;
    }

    /** Clickable row for a single {@code .env} overlay — matches Bruno's
     *  UX where only ONE {@code .env} is active at a time (mutually
     *  exclusive with siblings, like the flat environments above).
     *  Clicking anywhere in the row activates that {@code .env}
     *  (deactivates whichever was active). Right side shows ✎ Edit,
     *  ✕ Remove, and a green ✓ if this is the active overlay. */
    private JPanel makeDotEnvListRow(java.io.File f) {
        JPanel row = new JPanel(new BorderLayout(6, 0));
        row.setOpaque(true);
        boolean isActive = f.equals(activeDotEnvFile);
        row.setBackground(isActive ? UITheme.ghostHover() : UITheme.surface());
        row.setBorder(BorderFactory.createEmptyBorder(3, 8, 3, 8));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel name = new JLabel(f.getName());
        name.setFont(name.getFont().deriveFont(isActive ? Font.BOLD : Font.PLAIN, 12f));
        name.setForeground(isActive ? UITheme.SUCCESS : UITheme.foreground());
        name.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 0));
        name.setToolTipText(f.getAbsolutePath());
        row.add(name, BorderLayout.WEST);

        JPanel rightBox = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        rightBox.setOpaque(false);

        JButton edit = new JButton("✎");
        edit.setFont(edit.getFont().deriveFont(Font.PLAIN, 11f));
        edit.setToolTipText("Edit in-app (save re-applies process.env.* overlay)");
        edit.setMargin(new Insets(0, 4, 0, 4));
        edit.setFocusPainted(false);
        edit.addActionListener(e -> openEnvFileInAppEditor(f));
        rightBox.add(edit);

        JButton remove = new JButton("✕");
        remove.setFont(remove.getFont().deriveFont(Font.PLAIN, 11f));
        remove.setToolTipText("Remove from .env overlays (does not delete the file on disk)");
        remove.setMargin(new Insets(0, 4, 0, 4));
        remove.setFocusPainted(false);
        remove.addActionListener(e -> {
            dotenvFiles.remove(f);
            if (f.equals(activeDotEnvFile)) {
                // Auto-promote another .env if available (radio semantics).
                activeDotEnvFile = dotenvFiles.isEmpty() ? null : dotenvFiles.get(0);
            }
            applyProcessEnvOverlay();
            refreshOverviewPanel();
            appendLog("🗑 .env removed: " + f.getName()
                + (activeDotEnvFile == null ? "" : " (activated " + activeDotEnvFile.getName() + ")"));
        });
        rightBox.add(remove);

        if (isActive) {
            JLabel check = new JLabel("✓");
            check.setFont(check.getFont().deriveFont(Font.BOLD, 13f));
            check.setForeground(UITheme.SUCCESS);
            rightBox.add(check);
        }

        row.add(rightBox, BorderLayout.EAST);

        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
        row.setPreferredSize(new Dimension(320, 28));

        // Click anywhere (except the buttons) to toggle activation —
        // matches makeEnvListRow's UX exactly.
        row.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR));
        java.awt.event.MouseAdapter clickHandler = new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                if (isActive) {
                    activeDotEnvFile = null;
                    appendLog("🔓 .env deactivated: " + f.getName());
                } else {
                    activeDotEnvFile = f;
                    appendLog("🔐 .env activated: " + f.getName());
                }
                applyProcessEnvOverlay();
                refreshOverviewPanel();
            }
            @Override public void mouseEntered(java.awt.event.MouseEvent e) {
                if (!isActive) row.setBackground(UITheme.ghostHover());
            }
            @Override public void mouseExited(java.awt.event.MouseEvent e) {
                if (!isActive) row.setBackground(UITheme.surface());
            }
        };
        row.addMouseListener(clickHandler);
        name.addMouseListener(clickHandler);

        return row;
    }

    /** File chooser for adding a raw {@code .env} file as an always-on
     *  overlay. Accepts any file (Bruno's .env is extensionless, and users
     *  frequently name theirs {@code env.dev}, {@code .env.uat}, etc.).
     *  Auto-activates the added file so the user sees an immediate effect. */
    private void pickAndAddDotEnvFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Add .env overlay");
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setAcceptAllFileFilterUsed(true);
        chooser.addChoosableFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
            ".env files (.env, .env.*, env, env.*)", "env"));
        // Default to the workspace root if we have one.
        if (currentWorkspace != null && currentWorkspace.isDirectory()) {
            chooser.setCurrentDirectory(currentWorkspace);
        }
        int result = chooser.showOpenDialog(mainPanel);
        if (result != JFileChooser.APPROVE_OPTION) return;
        File picked = chooser.getSelectedFile();
        if (picked == null || !picked.isFile()) return;
        for (File existing : dotenvFiles) {
            if (existing.getAbsolutePath().equalsIgnoreCase(picked.getAbsolutePath())) {
                // Already tracked — just activate it (mimics clicking its row).
                activeDotEnvFile = existing;
                applyProcessEnvOverlay();
                refreshOverviewPanel();
                appendLog("🔐 .env activated (already tracked): " + picked.getName());
                return;
            }
        }
        dotenvFiles.add(picked);
        // Semi-strict Bruno: newly-added .env becomes the sole active
        // overlay (replaces whatever was active before). Matches the
        // radio-select model — one .env active at a time.
        activeDotEnvFile = picked;
        applyProcessEnvOverlay();
        refreshOverviewPanel();
        appendLog("➕ .env added and activated: " + picked.getAbsolutePath());
    }

    /** Open an env file in the OS default editor (Notepad on Windows,
     *  TextEdit on macOS, xdg-open on Linux). Best-effort — logs but
     *  doesn't throw on failure. Falls back to showing the path in a
     *  dialog so the user can open it manually. */
    private void openEnvFileInEditor(java.io.File f) {
        if (f == null || !f.isFile()) {
            appendLog("⚠ Env file no longer exists: " + f);
            return;
        }
        try {
            if (java.awt.Desktop.isDesktopSupported()) {
                java.awt.Desktop desktop = java.awt.Desktop.getDesktop();
                if (desktop.isSupported(java.awt.Desktop.Action.EDIT)) {
                    desktop.edit(f);
                    appendLog("✎ Opened for edit: " + f.getAbsolutePath());
                    return;
                }
                if (desktop.isSupported(java.awt.Desktop.Action.OPEN)) {
                    desktop.open(f);
                    appendLog("✎ Opened: " + f.getAbsolutePath());
                    return;
                }
            }
        } catch (Exception ex) {
            appendLog("⚠ Could not open editor for " + f.getName() + ": " + ex.getMessage());
        }
        // Fallback — show path in a dialog so the user can copy/open it manually.
        JOptionPane.showMessageDialog(mainPanel,
            "Open this file in your editor:\n" + f.getAbsolutePath(),
            "Edit environment", JOptionPane.INFORMATION_MESSAGE);
    }

    /** Open an env / .env file in the in-app editor
     *  ({@link burp.ui.TextFileEditorDialog}) rather than Notepad. On save,
     *  the callback rewires the variable resolver so changes are picked
     *  up immediately:
     *
     *  <ul>
     *    <li>If the file is a {@code .env} overlay → re-apply the
     *        {@code process.env.*} overlay so newly-added keys resolve.</li>
     *    <li>If the file is the currently-selected flat environment →
     *        re-fire {@code onEnvironmentSelected} to re-parse the env
     *        and refresh {@code {{var}}} bindings.</li>
     *    <li>Otherwise → just log; the change takes effect the next time
     *        the user activates that env.</li>
     *  </ul>
     *
     *  The dialog is modal against the main window and blocks Burp's
     *  extension pane until the user closes it (matches Bruno's UX). */
    private void openEnvFileInAppEditor(java.io.File f) {
        if (f == null || !f.isFile()) {
            appendLog("⚠ Env file no longer exists: " + f);
            return;
        }
        java.awt.Window owner = mainPanel != null
            ? SwingUtilities.getWindowAncestor(mainPanel) : null;
        burp.ui.TextFileEditorDialog.showFor(owner, f, savedFile -> {
            try {
                if (isDotEnvFile(savedFile)) {
                    appendLog("💾 Saved .env — re-applying process.env.* overlay");
                    applyProcessEnvOverlay();
                    return;
                }
                if (selectedEnvironment != null
                    && savedFile.getAbsolutePath().equalsIgnoreCase(
                           selectedEnvironment.getAbsolutePath())) {
                    appendLog("💾 Saved active env — re-parsing " + savedFile.getName());
                    // Re-fire onEnvironmentSelected via the combo so the
                    // normal cascade (clear + reparse + reapply overlay +
                    // reanalyze) runs. Set to null first to force a
                    // change event even if the current selection is
                    // still the same file.
                    if (environmentCombo != null) {
                        Object was = environmentCombo.getSelectedItem();
                        for (int i = 0; i < environmentCombo.getItemCount(); i++) {
                            EnvOption o = environmentCombo.getItemAt(i);
                            if (o != null && o.file != null
                                && o.file.getAbsolutePath().equalsIgnoreCase(savedFile.getAbsolutePath())) {
                                environmentCombo.setSelectedIndex(0);
                                environmentCombo.setSelectedItem(o);
                                break;
                            }
                        }
                    }
                    return;
                }
                appendLog("💾 Saved " + savedFile.getName()
                    + " — activate this env to see the changes.");
            } catch (Exception ex) {
                appendLog("⚠ Post-save refresh failed: " + ex.getMessage());
            }
        });
    }

    private int countAllRequests(java.util.List<burp.models.PostmanCollection.Item> items) {
        if (items == null) return 0;
        int n = 0;
        for (burp.models.PostmanCollection.Item it : items) {
            if (it == null) continue;
            if (it.request != null) n++;
            if (it.item != null) n += countAllRequests(it.item);
        }
        return n;
    }

    private String toHex(java.awt.Color c) {
        if (c == null) return "#333333";
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }

    /** Provision the workspace for an imported collection using the
     *  Bruno-style Import Collection dialog. Behaviour:
     *
     *  <ol>
     *    <li><b>Postman JSON exports</b> skip the dialog entirely — Postman
     *        collections don't need a persistent workspace since envs
     *        are separate {@code .postman_environment.json} files that
     *        can be loaded via the <b>Add env…</b> button.</li>
     *    <li><b>Bruno folder sources</b> (existing Bruno collection
     *        directory on disk) skip the dialog too — they already have
     *        their {@code .env} / {@code environments/} layout, so we
     *        just use the folder as-is.</li>
     *    <li><b>Bruno single-file sources</b> ({@code .bru},
     *        {@code bruno.json}, OpenCollection {@code .yml/.yaml}) show
     *        the dialog so the user can name a workspace folder that
     *        will hold the persisted envs.</li>
     *    <li>If a BurpMan workspace with the peeked name already exists
     *        at the default location, reuse it silently (no dialog spam
     *        on reopen).</li>
     *  </ol>
     *
     *  <p>Returns {@code null} for Postman sources or when the user cancels
     *  the dialog (envs will simply not be persisted for this session —
     *  the collection still loads).
     */
    private java.io.File provisionWorkspaceForImport(java.io.File source) {
        if (source == null) return null;

        // Postman JSON exports don't need a workspace — envs come from
        // separate .postman_environment.json files loaded via Add env…
        if (!isBrunoSource(source)) {
            return null;
        }

        // Bruno FOLDER sources already have their layout — reuse the
        // folder directly, no dialog. The Import dialog is only for
        // single-file Bruno collections that need a fresh workspace.
        if (source.isDirectory()) {
            return source;
        }

        // 1) Determine the default name — prefer collection.info.name over
        // the raw filename so "PDP_2026_PenTest_1.json" becomes "PDP".
        String peeked = burp.workspace.WorkspaceManager.peekCollectionName(source);
        String defaultName = (peeked != null && !peeked.isEmpty())
            ? burp.workspace.WorkspaceManager.sanitizeFolderName(peeked)
            : burp.workspace.WorkspaceManager.deriveWorkspaceName(source);

        // 2) Determine the default location — sticky if we've asked before
        // this session, otherwise the OneDrive/Documents/BurpMan-Workspaces
        // path.
        String defaultLocation = preferredImportLocation;
        if (defaultLocation == null || defaultLocation.isEmpty()) {
            java.nio.file.Path root = burp.workspace.WorkspaceManager.defaultWorkspaceRoot();
            defaultLocation = root == null ? "" : root.toString();
        }

        // 3) Reuse silently when a BurpMan workspace with that name already
        // exists at the default location AND is populated (has at least one
        // env file). An empty README-only stub is left over from a prior
        // failed import — don't reuse it, ask again so the user can pick
        // the format/location fresh.
        if (!defaultLocation.isEmpty()) {
            java.io.File candidate = new java.io.File(defaultLocation, defaultName);
            java.io.File envs = new java.io.File(candidate, "environments");
            if (candidate.isDirectory()
                && new java.io.File(candidate, "README.md").isFile()
                && envs.isDirectory()
                && workspaceLooksPopulated(envs)) {
                return candidate;
            }
        }

        // 4) Ask the user (matches Bruno's own Import Collection dialog).
        ImportCollectionDialog dlg = new ImportCollectionDialog(
            mainPanel, defaultName, defaultLocation, preferredEnvFormat);
        dlg.setVisible(true);
        if (!dlg.isConfirmed()) {
            appendLog("ℹ Import cancelled — envs will not be persisted for this session.");
            return null;
        }

        // 5) Create (or reuse) the workspace at the chosen path.
        java.io.File location = new java.io.File(dlg.getEnteredLocation());
        java.io.File ws = burp.workspace.WorkspaceManager
            .getOrCreateWorkspaceAt(location, dlg.getEnteredName());
        if (ws == null) {
            appendLog("⚠ Could not create workspace at "
                + dlg.getEnteredLocation() + "/" + dlg.getEnteredName()
                + " — envs will not be persisted.");
            return null;
        }

        // Remember for the next import in this session.
        preferredImportLocation = dlg.getEnteredLocation();
        preferredEnvFormat = dlg.getEnteredFormat();
        return ws;
    }

    /** True when the source is a Bruno collection (Bruno {@code .bru} file,
     *  {@code bruno.json}, OpenCollection {@code .yml/.yaml}, or a
     *  Bruno JSON export). Postman {@code .json} exports return false —
     *  they don't need a persistent workspace and shouldn't trigger the
     *  Import Collection dialog. */
    private boolean isBrunoSource(java.io.File source) {
        if (source == null) return false;
        // Bruno-shaped folder: has bruno.json, any .bru files, or the
        // Bruno-standard `.env` / `environments/` layout.
        if (source.isDirectory()) {
            if (new java.io.File(source, "bruno.json").isFile()) return true;
            if (new java.io.File(source, ".env").isFile()) return true;
            if (new java.io.File(source, "environments").isDirectory()) return true;
            java.io.File[] kids = source.listFiles();
            if (kids != null) {
                for (java.io.File k : kids) {
                    if (k.isFile() && k.getName().toLowerCase().endsWith(".bru")) {
                        return true;
                    }
                }
            }
            return false;
        }
        String name = source.getName().toLowerCase(java.util.Locale.ROOT);
        if (name.endsWith(".bru")) return true;
        if (name.equals("bruno.json")) return true;
        if (name.endsWith(".yml") || name.endsWith(".yaml")) {
            return sniffYamlIsOpenCollection(source);
        }
        if (name.endsWith(".json")) {
            // Bruno JSON collection export looks like:
            //   { "name": "...", "version": "1", "items": [ { "type": "http", ... } ] }
            // Postman v2.1 collection export looks like:
            //   { "info": { "name": "...", "schema": "https://schema.getpostman.com/..." },
            //     "item": [ ... ] }
            // The presence of a Postman schema URL is a hard signal; otherwise
            // check for Bruno-specific top-level keys.
            return sniffJsonIsBruno(source);
        }
        return false;
    }

    /** True when the first ~8 KB of a YAML file mention Bruno's
     *  {@code opencollection:} / {@code type: collection} header, versus
     *  some other unrelated YAML the user might have selected. */
    private boolean sniffYamlIsOpenCollection(java.io.File f) {
        if (f == null || !f.isFile()) return false;
        try (java.io.InputStream in = new java.io.FileInputStream(f)) {
            byte[] buf = new byte[8192];
            int n = in.read(buf);
            if (n <= 0) return false;
            String head = new String(buf, 0, n, java.nio.charset.StandardCharsets.UTF_8)
                .toLowerCase(java.util.Locale.ROOT);
            return head.contains("opencollection") || head.contains("type: collection")
                || head.contains("type:collection");
        } catch (Exception ignore) { }
        return false;
    }

    /** True when a workspace {@code environments/} directory contains at
     *  least one persisted env file ({@code *.bru}, {@code *.yml},
     *  {@code *.yaml}, {@code *.json}). An empty {@code environments/}
     *  means the workspace was only scaffolded — either by a prior failed
     *  import, or because the user cancelled before saving any env — so
     *  the Import Collection dialog should show again instead of silently
     *  reusing the stub. */
    private boolean workspaceLooksPopulated(java.io.File envs) {
        if (envs == null || !envs.isDirectory()) return false;
        java.io.File[] kids = envs.listFiles();
        if (kids == null) return false;
        for (java.io.File k : kids) {
            if (!k.isFile()) continue;
            String n = k.getName().toLowerCase(java.util.Locale.ROOT);
            if (n.endsWith(".bru") || n.endsWith(".yml") || n.endsWith(".yaml") || n.endsWith(".json")) {
                return true;
            }
        }
        return false;
    }

    /** True when the first ~8 KB of a JSON file look like a Bruno
     *  collection export ({@code name} + {@code version} + {@code items}
     *  at the top level, with item types like {@code "type": "http"} or
     *  {@code "type": "folder"}) rather than a Postman v2.1 export
     *  ({@code info.schema} pointing at schema.getpostman.com). */
    private boolean sniffJsonIsBruno(java.io.File f) {
        if (f == null || !f.isFile()) return false;
        try (java.io.InputStream in = new java.io.FileInputStream(f)) {
            byte[] buf = new byte[8192];
            int n = in.read(buf);
            if (n <= 0) return false;
            String head = new String(buf, 0, n, java.nio.charset.StandardCharsets.UTF_8);
            String lower = head.toLowerCase(java.util.Locale.ROOT);
            // Hard "Postman" signal — always beats Bruno hints.
            if (lower.contains("schema.getpostman.com")
                || lower.contains("schema.postman.com")) {
                return false;
            }
            // Bruno signal — top-level "items" (plural) array AND either
            // "version" or a Bruno-specific item type header. Postman uses
            // "item" (singular), so "items" alone is a strong hint.
            boolean hasItems = head.contains("\"items\"");
            boolean hasVersion = head.contains("\"version\"");
            boolean hasBrunoItemType = head.contains("\"type\": \"http\"")
                || head.contains("\"type\":\"http\"")
                || head.contains("\"type\": \"folder\"")
                || head.contains("\"type\":\"folder\"")
                || head.contains("\"type\": \"graphql\"")
                || head.contains("\"type\":\"graphql\"");
            return hasItems && (hasVersion || hasBrunoItemType);
        } catch (Exception ignore) { }
        return false;
    }

    /** Reveal the current collection's Bruno workspace folder in the OS
     *  file manager (Windows Explorer / Finder / xdg-open). Best-effort —
     *  logs but doesn't throw on failure. Also shows the path in a dialog
     *  so the user can copy it if desktop integration isn't available. */
    private void openCurrentWorkspaceInExplorer() {
        if (currentWorkspace == null || !currentWorkspace.isDirectory()) {
            appendLog("⚠ No workspace yet — load a collection first.");
            return;
        }
        try {
            if (java.awt.Desktop.isDesktopSupported()) {
                java.awt.Desktop.getDesktop().open(currentWorkspace);
                appendLog("📂 Opened workspace: " + currentWorkspace.getAbsolutePath());
                return;
            }
        } catch (Exception ex) {
            appendLog("ℹ Could not open workspace via Desktop API: " + ex.getMessage());
        }
        javax.swing.JOptionPane.showMessageDialog(mainPanel,
            "Bruno workspace folder:\n\n" + currentWorkspace.getAbsolutePath()
                + "\n\nCopy this path and paste it into Windows Explorer.",
            "BurpMan Workspace",
            javax.swing.JOptionPane.INFORMATION_MESSAGE);
    }

    /** Show the "Workspace ▾" popup menu next to the trigger button.
     *  Currently unused — kept in case we need a compact menu again in
     *  future. The rich workspace actions live in the Overview tab. */
    @SuppressWarnings("unused")
    private void showWorkspaceMenu(javax.swing.JComponent invoker) {
        javax.swing.JPopupMenu menu = new javax.swing.JPopupMenu();

        javax.swing.JMenuItem openItem = new javax.swing.JMenuItem("📂  Open workspace folder…");
        openItem.setToolTipText(currentWorkspace == null
            ? "Load a collection first"
            : currentWorkspace.getAbsolutePath());
        openItem.addActionListener(e -> openCurrentWorkspaceInExplorer());
        menu.add(openItem);

        javax.swing.JMenuItem linkItem = new javax.swing.JMenuItem("🔗  Link folder with envs…");
        linkItem.setToolTipText("Point BurpMan at a folder that already contains .env / environments/");
        linkItem.addActionListener(e -> linkExternalFolder());
        menu.add(linkItem);

        javax.swing.JMenuItem newItem = new javax.swing.JMenuItem("➕  New environment…");
        newItem.setToolTipText("Create an empty .bru or .yml environment file in the workspace");
        newItem.addActionListener(e -> createNewEnvironmentInWorkspace());
        menu.add(newItem);

        menu.addSeparator();

        javax.swing.JMenuItem rescanItem = new javax.swing.JMenuItem("🔄  Rescan for envs");
        rescanItem.setToolTipText("Re-read the workspace and linked folders — pick up any files you dropped in");
        rescanItem.addActionListener(e -> rescanEnvironments());
        menu.add(rescanItem);

        menu.show(invoker, 0, invoker.getHeight());
    }

    /** Let the user pick any folder that already contains {@code .env} or
     *  {@code environments/}. The path is saved to
     *  {@code <workspace>/.brunoLink} so future loads of this collection
     *  auto-pick up envs from that folder too. */
    private void linkExternalFolder() {
        if (currentWorkspace == null) {
            appendLog("⚠ Load a collection first — the workspace holds the link.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle("Link a folder with environments (must contain .env or environments/)");
        chooser.setAcceptAllFileFilterUsed(false);
        if (chooser.showOpenDialog(mainPanel) != JFileChooser.APPROVE_OPTION) return;
        java.io.File picked = chooser.getSelectedFile();
        if (picked == null || !picked.isDirectory()) return;
        if (!burp.workspace.WorkspaceManager.isBrunoCollectionFolder(picked)) {
            int ok = javax.swing.JOptionPane.showConfirmDialog(mainPanel,
                "That folder has no .env or environments/ subfolder.\n\n"
                    + picked.getAbsolutePath() + "\n\nLink it anyway?",
                "Link folder", javax.swing.JOptionPane.YES_NO_OPTION,
                javax.swing.JOptionPane.WARNING_MESSAGE);
            if (ok != javax.swing.JOptionPane.YES_OPTION) return;
        }
        boolean saved = burp.workspace.WorkspaceManager.saveBrunoLink(currentWorkspace, picked);
        if (saved) {
            appendLog("🔗 Linked env source: " + picked.getAbsolutePath()
                + "  (saved to " + currentWorkspace.getName() + "/.brunoLink)");
        } else {
            appendLog("⚠ Could not save link — falling back to session-only pickup.");
        }
        autoDiscoverBrunoEnvsNear(picked);
        refreshOverviewPanel();
    }

    /** Ask the user for a name + format ({@code .bru} or {@code .yml}) and
     *  create an empty environment file in the workspace. Adds it to the
     *  dropdown and selects it. */
    private void createNewEnvironmentInWorkspace() {
        if (currentWorkspace == null) {
            appendLog("⚠ Load a collection first — the workspace holds new envs.");
            return;
        }
        // Two prompts: name, then format.
        String name = (String) javax.swing.JOptionPane.showInputDialog(mainPanel,
            "Name for the new environment:\n(saved under "
                + currentWorkspace.getName() + "/environments/)",
            "New environment",
            javax.swing.JOptionPane.PLAIN_MESSAGE,
            null, null, "");
        if (name == null || name.trim().isEmpty()) return;

        Object[] options = {"Bruno (.bru)", "YAML (.yml)"};
        // Default to the format the user picked in the Import dialog.
        int defaultIdx = "yaml".equalsIgnoreCase(preferredEnvFormat) || "yml".equalsIgnoreCase(preferredEnvFormat) ? 1 : 0;
        int fmtChoice = javax.swing.JOptionPane.showOptionDialog(mainPanel,
            "Which format?",
            "New environment",
            javax.swing.JOptionPane.DEFAULT_OPTION,
            javax.swing.JOptionPane.QUESTION_MESSAGE,
            null, options, options[defaultIdx]);
        if (fmtChoice < 0) return;
        String fmt = (fmtChoice == 1) ? "yml" : "bru";
        // Remember for next time.
        preferredEnvFormat = fmt.equals("yml") ? "yaml" : "bru";

        java.io.File created = burp.workspace.WorkspaceManager
            .createEmptyEnvironment(currentWorkspace, name.trim(), fmt);
        if (created == null) {
            appendLog("⚠ Could not create env — name may collide or workspace missing.");
            return;
        }
        appendLog("➕ Created environment: " + created.getAbsolutePath());
        EnvOption opt = new EnvOption(created, prettyEnvLabel(created));
        loadedEnvironments.add(opt);
        environmentCombo.addItem(opt);
        environmentCombo.setSelectedItem(opt);
        // Open the file in the OS editor so the user can fill it in.
        try {
            if (java.awt.Desktop.isDesktopSupported()) {
                java.awt.Desktop.getDesktop().open(created);
            }
        } catch (Exception ignore) { /* silent */ }
    }

    /** Re-run env auto-discovery against the workspace, source location, and
     *  any linked folder. Adds anything new to the dropdown. */
    private void rescanEnvironments() {
        int before = loadedEnvironments.size();
        if (selectedCollection != null) autoDiscoverBrunoEnvsNear(selectedCollection);
        if (currentWorkspace != null) autoDiscoverBrunoEnvsNear(currentWorkspace);
        java.io.File linked = burp.workspace.WorkspaceManager
            .findLinkedBrunoFolder(currentWorkspace);
        if (linked != null) autoDiscoverBrunoEnvsNear(linked);
        int added = loadedEnvironments.size() - before;
        appendLog("🔄 Rescan complete — " + added + " new env(s) added ("
            + loadedEnvironments.size() + " total).");
        refreshOverviewPanel();
    }

    private void selectEnvironmentFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setMultiSelectionEnabled(true);
        chooser.setFileFilter(new FileNameExtensionFilter(
                "Auto-detect: Postman JSON, Bruno .bru/.json/.yml/.env environment",
                "json",
                "bru",
                "yml",
                "yaml",
                "env"
        ));
        chooser.setAcceptAllFileFilterUsed(true);
        chooser.setDialogTitle("Add Environment(s)");

        if (chooser.showOpenDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
            java.io.File[] picked = chooser.getSelectedFiles();
            if (picked == null || picked.length == 0) {
                java.io.File one = chooser.getSelectedFile();
                if (one != null) picked = new java.io.File[]{ one };
            }
            if (picked == null) return;
            EnvOption lastAdded = null;
            boolean addedAnyDotenv = false;
            for (java.io.File f : picked) {
                if (f == null) continue;
                // Bruno-workflow: if this env came from OUTSIDE the current
                // collection's workspace, offer to copy it in so it survives
                // future imports without the user hunting it down again.
                java.io.File effective = maybeMirrorEnvToWorkspace(f);

                // Route .env / .env.* files to the always-on overlay bucket
                // instead of the mutually-exclusive flat-env dropdown.
                // Bruno's model: .env provides process.env.* values and stays
                // active regardless of which flat environment is selected.
                if (isDotEnvFile(effective)) {
                    boolean already = false;
                    for (java.io.File existing : dotenvFiles) {
                        if (existing.getAbsolutePath().equalsIgnoreCase(effective.getAbsolutePath())) {
                            already = true; break;
                        }
                    }
                    if (!already) {
                        dotenvFiles.add(effective);
                        // Newly-added .env becomes the sole active overlay
                        // (semi-strict Bruno: one .env at a time).
                        activeDotEnvFile = effective;
                        appendLog("➕ .env added and activated: " + effective.getAbsolutePath());
                        addedAnyDotenv = true;
                    } else {
                        // Already tracked — activate it so the user gets
                        // immediate feedback (mimics clicking its row).
                        activeDotEnvFile = effective;
                        addedAnyDotenv = true;
                        appendLog("🔐 .env activated (already tracked): " + effective.getName());
                    }
                    continue;
                }

                boolean already = false;
                for (EnvOption o : loadedEnvironments) {
                    if (o.file != null && o.file.getAbsolutePath().equals(effective.getAbsolutePath())) {
                        already = true; lastAdded = o; break;
                    }
                }
                if (!already) {
                    EnvOption opt = new EnvOption(effective, prettyEnvLabel(effective));
                    loadedEnvironments.add(opt);
                    environmentCombo.addItem(opt);
                    appendLog("Added environment: " + effective.getAbsolutePath());
                    lastAdded = opt;
                }
            }
            if (addedAnyDotenv) {
                applyProcessEnvOverlay();
                refreshOverviewPanel();
            }
            if (lastAdded != null) {
                environmentCombo.setSelectedItem(lastAdded); // triggers onEnvironmentSelected
            }
        }
    }

    /** If the picked env file lives outside the current Bruno workspace,
     *  copy it into {@code <workspace>/environments/} (or overwrite
     *  {@code <workspace>/.env} for dotenv files) so the env survives
     *  future collection loads. Returns the effective file to use — the
     *  copy inside the workspace if the copy succeeded, or the original
     *  otherwise (best-effort, never fatal). */
    private java.io.File maybeMirrorEnvToWorkspace(java.io.File picked) {
        try {
            if (currentWorkspace == null || !currentWorkspace.isDirectory()) return picked;
            String pickedPath = picked.getAbsolutePath();
            String wsPath = currentWorkspace.getAbsolutePath();
            // Already inside the workspace? Use as-is.
            if (pickedPath.toLowerCase(java.util.Locale.ROOT)
                .startsWith(wsPath.toLowerCase(java.util.Locale.ROOT))) {
                return picked;
            }
            String lower = picked.getName().toLowerCase(java.util.Locale.ROOT);
            boolean isDotenv = lower.equals(".env")
                || lower.startsWith(".env.")
                || lower.endsWith(".env");
            java.io.File dest;
            if (isDotenv) {
                dest = new java.io.File(currentWorkspace, ".env");
            } else {
                java.io.File envsDir = new java.io.File(currentWorkspace, "environments");
                if (!envsDir.isDirectory()) envsDir.mkdirs();
                dest = new java.io.File(envsDir, picked.getName());
            }
            // Don't clobber an existing workspace file silently — if there's
            // already something there, keep the picked path as-is.
            if (dest.exists() && dest.length() > 0) return picked;
            java.nio.file.Files.copy(
                picked.toPath(),
                dest.toPath(),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            appendLog("📥 Copied env into workspace: " + dest.getAbsolutePath());
            return dest;
        } catch (Exception ex) {
            appendLog("ℹ Could not mirror env into workspace: " + ex.getMessage());
            return picked;
        }
    }

    /** Fired when the user picks a different environment from the dropdown. */
    private void onEnvironmentSelected() {
        Object sel = environmentCombo.getSelectedItem();
        if (!(sel instanceof EnvOption)) return;
        EnvOption opt = (EnvOption) sel;
        selectedEnvironment = opt.file;
        environmentField.setText(opt.file == null ? "" : opt.file.getAbsolutePath());
        if (authManagerPanel != null) authManagerPanel.resetUI();
        appendLog("Active environment: " + (opt.file == null ? "(none)" : opt.file.getName()));
        refreshOverviewPanel();
        // Persist the env selection so the next restart reopens it.
        persistWorkspaceSnapshot();
        // Re-parse so subsequent Analyze/Send/Preview use the new env vars.
        try {
            burp.parser.VariableResolver r = importer.getVariableResolver();
            if (r != null) r.clearAllVariables();
            if (opt.file != null) {
                burp.models.PostmanEnvironment env = new burp.parser.PostmanParser().parseEnvironment(opt.file);
                if (env != null && r != null) r.addEnvironmentVariables(env);
                // Auto-discover globals next to the env file (or re-apply the
                // already-discovered one). Lower precedence than env.
                autoLoadGlobalsNear(opt.file);
                if (selectedGlobals != null && r != null) {
                    try {
                        burp.models.PostmanEnvironment g = new burp.parser.PostmanParser().parseEnvironment(selectedGlobals);
                        if (g != null) r.addGlobalsVariables(g);
                    } catch (Exception ignore) {}
                }
            }
            // Keep collection-level vars loaded after env swaps (e.g. host1).
            importer.reapplyCollectionVariablesForCurrentCollection();
            // Re-apply the always-on .env overlay AFTER the flat env
            // swap so process.env.* placeholders in the new env's values
            // (e.g. Bruno's `apim-secret: {{process.env.uat-api-key}}`)
            // still resolve. Without this, clearAllVariables() above would
            // have dropped the overlay along with the previous env.
            applyProcessEnvOverlay();
            refreshVariables(r != null ? r.getVariables() : java.util.Collections.emptyMap());
        } catch (Exception ex) {
            appendLog("⚠ Failed to load environment: " + ex.getMessage());
        }

        // Postman-style: re-run analyze with the new env in the background
        // so OAuth2/JWT detection picks up env-templated URLs and tokens
        // populate before the user clicks anything. Failures are silent.
        if (selectedCollection != null) {
            final java.io.File envForAnalyze = selectedEnvironment;
            new Thread(() -> {
                try {
                    Thread.sleep(150);
                    importer.analyzeAuthFromFiles(selectedCollection, envForAnalyze);
                    SwingUtilities.invokeLater(() -> {
                        try { if (authManagerPanel != null) authManagerPanel.reenableAnalyzeButton(); }
                        catch (Exception ignore) {}
                    });
                } catch (Throwable t) {
                    SwingUtilities.invokeLater(() ->
                            appendLog("ℹ Re-analyze (env change) skipped: " + t.getMessage()));
                }
            }, "BurpMan-AutoAnalyze-EnvChange").start();
        }

        // Refresh the currently-selected request so {{vars}} re-resolve.
        try {
            javax.swing.JTree t = treePanel != null ? treePanel.getTree() : null;
            javax.swing.tree.TreePath p = t != null ? t.getSelectionPath() : null;
            if (t != null && p != null) {
                clearUnsavedCache();
                if (currentLoadedKey != null && !savedKeys.contains(currentLoadedKey)) currentLoadedKey = null;
                t.clearSelection();
                t.setSelectionPath(p);
            }
        } catch (Exception ignore) {}
    }
    
    
    private void startImport() {
        if (selectedCollection != null) {
            logArea.setText("");
            String destination = getSelectedDestination();
            importer.importCollection(selectedCollection, selectedEnvironment, destination);
        }
    }

    private void startRunPreview() {
        if (selectedCollection == null) return;
        int n = JOptionPane.showConfirmDialog(mainPanel,
            "<html>This will fire EACH request in the collection ONCE so that:<br/>"
          + "&nbsp;&nbsp;• pre-request scripts run<br/>"
          + "&nbsp;&nbsp;• post-response scripts run (extracting tokens, etc.)<br/>"
          + "&nbsp;&nbsp;• subsequent requests pick up the resolved variables<br/><br/>"
          + "<b>The requests will NOT be added to the Site map / Scanner queue.</b><br/>"
          + "Fully-resolved requests are then dropped into Repeater for manual replay.<br/><br/>"
          + "Continue?</html>",
            "Run Collection (Preview)",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE);
        if (n != JOptionPane.YES_OPTION) return;
        logArea.setText("");
        appendLog("▶️ Run Collection (Preview): firing requests once each (NOT added to site map)…");
        importer.importCollection(selectedCollection, selectedEnvironment, "preview");
    }
    
    private void startPreview() {
        if (selectedCollection != null) {
            logArea.setText("");
            importer.showPreview(selectedCollection, selectedEnvironment);
        }
    }
    private void restartApp() {
        SwingUtilities.invokeLater(() -> {
            try {
                // Clear selected files
                selectedCollection = null;
                selectedEnvironment = null;
                selectedGlobals = null;
                importer.setGlobalsFile(null);
                // Clear recent collection suggestions shown in the Browse ▾ menu.
                saveRecent(new java.util.ArrayList<>());
    
                // Reset fields
                collectionField.setText("");
                environmentField.setText("");
                if (environmentCombo != null) {
                    environmentCombo.removeAllItems();
                    environmentCombo.addItem(new EnvOption(null, "— No Environment —"));
                }
                loadedEnvironments.clear();
    
                // Clear collection tree panel
                treePanel.clearTree();
    
                // Reset progress
                progressBar.setValue(0);
    
                // Reset buttons
                previewButton.setEnabled(false);
                importButton.setEnabled(false);
                retryButton.setEnabled(false);
                cancelButton.setEnabled(false);
                importer.clearEnvironmentVariables();
    
                logArea.setText("");
                appendLog("Application reloaded successfully.");

                // Clear request builder, history, response viewer, and folder auth overrides
                if (builderPanel != null) {
                    builderPanel.clearBuilder();
                    builderPanel.setInheritedAuthSupplier(null);
                    builderPanel.setInheritedAuthDescription(null);
                    builderPanel.setSourceContext("", "");
                }
                requestEditCache.clear();
                requestSourceByKey.clear();
                requestResponseCache.clear();
                savedKeys.clear();
                currentLoadedKey = null;
                if (requestHistory != null) requestHistory.clear();
                if (responsePanel != null) responsePanel.clear();
                if (runResultsPanel != null) runResultsPanel.clear();
                if (authManagerPanel != null) authManagerPanel.resetUI();
                if (folderEditorRef != null) folderEditorRef.reset();
                try {
                    burp.auth.FolderAuthRegistry reg = importer.getFolderAuthRegistry();
                    if (reg != null) reg.clear();
                } catch (Exception ignore) { }
    
            } catch (Exception ex) {
                showError("Failed to reload application: " + ex.getMessage());
            }
        });
    }
    private void startRetry() {
        logArea.setText("");
        appendLog("Retrying failed requests...");
        String destination = getSelectedDestination();
        importer.retryFailedRequests(destination);
    }
    
    public String getSelectedDestination() {
        if (repeaterOption.isSelected()) {
            return "repeater";
        } else if (sitemapOption.isSelected()) {
            return "sitemap";
        } else if (bothOption.isSelected()) {
            return "both";
        }
        return "repeater"; // Default fallback
    }
    
    private final StringBuilder logBuffer = new StringBuilder();
    private final Object logLock = new Object();
    private javax.swing.Timer logFlushTimer;

    public void appendLog(String message) {
        synchronized (logLock) {
            logBuffer.append(message).append('\n');
            if (logFlushTimer == null) {
                logFlushTimer = new javax.swing.Timer(80, e -> flushLog());
                logFlushTimer.setRepeats(false);
            }
            if (!logFlushTimer.isRunning()) {
                logFlushTimer.restart();
            }
        }
    }

    private void flushLog() {
        String pending;
        synchronized (logLock) {
            if (logBuffer.length() == 0) return;
            pending = logBuffer.toString();
            logBuffer.setLength(0);
        }
        // Trim runaway log so the JTextArea doesn't choke. Lower cap (~5k
        // lines worth) keeps redraws snappy — the previous 500K char cap
        // let the document balloon to ~10k lines on big collections, which
        // made every appendLog() trigger a slow re-layout.
        int maxLen = 150_000;
        if (logArea.getDocument().getLength() + pending.length() > maxLen) {
            try {
                logArea.getDocument().remove(0,
                    Math.max(0, logArea.getDocument().getLength() + pending.length() - maxLen));
            } catch (Exception ignore) {}
        }
        logArea.append(pending);
        logArea.setCaretPosition(logArea.getDocument().getLength());
    }
    
    public void updateProgress(int value) {
        SwingUtilities.invokeLater(() -> progressBar.setValue(value));
    }

    /**
     * Clear any cached per-request edits in the Builder. Called by the importer
     * after a fresh Analyze/auto-run so stale snapshots (e.g. without an
     * Authorization header captured before the post-script set {{token}}) don't
     * shadow the freshly-resolved request when the user clicks the tree.
     */
    public void clearRequestEditCache() {
        SwingUtilities.invokeLater(() -> {
            requestEditCache.clear();
            requestSourceByKey.clear();
            savedKeys.clear();
            currentLoadedKey = null;
        });
    }

    /**
     * Persist the currently focused builder edits into the in-memory request model
     * right before a batch run. This prevents unsaved multipart/file path edits
     * from being dropped when run flows clear transient edit caches.
     */
    public void persistCurrentRequestEditsForRun() {
        Runnable persist = () -> {
            try {
                if (builderPanel != null && currentLoadedKey != null) {
                    burp.models.PostmanCollection.Request snap = builderPanel.getCurrentSnapshot();
                    if (snap != null) {
                        requestEditCache.put(currentLoadedKey, snap);
                    }
                }
                synchronized (requestEditCache) {
                    for (java.util.Map.Entry<String, burp.models.PostmanCollection.Request> en
                            : requestEditCache.entrySet()) {
                        burp.models.PostmanCollection.Request snap = en.getValue();
                        if (snap == null) continue;
                        burp.models.PostmanCollection.Request source = requestSourceByKey.get(en.getKey());
                        if (source == null) continue;
                        applySnapshotToSourceRequest(source, snap);
                    }
                }
                if (currentPmRequest != null && currentLoadedKey != null) {
                    burp.models.PostmanCollection.Request cur = requestEditCache.get(currentLoadedKey);
                    if (cur != null) applySnapshotToSourceRequest(currentPmRequest, cur);
                }
                if (currentClickedNode != null && currentPmRequest != null && currentPmRequest.method != null) {
                    currentClickedNode.setMethod(currentPmRequest.method);
                }
            } catch (Exception ignore) {}
        };
        if (SwingUtilities.isEventDispatchThread()) {
            persist.run();
        } else {
            try { SwingUtilities.invokeAndWait(persist); }
            catch (Exception ignore) { persist.run(); }
        }
    }

    private static void applySnapshotToSourceRequest(
            burp.models.PostmanCollection.Request source,
            burp.models.PostmanCollection.Request snap) {
        if (source == null || snap == null) return;
        source.method = snap.method;
        source.url = snapshotUrlForSource(snap);
        source.rawUrlTemplate = snap.rawUrlTemplate;
        source.header = snap.header;
        source.auth = snap.auth;
        source.body = snap.body;
    }

    private static boolean isUserAddedRequest(burp.models.PostmanCollection.Request req) {
        return req != null && req.userAdded;
    }

    private static Object snapshotUrlForSource(burp.models.PostmanCollection.Request snap) {
        if (snap == null) return null;
        String raw = snap.rawUrlTemplate;
        if (raw != null && !raw.trim().isEmpty()) {
            return raw;
        }
        return snap.url;
    }
    
    public void setImportInProgress() {
        SwingUtilities.invokeLater(() -> {
            previewButton.setEnabled(false);
            importButton.setEnabled(false);
            retryButton.setEnabled(false);
            cancelButton.setEnabled(true);
            progressBar.setValue(0);
        });
    }
    public void setImportComplete() {
        SwingUtilities.invokeLater(() -> {
            previewButton.setEnabled(selectedCollection != null);
            importButton.setEnabled(selectedCollection != null);
            // retryButton will be enabled by showImportSummary if there are failed requests
            cancelButton.setEnabled(false);
            progressBar.setValue(100);
        });
    }
    public void updateTokenArea(String token) {
        if (authManagerPanel != null) {
            SwingUtilities.invokeLater(() -> {
                authManagerPanel.setToken(token);
            });
        }
    }
    public void showImportSummary(ImportResult result) {
        SwingUtilities.invokeLater(() -> {
            StringBuilder summary = new StringBuilder();
            summary.append("\n========== IMPORT SUMMARY ==========\n");
            summary.append("Collection: ").append(result.collectionName).append("\n");
            summary.append("Total Requests: ").append(result.totalRequests).append("\n");
            summary.append("Successfully Imported: ").append(result.successCount).append("\n");
            summary.append("Failed: ").append(result.failedRequests.size()).append("\n");
            
            if (!result.failedRequests.isEmpty()) {
                summary.append("\nFailed Requests:\n");
                for (String failure : result.failedRequests) {
                    summary.append("  - ").append(failure).append("\n");
                }
                
                // Enable retry button if there are failed requests
                retryButton.setEnabled(true);
                summary.append("\n💡 TIP: Use 'Retry Failed Requests' button to retry failed requests after fixing network issues.\n");
            } else {
                retryButton.setEnabled(false);
            }
            
            if (result.error != null) {
                summary.append("\nError: ").append(result.error).append("\n");
            }
            
            summary.append("====================================\n");
            
            appendLog(summary.toString());
            
            // Show dialog
            String message = String.format(
                "Import completed!\n\n" +
                "Successfully imported: %d/%d requests\n" +
                "Failed: %d requests",
                result.successCount, result.totalRequests, result.failedRequests.size()
            );
            
            if (!result.failedRequests.isEmpty()) {
                message += "\n\n💡 You can retry failed requests using the 'Retry Failed Requests' button.";
            }
            
            JOptionPane.showMessageDialog(
                mainPanel,
                message,
                "Import Complete",
                result.failedRequests.isEmpty() ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.WARNING_MESSAGE
            );
        });
    }
    
    public void showError(String message) {
        SwingUtilities.invokeLater(() -> {
            JOptionPane.showMessageDialog(mainPanel, message, "Error", JOptionPane.ERROR_MESSAGE);
        });
    }
    
    private void clearEnvironmentVariables() {
        int result = JOptionPane.showConfirmDialog(
            mainPanel,
            "Clear all environment variables? This cannot be undone.",
            "Clear Variables",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.QUESTION_MESSAGE
        );
        
        if (result == JOptionPane.YES_OPTION) {
            // Clear the UI
            selectedEnvironment = null;
            environmentField.setText("");
            if (environmentCombo != null) {
                environmentCombo.removeAllItems();
                environmentCombo.addItem(new EnvOption(null, "— No Environment —"));
            }
            loadedEnvironments.clear();

            // Clear variables in the importer
            importer.clearEnvironmentVariables();

            // Log the action
            appendLog("Environment variables and dropdown cleared.");
        }
    }
    public CollectionTreePanel getTreePanel() {
    return treePanel;
    }

    /** Exposed so PostmanImporter.runAnalyzedBatch can push per-request
     *  outcomes into the Run Results tab as they complete. */
    public RunResultsPanel getRunResultsPanel() {
        return runResultsPanel;
    }

    /** Switch the right-side tabbed pane to the Run Results tab. Called by
     *  PostmanImporter.runAnalyzedBatch on every Run Scripts kick-off so the
     *  user immediately sees pass/fail rows stream in instead of having to
     *  click over from whatever tab they were on. */
    public void showRunResultsTab() {
        if (rightTabbedPaneField == null || runResultsPanel == null) return;
        SwingUtilities.invokeLater(() -> {
            try {
                int idx = rightTabbedPaneField.indexOfComponent(runResultsPanel);
                if (idx >= 0) rightTabbedPaneField.setSelectedIndex(idx);
            } catch (Exception ignore) {}
        });
    }
    
    public JPanel getPanel() {
        return mainPanel;
    }

    /** Re-enable the Analyze button (used after the user stops Auto Run). */
    public void reenableAnalyzeButton() {
        if (authManagerPanel != null) authManagerPanel.reenableAnalyzeButton();
    }

    /**
     * Show the "Run Scripts" CTA banner above the tree. Used after Analyze
     * detects pre-request / post-response scripts but DOES NOT auto-fire them.
     * Click the button to actually fire the chain (token endpoints, etc.).
     * Click ✕ to dismiss the banner without running.
     */
    public void showRunScriptsBanner(int scriptedCount, String label, Runnable onRun) {
        if (builderPanel != null) {
            builderPanel.showRunScriptsBanner(scriptedCount, label, onRun);
            return;
        }
        if (runScriptsBanner == null) return;
        SwingUtilities.invokeLater(() -> {
            String text = "⚠ " + scriptedCount + " request(s) have pre/post-scripts. "
                    + "Click Run to execute the script chain (fetch tokens, etc.).";
            runScriptsBannerLabel.setText(text);
            runScriptsBannerButton.setText("▶ " + (label == null ? "Run Scripts" : label));
            // Replace any prior listeners so we don't accumulate.
            for (java.awt.event.ActionListener al : runScriptsBannerButton.getActionListeners()) {
                runScriptsBannerButton.removeActionListener(al);
            }
            for (java.awt.event.ActionListener al : runScriptsBannerDismiss.getActionListeners()) {
                runScriptsBannerDismiss.removeActionListener(al);
            }
            runScriptsBannerButton.addActionListener(e -> {
                hideRunScriptsBanner();
                if (onRun != null) {
                    try { onRun.run(); } catch (Exception ex) {
                        appendLog("⚠ Run Scripts failed: " + ex.getMessage());
                    }
                }
            });
            runScriptsBannerDismiss.addActionListener(e -> hideRunScriptsBanner());
            runScriptsBanner.setVisible(true);
            runScriptsBanner.revalidate();
            runScriptsBanner.repaint();
        });
    }

    /** Hide the "Run Scripts" banner. Called automatically on Run click / Dismiss. */
    public void hideRunScriptsBanner() {
        if (builderPanel != null) {
            builderPanel.hideRunScriptsBanner();
        }
        if (runScriptsBanner == null) return;
        SwingUtilities.invokeLater(() -> {
            runScriptsBanner.setVisible(false);
            runScriptsBanner.revalidate();
            runScriptsBanner.repaint();
        });
    }

    private static String displayEngineMode(burp.service.ScriptExecutor.EngineMode mode) {
        if (mode == null) return "AUTO";
        switch (mode) {
            case RHINO:
                return "FULL";
            case NASHORN:
                return "LEGACY";
            case AUTO:
            default:
                return "AUTO";
        }
    }
    
    public int getDelayMs() {
        return 0;
    }
    
    /**
     * Load and display the collection tree
     */
    public void loadCollectionTree(burp.models.CollectionTreeNode root) {
        if (treePanel != null && root != null) {
            SwingUtilities.invokeLater(() -> {
                treePanel.loadCollection(root);
            });
        }
    }
}