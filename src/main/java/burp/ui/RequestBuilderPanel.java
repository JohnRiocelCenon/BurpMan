package burp.ui;

import burp.models.ExecutedRequest;
import burp.models.PostmanCollection;
import burp.models.RequestHistory;
import burp.service.RequestExecutor;

import javax.swing.*;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class RequestBuilderPanel extends JPanel {
    
    private final RequestExecutor requestExecutor;
    private final RequestHistory requestHistory;
    
    // UI Components
    private UrlBar urlBar;
    private BodyEditorPanel bodyEditor;
    private HeadersTablePanel headersTable;
    private ParametersPanel parametersPanel;
    private AuthorizationPanel authPanel;
    private ResponsePanel responsePanel;
    private JButton sendButton;
    private JButton sendToRepeaterButton;
    private JButton saveButton;
    private JPanel sendPanel;
    private JPanel preSaveControlsPanel;
    private JPanel runScriptsBanner;
    private JLabel runScriptsBannerLabel;
    private JButton runScriptsBannerButton;
    private JButton runScriptsBannerDismiss;
    private int actionBarMode = -1;
    private String currentFolderPath = "";
    private String currentRequestName = "";
    private burp.auth.AuthManager authManagerRef;
    private java.util.function.Supplier<burp.auth.FolderAuthOverride> inheritedAuthSupplier;
    private String cachedPreScript;
    private String cachedPostScript;
    private Runnable runScriptsBannerAction;
    private Runnable postSendListener;
    private Runnable saveListener;

    /** Notified after every Send completes (post-script already applied). */
    public void setPostSendListener(Runnable r) { this.postSendListener = r; }
    /** Notified when the user clicks Save to persist the current request edits. */
    public void setSaveListener(Runnable r) { this.saveListener = r; }
    private javax.swing.text.JTextComponent preScriptArea;
    private javax.swing.text.JTextComponent postScriptArea;
    private JProgressBar progressBar;
    private JTabbedPane requestTabs;
    private JSplitPane splitPane;
    private final List<Runnable> layoutHintListeners = new java.util.concurrent.CopyOnWriteArrayList<>();
    private Boolean lastCompactHint = null;
    /** Content-driven builder height last broadcast — snap the split divider
     *  when the estimate changes by more than a threshold so a small body
     *  (Postman-style) doesn't push the response panel below the fold. */
    private int lastContentBuilderHeight = -1;
    
    // Current request state
    private ExecutedRequest lastResponse;
    /** Raw {{var}}-templated URL of the currently loaded request, so a
     *  variable edit can re-resolve and refresh the URL bar live. */
    private String currentRawUrlTemplate;
    
    public RequestBuilderPanel(RequestExecutor requestExecutor, RequestHistory requestHistory) {
        this.requestExecutor = requestExecutor;
        this.requestHistory = requestHistory;
        
        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        initializeComponents();
        setupLayout();
        setupListeners();
    }

    // ─── Live edit notifications ──────────────────────────────────────────
    /** Listeners notified on every URL / body / header / script edit so the
     *  owning panel can persist a snapshot to its edit cache live. Fixes the
     *  "body wiped on tab/focus change" class of bugs by removing the
     *  dependency on save-only-when-switching-requests cache writes. */
    private final java.util.List<Runnable> editListeners = new java.util.concurrent.CopyOnWriteArrayList<>();
    public void addEditListener(Runnable r)    { if (r != null) editListeners.add(r); }
    public void removeEditListener(Runnable r) { if (r != null) editListeners.remove(r); }
    private void fireEdit() {
        for (Runnable r : editListeners) { try { r.run(); } catch (Throwable ignore) {} }
    }
    public void addLayoutHintListener(Runnable r) {
        if (r != null) layoutHintListeners.add(r);
    }
    public void removeLayoutHintListener(Runnable r) {
        if (r != null) layoutHintListeners.remove(r);
    }
    private void fireLayoutHint() {
        for (Runnable r : layoutHintListeners) {
            try { r.run(); } catch (Throwable ignore) {}
        }
    }
    private void maybeFireLayoutHintChanged() {
        boolean compact = shouldCompactPrimaryRequestTab();
        int newContentH = estimateSelectedTabContentHeight();
        boolean compactFlipped = lastCompactHint == null || lastCompactHint.booleanValue() != compact;
        boolean heightShifted = lastContentBuilderHeight < 0
                || Math.abs(newContentH - lastContentBuilderHeight) >= 12;
        if (!compactFlipped && !heightShifted) return;
        lastCompactHint = compact;
        lastContentBuilderHeight = newContentH;
        fireLayoutHint();
    }
    private boolean shouldCompactPrimaryRequestTab() {
        if (requestTabs == null) return false;
        int idx = requestTabs.getSelectedIndex();
        if (idx < 0 || idx >= requestTabs.getTabCount()) return false;
        String title = requestTabs.getTitleAt(idx);
        // "Compact" now means the tab's *content* is small enough that the
        // builder shouldn't dominate the split — the response panel gets
        // the extra vertical space instead. Postman/Bruno UX.
        if ("Params".equals(title)) {
            int rows = parametersPanel == null ? 0 : parametersPanel.getParameters().size();
            return rows <= 5;
        }
        if ("Authorization".equals(title)) {
            return isAuthorizationTabEffectivelyEmpty() || isAuthorizationTabCompact();
        }
        if ("Headers".equals(title)) {
            int rows = headersTable == null ? 0 : headersTable.getHeaders().size();
            return rows <= 5;
        }
        if ("Body".equals(title)) {
            String body = bodyEditor == null ? null : bodyEditor.getBody();
            if (body == null || body.trim().isEmpty()) return true;
            int lines = countLines(body);
            return lines <= 8 && body.length() <= 600;
        }
        return false;
    }
    private boolean isAuthorizationTabEffectivelyEmpty() {
        if (authPanel == null) return true;
        PostmanCollection.Auth auth = authPanel.getAuth();
        if (auth == null || auth.type == null || auth.type.trim().isEmpty()) return true;
        String type = auth.type.trim().toLowerCase(java.util.Locale.ROOT);
        if ("noauth".equals(type)) return true;
        if ("bearer".equals(type)) {
            String token = authPanel.getBearerToken();
            return token == null || token.trim().isEmpty();
        }
        if ("basic".equals(type)) {
            String creds = authPanel.getBasicCredentialsBase64();
            return creds == null || creds.trim().isEmpty();
        }
        return false;
    }
    /** Auth is compact for bearer/basic/apikey (fixed short forms) — only
     *  OAuth 2.0 / other complex auths take significant vertical room. */
    private boolean isAuthorizationTabCompact() {
        if (authPanel == null) return true;
        PostmanCollection.Auth auth = authPanel.getAuth();
        if (auth == null || auth.type == null) return true;
        String type = auth.type.trim().toLowerCase(java.util.Locale.ROOT);
        return "bearer".equals(type) || "basic".equals(type) || "apikey".equals(type)
                || "noauth".equals(type) || "inherit".equals(type);
    }
    private static int countLines(String s) {
        if (s == null || s.isEmpty()) return 0;
        int lines = 1;
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) == '\n') lines++;
        return lines;
    }
    /**
     * Estimate the ideal preferred height (in px) of the currently-selected
     * inner tab's content, so the outer split divider can shrink the request
     * builder when the content is small (Postman/Bruno-style). Returns just
     * the *content-area* height (not URL bar / tab strip); the caller adds
     * chrome/padding.
     */
    private int estimateSelectedTabContentHeight() {
        if (requestTabs == null) return 100;
        int idx = requestTabs.getSelectedIndex();
        if (idx < 0 || idx >= requestTabs.getTabCount()) return 100;
        String title = requestTabs.getTitleAt(idx);
        if ("Params".equals(title)) {
            int rows = parametersPanel == null ? 0 : parametersPanel.getParameters().size();
            return estimateTableHeight(rows);
        }
        if ("Headers".equals(title)) {
            int rows = headersTable == null ? 0 : headersTable.getHeaders().size();
            return estimateTableHeight(rows);
        }
        if ("Authorization".equals(title)) {
            if (isAuthorizationTabEffectivelyEmpty()) return 90;
            if (isAuthorizationTabCompact()) return 110;
            return 220;
        }
        if ("Body".equals(title)) {
            String body = bodyEditor == null ? null : bodyEditor.getBody();
            int lines = Math.max(3, Math.min(24, countLines(body)));
            // Body-type/format toolbar (~36) + editor scroll (line*18 + 24 padding)
            return 36 + (lines * 18) + 24;
        }
        // Pre-request Script / Tests — reasonable default; user can drag divider.
        return 180;
    }
    /** Toolbar (32) + table header (26) + rows*26, min 3 visible rows, max ~12 rows. */
    private static int estimateTableHeight(int rows) {
        int visibleRows = Math.max(3, Math.min(12, rows + 1));
        return 32 + 26 + visibleRows * 26;
    }
    /**
     * Returns the ideal builder-half height in px given the total split height
     * (URL bar + tab strip + content + padding). Content-driven, so a short
     * body/params list keeps the response panel visible without scrolling.
     *
     * Never exceeds (splitHeight - responseFloor) so the response half stays
     * usable. Never below {@code minFloor} (~120) so the URL bar and tab
     * strip remain visible.
     */
    public int getContentBasedBuilderHeight(int splitHeight) {
        int urlBarH = 46;
        int tabStripH = 30;
        int paddingH = 16;
        int contentH = estimateSelectedTabContentHeight();
        int total = urlBarH + tabStripH + contentH + paddingH;
        int minFloor = 130;
        int responseFloor = Math.max(splitHeight < 620 ? 150 : 180,
                (int) Math.round(splitHeight * 0.34));
        int maxBuilder = Math.max(minFloor, splitHeight - responseFloor);
        return Math.max(minFloor, Math.min(total, maxBuilder));
    }
    public int getAdaptiveBuilderMinHeight(int splitHeight) {
        // Preserved for compatibility; delegates to content-based height.
        return getContentBasedBuilderHeight(splitHeight);
    }
    public boolean isCompactLayoutHintActive() {
        return shouldCompactPrimaryRequestTab();
    }
    /** Attach an EDT-safe DocumentListener that forwards to {@link #fireEdit}. */
    private void wireEditNotifications(javax.swing.text.JTextComponent area) {
        if (area == null) return;
        area.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e)  { fireEdit(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e)  { fireEdit(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { fireEdit(); }
        });
    }
    // ──────────────────────────────────────────────────────────────────────
    
    private void initializeComponents() {
        // URL Bar
        urlBar = new UrlBar();
        // Wire the variable resolver so {{vars}} render in orange + hover
        // shows resolved value (Postman parity).
        try {
            urlBar.setVariableResolver(requestExecutor.getVariableResolver());
        } catch (Exception ignore) {}
        // When the user edits a {{var}} via the inline popover, re-resolve
        // the URL bar and broadcast to any global refresh listeners (so the
        // Edit Variables grid / other panels also reflect the change).
        urlBar.addPropertyChangeListener("varEdited", evt -> {
            refreshFromVariables();
            try {
                if (postSendListener != null) postSendListener.run();
            } catch (Exception ignore) {}
        });

        // Request Tabs
        requestTabs = new JTabbedPane();
        requestTabs.setFont(burp.ui.UITheme.boldFont(12f));
        requestTabs.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        requestTabs.addChangeListener(e -> maybeFireLayoutHintChanged());
        headersTable = new HeadersTablePanel();
        parametersPanel = new ParametersPanel();
        bodyEditor = new BodyEditorPanel();
        try {
            bodyEditor.setVariableResolver(requestExecutor.getVariableResolver());
        } catch (Exception ignore) {}
        bodyEditor.addPropertyChangeListener("varEdited", evt -> {
            refreshFromVariables();
            try {
                if (postSendListener != null) postSendListener.run();
            } catch (Exception ignore) {}
        });
        
        requestTabs.addTab("Params", parametersPanel);
        authPanel = new AuthorizationPanel();
        authPanel.setChangeListener(() -> {
            // If the user picked "Inherit auth from parent", the Authorization
            // header is generated from the parent's override at send time and
            // editing it directly is meaningless — lock that row.
            if (headersTable != null) {
                burp.models.PostmanCollection.Auth a = authPanel.getAuth();
                headersTable.setAuthorizationLocked(a == null);
            }
            syncAuthIntoHeaders();
            maybeFireLayoutHintChanged();
        });
        requestTabs.addTab("Authorization", authPanel);
        requestTabs.addTab("Headers", headersTable);
        requestTabs.addTab("Body", bodyEditor);

        // Pre-request script tab — uses RSyntaxTextArea (JavaScript highlight)
        // when bundled, plain JTextArea otherwise.
        preScriptArea = SyntaxEditorFactory.create("javascript");
        preScriptArea.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 12));
        UndoSupport.install(preScriptArea);
        wireEditNotifications(preScriptArea);
        JPanel preScriptPanel = buildScriptTab(preScriptArea,
                "// Runs BEFORE the request is sent.\n"
              + "// Use pm.variables.set('name', value) to inject variables\n"
              + "// that {{name}} placeholders in the URL/headers/body will pick up.\n");
        requestTabs.addTab("Pre-request Script", preScriptPanel);

        // Post-response / Tests tab — same syntax highlighter.
        postScriptArea = SyntaxEditorFactory.create("javascript");
        postScriptArea.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 12));
        UndoSupport.install(postScriptArea);
        wireEditNotifications(postScriptArea);
        JPanel postScriptPanel = buildScriptTab(postScriptArea,
                "// Runs AFTER the response comes back.\n"
              + "// pm.response.code, pm.response.text(), pm.response.json()\n"
              + "// pm.environment.set('token', pm.response.json().access_token);\n");
        requestTabs.addTab("Tests", postScriptPanel);

        // Aggregate change notifications from URL / body / headers so callers
        // can persist live edits to an external cache via addEditListener().
        try { urlBar.addUrlChangeListener(this::fireEdit); } catch (Exception ignore) {}
        try { bodyEditor.addChangeListener(() -> { fireEdit(); maybeFireLayoutHintChanged(); }); } catch (Exception ignore) {}
        try { headersTable.addChangeListener(() -> { fireEdit(); maybeFireLayoutHintChanged(); }); } catch (Exception ignore) {}
        SwingUtilities.invokeLater(this::maybeFireLayoutHintChanged);
        
        // Response Panel
        responsePanel = new ResponsePanel();
        
        // Send Button — themed (blue primary)
        sendButton = burp.ui.UITheme.button("Send", burp.ui.UITheme.BtnStyle.PRIMARY);
        sendButton.setPreferredSize(new Dimension(110, 38));
        sendButton.setFont(sendButton.getFont().deriveFont(java.awt.Font.BOLD, 14f));

        // Send to Repeater
        sendToRepeaterButton = burp.ui.UITheme.button("Send to Repeater", burp.ui.UITheme.BtnStyle.GHOST);
        sendToRepeaterButton.setPreferredSize(new Dimension(150, 38));
        sendToRepeaterButton.setToolTipText("Send this request to Burp Repeater");

        // Save Button
        saveButton = burp.ui.UITheme.button("Save", burp.ui.UITheme.BtnStyle.GHOST);
        saveButton.setPreferredSize(new Dimension(80, 38));
        saveButton.setToolTipText("Save current edits to this request");
        
        // Progress Bar
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        progressBar.setForeground(new java.awt.Color(40, 160, 70));
        progressBar.setBackground(new java.awt.Color(230, 230, 230));
        progressBar.setUI(new javax.swing.plaf.basic.BasicProgressBarUI() {
            @Override protected java.awt.Color getSelectionBackground() { return java.awt.Color.WHITE; }
            @Override protected java.awt.Color getSelectionForeground() { return java.awt.Color.WHITE; }
        });
    }
    
    private void setupLayout() {
        // Top: URL Bar and Send Buttons
        JPanel topPanel = new JPanel(new BorderLayout(5, 5));
        topPanel.add(urlBar, BorderLayout.CENTER);
        
        sendPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        preSaveControlsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        preSaveControlsPanel.setOpaque(false);
        sendPanel.add(preSaveControlsPanel);
        sendPanel.add(saveButton);
        sendPanel.add(sendToRepeaterButton);
        sendPanel.add(sendButton);
        topPanel.add(sendPanel, BorderLayout.EAST);
        Runnable adaptActionBar = () -> {
            int w = Math.max(0, this.getWidth());
            if (w <= 0) w = topPanel.getWidth();
            int mode = w < 860 ? 2 : (w < 1040 ? 1 : 0);
            applyActionBarMode(mode);
        };
        addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                adaptActionBar.run();
            }
        });
        SwingUtilities.invokeLater(adaptActionBar);

        runScriptsBanner = new JPanel(new BorderLayout(8, 0));
        runScriptsBanner.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UITheme.border()),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)));
        runScriptsBanner.setBackground(UITheme.surfaceAlt());
        runScriptsBannerLabel = new JLabel();
        runScriptsBannerLabel.setForeground(UITheme.foreground());
        runScriptsBannerButton = UITheme.button("▶ Run Scripts", UITheme.BtnStyle.ACCENT);
        runScriptsBannerDismiss = UITheme.button("✕", UITheme.BtnStyle.GHOST);
        runScriptsBannerDismiss.setMargin(new Insets(2, 8, 2, 8));
        JPanel bannerActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        bannerActions.setOpaque(false);
        bannerActions.add(runScriptsBannerButton);
        bannerActions.add(runScriptsBannerDismiss);
        runScriptsBanner.add(runScriptsBannerLabel, BorderLayout.CENTER);
        runScriptsBanner.add(bannerActions, BorderLayout.EAST);
        runScriptsBanner.setVisible(false);
        runScriptsBannerButton.addActionListener(e -> {
            hideRunScriptsBanner();
            if (runScriptsBannerAction != null) {
                try { runScriptsBannerAction.run(); } catch (Exception ignore) {}
            }
        });
        runScriptsBannerDismiss.addActionListener(e -> hideRunScriptsBanner());

        JPanel northPanel = new JPanel(new BorderLayout(0, 4));
        northPanel.add(runScriptsBanner, BorderLayout.NORTH);
        northPanel.add(topPanel, BorderLayout.CENTER);
        add(northPanel, BorderLayout.NORTH);
        
        // Middle: Just the request tabs (response shown externally)
        add(requestTabs, BorderLayout.CENTER);
        
        // Bottom: Progress Bar
        add(progressBar, BorderLayout.SOUTH);
    }

    public void setPreSaveControls(JButton primary, JButton secondary) {
        if (preSaveControlsPanel == null) return;
        preSaveControlsPanel.removeAll();
        if (primary != null) preSaveControlsPanel.add(primary);
        if (secondary != null) preSaveControlsPanel.add(secondary);
        applyActionBarMode(actionBarMode < 0 ? 0 : actionBarMode);
        if (sendPanel != null) {
            sendPanel.revalidate();
            sendPanel.repaint();
        }
    }

    private void applyActionBarMode(int mode) {
        if (mode < 0) mode = 0;
        if (mode == actionBarMode) return;
        actionBarMode = mode;
        if (mode >= 2) {
            sendToRepeaterButton.setText("Rpt");
            sendToRepeaterButton.setPreferredSize(new Dimension(66, 34));
            saveButton.setText("Save");
            saveButton.setPreferredSize(new Dimension(66, 34));
            if (!"Stop".equalsIgnoreCase(sendButton.getText())) {
                sendButton.setText("Send");
            }
            sendButton.setPreferredSize(new Dimension(78, 34));
            compactPreSaveButtons(true, true);
        } else if (mode == 1) {
            sendToRepeaterButton.setText("Repeater");
            sendToRepeaterButton.setPreferredSize(new Dimension(104, 36));
            saveButton.setText("Save");
            saveButton.setPreferredSize(new Dimension(74, 36));
            if (!"Stop".equalsIgnoreCase(sendButton.getText())) {
                sendButton.setText("Send");
            }
            sendButton.setPreferredSize(new Dimension(92, 36));
            compactPreSaveButtons(true, false);
        } else {
            sendToRepeaterButton.setText("Send to Repeater");
            sendToRepeaterButton.setPreferredSize(new Dimension(150, 38));
            saveButton.setText("Save");
            saveButton.setPreferredSize(new Dimension(80, 38));
            if (!"Stop".equalsIgnoreCase(sendButton.getText())) {
                sendButton.setText("Send");
            }
            sendButton.setPreferredSize(new Dimension(110, 38));
            compactPreSaveButtons(false, false);
        }
        if (sendPanel != null) {
            sendPanel.revalidate();
            sendPanel.repaint();
        }
    }

    private void compactPreSaveButtons(boolean compact, boolean ultra) {
        if (preSaveControlsPanel == null) return;
        for (Component c : preSaveControlsPanel.getComponents()) {
            if (!(c instanceof JButton)) continue;
            JButton b = (JButton) c;
            Object origObj = b.getClientProperty("burpman.origText");
            if (origObj == null) {
                b.putClientProperty("burpman.origText", b.getText());
                origObj = b.getText();
            }
            String original = String.valueOf(origObj);
            if (!compact) {
                b.setText(original);
                b.setPreferredSize(null);
                continue;
            }
            String lower = original == null ? "" : original.toLowerCase(java.util.Locale.ROOT);
            if (lower.startsWith("edit variables")) {
                b.setText(ultra ? "Vars" : "Edit Vars");
                b.setPreferredSize(new Dimension(ultra ? 60 : 86, ultra ? 34 : 36));
            } else if (lower.startsWith("advanced")) {
                b.setText(ultra ? "Adv ▾" : "Advanced ▾");
                b.setPreferredSize(new Dimension(ultra ? 72 : 98, ultra ? 34 : 36));
            } else {
                if (ultra && original != null && original.length() > 10) {
                    b.setText(original.substring(0, 10));
                } else {
                    b.setText(original);
                }
                b.setPreferredSize(null);
            }
        }
    }

    public void showRunScriptsBanner(int scriptedCount, String label, Runnable onRun) {
        if (runScriptsBanner == null) return;
        SwingUtilities.invokeLater(() -> {
            runScriptsBannerAction = onRun;
            runScriptsBannerLabel.setText("⚠ " + scriptedCount
                    + " request(s) include scripts. Run script chain before sending.");
            runScriptsBannerButton.setText("▶ " + (label == null || label.trim().isEmpty() ? "Run Scripts" : label));
            runScriptsBanner.setVisible(true);
            runScriptsBanner.revalidate();
            runScriptsBanner.repaint();
        });
    }

    public void hideRunScriptsBanner() {
        if (runScriptsBanner == null) return;
        SwingUtilities.invokeLater(() -> {
            runScriptsBannerAction = null;
            runScriptsBanner.setVisible(false);
            runScriptsBanner.revalidate();
            runScriptsBanner.repaint();
        });
    }
    
    private boolean syncing = false;
    /** Worker thread executing the pre-request script chain (token endpoints).
     *  Tracked so the Stop button can interrupt it before the final request fires. */
    private volatile Thread preScriptThread;
    /** Set when the user clicks Stop while the pre-script is running.
     *  dispatchSendAfterPreScript checks this and skips the final request. */
    private volatile boolean sendCancelled = false;
    /** Monotonic token for pre-script send dispatch. Incrementing this
     *  invalidates stale pre-script completions so an old cancelled run
     *  cannot fire after a newer Send starts. */
    private volatile long sendDispatchGeneration = 0L;
    
    private void setupListeners() {
        sendButton.addActionListener(e -> {
            if (requestExecutor.isBusy()) {
                // Acting as Stop button — final request is in flight
                boolean cancelled = requestExecutor.cancelCurrent();
                if (cancelled && burp.service.ScriptExecutor.UI_LOG != null) {
                    try {
                        burp.service.ScriptExecutor.UI_LOG.accept(
                            "⏹ Stop requested for in-flight request.");
                    } catch (Throwable ignore) {}
                }
            } else if (preScriptThread != null && preScriptThread.isAlive()) {
                // Acting as Stop button — pre-script chain (token endpoints) is running.
                // Burp's HTTP API is BLOCKING and ignores Thread.interrupt() — we
                // can't stop the in-flight token call mid-flight, but we CAN:
                //   1. Set the cancel flag so pm.sendRequest aborts BEFORE its
                //      next call (caught by the interrupt check we added in Rhino).
                //   2. Detach the thread reference so the user's next click
                //      starts a fresh send instead of being treated as Stop.
                //   3. Reset the UI synchronously so it never feels stuck.
                sendCancelled = true;
                // Invalidate this run's pending dispatch callback now. Without
                // this, a fast "Stop then Send" can let the old cancelled pre-
                // script completion fire a stale final request.
                sendDispatchGeneration++;
                Thread doomed = preScriptThread;
                preScriptThread = null;
                try { doomed.interrupt(); } catch (Throwable ignore) {}
                if (burp.service.ScriptExecutor.UI_LOG != null) {
                    try {
                        burp.service.ScriptExecutor.UI_LOG.accept(
                            "⏹ Send cancelled by user (waiting for in-flight call to return…)");
                    } catch (Throwable ignore) {}
                }
                progressBar.setVisible(false);
                sendButton.setText("Send");
                burp.ui.UITheme.apply(sendButton, burp.ui.UITheme.BtnStyle.PRIMARY);
                // Cancel any pending URL re-resolution so we don't fight the
                // background chain for the EDT.
                if (refreshDebounceTimer != null) refreshDebounceTimer.stop();
            } else {
                handleSendRequest();
            }
        });
        sendToRepeaterButton.addActionListener(e -> handleSendToRepeater());
        saveButton.addActionListener(e -> {
            if (saveListener != null) {
                try { saveListener.run(); } catch (Exception ignore) {}
            }
        });
        
        // Bidirectional sync: URL <-> Params (Postman-style)
        urlBar.addUrlChangeListener(() -> {
            String current = urlBar.getUrl();
            if (current != null && hasTemplateVariables(current)) {
                currentRawUrlTemplate = current;
            } else if (current != null
                    && (currentRawUrlTemplate == null
                    || currentRawUrlTemplate.isEmpty()
                    || !hasTemplateVariables(currentRawUrlTemplate))) {
                // Keep raw/resolved in lock-step for literal URLs. This prevents
                // stale placeholders like the default "https://" from surviving
                // after the user types a full host/path.
                currentRawUrlTemplate = current;
            }
            if (syncing) return;
            syncing = true;
            try {
                syncParamsFromUrl();
            } finally {
                syncing = false;
            }
        });
        parametersPanel.addChangeListener(() -> {
            if (syncing) return;
            syncing = true;
            try {
                syncUrlFromParams();
            } finally {
                syncing = false;
            }
            maybeFireLayoutHintChanged();
        });
        
        // Listen to request executor events
        requestExecutor.addListener(new RequestExecutor.ExecutionListener() {
            @Override
            public void onRequestStart(ExecutedRequest request) {
                SwingUtilities.invokeLater(() -> {
                    progressBar.setVisible(true);
                    progressBar.setIndeterminate(true);
                    sendButton.setText("Stop");
                    burp.ui.UITheme.apply(sendButton, burp.ui.UITheme.BtnStyle.DANGER);
                });
            }
            
            @Override
            public void onRequestComplete(ExecutedRequest request) {
                SwingUtilities.invokeLater(() -> {
                    progressBar.setVisible(false);
                    progressBar.setIndeterminate(false);
                    sendButton.setText("Send");
                    burp.ui.UITheme.apply(sendButton, burp.ui.UITheme.BtnStyle.PRIMARY);

                    String err = request != null ? request.getError() : null;
                    boolean cancelledByUser = err != null
                        && err.toLowerCase(java.util.Locale.ROOT).contains("cancelled by user");
                    if (cancelledByUser) {
                        return;
                    }

                    lastResponse = request;
                    requestHistory.add(request);
                    responsePanel.displayResponse(request);
                    responsePanel.setSelectedTab(0);

                    // Run post-response (test) script on a worker thread. Burp
                    // forbids HTTP from the Swing EDT, and pm.sendRequest in
                    // a Postman test script would otherwise throw
                    // "Extensions should not make HTTP requests in the Swing
                    // event dispatch thread". Variable writes are still merged
                    // back into the shared VariableResolver, and the
                    // postSendListener is notified back on the EDT.
                    // Same fallback semantics as the pre-script: prefer the
                    // editor text only if non-empty, otherwise the cached
                    // cascaded script.
                    String editorPost = postScriptArea != null ? postScriptArea.getText() : null;
                    final String postScript = (editorPost != null && !editorPost.trim().isEmpty())
                        ? editorPost : cachedPostScript;
                    if (postScript == null || postScript.isEmpty()) return;
                    Thread postThread = new Thread(() -> {
                        boolean variablesChanged = false;
                        PostmanCollection.Request requestContext = null;
                        try { requestContext = getCurrentSnapshot(); } catch (Exception ignore) {}
                        // Bind a thread-local test sink so pm.test(...) results
                        // get captured and attached to the ExecutedRequest. The
                        // ResponsePanel's Tests tab reads request.getTestResults()
                        // to render pass/fail rows. Without this binding the
                        // sink is null and tests appear to never run.
                        java.util.List<burp.models.ExecutedRequest.TestResult> sink =
                                new java.util.ArrayList<>();
                        burp.service.RhinoScriptEngine.TEST_RESULTS_THREADLOCAL.set(sink);
                        try {
                            burp.parser.VariableResolver resolver = requestExecutor.getVariableResolver();
                            if (resolver != null) {
                                requestContext = burp.utils.ScriptRequestContextBuilder.fromTemplate(
                                    requestContext, resolver, request != null ? request.getUrl() : null);
                                java.util.Map<String,String> before = new java.util.HashMap<>(resolver.getVariables());
                                burp.service.ScriptExecutor.runAndApply(postScript, resolver, request, requestContext);
                                java.util.Map<String,String> after = resolver.getVariables();
                                variablesChanged = !before.equals(after);
                            } else {
                                burp.service.ScriptExecutor.runAndApply(postScript, null, request, requestContext);
                            }
                        } catch (Throwable ignore) {
                        } finally {
                            burp.service.RhinoScriptEngine.TEST_RESULTS_THREADLOCAL.remove();
                        }
                        // Attach captured test results + re-render the Tests tab.
                        if (!sink.isEmpty()) {
                            request.setTestResults(sink);
                            SwingUtilities.invokeLater(() -> {
                                try { responsePanel.displayResponse(request); } catch (Exception ignore) {}
                            });
                        }
                        final boolean changed = variablesChanged;
                        // Notify listeners ONLY when the post-script actually changed
                        // a variable — keeps {{token}} cascades fresh while leaving
                        // the edit cache alone for plain Sends so manual edits and
                        // fetched OAuth2 tokens persist.
                        if (changed && postSendListener != null) {
                            SwingUtilities.invokeLater(() -> {
                                try { postSendListener.run(); } catch (Exception ignore) {}
                            });
                        }
                    }, "BurpMan-PostScript");
                    postThread.setDaemon(true);
                    postThread.start();
                });
            }
            
            @Override
            public void onRequestError(ExecutedRequest request, Throwable error) {
                SwingUtilities.invokeLater(() -> {
                    progressBar.setVisible(false);
                    sendButton.setText("Send");
                    burp.ui.UITheme.apply(sendButton, burp.ui.UITheme.BtnStyle.PRIMARY);
                    JOptionPane.showMessageDialog(RequestBuilderPanel.this,
                            "Request failed: " + error.getMessage(),
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                });
            }
        });
    }
    
    /** Ensure the URL begins with a scheme; default to https:// when missing. */
    private static String ensureScheme(String url) {
        if (url == null) return null;
        String u = url.trim();
        if (u.isEmpty()) return u;
        // Leave intact if a scheme is already present (http, https, ws, wss, file, ftp, etc.)
        if (u.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*")) return u;
        // Don't prepend if the value still contains an unresolved {{var}} at the start.
        if (u.startsWith("{{")) return u;
        return "https://" + u;
    }

    /**
     * Resolve Postman-style path placeholders (/:country) from resolver vars.
     * Fallback convention: :country -> {{country}}.
     */
    private static String resolvePostmanPathPlaceholders(
            String url,
            burp.parser.VariableResolver resolver) {
        if (url == null || url.isEmpty() || resolver == null) return url;
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("(?<=/):([A-Za-z0-9_-]+)(?=([/?#]|$))");
        java.util.regex.Matcher m = p.matcher(url);
        StringBuffer sb = new StringBuffer();
        boolean changed = false;
        while (m.find()) {
            String key = m.group(1);
            String replacement = resolver.resolve("{{" + key + "}}");
            if (replacement == null || replacement.equals("{{" + key + "}}")) {
                replacement = m.group(0);
            } else {
                changed = true;
            }
            m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        return changed ? sb.toString() : url;
    }

    /**
     * Whether this request should carry a Content-Length header. Always true for
     * methods that semantically send a body (POST/PUT/PATCH/DELETE) — even when
     * the body is empty (servers may reject `Content-Length: 0` being absent).
     * For GET/HEAD/OPTIONS we still emit one if there's an actual body to send.
     */
    private static boolean requiresContentLength(String method, int bodyLen) {
        if (method == null) return bodyLen > 0;
        String m = method.toUpperCase();
        switch (m) {
            case "POST":
            case "PUT":
            case "PATCH":
            case "DELETE":
                return true;
            default:
                return bodyLen > 0;
        }
    }
    
    private void handleSendRequest() {
        final String method = urlBar.getMethod();
        burp.parser.VariableResolver resolver = null;
        try { resolver = requestExecutor.getVariableResolver(); } catch (Exception ignore) {}
        final String url = resolvePostmanPathPlaceholders(ensureScheme(urlBar.getUrl()), resolver);
        if (url != null && !url.equals(urlBar.getUrl())) {
            String raw = currentRawUrlTemplate;
            if (raw == null || raw.isEmpty()) raw = urlBar.getUrl();
            if (hasScheme(url) && raw != null && !raw.isEmpty() && !hasScheme(raw) && !raw.startsWith("{{")) {
                raw = "https://" + raw;
            }
            applyUrlWithTemplate(url, raw);
        }

        if (url == null || url.isEmpty()) {
            JOptionPane.showMessageDialog(this, "URL is required", "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (!confirmNoUnresolvedVariables(url, headersTable.getHeaders(), bodyEditor.getBody())) return;

        // Snapshot the pre-request script on the EDT (UI read), then run it
        // on a worker thread. Burp forbids HTTP calls from the Swing event-
        // dispatch thread, and pm.sendRequest inside a Postman pre-request
        // script (token chains, CPS-auth, etc.) goes through Burp's HTTP API.
        // After the script finishes (off-EDT), we bounce back to the EDT to
        // read the final headers/body and let RequestExecutor.executeAsync
        // dispatch the actual request on its own worker thread.
        // Prefer the live editor text if present, but fall back to the
        // cached cascaded script when the editor is empty (the editor is
        // empty by design until the user opens the Pre-request Script tab).
        String editorText = preScriptArea != null ? preScriptArea.getText() : null;
        final String preScript = (editorText != null && !editorText.trim().isEmpty())
            ? editorText : cachedPreScript;

        // Build a Request mirror of the current UI so the script can call
        // pm.request.headers.add(...) / pm.request.url etc. and we can merge
        // any added headers back into the headers table before dispatching.
        // Without this, Postman scripts that inject Authorization /
        // Subscription-Key / Cookie via pm.request.headers.add lose those
        // headers and the final endpoint goes out unauthenticated (403).
        final PostmanCollection.Request scriptRequest = new PostmanCollection.Request();
        scriptRequest.method = method;
        // url is typed as Object (string OR Url-object form). Plain string
        // matches what RhinoScriptEngine.RequestHost.getUrl() expects.
        scriptRequest.url = url;
        scriptRequest.header = new java.util.ArrayList<>();
        // Snapshot of the pre-script header values keyed by lowercased name.
        // Used by dispatchSendAfterPreScript to distinguish "script actually
        // modified this header" from "header was just present in the initial
        // mirror". Without this snapshot the merge loop treated every mirror
        // header as script-modified and clobbered our ensureContentTypeForMode
        // override — e.g. a collection ships urlencoded body + Content-Type:
        // application/json, we correctly force application/x-www-form-urlencoded,
        // then the merge loop restored the wrong Content-Type from the mirror
        // and Microsoft's /oauth2/token returned AADSTS900410.
        final java.util.LinkedHashMap<String, String> preScriptHeaderSnapshot =
            new java.util.LinkedHashMap<>();
        for (PostmanCollection.Header h : headersTable.getHeaders()) {
            if (h == null) continue;
            PostmanCollection.Header c = new PostmanCollection.Header();
            c.key = h.key; c.value = h.value;
            scriptRequest.header.add(c);
            if (h.key != null) {
                preScriptHeaderSnapshot.put(h.key.toLowerCase().trim(),
                    h.value == null ? "" : h.value);
            }
        }

        // Reflect "we're working" so the user can see the chain is running
        // (token endpoints can take a couple of seconds each).
        // Reset the cancel flag from any prior interrupted send.
        final long generation = ++sendDispatchGeneration;
        sendCancelled = false;
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);
        sendButton.setText("Stop");
        burp.ui.UITheme.apply(sendButton, burp.ui.UITheme.BtnStyle.DANGER);

        Thread preThread = new Thread(() -> {
            try {
                if (preScript != null && !preScript.isEmpty()) {
                    burp.parser.VariableResolver scriptResolver = requestExecutor.getVariableResolver();
                    if (scriptResolver != null) {
                        try {
                            burp.service.ScriptExecutor.runAndApply(
                                preScript, scriptResolver, null, scriptRequest);
                        } catch (Throwable ignore) { /* script failures shouldn't block send */ }
                    }
                }
            } finally {
                preScriptThread = null;
                SwingUtilities.invokeLater(() ->
                    dispatchSendAfterPreScript(method, url, scriptRequest, generation, preScriptHeaderSnapshot));
            }
        }, "BurpMan-PreScript");
        preThread.setDaemon(true);
        preScriptThread = preThread;
        preThread.start();
    }

    /**
     * Runs on the EDT after the pre-request script has finished on a worker
     * thread. Reads the latest headers/body from the UI (now reflecting any
     * variables the pre-script wrote) and hands the request off to
     * RequestExecutor.executeAsync, which dispatches on its own worker.
     *
     * @param scriptRequest the Request mirror passed to the pre-script; any
     *                      headers it added via {@code pm.request.headers.add}
     *                      are merged into the outgoing header set.
     */
    private void dispatchSendAfterPreScript(String method, String url,
                                            PostmanCollection.Request scriptRequest,
                                            long generation,
                                            java.util.Map<String, String> preScriptHeaderSnapshot) {
        // Stale completion from an older cancelled run — ignore.
        if (generation != sendDispatchGeneration) {
            return;
        }
        // Honor a Stop click that arrived while the pre-script was running.
        // Skip the final HTTP request entirely.
        if (sendCancelled) {
            sendCancelled = false;
            progressBar.setVisible(false);
            sendButton.setText("Send");
            burp.ui.UITheme.apply(sendButton, burp.ui.UITheme.BtnStyle.PRIMARY);
            return;
        }
        try {
            // Strip any prior script-managed rows from the headers tab before
            // reading user headers, so getHeaders() reflects user intent only.
            try { headersTable.clearScriptManagedHeaders(); } catch (Throwable ignore) {}

            List<PostmanCollection.Header> headers = applyAuthToHeaders(headersTable.getHeaders());
            ensureContentTypeForMode(headers);

            // Merge headers added by the pre-script (e.g. Authorization,
            // Ocp-Apim-Subscription-Key, Cps-Authorization, Cookie). The
            // script-mirror is the source of truth: its set replaces ours
            // (case-insensitive), since real Postman lets the script override
            // user-defined headers. We also collect them separately so we
            // can surface them in the Headers tab as read-only rows (like
            // Postman's "Hidden Headers" / Auto-generated section).
            //
            // IMPORTANT: only treat a header as "script-modified" if its
            // value CHANGED vs the pre-script snapshot. The mirror was seeded
            // with a copy of the UI headers, so unchanged entries would
            // otherwise clobber ensureContentTypeForMode's authoritative
            // rewrite — e.g. collection ships urlencoded body with a stale
            // Content-Type: application/json, we correctly force
            // application/x-www-form-urlencoded, then the merge loop
            // restored the wrong value from the mirror and Microsoft's
            // /oauth2/token returned AADSTS900410 invalid_request.
            java.util.List<PostmanCollection.Header> scriptInjected = new java.util.ArrayList<>();
            if (scriptRequest != null && scriptRequest.header != null) {
                java.util.LinkedHashMap<String, PostmanCollection.Header> baseUser =
                    new java.util.LinkedHashMap<>();
                for (PostmanCollection.Header h : headers) {
                    if (h == null || h.key == null) continue;
                    baseUser.put(h.key.toLowerCase().trim(), h);
                }
                int added = 0;
                for (PostmanCollection.Header sh : scriptRequest.header) {
                    if (sh == null || sh.key == null || sh.key.isEmpty()) continue;
                    String lk = sh.key.toLowerCase().trim();
                    String snapshotValue = preScriptHeaderSnapshot == null
                        ? null : preScriptHeaderSnapshot.get(lk);
                    boolean scriptTouched = snapshotValue == null
                        || !java.util.Objects.equals(snapshotValue, sh.value);
                    if (!scriptTouched) {
                        // Header was in the initial mirror and the script
                        // didn't change its value — don't overwrite our
                        // resolved/authoritative version.
                        continue;
                    }
                    PostmanCollection.Header existing = baseUser.get(lk);
                    if (existing == null) {
                        PostmanCollection.Header c = new PostmanCollection.Header();
                        c.key = sh.key; c.value = sh.value == null ? "" : sh.value;
                        headers.add(c);
                        baseUser.put(lk, c);
                        scriptInjected.add(c);
                        added++;
                    } else {
                        // Script-added value wins (matches Postman behavior).
                        if (!java.util.Objects.equals(existing.value, sh.value)) {
                            existing.value = sh.value == null ? "" : sh.value;
                            scriptInjected.add(existing);
                            added++;
                        }
                        // If the value matched, the existing user row is
                        // already representing this header — don't duplicate
                        // it as a script-managed row in the UI.
                    }
                }
                if (added > 0) {
                    try {
                        if (burp.service.ScriptExecutor.UI_LOG != null) {
                            burp.service.ScriptExecutor.UI_LOG.accept(
                                "🧷 Merged " + added + " script-added header(s) into outgoing request.");
                        }
                    } catch (Throwable ignore) {}
                }
                // Reflect script-injected headers in the Headers tab as
                // read-only rows so the user can SEE what was actually sent.
                try { headersTable.setScriptManagedHeaders(scriptInjected); } catch (Throwable ignore) {}
            }

            String body = bodyEditor.getBody();

            // If the user is in form-data (multipart) mode, build a real multipart body and
            // overwrite the Content-Type with a boundary. Without this we used to send the
            // editor's "k=v&k=v" text under a Content-Type: multipart/form-data header — invalid.
            if (BodyEditorPanel.MODE_FORM_DATA.equalsIgnoreCase(bodyEditor.getMode())) {
                String boundary = "----BurpManBoundary" + Long.toHexString(System.nanoTime());
                byte[] multipartBody = buildMultipartFromKvTextBytes(
                    body, boundary, requestExecutor.getVariableResolver());
                headers.removeIf(h -> h != null && h.key != null && "content-type".equalsIgnoreCase(h.key.trim()));
                PostmanCollection.Header ct = new PostmanCollection.Header();
                ct.key = "Content-Type";
                ct.value = "multipart/form-data; boundary=" + boundary;
                headers.add(ct);
                requestExecutor.executeAsync(method, url, headers, multipartBody);
                return;
            }

            // Send request asynchronously (RequestExecutor spawns its own worker thread)
            requestExecutor.executeAsync(method, url, headers, body);
        } catch (Throwable t) {
            progressBar.setVisible(false);
            sendButton.setText("Send");
            burp.ui.UITheme.apply(sendButton, burp.ui.UITheme.BtnStyle.PRIMARY);
            JOptionPane.showMessageDialog(RequestBuilderPanel.this,
                    "Send failed: " + t.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static byte[] buildMultipartFromKvTextBytes(String kvText, String boundary,
                                                         burp.parser.VariableResolver resolver) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (kvText != null && !kvText.isEmpty()) {
            for (String pair : kvText.split("&")) {
                if (pair == null || pair.isEmpty()) continue;
                int eq = pair.indexOf('=');
                String k = eq >= 0 ? pair.substring(0, eq) : pair;
                String v = eq >= 0 ? pair.substring(eq + 1) : "";
                try {
                    k = java.net.URLDecoder.decode(k, "UTF-8");
                    v = java.net.URLDecoder.decode(v, "UTF-8");
                } catch (Exception ignore) { /* keep as-is */ }
                if (resolver != null) {
                    if (k != null) k = resolver.resolve(k);
                    if (v != null) v = resolver.resolve(v);
                }
                boolean disabled = k != null && k.startsWith("~");
                if (disabled && k != null) {
                    k = k.substring(1);
                }
                if (k == null || k.trim().isEmpty()) continue;
                if (disabled) continue;
                k = k.trim();

                writeMultipartAscii(out, "--" + boundary + "\r\n");
                if (v != null && v.startsWith("@")) {
                    String filePath = v.substring(1).trim();
                    if ((filePath.startsWith("\"") && filePath.endsWith("\""))
                            || (filePath.startsWith("'") && filePath.endsWith("'"))) {
                        filePath = filePath.substring(1, filePath.length() - 1);
                    }
                    if (filePath.isEmpty()) {
                        throw new Exception("Missing file path for multipart field '" + k + "'");
                    }
                    Path p = Path.of(filePath);
                    if (!Files.exists(p) || !Files.isRegularFile(p)) {
                        throw new Exception("File not found for multipart field '" + k + "': " + filePath);
                    }
                    String filename = new File(filePath).getName();
                    String mime = Files.probeContentType(p);
                    if (mime == null || mime.trim().isEmpty()) mime = "application/octet-stream";
                    writeMultipartAscii(out, "Content-Disposition: form-data; name=\""
                        + k.replace("\"", "") + "\"; filename=\"" + filename.replace("\"", "") + "\"\r\n");
                    writeMultipartAscii(out, "Content-Type: " + mime + "\r\n\r\n");
                    out.write(Files.readAllBytes(p));
                    writeMultipartAscii(out, "\r\n");
                } else {
                    writeMultipartAscii(out, "Content-Disposition: form-data; name=\""
                        + k.replace("\"", "") + "\"\r\n\r\n");
                    writeMultipartAscii(out, v == null ? "" : v);
                    writeMultipartAscii(out, "\r\n");
                }
            }
        }
        writeMultipartAscii(out, "--" + boundary + "--\r\n");
        return out.toByteArray();
    }

    private static void writeMultipartAscii(ByteArrayOutputStream out, String text) throws Exception {
        out.write((text == null ? "" : text).getBytes(StandardCharsets.UTF_8));
    }

    /** Build a script tab: monospaced editor + scrollpane + placeholder hint label. */
    private JPanel buildScriptTab(javax.swing.text.JTextComponent area, String placeholderHint) {
        JPanel p = new JPanel(new BorderLayout());
        if (placeholderHint != null) {
            // Use a read-only multi-line text area instead of a JLabel — Burp's
            // current LookAndFeel sometimes strips JLabel HTML and renders the
            // raw <html>…</html> markup as plain text.
            javax.swing.JTextArea hint = new javax.swing.JTextArea(placeholderHint.trim());
            hint.setEditable(false);
            hint.setOpaque(false);
            hint.setFocusable(false);
            hint.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, java.awt.Color.LIGHT_GRAY),
                BorderFactory.createEmptyBorder(4, 6, 4, 6)));
            hint.setForeground(new java.awt.Color(0x66, 0x66, 0x66));
            hint.setFont(hint.getFont().deriveFont(11f));
            p.add(hint, BorderLayout.NORTH);
        }
        javax.swing.JScrollPane sp = SyntaxEditorFactory.wrap(area);
        sp.setVerticalScrollBarPolicy(javax.swing.ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        p.add(sp, BorderLayout.CENTER);

        // Toolbar: Analyze button — runs static analysis on the current script
        // text and shows the results in a non-modal dialog. No code is executed.
        javax.swing.JPanel toolbar = new javax.swing.JPanel(
                new java.awt.FlowLayout(java.awt.FlowLayout.RIGHT, 4, 2));
        toolbar.setOpaque(false);
        javax.swing.JButton analyzeBtn = new javax.swing.JButton("🔎 Analyze");
        analyzeBtn.setFocusPainted(false);
        analyzeBtn.setToolTipText(
            "Static analysis of this script: variables read/written, HTTP calls fired, " +
            "headers added, ES features used, and which engine (basic/full) it needs.");
        analyzeBtn.addActionListener(e -> showAnalysis(area.getText()));
        toolbar.add(analyzeBtn);
        p.add(toolbar, BorderLayout.SOUTH);
        return p;
    }

    private void showAnalysis(String script) {
        burp.service.ScriptAnalyzer.Result res = burp.service.ScriptAnalyzer.analyze(script);
        javax.swing.JTextArea out = new javax.swing.JTextArea(res.render(), 22, 70);
        out.setEditable(false);
        out.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 12));
        javax.swing.JScrollPane sp = new javax.swing.JScrollPane(out);
        java.awt.Window owner = javax.swing.SwingUtilities.getWindowAncestor(this);
        javax.swing.JDialog d = new javax.swing.JDialog(
                owner, "Script Analysis", java.awt.Dialog.ModalityType.MODELESS);
        d.getContentPane().add(sp);
        d.pack();
        d.setLocationRelativeTo(owner);
        d.setVisible(true);
    }
    
    private void ensureContentTypeForMode(List<PostmanCollection.Header> headers) {
        String mode = bodyEditor.getMode();
        if (mode == null) return;
        String want = null;
        boolean authoritative = false;
        if (BodyEditorPanel.MODE_GRAPHQL.equalsIgnoreCase(mode) || BodyEditorPanel.MODE_JSON.equalsIgnoreCase(mode)) {
            want = "application/json";
        } else if (BodyEditorPanel.MODE_XML.equalsIgnoreCase(mode)) {
            want = "application/xml";
        } else if (BodyEditorPanel.MODE_URLENC.equalsIgnoreCase(mode)) {
            want = "application/x-www-form-urlencoded";
            // urlencoded bodies MUST use application/x-www-form-urlencoded
            // (RFC 1866 / WHATWG URL). Postman itself overrides any
            // Content-Type on urlencoded bodies. Without this, a collection
            // that ships with Content-Type: application/json on a urlencoded
            // request (e.g. the CIAM APIM Token request) sends
            //   Content-Type: application/json
            //   Body: grant_type=client_credentials&client_id=...
            // and the auth server returns AADSTS900410 / invalid_request,
            // cascading through every downstream token-exchange step.
            authoritative = true;
        }
        if (want == null) return;
        if (authoritative) {
            headers.removeIf(h -> h != null && h.key != null
                    && "content-type".equalsIgnoreCase(h.key.trim()));
        } else {
            for (PostmanCollection.Header h : headers) {
                // Skip disabled headers — a commented-out ~Content-Type must
                // not veto body-derived injection (the wire wouldn't carry it).
                if (h == null || h.disabled) continue;
                if (h.key != null && "content-type".equalsIgnoreCase(h.key.trim())) return;
            }
        }
        PostmanCollection.Header h = new PostmanCollection.Header();
        h.key = "Content-Type";
        h.value = want;
        headers.add(h);
    }
    
    /** Returns true if the user wants to proceed (no unresolved vars, or chose Yes). */
    private boolean confirmNoUnresolvedVariables(String url, java.util.List<PostmanCollection.Header> hdrSnapshot, String bodyText) {
        java.util.LinkedHashSet<String> unresolvedNames = new java.util.LinkedHashSet<>();
        java.util.regex.Pattern PAT = java.util.regex.Pattern.compile("\\{\\{([^}]+)\\}\\}");
        java.util.regex.Pattern PATH_PAT = java.util.regex.Pattern.compile("(?<=/):([A-Za-z0-9_-]+)(?=([/?#]|$))");
        burp.parser.VariableResolver resolver = null;
        try { resolver = requestExecutor.getVariableResolver(); } catch (Exception ignore) {}
        try {
            String ru = resolver != null && url != null ? resolver.resolve(url) : url;
            ru = resolvePostmanPathPlaceholders(ru, resolver);
            if (ru != null) {
                java.util.regex.Matcher m = PAT.matcher(ru);
                while (m.find()) unresolvedNames.add(m.group(1).trim());
                java.util.regex.Matcher pm = PATH_PAT.matcher(ru);
                while (pm.find()) unresolvedNames.add(pm.group(1).trim());
            }
            if (hdrSnapshot != null) {
                for (PostmanCollection.Header h : hdrSnapshot) {
                    String v = h == null || h.value == null ? "" : (resolver != null ? resolver.resolve(h.value) : h.value);
                    java.util.regex.Matcher mm = PAT.matcher(v);
                    while (mm.find()) unresolvedNames.add(mm.group(1).trim());
                }
            }
            if (bodyText != null && !bodyText.isEmpty()) {
                String br = resolver != null ? resolver.resolve(bodyText) : bodyText;
                java.util.regex.Matcher mm = PAT.matcher(br);
                while (mm.find()) unresolvedNames.add(mm.group(1).trim());
            }
        } catch (Exception ignore) {}
        if (unresolvedNames.isEmpty()) return true;

        // Use the rich VariableResolutionDialog (same modal shown during import).
        burp.models.VariableAnalysis analysis =
                new burp.models.VariableAnalysis(unresolvedNames, 1, 1);
        burp.utils.VariableDetector detector = new burp.utils.VariableDetector(resolver);
        VariableResolutionDialog dlg = new VariableResolutionDialog(this, analysis, detector);
        boolean ok = dlg.showDialog();
        if (!ok) return false;
        switch (dlg.getChoice()) {
            case MANUAL_ENTRY:
                if (resolver != null && dlg.getManualVariables() != null) {
                    for (java.util.Map.Entry<String,String> e : dlg.getManualVariables().entrySet()) {
                        resolver.addCustomVariable(e.getKey(), e.getValue());
                    }
                }
                return true;
            case UPLOAD_ENVIRONMENT:
                if (resolver != null && dlg.getSelectedEnvironmentFile() != null) {
                    try {
                        burp.models.PostmanEnvironment env =
                                new burp.parser.PostmanParser().parseEnvironment(dlg.getSelectedEnvironmentFile());
                        if (env != null) resolver.addEnvironmentVariables(env);
                    } catch (Exception ignore) {}
                }
                return true;
            case IGNORE_CONTINUE:
                return true;
            case SKIP_VARIABLE_REQUESTS:
            case CANCEL:
            default:
                return false;
        }
    }
    
    private void handleSendToRepeater() {
        String method = urlBar.getMethod();
        burp.parser.VariableResolver resolver = null;
        try { resolver = requestExecutor.getVariableResolver(); } catch (Exception ignore) {}
        String url = resolvePostmanPathPlaceholders(ensureScheme(urlBar.getUrl()), resolver);
        if (url != null && !url.equals(urlBar.getUrl())) {
            String raw = currentRawUrlTemplate;
            if (raw == null || raw.isEmpty()) raw = urlBar.getUrl();
            if (hasScheme(url) && raw != null && !raw.isEmpty() && !hasScheme(raw) && !raw.startsWith("{{")) {
                raw = "https://" + raw;
            }
            applyUrlWithTemplate(url, raw);
        }
        
        if (url == null || url.isEmpty()) {
            JOptionPane.showMessageDialog(this, "URL is required", "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (!confirmNoUnresolvedVariables(url, headersTable.getHeaders(), bodyEditor.getBody())) return;
        
        List<PostmanCollection.Header> headers = applyAuthToHeaders(headersTable.getHeaders());
        ensureContentTypeForMode(headers);
        boolean isFormData = BodyEditorPanel.MODE_FORM_DATA.equalsIgnoreCase(bodyEditor.getMode());
        String body = bodyEditor.getBody();

        // Resolve any remaining {{var}} the user may have typed manually
        // (the loaded URL is already resolved, but typed-over content might
        // contain templates).
        resolver = resolver == null ? requestExecutor.getVariableResolver() : resolver;
        if (resolver != null) {
            url = resolvePostmanPathPlaceholders(resolver.resolve(url), resolver);
            if (body != null && !isFormData) body = resolver.resolve(body);
            List<PostmanCollection.Header> resolved = new java.util.ArrayList<>();
            for (PostmanCollection.Header h : headers) {
                PostmanCollection.Header nh = new PostmanCollection.Header();
                nh.key = h.key == null ? null : resolver.resolve(h.key);
                nh.value = h.value == null ? null : resolver.resolve(h.value);
                resolved.add(nh);
            }
            headers = resolved;
        }
        
        try {
            // Resolve variables if resolver available
            String resolvedUrl = url;
            byte[] bodyBytes;
            if (isFormData) {
                String boundary = "----BurpManBoundary" + Long.toHexString(System.nanoTime());
                headers.removeIf(h -> h != null && h.key != null && "content-type".equalsIgnoreCase(h.key.trim()));
                PostmanCollection.Header ct = new PostmanCollection.Header();
                ct.key = "Content-Type";
                ct.value = "multipart/form-data; boundary=" + boundary;
                headers.add(ct);
                bodyBytes = buildMultipartFromKvTextBytes(body, boundary, resolver);
            } else {
                String resolvedBody = body;
                bodyBytes = (resolvedBody != null && !resolvedBody.isEmpty())
                    ? resolvedBody.getBytes(java.nio.charset.StandardCharsets.UTF_8)
                    : new byte[0];
            }

            // Parse URL
            java.net.URL parsedUrl = new java.net.URL(resolvedUrl);
            String host = parsedUrl.getHost();
            int port = parsedUrl.getPort();
            boolean isHttps = "https".equalsIgnoreCase(parsedUrl.getProtocol());
            if (port == -1) port = isHttps ? 443 : 80;
            
            String path = parsedUrl.getPath();
            if (parsedUrl.getQuery() != null) {
                path += "?" + parsedUrl.getQuery();
            }
            if (path.isEmpty()) path = "/";
            // Strip whitespace from the request line — see RequestExecutor
            // for rationale. Spaces in env values (e.g. "Washington, DC")
            // are valid in the Headers/Params tabs, but the wire request
            // line cannot contain literal whitespace.
            if (path.indexOf(' ') >= 0 || path.indexOf('\t') >= 0
                    || path.indexOf('\r') >= 0 || path.indexOf('\n') >= 0) {
                path = path.replace(" ", "")
                           .replace("\t", "")
                           .replace("\r", "")
                           .replace("\n", "");
            }
            
            // Build raw HTTP request
            StringBuilder rawRequest = new StringBuilder();
            rawRequest.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
            rawRequest.append("Host: ").append(host).append("\r\n");
            
            boolean hasContentLength = false;
            for (PostmanCollection.Header h : headers) {
                if (h.key != null && h.value != null) {
                    if ("host".equalsIgnoreCase(h.key)) continue;
                    if ("content-length".equalsIgnoreCase(h.key)) hasContentLength = true;
                    rawRequest.append(h.key).append(": ").append(h.value).append("\r\n");
                }
            }
            
            // Add Content-Length for any method that typically carries a body
            // (POST/PUT/PATCH/DELETE). Many servers reject these without an
            // explicit Content-Length header — even when the body is empty.
            if (!hasContentLength && requiresContentLength(method, bodyBytes.length)) {
                rawRequest.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
            }
            rawRequest.append("\r\n");
            
            byte[] headerBytes = rawRequest.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] fullRequest = new byte[headerBytes.length + bodyBytes.length];
            System.arraycopy(headerBytes, 0, fullRequest, 0, headerBytes.length);
            System.arraycopy(bodyBytes, 0, fullRequest, headerBytes.length, bodyBytes.length);
            
            // Build Montoya HttpRequest
            burp.api.montoya.http.HttpService httpService = 
                burp.api.montoya.http.HttpService.httpService(host, port, isHttps);
            
            burp.api.montoya.http.message.requests.HttpRequest httpRequest = 
                burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                    httpService,
                    burp.api.montoya.core.ByteArray.byteArray(fullRequest)
                );
            
            // Send to Repeater — METHOD - FOLDER - NAME (folder/name omitted if unknown)
            String tabName = method;
            if (currentFolderPath != null && !currentFolderPath.isEmpty()) {
                tabName += " - " + currentFolderPath;
            }
            if (currentRequestName != null && !currentRequestName.isEmpty()) {
                tabName += " - " + currentRequestName;
            }
            requestExecutor.getApi().repeater().sendToRepeater(httpRequest, tabName);
            
            JOptionPane.showMessageDialog(this, "Request sent to Repeater!", "Success", JOptionPane.INFORMATION_MESSAGE);
            
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, 
                "Failed to send to Repeater: " + ex.getMessage(), 
                "Error", 
                JOptionPane.ERROR_MESSAGE);
            ex.printStackTrace();
        }
    }
    
    /** Inject AuthManager so the Authorization tab can auto-fetch the current token. */
    public void setAuthManager(burp.auth.AuthManager am) {
        this.authManagerRef = am;
        if (authPanel != null) authPanel.setAuthManager(am);
    }

    /**
     * Push a freshly-fetched bearer token into the Authorization tab, overriding
     * whatever was loaded from the request. Also rewrites the visible
     * Authorization header so the Headers tab matches what will be sent.
     */
    /**
     * Push a freshly-fetched token down to the Authorization tab. If the user
     * has the tab set to "Inherit" we leave it as-is so the OAuth2/Bearer
     * inheritance from the parent collection/folder still wins — the supplier
     * picks up the new AuthManager token automatically. Only when the user
     * explicitly chose Bearer do we update the Bearer field directly.
     */
    public void applyBearerToken(String token) {
        if (authPanel != null) {
            burp.models.PostmanCollection.Auth a = authPanel.getAuth();
            if (a != null && "bearer".equalsIgnoreCase(a.type)) {
                authPanel.setBearerToken(token);
            }
        }
        // Re-render the Authorization header with the latest auth state. When
        // the tab is Inherit, applyAuthToHeaders calls inheritedAuthSupplier
        // which will read the freshly-set AuthManager token.
        syncAuthIntoHeaders();
    }
    
    /** Apply the Authorization-tab selection on top of the user-entered headers. */
    private List<PostmanCollection.Header> applyAuthToHeaders(List<PostmanCollection.Header> baseHeaders) {
        if (authPanel == null) return baseHeaders;
        PostmanCollection.Auth a = authPanel.getAuth();
        // Strip any existing Authorization header first; we'll re-add based on effective auth.
        List<PostmanCollection.Header> out = new java.util.ArrayList<>();
        for (PostmanCollection.Header h : baseHeaders) {
            if (h.key != null && "authorization".equalsIgnoreCase(h.key.trim())) continue;
            out.add(h);
        }
        // Inherit: resolve from parent folder/collection
        if (a == null) {
            // Skip inherited auth on URLs that look like token endpoints (so we
            // don't send Bearer ... to the very endpoint we use to GET a bearer).
            String urlLower = urlBar == null || urlBar.getUrl() == null ? "" : urlBar.getUrl().toLowerCase();
            boolean isTokenEndpoint =
                    urlLower.contains("/oauth2/token")
                    || urlLower.contains("/oauth/token")
                    || urlLower.contains("/connect/token")
                    || urlLower.endsWith("/token")
                    || urlLower.contains("login.microsoftonline.com")
                    || urlLower.contains("login.windows.net");
            if (isTokenEndpoint) return out;
            burp.auth.FolderAuthOverride ov = inheritedAuthSupplier == null ? null : inheritedAuthSupplier.get();
            if (ov == null || ov.type == null || ov.type == burp.auth.FolderAuthOverride.Type.INHERIT
                    || ov.type == burp.auth.FolderAuthOverride.Type.NO_AUTH) {
                return out; // no auth → leave stripped
            }
            if (ov.type == burp.auth.FolderAuthOverride.Type.BEARER
                    || ov.type == burp.auth.FolderAuthOverride.Type.OAUTH2
                    || ov.type == burp.auth.FolderAuthOverride.Type.JWT_BEARER) {
                String tok = ov.get("token");
                try {
                    burp.parser.VariableResolver r = requestExecutor.getVariableResolver();
                    if (r != null && tok != null) tok = r.resolve(tok);
                } catch (Exception ignore) {}
                if ((tok == null || tok.isEmpty() || tok.contains("{{"))
                        && authManagerRef != null && authManagerRef.hasAccessToken()) {
                    tok = authManagerRef.getAccessToken();
                }
                if (tok != null && !tok.isEmpty() && !tok.contains("{{")) {
                    PostmanCollection.Header h = new PostmanCollection.Header();
                    h.key = "Authorization"; h.value = "Bearer " + tok;
                    out.add(h);
                }
            } else if (ov.type == burp.auth.FolderAuthOverride.Type.BASIC) {
                String u = ov.get("username"); String p = ov.get("password");
                if (u != null) {
                    String creds = java.util.Base64.getEncoder().encodeToString(
                            ((u == null ? "" : u) + ":" + (p == null ? "" : p)).getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    PostmanCollection.Header h = new PostmanCollection.Header();
                    h.key = "Authorization"; h.value = "Basic " + creds;
                    out.add(h);
                }
            } else if (ov.type == burp.auth.FolderAuthOverride.Type.APIKEY) {
                String key = ov.get("key");
                String value = ov.get("value");
                String addTo = ov.get("addTo");
                if (key != null && !key.isEmpty() && !"query".equalsIgnoreCase(addTo)) {
                    final String keyF = key;
                    out.removeIf(h -> h.key != null && h.key.equalsIgnoreCase(keyF));
                    PostmanCollection.Header h = new PostmanCollection.Header();
                    h.key = key;
                    h.value = value == null ? "" : value;
                    out.add(h);
                }
            }
            return out;
        }
        if ("bearer".equalsIgnoreCase(a.type)
                || "oauth2".equalsIgnoreCase(a.type)
                || "jwt".equalsIgnoreCase(a.type)) {
            String tok = null;
            if ("oauth2".equalsIgnoreCase(a.type)
                    && authManagerRef != null && authManagerRef.hasAccessToken()) {
                tok = authManagerRef.getAccessToken();
            }
            if ("bearer".equalsIgnoreCase(a.type)) {
                tok = authPanel.getBearerToken();
            }
            if (tok == null || tok.isEmpty()) {
                tok = extractAuthValue(a.bearer, "token");
            }
            if (tok == null || tok.isEmpty()) {
                tok = extractAuthValue(a.oauth2, "accessToken");
            }
            if (tok == null || tok.isEmpty()) {
                String tokenName = extractAuthValue(a.oauth2, "tokenName");
                if (tokenName != null && !tokenName.isEmpty()) {
                    tok = tokenName.contains("{{") ? tokenName : "{{" + tokenName + "}}";
                }
            }
            if ((tok == null || tok.isEmpty()) && authManagerRef != null && authManagerRef.hasAccessToken()) {
                tok = authManagerRef.getAccessToken();
            }
            // Resolve any {{vars}} (e.g. {{token}}) before emitting the header.
            try {
                burp.parser.VariableResolver resolver = requestExecutor.getVariableResolver();
                if (resolver != null && tok != null) tok = resolver.resolve(tok);
            } catch (Exception ignore) {}
            if ((tok == null || tok.isEmpty() || tok.contains("{{"))
                    && authManagerRef != null && authManagerRef.hasAccessToken()) {
                tok = authManagerRef.getAccessToken();
            }
            if (tok != null && !tok.isEmpty() && !tok.contains("{{")) {
                PostmanCollection.Header h = new PostmanCollection.Header();
                h.key = "Authorization";
                h.value = "Bearer " + tok;
                out.add(h);
            }
        } else if ("basic".equalsIgnoreCase(a.type)) {
            String creds = authPanel.getBasicCredentialsBase64();
            if (creds != null && !creds.isEmpty()) {
                PostmanCollection.Header h = new PostmanCollection.Header();
                h.key = "Authorization";
                h.value = "Basic " + creds;
                out.add(h);
            }
        } else if ("apikey".equalsIgnoreCase(a.type)) {
            String key = extractAuthValue(a.apikey, "key");
            String value = extractAuthValue(a.apikey, "value");
            String in = extractAuthValue(a.apikey, "in");
            if (key != null && !key.isEmpty() && !"query".equalsIgnoreCase(in)) {
                try {
                    burp.parser.VariableResolver resolver = requestExecutor.getVariableResolver();
                    if (resolver != null) {
                        key = resolver.resolve(key);
                        if (value != null) value = resolver.resolve(value);
                    }
                } catch (Exception ignore) {}
                final String keyFinal = key;
                out.removeIf(h -> h.key != null && h.key.equalsIgnoreCase(keyFinal));
                PostmanCollection.Header h = new PostmanCollection.Header();
                h.key = key;
                h.value = value == null ? "" : value;
                out.add(h);
            }
        }
        // "noauth" falls through with Authorization stripped
        return out;
    }

    private static String extractAuthValue(Object authData, String key) {
        if (authData == null || key == null) return null;
        try {
            if (authData instanceof List) {
                for (Object item : (List<?>) authData) {
                    if (item instanceof PostmanCollection.AuthAttribute) {
                        PostmanCollection.AuthAttribute aa = (PostmanCollection.AuthAttribute) item;
                        if (aa.key != null && key.equalsIgnoreCase(aa.key)) {
                            return aa.value == null ? null : aa.value;
                        }
                    } else if (item instanceof Map) {
                        Map<?, ?> m = (Map<?, ?>) item;
                        Object k = m.get("key");
                        if (k != null && key.equalsIgnoreCase(String.valueOf(k))) {
                            Object v = m.get("value");
                            return v == null ? null : String.valueOf(v);
                        }
                    }
                }
            } else if (authData instanceof Map) {
                Object v = ((Map<?, ?>) authData).get(key);
                return v == null ? null : String.valueOf(v);
            }
        } catch (Exception ignore) {}
        return null;
    }
    
    /** Re-render the Authorization header in the headers table based on the current Auth tab. */
    private void syncAuthIntoHeaders() {
        if (headersTable == null) return;
        List<PostmanCollection.Header> updated = applyAuthToHeaders(headersTable.getHeaders());
        headersTable.setHeaders(updated);
    }
    
    /** Public hook: re-apply auth (e.g., when folder registry changed externally). */
    public void syncInheritedAuth() {
        syncAuthIntoHeaders();
    }
    
    /** Supplier returning the effective inherited folder/collection auth (or null for none). */
    public void setInheritedAuthSupplier(java.util.function.Supplier<burp.auth.FolderAuthOverride> supplier) {
        this.inheritedAuthSupplier = supplier;
        syncAuthIntoHeaders();
    }
    
    public void setSourceContext(String folderPath, String requestName) {
        this.currentFolderPath = folderPath == null ? "" : folderPath;
        this.currentRequestName = requestName == null ? "" : requestName;
    }
    
    /** Show inherited-auth description in the Authorization tab (e.g. "Bearer from collection X"). */
    public void setInheritedAuthDescription(String description) {
        if (authPanel != null) authPanel.setInheritedDescription(description);
    }
    
    /** Snapshot the current builder state into a Request object (for per-request edit persistence). */
    public PostmanCollection.Request getCurrentSnapshot() {
        PostmanCollection.Request snap = new PostmanCollection.Request();
        snap.method = urlBar.getMethod();
        String currentUrl = urlBar.getUrl();
        snap.url = currentUrl;
        String rawTemplate = currentRawUrlTemplate;
        if (currentUrl != null && hasTemplateVariables(currentUrl)) {
            rawTemplate = currentUrl;
        } else if (rawTemplate == null || rawTemplate.isEmpty() || !hasTemplateVariables(rawTemplate)) {
            rawTemplate = currentUrl;
        }
        snap.rawUrlTemplate = rawTemplate;
        snap.header = new java.util.ArrayList<>(headersTable.getHeaders());
        snap.auth = authPanel != null ? authPanel.getAuth() : null;
        String mode = bodyEditor.getMode();
        String body = bodyEditor.getBody();
        String formDraft = bodyEditor.getFormDataBody();
        if (BodyEditorPanel.MODE_FORM_DATA.equalsIgnoreCase(mode)) {
            snap.body = new PostmanCollection.Body();
            snap.body.mode = "formdata";
            snap.body.formdata = parseFormDataBody(body);
        } else if ((body == null || body.isEmpty()) && bodyEditor.hasFormDataRows() && formDraft != null && !formDraft.isEmpty()) {
            // Preserve multipart rows when the user temporarily flips body mode
            // to inspect another editor and then navigates away.
            snap.body = new PostmanCollection.Body();
            snap.body.mode = "formdata";
            snap.body.formdata = parseFormDataBody(formDraft);
        } else if (body != null && !body.isEmpty()) {
            snap.body = new PostmanCollection.Body();
            if (BodyEditorPanel.MODE_GRAPHQL.equalsIgnoreCase(mode)) {
                snap.body.mode = "graphql";
                snap.body.graphql = new PostmanCollection.GraphQL();
                snap.body.graphql.query = bodyEditor.getGraphQLQuery();
                snap.body.graphql.variables = bodyEditor.getGraphQLVariables();
            } else {
                snap.body.mode = "raw";
                snap.body.raw = body;
            }
        }
        return snap;
    }

    private static List<PostmanCollection.FormData> parseFormDataBody(String encodedBody) {
        List<PostmanCollection.FormData> rows = new ArrayList<>();
        if (encodedBody == null || encodedBody.isEmpty()) return rows;
        for (String pair : encodedBody.split("&")) {
            if (pair == null || pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String key = decodeFormComponent(eq >= 0 ? pair.substring(0, eq) : pair);
            if (key == null || key.trim().isEmpty()) continue;
            boolean disabled = key.startsWith("~");
            if (disabled) key = key.substring(1);
            if (key.trim().isEmpty()) continue;
            String value = decodeFormComponent(eq >= 0 ? pair.substring(eq + 1) : "");
            PostmanCollection.FormData fd = new PostmanCollection.FormData();
            fd.key = key;
            fd.disabled = disabled;
            if (value != null && value.startsWith("@")) {
                fd.type = "file";
                String src = value.substring(1).trim();
                if ((src.startsWith("\"") && src.endsWith("\"")) || (src.startsWith("'") && src.endsWith("'"))) {
                    src = src.substring(1, src.length() - 1);
                }
                fd.src = src;
            } else {
                fd.type = "text";
                fd.value = value;
            }
            rows.add(fd);
        }
        return rows;
    }

    private static String decodeFormComponent(String value) {
        try { return java.net.URLDecoder.decode(value == null ? "" : value, "UTF-8"); }
        catch (Exception ignore) { return value == null ? "" : value; }
    }
    
    /**
     * Re-resolve the currently displayed URL using the latest variable values.
     * Called by ImporterPanel.refreshVariables() so a variable edited via the
     * Edit Variables dialog (or via the inline {{var}} popover) immediately
     * updates the URL bar — Postman behavior.
     *
     * Heavily debounced (400ms) and skipped during in-flight Send to avoid
     * pinning the EDT when a script chain writes 60+ variables back-to-back.
     */
    private volatile javax.swing.Timer refreshDebounceTimer;
    private volatile String lastResolvedUrlShown;
    public void refreshFromVariables() {
        try {
            if (bodyEditor != null) bodyEditor.refreshFromVariables();
        } catch (Exception ignore) {}
        // Cheap pre-check off the EDT — most calls are no-ops during a chain.
        if (currentRawUrlTemplate == null || currentRawUrlTemplate.isEmpty()) return;
        // Skip while the user's Send is in flight; the chain writes a flood
        // of vars and refreshing for each one freezes the UI. We re-resolve
        // once when the chain finishes (RequestExecutor.onRequestComplete
        // already triggers a final refreshVariables).
        if (preScriptThread != null && preScriptThread.isAlive()) return;
        if (requestExecutor != null && requestExecutor.isBusy()) return;

        SwingUtilities.invokeLater(() -> {
            if (refreshDebounceTimer == null) {
                refreshDebounceTimer = new javax.swing.Timer(400, e -> doRefresh());
                refreshDebounceTimer.setRepeats(false);
            }
            refreshDebounceTimer.restart();
        });
    }

    private void doRefresh() {
        try {
            if (currentRawUrlTemplate == null || currentRawUrlTemplate.isEmpty()) return;
            burp.parser.VariableResolver resolver = requestExecutor.getVariableResolver();
            if (resolver == null) return;
            String resolved = resolvePostmanPathPlaceholders(
                resolver.resolve(currentRawUrlTemplate), resolver);
            if (resolved != null && resolved.equals(lastResolvedUrlShown)) return;
            lastResolvedUrlShown = resolved;
            urlBar.setUrl(resolved, currentRawUrlTemplate);
        } catch (Throwable ignore) {}
    }

    public void loadRequest(PostmanCollection.Request request) {
        if (request == null) return;
        
        // Clear everything first to prevent state leak between requests
        urlBar.clear();
        headersTable.clear();
        bodyEditor.clear();
        parametersPanel.clear();
        if (authPanel != null) authPanel.clear();
        if (authPanel != null) authPanel.setAuth(request.auth);

        // Capture any pre-request / post-response (test) script attached to this request
        cachedPreScript = extractScript(request, "prerequest");
        cachedPostScript = extractScript(request, "test");
        if (preScriptArea != null)  UndoSupport.setTextWithoutUndo(preScriptArea, "");
        if (postScriptArea != null) UndoSupport.setTextWithoutUndo(postScriptArea, "");
        // (Caller will follow up with setScripts(...) using the cascaded text.)

        // Pass both the resolved URL (for display) and the raw {{var}} template
        // (for span highlighting). UrlBar resolves the template with spans
        // internally and shows the resolved text with colored variable spans.
        String resolvedUrl = request.url != null ? request.url.toString() : "";
        String rawTemplate = request.rawUrlTemplate;
        if ((rawTemplate == null || rawTemplate.isEmpty()) && resolvedUrl.contains("{{")) {
            rawTemplate = resolvedUrl;
        }
        if (rawTemplate == null || rawTemplate.isEmpty()) {
            rawTemplate = resolvedUrl;
        }
        try {
            burp.parser.VariableResolver resolver = requestExecutor.getVariableResolver();
            if (resolver != null && rawTemplate != null && !rawTemplate.isEmpty()) {
                resolvedUrl = resolvePostmanPathPlaceholders(resolver.resolve(rawTemplate), resolver);
            } else {
                resolvedUrl = resolvePostmanPathPlaceholders(resolvedUrl, resolver);
            }
        } catch (Exception ignore) {}
        currentRawUrlTemplate = rawTemplate;
        urlBar.setUrl(resolvedUrl, rawTemplate);
        urlBar.setMethod(request.method != null ? request.method : "GET");
        // Params tab will populate automatically via the URL change listener
        
        if (request.header != null) {
            headersTable.setHeaders(request.header);
        }
        
        if (request.body != null && "graphql".equalsIgnoreCase(request.body.mode) && request.body.graphql != null) {
            bodyEditor.setMode(BodyEditorPanel.MODE_GRAPHQL);
            bodyEditor.setGraphQL(request.body.graphql.query, request.body.graphql.variables);
        } else if (request.body != null && request.body.raw != null
                && !"formdata".equals(request.body.mode)
                && !"urlencoded".equals(request.body.mode)) {
            // Auto-detect JSON/XML for nicer mode display
            String raw = request.body.raw;
            String lang = null;
            if (request.body.options != null && request.body.options.raw != null) {
                lang = request.body.options.raw.language;
            }
            if ("json".equalsIgnoreCase(lang)) {
                bodyEditor.setMode(BodyEditorPanel.MODE_JSON);
            } else if ("xml".equalsIgnoreCase(lang)) {
                bodyEditor.setMode(BodyEditorPanel.MODE_XML);
            }
            bodyEditor.setBody(raw);
        } else if (request.body != null && "urlencoded".equals(request.body.mode) && request.body.urlencoded != null) {
            // Convert urlencoded form data into key=value&key=value format.
            // We use urlEncodePreservingVars so {{var}} markers survive
            // URLEncoder untouched — otherwise "{{"/"}}" get encoded to
            // "%7B%7B"/"%7D%7D", VariableResolver.resolve()'s fast-path
            // (line 157: "if (value.indexOf(\"{{\") < 0) return value;")
            // skips substitution, and the server sees literal
            // "client_id={{su-api-apim-client-id}}" and rejects the request.
            StringBuilder sb = new StringBuilder();
            for (PostmanCollection.UrlEncoded ue : request.body.urlencoded) {
                if (sb.length() > 0) sb.append("&");
                try {
                    String key = ue.key != null ? ue.key : "";
                    if (ue.disabled) key = "~" + key;
                    sb.append(urlEncodePreservingVars(key));
                    sb.append("=");
                    sb.append(urlEncodePreservingVars(ue.value != null ? ue.value : ""));
                } catch (Exception e) {
                    String key = ue.key != null ? ue.key : "";
                    if (ue.disabled) key = "~" + key;
                    sb.append(key).append("=").append(ue.value);
                }
            }
            bodyEditor.setMode(BodyEditorPanel.MODE_URLENC);
            bodyEditor.setBody(sb.toString());
        } else if (request.body != null && "formdata".equals(request.body.mode) && request.body.formdata != null) {
            bodyEditor.setMode(BodyEditorPanel.MODE_FORM_DATA);
            StringBuilder sb = new StringBuilder();
            for (PostmanCollection.FormData fd : request.body.formdata) {
                if (sb.length() > 0) sb.append("&");
                String payload;
                if ("file".equalsIgnoreCase(fd.type)) {
                    String src = fd.getSrcAsString();
                    payload = (src == null || src.isEmpty()) ? "" : "@" + src;
                } else {
                    payload = fd.value != null ? fd.value : "";
                }
                try {
                    String key = fd.key != null ? fd.key : "";
                    if (fd.disabled) key = "~" + key;
                    sb.append(urlEncodePreservingVars(key));
                    sb.append("=");
                    sb.append(urlEncodePreservingVars(payload));
                } catch (Exception e) {
                    String key = fd.key != null ? fd.key : "";
                    if (fd.disabled) key = "~" + key;
                    sb.append(key).append("=").append(payload);
                }
            }
            bodyEditor.setBody(sb.toString());
        } else {
            bodyEditor.setBody("");
        }
        maybeFireLayoutHintChanged();
    }

    /**
     * URL-encode a value while preserving any {{var}} placeholders intact,
     * so VariableResolver.resolve() can still substitute them at send time.
     * Postman itself never encodes {{var}} markers — they're a client-side
     * template, and the resolved value is what gets encoded (see the Runner's
     * utils.RequestBuilder.buildBody urlencoded branch: it resolves first,
     * THEN URLEncoder.encode(...)). Without this helper the single-Send
     * urlencoded path emits body bytes like
     *   client_id=%7B%7Bsu-api-apim-client-id%7D%7D
     * and VariableResolver's fast-path skips substitution because the text
     * no longer contains a literal "{{" — so the wire body ends up with
     * "{{su-api-apim-client-id}}" and the auth server rejects the request.
     */
    private static String urlEncodePreservingVars(String value) throws java.io.UnsupportedEncodingException {
        if (value == null || value.isEmpty()) return "";
        java.util.regex.Matcher m =
            java.util.regex.Pattern.compile("\\{\\{[^{}]+\\}\\}").matcher(value);
        StringBuilder out = new StringBuilder();
        int last = 0;
        while (m.find()) {
            if (m.start() > last) {
                out.append(java.net.URLEncoder.encode(value.substring(last, m.start()), "UTF-8"));
            }
            out.append(m.group());
            last = m.end();
        }
        if (last < value.length()) {
            out.append(java.net.URLEncoder.encode(value.substring(last), "UTF-8"));
        }
        return out.toString();
    }
    
    public void clearBuilder() {
        urlBar.clear();
        headersTable.clear();
        bodyEditor.clear();
        parametersPanel.clear();
        if (authPanel != null) authPanel.clear();
        if (responsePanel != null) responsePanel.clear();
        if (preScriptArea != null) UndoSupport.setTextWithoutUndo(preScriptArea, "");
        if (postScriptArea != null) UndoSupport.setTextWithoutUndo(postScriptArea, "");
        cachedPreScript = null;
        cachedPostScript = null;
        lastResponse = null;
        currentRawUrlTemplate = null;
        lastResolvedUrlShown = null;
        // Reset Send button state — without this, a Restart while a send
        // was mid-flight leaves the button stuck on "Stop" (red).
        resetSendButton();
        maybeFireLayoutHintChanged();
    }

    /** Force the Send button back to idle "Send" state regardless of any
     *  in-flight send. Used by clearBuilder and as a safety net after
     *  the user clicks Stop or Restart. */
    public void resetSendButton() {
        SwingUtilities.invokeLater(() -> {
            sendDispatchGeneration++;
            sendCancelled = false;
            preScriptThread = null;
            if (progressBar != null) progressBar.setVisible(false);
            if (sendButton != null) {
                sendButton.setText("Send");
                burp.ui.UITheme.apply(sendButton, burp.ui.UITheme.BtnStyle.PRIMARY);
            }
            if (refreshDebounceTimer != null) refreshDebounceTimer.stop();
        });
    }
    
    /**
     * Allow external response panel to be used instead of internal one
     */
    public void setExternalResponsePanel(ResponsePanel external) {
        this.responsePanel = external;
    }

    /** Pull a script of the requested type ("prerequest" or "test") from request.event[]. */
    private static String extractScript(PostmanCollection.Request request, String wantType) {
        if (request == null) return null;
        // request.event is on Item, but Request itself doesn't carry events directly in our model.
        // Fall back to scanning the body for now (Postman attaches scripts on the parent Item;
        // ImporterPanel passes a copy of Item.request, not Item — so script lookup happens via
        // the cached event list set externally if needed). Keep this as a hook.
        return null;
    }

    /** Set scripts captured from the parent Item.event[] (called by caller after loadRequest). */
    public void setScripts(String preRequestScript, String postResponseScript) {
        this.cachedPreScript = preRequestScript;
        this.cachedPostScript = postResponseScript;
        if (preScriptArea != null)  UndoSupport.setTextWithoutUndo(preScriptArea,  preRequestScript  == null ? "" : preRequestScript);
        if (postScriptArea != null) UndoSupport.setTextWithoutUndo(postScriptArea, postResponseScript == null ? "" : postResponseScript);
        if (preScriptArea != null)  preScriptArea.setCaretPosition(0);
        if (postScriptArea != null) postScriptArea.setCaretPosition(0);
    }
    
    private void syncParamsFromUrl() {
        String url = urlBar.getUrl();
        List<ParametersPanel.ParamRow> params = new ArrayList<>();
        int q = url.indexOf('?');
        if (q >= 0 && q < url.length() - 1) {
            String query = url.substring(q + 1);
            for (String pair : query.split("&")) {
                if (pair.isEmpty()) continue;
                int eq = pair.indexOf('=');
                ParametersPanel.ParamRow row = new ParametersPanel.ParamRow();
                row.enabled = true;
                try {
                    if (eq >= 0) {
                        row.key = java.net.URLDecoder.decode(pair.substring(0, eq), "UTF-8");
                        row.value = java.net.URLDecoder.decode(pair.substring(eq + 1), "UTF-8");
                    } else {
                        row.key = java.net.URLDecoder.decode(pair, "UTF-8");
                    }
                } catch (Exception e) {
                    row.key = eq >= 0 ? pair.substring(0, eq) : pair;
                    row.value = eq >= 0 ? pair.substring(eq + 1) : "";
                }
                params.add(row);
            }
        }
        parametersPanel.setParameters(params);
    }
    
    private void syncUrlFromParams() {
        String url = urlBar.getUrl();
        String base = stripQuery(url);
        String rawSource = currentRawUrlTemplate;
        if (rawSource == null || rawSource.isEmpty() || !hasTemplateVariables(rawSource)) {
            rawSource = url;
        }
        String rawBase = stripQuery(rawSource);
        
        StringBuilder qs = new StringBuilder();
        for (ParametersPanel.ParamRow row : parametersPanel.getParameters()) {
            if (!row.enabled || row.key == null || row.key.isEmpty()) continue;
            if (qs.length() > 0) qs.append("&");
            try {
                qs.append(java.net.URLEncoder.encode(row.key, "UTF-8"));
                qs.append("=");
                qs.append(java.net.URLEncoder.encode(row.value != null ? row.value : "", "UTF-8"));
            } catch (Exception e) {
                qs.append(row.key).append("=").append(row.value != null ? row.value : "");
            }
        }
        String query = qs.toString();
        String resolvedUrl = appendQuery(base, query);
        String rawUrl = appendQuery(rawBase, query);
        applyUrlWithTemplate(resolvedUrl, rawUrl);
    }

    private void applyUrlWithTemplate(String resolvedUrl, String rawTemplate) {
        String resolved = resolvedUrl == null ? "" : resolvedUrl;
        String raw = (rawTemplate == null || rawTemplate.isEmpty()) ? resolved : rawTemplate;
        if (!hasTemplateVariables(raw)) {
            raw = resolved;
        }
        currentRawUrlTemplate = raw;
        urlBar.setUrl(resolved, raw);
    }

    private static String stripQuery(String url) {
        if (url == null) return "";
        int q = url.indexOf('?');
        return q >= 0 ? url.substring(0, q) : url;
    }

    private static String appendQuery(String base, String query) {
        if (base == null) base = "";
        if (query == null || query.isEmpty()) return base;
        return base + "?" + query;
    }

    private static boolean hasScheme(String url) {
        return url != null && url.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*");
    }

    private static boolean hasTemplateVariables(String value) {
        return value != null && value.contains("{{");
    }
}
