package burp.auth;

import burp.PostmanImporter;
import burp.models.PostmanCollection;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.io.File;
import java.util.List;

public class AuthManagerPanel extends JPanel {
    private static final int OAUTH_HTTP_TIMEOUT_MS = 25000;
    private static final int OAUTH_BROWSER_LOCAL_CAPTURE_TIMEOUT_SECONDS = 25;
    private static final int OAUTH_BROWSER_PROXY_CAPTURE_TIMEOUT_SECONDS = 20;
    private static final int OAUTH_BROWSER_PROXY_FALLBACK_TIMEOUT_SECONDS = 10;

    private final AuthManager authManager;
    private final PostmanImporter importer;

    private JTable jwtTable;
    private javax.swing.table.DefaultTableModel jwtModel;
    private JTable scriptJwtTable;
    private javax.swing.table.DefaultTableModel scriptJwtModel;
    private JButton analyzeButton;
    private JTextArea tokenArea;
    private JButton scriptPreviewButton;
    private JLabel tokenStatusLabel;
    private JButton tokenRefreshButton;
    private JComboBox<OAuth2Config> oauthConfigCombo;
    private JLabel scopeLabel;
    private JButton clearScopeBtn;
    private JSplitPane tokenSourcesSplit;
    private JSplitPane authMainSplit;
    private JPanel tokenRightHost;
    private boolean suppressOAuthComboEvents = false;
    private String currentRequestPath;
    private String currentRequestEndpoint;
    private String currentRequestMethod;

    private List<JwtEndpointCandidate> jwtData;
    private final List<JwtEndpointCandidate> visibleJwtData = new java.util.ArrayList<>();
    private final List<JwtEndpointCandidate> visibleScriptJwtData = new java.util.ArrayList<>();

    /**
     * Optional callback invoked when the user clicks "Apply" with a fresh
     * token. The host (ImporterPanel) wires this to push the token into the
     * Request Builder's Authorization tab so the UI matches what will be sent.
     */
    private java.util.function.Consumer<String> onTokenApplied;

    public void setOnTokenApplied(java.util.function.Consumer<String> cb) {
        this.onTokenApplied = cb;
    }

    public void clear() {
        updateJwtDetection(
            new java.util.ArrayList<>(),
            new java.util.ArrayList<>()
        );
        setToken("");
        // Reset scope filter so the label/button don't show stale state from a
        // previous collection.
        lastScopeFilter = null;
        setScopeFilter(null);
        if (scopeLabel != null) {
            scopeLabel.setText("Scope: All collections (no filter)");
            scopeLabel.setToolTipText(scopeLabel.getText());
        }
        }
    public AuthManagerPanel(AuthManager authManager, PostmanImporter importer) {
        this.authManager = authManager;
        this.importer = importer;

        initializeUI();
    }

    private void initializeUI() {

        setLayout(new BorderLayout(6, 6));
        setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));

        // ===== TOKEN SOURCE TABLE =====
        jwtModel = new javax.swing.table.DefaultTableModel(
                new Object[]{"Use", "Collection", "Folder Path", "Endpoint", "Method", "Confidence"}, 0) {

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0) {
                    return Boolean.class;
                }
                return String.class;
            }

            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0;
            }
        };

        jwtTable = new JTable(jwtModel);
        jwtTable.getColumnModel().getColumn(0).setMaxWidth(50);
        jwtTable.getColumnModel().getColumn(0).setPreferredWidth(45);
        jwtTable.getColumnModel().getColumn(1).setPreferredWidth(180); // Collection
        jwtTable.getColumnModel().getColumn(2).setPreferredWidth(180); // Folder Path
        jwtTable.getColumnModel().getColumn(3).setPreferredWidth(380); // Endpoint
        jwtTable.getColumnModel().getColumn(4).setMaxWidth(70);        // Method
        jwtTable.getColumnModel().getColumn(5).setMaxWidth(90);        // Confidence
        jwtTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        jwtTable.setFillsViewportHeight(false);
        JScrollPane tableScroll = new JScrollPane(
                jwtTable,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        tableScroll.getVerticalScrollBar().setUnitIncrement(14);
        tableScroll.getHorizontalScrollBar().setUnitIncrement(14);
        tableScroll.setPreferredSize(new Dimension(520, 190));
        tableScroll.setMinimumSize(new Dimension(260, 120));

        // ===== SCRIPT TOKEN SOURCE TABLE =====
        scriptJwtModel = new javax.swing.table.DefaultTableModel(
                new Object[]{"Use", "Collection", "Folder Path", "Endpoint", "Method"}, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 0 ? Boolean.class : String.class;
            }

            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0;
            }
        };
        scriptJwtTable = new JTable(scriptJwtModel);
        scriptJwtTable.getColumnModel().getColumn(0).setMaxWidth(50);
        scriptJwtTable.getColumnModel().getColumn(0).setPreferredWidth(45);
        scriptJwtTable.getColumnModel().getColumn(1).setPreferredWidth(170);
        scriptJwtTable.getColumnModel().getColumn(2).setPreferredWidth(170);
        scriptJwtTable.getColumnModel().getColumn(3).setPreferredWidth(360);
        scriptJwtTable.getColumnModel().getColumn(4).setMaxWidth(70);
        scriptJwtTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        scriptJwtTable.setFillsViewportHeight(false);

        JScrollPane scriptTableScroll = new JScrollPane(
                scriptJwtTable,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scriptTableScroll.getVerticalScrollBar().setUnitIncrement(14);
        scriptTableScroll.getHorizontalScrollBar().setUnitIncrement(14);
        scriptTableScroll.setPreferredSize(new Dimension(520, 104));
        scriptTableScroll.setMinimumSize(new Dimension(260, 72));

        JPanel scriptSection = new JPanel(new BorderLayout());
        scriptSection.setBorder(BorderFactory.createTitledBorder("Possible token source from scripts"));
        scriptPreviewButton = burp.ui.UITheme.button("View Script", burp.ui.UITheme.BtnStyle.GHOST);
        scriptPreviewButton.setEnabled(false);
        scriptPreviewButton.setToolTipText("Open the selected script token source in a popup preview");
        scriptPreviewButton.addActionListener(e -> openScriptPreviewForSelectedRow());
        JLabel scriptHint = new JLabel("Double-click a row to open script + translated request.");
        scriptHint.setFont(scriptHint.getFont().deriveFont(Font.PLAIN, 11f));
        JPanel scriptActions = new JPanel(new BorderLayout(6, 0));
        scriptActions.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
        scriptActions.setOpaque(false);
        scriptActions.add(scriptHint, BorderLayout.CENTER);
        scriptActions.add(scriptPreviewButton, BorderLayout.EAST);
        scriptSection.add(scriptActions, BorderLayout.NORTH);
        scriptSection.add(scriptTableScroll, BorderLayout.CENTER);
        scriptSection.setMinimumSize(new Dimension(120, 70));
        scriptSection.setPreferredSize(new Dimension(120, 96));

        // ===== BUTTON BAR =====
        // Analyze on LEFT (big green primary CTA), helpers on RIGHT (Postman-style).
        JPanel buttonPanel = new JPanel(new BorderLayout());
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));

        JButton analyzeBtn = burp.ui.UITheme.button("Analyze", burp.ui.UITheme.BtnStyle.SUCCESS);
        analyzeBtn.setFont(analyzeBtn.getFont().deriveFont(Font.BOLD, 13f));
        analyzeBtn.setPreferredSize(new Dimension(130, 30));
        analyzeBtn.setToolTipText("<html>Resolve <b>{{variables}}</b>, detect OAuth2/JWT auth endpoints,<br/>"
                + "and run pre/post-request scripts on every request<br/>"
                + "so captured tokens land in your variables.</html>");

        JButton fetchBtn = burp.ui.UITheme.button("Fetch Token", burp.ui.UITheme.BtnStyle.GHOST);
        JCheckBox useRepeater = new JCheckBox("Use Repeater");
        useRepeater.setOpaque(false);
        JButton editVarsBtn = burp.ui.UITheme.button("Edit Variables", burp.ui.UITheme.BtnStyle.GHOST);

        JPanel leftBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        leftBar.setOpaque(false);
        leftBar.add(analyzeBtn);

        JPanel rightBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        rightBar.setOpaque(false);
        rightBar.add(editVarsBtn);
        rightBar.add(fetchBtn);
        rightBar.add(useRepeater);

        buttonPanel.add(leftBar, BorderLayout.WEST);
        buttonPanel.add(rightBar, BorderLayout.EAST);

        // ===== TOKEN AREA =====
        tokenArea = new JTextArea();
        tokenArea.setRows(2);
        tokenArea.setColumns(30);

        // ✅ make tokens readable
        tokenArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        // Keep token area height stable (no panel growth from very long JWTs).
        tokenArea.setLineWrap(false);
        tokenArea.setWrapStyleWord(false);

        JPanel tokenPanel = new JPanel(new BorderLayout());
        tokenPanel.setBorder(BorderFactory.createTitledBorder("Token"));

        JPanel tokenStatusBar = new JPanel(new BorderLayout(6, 0));
        tokenStatusBar.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
        tokenStatusLabel = new JLabel("No token set.");
        tokenStatusLabel.setFont(tokenStatusLabel.getFont().deriveFont(Font.PLAIN, 11f));
        tokenStatusLabel.setForeground(new Color(120, 120, 120));
        tokenRefreshButton = burp.ui.UITheme.button("Refresh", burp.ui.UITheme.BtnStyle.GHOST);
        tokenRefreshButton.setToolTipText("Select token source or OAuth2 config first");
        tokenStatusBar.add(tokenStatusLabel, BorderLayout.CENTER);
        tokenStatusBar.add(tokenRefreshButton, BorderLayout.EAST);
        tokenPanel.add(tokenStatusBar, BorderLayout.NORTH);

        JScrollPane tokenScroll = new JScrollPane(
                tokenArea,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        tokenScroll.getVerticalScrollBar().setUnitIncrement(14);
        tokenScroll.getHorizontalScrollBar().setUnitIncrement(14);
        tokenScroll.setPreferredSize(new Dimension(240, 86));
        tokenScroll.setMinimumSize(new Dimension(180, 68));
        tokenPanel.add(tokenScroll, BorderLayout.CENTER);

        JPanel tokenButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 2));
        JButton applyBtn = new JButton("Apply");
        JButton copyBtn = new JButton("Copy");

        tokenButtons.add(applyBtn);
        tokenButtons.add(copyBtn);

        tokenPanel.add(tokenButtons, BorderLayout.SOUTH);


        // ===== OAUTH PANEL =====
        JPanel topPanel = new JPanel(new BorderLayout(6, 4));
        topPanel.setBorder(BorderFactory.createTitledBorder("OAuth2"));

        oauthConfigCombo = new JComboBox<>();
        oauthConfigCombo.addActionListener(e -> {
            if (suppressOAuthComboEvents) return;
            Object selected = oauthConfigCombo.getSelectedItem();
            if (selected instanceof OAuth2Config) {
                authManager.setPreferredOAuth2Config((OAuth2Config) selected);
            }
            refreshTokenStatus();
        });
        JPanel oauthConfigRow = new JPanel(new BorderLayout(6, 0));
        oauthConfigRow.add(new JLabel("Config:"), BorderLayout.WEST);
        oauthConfigRow.add(oauthConfigCombo, BorderLayout.CENTER);

        JButton oauthSendBtn = burp.ui.UITheme.button("Send to Repeater", burp.ui.UITheme.BtnStyle.GHOST);
        JButton oauthEditBtn = burp.ui.UITheme.button("OAuth2", burp.ui.UITheme.BtnStyle.ACCENT);
        JPanel oauthBtnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        oauthBtnRow.setOpaque(false);
        oauthBtnRow.add(oauthEditBtn);
        oauthBtnRow.add(oauthSendBtn);

        topPanel.add(oauthConfigRow, BorderLayout.CENTER);
        topPanel.add(oauthBtnRow, BorderLayout.EAST);

        // ===== LAYOUT =====

        // ===== SCOPE BAR (filter by clicked tree node) =====
        scopeLabel = new JLabel("Scope: All collections");
        scopeLabel.setFont(scopeLabel.getFont().deriveFont(Font.PLAIN, 11f));
        scopeLabel.setForeground(burp.ui.UITheme.foreground());
        scopeLabel.setToolTipText(scopeLabel.getText());
        clearScopeBtn = new JButton("Clear Filter");
        clearScopeBtn.setMargin(new Insets(1, 6, 1, 6));
        clearScopeBtn.setToolTipText("Clear the collection/folder filter and show every detected endpoint");
        clearScopeBtn.addActionListener(e -> {
            if (scopeFilterPath != null) {
                // Active filter -> remember it, then clear
                lastScopeFilter = scopeFilterPath;
                setScopeFilter(null);
            } else if (lastScopeFilter != null) {
                // No filter, but we have a previous one -> reapply
                setScopeFilter(lastScopeFilter);
            }
        });
        JScrollPane scopeScroll = new JScrollPane(
                scopeLabel,
                JScrollPane.VERTICAL_SCROLLBAR_NEVER,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scopeScroll.setBorder(BorderFactory.createEmptyBorder());
        scopeScroll.setOpaque(false);
        scopeScroll.getViewport().setOpaque(false);
        scopeScroll.getHorizontalScrollBar().setUnitIncrement(14);
        JPanel scopeBar = new JPanel(new BorderLayout(6, 0));
        scopeBar.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
        scopeBar.add(scopeScroll, BorderLayout.CENTER);
        scopeBar.add(clearScopeBtn, BorderLayout.EAST);

        JPanel centerTop = new JPanel(new BorderLayout());
        centerTop.add(scopeBar, BorderLayout.NORTH);
        tokenSourcesSplit = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                tableScroll,
                scriptSection
        );
        tokenSourcesSplit.setResizeWeight(0.84);
        tokenSourcesSplit.setDividerLocation(0.84);
        tokenSourcesSplit.setOneTouchExpandable(true);
        centerTop.add(tokenSourcesSplit, BorderLayout.CENTER);
        centerTop.add(buttonPanel, BorderLayout.SOUTH);

        authMainSplit = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                centerTop,
                buildTokenRightHost(tokenPanel)
        );
        authMainSplit.setResizeWeight(0.76);
        authMainSplit.setDividerLocation(0.76);
        authMainSplit.setOneTouchExpandable(true);

        centerTop.setMinimumSize(new Dimension(320, 90));
        tokenPanel.setMinimumSize(new Dimension(200, 72));
        tokenPanel.setPreferredSize(new Dimension(240, 92));
        if (tokenRightHost != null) {
            tokenRightHost.setMinimumSize(new Dimension(200, 72));
            tokenRightHost.setPreferredSize(new Dimension(240, 120));
        }

        add(topPanel, BorderLayout.NORTH);
        add(authMainSplit, BorderLayout.CENTER);
        authMainSplit.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                adaptCompactLayout();
            }
        });
        tokenSourcesSplit.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                adaptCompactLayout();
            }
        });
        SwingUtilities.invokeLater(this::adaptCompactLayout);


        // ===== ACTIONS =====

        analyzeBtn.addActionListener(e -> {
            if (!analyzeBtn.isEnabled()) return;
            analyzeBtn.setEnabled(false);
            analyzeBtn.setText("Analyzing...");
            new Thread(() -> {
                final boolean[] success = {false};
                try {
                    success[0] = runAuthAnalysis();
                } finally {
                    SwingUtilities.invokeLater(() -> {
                        if (success[0]) {
                            // Reflect the actual analyzed state of the
                            // currently-scoped collection (might be only one).
                            refreshAnalyzeButtonForScope();
                        } else {
                            analyzeBtn.setEnabled(true);
                            analyzeBtn.setText("Analyze");
                            analyzeBtn.setToolTipText("<html>Resolve <b>{{variables}}</b>, detect OAuth2/JWT auth endpoints,<br/>"
                                    + "and run pre/post-request scripts on every request<br/>"
                                    + "so captured tokens land in your variables.</html>");
                        }
                    });
                }
            }, "auth-analysis").start();
        });
        // Expose for reset
        this.analyzeButton = analyzeBtn;
        editVarsBtn.addActionListener(e -> {
            importer.showManualVariablesDialog();
        });
        fetchBtn.addActionListener(e -> triggerTokenFetch(useRepeater.isSelected()));
        tokenRefreshButton.addActionListener(e -> triggerTokenFetch(false));
        jwtModel.addTableModelListener(e -> {
            if (e.getColumn() != 0) {
                return;
            }

            int selectedRow = e.getFirstRow();

            if (selectedRow < 0 || selectedRow >= jwtModel.getRowCount()) {
                return;
            }

            Object checkedValue = jwtModel.getValueAt(selectedRow, 0);

            if (!(checkedValue instanceof Boolean)) {
                return;
            }

            boolean checked = (Boolean) checkedValue;

            if (!checked) {
                if (!hasCheckedTokenSource()) {
                    authManager.setTokenSourceRequest(null);
                }
                refreshTokenStatus();
                return;
            }

            // ✅ Only allow one checked token source.
            clearCheckedRows(jwtModel, selectedRow);
            clearCheckedRows(scriptJwtModel, -1);

            if (selectedRow < 0 || selectedRow >= visibleJwtData.size()) {
                return;
            }

            JwtEndpointCandidate selectedCandidate = visibleJwtData.get(selectedRow);

            authManager.setTokenSourceRequest(selectedCandidate.request);
            refreshTokenStatus();

            burp.ui.ToastManager.show(this,
                    "Token source: " + selectedCandidate.method + " "
                            + candidateDisplayEndpoint(selectedCandidate, false),
                    burp.ui.ToastManager.Level.INFO);
        });
        scriptJwtModel.addTableModelListener(e -> {
            if (e.getColumn() != 0) {
                return;
            }
            int selectedRow = e.getFirstRow();
            if (selectedRow < 0 || selectedRow >= scriptJwtModel.getRowCount()) {
                return;
            }
            Object checkedValue = scriptJwtModel.getValueAt(selectedRow, 0);
            if (!(checkedValue instanceof Boolean)) {
                return;
            }
            boolean checked = (Boolean) checkedValue;
            if (!checked) {
                if (!hasCheckedTokenSource()) {
                    authManager.setTokenSourceRequest(null);
                }
                refreshTokenStatus();
                return;
            }
            clearCheckedRows(scriptJwtModel, selectedRow);
            clearCheckedRows(jwtModel, -1);

            if (selectedRow < 0 || selectedRow >= visibleScriptJwtData.size()) {
                return;
            }
            JwtEndpointCandidate selectedCandidate = visibleScriptJwtData.get(selectedRow);
            authManager.setTokenSourceRequest(selectedCandidate.request);
            refreshTokenStatus();

            burp.ui.ToastManager.show(this,
                    "Script token source: " + selectedCandidate.method + " "
                            + candidateDisplayEndpoint(selectedCandidate, true),
                    burp.ui.ToastManager.Level.INFO);
        });
        scriptJwtTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            updateScriptPreviewForSelection(scriptJwtTable.getSelectedRow());
        });
        scriptJwtTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() >= 2 && SwingUtilities.isLeftMouseButton(e)) {
                    int row = scriptJwtTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        openScriptPreviewPopup(row);
                    }
                }
            }
        });
        oauthEditBtn.addActionListener(e -> {
            OAuth2Config selected = (OAuth2Config) oauthConfigCombo.getSelectedItem();
            if (selected == null) {
                showOAuthWarning("No OAuth2 config selected.");
                return;
            }
            Window owner = SwingUtilities.getWindowAncestor(this);
            OAuth2ConfigDialog dlg = new OAuth2ConfigDialog(
                    owner, selected, importer, authManager, importer.getApi());
            dlg.setVisible(true);
            // After editing, propagate any extracted token into the token area.
            String tok = authManager.getAccessToken();
            if (tok != null && !tok.isEmpty()) {
                setToken(tok);
            }
            // Refresh the combo so the displayed name picks up edits.
            oauthConfigCombo.repaint();
        });

        oauthSendBtn.addActionListener(e -> {

            OAuth2Config selected =
                    (OAuth2Config) oauthConfigCombo.getSelectedItem();

            if (selected == null) {
                showOAuthWarning("No OAuth2 config selected.");
                return;
            }

            try {
                OAuth2RequestFactory factory = new OAuth2RequestFactory(importer.getVariableResolver());
                burp.api.montoya.http.message.requests.HttpRequest req = factory.buildTokenRequest(selected);

                importer.sendOAuthToRepeater(req);

            } catch (Exception ex) {
                showOAuthError("Failed to build OAuth request: " + ex.getMessage());
            }
        });

        applyBtn.addActionListener(e -> {
            String token = tokenArea.getText() != null
                    ? tokenArea.getText().trim()
                    : "";

            if (token.isEmpty()) {
                showOAuthWarning("No token to apply.");
                return;
            }

            authManager.setAccessToken(token);
            cacheTokenForSelectedConfig(token);

            java.util.Map<String, String> vars =
                    new java.util.LinkedHashMap<>();

            vars.put("token", token);

            importer.addCustomVariables(vars);

            // Notify host (ImporterPanel) so the Request Builder's
            // Authorization tab can be refreshed with the new token.
            if (onTokenApplied != null) {
                try { onTokenApplied.accept(token); } catch (Exception ignore) {}
            }

            burp.ui.ToastManager.show(this, "Token applied to {{token}}", burp.ui.ToastManager.Level.SUCCESS);
        });

        copyBtn.addActionListener(e ->
                Toolkit.getDefaultToolkit()
                        .getSystemClipboard()
                        .setContents(new StringSelection(tokenArea.getText()), null));

        authManager.addTokenChangeListener(token ->
                SwingUtilities.invokeLater(() -> setToken(token)));
        setToken(authManager.getAccessToken());
        refreshTokenStatus();
    }

    public void setToken(String token) {
        if (tokenArea == null) return;
        tokenArea.setText(token == null ? "" : token);
        refreshTokenStatus();
    }

    private void triggerTokenFetch(boolean useRepeater) {
        PostmanCollection.Request tokenSource = authManager.getTokenSourceRequest();
        if (tokenSource != null) {
            if (useRepeater) {
                importer.sendJwtToRepeater(tokenSource);
            } else {
                importer.autoFetchFromJwt(tokenSource);
            }
            return;
        }

        OAuth2Config selectedCfg = (OAuth2Config) oauthConfigCombo.getSelectedItem();
        if (selectedCfg != null) {
            fetchOAuthToken(selectedCfg, useRepeater);
            return;
        }

        showOAuthWarning("Select a token endpoint or an OAuth2 config first.");
    }

    private boolean canRefreshTokenNow() {
        if (authManager.getTokenSourceRequest() != null) return true;
        try {
            return oauthConfigCombo != null
                    && oauthConfigCombo.getSelectedItem() instanceof OAuth2Config;
        } catch (Exception ignore) {
            return false;
        }
    }

    private void refreshTokenStatus() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshTokenStatus);
            return;
        }
        if (tokenStatusLabel == null) return;

        boolean canRefresh = canRefreshTokenNow();
        if (tokenRefreshButton != null) {
            tokenRefreshButton.setEnabled(canRefresh);
            tokenRefreshButton.setToolTipText(
                    canRefresh
                            ? "Fetch a fresh access token now"
                            : "Select token source or OAuth2 config first"
            );
        }

        String token = authManager.getAccessToken();
        if (token == null || token.trim().isEmpty()) {
            tokenStatusLabel.setText("No token set.");
            tokenStatusLabel.setForeground(new Color(120, 120, 120));
            return;
        }

        long expiresAtMs = authManager.getAccessTokenExpiryEpochMs();
        boolean expiredOrNear = authManager.isAccessTokenExpiredOrNearExpiry();
        if (expiresAtMs > 0L) {
            long remainingMs = expiresAtMs - System.currentTimeMillis();
            if (expiredOrNear) {
                tokenStatusLabel.setText(remainingMs <= 0L
                        ? "Token expired."
                        : "Token expiring soon (" + formatRemainingTime(remainingMs) + ").");
                tokenStatusLabel.setForeground(new Color(185, 40, 40));
                return;
            }
            tokenStatusLabel.setText("Token valid (" + formatRemainingTime(remainingMs) + " remaining).");
            tokenStatusLabel.setForeground(new Color(40, 130, 60));
            return;
        }

        if (expiredOrNear) {
            tokenStatusLabel.setText("Token expired or near expiry.");
            tokenStatusLabel.setForeground(new Color(185, 40, 40));
        } else {
            tokenStatusLabel.setText("Token set (expiry unknown).");
            tokenStatusLabel.setForeground(new Color(160, 120, 20));
        }
    }

    private static String formatRemainingTime(long remainingMs) {
        long totalSeconds = Math.max(0L, remainingMs / 1000L);
        long hours = totalSeconds / 3600L;
        long minutes = (totalSeconds % 3600L) / 60L;
        long seconds = totalSeconds % 60L;
        if (hours > 0L) {
            return hours + "h " + minutes + "m";
        }
        if (minutes > 0L) {
            return minutes + "m " + seconds + "s";
        }
        return seconds + "s";
    }

    private void fetchOAuthToken(OAuth2Config config, boolean useRepeater) {
        try {
            OAuth2RequestFactory factory = new OAuth2RequestFactory(importer.getVariableResolver());
            if (factory.isBrowserInteractiveFlow(config)) {
                fetchOAuthTokenViaBrowser(config, factory, useRepeater);
                return;
            }
            burp.api.montoya.http.message.requests.HttpRequest req = factory.buildTokenRequest(config);
            if (useRepeater) {
                importer.sendOAuthToRepeater(req);
                burp.ui.ToastManager.show(this,
                        "OAuth token request sent to Repeater",
                        burp.ui.ToastManager.Level.INFO);
                return;
            }

            new Thread(() -> {
                try {
                    burp.api.montoya.http.message.HttpRequestResponse rr =
                            OAuthHttpClient.sendRequestWithTimeout(importer.getApi(), req, OAUTH_HTTP_TIMEOUT_MS);
                    if (rr == null || rr.response() == null) {
                        showOAuthWarning("No response from OAuth token endpoint.");
                        return;
                    }
                    int status = rr.response().statusCode();
                    String body = rr.response().bodyToString();
                    SwingUtilities.invokeLater(() -> {
                        if (status >= 200 && status < 300 && authManager.extractAnyToken(body)) {
                            String token = authManager.getAccessToken();
                            cacheTokenForSelectedConfig(token);
                            setToken(token);
                            burp.ui.ToastManager.show(this,
                                    "OAuth token fetched successfully",
                                    burp.ui.ToastManager.Level.SUCCESS);
                        } else {
                            showOAuthWarning(buildOAuthFailureMessage(status, body));
                        }
                    });
                } catch (Exception ex) {
                    showOAuthError("OAuth token fetch failed: " + ex.getMessage());
                }
            }, "oauth-fetch-from-auth-panel").start();
        } catch (Exception ex) {
            showOAuthError("Failed to build OAuth token request: " + ex.getMessage());
        }
    }

    private void fetchOAuthTokenViaBrowser(OAuth2Config config, OAuth2RequestFactory factory, boolean useRepeater) {
        new Thread(() -> runBrowserOAuthFlow(config, factory, useRepeater), "oauth-browser-flow").start();
    }

    private void runBrowserOAuthFlow(OAuth2Config config, OAuth2RequestFactory factory, boolean useRepeater) {
        try {
            OAuth2RequestFactory.PkcePair pkce = factory.generatePkcePair();
            String authUrl = factory.buildAuthorizationRequestUrl(config, pkce.challenge);
            String callbackUrl = factory.resolveBrowserCallbackUrl(config);
            String code = null;
            long captureStartMillis = System.currentTimeMillis();
            boolean canAutoCapture = OAuthBrowserCallbackServer.canAutoCapture(callbackUrl);
            boolean canProxyCapture = OAuthProxyCallbackCapture.canCapture(callbackUrl);
            int waitBudgetSeconds =
                    (canAutoCapture ? OAUTH_BROWSER_LOCAL_CAPTURE_TIMEOUT_SECONDS : 0)
                            + (canProxyCapture ? OAUTH_BROWSER_PROXY_CAPTURE_TIMEOUT_SECONDS : 0)
                            + OAUTH_BROWSER_PROXY_FALLBACK_TIMEOUT_SECONDS;
            boolean browserOpened = false;

            if (canAutoCapture) {
                try {
                    browserOpened = true;
                    code = OAuthBrowserCallbackServer.openBrowserAndAwaitCode(
                            authUrl,
                            callbackUrl,
                            OAUTH_BROWSER_LOCAL_CAPTURE_TIMEOUT_SECONDS
                    );
                } catch (Exception ex) {
                    // Fall back to manual paste if local callback capture fails.
                }
            }

            if (code == null || code.isEmpty()) {
                if (!browserOpened) {
                    openBrowser(authUrl);
                }
                if (canProxyCapture) {
                    try {
                        code = OAuthProxyCallbackCapture.awaitCodeFromProxy(
                                importer.getApi(),
                                callbackUrl,
                                OAUTH_BROWSER_PROXY_CAPTURE_TIMEOUT_SECONDS,
                                captureStartMillis
                        );
                    } catch (Exception ex) {
                        // Fall back to manual paste mode if proxy capture fails.
                    }
                }
                if (code == null || code.isEmpty()) {
                    try {
                        code = OAuthProxyCallbackCapture.awaitAnyCodeFromProxy(
                                importer.getApi(),
                                OAUTH_BROWSER_PROXY_FALLBACK_TIMEOUT_SECONDS,
                                captureStartMillis
                        );
                    } catch (Exception ex) {
                        // Fall back to manual paste mode if broad proxy capture fails.
                    }
                }
            }

            if (code == null || code.isEmpty()) {
                showOAuthWarning(
                        "Browser auth did not return a callback code automatically. "
                                + "Manual paste popup is disabled. "
                                + "Waited about " + waitBudgetSeconds + "s. "
                                + "Check callback URL/port registration and retry."
                );
                return;
            }

            burp.api.montoya.http.message.requests.HttpRequest req =
                    factory.buildAuthorizationCodeTokenRequest(config, code, pkce.verifier);

            if (useRepeater) {
                importer.sendOAuthToRepeater(req);
                SwingUtilities.invokeLater(() -> burp.ui.ToastManager.show(
                        this,
                        "OAuth code-exchange request sent to Repeater",
                        burp.ui.ToastManager.Level.INFO));
                return;
            }

            new Thread(() -> {
                try {
                    burp.api.montoya.http.message.HttpRequestResponse rr =
                            OAuthHttpClient.sendRequestWithTimeout(importer.getApi(), req, OAUTH_HTTP_TIMEOUT_MS);
                    if (rr == null || rr.response() == null) {
                        showOAuthWarning("No response from OAuth token endpoint.");
                        return;
                    }
                    int status = rr.response().statusCode();
                    String body = rr.response().bodyToString();
                    SwingUtilities.invokeLater(() -> {
                        if (status >= 200 && status < 300 && authManager.extractAnyToken(body)) {
                            String token = authManager.getAccessToken();
                            cacheTokenForSelectedConfig(token);
                            setToken(token);
                            burp.ui.ToastManager.show(this,
                                    "OAuth token fetched successfully",
                                    burp.ui.ToastManager.Level.SUCCESS);
                        } else {
                            showOAuthWarning(buildOAuthFailureMessage(status, body));
                        }
                    });
                } catch (Exception ex) {
                    showOAuthError("OAuth token fetch failed: " + ex.getMessage());
                }
            }, "oauth-browser-code-exchange").start();
        } catch (Exception ex) {
            showOAuthError("OAuth browser flow failed: " + ex.getMessage());
        }
    }

    private String resolveCallbackUrl(OAuth2Config config) {
        if (config == null || config.callbackUrl == null || config.callbackUrl.trim().isEmpty()) return null;
        try {
            return importer.getVariableResolver().resolve(config.callbackUrl);
        } catch (Exception ex) {
            return config.callbackUrl;
        }
    }

    private static void openBrowser(String url) throws Exception {
        BrowserLauncher.open(url);
    }

    private void showOAuthWarning(String message) {
        final String msg = message == null ? "OAuth warning." : message;
        try {
            importer.getApi().logging().logToOutput("[OAuth] " + msg);
        } catch (Exception ignore) {}
        SwingUtilities.invokeLater(() -> burp.ui.ToastManager.show(
                this,
                compactBody(msg, 220),
                burp.ui.ToastManager.Level.WARNING
        ));
    }

    private void showOAuthError(String message) {
        final String msg = message == null ? "OAuth error." : message;
        try {
            importer.getApi().logging().logToError("[OAuth] " + msg);
        } catch (Exception ignore) {}
        SwingUtilities.invokeLater(() -> burp.ui.ToastManager.show(
                this,
                compactBody(msg, 220),
                burp.ui.ToastManager.Level.ERROR
        ));
    }

    private static String buildOAuthFailureMessage(int status, String body) {
        StringBuilder msg = new StringBuilder("OAuth token fetch failed (HTTP ");
        msg.append(status).append(").");
        if (body != null && !body.trim().isEmpty()) {
            msg.append("\n\nResponse:\n").append(compactBody(body, 700));
        }
        return msg.toString();
    }

    private static String compactBody(String body, int maxLen) {
        if (body == null) return "";
        String compact = body.replace('\r', ' ').replace('\n', ' ').trim();
        if (compact.length() <= maxLen) return compact;
        return compact.substring(0, Math.max(0, maxLen)) + "...";
    }

    private void cacheTokenForSelectedConfig(String token) {
        if (token == null || token.trim().isEmpty()) return;
        OAuth2Config selectedCfg = null;
        try {
            selectedCfg = (OAuth2Config) oauthConfigCombo.getSelectedItem();
        } catch (Exception ignore) {}
        if (selectedCfg == null) {
            selectedCfg = authManager.getPreferredOAuth2Config();
        }
        if (selectedCfg == null) return;
        try {
            if (selectedCfg.rawAttributes == null) {
                selectedCfg.rawAttributes = new java.util.LinkedHashMap<>();
            }
            selectedCfg.rawAttributes.put("accessToken", token.trim());
        } catch (Exception ignore) {}
    }

    // ✅ FIXED — NO DUPLICATE ANALYSIS
    private boolean runAuthAnalysis() {
        try {
            File collectionFile = importer.getSelectedCollection();
            File environmentFile = importer.getSelectedEnvironment();

            if (collectionFile == null) {
                showOAuthWarning("Select a collection first.");
                return false;
            }

            // If the user has a collection/folder scoped (clicked it in the
            // tree), restrict this Analyze run to that wrapper so we don't
            // fire requests from other collections in the workspace.
            String scopeTop = null;
            if (scopeFilterPath != null && !scopeFilterPath.isEmpty()) {
                int slash = scopeFilterPath.indexOf('/');
                scopeTop = slash >= 0 ? scopeFilterPath.substring(0, slash) : scopeFilterPath;
            }
            // Only force a strict scope when scopeTop matches an ACTUAL collection
            // wrapper. Otherwise (workspace root selected, no selection, etc.)
            // leave scope unset so analyzeAuthFromFiles can multi-loop through
            // every pending wrapper in its own private scope.
            String matchedWrapper = null;
            try {
                burp.models.PostmanCollection cc = importer.getCurrentCollection();
                if (scopeTop != null && cc != null && cc.item != null) {
                    for (burp.models.PostmanCollection.Item w : cc.item) {
                        if (w != null && w.isCollectionWrapper && scopeTop.equals(w.name)) {
                            matchedWrapper = w.name; break;
                        }
                    }
                }
            } catch (Exception ignore) {}
            importer.setAnalyzeScope(matchedWrapper);
            try {
                importer.analyzeAuthFromFiles(collectionFile, environmentFile);
            } finally {
                importer.setAnalyzeScope(null);
            }
            return true;

        } catch (Exception ex) {
            showOAuthError("Auth analysis failed: " + ex.getMessage());
            return false;
        }
    }

    // ✅ UI UPDATE (STATIC JWT FIXED)
    public void updateJwtDetection(
            List<JwtEndpointCandidate> jwt,
            List<String> staticTokens) {

        jwtData = jwt;
        repopulateTable();

        // ✅ OAuth dropdown refresh
        oauthConfigCombo.removeAllItems();
        List<OAuth2Config> configs = authManager.getOAuth2Configs();
        if (configs != null) {
            for (OAuth2Config c : configs) {
                oauthConfigCombo.addItem(c);
            }
        }
        autoSelectOAuthConfigForContext();
        refreshTokenStatus();
    }

    /**
     * Called by ImporterPanel whenever a request node is focused so Auth Manager
     * can auto-map OAuth2 Config to the closest detected path/endpoint.
     */
    public void setRequestContext(String requestPath, String endpoint, String method) {
        this.currentRequestPath = stripSyntheticRoot(normalizePath(requestPath));
        this.currentRequestEndpoint = endpoint == null ? null : endpoint.trim();
        this.currentRequestMethod = method == null ? null : method.trim();
        autoSelectOAuthConfigForContext();
    }

    /**
     * Restrict the candidate table to endpoints under the given tree-node path
     * (collection name or "Collection/Subfolder/..."). Pass null or empty to
     * show every detected endpoint across all imported collections.
     */
    private String scopeFilterPath = null;
    private String lastScopeFilter = null;
    public void setScopeFilter(String path) {
        String normalizedPath = stripSyntheticRoot(normalizePath(path));
        this.scopeFilterPath = (normalizedPath == null || normalizedPath.isEmpty()) ? null : normalizedPath;
        if (this.scopeFilterPath != null) {
            this.lastScopeFilter = this.scopeFilterPath;
        }
        repopulateTable();
        refreshAnalyzeButtonForScope();
        // Update the toggle button label/tooltip
        if (clearScopeBtn != null) {
            if (this.scopeFilterPath != null) {
                clearScopeBtn.setText("Clear Filter");
                clearScopeBtn.setToolTipText("Clear the collection/folder filter and show every detected endpoint");
            } else if (this.lastScopeFilter != null) {
                clearScopeBtn.setText("Filter");
                clearScopeBtn.setToolTipText("Re-apply previous filter: " + this.lastScopeFilter);
            } else {
                clearScopeBtn.setText("Clear Filter");
                clearScopeBtn.setToolTipText("No filter active");
            }
        }
    }

    /** Update the Analyze button's label/state based on whether the
     *  currently-scoped collection has been analyzed. */
    public void refreshAnalyzeButtonForScope() {
        if (analyzeButton == null) return;
        try {
            String top = scopeFilterPath;
            if (top != null && top.contains("/")) top = top.substring(0, top.indexOf('/'));
            boolean analyzed = false;
            burp.models.PostmanCollection cc = importer.getCurrentCollection();
            if (top != null && cc != null && cc.item != null) {
                for (burp.models.PostmanCollection.Item it : cc.item) {
                    if (it != null && it.isCollectionWrapper && top.equals(it.name)) {
                        analyzed = it.analyzed; break;
                    }
                }
            } else if (top == null && cc != null && cc.item != null) {
                // No scope = workspace overview; show neutral state.
                boolean any = false; boolean allAnalyzed = true;
                for (burp.models.PostmanCollection.Item it : cc.item) {
                    if (it != null && it.isCollectionWrapper) {
                        any = true;
                        if (!it.analyzed) { allAnalyzed = false; break; }
                    }
                }
                analyzed = any && allAnalyzed;
            }
            final boolean isAnalyzed = analyzed;
            SwingUtilities.invokeLater(() -> {
                analyzeButton.setEnabled(true);
                if (isAnalyzed) {
                    analyzeButton.setText("Analyzed ✓");
                    analyzeButton.setToolTipText("Click to re-analyze this collection");
                } else {
                    analyzeButton.setText("Analyze");
                    analyzeButton.setToolTipText("Scan the loaded collection for OAuth2/JWT auth endpoints");
                }
            });
        } catch (Exception ignore) {}
    }

    private void adaptCompactLayout() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::adaptCompactLayout);
            return;
        }
        try {
            if (tokenSourcesSplit != null) {
                int h = Math.max(1, tokenSourcesSplit.getHeight());
                if (h > 1) {
                    int scriptRows = visibleScriptJwtData == null ? 0 : visibleScriptJwtData.size();
                    int rowHeight = scriptJwtTable == null ? 18 : Math.max(16, scriptJwtTable.getRowHeight());
                    int targetBottom = (scriptRows <= 0)
                            ? 66
                            : Math.min(170, 56 + (Math.min(scriptRows, 4) * rowHeight));
                    int cur = tokenSourcesSplit.getDividerLocation();
                    int bottom = h - Math.max(0, cur);
                    int minBottom = Math.max(52, targetBottom - 10);
                    int maxBottom = targetBottom + 26;
                    if (cur <= 0 || bottom < minBottom || bottom > maxBottom) {
                        int desiredDivider = Math.max(90, h - targetBottom);
                        tokenSourcesSplit.setDividerLocation(desiredDivider);
                    }
                }
            }
        } catch (Exception ignore) {}

        try {
            if (authMainSplit != null) {
                int w = Math.max(1, authMainSplit.getWidth());
                if (w > 1) {
                    int tokenMin = w < 900 ? 210 : 230;
                    int tokenMax = w < 900 ? 300 : 340;
                    int targetToken = w < 900 ? 240 : 280;
                    int cur = authMainSplit.getDividerLocation();
                    int rightWidth = w - Math.max(0, cur);
                    if (cur <= 0 || rightWidth < tokenMin || rightWidth > tokenMax) {
                        int desiredDivider = Math.max(220, w - targetToken);
                        authMainSplit.setDividerLocation(desiredDivider);
                    }
                }
            }
        } catch (Exception ignore) {}
    }

    /**
     * Keep the token card compact (top-aligned) so the Auth Manager right pane
     * does not render as a stretched, malformed bordered block on tall windows.
     */
    private JPanel buildTokenRightHost(JPanel tokenPanel) {
        tokenRightHost = new JPanel(new BorderLayout());
        tokenRightHost.setOpaque(false);
        tokenRightHost.add(tokenPanel, BorderLayout.NORTH);
        JPanel filler = new JPanel();
        filler.setOpaque(false);
        tokenRightHost.add(filler, BorderLayout.CENTER);
        return tokenRightHost;
    }

    private void clearCheckedRows(javax.swing.table.DefaultTableModel model, int keepRow) {
        if (model == null) return;
        for (int i = 0; i < model.getRowCount(); i++) {
            if (i == keepRow) continue;
            Object v = model.getValueAt(i, 0);
            if (Boolean.TRUE.equals(v)) {
                model.setValueAt(Boolean.FALSE, i, 0);
            }
        }
    }

    private boolean hasCheckedTokenSource() {
        return hasCheckedRow(jwtModel) || hasCheckedRow(scriptJwtModel);
    }

    private static boolean hasCheckedRow(javax.swing.table.DefaultTableModel model) {
        if (model == null) return false;
        for (int i = 0; i < model.getRowCount(); i++) {
            if (Boolean.TRUE.equals(model.getValueAt(i, 0))) return true;
        }
        return false;
    }

    private void updateScriptPreviewForSelection(int row) {
        if (scriptPreviewButton == null) return;
        scriptPreviewButton.setEnabled(row >= 0 && row < visibleScriptJwtData.size());
    }

    private void openScriptPreviewForSelectedRow() {
        int row = scriptJwtTable == null ? -1 : scriptJwtTable.getSelectedRow();
        if (row < 0 || row >= visibleScriptJwtData.size()) {
            burp.ui.ToastManager.show(this,
                    "Select a script token-source row first.",
                    burp.ui.ToastManager.Level.INFO);
            return;
        }
        openScriptPreviewPopup(row);
    }

    private void openScriptPreviewPopup(int row) {
        if (row < 0 || row >= visibleScriptJwtData.size()) return;
        JwtEndpointCandidate c = visibleScriptJwtData.get(row);
        String script = c == null ? "" : c.scriptSource;
        String scriptText = (script == null || script.trim().isEmpty())
                ? "(Script source not captured for this row)"
                : script;
        String requestText = formatTranslatedRequest(c == null ? null : c.request);
        String titleTarget = c == null ? ""
                : (c.method == null ? "" : c.method + " ") + candidateDisplayEndpoint(c, true);

        JTextArea scriptArea = new JTextArea(scriptText);
        scriptArea.setEditable(false);
        scriptArea.setLineWrap(false);
        scriptArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JTextArea translatedArea = new JTextArea(requestText);
        translatedArea.setEditable(false);
        translatedArea.setLineWrap(false);
        translatedArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JScrollPane scriptScroll = new JScrollPane(scriptArea);
        scriptScroll.setBorder(BorderFactory.createTitledBorder("Script"));
        scriptScroll.getVerticalScrollBar().setUnitIncrement(14);
        scriptScroll.getHorizontalScrollBar().setUnitIncrement(14);

        JScrollPane translatedScroll = new JScrollPane(translatedArea);
        translatedScroll.setBorder(BorderFactory.createTitledBorder("Translated Request"));
        translatedScroll.getVerticalScrollBar().setUnitIncrement(14);
        translatedScroll.getHorizontalScrollBar().setUnitIncrement(14);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, scriptScroll, translatedScroll);
        split.setResizeWeight(0.5);
        split.setDividerLocation(0.5);
        split.setOneTouchExpandable(true);

        Window owner = SwingUtilities.getWindowAncestor(this);
        JDialog dlg = new JDialog(owner, "Script token source preview", Dialog.ModalityType.MODELESS);
        dlg.setLayout(new BorderLayout(6, 6));
        dlg.add(split, BorderLayout.CENTER);

        JLabel target = new JLabel(titleTarget.isEmpty() ? "Selected script token source" : titleTarget);
        target.setBorder(BorderFactory.createEmptyBorder(6, 8, 0, 8));
        dlg.add(target, BorderLayout.NORTH);

        JButton close = burp.ui.UITheme.button("Close", burp.ui.UITheme.BtnStyle.GHOST);
        close.addActionListener(e -> dlg.dispose());
        JPanel south = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 6));
        south.add(close);
        dlg.add(south, BorderLayout.SOUTH);

        Dimension screen = Toolkit.getDefaultToolkit().getScreenSize();
        int targetW = Math.max(760, Math.min(980, screen.width - 120));
        int targetH = Math.max(400, Math.min(520, screen.height - 160));
        dlg.setSize(targetW, targetH);
        dlg.setMinimumSize(new Dimension(700, 380));
        dlg.setLocationRelativeTo(owner == null ? this : owner);
        dlg.setVisible(true);
    }

    private static String formatTranslatedRequest(PostmanCollection.Request req) {
        if (req == null) return "(No translated request)";
        StringBuilder sb = new StringBuilder();
        String method = req.method == null || req.method.trim().isEmpty() ? "GET" : req.method.trim().toUpperCase(java.util.Locale.ROOT);
        String url = req.rawUrlTemplate;
        if (url == null || url.trim().isEmpty()) {
            url = req.url == null ? "" : req.url.toString();
        }
        sb.append(method).append(' ').append(url == null ? "" : url).append('\n');

        if (req.header != null && !req.header.isEmpty()) {
            sb.append("\nHeaders:\n");
            for (PostmanCollection.Header h : req.header) {
                if (h == null || h.disabled || h.key == null || h.key.trim().isEmpty()) continue;
                sb.append(h.key).append(": ").append(h.value == null ? "" : h.value).append('\n');
            }
        }

        if (req.body != null) {
            PostmanCollection.Body b = req.body;
            sb.append("\nBody mode: ").append(b.mode == null ? "(none)" : b.mode).append('\n');
            if (b.raw != null && !b.raw.trim().isEmpty()) {
                sb.append("\nRaw:\n").append(b.raw).append('\n');
            }
            if (b.urlencoded != null && !b.urlencoded.isEmpty()) {
                sb.append("\nurlencoded:\n");
                for (PostmanCollection.UrlEncoded ue : b.urlencoded) {
                    if (ue == null || ue.disabled || ue.key == null || ue.key.trim().isEmpty()) continue;
                    sb.append(ue.key).append('=').append(ue.value == null ? "" : ue.value).append('\n');
                }
            }
            if (b.formdata != null && !b.formdata.isEmpty()) {
                sb.append("\nformdata:\n");
                for (PostmanCollection.FormData fd : b.formdata) {
                    if (fd == null || fd.disabled || fd.key == null || fd.key.trim().isEmpty()) continue;
                    sb.append(fd.key).append('=').append(fd.value == null ? "" : fd.value);
                    if (fd.type != null && !fd.type.trim().isEmpty()) {
                        sb.append(" (").append(fd.type).append(')');
                    }
                    sb.append('\n');
                }
            }
        }
        return sb.toString().trim();
    }

    private static String candidateDisplayEndpoint(JwtEndpointCandidate c, boolean preferTemplate) {
        if (c == null) return "";
        String resolved = c.url == null ? "" : c.url.trim();
        String raw = "";
        if (c.request != null) {
            if (c.request.rawUrlTemplate != null) {
                raw = c.request.rawUrlTemplate.trim();
            }
            if (raw.isEmpty() && c.request.url != null) {
                raw = c.request.url.toString().trim();
            }
        }
        if (preferTemplate && !raw.isEmpty()) return raw;
        if (!raw.isEmpty() && raw.contains("{{")) return raw;
        if (!resolved.isEmpty()) return resolved;
        return raw;
    }

    private static boolean isScriptCandidate(JwtEndpointCandidate c) {
        if (c == null) return false;
        if (c.fromScriptSendRequest) return true;
        if (c.scriptSource != null && !c.scriptSource.trim().isEmpty()) return true;
        String conf = c.confidence == null ? "" : c.confidence.trim().toUpperCase(java.util.Locale.ROOT);
        return conf.contains("SCRIPT");
    }

    private void repopulateTable() {
        if (jwtModel == null) return;
        jwtModel.setRowCount(0);
        visibleJwtData.clear();
        if (scriptJwtModel != null) scriptJwtModel.setRowCount(0);
        visibleScriptJwtData.clear();
        if (jwtData == null) return;
        int shown = 0, total = jwtData.size();
        for (JwtEndpointCandidate c : jwtData) {
            if (scopeFilterPath != null) {
                String p = c.path == null ? "" : c.path;
                // c.path is "Collection/Folder/.../RequestName" while the
                // scope filter is "Collection" or "Collection/Folder".
                // Match if the candidate path equals or is a descendant of
                // the filter path.
                if (!(p.equals(scopeFilterPath) || p.startsWith(scopeFilterPath + "/"))) {
                    continue;
                }
            }
            String folderOnly = c.path == null ? "" : c.path;
            int slash = folderOnly.lastIndexOf('/');
            if (slash >= 0) folderOnly = folderOnly.substring(0, slash);
            else folderOnly = "";
            Object[] row = new Object[]{
                    Boolean.FALSE,
                    c.collectionName == null ? "" : c.collectionName,
                    folderOnly,
                    candidateDisplayEndpoint(c, false),
                    c.method,
                    c.confidence
            };
            if (isScriptCandidate(c)) {
                if (scriptJwtModel != null) {
                    scriptJwtModel.addRow(new Object[]{
                            Boolean.FALSE,
                            c.collectionName == null ? "" : c.collectionName,
                            folderOnly,
                            candidateDisplayEndpoint(c, true),
                            c.method
                    });
                }
                visibleScriptJwtData.add(c);
            } else {
                jwtModel.addRow(row);
                visibleJwtData.add(c);
            }
            shown++;
        }
        updateScriptPreviewForSelection(-1);
        if (scopeLabel != null) {
            if (scopeFilterPath == null) {
                scopeLabel.setText("Scope: All collections (" + total + " endpoints)");
            } else {
                scopeLabel.setText("Scope: " + scopeFilterPath
                        + " (" + shown + " of " + total + " endpoints)");
            }
            scopeLabel.setToolTipText(scopeLabel.getText());
        }
        adaptCompactLayout();
    }

    private void autoSelectOAuthConfigForContext() {
        if (oauthConfigCombo == null) return;
        int count = oauthConfigCombo.getItemCount();
        if (count <= 0) return;

        String contextPath = getContextPathForOAuthSelection();
        String contextTop = topSegment(contextPath);
        OAuth2Config best = findBestOAuthConfig();
        if (best == null) {
            OAuth2Config preferred = authManager.getPreferredOAuth2Config();
            if (preferred != null) {
                String prefPath = normalizePath(preferred.path);
                if (contextTop == null || sameTopScope(prefPath, contextTop)) {
                    best = preferred;
                }
            }
            if (best == null) {
                best = firstConfigForTopScope(contextTop);
            }
            if (best == null && count > 0) {
                best = oauthConfigCombo.getItemAt(0);
            }
        }
        if (best == null) return;

        suppressOAuthComboEvents = true;
        try {
            oauthConfigCombo.setSelectedItem(best);
        } finally {
            suppressOAuthComboEvents = false;
        }
        authManager.setPreferredOAuth2Config(best);
    }

    private OAuth2Config findBestOAuthConfig() {
        String reqPath = getContextPathForOAuthSelection();
        if (reqPath == null || reqPath.isEmpty()) return null;
        try {
            if (importer != null) {
                OAuth2Config scoped = importer.findOAuth2ConfigForPath(reqPath);
                if (scoped != null) return scoped;
            }
        } catch (Exception ignore) {}
        String reqTop = topSegment(reqPath);

        OAuth2Config exact = null;
        OAuth2Config bestPrefix = null;
        int bestPrefixLen = -1;

        for (int i = 0; i < oauthConfigCombo.getItemCount(); i++) {
            OAuth2Config cfg = oauthConfigCombo.getItemAt(i);
            if (cfg == null) continue;
            String cfgPath = normalizePath(cfg.path);
            if (cfgPath == null || cfgPath.isEmpty()) continue;
            if (!sameTopScope(cfgPath, reqTop)) continue;

            if (cfgPath.equalsIgnoreCase(reqPath)) {
                exact = cfg;
                break;
            }

            // Folder-level fallback: choose the deepest matching ancestor path.
            if (reqPath.startsWith(cfgPath + "/") && cfgPath.length() > bestPrefixLen) {
                bestPrefix = cfg;
                bestPrefixLen = cfgPath.length();
            }
        }
        if (exact != null) return exact;
        if (bestPrefix != null) return bestPrefix;

        // Last fallback: if the config name appears in request path, prefer it.
        for (int i = 0; i < oauthConfigCombo.getItemCount(); i++) {
            OAuth2Config cfg = oauthConfigCombo.getItemAt(i);
            if (cfg == null || cfg.name == null) continue;
            String cfgPath = normalizePath(cfg.path);
            if (!sameTopScope(cfgPath, reqTop)) continue;
            String name = cfg.name.trim();
            if (name.isEmpty()) continue;
            if (containsIgnoreCase(reqPath, name)) return cfg;
        }

        return null;
    }

    private String getContextPathForOAuthSelection() {
        String reqPath = normalizePath(currentRequestPath);
        if (reqPath != null && !reqPath.isEmpty()) return reqPath;
        String scopePath = normalizePath(scopeFilterPath);
        if (scopePath != null && !scopePath.isEmpty()) return scopePath;
        return null;
    }

    private OAuth2Config firstConfigForTopScope(String top) {
        if (oauthConfigCombo == null) return null;
        for (int i = 0; i < oauthConfigCombo.getItemCount(); i++) {
            OAuth2Config cfg = oauthConfigCombo.getItemAt(i);
            if (cfg == null) continue;
            String cfgPath = normalizePath(cfg.path);
            if (top == null || sameTopScope(cfgPath, top)) {
                return cfg;
            }
        }
        return null;
    }

    private static String topSegment(String path) {
        if (path == null || path.isEmpty()) return null;
        int slash = path.indexOf('/');
        return slash >= 0 ? path.substring(0, slash) : path;
    }

    private static boolean sameTopScope(String cfgPath, String top) {
        if (top == null || top.isEmpty()) return true;
        String cfgTop = topSegment(cfgPath);
        return cfgTop != null && cfgTop.equalsIgnoreCase(top);
    }

    private static boolean containsIgnoreCase(String haystack, String needle) {
        if (haystack == null || needle == null) return false;
        return haystack.toLowerCase(java.util.Locale.ROOT)
                .contains(needle.toLowerCase(java.util.Locale.ROOT));
    }

    private static String normalizePath(String path) {
        if (path == null) return null;
        String p = path.trim().replace('\\', '/');
        while (p.contains("//")) p = p.replace("//", "/");
        if (p.endsWith("/") && p.length() > 1) p = p.substring(0, p.length() - 1);
        return p;
    }

    private String stripSyntheticRoot(String path) {
        if (path == null || path.isEmpty()) return path;
        String root = "Workspace";
        try {
            if (importer != null && importer.getCurrentCollection() != null
                    && importer.getCurrentCollection().info != null
                    && importer.getCurrentCollection().info.name != null
                    && !importer.getCurrentCollection().info.name.trim().isEmpty()) {
                root = importer.getCurrentCollection().info.name.trim();
            }
        } catch (Exception ignore) {}
        boolean syntheticWorkspaceRoot = "Workspace".equalsIgnoreCase(root);
        if (!syntheticWorkspaceRoot) {
            try {
                burp.models.PostmanCollection current = importer == null ? null : importer.getCurrentCollection();
                if (current != null && current.item != null && !current.item.isEmpty()) {
                    boolean allWrapped = true;
                    for (burp.models.PostmanCollection.Item it : current.item) {
                        if (it != null && !it.isCollectionWrapper) {
                            allWrapped = false;
                            break;
                        }
                    }
                    syntheticWorkspaceRoot = allWrapped;
                }
            } catch (Exception ignore) {}
        }
        if (!syntheticWorkspaceRoot) return path;

        if (path.equalsIgnoreCase(root)) return "";
        String prefix = root + "/";
        if (path.regionMatches(true, 0, prefix, 0, prefix.length())) {
            return path.substring(prefix.length());
        }
        return path;
    }


    public void resetUI() {
        jwtModel.setRowCount(0);
        if (scriptJwtModel != null) scriptJwtModel.setRowCount(0);
        visibleJwtData.clear();
        visibleScriptJwtData.clear();
        jwtData = null;
        updateScriptPreviewForSelection(-1);

        oauthConfigCombo.removeAllItems();
        setToken("");
        reenableAnalyzeButton();
    }

    public JButton getAnalyzeButton() {
        return analyzeButton;
    }

    /** Re-enable the Analyze button after Auto Run completes/cancels, OR
     *  after a new collection has been appended so the user can re-scan. */
    public void reenableAnalyzeButton() {
        if (analyzeButton != null) {
            analyzeButton.setEnabled(true);
            analyzeButton.setText("Analyze");
            burp.ui.UITheme.apply(analyzeButton, burp.ui.UITheme.BtnStyle.SUCCESS);
            analyzeButton.setToolTipText("Scan the loaded collection for OAuth2/JWT auth endpoints");
        }
    }
}