package burp.ui;

import burp.PostmanImporter;
import burp.models.AnalyzedRequest;
import burp.models.CollectionTreeNode;
import burp.models.CollectionTreeNode.NodeType;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * Tree panel displaying collection hierarchy similar to Postman.
 * Supports selection and bulk actions on folders.
 */
public class CollectionTreePanel extends JPanel {

    private final PostmanImporter importer;
    private final JTree tree;
    private final JScrollPane treeScrollPane;
    private final JLabel statusLabel;
    private CollectionTreeNode rootNode;
    private JPopupMenu contextMenu;
    private TreePath contextMenuPath;

    /** Components revealed only when the Advanced Options toggle is on. */
    private JButton advancedCurlBtn;
    private JButton wsButton;
    private JPanel advancedMultiBox;

    /** The "+ Add Collection" toolbar button. Hidden until the user has loaded
     *  their first collection so newcomers use the Browse... control at the
     *  top instead of mistaking this button for it. Re-shown by
     *  {@link #loadCollection(CollectionTreeNode)} and hidden again by
     *  {@link #clearTree()}. */
    private JButton addCollectionBtn;

    /** Detach the cURL button from the tree toolbar and return it so the host
     *  can mount it in its own footer. Idempotent. */
    public JButton takeCurlButton() {
        if (advancedCurlBtn != null) {
            Container parent = advancedCurlBtn.getParent();
            if (parent != null) parent.remove(advancedCurlBtn);
            advancedCurlBtn.setVisible(true);
            JButton b = advancedCurlBtn;
            advancedCurlBtn = null; // so setAdvancedVisible() no-ops it
            revalidate();
            repaint();
            return b;
        }
        return null;
    }

    /** Detach the WS button from the tree toolbar. */
    public JButton takeWsButton() {
        if (wsButton != null) {
            Container parent = wsButton.getParent();
            if (parent != null) parent.remove(wsButton);
            wsButton.setVisible(true);
            JButton b = wsButton;
            wsButton = null;
            revalidate();
            repaint();
            return b;
        }
        return null;
    }

    /** Detach the Multi toggle box from the tree header. */
    public JPanel takeMultiBox() {
        if (advancedMultiBox != null) {
            Container parent = advancedMultiBox.getParent();
            if (parent != null) parent.remove(advancedMultiBox);
            advancedMultiBox.setVisible(true);
            JPanel p = advancedMultiBox;
            advancedMultiBox = null;
            revalidate();
            repaint();
            return p;
        }
        return null;
    }

    /** Show/hide power-user controls (Multi toggle, cURL import button). Driven
     *  by the host {@code ImporterPanel}'s Advanced Options footer toggle. */
    public void setAdvancedVisible(boolean show) {
        if (advancedCurlBtn != null) advancedCurlBtn.setVisible(show);
        if (advancedMultiBox != null) advancedMultiBox.setVisible(show);
        revalidate();
        repaint();
    }

    public CollectionTreePanel(PostmanImporter importer) {
        this.importer = importer;
        this.setLayout(new BorderLayout(0, 0));
        this.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
        this.setBackground(UITheme.surface());

        // Initial empty tree
        tree = new JTree();
        clearTree();

        tree.setCellRenderer(new TreeCellRenderer());
        tree.setRootVisible(true);
        tree.setShowsRootHandles(true);
        tree.setRowHeight(22);
        tree.setBackground(UITheme.surface());
        tree.setForeground(UITheme.foreground());
        tree.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        setupContextMenu();
        tree.addMouseListener(new TreeMouseListener());

        // Drag-and-drop reordering of tree nodes (folders/requests)
        try {
            tree.setDragEnabled(true);
            tree.setDropMode(DropMode.ON_OR_INSERT);
            tree.setTransferHandler(new CollectionTreeTransferHandler(this));
        } catch (Throwable t) {
            System.err.println("[CollectionTreePanel] DnD setup failed: " + t);
        }

        JScrollPane scrollPane = new JScrollPane(tree);
        this.treeScrollPane = scrollPane;
        scrollPane.setPreferredSize(new Dimension(280, 400));
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.getViewport().setBackground(UITheme.surface());
        scrollPane.getVerticalScrollBar().setUnitIncrement(14);
        scrollPane.getHorizontalScrollBar().setUnitIncrement(14);
        installIndependentWheelScrolling(tree, scrollPane);

        statusLabel = new JLabel("No collection loaded");
        statusLabel.setFont(UITheme.baseFont().deriveFont(11f));
        statusLabel.setForeground(UITheme.subtleText());
        statusLabel.setBorder(BorderFactory.createEmptyBorder(4, 10, 6, 10));

        JLabel headerLabel = new JLabel("Collections");
        headerLabel.setFont(UITheme.boldFont(13f));
        headerLabel.setForeground(UITheme.foreground());

        // 🔍 Global search button + Ctrl+F shortcut.
        JButton searchBtn = UITheme.button("🔍", UITheme.BtnStyle.GHOST);
        searchBtn.setToolTipText("Find any request by name / URL / method (Ctrl+F)");
        searchBtn.setMargin(new java.awt.Insets(2, 6, 2, 6));
        searchBtn.setFocusable(false);
        searchBtn.addActionListener(e -> openSearchDialog());
        // Bind Ctrl+F at the tree-panel level (WHEN_IN_FOCUSED_WINDOW so it
        // works no matter which sub-component currently has focus).
        getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
                KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_F,
                        java.awt.Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()),
                "burpman-search");
        getActionMap().put("burpman-search", new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent e) { openSearchDialog(); }
        });

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.setBackground(UITheme.surfaceAlt());
        topPanel.setOpaque(true);
        topPanel.setBorder(BorderFactory.createEmptyBorder(8, 10, 6, 10));
        topPanel.add(headerLabel, BorderLayout.WEST);

        // Header right side gets the search button (Multi toggle added later).

        // "Multi" toggle — advanced-only.
        final JLabel multiLabel = new JLabel("Multi ");
        multiLabel.setFont(UITheme.baseFont().deriveFont(11f));
        multiLabel.setForeground(UITheme.subtleText());
        final IosToggleSwitch multiToggle = new IosToggleSwitch(true);
        multiToggle.setToolTipText(
            "<html>When ON: Ctrl/Shift-click selects multiple requests/folders for bulk actions.<br/>"
          + "When OFF: only one item can be selected at a time.</html>");
        multiToggle.addChangeListener(e -> {
            tree.getSelectionModel().setSelectionMode(multiToggle.isOn()
                ? javax.swing.tree.TreeSelectionModel.DISCONTIGUOUS_TREE_SELECTION
                : javax.swing.tree.TreeSelectionModel.SINGLE_TREE_SELECTION);
        });
        tree.getSelectionModel().setSelectionMode(
            javax.swing.tree.TreeSelectionModel.DISCONTIGUOUS_TREE_SELECTION);

        JPanel multiBox = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        multiBox.setOpaque(false);
        multiBox.add(multiLabel);
        multiBox.add(multiToggle);
        multiBox.setVisible(false);
        this.advancedMultiBox = multiBox;
        topPanel.add(multiBox, BorderLayout.EAST);

        // "+ Add Collection" button — themed accent
        JButton addCollectionBtn = UITheme.button("+ Add Collection", UITheme.BtnStyle.ACCENT);
        addCollectionBtn.setToolTipText("Append another Postman/Bruno collection (file or folder) into this workspace.");
        addCollectionBtn.addActionListener(e -> promptAddCollection());
        // Hidden by default so first-time users use the Browse... field above
        // to load their initial collection. Revealed by loadCollection() once
        // something is on the tree, then hidden again by clearTree().
        addCollectionBtn.setVisible(false);
        this.addCollectionBtn = addCollectionBtn;

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 4));
        toolbar.setOpaque(true);
        toolbar.setBackground(UITheme.surfaceAlt());
        toolbar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, UITheme.border()),
                BorderFactory.createEmptyBorder(4, 6, 6, 6)));
        toolbar.add(addCollectionBtn);
        toolbar.add(searchBtn);

        JButton curlBtn = UITheme.button("📥 cURL", UITheme.BtnStyle.GHOST);
        curlBtn.setToolTipText("Import a request from a curl command (paste from docs / DevTools / Postman)");
        curlBtn.addActionListener(e -> openCurlImporter());
        curlBtn.setVisible(false);
        this.advancedCurlBtn = curlBtn;
        toolbar.add(curlBtn);

        JButton wsBtn = UITheme.button("🌐 WS", UITheme.BtnStyle.GHOST);
        wsBtn.setToolTipText("Open the WebSocket client (connect to ws:// or wss:// endpoints)");
        wsBtn.addActionListener(e -> burp.ui.WebSocketDialog.show(this));
        this.wsButton = wsBtn;
        toolbar.add(wsBtn);

        JPanel north = new JPanel(new BorderLayout());
        north.add(topPanel, BorderLayout.NORTH);
        north.add(toolbar, BorderLayout.SOUTH);

        this.add(north, BorderLayout.NORTH);
        this.add(scrollPane, BorderLayout.CENTER);
        this.add(statusLabel, BorderLayout.SOUTH);
    }

    private static void installIndependentWheelScrolling(JComponent wheelTarget, JScrollPane owner) {
        if (wheelTarget == null || owner == null) return;
        wheelTarget.addMouseWheelListener(e -> {
            JScrollBar bar = e.isShiftDown() ? owner.getHorizontalScrollBar() : owner.getVerticalScrollBar();
            if (bar == null || !bar.isVisible()) {
                // Keep wheel events inside the tree region so parent workspace
                // scroll panes don't steal scrolling while hovering the tree.
                e.consume();
                return;
            }
            int units = e.getUnitsToScroll();
            if (units == 0) {
                e.consume();
                return;
            }
            int direction = units > 0 ? 1 : -1;
            int increment = bar.getUnitIncrement(direction);
            if (increment <= 0) increment = 16;
            int delta = units * increment;
            int min = bar.getMinimum();
            int max = Math.max(min, bar.getMaximum() - bar.getVisibleAmount());
            int next = Math.max(min, Math.min(max, bar.getValue() + delta));
            if (next != bar.getValue()) {
                bar.setValue(next);
            }
            e.consume();
        });
    }

    /** Open the cURL importer; on accept, add the parsed request as a new
     *  child of the currently-selected folder (or the root collection if no
     *  folder selected), then rebuild the tree. */
    private void openCurlImporter() {
        burp.ui.CurlImportDialog.show(this, req -> {
            try {
                burp.models.PostmanCollection.Item leaf = new burp.models.PostmanCollection.Item();
                leaf.name = deriveNameFromRequest(req);
                leaf.request = req;

                // Where to insert?
                java.util.List<burp.models.PostmanCollection.Item> parent;
                TreePath path = tree.getSelectionPath();
                if (path != null && path.getLastPathComponent() instanceof CollectionTreeNode) {
                    parent = parentItemList((CollectionTreeNode) path.getLastPathComponent());
                } else {
                    burp.models.PostmanCollection coll =
                            importer == null ? null : importer.getCurrentCollection();
                    if (coll == null) {
                        JOptionPane.showMessageDialog(this,
                                "Load a collection first (or create one via Add Collection).");
                        return;
                    }
                    if (coll.item == null) coll.item = new java.util.ArrayList<>();
                    parent = coll.item;
                }
                if (parent == null) return;
                parent.add(leaf);
                rebuildAndKeepSelection(leaf.name);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                        "Failed to add request: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        });
    }

    /** Build a friendly request name from method + path (last segment). */
    private static String deriveNameFromRequest(burp.models.PostmanCollection.Request req) {
        if (req == null) return "Imported request";
        String method = req.method == null ? "GET" : req.method;
        String url = req.url == null ? "" : req.url.toString();
        try {
            java.net.URI u = new java.net.URI(url);
            String p = u.getPath();
            if (p != null && !p.isEmpty() && !p.equals("/")) {
                String last = p;
                int slash = p.lastIndexOf('/', p.length() - 2);
                if (slash >= 0) last = p.substring(slash + 1);
                if (last.endsWith("/")) last = last.substring(0, last.length() - 1);
                if (!last.isEmpty()) return method + " " + last;
            }
            if (u.getHost() != null) return method + " " + u.getHost();
        } catch (Exception ignore) {}
        return method + " request";
    }

    /** Open the global search dialog and route the chosen request through
     *  the existing tree-click listener so the request loads normally. */
    private void openSearchDialog() {
        burp.ui.GlobalSearchDialog.show(this, importer, request -> {
            if (request == null) return;
            // Try to find the matching tree node so the tree highlights the result.
            try {
                javax.swing.tree.TreeModel m = tree.getModel();
                java.util.Enumeration<?> enumeration =
                        ((javax.swing.tree.DefaultMutableTreeNode) m.getRoot()).depthFirstEnumeration();
                while (enumeration.hasMoreElements()) {
                    Object n = enumeration.nextElement();
                    if (n instanceof CollectionTreeNode) {
                        CollectionTreeNode node = (CollectionTreeNode) n;
                        AnalyzedRequest r = node.getRequest();
                        if (r != null && r.getRequest() == request.getRequest()) {
                            TreePath p = new TreePath(node.getPath());
                            tree.setSelectionPath(p);
                            tree.scrollPathToVisible(p);
                            handleRequestClick(node);
                            return;
                        }
                    }
                }
            } catch (Throwable ignore) {}
            // Fall back: open directly through the requestNodeClickListener with no clicked node.
            if (requestNodeClickListener != null) {
                requestNodeClickListener.onRequestNodeClicked(request, null);
            }
        });
    }

    /** Hook fired when the user clicks the inline + Add Collection button. */
    public interface AddCollectionListener { void onAddCollection(); }
    public interface ImportEnvironmentListener { void onImportEnvironment(); }
    public interface CreateEmptyCollectionListener { void onCreateEmptyCollection(); }
    private AddCollectionListener addCollectionListener;
    private ImportEnvironmentListener importEnvironmentListener;
    private CreateEmptyCollectionListener createEmptyCollectionListener;
    public void setAddCollectionListener(AddCollectionListener l) { this.addCollectionListener = l; }
    public void setImportEnvironmentListener(ImportEnvironmentListener l) { this.importEnvironmentListener = l; }
    public void setCreateEmptyCollectionListener(CreateEmptyCollectionListener l) { this.createEmptyCollectionListener = l; }
    private void promptAddCollection() {
        if (addCollectionListener != null) {
            addCollectionListener.onAddCollection();
        } else {
            JOptionPane.showMessageDialog(this,
                    "Add-collection handler not wired yet.", "Unavailable",
                    JOptionPane.WARNING_MESSAGE);
        }
    }

    private void promptImportEnvironment() {
        if (importEnvironmentListener != null) {
            importEnvironmentListener.onImportEnvironment();
        } else {
            JOptionPane.showMessageDialog(this,
                    "Environment import handler not wired yet.", "Unavailable",
                    JOptionPane.WARNING_MESSAGE);
        }
    }

    private void promptCreateEmptyCollection() {
        if (createEmptyCollectionListener != null) {
            createEmptyCollectionListener.onCreateEmptyCollection();
        } else {
            JOptionPane.showMessageDialog(this,
                    "Create-empty-collection handler not wired yet.", "Unavailable",
                    JOptionPane.WARNING_MESSAGE);
        }
    }

    /**
     * iOS-style sliding switch: green pill (ON) / gray pill (OFF) with a white
     * circle that slides between the two ends.
     */
    public static class IosToggleSwitch extends JComponent {
        private boolean on;
        private final java.util.List<javax.swing.event.ChangeListener> listeners = new java.util.ArrayList<>();
        private static final java.awt.Color ON_COLOR  = new java.awt.Color(46, 184, 92);
        private static final java.awt.Color OFF_COLOR = new java.awt.Color(189, 189, 189);

        public IosToggleSwitch(boolean initial) {
            this.on = initial;
            setPreferredSize(new Dimension(40, 22));
            setMinimumSize(new Dimension(40, 22));
            setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR));
            addMouseListener(new java.awt.event.MouseAdapter() {
                @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                    setOn(!on);
                }
            });
        }

        public boolean isOn() { return on; }

        public void setOn(boolean v) {
            if (this.on == v) return;
            this.on = v;
            repaint();
            javax.swing.event.ChangeEvent evt = new javax.swing.event.ChangeEvent(this);
            for (javax.swing.event.ChangeListener l : listeners) l.stateChanged(evt);
        }

        public void addChangeListener(javax.swing.event.ChangeListener l) { listeners.add(l); }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int w = getWidth();
            int h = getHeight();
            int arc = h;
            g2.setColor(on ? ON_COLOR : OFF_COLOR);
            g2.fillRoundRect(0, 0, w, h, arc, arc);
            int knobD = h - 4;
            int knobX = on ? (w - knobD - 2) : 2;
            int knobY = 2;
            g2.setColor(java.awt.Color.WHITE);
            g2.fillOval(knobX, knobY, knobD, knobD);
            g2.setColor(new java.awt.Color(0, 0, 0, 30));
            g2.drawOval(knobX, knobY, knobD, knobD);
            g2.dispose();
        }
    }

    /**
     * Load and display a collection tree
     */
    public void loadCollection(CollectionTreeNode root) {
        this.rootNode = root;

        if (root == null) {
            clearTree();
            statusLabel.setText("No collection loaded");
            return;
        }

        tree.setModel(new DefaultTreeModel(root));

        expandNode(root, 1);

        int requestCount = root.getAllRequests().size();
        statusLabel.setText(requestCount + " requests");

        // Reveal the "+ Add Collection" toolbar button now that there is
        // already something on the tree — users adding a second workspace
        // are the ones who need it. Hidden in clearTree() and on init.
        if (addCollectionBtn != null) {
            addCollectionBtn.setVisible(true);
        }
    }

    /**
     * Reset tree to empty state with a friendly call-to-action.
     */
    public void clearTree() {
        DefaultMutableTreeNode emptyRoot =
                new DefaultMutableTreeNode("📁  Click \"Browse…\" above to load a Postman or Bruno collection");

        tree.setModel(new DefaultTreeModel(emptyRoot));
        this.rootNode = null;
        if (statusLabel != null) {
            statusLabel.setText("No collection loaded");
        }
        // Return to the empty state — hide "+ Add Collection" so users know
        // to use the Browse... field above to load their first collection.
        if (addCollectionBtn != null) {
            addCollectionBtn.setVisible(false);
        }
    }

    /**
     * Expand nodes up to a certain depth
     */
    private void expandNode(CollectionTreeNode node, int depth) {
        if (depth <= 0) return;

        TreePath path = new TreePath(node.getPath());
        tree.expandPath(path);

        for (int i = 0; i < node.getChildCount(); i++) {
            CollectionTreeNode child = (CollectionTreeNode) node.getChildAt(i);
            expandNode(child, depth - 1);
        }
    }

    /**
     * Setup right-click context menu
     */
    private void setupContextMenu() {
        contextMenu = new JPopupMenu();
        contextMenu.addPopupMenuListener(new javax.swing.event.PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent e) { }

            @Override
            public void popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent e) {
                contextMenuPath = null;
            }

            @Override
            public void popupMenuCanceled(javax.swing.event.PopupMenuEvent e) {
                contextMenuPath = null;
            }
        });

        JMenu sendTo = new JMenu("Send to");
        JMenuItem sendRequest = new JMenuItem("Repeater (with Auth)");
        sendRequest.addActionListener(e -> sendSelectedTo(Tool.REPEATER, true));
        sendTo.add(sendRequest);

        JMenuItem sendRequestNoAuth = new JMenuItem("Repeater (no Auth)");
        sendRequestNoAuth.addActionListener(e -> sendSelectedTo(Tool.REPEATER, false));
        sendTo.add(sendRequestNoAuth);

        JMenuItem sendIntruder = new JMenuItem("Intruder (with Auth)");
        sendIntruder.addActionListener(e -> sendSelectedTo(Tool.INTRUDER, true));
        sendTo.add(sendIntruder);

        JMenuItem sendIntruderNoAuth = new JMenuItem("Intruder (no Auth)");
        sendIntruderNoAuth.addActionListener(e -> sendSelectedTo(Tool.INTRUDER, false));
        sendTo.add(sendIntruderNoAuth);

        JMenuItem sendOrganizer = new JMenuItem("Organizer (with Auth)");
        sendOrganizer.addActionListener(e -> sendSelectedTo(Tool.ORGANIZER, true));
        sendTo.add(sendOrganizer);
        contextMenu.add(sendTo);

        JMenu sendFolderTo = new JMenu("Send Folder to");
        JMenuItem sendFolder = new JMenuItem("Repeater (with Auth)");
        sendFolder.addActionListener(e -> sendFolderTo(Tool.REPEATER, true));
        sendFolderTo.add(sendFolder);

        JMenuItem sendFolderNoAuth = new JMenuItem("Repeater (no Auth)");
        sendFolderNoAuth.addActionListener(e -> sendFolderTo(Tool.REPEATER, false));
        sendFolderTo.add(sendFolderNoAuth);

        JMenuItem sendFolderIntruder = new JMenuItem("Intruder (with Auth)");
        sendFolderIntruder.addActionListener(e -> sendFolderTo(Tool.INTRUDER, true));
        sendFolderTo.add(sendFolderIntruder);
        contextMenu.add(sendFolderTo);

        JMenu runPreviewMenu = new JMenu("Run (Preview)");
        JMenuItem runPreview = new JMenuItem("Selected - fire once, NOT scanned");
        runPreview.addActionListener(e -> runSelectedAsPreview(true));
        runPreviewMenu.add(runPreview);

        JMenuItem runPreviewNoAuth = new JMenuItem("Selected (no Auth)");
        runPreviewNoAuth.addActionListener(e -> runSelectedAsPreview(false));
        runPreviewMenu.add(runPreviewNoAuth);

        JMenuItem runFolderPreview = new JMenuItem("Folder");
        runFolderPreview.addActionListener(e -> runFolderAsPreview());
        runPreviewMenu.add(runFolderPreview);
        contextMenu.add(runPreviewMenu);

        JMenu analyzeMenu = new JMenu("Analyze");
        JMenuItem analyzeFolder = new JMenuItem("This Folder (run scripts)");
        analyzeFolder.addActionListener(e -> analyzeSelectedFolder());
        analyzeMenu.add(analyzeFolder);

        JMenuItem analyzeMulti = new JMenuItem("Selected Collections (each in own scope)");
        analyzeMulti.addActionListener(e -> analyzeSelectedCollectionsMulti());
        analyzeMenu.add(analyzeMulti);
        contextMenu.add(analyzeMenu);

        contextMenu.addSeparator();

        // ─── Edit collection: add / duplicate / rename / delete ──────────
        JMenuItem addRequest = new JMenuItem("➕ Add Request here...");
        addRequest.setToolTipText("Insert a new request inside the selected folder (or the parent of the selected request)");
        addRequest.addActionListener(e -> addRequestUnderSelection());
        contextMenu.add(addRequest);

        JMenuItem addFolder = new JMenuItem("📁 Add Folder here...");
        addFolder.setToolTipText("Insert a new folder inside the selected folder");
        addFolder.addActionListener(e -> addFolderUnderSelection());
        contextMenu.add(addFolder);

        JMenuItem createEmpty = new JMenuItem("🆕 Create Empty Collection...");
        createEmpty.setToolTipText("Create a new empty collection in the workspace");
        createEmpty.addActionListener(e -> promptCreateEmptyCollection());
        contextMenu.add(createEmpty);

        JMenuItem duplicate = new JMenuItem("📄 Duplicate");
        duplicate.setToolTipText("Deep-copy this request or folder next to itself");
        duplicate.addActionListener(e -> duplicateSelection());
        contextMenu.add(duplicate);

        JMenuItem rename = new JMenuItem("✏ Rename...");
        rename.addActionListener(e -> renameSelection());
        contextMenu.add(rename);

        JMenuItem deleteItem = new JMenuItem("🗑 Delete");
        deleteItem.addActionListener(e -> deleteSelection());
        contextMenu.add(deleteItem);

        contextMenu.addSeparator();

        JMenuItem removeColl = new JMenuItem("🗑 Remove Collection from Workspace");
        removeColl.addActionListener(e -> removeSelectedCollection());
        contextMenu.add(removeColl);

        contextMenu.addSeparator();

        // ─── Copy as code (submenu) ──────────────────────────────────────
        JMenu copyAsCode = new JMenu("📋 Copy as code");
        for (burp.codegen.CodeGenerator gen : burp.codegen.CodeGeneratorRegistry.all()) {
            JMenuItem item = new JMenuItem(gen.label());
            item.addActionListener(e -> copySelectedAsCode(gen));
            copyAsCode.add(item);
        }
        contextMenu.add(copyAsCode);

        contextMenu.addSeparator();

        JMenuItem expandAll = new JMenuItem("⊞ Expand All");
        expandAll.addActionListener(e -> expandOrCollapseAll(true));
        contextMenu.add(expandAll);

        JMenuItem collapseAll = new JMenuItem("⊟ Collapse All");
        collapseAll.addActionListener(e -> expandOrCollapseAll(false));
        contextMenu.add(collapseAll);
    }

    /** Generate a snippet for the currently-selected request and copy to clipboard. */
    private void copySelectedAsCode(burp.codegen.CodeGenerator gen) {
        TreePath path = tree.getSelectionPath();
        if (path == null) {
            JOptionPane.showMessageDialog(this, "Please select a request");
            return;
        }
        Object obj = path.getLastPathComponent();
        if (!(obj instanceof CollectionTreeNode)) return;
        CollectionTreeNode node = (CollectionTreeNode) obj;

        AnalyzedRequest target = null;
        if (node.getNodeType() == NodeType.REQUEST) {
            target = node.getRequest();
        } else {
            List<AnalyzedRequest> all = node.getAllRequests();
            if (!all.isEmpty()) target = all.get(0);
        }
        if (target == null || target.getRequest() == null) {
            JOptionPane.showMessageDialog(this, "Cannot generate code: empty request");
            return;
        }

        try {
            burp.codegen.GenRequest g = burp.codegen.GenRequest.from(
                    target.getRequest(), target.getName(),
                    importer == null ? null : importer.getVariableResolver());
            String snippet = gen.generate(g);
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new java.awt.datatransfer.StringSelection(snippet), null);
            JOptionPane.showMessageDialog(this,
                    gen.label() + " snippet copied to clipboard (" + snippet.length() + " chars)",
                    "Code generated", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Code generation failed: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /** Prompt for a CSV/JSON data file and run the selected folder/request N times. */
    private void runSelectedWithDataFile() {
        TreePath path = tree.getSelectionPath();
        if (path == null) {
            JOptionPane.showMessageDialog(this, "Please select a folder or request first");
            return;
        }
        Object obj = path.getLastPathComponent();
        if (!(obj instanceof CollectionTreeNode)) return;
        CollectionTreeNode node = (CollectionTreeNode) obj;

        List<AnalyzedRequest> targets = node.getNodeType() == NodeType.REQUEST
                ? java.util.Collections.singletonList(node.getRequest())
                : node.getAllRequests();
        if (targets.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No requests to run");
            return;
        }

        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Choose CSV or JSON data file");
        fc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("CSV / JSON", "csv", "json"));
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;

        try {
            burp.runner.DataIterator data = burp.runner.DataIterator.fromFile(fc.getSelectedFile());
            if (data.size() == 0) {
                JOptionPane.showMessageDialog(this, "Data file has no rows");
                return;
            }
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Run " + targets.size() + " requests × " + data.size() + " iterations = "
                            + (targets.size() * data.size()) + " total sends?",
                    "Confirm data-driven run", JOptionPane.YES_NO_OPTION);
            if (confirm != JOptionPane.YES_OPTION) return;

            burp.parser.VariableResolver resolver = importer == null ? null : importer.getVariableResolver();
            if (resolver == null) {
                JOptionPane.showMessageDialog(this, "No variable resolver available");
                return;
            }
            new Thread(() -> {
                try {
                    // Fire each iteration through Burp's HTTP stack via
                    // importer.runAnalyzedBatch — this populates the Logger /
                    // Proxy History / Run Results panel but does NOT spam
                    // Burp Repeater with one tab per request. Matches user
                    // expectation: autorun = execute + observe, not edit.
                    new burp.runner.DataDrivenRunner(resolver, data)
                            .run(targets, (req, idx, row) -> {
                                try {
                                    importer.runAnalyzedBatch(
                                            java.util.Collections.singletonList(req),
                                            "Data row " + idx,
                                            false /* scriptedOnly=false → fire all */);
                                } catch (Throwable t) { /* keep iteration going */ }
                            });
                } catch (Exception ex) {
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this,
                            "Run failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE));
                }
            }, "BurpMan-DataDrivenRunner").start();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to read data file: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /** Expand or collapse every node in the tree (operates on the visible tree). */
    private void expandOrCollapseAll(boolean expand) {
        for (int i = 0; i < tree.getRowCount(); i++) {
            if (expand) tree.expandRow(i);
            else tree.collapseRow(i);
        }
        if (expand) {
            // expandRow may add new rows during iteration; loop again to catch them
            int last;
            do {
                last = tree.getRowCount();
                for (int i = 0; i < tree.getRowCount(); i++) tree.expandRow(i);
            } while (tree.getRowCount() > last);
        }
    }

    // ─── Collection edit actions (add / duplicate / rename / delete) ─────

    /** Find the underlying {@link burp.models.PostmanCollection.Item} for a
     *  tree node — for folders this is the node's rawItem; for requests it's
     *  also the rawItem (single Item carrying request + child list = null). */
    private burp.models.PostmanCollection.Item itemFor(CollectionTreeNode node) {
        return node == null ? null : node.getRawItem();
    }

    /** Resolve the parent Item list a new child should be inserted into.
     *  If the selected node is a folder, use its child list. If it's a request,
     *  use its parent folder's child list. */
    private java.util.List<burp.models.PostmanCollection.Item> parentItemList(CollectionTreeNode selection) {
        if (selection == null) return null;
        if (selection.getNodeType() == NodeType.REQUEST) {
            javax.swing.tree.TreeNode p = selection.getParent();
            if (p instanceof CollectionTreeNode) {
                burp.models.PostmanCollection.Item parentItem = ((CollectionTreeNode) p).getRawItem();
                if (parentItem != null) {
                    if (parentItem.item == null) parentItem.item = new java.util.ArrayList<>();
                    return parentItem.item;
                }
                // Top-level: parent is the workspace root → fall through to collection.item
            }
        } else {
            burp.models.PostmanCollection.Item folderItem = selection.getRawItem();
            if (folderItem != null) {
                if (folderItem.item == null) folderItem.item = new java.util.ArrayList<>();
                return folderItem.item;
            }
        }
        // Fall back to the root collection's top-level item list.
        burp.models.PostmanCollection coll = importer == null ? null : importer.getCurrentCollection();
        if (coll == null) return null;
        if (coll.item == null) coll.item = new java.util.ArrayList<>();
        return coll.item;
    }

    private TreePath activeTreePath() {
        return contextMenuPath != null ? contextMenuPath : tree.getSelectionPath();
    }

    private CollectionTreeNode activeSelectionNode() {
        TreePath path = activeTreePath();
        if (path == null) return null;
        Object obj = path.getLastPathComponent();
        return (obj instanceof CollectionTreeNode) ? (CollectionTreeNode) obj : null;
    }

    private void rebuildAndKeepSelection(String tryReselectName) {
        try {
            if (importer != null) importer.rebuildTreeOnly();
        } catch (Exception ignore) {}
        if (tryReselectName == null) return;
        // Best-effort: walk the rebuilt tree and re-select the row with that name.
        SwingUtilities.invokeLater(() -> {
            try {
                javax.swing.tree.TreeModel m = tree.getModel();
                java.util.Enumeration<?> enumeration =
                    ((javax.swing.tree.DefaultMutableTreeNode) m.getRoot()).depthFirstEnumeration();
                while (enumeration.hasMoreElements()) {
                    Object n = enumeration.nextElement();
                    if (n instanceof CollectionTreeNode
                            && tryReselectName.equals(((CollectionTreeNode) n).toString())) {
                        CollectionTreeNode matched = (CollectionTreeNode) n;
                        TreePath p = new TreePath(matched.getPath());
                        tree.setSelectionPath(p);
                        tree.scrollPathToVisible(p);
                        handleRequestClick(matched);
                        return;
                    }
                }
            } catch (Throwable ignore) {}
        });
    }

    private void addRequestUnderSelection() {
        CollectionTreeNode node = activeSelectionNode();
        if (node == null) {
            JOptionPane.showMessageDialog(this, "Right-click a folder (or any request inside it) first");
            return;
        }
        java.util.List<burp.models.PostmanCollection.Item> parent = parentItemList(node);
        if (parent == null) {
            JOptionPane.showMessageDialog(this, "Cannot add here — no parent folder.");
            return;
        }
        String name = JOptionPane.showInputDialog(this, "Request name:", "New Request");
        if (name == null || name.trim().isEmpty()) return;

        burp.models.PostmanCollection.Item leaf = new burp.models.PostmanCollection.Item();
        leaf.name = name.trim();
        leaf.request = new burp.models.PostmanCollection.Request();
        leaf.request.userAdded = true;
        leaf.request.method = "GET";
        leaf.request.url = "https://";
        leaf.request.header = new java.util.ArrayList<>();
        parent.add(leaf);
        rebuildAndKeepSelection(leaf.name);
    }

    private void addFolderUnderSelection() {
        CollectionTreeNode node = activeSelectionNode();
        if (node == null) {
            JOptionPane.showMessageDialog(this, "Right-click a folder first");
            return;
        }
        java.util.List<burp.models.PostmanCollection.Item> parent = parentItemList(node);
        if (parent == null) {
            JOptionPane.showMessageDialog(this, "Cannot add here.");
            return;
        }
        String name = JOptionPane.showInputDialog(this, "Folder name:", "New Folder");
        if (name == null || name.trim().isEmpty()) return;

        burp.models.PostmanCollection.Item folder = new burp.models.PostmanCollection.Item();
        folder.name = name.trim();
        folder.item = new java.util.ArrayList<>();
        parent.add(folder);
        rebuildAndKeepSelection(folder.name);
    }

    private void duplicateSelection() {
        CollectionTreeNode node = activeSelectionNode();
        if (node == null) return;
        burp.models.PostmanCollection.Item original = itemFor(node);
        if (original == null) return;
        javax.swing.tree.TreeNode p = node.getParent();
        if (!(p instanceof CollectionTreeNode)) return;
        burp.models.PostmanCollection.Item parentItem = ((CollectionTreeNode) p).getRawItem();
        java.util.List<burp.models.PostmanCollection.Item> siblings;
        if (parentItem != null && parentItem.item != null) {
            siblings = parentItem.item;
        } else {
            burp.models.PostmanCollection coll = importer == null ? null : importer.getCurrentCollection();
            if (coll == null || coll.item == null) return;
            siblings = coll.item;
        }
        // Deep copy via Gson roundtrip — handles nested folders + requests.
        com.google.gson.Gson g = new com.google.gson.Gson();
        burp.models.PostmanCollection.Item copy =
                g.fromJson(g.toJson(original), burp.models.PostmanCollection.Item.class);
        copy.name = (original.name == null ? "Item" : original.name) + " (copy)";
        int idx = siblings.indexOf(original);
        if (idx >= 0) siblings.add(idx + 1, copy);
        else          siblings.add(copy);
        rebuildAndKeepSelection(copy.name);
    }

    private void renameSelection() {
        CollectionTreeNode node = activeSelectionNode();
        if (node == null) return;
        burp.models.PostmanCollection.Item item = itemFor(node);
        if (item == null) return;
        String newName = (String) JOptionPane.showInputDialog(this,
                "New name:", "Rename", JOptionPane.PLAIN_MESSAGE,
                null, null, item.name);
        if (newName == null || newName.trim().isEmpty()) return;
        item.name = newName.trim();
        rebuildAndKeepSelection(item.name);
    }

    private void deleteSelection() {
        CollectionTreeNode node = activeSelectionNode();
        if (node == null) return;
        burp.models.PostmanCollection.Item item = itemFor(node);
        if (item == null && node.getRequest() == null) return;
        int confirm = JOptionPane.showConfirmDialog(this,
                "Delete '" + (item != null ? item.name : node.toString()) + "'?", "Confirm",
                JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) return;

        boolean removed = false;
        javax.swing.tree.TreeNode p = node.getParent();
        if (p instanceof CollectionTreeNode) {
            burp.models.PostmanCollection.Item parentItem = ((CollectionTreeNode) p).getRawItem();
            if (parentItem != null && parentItem.item != null) {
                removed = removeFromSiblings(parentItem.item, item, node);
            }
        }
        if (!removed) {
            burp.models.PostmanCollection coll = importer == null ? null : importer.getCurrentCollection();
            if (coll != null && coll.item != null) {
                removed = removeFromSiblings(coll.item, item, node);
            }
        }
        if (!removed) {
            JOptionPane.showMessageDialog(this,
                    "Could not locate the selected item in the collection model.",
                    "Delete Failed",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }
        rebuildAndKeepSelection(null);
        try { importer.refreshAuthDetectionFromCurrentCollection(); } catch (Exception ignore) {}
    }

    private static boolean removeFromSiblings(
            java.util.List<burp.models.PostmanCollection.Item> siblings,
            burp.models.PostmanCollection.Item targetItem,
            CollectionTreeNode selectedNode) {
        if (siblings == null || siblings.isEmpty()) return false;

        if (targetItem != null && siblings.remove(targetItem)) return true;

        burp.models.PostmanCollection.Request targetRequest =
                selectedNode != null && selectedNode.getRequest() != null
                        ? selectedNode.getRequest().getRequest()
                        : null;
        if (targetRequest != null) {
            for (int i = 0; i < siblings.size(); i++) {
                burp.models.PostmanCollection.Item candidate = siblings.get(i);
                if (candidate != null && candidate.request == targetRequest) {
                    siblings.remove(i);
                    return true;
                }
            }
        }

        String wantedName = targetItem != null ? targetItem.name : (selectedNode == null ? null : selectedNode.toString());
        for (int i = 0; i < siblings.size(); i++) {
            burp.models.PostmanCollection.Item candidate = siblings.get(i);
            if (candidate == null) continue;
            if ((wantedName == null && candidate.name == null)
                    || (wantedName != null && wantedName.equals(candidate.name))) {
                siblings.remove(i);
                return true;
            }
        }
        return false;
    }

    private void removeSelectedCollection() {
        CollectionTreeNode node = activeSelectionNode();
        if (node == null) {
            JOptionPane.showMessageDialog(this, "Right-click a collection first");
            return;
        }
        // Walk up to the top-level collection (child of workspace root).
        CollectionTreeNode top = node;
        while (top.getParent() instanceof CollectionTreeNode
                && ((CollectionTreeNode) top.getParent()).getParent() != null) {
            top = (CollectionTreeNode) top.getParent();
        }
        if (top.getParent() == null) {
            JOptionPane.showMessageDialog(this, "Cannot remove the workspace root.");
            return;
        }
        String wrapperName = top.getRawItem() != null && top.getRawItem().name != null
                ? top.getRawItem().name
                : top.toString();
        int ans = JOptionPane.showConfirmDialog(this,
                "Remove collection \"" + wrapperName + "\" from this workspace?\n"
                        + "This does not delete the source file.",
                "Remove Collection", JOptionPane.OK_CANCEL_OPTION);
        if (ans != JOptionPane.OK_OPTION) return;
        try {
            boolean ok = importer.removeCollection(wrapperName);
            if (!ok) {
                JOptionPane.showMessageDialog(this, "Collection not found: " + wrapperName);
                return;
            }
            try { importer.refreshAuthDetectionFromCurrentCollection(); } catch (Exception ignore) {}
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Remove failed: " + ex.getMessage());
        }
    }

    /** Analyze every selected collection wrapper, each in its own strict scope. */
    private void analyzeSelectedCollectionsMulti() {
        TreePath[] paths = tree.getSelectionPaths();
        if (paths == null || paths.length == 0) {
            JOptionPane.showMessageDialog(this, "Select one or more collections first");
            return;
        }
        java.util.LinkedHashSet<String> wrappers = new java.util.LinkedHashSet<>();
        for (TreePath p : paths) {
            Object obj = p.getLastPathComponent();
            if (!(obj instanceof CollectionTreeNode)) continue;
            CollectionTreeNode top = (CollectionTreeNode) obj;
            while (top.getParent() instanceof CollectionTreeNode
                    && ((CollectionTreeNode) top.getParent()).getParent() != null) {
                top = (CollectionTreeNode) top.getParent();
            }
            if (top.getParent() == null) continue; // skip workspace root
            wrappers.add(top.toString());
        }
        if (wrappers.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No valid collections in selection");
            return;
        }
        java.io.File cf = importer.getSelectedCollection();
        java.io.File ef = importer.getSelectedEnvironment();
        if (cf == null) {
            JOptionPane.showMessageDialog(this, "No collection file selected");
            return;
        }
        new Thread(() -> {
            for (String wname : wrappers) {
                try {
                    importer.setAnalyzeScope(wname);
                    importer.analyzeAuthFromFiles(cf, ef);
                } catch (Exception ex) {
                    // log and continue with next
                } finally {
                    importer.setAnalyzeScope(null);
                }
            }
        }, "analyze-multi-" + wrappers.size()).start();
    }

    /** Run the global Auth analysis pipeline scoped to the top-level
     *  collection wrapper containing the right-clicked node. */
    private void analyzeSelectedCollection() {
        TreePath path = tree.getSelectionPath();
        if (path == null) {
            JOptionPane.showMessageDialog(this, "Right-click a collection first");
            return;
        }
        Object obj = path.getLastPathComponent();
        if (!(obj instanceof CollectionTreeNode)) return;
        CollectionTreeNode node = (CollectionTreeNode) obj;
        // Walk up to the top-level COLLECTION node (workspace root excluded).
        CollectionTreeNode top = node;
        while (top.getParent() instanceof CollectionTreeNode
                && ((CollectionTreeNode) top.getParent()).getParent() != null) {
            top = (CollectionTreeNode) top.getParent();
        }
        String wrapperName = top.toString();
        try {
            importer.setAnalyzeScope(wrapperName);
            java.io.File cf = importer.getSelectedCollection();
            java.io.File ef = importer.getSelectedEnvironment();
            if (cf == null) {
                JOptionPane.showMessageDialog(this, "No collection file selected");
                return;
            }
            new Thread(() -> {
                try {
                    importer.analyzeAuthFromFiles(cf, ef);
                } finally {
                    importer.setAnalyzeScope(null);
                }
            }, "analyze-collection-" + wrapperName).start();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Analyze failed: " + ex.getMessage());
        }
    }

    /** Fire the selected request(s) once through the preview pipeline (no site map). */
    private void runSelectedAsPreview(boolean withAuth) {
        TreePath[] paths = tree.getSelectionPaths();
        if (paths == null || paths.length == 0) {
            JOptionPane.showMessageDialog(this, "Please select request(s) or a folder");
            return;
        }
        List<AnalyzedRequest> requests = new ArrayList<>();
        for (TreePath path : paths) {
            Object obj = path.getLastPathComponent();
            if (!(obj instanceof CollectionTreeNode)) continue;
            CollectionTreeNode node = (CollectionTreeNode) obj;
            if (node.getNodeType() == NodeType.REQUEST) {
                if (node.getRequest() != null) requests.add(node.getRequest());
            } else {
                requests.addAll(node.getAllRequests());
            }
        }
        if (requests.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No requests found");
            return;
        }
        importer.runAnalyzedBatch(requests,
            "Run (Preview" + (withAuth ? "" : ", no Auth") + ")", false);
    }

    /** Fire every request inside the selected folder once via preview (no site map). */
    private void runFolderAsPreview() {
        TreePath path = tree.getSelectionPath();
        if (path == null) {
            JOptionPane.showMessageDialog(this, "Please select a folder");
            return;
        }
        Object obj = path.getLastPathComponent();
        if (!(obj instanceof CollectionTreeNode)) return;
        CollectionTreeNode node = (CollectionTreeNode) obj;
        List<AnalyzedRequest> requests = node.getAllRequests();
        if (requests == null || requests.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Folder contains no requests");
            return;
        }
        importer.runAnalyzedBatch(requests, "Run Folder (Preview): " + node.toString(), false);
    }

    /** Run the Analyze (preview/scripts) pipeline on just the selected folder's requests. */
    private void analyzeSelectedFolder() {
        CollectionTreeNode node = activeSelectionNode();
        if (node == null) {
            JOptionPane.showMessageDialog(this, "Please select a folder to analyze");
            return;
        }
        List<AnalyzedRequest> requests;
        if (node.getNodeType() == NodeType.REQUEST) {
            requests = new ArrayList<>();
            if (node.getRequest() != null) requests.add(node.getRequest());
        } else {
            requests = node.getAllRequests();
        }
        if (requests == null || requests.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Folder contains no requests");
            return;
        }
        importer.runAnalyzedBatch(requests, "Analyze Folder: " + node.toString());
    }

    public enum Tool { REPEATER, INTRUDER, ORGANIZER }

    public PostmanImporter getImporter() { return importer; }
    
    /** Build a "/"-joined key from the tree path of a node, excluding the synthetic root label. */
    public static String nodePathKey(CollectionTreeNode node) {
        java.util.Deque<String> parts = new java.util.ArrayDeque<>();
        javax.swing.tree.TreeNode n = node;
        while (n != null && n.getParent() != null) {
            if (n instanceof CollectionTreeNode) {
                parts.push(((CollectionTreeNode) n).toString());
            }
            n = n.getParent();
        }
        StringBuilder sb = new StringBuilder();
        for (String s : parts) {
            if (sb.length() > 0) sb.append('/');
            sb.append(s);
        }
        return sb.toString();
    }

    /**
     * Send selected node(s) to the chosen tool.
     */
    private void sendSelectedTo(Tool tool, boolean withAuth) {
        TreePath[] paths = tree.getSelectionPaths();

        if (paths == null || paths.length == 0) {
            JOptionPane.showMessageDialog(this, "Please select a request or folder");
            return;
        }

        List<AnalyzedRequest> requests = new ArrayList<>();

        for (TreePath path : paths) {
            Object obj = path.getLastPathComponent();

            if (!(obj instanceof CollectionTreeNode)) {
                continue;
            }

            CollectionTreeNode node = (CollectionTreeNode) obj;

            if (node.getNodeType() == NodeType.REQUEST) {
                if (node.getRequest() != null) {
                    requests.add(node.getRequest());
                }
            } else {
                requests.addAll(node.getAllRequests());
            }
        }

        if (requests.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No requests found to send");
            return;
        }

        sendRequestsTo(tool, requests, withAuth);
    }

    /**
     * Send entire folder to chosen tool.
     */
    private void sendFolderTo(Tool tool, boolean withAuth) {
        TreePath path = tree.getSelectionPath();

        if (path == null) {
            JOptionPane.showMessageDialog(this, "Please select a folder");
            return;
        }

        Object obj = path.getLastPathComponent();

        if (!(obj instanceof CollectionTreeNode)) {
            JOptionPane.showMessageDialog(this, "Invalid node selected");
            return;
        }

        CollectionTreeNode node = (CollectionTreeNode) obj;

        if (node.getNodeType() == NodeType.REQUEST) {
            JOptionPane.showMessageDialog(this, "Please select a folder, not a request");
            return;
        }

        List<AnalyzedRequest> requests = node.getAllRequests();

        if (requests.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Folder contains no requests");
            return;
        }

        int response = JOptionPane.showConfirmDialog(
                this,
                "Send " + requests.size() + " requests from '" + node + "' to " + tool.name() + "?",
                "Confirm Bulk Send",
                JOptionPane.YES_NO_OPTION
        );

        if (response == JOptionPane.YES_OPTION) {
            sendRequestsTo(tool, requests, withAuth);
        }
    }

    /**
     * Dispatch requests to the chosen tool.
     */
    private void sendRequestsTo(Tool tool, List<AnalyzedRequest> requests, boolean withAuth) {
        new Thread(() -> {
            int sent = 0;

            for (AnalyzedRequest req : requests) {
                try {
                    switch (tool) {
                        case REPEATER:
                            importer.sendRequestToRepeater(req, withAuth);
                            break;
                        case INTRUDER:
                            importer.sendRequestToTool(req, withAuth, "intruder");
                            break;
                        case ORGANIZER:
                            importer.sendRequestToTool(req, withAuth, "organizer");
                            break;
                    }
                    sent++;
                } catch (Exception e) {
                    importer.log("Error sending request: " + e.getMessage());
                }
            }

            importer.log("Sent " + sent + " request(s) to " + tool.name());
        }).start();
    }

    /**
     * Mouse listener for context menu
     */
    private class TreeMouseListener extends MouseAdapter {
        @Override
        public void mousePressed(MouseEvent e) {
            if (e.isPopupTrigger()) {
                showContextMenu(e);
            } else if (e.getClickCount() == 1) {
                contextMenuPath = null;
                // Single click - load request into builder
                TreePath path = tree.getPathForLocation(e.getX(), e.getY());
                if (path != null) {
                    Object obj = path.getLastPathComponent();
                    if (obj instanceof CollectionTreeNode) {
                        handleRequestClick((CollectionTreeNode) obj);
                    }
                }
            }
        }

        @Override
        public void mouseReleased(MouseEvent e) {
            if (e.isPopupTrigger()) showContextMenu(e);
        }

        private void showContextMenu(MouseEvent e) {
            TreePath path = tree.getPathForLocation(e.getX(), e.getY());

            if (path == null) {
                contextMenuPath = null;
                if (rootNode == null) {
                    showEmptyStateMenu(e);
                }
                return;
            }

            Object node = path.getLastPathComponent();
            if (!(node instanceof CollectionTreeNode)) {
                contextMenuPath = null;
                if (rootNode == null) {
                    showEmptyStateMenu(e);
                }
                return;
            }
            contextMenuPath = path;

            // Preserve multi-selection: only change selection if right-click
            // was on a row that wasn't already selected.
            if (!tree.isPathSelected(path)) {
                tree.setSelectionPath(path);
            }
            try { tree.setLeadSelectionPath(path); } catch (Throwable ignore) {}
            contextMenu.show(tree, e.getX(), e.getY());
        }

        private void showEmptyStateMenu(MouseEvent e) {
            JPopupMenu emptyMenu = new JPopupMenu();
            JMenuItem addCollection = new JMenuItem("+ Add Collection");
            addCollection.addActionListener(ev -> promptAddCollection());
            emptyMenu.add(addCollection);

            JMenuItem createEmpty = new JMenuItem("Create Empty Collection...");
            createEmpty.addActionListener(ev -> promptCreateEmptyCollection());
            emptyMenu.add(createEmpty);

            emptyMenu.show(tree, e.getX(), e.getY());
        }
    }

    public JTree getTree() {
        return tree;
    }

    public CollectionTreeNode getRootNode() {
        return rootNode;
    }
    
    // ✅ LISTENER INTERFACE FOR TREE CLICKS
    public interface RequestClickListener {
        void onRequestClicked(AnalyzedRequest request);
    }
    
    /** Extended listener with the node for folder-auth lookup. */
    public interface RequestNodeClickListener {
        void onRequestNodeClicked(AnalyzedRequest request, CollectionTreeNode node);
    }
    
    /** Fired when the user clicks a folder/collection node (not a request leaf). */
    public interface FolderNodeClickListener {
        void onFolderNodeClicked(CollectionTreeNode node, String folderPath, boolean isCollection);
    }
    
    private RequestClickListener requestClickListener;
    private RequestNodeClickListener requestNodeClickListener;
    private FolderNodeClickListener folderNodeClickListener;
    
    public void setRequestClickListener(RequestClickListener listener) {
        this.requestClickListener = listener;
    }
    
    public void setRequestNodeClickListener(RequestNodeClickListener listener) {
        this.requestNodeClickListener = listener;
    }
    
    public void setFolderNodeClickListener(FolderNodeClickListener listener) {
        this.folderNodeClickListener = listener;
    }
    
    private void handleRequestClick(CollectionTreeNode node) {
        if (node.getNodeType() == NodeType.REQUEST && node.getRequest() != null) {
            if (requestNodeClickListener != null) {
                requestNodeClickListener.onRequestNodeClicked(node.getRequest(), node);
            }
            if (requestClickListener != null) {
                requestClickListener.onRequestClicked(node.getRequest());
            }
        } else if (folderNodeClickListener != null
                && (node.getNodeType() == NodeType.FOLDER || node.getNodeType() == NodeType.COLLECTION)) {
            String path = nodePathKey(node);
            boolean isCollection = node.getNodeType() == NodeType.COLLECTION || node.getParent() == null;
            folderNodeClickListener.onFolderNodeClicked(node, path, isCollection);
        }
    }
}