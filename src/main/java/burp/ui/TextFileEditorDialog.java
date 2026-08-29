package burp.ui;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.function.Consumer;

/** Lightweight in-app editor for plain text files (.env, .bru, .yml, .yaml).
 *  Modeled after Bruno's environment editor UX: monospaced text area, dirty
 *  indicator in the title, and a top toolbar with Save / Reload / Open
 *  externally. Saves atomically (write to <file>.tmp, then move), and
 *  fires an {@code onSaved} callback so the caller can reapply variables.
 *
 *  <p>Not tied to .env specifically — usable for any text file. But the
 *  common case is editing {@code .env} overlays without leaving BurpMan.
 */
public class TextFileEditorDialog extends JDialog {
    private final File file;
    private final Consumer<File> onSaved;
    private final JTextArea textArea;
    private final JLabel statusLabel;
    private final JButton saveBtn;
    private String lastSavedContent = "";
    private boolean dirty = false;

    /** Static entry point — creates, positions, and shows the dialog.
     *  @param owner parent window (may be null; will fall back to no owner)
     *  @param file  file to edit; must exist and be readable
     *  @param onSaved callback fired AFTER a successful save (main thread) */
    public static void showFor(Window owner, File file, Consumer<File> onSaved) {
        if (file == null || !file.isFile()) {
            JOptionPane.showMessageDialog(owner,
                "File no longer exists:\n" + file,
                "Edit file", JOptionPane.WARNING_MESSAGE);
            return;
        }
        TextFileEditorDialog d = new TextFileEditorDialog(owner, file, onSaved);
        // Clamp to a comfortable modal size that fits small screens
        // (13-14" laptops at 100% DPI). We shoot for ~640x420 but never
        // exceed 85% of the usable screen — that way OneDrive banner +
        // Windows taskbar don't chop off the Save button.
        Rectangle usable = getUsableScreenBounds(owner);
        int w = Math.min(640, (int) (usable.width * 0.85));
        int h = Math.min(420, (int) (usable.height * 0.80));
        d.setMinimumSize(new Dimension(420, 260));
        d.setSize(new Dimension(w, h));
        d.setLocationRelativeTo(owner);
        // Nudge back into bounds if setLocationRelativeTo pushed us off-screen.
        Point loc = d.getLocation();
        int maxX = usable.x + usable.width - d.getWidth();
        int maxY = usable.y + usable.height - d.getHeight();
        loc.x = Math.max(usable.x, Math.min(loc.x, maxX));
        loc.y = Math.max(usable.y, Math.min(loc.y, maxY));
        d.setLocation(loc);
        d.setVisible(true);
    }

    /** Usable screen bounds for the display the owner window sits on
     *  (multi-monitor aware, excludes taskbar/dock). Falls back to the
     *  default screen if the owner is null or off-screen. */
    private static Rectangle getUsableScreenBounds(Window owner) {
        try {
            GraphicsConfiguration gc = owner != null
                ? owner.getGraphicsConfiguration()
                : GraphicsEnvironment.getLocalGraphicsEnvironment()
                    .getDefaultScreenDevice().getDefaultConfiguration();
            if (gc == null) return new Rectangle(0, 0, 1024, 768);
            Rectangle full = gc.getBounds();
            Insets insets = Toolkit.getDefaultToolkit().getScreenInsets(gc);
            return new Rectangle(
                full.x + insets.left,
                full.y + insets.top,
                full.width - insets.left - insets.right,
                full.height - insets.top - insets.bottom);
        } catch (Exception ignore) {
            return new Rectangle(0, 0, 1024, 768);
        }
    }

    private TextFileEditorDialog(Window owner, File file, Consumer<File> onSaved) {
        super(owner, "Edit — " + file.getName(), ModalityType.APPLICATION_MODAL);
        this.file = file;
        this.onSaved = onSaved;

        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override public void windowClosing(WindowEvent e) { confirmCloseAndDispose(); }
        });

        setLayout(new BorderLayout());

        // --- top toolbar --------------------------------------------------
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        toolbar.setBorderPainted(true);
        toolbar.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        saveBtn = new JButton("💾 Save");
        saveBtn.setToolTipText("Save (Ctrl+S)");
        saveBtn.addActionListener(e -> saveToDisk());
        saveBtn.setEnabled(false);

        JButton reloadBtn = new JButton("↻ Reload");
        reloadBtn.setToolTipText("Discard changes and reload from disk");
        reloadBtn.addActionListener(e -> {
            if (dirty) {
                int ok = JOptionPane.showConfirmDialog(this,
                    "Discard unsaved changes and reload from disk?",
                    "Reload", JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.WARNING_MESSAGE);
                if (ok != JOptionPane.OK_OPTION) return;
            }
            loadFromDisk();
        });

        JButton openExternalBtn = new JButton("↗ Open externally");
        openExternalBtn.setToolTipText("Open in your OS default editor (Notepad on Windows)");
        openExternalBtn.addActionListener(e -> openExternally());

        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> confirmCloseAndDispose());

        toolbar.add(saveBtn);
        toolbar.addSeparator();
        toolbar.add(reloadBtn);
        toolbar.add(openExternalBtn);
        toolbar.add(Box.createHorizontalGlue());
        toolbar.add(closeBtn);
        add(toolbar, BorderLayout.NORTH);

        // --- editor -------------------------------------------------------
        textArea = new JTextArea();
        textArea.setFont(UITheme.monoFont().deriveFont(13f));
        textArea.setTabSize(2);
        textArea.setLineWrap(false);
        textArea.setMargin(new Insets(6, 8, 6, 8));
        textArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e)  { markDirty(); }
            @Override public void removeUpdate(DocumentEvent e)  { markDirty(); }
            @Override public void changedUpdate(DocumentEvent e) { markDirty(); }
        });

        JScrollPane scroll = new JScrollPane(textArea);
        scroll.setBorder(BorderFactory.createEmptyBorder(0, 6, 6, 6));
        add(scroll, BorderLayout.CENTER);

        // --- status bar --------------------------------------------------
        JPanel statusBar = new JPanel(new BorderLayout());
        statusBar.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        statusLabel = new JLabel(" ");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.PLAIN, 11f));
        statusLabel.setForeground(UITheme.subtleText());
        statusBar.add(statusLabel, BorderLayout.WEST);
        JLabel pathLabel = new JLabel(file.getAbsolutePath());
        pathLabel.setFont(pathLabel.getFont().deriveFont(Font.PLAIN, 10.5f));
        pathLabel.setForeground(UITheme.subtleText());
        pathLabel.setHorizontalAlignment(SwingConstants.RIGHT);
        statusBar.add(pathLabel, BorderLayout.EAST);
        add(statusBar, BorderLayout.SOUTH);

        // --- keyboard shortcuts ------------------------------------------
        KeyStroke ctrlS = KeyStroke.getKeyStroke(KeyEvent.VK_S,
            Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx());
        textArea.getInputMap().put(ctrlS, "save");
        textArea.getActionMap().put("save", new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent e) { saveToDisk(); }
        });
        KeyStroke esc = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0);
        getRootPane().registerKeyboardAction(e -> confirmCloseAndDispose(),
            esc, JComponent.WHEN_IN_FOCUSED_WINDOW);

        loadFromDisk();
    }

    private void loadFromDisk() {
        try {
            String content = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
            lastSavedContent = content;
            textArea.setText(content);
            textArea.setCaretPosition(0);
            dirty = false;
            saveBtn.setEnabled(false);
            setTitle("Edit — " + file.getName());
            statusLabel.setText("Loaded " + content.length() + " bytes");
        } catch (IOException ex) {
            statusLabel.setText("⚠ Could not read: " + ex.getMessage());
            JOptionPane.showMessageDialog(this,
                "Could not read file:\n" + ex.getMessage(),
                "Read error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void saveToDisk() {
        if (!dirty) return;
        String content = textArea.getText();
        try {
            // Atomic write: temp file next to target, then move.
            File tmp = new File(file.getAbsolutePath() + ".tmp");
            Files.write(tmp.toPath(), content.getBytes(StandardCharsets.UTF_8));
            try {
                Files.move(tmp.toPath(), file.toPath(),
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException a) {
                // Some filesystems (OneDrive placeholders) block atomic moves.
                Files.move(tmp.toPath(), file.toPath(),
                    StandardCopyOption.REPLACE_EXISTING);
            }
            lastSavedContent = content;
            dirty = false;
            saveBtn.setEnabled(false);
            setTitle("Edit — " + file.getName());
            statusLabel.setText("✓ Saved " + content.length() + " bytes");
            if (onSaved != null) {
                try { onSaved.accept(file); } catch (Exception ignore) {}
            }
        } catch (IOException ex) {
            statusLabel.setText("⚠ Save failed: " + ex.getMessage());
            JOptionPane.showMessageDialog(this,
                "Could not save file:\n" + ex.getMessage(),
                "Save error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void openExternally() {
        try {
            if (Desktop.isDesktopSupported()) {
                Desktop d = Desktop.getDesktop();
                if (d.isSupported(Desktop.Action.EDIT)) { d.edit(file); return; }
                if (d.isSupported(Desktop.Action.OPEN)) { d.open(file); return; }
            }
            JOptionPane.showMessageDialog(this,
                "Open this file in your editor:\n" + file.getAbsolutePath(),
                "Open externally", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                "Could not open externally:\n" + ex.getMessage(),
                "Open error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void markDirty() {
        String current = textArea.getText();
        boolean nowDirty = !current.equals(lastSavedContent);
        if (nowDirty == dirty) return;
        dirty = nowDirty;
        saveBtn.setEnabled(dirty);
        setTitle((dirty ? "● " : "") + "Edit — " + file.getName());
        statusLabel.setText(dirty ? "Modified" : "No changes");
    }

    private void confirmCloseAndDispose() {
        if (dirty) {
            int ans = JOptionPane.showConfirmDialog(this,
                "Save changes to " + file.getName() + "?",
                "Unsaved changes",
                JOptionPane.YES_NO_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE);
            if (ans == JOptionPane.CANCEL_OPTION || ans == JOptionPane.CLOSED_OPTION) return;
            if (ans == JOptionPane.YES_OPTION) {
                saveToDisk();
                if (dirty) return; // save failed — stay open
            }
        }
        dispose();
    }
}
