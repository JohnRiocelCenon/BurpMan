package burp.ui;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.io.File;

/**
 * Bruno-style "Import Collection" dialog shown when the user loads a new
 * collection file. Asks for:
 *
 * <ul>
 *   <li><b>Name</b> — folder name for the workspace (defaults to the
 *       collection's {@code info.name} when present).</li>
 *   <li><b>Location</b> — parent directory that will hold the workspace
 *       folder (defaults to a visible {@code BurpMan-Workspaces} folder
 *       under the user's Documents / OneDrive-Documents).</li>
 *   <li><b>File Format</b> — {@code Bruno (.bru)} or
 *       {@code OpenCollection (YAML)}, used as the default format when
 *       the user later clicks <b>+ New env</b> in the Overview tab.</li>
 * </ul>
 *
 * <p>This matches Bruno's own "Import Collection" dialog UX. Cancel discards
 * the import (no workspace is created); Import validates that Name and
 * Location aren't empty, then closes with {@link #isConfirmed()} true.
 */
public class ImportCollectionDialog extends JDialog {

    private final JTextField nameField;
    private final JTextField locationField;
    private final JComboBox<String> formatCombo;
    private boolean confirmed;

    public ImportCollectionDialog(Component parent,
                                  String defaultName,
                                  String defaultLocation,
                                  String defaultFormat) {
        super(ownerFrame(parent), "Import Collection", true);
        setLayout(new BorderLayout());

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(20, 24, 12, 24));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6, 6, 6, 6);
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 0.0;

        // Name row -----------------------------------------------------------
        c.gridx = 0; c.gridy = 0;
        JLabel nameLbl = new JLabel("Name");
        nameLbl.setFont(nameLbl.getFont().deriveFont(Font.BOLD, 12f));
        form.add(nameLbl, c);
        c.gridx = 1; c.weightx = 1.0;
        nameField = new JTextField(defaultName == null ? "" : defaultName, 30);
        form.add(nameField, c);

        // Location row -------------------------------------------------------
        c.gridx = 0; c.gridy = 1; c.weightx = 0.0;
        JLabel locLbl = new JLabel("Location");
        locLbl.setFont(locLbl.getFont().deriveFont(Font.BOLD, 12f));
        form.add(locLbl, c);
        c.gridx = 1; c.weightx = 1.0;
        JPanel locRow = new JPanel(new BorderLayout(6, 0));
        locRow.setOpaque(false);
        locationField = new JTextField(defaultLocation == null ? "" : defaultLocation, 30);
        locRow.add(locationField, BorderLayout.CENTER);
        JButton browse = UITheme.button("Browse…", UITheme.BtnStyle.GHOST);
        browse.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            chooser.setDialogTitle("Pick parent folder for the workspace");
            String cur = locationField.getText();
            if (cur != null && !cur.isEmpty()) {
                File f = new File(cur);
                if (f.isDirectory()) chooser.setCurrentDirectory(f);
                else if (f.getParentFile() != null && f.getParentFile().isDirectory()) {
                    chooser.setCurrentDirectory(f.getParentFile());
                }
            }
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                locationField.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });
        locRow.add(browse, BorderLayout.EAST);
        form.add(locRow, c);

        // File format row ----------------------------------------------------
        c.gridx = 0; c.gridy = 2; c.weightx = 0.0;
        JLabel fmtLbl = new JLabel("File Format");
        fmtLbl.setFont(fmtLbl.getFont().deriveFont(Font.BOLD, 12f));
        form.add(fmtLbl, c);
        c.gridx = 1; c.weightx = 1.0;
        formatCombo = new JComboBox<>(new String[] {
            "Bruno (.bru)",
            "OpenCollection (YAML)"
        });
        if ("yaml".equalsIgnoreCase(defaultFormat) || "yml".equalsIgnoreCase(defaultFormat)) {
            formatCombo.setSelectedIndex(1);
        } else {
            formatCombo.setSelectedIndex(0);
        }
        form.add(formatCombo, c);

        // Preview of the final workspace path so users see de-dup live.
        c.gridx = 0; c.gridy = 3; c.gridwidth = 2; c.weightx = 1.0;
        JLabel preview = new JLabel(" ");
        preview.setForeground(UITheme.subtleText());
        preview.setFont(preview.getFont().deriveFont(Font.PLAIN, 11f));
        preview.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));
        form.add(preview, c);
        Runnable updatePreview = () -> {
            String loc = locationField.getText() == null ? "" : locationField.getText().trim();
            String nm = nameField.getText() == null ? "" : nameField.getText().trim();
            if (loc.isEmpty() || nm.isEmpty()) {
                preview.setText(" ");
                return;
            }
            preview.setText("→ " + new File(loc, nm).getAbsolutePath());
        };
        javax.swing.event.DocumentListener dl = new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { updatePreview.run(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { updatePreview.run(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { updatePreview.run(); }
        };
        nameField.getDocument().addDocumentListener(dl);
        locationField.getDocument().addDocumentListener(dl);
        updatePreview.run();

        // Buttons ------------------------------------------------------------
        JPanel btns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        btns.setBorder(BorderFactory.createEmptyBorder(0, 12, 12, 12));
        JButton cancel = UITheme.button("Cancel", UITheme.BtnStyle.GHOST);
        JButton importBtn = UITheme.button("Import", UITheme.BtnStyle.ACCENT);
        cancel.addActionListener(e -> {
            confirmed = false;
            dispose();
        });
        importBtn.addActionListener(e -> {
            String nm = nameField.getText() == null ? "" : nameField.getText().trim();
            String loc = locationField.getText() == null ? "" : locationField.getText().trim();
            if (nm.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                    "Please enter a name for the workspace folder.",
                    "Import Collection",
                    JOptionPane.WARNING_MESSAGE);
                nameField.requestFocusInWindow();
                return;
            }
            if (loc.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                    "Please enter a Location or click Browse… to pick one.",
                    "Import Collection",
                    JOptionPane.WARNING_MESSAGE);
                locationField.requestFocusInWindow();
                return;
            }
            confirmed = true;
            dispose();
        });
        getRootPane().setDefaultButton(importBtn);
        btns.add(cancel);
        btns.add(importBtn);

        add(form, BorderLayout.CENTER);
        add(btns, BorderLayout.SOUTH);
        pack();
        setSize(Math.max(560, getWidth()), Math.max(getHeight(), 260));
        setResizable(true);
        setLocationRelativeTo(parent);
    }

    /** True if the user clicked Import (and validation passed). */
    public boolean isConfirmed() {
        return confirmed;
    }

    /** Workspace folder name entered by the user (trimmed, non-empty when
     *  {@link #isConfirmed()} is true). */
    public String getEnteredName() {
        return nameField.getText() == null ? "" : nameField.getText().trim();
    }

    /** Absolute parent-directory path entered by the user (trimmed,
     *  non-empty when {@link #isConfirmed()} is true). */
    public String getEnteredLocation() {
        return locationField.getText() == null ? "" : locationField.getText().trim();
    }

    /** {@code "bru"} or {@code "yaml"} — used as default when the user
     *  later creates a new environment file. */
    public String getEnteredFormat() {
        int idx = formatCombo.getSelectedIndex();
        return idx == 1 ? "yaml" : "bru";
    }

    private static Frame ownerFrame(Component parent) {
        Window w = parent == null ? null : SwingUtilities.getWindowAncestor(parent);
        return (w instanceof Frame) ? (Frame) w : null;
    }
}
