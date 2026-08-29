package burp.ui;

import burp.service.ProxyRouter;
import burp.service.ProxySettings;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JEditorPane;
import javax.swing.JFormattedTextField;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.text.NumberFormatter;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.GraphicsConfiguration;
import java.awt.GraphicsEnvironment;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.Window;
import java.text.NumberFormat;
import java.util.function.Consumer;

/**
 * Modal dialog for editing {@link ProxySettings}.
 *
 * <p>Fields: on/off toggle, host, port, bypass-localhost, trust-all-certs.
 * Includes a "Test connection" button that does a TCP-level reachability
 * check. Applies changes only when OK is pressed; Cancel discards.
 *
 * <p>An optional {@code onApplied} callback fires after successful save
 * so the toolbar button can re-render its status label.
 */
public final class ProxySettingsDialog extends JDialog {

    private final JCheckBox enabledBox = new JCheckBox("Route BurpMan traffic through this proxy");
    private final JTextField hostField = new JTextField(20);
    private final JFormattedTextField portField;
    private final JCheckBox bypassBox  = new JCheckBox("Bypass localhost / 127.0.0.1");
    private final JCheckBox insecureBox = new JCheckBox("Trust all TLS certs (recommended for Burp Proxy)");
    private final JLabel statusLabel   = new JLabel(" ");

    private final Consumer<ProxySettings> onApplied;

    public ProxySettingsDialog(Component parent, Consumer<ProxySettings> onApplied) {
        super(ownerFrame(parent), "BurpMan — Upstream Proxy Settings", true);
        this.onApplied = onApplied;

        NumberFormat fmt = NumberFormat.getIntegerInstance();
        fmt.setGroupingUsed(false);
        NumberFormatter nf = new NumberFormatter(fmt);
        nf.setValueClass(Integer.class);
        nf.setMinimum(1);
        nf.setMaximum(65535);
        nf.setAllowsInvalid(false);
        this.portField = new JFormattedTextField(nf);
        this.portField.setColumns(6);

        ProxySettings ps = ProxySettings.get();
        enabledBox.setSelected(ps.isEnabled());
        hostField.setText(ps.getHost());
        portField.setValue(ps.getPort());
        bypassBox.setSelected(ps.isBypassLocalhost());
        insecureBox.setSelected(ps.isTrustAllCerts());

        setContentPane(buildContent());
        pack();
        setMinimumSize(new Dimension(520, getHeight()));
        clampToScreen(parent);
        setLocationRelativeTo(parent);
        setResizable(false);
        toggleFieldEnable();
        enabledBox.addActionListener(e -> toggleFieldEnable());
    }

    /**
     * Ensure the dialog fits within the screen it will appear on. Burp Suite
     * dialogs occasionally end up wider than the visible screen (very small
     * laptop displays, DPI mismatches on multi-monitor setups) which pushes
     * the OK/Cancel buttons off-screen and leaves the user stranded. We cap
     * the size to 96 % of the target screen's usable bounds so the whole
     * dialog stays clickable.
     */
    private void clampToScreen(Component parent) {
        try {
            Rectangle screen;
            GraphicsConfiguration gc = null;
            if (parent != null) {
                Window w = javax.swing.SwingUtilities.getWindowAncestor(parent);
                if (w != null) gc = w.getGraphicsConfiguration();
            }
            if (gc == null) {
                gc = GraphicsEnvironment.getLocalGraphicsEnvironment()
                    .getDefaultScreenDevice().getDefaultConfiguration();
            }
            screen = gc.getBounds();
            java.awt.Insets sInsets = Toolkit.getDefaultToolkit().getScreenInsets(gc);
            int maxW = Math.max(320, screen.width - sInsets.left - sInsets.right - 24);
            int maxH = Math.max(240, screen.height - sInsets.top - sInsets.bottom - 24);
            // Cap to 96% of usable screen so borders + shadows stay visible.
            maxW = (int) Math.floor(maxW * 0.96);
            maxH = (int) Math.floor(maxH * 0.96);
            Dimension cur = getSize();
            int newW = Math.min(cur.width, maxW);
            int newH = Math.min(cur.height, maxH);
            if (newW != cur.width || newH != cur.height) {
                setSize(newW, newH);
            }
        } catch (Exception ignore) {
            // Best-effort only — don't block the dialog from opening.
        }
    }

    private static Frame ownerFrame(Component parent) {
        Window w = parent == null ? null : javax.swing.SwingUtilities.getWindowAncestor(parent);
        return (w instanceof Frame) ? (Frame) w : null;
    }

    private JPanel buildContent() {
        JPanel root = new JPanel(new BorderLayout(0, 8));
        root.setBorder(BorderFactory.createEmptyBorder(14, 14, 12, 14));

        JLabel title = new JLabel("Upstream Proxy");
        title.setFont(title.getFont().deriveFont(java.awt.Font.BOLD, 14f));

        // Use JEditorPane instead of JLabel because Burp Suite disables HTML
        // rendering on JLabels globally (BasicHTML.propertyKey = false in the
        // shared UIManager). JEditorPane with content-type "text/html" always
        // renders HTML regardless of that setting.
        JEditorPane help = new JEditorPane("text/html",
            "<html><div style='width:460px;color:#666;font-size:11px;font-family:sans-serif'>"
            + "When enabled, every request BurpMan sends is routed through the "
            + "upstream proxy below. Point this at Burp's own Proxy listener "
            + "(default <b>127.0.0.1:8080</b>) so runs appear in "
            + "<b>Proxy&nbsp;→&nbsp;HTTP&nbsp;history</b>, not just Logger."
            + "</div></html>");
        help.setEditable(false);
        help.setOpaque(false);
        help.setBorder(BorderFactory.createEmptyBorder());

        JEditorPane loopWarning = new JEditorPane("text/html",
            "<html><div style='width:460px;background:#fff5e6;"
            + "border:1px solid #e0a060;padding:6px;color:#7a4a10;font-size:11px;font-family:sans-serif'>"
            + "⚠ <b>First-time setup</b>: If Burp shows "
            + "<i>\"Dropped request looping back to same Proxy listener\"</i>, go to "
            + "<b>Burp → Settings → Tools → Proxy → Miscellaneous</b> and uncheck "
            + "<b>\"Drop requests that appear to be looping back to the same "
            + "proxy listener\"</b>. Loop-detection blocks same-process traffic by default."
            + "</div></html>");
        loopWarning.setEditable(false);
        loopWarning.setOpaque(false);
        loopWarning.setBorder(BorderFactory.createEmptyBorder());

        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        help.setAlignmentX(Component.LEFT_ALIGNMENT);
        loopWarning.setAlignmentX(Component.LEFT_ALIGNMENT);
        top.add(title);
        top.add(Box.createVerticalStrut(4));
        top.add(help);
        top.add(Box.createVerticalStrut(8));
        top.add(loopWarning);

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;

        c.gridx = 0; c.gridy = 0; c.gridwidth = 3;
        form.add(enabledBox, c);

        c.gridwidth = 1;
        c.gridy = 1; c.gridx = 0; c.weightx = 0;
        form.add(new JLabel("Host:"), c);
        c.gridx = 1; c.weightx = 1.0;
        form.add(hostField, c);
        c.gridx = 2; c.weightx = 0;
        form.add(new JLabel("(e.g. 127.0.0.1)"), c);

        c.gridy = 2; c.gridx = 0; c.weightx = 0;
        form.add(new JLabel("Port:"), c);
        c.gridx = 1; c.weightx = 0;
        JPanel portPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        portPanel.add(portField);
        JButton test = new JButton("Test connection");
        test.addActionListener(e -> onTest());
        portPanel.add(test);
        form.add(portPanel, c);
        c.gridx = 2;
        form.add(new JLabel("(Burp default: 8080)"), c);

        c.gridy = 3; c.gridx = 0; c.gridwidth = 3;
        form.add(bypassBox, c);
        c.gridy = 4;
        form.add(insecureBox, c);

        c.gridy = 5;
        statusLabel.setHorizontalAlignment(SwingConstants.LEFT);
        statusLabel.setFont(statusLabel.getFont().deriveFont(11f));
        form.add(statusLabel, c);

        JPanel south = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JButton cancel = new JButton("Cancel");
        cancel.addActionListener(e -> dispose());
        JButton ok = new JButton("Save");
        ok.addActionListener(e -> onSave());
        south.add(cancel);
        south.add(ok);
        getRootPane().setDefaultButton(ok);

        root.add(top,  BorderLayout.NORTH);
        root.add(form, BorderLayout.CENTER);
        root.add(south, BorderLayout.SOUTH);
        return root;
    }

    private void toggleFieldEnable() {
        boolean on = enabledBox.isSelected();
        hostField.setEnabled(on);
        portField.setEnabled(on);
        bypassBox.setEnabled(on);
        insecureBox.setEnabled(on);
    }

    private void onTest() {
        String host = hostField.getText().trim();
        int port = portValue();
        if (host.isEmpty() || port <= 0) {
            statusLabel.setText("⚠ Enter host and port first.");
            return;
        }
        statusLabel.setText("… testing " + host + ":" + port + " …");
        new Thread(() -> {
            String err = ProxyRouter.testConnection(host, port);
            javax.swing.SwingUtilities.invokeLater(() -> {
                if (err == null) statusLabel.setText("✅ " + host + ":" + port + " is reachable.");
                else             statusLabel.setText("❌ " + err);
            });
        }, "burpman-proxy-test").start();
    }

    private void onSave() {
        String host = hostField.getText().trim();
        int port = portValue();
        if (enabledBox.isSelected()) {
            if (host.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                    "Please enter a proxy host.", "Missing host",
                    JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (port <= 0 || port > 65535) {
                JOptionPane.showMessageDialog(this,
                    "Port must be between 1 and 65535.", "Invalid port",
                    JOptionPane.WARNING_MESSAGE);
                return;
            }
        }
        ProxySettings ps = ProxySettings.get();
        ps.update(enabledBox.isSelected(), host, port,
            bypassBox.isSelected(), insecureBox.isSelected());
        if (onApplied != null) {
            try { onApplied.accept(ps); } catch (Throwable ignore) {}
        }
        dispose();
    }

    private int portValue() {
        try {
            Object v = portField.getValue();
            if (v instanceof Number) return ((Number) v).intValue();
            return Integer.parseInt(portField.getText().trim());
        } catch (Exception e) {
            return -1;
        }
    }
}
