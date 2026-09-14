package burp.auth;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.datatransfer.DataFlavor;
import java.awt.event.ActionEvent;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 * Last-resort way to finish a browser OAuth flow: the user completes sign-in in whatever
 * browser opened, then hands the redirected URL back to BurpMan.
 *
 * <p>The clipboard is watched while the dialog is open, so copying the address bar is usually
 * all that is needed.
 */
final class OAuthManualCodeDialog {

   private OAuthManualCodeDialog() {
   }

   /**
    * Shows the dialog and blocks until the user supplies a response or cancels.
    * Safe to call from a background thread.
    *
    * @return the parsed authorization response, or null if the user cancelled
    */
   static OAuthCallbackParser.Result prompt(Window owner, String callbackUrl, String expectedState) {
      AtomicReference<OAuthCallbackParser.Result> out = new AtomicReference<>();
      Runnable task = () -> out.set(show(owner, callbackUrl, expectedState));
      try {
         if (SwingUtilities.isEventDispatchThread()) {
            task.run();
         } else {
            SwingUtilities.invokeAndWait(task);
         }
      } catch (Exception ex) {
         return null;
      }
      return out.get();
   }

   private static OAuthCallbackParser.Result show(Window owner, String callbackUrl, String expectedState) {
      JDialog dialog = new JDialog(owner, "Finish OAuth Sign-In", JDialog.ModalityType.APPLICATION_MODAL);
      AtomicReference<OAuthCallbackParser.Result> accepted = new AtomicReference<>();

      JTextArea input = new JTextArea(4, 58);
      input.setLineWrap(true);
      input.setWrapStyleWord(false);
      input.setBorder(BorderFactory.createCompoundBorder(
         BorderFactory.createLineBorder(new Color(160, 160, 160)),
         BorderFactory.createEmptyBorder(6, 6, 6, 6)));

      JLabel status = new JLabel(" ");
      JButton useIt = new JButton("Use This Code");
      useIt.setEnabled(false);

      AtomicReference<OAuthCallbackParser.Result> current = new AtomicReference<>();
      Runnable revalidate = () -> {
         OAuthCallbackParser.Result parsed = OAuthCallbackParser.parse(input.getText());
         current.set(parsed);
         if (parsed.isEmpty()) {
            status.setForeground(new Color(120, 120, 120));
            status.setText(input.getText().trim().isEmpty()
               ? "Waiting for the redirected URL\u2026"
               : "No authorization code found in that text.");
            useIt.setEnabled(false);
            return;
         }
         if (parsed.hasError()) {
            status.setForeground(new Color(178, 34, 34));
            status.setText("\u26a0 Authorization server returned: " + parsed.errorMessage());
            useIt.setEnabled(false);
            return;
         }
         StringBuilder sb = new StringBuilder();
         if (parsed.hasCode()) {
            sb.append("\u2714 Found authorization code (").append(parsed.code.length()).append(" chars)");
         } else {
            sb.append("\u2714 Found access token (").append(parsed.accessToken.length()).append(" chars)");
         }
         boolean stateOk = true;
         if (expectedState != null && !expectedState.trim().isEmpty()) {
            stateOk = expectedState.trim().equals(parsed.state);
            sb.append(stateOk ? "; state matches." : "; \u26a0 state does NOT match \u2014 possible cross-site response.");
         }
         status.setForeground(stateOk ? new Color(0, 128, 0) : new Color(200, 120, 0));
         status.setText(sb.toString());
         useIt.setEnabled(true);
      };

      input.getDocument().addDocumentListener(new DocumentListener() {
         public void insertUpdate(DocumentEvent e) {
            revalidate.run();
         }

         public void removeUpdate(DocumentEvent e) {
            revalidate.run();
         }

         public void changedUpdate(DocumentEvent e) {
            revalidate.run();
         }
      });

      // Watch the clipboard so copying the address bar is enough.
      AtomicReference<String> lastSeen = new AtomicReference<>("");
      Timer clipboardWatcher = new Timer(500, (ActionEvent e) -> {
         String text = readClipboard();
         if (text == null || text.equals(lastSeen.get())) return;
         lastSeen.set(text);
         if (OAuthCallbackParser.parse(text).isEmpty()) return;
         if (text.trim().equals(input.getText().trim())) return;
         input.setText(text.trim());
         status.setText("\u2714 Picked up from clipboard.");
      });
      clipboardWatcher.setRepeats(true);

      JPanel content = new JPanel(new BorderLayout(0, 10));
      content.setBorder(BorderFactory.createEmptyBorder(14, 16, 12, 16));

      JPanel header = new JPanel();
      header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
      // Burp turns off HTML rendering in Swing labels, so this has to stay plain text.
      JLabel title = new JLabel("Complete the sign-in in your browser.");
      title.setFont(title.getFont().deriveFont(java.awt.Font.BOLD));
      header.add(left(title));
      header.add(Box.createVerticalStrut(6));
      header.add(left(new JLabel("When it finishes, the browser lands on the callback URL.")));
      header.add(left(new JLabel("Copy that whole address from the address bar — it is picked up automatically.")));
      if (callbackUrl != null && !callbackUrl.trim().isEmpty()) {
         header.add(Box.createVerticalStrut(8));
         JPanel row = new JPanel(new GridBagLayout());
         GridBagConstraints c = new GridBagConstraints();
         c.gridx = 0;
         c.gridy = 0;
         c.anchor = GridBagConstraints.WEST;
         c.insets = new Insets(0, 0, 0, 8);
         row.add(new JLabel("Expected callback:"), c);
         c.gridx = 1;
         c.weightx = 1.0;
         c.fill = GridBagConstraints.HORIZONTAL;
         JLabel cb = new JLabel(callbackUrl.trim());
         cb.setForeground(new Color(70, 90, 160));
         row.add(cb, c);
         header.add(left(row));
      }
      content.add(header, BorderLayout.NORTH);

      JPanel middle = new JPanel(new BorderLayout(0, 6));
      middle.add(new JScrollPane(input), BorderLayout.CENTER);
      middle.add(status, BorderLayout.SOUTH);
      content.add(middle, BorderLayout.CENTER);

      JButton cancel = new JButton("Cancel");
      JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
      buttons.add(cancel);
      buttons.add(useIt);
      content.add(buttons, BorderLayout.SOUTH);

      useIt.addActionListener(e -> {
         accepted.set(current.get());
         dialog.dispose();
      });
      cancel.addActionListener(e -> dialog.dispose());

      dialog.setContentPane(content);
      dialog.getRootPane().setDefaultButton(useIt);
      dialog.pack();
      dialog.setMinimumSize(new Dimension(620, dialog.getHeight()));
      dialog.setLocationRelativeTo(owner);
      revalidate.run();
      clipboardWatcher.start();
      try {
         dialog.setVisible(true);
      } finally {
         clipboardWatcher.stop();
      }
      return accepted.get();
   }

   private static JPanel left(java.awt.Component component) {
      JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
      panel.add(component);
      return panel;
   }

   private static String readClipboard() {
      try {
         Object data = Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor);
         return data instanceof String ? (String) data : null;
      } catch (Exception ex) {
         return null;
      }
   }
}
