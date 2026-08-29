package burp.ui;

import burp.models.PostmanCollection;
import burp.parser.CurlCommandParser;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.datatransfer.DataFlavor;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

public final class CurlImportDialog extends JDialog {
   public static void show(Component owner, CurlImportDialog.OnImported callback) {
      Window w = SwingUtilities.getWindowAncestor(owner);
      CurlImportDialog dlg;
      if (w instanceof Frame) {
         dlg = new CurlImportDialog((Frame)w, callback);
      } else if (w instanceof Dialog) {
         dlg = new CurlImportDialog((Dialog)w, callback);
      } else {
         dlg = new CurlImportDialog((Frame)null, callback);
      }

      dlg.setLocationRelativeTo(owner);
      dlg.setVisible(true);
   }

   private CurlImportDialog(Frame owner, CurlImportDialog.OnImported cb) {
      super(owner, "Import from cURL", true);
      this.init(cb);
   }

   private CurlImportDialog(Dialog owner, CurlImportDialog.OnImported cb) {
      super(owner, "Import from cURL", true);
      this.init(cb);
   }

   private void init(CurlImportDialog.OnImported callback) {
      this.setSize(720, 460);
      this.setLayout(new BorderLayout(0, 4));
      JLabel hint = new JLabel("Paste a curl command (from docs, terminal, browser DevTools, Postman's Copy as cURL, etc.):");
      hint.setBorder(BorderFactory.createEmptyBorder(8, 10, 4, 10));
      hint.setFont(hint.getFont().deriveFont(0, 12.0F));
      JTextArea area = new JTextArea();
      area.setFont(new Font("Monospaced", 0, 12));
      area.setLineWrap(true);
      area.setWrapStyleWord(false);
      UndoSupport.install(area);

      try {
         String clip = (String)Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor);
         if (clip != null) {
            String trimmed = clip.trim();
            if (trimmed.regionMatches(true, 0, "curl", 0, 4) || trimmed.startsWith("$ curl")) {
               area.setText(clip);
            }
         }
      } catch (Throwable var11) {
      }

      JScrollPane scroll = new JScrollPane(area);
      scroll.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
      JLabel statusLbl = new JLabel(" ");
      statusLbl.setBorder(BorderFactory.createEmptyBorder(4, 10, 0, 10));
      statusLbl.setForeground(new Color(136, 136, 136));
      JPanel south = new JPanel(new FlowLayout(2, 6, 6));
      JButton cancel = new JButton("Cancel");
      cancel.addActionListener(e -> this.dispose());
      south.add(cancel);
      JButton importBtn = new JButton("Import");
      importBtn.addActionListener(e -> {
         String cmd = area.getText();
         if (cmd != null && !cmd.trim().isEmpty()) {
            try {
               PostmanCollection.Request req = new CurlCommandParser().parse(cmd);
               if (callback != null) {
                  callback.onImported(req);
               }

               this.dispose();
            } catch (Exception var7x) {
               statusLbl.setForeground(new Color(198, 40, 40));
               statusLbl.setText("Parse failed: " + var7x.getMessage());
            }
         } else {
            statusLbl.setForeground(new Color(198, 40, 40));
            statusLbl.setText("Paste a curl command first.");
         }
      });
      this.getRootPane().setDefaultButton(importBtn);
      south.add(importBtn);
      JPanel northStack = new JPanel(new BorderLayout());
      northStack.add(hint, "North");
      northStack.add(statusLbl, "South");
      JPanel southStack = new JPanel(new BorderLayout());
      southStack.add(south, "East");
      this.add(northStack, "North");
      this.add(scroll, "Center");
      this.add(southStack, "South");
   }

   public interface OnImported {
      void onImported(PostmanCollection.Request var1);
   }
}
