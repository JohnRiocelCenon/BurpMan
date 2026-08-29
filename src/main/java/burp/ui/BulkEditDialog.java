package burp.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.awt.Window;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

public final class BulkEditDialog extends JDialog {
   public static void show(Component owner, String title, String hint, Map<String, String> initial, BulkEditDialog.OnApply callback) {
      Window w = SwingUtilities.getWindowAncestor(owner);
      BulkEditDialog dlg;
      if (w instanceof Frame) {
         dlg = new BulkEditDialog((Frame)w, title, hint, initial, callback);
      } else if (w instanceof Dialog) {
         dlg = new BulkEditDialog((Dialog)w, title, hint, initial, callback);
      } else {
         dlg = new BulkEditDialog((Frame)null, title, hint, initial, callback);
      }

      dlg.setLocationRelativeTo(owner);
      dlg.setVisible(true);
   }

   private BulkEditDialog(Frame owner, String title, String hint, Map<String, String> initial, BulkEditDialog.OnApply cb) {
      super(owner, title, true);
      this.init(hint, initial, cb);
   }

   private BulkEditDialog(Dialog owner, String title, String hint, Map<String, String> initial, BulkEditDialog.OnApply cb) {
      super(owner, title, true);
      this.init(hint, initial, cb);
   }

   private void init(String hintText, Map<String, String> initial, BulkEditDialog.OnApply callback) {
      this.setSize(720, 520);
      this.setLayout(new BorderLayout(0, 4));
      JLabel hint = new JLabel(hintText == null ? "One entry per line:   Key:Value  or  Key=Value" : hintText);
      hint.setBorder(BorderFactory.createEmptyBorder(8, 10, 4, 10));
      JTextArea area = new JTextArea();
      area.setFont(new Font("Monospaced", 0, 12));
      area.setLineWrap(false);
      UndoSupport.install(area);
      if (initial != null && !initial.isEmpty()) {
         StringBuilder sb = new StringBuilder();

         for (Entry<String, String> e : initial.entrySet()) {
            String k = e.getKey() == null ? "" : e.getKey();
            String v = e.getValue() == null ? "" : e.getValue();
            sb.append(k).append(": ").append(v).append('\n');
         }

         area.setText(sb.toString());
         area.setCaretPosition(0);
      }

      JLabel counter = new JLabel(" ");
      counter.setForeground(new Color(136, 136, 136));
      counter.setBorder(BorderFactory.createEmptyBorder(4, 10, 0, 10));
      final Runnable updateCounter = () -> {
         int rows = countEntries(area.getText());
         counter.setText(rows + " entr" + (rows == 1 ? "y" : "ies"));
      };
      area.getDocument().addDocumentListener(new DocumentListener() {
         @Override
         public void insertUpdate(DocumentEvent e) {
            updateCounter.run();
         }

         @Override
         public void removeUpdate(DocumentEvent e) {
            updateCounter.run();
         }

         @Override
         public void changedUpdate(DocumentEvent e) {
            updateCounter.run();
         }
      });
      updateCounter.run();
      JButton cancel = new JButton("Cancel");
      cancel.addActionListener(e -> this.dispose());
      JButton apply = new JButton("Apply");
      apply.addActionListener(e -> {
         Map<String, String> parsed = parse(area.getText());
         if (callback != null) {
            callback.apply(parsed);
         }

         this.dispose();
      });
      this.getRootPane().setDefaultButton(apply);
      JPanel south = new JPanel(new BorderLayout());
      JPanel southRight = new JPanel(new FlowLayout(2, 6, 6));
      southRight.add(cancel);
      southRight.add(apply);
      south.add(counter, "West");
      south.add(southRight, "East");
      this.add(hint, "North");
      this.add(new JScrollPane(area), "Center");
      this.add(south, "South");
      this.setMinimumSize(new Dimension(480, 320));
   }

   public static Map<String, String> parse(String text) {
      Map<String, String> out = new LinkedHashMap<>();
      if (text != null && !text.isEmpty()) {
         String[] var5;
         for (String line : var5 = text.split("\\r?\\n")) {
            if (line != null) {
               String trimmed = line.trim();
               if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                  int sep = -1;
                  int colon = trimmed.indexOf(58);
                  int equal = trimmed.indexOf(61);
                  if (colon < 0 || equal >= 0 && colon >= equal) {
                     if (equal >= 0) {
                        sep = equal;
                     }
                  } else {
                     sep = colon;
                  }

                  if (sep < 0) {
                     out.put(trimmed, "");
                  } else {
                     String k = trimmed.substring(0, sep).trim();
                     String v = trimmed.substring(sep + 1).trim();
                     if (!k.isEmpty()) {
                        out.put(k, v);
                     }
                  }
               }
            }
         }

         return out;
      } else {
         return out;
      }
   }

   private static int countEntries(String text) {
      if (text == null) {
         return 0;
      } else {
         int n = 0;

         String[] var5;
         for (String line : var5 = text.split("\\r?\\n")) {
            String t = line.trim();
            if (!t.isEmpty() && !t.startsWith("#")) {
               n++;
            }
         }

         return n;
      }
   }

   public static Map<String, String> listToMap(List<String[]> rows) {
      Map<String, String> m = new LinkedHashMap<>();
      if (rows == null) {
         return m;
      } else {
         for (String[] kv : rows) {
            if (kv != null && kv.length >= 1 && kv[0] != null) {
               m.put(kv[0], kv.length > 1 && kv[1] != null ? kv[1] : "");
            }
         }

         return m;
      }
   }

   public interface OnApply {
      void apply(Map<String, String> var1);
   }
}
