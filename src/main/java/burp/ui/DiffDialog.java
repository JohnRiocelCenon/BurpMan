package burp.ui;

import burp.models.ExecutedRequest;
import burp.models.PostmanCollection;
import burp.utils.FormatUtils;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.Window;
import java.awt.Dialog.ModalityType;
import java.util.ArrayList;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.event.ChangeListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

public class DiffDialog extends JDialog {
   public static void show(Component parent, ExecutedRequest left, ExecutedRequest right) {
      Window w = parent == null ? null : SwingUtilities.getWindowAncestor(parent);
      DiffDialog d = new DiffDialog(w, left, right);
      d.setLocationRelativeTo(parent);
      d.setVisible(true);
   }

   private DiffDialog(Window owner, ExecutedRequest left, ExecutedRequest right) {
      super(owner, "Compare Responses", ModalityType.APPLICATION_MODAL);
      this.setSize(1200, 700);
      this.setLayout(new BorderLayout());
      JTabbedPane tabs = new JTabbedPane();
      tabs.addTab("Body", this.buildBodyTab(left, right));
      tabs.addTab("Headers", this.buildHeadersTab(left, right));
      tabs.addTab("Status & Timing", this.buildStatusTab(left, right));
      this.add(this.buildHeader(left, right), "North");
      this.add(tabs, "Center");
      JPanel south = new JPanel(new FlowLayout(2));
      JButton close = new JButton("Close");
      close.addActionListener(e -> this.dispose());
      south.add(close);
      this.add(south, "South");
   }

   private JComponent buildHeader(ExecutedRequest left, ExecutedRequest right) {
      JPanel p = new JPanel(new GridLayout(1, 2));
      p.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
      p.add(this.buildLabelBlock("Left  (A)", left));
      p.add(this.buildLabelBlock("Right (B)", right));
      return p;
   }

   private JComponent buildLabelBlock(String title, ExecutedRequest r) {
      JLabel lbl = new JLabel(
         String.format(
            "<html><b>%s</b><br/>%s · <i>%s</i><br/>%d %s · %d ms</html>",
            title,
            r == null ? "(none)" : safe(r.getMethod()),
            r == null ? "" : safe(r.getUrl()),
            r == null ? 0 : r.getStatusCode(),
            r == null ? "" : safe(r.getStatusText()),
            r == null ? 0L : r.getDurationMs()
         )
      );
      lbl.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
      return lbl;
   }

   private JComponent buildBodyTab(ExecutedRequest a, ExecutedRequest b) {
      String aBody = pretty(a);
      String bBody = pretty(b);
      return this.buildSideBySide(aBody, bBody);
   }

   private JComponent buildHeadersTab(ExecutedRequest a, ExecutedRequest b) {
      return this.buildSideBySide(formatHeaders(a), formatHeaders(b));
   }

   private JComponent buildStatusTab(ExecutedRequest a, ExecutedRequest b) {
      String aTxt = describe(a);
      String bTxt = describe(b);
      return this.buildSideBySide(aTxt, bTxt);
   }

   private static String describe(ExecutedRequest r) {
      if (r == null) {
         return "(no response)";
      } else {
         StringBuilder sb = new StringBuilder();
         sb.append("Status:        ").append(r.getStatusCode()).append(' ').append(safe(r.getStatusText())).append('\n');
         sb.append("Duration (ms): ").append(r.getDurationMs()).append('\n');
         sb.append("Content-Type:  ").append(safe(r.getContentType())).append('\n');
         sb.append("Success:       ").append(r.isSuccess() ? "Yes" : "No").append('\n');
         if (r.getError() != null) {
            sb.append("Error:         ").append(r.getError()).append('\n');
         }

         sb.append("Method:        ").append(safe(r.getMethod())).append('\n');
         sb.append("URL:           ").append(safe(r.getUrl())).append('\n');
         if (r.getResponseBody() != null) {
            sb.append("Body size:     ").append(r.getResponseBody().length()).append(" chars\n");
         }

         return sb.toString();
      }
   }

   private static String formatHeaders(ExecutedRequest r) {
      if (r != null && r.getResponseHeaders() != null) {
         StringBuilder sb = new StringBuilder();

         for (PostmanCollection.Header h : r.getResponseHeaders()) {
            sb.append(h.key == null ? "" : h.key).append(": ").append(h.value == null ? "" : h.value).append('\n');
         }

         return sb.toString();
      } else {
         return "";
      }
   }

   private static String pretty(ExecutedRequest r) {
      if (r != null && r.getResponseBody() != null) {
         String body = r.getResponseBody();
         String ct = r.getContentType() == null ? "" : r.getContentType().toLowerCase();

         try {
            if (ct.contains("json")) {
               return FormatUtils.prettyPrintJson(body);
            }

            if (ct.contains("xml") || ct.contains("html")) {
               return FormatUtils.prettyPrintXml(body);
            }
         } catch (Exception var4) {
         }

         return body;
      } else {
         return "";
      }
   }

   private static String safe(String s) {
      return s == null ? "" : s;
   }

   private JComponent buildSideBySide(String left, String right) {
      JTextPane leftPane = newColoredPane();
      JTextPane rightPane = newColoredPane();
      renderDiff(leftPane, rightPane, left == null ? "" : left, right == null ? "" : right);
      JScrollPane ls = new JScrollPane(leftPane);
      JScrollPane rs = new JScrollPane(rightPane);
      ChangeListener sync = e -> {
         if (e.getSource() == ls.getVerticalScrollBar().getModel()) {
            rs.getVerticalScrollBar().setValue(ls.getVerticalScrollBar().getValue());
         } else {
            ls.getVerticalScrollBar().setValue(rs.getVerticalScrollBar().getValue());
         }
      };
      ls.getVerticalScrollBar().getModel().addChangeListener(sync);
      rs.getVerticalScrollBar().getModel().addChangeListener(sync);
      JSplitPane split = new JSplitPane(1, ls, rs);
      split.setResizeWeight(0.5);
      split.setDividerLocation(580);
      return split;
   }

   private static JTextPane newColoredPane() {
      JTextPane p = new JTextPane();
      p.setEditable(false);
      p.setFont(new Font("Monospaced", 0, 12));
      return p;
   }

   private static void renderDiff(JTextPane leftPane, JTextPane rightPane, String leftText, String rightText) {
      String[] a = leftText.split("\n", -1);
      String[] b = rightText.split("\n", -1);
      int[][] lcs = new int[a.length + 1][b.length + 1];

      for (int i = a.length - 1; i >= 0; i--) {
         for (int j = b.length - 1; j >= 0; j--) {
            if (a[i].equals(b[j])) {
               lcs[i][j] = lcs[i + 1][j + 1] + 1;
            } else {
               lcs[i][j] = Math.max(lcs[i + 1][j], lcs[i][j + 1]);
            }
         }
      }

      List<String[]> leftRows = new ArrayList<>();
      List<String[]> rightRows = new ArrayList<>();
      int i = 0;
      int jx = 0;

      while (i < a.length && jx < b.length) {
         if (a[i].equals(b[jx])) {
            leftRows.add(new String[]{a[i], "eq"});
            rightRows.add(new String[]{b[jx], "eq"});
            i++;
            jx++;
         } else if (lcs[i + 1][jx] >= lcs[i][jx + 1]) {
            leftRows.add(new String[]{a[i], "del"});
            rightRows.add(new String[]{"", "fill"});
            i++;
         } else {
            leftRows.add(new String[]{"", "fill"});
            rightRows.add(new String[]{b[jx], "ins"});
            jx++;
         }
      }

      while (i < a.length) {
         leftRows.add(new String[]{a[i], "del"});
         rightRows.add(new String[]{"", "fill"});
         i++;
      }

      while (jx < b.length) {
         leftRows.add(new String[]{"", "fill"});
         rightRows.add(new String[]{b[jx], "ins"});
         jx++;
      }

      paint(leftPane, leftRows);
      paint(rightPane, rightRows);
   }

   private static void paint(JTextPane pane, List<String[]> rows) {
      StyledDocument doc = pane.getStyledDocument();
      SimpleAttributeSet eqAttr = new SimpleAttributeSet();
      StyleConstants.setForeground(eqAttr, new Color(85, 85, 85));
      SimpleAttributeSet delAttr = new SimpleAttributeSet();
      StyleConstants.setForeground(delAttr, new Color(183, 28, 28));
      StyleConstants.setBackground(delAttr, new Color(255, 235, 238));
      SimpleAttributeSet insAttr = new SimpleAttributeSet();
      StyleConstants.setForeground(insAttr, new Color(27, 94, 32));
      StyleConstants.setBackground(insAttr, new Color(232, 245, 233));
      SimpleAttributeSet fillAttr = new SimpleAttributeSet();
      StyleConstants.setBackground(fillAttr, new Color(250, 250, 250));

      try {
         doc.remove(0, doc.getLength());
         int row = 1;

         for (String[] r : rows) {
            String line;
            SimpleAttributeSet a;
            String prefix;
            label35: {
               line = r[0] == null ? "" : r[0];
               String tag = r[1];
               switch (tag.hashCode()) {
                  case 99339:
                     if (tag.equals("del")) {
                        a = delAttr;
                        prefix = "- ";
                        break label35;
                     }
                     break;
                  case 104430:
                     if (tag.equals("ins")) {
                        a = insAttr;
                        prefix = "+ ";
                        break label35;
                     }
                     break;
                  case 3143043:
                     if (tag.equals("fill")) {
                        a = fillAttr;
                        prefix = "  ";
                        break label35;
                     }
               }

               a = eqAttr;
               prefix = "  ";
            }

            String lineNo = String.format("%4d  ", row++);
            doc.insertString(doc.getLength(), lineNo + prefix + line + "\n", a);
         }
      } catch (BadLocationException var15) {
      }

      pane.setCaretPosition(0);
   }
}
