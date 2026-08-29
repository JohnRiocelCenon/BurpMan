package burp.ui;

import burp.models.ExecutedRequest;
import burp.models.PostmanCollection;
import burp.utils.FormatUtils;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.io.StringReader;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextPane;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

public class ResponsePanel extends JPanel {
   private JTabbedPane tabbedPane;
   private ResponsePanel.BodyViewer prettyViewer;
   private ResponsePanel.BodyViewer rawViewer;
   private ResponsePanel.HeadersViewer headersViewer;
   private ResponsePanel.PreviewViewer previewViewer;
   private JTextArea detailsArea;
   private JTextPane testsArea;
   private JLabel statusLabel;
   private String lastBody = "";
   private String lastContentType = "";
   private ExecutedRequest lastResponse;

   public ExecutedRequest getCurrentResponse() {
      return this.lastResponse;
   }

   public ResponsePanel() {
      this.setLayout(new BorderLayout());
      this.initializeComponents();
   }

   private void initializeComponents() {
      this.tabbedPane = new JTabbedPane();
      this.tabbedPane.setFont(UITheme.boldFont(12.0F));
      this.prettyViewer = new ResponsePanel.BodyViewer(true);
      this.tabbedPane.addTab("Pretty", this.prettyViewer);
      this.rawViewer = new ResponsePanel.BodyViewer(false);
      this.tabbedPane.addTab("Raw", this.rawViewer);
      this.headersViewer = new ResponsePanel.HeadersViewer();
      this.tabbedPane.addTab("Headers", this.headersViewer);
      this.previewViewer = new ResponsePanel.PreviewViewer();
      this.tabbedPane.addTab("Preview", this.previewViewer);
      this.testsArea = new JTextPane();
      this.testsArea.setEditable(false);
      this.testsArea.setFont(UITheme.monoFont());
      UndoSupport.install(this.testsArea);
      this.tabbedPane.addTab("Tests", createPayloadScroll(this.testsArea, false));
      this.detailsArea = new JTextArea(12, 100);
      this.detailsArea.setEditable(false);
      this.detailsArea.setFont(UITheme.monoFont());
      this.tabbedPane.addTab("Details", createPayloadScroll(this.detailsArea, true));
      this.statusLabel = new JLabel(" ");
      this.statusLabel.setBorder(BorderFactory.createEmptyBorder(6, 10, 6, 10));
      this.statusLabel.setFont(UITheme.boldFont(12.0F));
      this.statusLabel.setOpaque(true);
      this.statusLabel.setBackground(UITheme.surfaceAlt());
      JLabel sectionLabel = new JLabel("  Response");
      sectionLabel.setFont(UITheme.boldFont(13.0F));
      sectionLabel.setBorder(BorderFactory.createEmptyBorder(6, 4, 6, 10));
      sectionLabel.setOpaque(true);
      sectionLabel.setBackground(UITheme.surfaceAlt());
      JPanel statusRow = new JPanel(new BorderLayout());
      statusRow.setOpaque(true);
      statusRow.setBackground(UITheme.surfaceAlt());
      statusRow.add(sectionLabel, "West");
      statusRow.add(this.statusLabel, "Center");
      this.add(statusRow, "North");
      this.add(this.tabbedPane, "Center");
   }

   public void displayResponse(ExecutedRequest request) {
      if (request == null) {
         this.clear();
      } else {
         this.lastResponse = request;
         this.lastBody = request.getResponseBody() == null ? "" : request.getResponseBody();
         this.lastContentType = request.getContentType() == null ? "" : request.getContentType();
         this.prettyViewer.displayBody(this.lastBody, this.lastContentType);
         this.rawViewer.displayBody(this.lastBody, this.lastContentType);
         this.headersViewer.displayHeaders(request.getResponseHeaders());
         this.previewViewer.displayPreview(this.lastBody, this.lastContentType);
         int code = request.getStatusCode();
         Color codeColor = code >= 500
            ? new Color(176, 0, 32)
            : (code >= 400 ? new Color(204, 134, 0) : (code >= 300 ? new Color(60, 90, 140) : (code >= 200 ? new Color(46, 125, 50) : Color.GRAY)));
         int size = this.lastBody.getBytes().length;
         String sizeText = size < 1024 ? size + " B" : (size < 1048576 ? String.format("%.1f KB", size / 1024.0) : String.format("%.1f MB", size / 1048576.0));
         this.statusLabel.setForeground(codeColor);
         this.statusLabel
            .setText(
               String.format(
                  "Status: %d %s   ·   Time: %d ms   ·   Size: %s",
                  code,
                  request.getStatusText() == null ? "" : request.getStatusText(),
                  request.getDurationMs(),
                  sizeText
               )
            );
         StringBuilder detailsText = new StringBuilder();
         SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
         detailsText.append("Status Code: ").append(code).append("\n");
         detailsText.append("Status Text: ").append(request.getStatusText()).append("\n");
         detailsText.append("Duration: ").append(request.getDurationMs()).append(" ms\n");
         detailsText.append("Content-Type: ").append(this.lastContentType.isEmpty() ? "-" : this.lastContentType).append("\n");
         detailsText.append("Success: ").append(request.isSuccess() ? "Yes" : "No").append("\n");
         if (request.getError() != null) {
            detailsText.append("Error: ").append(request.getError()).append("\n");
         }

         detailsText.append("Request ID: ").append(request.getId()).append("\n");
         detailsText.append("Timestamp: ").append(sdf.format(new Date(request.getTimestamp()))).append("\n");
         this.detailsArea.setText(detailsText.toString());
         this.detailsArea.setCaretPosition(0);
         this.renderTests(request);
      }
   }

   private void renderTests(ExecutedRequest request) {
      if (this.testsArea != null) {
         List<ExecutedRequest.TestResult> results = request == null ? null : request.getTestResults();
         StyledDocument doc = this.testsArea.getStyledDocument();

         try {
            doc.remove(0, doc.getLength());
         } catch (Exception var14) {
         }

         if (results != null && !results.isEmpty()) {
            int passed = 0;

            for (ExecutedRequest.TestResult r : results) {
               if (r.passed) {
                  passed++;
               }
            }

            int failed = results.size() - passed;

            try {
               SimpleAttributeSet headerAttr = new SimpleAttributeSet();
               StyleConstants.setBold(headerAttr, true);
               StyleConstants.setFontSize(headerAttr, 13);
               doc.insertString(doc.getLength(), String.format("%d passed   %d failed   (%d total)\n\n", passed, failed, results.size()), headerAttr);
               SimpleAttributeSet passAttr = new SimpleAttributeSet();
               StyleConstants.setForeground(passAttr, new Color(46, 125, 50));
               SimpleAttributeSet failAttr = new SimpleAttributeSet();
               StyleConstants.setForeground(failAttr, new Color(198, 40, 40));
               SimpleAttributeSet errAttr = new SimpleAttributeSet();
               StyleConstants.setForeground(errAttr, new Color(85, 85, 85));

               for (ExecutedRequest.TestResult rx : results) {
                  String prefix = rx.passed ? "✓  PASS  " : "✗  FAIL  ";
                  doc.insertString(doc.getLength(), prefix, rx.passed ? passAttr : failAttr);
                  doc.insertString(doc.getLength(), (rx.name == null ? "(unnamed)" : rx.name) + "\n", null);
                  if (!rx.passed && rx.error != null && !rx.error.isEmpty()) {
                     doc.insertString(doc.getLength(), "         " + rx.error + "\n", errAttr);
                  }
               }
            } catch (Exception var15) {
            }

            this.testsArea.setCaretPosition(0);
            this.setTabTitle("Tests", "Tests (" + passed + "/" + results.size() + ")");
         } else {
            try {
               SimpleAttributeSet a = new SimpleAttributeSet();
               StyleConstants.setForeground(a, new Color(144, 144, 144));
               doc.insertString(
                  0,
                  "No tests run for this request.\n\nAdd pm.test('your test', function () {\n    pm.expect(pm.response.code).to.equal(200);\n}); in the Tests tab of the request to populate this view.",
                  a
               );
            } catch (Exception var13) {
            }

            this.setTabTitle("Tests", "Tests");
         }
      }
   }

   private void setTabTitle(String tabName, String newTitle) {
      if (this.tabbedPane != null) {
         for (int i = 0; i < this.tabbedPane.getTabCount(); i++) {
            String t = this.tabbedPane.getTitleAt(i);
            if (t != null && (t.equals(tabName) || t.startsWith(tabName + " ("))) {
               this.tabbedPane.setTitleAt(i, newTitle);
               return;
            }
         }
      }
   }

   public void clear() {
      this.lastResponse = null;
      this.lastBody = "";
      this.lastContentType = "";
      this.prettyViewer.clear();
      this.rawViewer.clear();
      this.headersViewer.clear();
      this.previewViewer.clear();
      this.detailsArea.setText("");
      if (this.testsArea != null) {
         this.testsArea.setText("");
      }

      this.setTabTitle("Tests", "Tests");
      this.statusLabel.setText(" ");
   }

   public void setSelectedTab(int index) {
      if (index >= 0 && index < this.tabbedPane.getTabCount()) {
         this.tabbedPane.setSelectedIndex(index);
      }
   }

   private static String prettyJson(String json) {
      if (json == null) {
         return "";
      } else {
         StringBuilder out = new StringBuilder();
         int indent = 0;
         boolean inString = false;
         char prev = 0;

         for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"' && prev != '\\') {
               inString = !inString;
            }

            if (inString) {
               out.append(c);
               prev = c;
            } else {
               switch (c) {
                  case ',':
                     out.append(c).append('\n');
                     pad(out, indent);
                     break;
                  case ':':
                     out.append(c).append(' ');
                     break;
                  case '[':
                  case '{':
                     out.append(c).append('\n');
                     pad(out, ++indent);
                     break;
                  case ']':
                  case '}':
                     out.append('\n');
                     indent = Math.max(0, indent - 1);
                     pad(out, indent);
                     out.append(c);
                     break;
                  default:
                     if (!Character.isWhitespace(c)) {
                        out.append(c);
                     }
               }

               prev = c;
            }
         }

         return out.toString();
      }
   }

   private static void pad(StringBuilder sb, int n) {
      for (int i = 0; i < n; i++) {
         sb.append("  ");
      }
   }

   private static String prettyXml(String xml) {
      if (xml == null) {
         return "";
      } else {
         try {
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer t = tf.newTransformer();
            t.setOutputProperty("indent", "yes");
            t.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            StringWriter w = new StringWriter();
            t.transform(new StreamSource(new StringReader(xml)), new StreamResult(w));
            return w.toString();
         } catch (Exception var4) {
            return xml;
         }
      }
   }

   private static class BodyViewer extends JPanel {
      private final JTextArea bodyArea;
      private final boolean pretty;

      BodyViewer(boolean pretty) {
         this.pretty = pretty;
         this.setLayout(new BorderLayout());
         this.bodyArea = new JTextArea(16, 120);
         this.bodyArea.setEditable(false);
         this.bodyArea.setFont(new Font("Monospaced", 0, 12));
         this.bodyArea.setLineWrap(pretty);
         this.bodyArea.setWrapStyleWord(pretty);
         JScrollPane sp = ResponsePanel.createPayloadScroll(this.bodyArea, !pretty);
         this.add(sp, "Center");
      }

      void displayBody(String body, String contentType) {
         if (body != null && !body.isEmpty()) {
            String out = body;
            if (this.pretty) {
               out = FormatUtils.autoFormat(body, contentType);
            }

            this.bodyArea.setText(out);
            this.bodyArea.setCaretPosition(0);
         } else {
            this.bodyArea.setText("(empty)");
         }
      }

      void clear() {
         this.bodyArea.setText("");
      }
   }

   private static class HeadersViewer extends JPanel {
      private final DefaultTableModel model;

      HeadersViewer() {
         this.setLayout(new BorderLayout());
         this.model = new DefaultTableModel(new String[]{"Header", "Value"}, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
               return false;
            }
         };
         JTable table = new JTable(this.model);
         table.setFont(new Font("Monospaced", 0, 12));
         table.setRowHeight(22);
         table.setShowGrid(true);
         table.setGridColor(new Color(220, 220, 220));
         table.setSelectionMode(0);
         table.setAutoResizeMode(3);
         table.getColumnModel().getColumn(0).setPreferredWidth(180);
         table.getColumnModel().getColumn(1).setPreferredWidth(420);
         this.add(new JScrollPane(table), "Center");
      }

      void displayHeaders(List<PostmanCollection.Header> headers) {
         this.model.setRowCount(0);
         if (headers != null) {
            for (PostmanCollection.Header h : headers) {
               this.model.addRow(new Object[]{h.key != null ? h.key : "", h.value != null ? h.value : ""});
            }
         }
      }

      void clear() {
         this.model.setRowCount(0);
      }
   }

   private static class PreviewViewer extends JPanel {
      private final JEditorPane editor;

      PreviewViewer() {
         this.setLayout(new BorderLayout());
         this.editor = new JEditorPane();
         this.editor.setEditable(false);
         this.add(ResponsePanel.createPayloadScroll(this.editor, true), "Center");
      }

      void displayPreview(String body, String contentType) {
         if (body != null && !body.isEmpty()) {
            String ct = contentType == null ? "" : contentType.toLowerCase();

            try {
               if (ct.contains("html")) {
                  this.editor.setContentType("text/html");
                  this.editor.setText(body);
               } else {
                  this.editor.setContentType("text/plain");
                  this.editor.setText(body);
               }

               this.editor.setCaretPosition(0);
            } catch (Exception var5) {
               this.editor.setContentType("text/plain");
               this.editor.setText(body);
            }
         } else {
            this.editor.setText("");
         }
      }

      void clear() {
         this.editor.setText("");
      }
   }

   private static JScrollPane createPayloadScroll(java.awt.Component view, boolean allowHorizontal) {
      int hPolicy = allowHorizontal ? JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED : JScrollPane.HORIZONTAL_SCROLLBAR_NEVER;
      JScrollPane sp = new JScrollPane(view, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, hPolicy);
      sp.setPreferredSize(new Dimension(560, 220));
      sp.setMinimumSize(new Dimension(180, 120));
      sp.getVerticalScrollBar().setUnitIncrement(16);
      sp.getHorizontalScrollBar().setUnitIncrement(16);
      return sp;
   }
}
