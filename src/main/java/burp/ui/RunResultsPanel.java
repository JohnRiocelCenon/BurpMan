package burp.ui;

import burp.models.ExecutedRequest;
import burp.models.PostmanCollection;
import burp.models.RunResult;
import burp.service.CookieJar;
import burp.utils.FormatUtils;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;

public final class RunResultsPanel extends JPanel {
   private static final int MAX_RESPONSE_PREVIEW_CHARS = 120000;
   private static final int MAX_HEADERS_PREVIEW_CHARS = 24000;
   private static final int MAX_POSTMAN_PREVIEW_CHARS = 100000;
   private final List<RunResult> rows = new ArrayList<>();
   private final RunResultsPanel.ResultsTableModel model = new RunResultsPanel.ResultsTableModel();
   private final JTable table = new JTable(this.model);
   private final JLabel headerLabel = new JLabel(" ");
   private final JTabbedPane detailTabs = new JTabbedPane();
   private final JTextArea responseArea = new JTextArea();
   private final JTextArea headersArea = new JTextArea();
   private final JPanel testsList = new JPanel();
   private final JTextArea postmanArea = new JTextArea();
   private final JLabel summaryLabel = new JLabel(" ");
   private final JButton clearCookiesBtn = UITheme.button("\ud83c\udf6a Clear Cookies", UITheme.BtnStyle.GHOST);
   private final JButton proxyBtn = UITheme.button("\ud83c\udf10 Proxy: OFF", UITheme.BtnStyle.GHOST);
   private CookieJar cookieJar;
   private RunResultsPanel.Filter currentFilter = RunResultsPanel.Filter.ALL;
   private String runId = "";
   private long runStartedAtMs = 0L;
   private long runFinishedAtMs = 0L;

   public RunResultsPanel() {
      super(new BorderLayout(0, 4));
      this.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
      this.add(this.buildHeader(), "North");
      this.add(this.buildSplit(), "Center");
   }

   private JPanel buildHeader() {
      JPanel p = new JPanel(new BorderLayout(8, 0));
      p.setOpaque(false);
      JPanel left = new JPanel(new FlowLayout(0, 4, 0));
      left.setOpaque(false);
      this.headerLabel.setFont(this.headerLabel.getFont().deriveFont(1, 13.0F));
      left.add(this.headerLabel);
      JPanel filters = new JPanel(new FlowLayout(0, 4, 0));
      filters.setOpaque(false);
      filters.add(this.filterButton("All", RunResultsPanel.Filter.ALL));
      filters.add(this.filterButton("Passed", RunResultsPanel.Filter.PASSED));
      filters.add(this.filterButton("Failed", RunResultsPanel.Filter.FAILED));
      filters.add(this.filterButton("Skipped", RunResultsPanel.Filter.SKIPPED));
      JPanel right = new JPanel(new FlowLayout(2, 8, 0));
      right.setOpaque(false);
      this.summaryLabel.setFont(this.summaryLabel.getFont().deriveFont(11.0F));
      this.clearCookiesBtn.setMargin(new Insets(2, 8, 2, 8));
      this.clearCookiesBtn.setToolTipText("Clear all captured cookies from the jar (reset session between runs)");
      this.clearCookiesBtn.setEnabled(false);
      this.clearCookiesBtn.addActionListener(e -> this.onClearCookies());
      this.proxyBtn.setMargin(new Insets(2, 8, 2, 8));
      this.proxyBtn.setToolTipText("<html>Route BurpMan traffic through an upstream proxy so it appears in "
         + "Burp <b>Proxy → HTTP history</b> (not just Logger).<br>"
         + "Point at <b>127.0.0.1:8080</b> to log through your own Burp Proxy listener.<br>"
         + "<i>First-time setup: uncheck</i> <b>Burp → Settings → Tools → Proxy → Miscellaneous → "
         + "\"Drop requests that appear to be looping back...\"</b></html>");
      this.proxyBtn.addActionListener(e -> this.onOpenProxySettings());
      this.updateProxyLabel();
      right.add(this.proxyBtn);
      right.add(this.clearCookiesBtn);
      right.add(this.summaryLabel);
      p.add(left, "West");
      p.add(filters, "Center");
      p.add(right, "East");
      return p;
   }

   public void setCookieJar(CookieJar jar) {
      this.cookieJar = jar;
      if (jar != null) {
         jar.addChangeListener(() -> SwingUtilities.invokeLater(this::updateClearCookiesLabel));
      }

      SwingUtilities.invokeLater(this::updateClearCookiesLabel);
   }

   private void updateClearCookiesLabel() {
      int count = this.cookieJar == null ? 0 : this.cookieJar.getAll().size();
      this.clearCookiesBtn.setText(count > 0 ? "\ud83c\udf6a Clear Cookies (" + count + ")" : "\ud83c\udf6a Clear Cookies");
      this.clearCookiesBtn.setEnabled(count > 0);
   }

   private void onClearCookies() {
      if (this.cookieJar != null && !this.cookieJar.getAll().isEmpty()) {
         int n = this.cookieJar.getAll().size();
         int ok = JOptionPane.showConfirmDialog(
            this,
            "Clear " + n + " cookie" + (n == 1 ? "" : "s") + " from the jar?\nAll captured session state will be lost.",
            "Clear cookies",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.WARNING_MESSAGE
         );
         if (ok == JOptionPane.OK_OPTION) {
            this.cookieJar.clear();
         }
      }
   }

   private void updateProxyLabel() {
      burp.service.ProxySettings ps = burp.service.ProxySettings.get();
      this.proxyBtn.setText(ps.statusLabel());
      if (ps.isEnabled()) {
         UITheme.apply(this.proxyBtn, UITheme.BtnStyle.SUCCESS);
      } else {
         UITheme.apply(this.proxyBtn, UITheme.BtnStyle.GHOST);
      }
   }

   private void onOpenProxySettings() {
      new burp.ui.ProxySettingsDialog(this, ps -> {
         SwingUtilities.invokeLater(this::updateProxyLabel);
      }).setVisible(true);
   }

   private JButton filterButton(String label, RunResultsPanel.Filter f) {
      JButton b = UITheme.button(label, UITheme.BtnStyle.GHOST);
      b.setMargin(new Insets(2, 8, 2, 8));
      b.addActionListener(e -> {
         this.currentFilter = f;
         this.rebuild();
      });
      return b;
   }

   private JSplitPane buildSplit() {
      this.table.setFillsViewportHeight(true);
      this.table.setRowHeight(24);
      this.table.setShowGrid(false);
      this.table.setIntercellSpacing(new Dimension(0, 0));
      this.table.getSelectionModel().setSelectionMode(0);
      this.table.getSelectionModel().addListSelectionListener(this::onRowSelected);
      TableCellRenderer cr = new DefaultTableCellRenderer() {
         @Override
         public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int row, int col) {
            Component c = super.getTableCellRendererComponent(t, v, sel, focus, row, col);
            if (col == 0 && !sel) {
               String s = String.valueOf(v);
               if ("✓".equals(s)) {
                  c.setForeground(new Color(46, 125, 50));
               } else if ("✗".equals(s)) {
                  c.setForeground(new Color(198, 40, 40));
               } else if ("○".equals(s)) {
                  c.setForeground(new Color(158, 158, 158));
               } else {
                  c.setForeground(t.getForeground());
               }
            }

            if (col == 3 && !sel) {
               int code = v instanceof Integer ? (Integer)v : 0;
               if (code >= 200 && code < 300) {
                  c.setForeground(new Color(46, 125, 50));
               } else if (code >= 400) {
                  c.setForeground(new Color(198, 40, 40));
               } else if (code >= 300) {
                  c.setForeground(new Color(230, 126, 34));
               } else {
                  c.setForeground(t.getForeground());
               }
            }

            return c;
         }
      };
      this.table.getColumnModel().getColumn(0).setCellRenderer(cr);
      this.table.getColumnModel().getColumn(3).setCellRenderer(cr);
      this.table.getColumnModel().getColumn(0).setMaxWidth(30);
      this.table.getColumnModel().getColumn(2).setPreferredWidth(70);
      this.table.getColumnModel().getColumn(3).setPreferredWidth(50);
      this.table.getColumnModel().getColumn(4).setPreferredWidth(70);
      this.table.getColumnModel().getColumn(5).setPreferredWidth(70);
      JScrollPane left = new JScrollPane(this.table);
      this.responseArea.setEditable(false);
      this.responseArea.setFont(new Font("Courier New", 0, 12));
      this.responseArea.setLineWrap(true);
      this.responseArea.setWrapStyleWord(true);
      this.headersArea.setEditable(false);
      this.headersArea.setFont(new Font("Courier New", 0, 12));
      this.headersArea.setLineWrap(true);
      this.headersArea.setWrapStyleWord(true);
      this.testsList.setLayout(new BoxLayout(this.testsList, 1));
      this.testsList.setOpaque(true);
      this.testsList.setBackground(Color.WHITE);
      JScrollPane testsScroll = createDetailScroll(this.testsList, false);
      this.postmanArea.setEditable(false);
      this.postmanArea.setFont(new Font("Courier New", 0, 12));
      this.postmanArea.setLineWrap(true);
      this.postmanArea.setWrapStyleWord(true);
      JScrollPane postmanScroll = createDetailScroll(this.postmanArea, false);
      this.detailTabs.addTab("Response", createDetailScroll(this.responseArea, false));
      this.detailTabs.addTab("Headers", createDetailScroll(this.headersArea, false));
      this.detailTabs.addTab("Tests", testsScroll);
      this.detailTabs.addTab("Postman View", postmanScroll);
      JSplitPane split = new JSplitPane(1, left, this.detailTabs);
      split.setResizeWeight(0.55);
      split.setDividerLocation(640);
      return split;
   }

   private static JScrollPane createDetailScroll(Component view, boolean allowHorizontal) {
      int hPolicy = allowHorizontal ? JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED : JScrollPane.HORIZONTAL_SCROLLBAR_NEVER;
      JScrollPane sp = new JScrollPane(view, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, hPolicy);
      sp.setPreferredSize(new Dimension(560, 220));
      sp.setMinimumSize(new Dimension(180, 120));
      sp.getVerticalScrollBar().setUnitIncrement(16);
      sp.getHorizontalScrollBar().setUnitIncrement(16);
      return sp;
   }

   public void startRun(String runId, int totalRequests) {
      this.runId = runId;
      this.runStartedAtMs = System.currentTimeMillis();
      this.runFinishedAtMs = 0L;
      SwingUtilities.invokeLater(() -> {
         this.rows.clear();
         this.model.fireTableDataChanged();
         this.responseArea.setText("");
         this.headersArea.setText("");
         this.postmanArea.setText("");
         this.testsList.removeAll();
         this.testsList.revalidate();
         this.testsList.repaint();
         this.headerLabel.setText("Run Results · " + runId + " · " + totalRequests + " request(s)");
         this.updateSummary();
         this.refreshPostmanReport();
      });
   }

   public void clear() {
      this.runId = "";
      this.runStartedAtMs = 0L;
      this.runFinishedAtMs = 0L;
      SwingUtilities.invokeLater(() -> {
         this.rows.clear();
         this.model.fireTableDataChanged();
         this.responseArea.setText("");
         this.headersArea.setText("");
         this.postmanArea.setText("");
         this.testsList.removeAll();
         this.testsList.revalidate();
         this.testsList.repaint();
         this.headerLabel.setText(" ");
         this.updateSummary();
         this.refreshPostmanReport();
      });
   }

   public void addResult(RunResult r) {
      SwingUtilities.invokeLater(() -> {
         this.rows.add(r);
         this.model.fireTableDataChanged();
         this.updateSummary();
         this.refreshPostmanReport();
         if (this.rows.size() == 1) {
            this.table.getSelectionModel().setSelectionInterval(0, 0);
         }
      });
   }

   public void finishRun() {
      this.runFinishedAtMs = System.currentTimeMillis();
      SwingUtilities.invokeLater(() -> {
         this.updateSummary();
         this.refreshPostmanReport();
      });
   }

   private void updateSummary() {
      int total = this.rows.size();
      int reqPass = 0;
      int reqFail = 0;
      int reqSkip = 0;
      int testPass = 0;
      int testFail = 0;

      for (RunResult r : this.rows) {
         if (r.isPassed()) {
            reqPass++;
         } else if (r.isFailed()) {
            reqFail++;
         } else {
            reqSkip++;
         }

         for (ExecutedRequest.TestResult t : r.tests) {
            if (t != null && t.passed) {
               testPass++;
            } else {
               testFail++;
            }
         }
      }

      int testTotal = testPass + testFail;
      this.summaryLabel.setText("Req ✓ " + reqPass + "   ✗ " + reqFail + "   ○ " + reqSkip + "   / " + total
         + "    Tests ✓ " + testPass + "   ✗ " + testFail + "   / " + testTotal);
   }

   private void onRowSelected(ListSelectionEvent e) {
      if (!e.getValueIsAdjusting()) {
         int viewRow = this.table.getSelectedRow();
         if (viewRow >= 0) {
            RunResult r = this.visibleRows().get(viewRow);
            this.responseArea.setText(this.previewText(this.prettyResponseBody(r), "Response body", MAX_RESPONSE_PREVIEW_CHARS));
            this.responseArea.setCaretPosition(0);
            StringBuilder hb = new StringBuilder();
            if (r.responseHeaders != null) {
               for (PostmanCollection.Header h : r.responseHeaders) {
                  hb.append(h.key).append(": ").append(h.value == null ? "" : h.value).append('\n');
               }
            }
            this.headersArea.setText(this.previewText(hb.toString(), "Headers", MAX_HEADERS_PREVIEW_CHARS));
            this.headersArea.setCaretPosition(0);
            this.testsList.removeAll();
            if (r.tests.isEmpty()) {
               JLabel none = new JLabel("  No tests found");
               none.setForeground(new Color(102, 102, 102));
               none.setAlignmentX(0.0F);
               this.testsList.add(none);
            } else {
               for (ExecutedRequest.TestResult t : r.tests) {
                  String error = this.normalizeError(t.error);
                  JLabel row = new JLabel(
                     "  " + (t.passed ? "✓ " : "✗ ") + (t.name == null ? "(unnamed)" : t.name)
                        + (!t.passed && !error.isEmpty() ? " — " + error : "")
                  );
                  row.setForeground(t.passed ? new Color(46, 125, 50) : new Color(198, 40, 40));
                  row.setAlignmentX(0.0F);
                  this.testsList.add(row);
               }
            }

            this.testsList.revalidate();
            this.testsList.repaint();
         }
      }
   }

      private void refreshPostmanReport() {
         StringBuilder sb = new StringBuilder();
         int totalRequests = this.rows.size();
         int reqPass = 0;
         int reqFail = 0;
         int reqSkip = 0;
         int testPass = 0;
         int testFail = 0;
         long sumDurMs = 0L;
         int durCount = 0;

         for (RunResult r : this.rows) {
            if (r.isPassed()) {
               reqPass++;
            } else if (r.isFailed()) {
               reqFail++;
            } else {
               reqSkip++;
            }

            if (r.durationMs > 0L) {
               sumDurMs += r.durationMs;
               durCount++;
            }

            for (ExecutedRequest.TestResult t : r.tests) {
               if (t != null && t.passed) {
                  testPass++;
               } else {
                  testFail++;
               }
            }
         }

         int testTotal = testPass + testFail;
         long avgRespMs = durCount > 0 ? Math.round((double)sumDurMs / (double)durCount) : 0L;
         long runElapsedMs = 0L;
         if (this.runStartedAtMs > 0L) {
            long end = this.runFinishedAtMs > 0L ? this.runFinishedAtMs : System.currentTimeMillis();
            runElapsedMs = Math.max(0L, end - this.runStartedAtMs);
         }

         sb.append("Run results");
         if (this.runId != null && !this.runId.isEmpty()) {
            sb.append(" · ").append(this.runId);
         }
         sb.append('\n');
         sb.append("Requests: ").append(totalRequests)
            .append(" (passed ").append(reqPass)
            .append(", failed ").append(reqFail)
            .append(", skipped ").append(reqSkip).append(")\n");
         sb.append("All tests: ").append(testTotal)
            .append(" (passed ").append(testPass)
            .append(", failed ").append(testFail).append(")\n");
         sb.append("Duration: ").append(runElapsedMs > 0L ? runElapsedMs + " ms" : "—")
            .append("   Avg Resp Time: ").append(avgRespMs > 0L ? avgRespMs + " ms" : "—")
            .append("\n\n");

         int idx = 1;
         for (RunResult r : this.rows) {
            String name = r.name == null || r.name.isEmpty() ? (r.path == null ? "(unnamed request)" : r.path) : r.name;
            sb.append(idx++).append(". ").append(r.method == null ? "" : r.method).append(" ").append(name).append('\n');
            if (r.url != null && !r.url.isEmpty()) {
               sb.append("   ").append(r.url).append('\n');
            }
            String statusShown = r.statusCode > 0 ? String.valueOf(r.statusCode) : (r.isSkipped() ? "SKIPPED" : "ERROR");
            sb.append("   Status: ").append(statusShown);
            if (r.durationMs > 0L) {
               sb.append("   ").append(r.durationMs).append(" ms");
            }
            if (r.sizeBytes > 0L) {
               sb.append("   ").append(formatBytes(r.sizeBytes));
            }
            sb.append('\n');
            if (r.error != null && !r.error.trim().isEmpty()) {
               String err = this.normalizeError(r.error);
               sb.append("   FAIL Request error");
               if (!err.isEmpty()) {
                  sb.append(" | ").append(err);
               }
               sb.append('\n');
            }
            if (r.tests == null || r.tests.isEmpty()) {
               sb.append("   (No tests)\n\n");
            } else {
               for (ExecutedRequest.TestResult t : r.tests) {
                  boolean passed = t != null && t.passed;
                  sb.append("   ").append(passed ? "PASS " : "FAIL ");
                  String testName = t != null && t.name != null && !t.name.trim().isEmpty() ? t.name.trim() : "(unnamed)";
                  sb.append(testName);
                  if (!passed && t != null) {
                     String err = this.normalizeError(t.error);
                     if (!err.isEmpty()) {
                        sb.append(" | ").append(err);
                     }
                  }
                  sb.append('\n');
               }
               sb.append('\n');
            }
         }

         this.postmanArea.setText(this.previewText(sb.toString(), "Postman View", MAX_POSTMAN_PREVIEW_CHARS));
         this.postmanArea.setCaretPosition(0);
      }

      private String prettyResponseBody(RunResult r) {
        if (r == null || r.responseBody == null || r.responseBody.isEmpty()) {
           return "";
        }
        String contentType = "";
        if (r.responseHeaders != null) {
           for (PostmanCollection.Header h : r.responseHeaders) {
              if (h == null || h.key == null) {
                 continue;
              }
              if ("content-type".equalsIgnoreCase(h.key.trim())) {
                 contentType = h.value == null ? "" : h.value;
                 break;
              }
           }
        }
        try {
           return FormatUtils.autoFormat(r.responseBody, contentType);
        } catch (Exception ignore) {
           return r.responseBody;
        }
      }

      private String previewText(String text, String label, int maxChars) {
        if (text == null || text.isEmpty()) {
           return "";
        }
        if (text.length() <= maxChars) {
           return text;
        }
        int hidden = text.length() - maxChars;
        StringBuilder out = new StringBuilder(maxChars + 160);
        out.append(text, 0, maxChars);
        out.append("\n\n[")
           .append(label)
           .append(" truncated in Run Results. Hidden ")
           .append(hidden)
           .append(" chars.]");
        return out.toString();
      }

      private String normalizeError(String err) {
         if (err == null) {
            return "";
         } else {
            String out = err.trim();
            String[] prefixes = new String[]{
               "Wrapped java.lang.RuntimeException:",
               "java.lang.RuntimeException:",
               "RuntimeException:"
            };
            for (String p : prefixes) {
               if (out.startsWith(p)) {
                  out = out.substring(p.length()).trim();
               }
            }
            return out;
         }
      }

   private List<RunResult> visibleRows() {
      if (this.currentFilter == RunResultsPanel.Filter.ALL) {
         return this.rows;
      } else {
         List<RunResult> out = new ArrayList<>();

         for (RunResult r : this.rows) {
            switch (this.currentFilter) {
               case PASSED:
                  if (r.isPassed()) {
                     out.add(r);
                  }
                  break;
               case FAILED:
                  if (r.isFailed()) {
                     out.add(r);
                  }
                  break;
               case SKIPPED:
                  if (r.isSkipped()) {
                     out.add(r);
                  }
                  break;
               default:
                  out.add(r);
            }
         }

         return out;
      }
   }

   private void rebuild() {
      this.model.fireTableDataChanged();
      if (this.model.getRowCount() > 0) {
         this.table.getSelectionModel().setSelectionInterval(0, 0);
      }
   }

   private static String formatBytes(long n) {
      if (n < 1024L) {
         return n + " B";
      } else {
         return n < 1048576L ? String.format("%.1f KB", n / 1024.0) : String.format("%.2f MB", n / 1048576.0);
      }
   }

   public static enum Filter {
      ALL,
      PASSED,
      FAILED,
      SKIPPED;
   }

   private final class ResultsTableModel extends AbstractTableModel {
      private final String[] cols = new String[]{"", "Name", "Method", "Status", "Duration", "Size"};

      @Override
      public int getRowCount() {
         return RunResultsPanel.this.visibleRows().size();
      }

      @Override
      public int getColumnCount() {
         return this.cols.length;
      }

      @Override
      public String getColumnName(int c) {
         return this.cols[c];
      }

      @Override
      public Class<?> getColumnClass(int c) {
         return c == 3 ? Integer.class : String.class;
      }

      @Override
      public Object getValueAt(int row, int col) {
         List<RunResult> vis = RunResultsPanel.this.visibleRows();
         if (row >= vis.size()) {
            return "";
         } else {
            RunResult r = vis.get(row);
            switch (col) {
               case 0:
                  return r.isPassed() ? "✓" : (r.isFailed() ? "✗" : "○");
               case 1:
                  return r.name == null ? r.path : r.name;
               case 2:
                  return r.method == null ? "" : r.method;
               case 3:
                  return r.statusCode;
               case 4:
                  return r.durationMs > 0L ? r.durationMs + " ms" : (r.error != null ? "error" : "—");
               case 5:
                  return r.sizeBytes > 0L ? RunResultsPanel.formatBytes(r.sizeBytes) : "—";
               default:
                  return "";
            }
         }
      }
   }
}
