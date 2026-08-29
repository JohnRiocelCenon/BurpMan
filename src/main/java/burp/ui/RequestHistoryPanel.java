package burp.ui;

import burp.models.ExecutedRequest;
import burp.models.PostmanCollection;
import burp.models.RequestHistory;
import burp.service.RequestExecutor;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;

public class RequestHistoryPanel extends JPanel {
   private final RequestHistory requestHistory;
   private final RequestBuilderPanel builderPanel;
   private final RequestExecutor requestExecutor;
   private final JTable historyTable;
   private final RequestHistoryPanel.HistoryTableModel tableModel;
   private JTextField searchField;
   private JComboBox<String> filterCombo;
   private List<ExecutedRequest> displayedRequests = new ArrayList<>();

   public RequestHistoryPanel(RequestHistory requestHistory, RequestBuilderPanel builderPanel) {
      this(requestHistory, builderPanel, null);
   }

   public RequestHistoryPanel(RequestHistory requestHistory, RequestBuilderPanel builderPanel, RequestExecutor requestExecutor) {
      this.requestHistory = requestHistory;
      this.builderPanel = builderPanel;
      this.requestExecutor = requestExecutor;
      this.setLayout(new BorderLayout(5, 5));
      this.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
      JPanel filterPanel = this.createFilterPanel();
      this.add(filterPanel, "North");
      this.tableModel = new RequestHistoryPanel.HistoryTableModel();
      this.historyTable = new JTable(this.tableModel);
      this.historyTable.setSelectionMode(2);
      this.historyTable.getColumnModel().getColumn(0).setPreferredWidth(150);
      this.historyTable.getColumnModel().getColumn(1).setPreferredWidth(50);
      this.historyTable.getColumnModel().getColumn(2).setPreferredWidth(300);
      this.historyTable.getColumnModel().getColumn(3).setPreferredWidth(80);
      this.historyTable.getColumnModel().getColumn(4).setPreferredWidth(80);
      JScrollPane scrollPane = new JScrollPane(this.historyTable);
      this.add(scrollPane, "Center");
      this.setupContextMenu();
      requestHistory.addListener(new RequestHistory.HistoryListener() {
         @Override
         public void onRequestAdded(ExecutedRequest request) {
            SwingUtilities.invokeLater(() -> {
               RequestHistoryPanel.this.displayedRequests.add(0, request);
               RequestHistoryPanel.this.tableModel.fireTableDataChanged();
            });
         }

         @Override
         public void onHistoryCleared() {
            SwingUtilities.invokeLater(() -> {
               RequestHistoryPanel.this.displayedRequests.clear();
               RequestHistoryPanel.this.tableModel.fireTableDataChanged();
            });
         }

         @Override
         public void onRequestRemoved(ExecutedRequest request) {
            SwingUtilities.invokeLater(() -> {
               RequestHistoryPanel.this.displayedRequests.remove(request);
               RequestHistoryPanel.this.tableModel.fireTableDataChanged();
            });
         }
      });
      this.displayedRequests.addAll(requestHistory.getAll());
      this.tableModel.fireTableDataChanged();
   }

   private JPanel createFilterPanel() {
      JPanel panel = new JPanel(new FlowLayout(0, 5, 5));
      panel.add(new JLabel("Search:"));
      this.searchField = new JTextField(20);
      this.searchField.addActionListener(e -> this.applyFilter());
      panel.add(this.searchField);
      panel.add(new JLabel("Filter:"));
      this.filterCombo = new JComboBox<>(new String[]{"All", "Success", "Error", "GET", "POST", "PUT", "DELETE"});
      this.filterCombo.addActionListener(e -> this.applyFilter());
      panel.add(this.filterCombo);
      JButton clearBtn = new JButton("Clear History");
      clearBtn.addActionListener(e -> {
         this.requestHistory.clear();
         this.displayedRequests.clear();
         this.tableModel.fireTableDataChanged();
      });
      panel.add(clearBtn);
      return panel;
   }

   private void setupContextMenu() {
      JPopupMenu menu = new JPopupMenu();
      JMenuItem openInBuilder = new JMenuItem("Open in Builder");
      openInBuilder.addActionListener(e -> this.handleOpenInBuilder());
      menu.add(openInBuilder);
      JMenuItem resend = new JMenuItem("Resend");
      resend.addActionListener(e -> this.handleResend());
      menu.add(resend);
      JMenuItem viewDetails = new JMenuItem("View Details");
      viewDetails.addActionListener(e -> this.handleViewDetails());
      menu.add(viewDetails);
      JMenuItem diffSelected = new JMenuItem("Compare selected (2 rows)…");
      diffSelected.setToolTipText("Side-by-side diff of two responses. Select exactly 2 rows in the history first.");
      diffSelected.addActionListener(e -> this.handleDiffSelected());
      menu.add(diffSelected);
      menu.addSeparator();
      JMenuItem delete = new JMenuItem("Delete");
      delete.addActionListener(e -> this.handleDelete());
      menu.add(delete);
      this.historyTable.setComponentPopupMenu(menu);
   }

   private void handleDiffSelected() {
      int[] rows = this.historyTable.getSelectedRows();
      if (rows.length != 2) {
         JOptionPane.showMessageDialog(this, "Select exactly 2 rows in the history (Ctrl/Shift-click) to compare.", "Select 2 responses", 1);
      } else {
         ExecutedRequest a = this.displayedRequests.get(rows[0]);
         ExecutedRequest b = this.displayedRequests.get(rows[1]);
         DiffDialog.show(this, a, b);
      }
   }

   private void applyFilter() {
      this.displayedRequests.clear();
      String search = this.searchField.getText().toLowerCase();
      String filter = (String)this.filterCombo.getSelectedItem();

      for (ExecutedRequest req : this.requestHistory.getAll()) {
         boolean matches = true;
         if (!search.isEmpty()) {
            matches = req.getUrl().toLowerCase().contains(search) || req.getMethod().toLowerCase().contains(search);
         }

         if (matches && !filter.equals("All")) {
            if (filter.equals("Success")) {
               matches = req.isSuccess();
            } else if (filter.equals("Error")) {
               matches = !req.isSuccess();
            } else {
               matches = req.getMethod().equalsIgnoreCase(filter);
            }
         }

         if (matches) {
            this.displayedRequests.add(0, req);
         }
      }

      this.tableModel.fireTableDataChanged();
   }

   private void handleOpenInBuilder() {
      int row = this.historyTable.getSelectedRow();
      if (row >= 0 && row < this.displayedRequests.size()) {
         ExecutedRequest req = this.displayedRequests.get(row);
         PostmanCollection.Request request = new PostmanCollection.Request();
         request.url = req.getUrl();
         request.method = req.getMethod();
         if (req.getRequestHeaders() != null && !req.getRequestHeaders().isEmpty()) {
            request.header = new ArrayList<>(req.getRequestHeaders());
         }

         if (req.getRequestBody() != null && !req.getRequestBody().isEmpty()) {
            PostmanCollection.Body body = new PostmanCollection.Body();
            body.raw = req.getRequestBody();
            body.mode = "raw";
            request.body = body;
         }

         this.builderPanel.loadRequest(request);
      }
   }

   private void handleResend() {
      int row = this.historyTable.getSelectedRow();
      if (row >= 0 && row < this.displayedRequests.size() && this.requestExecutor != null) {
         ExecutedRequest req = this.displayedRequests.get(row);

         try {
            this.requestExecutor.executeAsync(req.getMethod(), req.getUrl(), req.getRequestHeaders(), req.getRequestBody());
         } catch (Exception var4) {
            JOptionPane.showMessageDialog(this, "Failed to resend request: " + var4.getMessage(), "Error", 0);
         }
      }
   }

   private void handleViewDetails() {
      int row = this.historyTable.getSelectedRow();
      if (row >= 0 && row < this.displayedRequests.size()) {
         ExecutedRequest req = this.displayedRequests.get(row);
         new RequestDetailDialog(SwingUtilities.getWindowAncestor(this), req).setVisible(true);
      }
   }

   private void handleDelete() {
      int row = this.historyTable.getSelectedRow();
      if (row >= 0 && row < this.displayedRequests.size()) {
         ExecutedRequest req = this.displayedRequests.get(row);
         this.requestHistory.remove(req);
         this.displayedRequests.remove(row);
         this.tableModel.fireTableDataChanged();
      }
   }

   private class HistoryTableModel extends AbstractTableModel {
      private final String[] columns = new String[]{"Timestamp", "Method", "URL", "Status", "Duration"};
      private final SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");

      @Override
      public int getRowCount() {
         return RequestHistoryPanel.this.displayedRequests.size();
      }

      @Override
      public int getColumnCount() {
         return this.columns.length;
      }

      @Override
      public String getColumnName(int column) {
         return this.columns[column];
      }

      @Override
      public Object getValueAt(int row, int col) {
         if (row >= 0 && row < RequestHistoryPanel.this.displayedRequests.size()) {
            ExecutedRequest req = RequestHistoryPanel.this.displayedRequests.get(row);
            switch (col) {
               case 0:
                  return this.sdf.format(new Date(req.getTimestamp()));
               case 1:
                  return req.getMethod();
               case 2:
                  return req.getUrl();
               case 3:
                  return req.getStatusCode() > 0 ? req.getStatusCode() + " " + (req.isSuccess() ? "✓" : "✗") : "-";
               case 4:
                  return req.getDurationMs() + "ms";
               default:
                  return "";
            }
         } else {
            return "";
         }
      }
   }
}
