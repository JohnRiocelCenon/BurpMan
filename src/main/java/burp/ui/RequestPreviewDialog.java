package burp.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.util.List;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;

public class RequestPreviewDialog extends JDialog {
   private boolean approved = false;

   public RequestPreviewDialog(Frame parent, List<RequestPreviewDialog.RequestPreview> requests) {
      super(parent, "Preview Requests", true);
      this.initializeUI(requests);
   }

   private void initializeUI(List<RequestPreviewDialog.RequestPreview> requests) {
      this.setLayout(new BorderLayout());
      String[] columnNames = new String[]{"Import", "Name", "Method", "URL"};
      Object[][] data = new Object[requests.size()][4];

      for (int i = 0; i < requests.size(); i++) {
         RequestPreviewDialog.RequestPreview req = requests.get(i);
         data[i][0] = true;
         data[i][1] = req.name;
         data[i][2] = req.method;
         data[i][3] = req.url;
      }

      JTable table = new JTable(data, columnNames) {
         @Override
         public Class<?> getColumnClass(int column) {
            return column == 0 ? Boolean.class : String.class;
         }

         @Override
         public boolean isCellEditable(int row, int column) {
            return column == 0;
         }
      };
      table.getColumnModel().getColumn(0).setPreferredWidth(50);
      table.getColumnModel().getColumn(1).setPreferredWidth(200);
      table.getColumnModel().getColumn(2).setPreferredWidth(80);
      table.getColumnModel().getColumn(3).setPreferredWidth(400);
      JScrollPane scrollPane = new JScrollPane(table);
      scrollPane.setPreferredSize(new Dimension(800, 400));
      this.add(scrollPane, "Center");
      JPanel buttonPanel = new JPanel(new FlowLayout(2));
      JButton selectAllBtn = new JButton("Select All");
      selectAllBtn.addActionListener(e -> this.setAllSelected(table, true));
      JButton deselectAllBtn = new JButton("Deselect All");
      deselectAllBtn.addActionListener(e -> this.setAllSelected(table, false));
      JButton importBtn = new JButton("Import Selected");
      importBtn.addActionListener(e -> {
         this.approved = true;
         this.updateRequestSelection(table, requests);
         this.dispose();
      });
      JButton cancelBtn = new JButton("Cancel");
      cancelBtn.addActionListener(e -> this.dispose());
      buttonPanel.add(selectAllBtn);
      buttonPanel.add(deselectAllBtn);
      buttonPanel.add(Box.createHorizontalStrut(20));
      buttonPanel.add(cancelBtn);
      buttonPanel.add(importBtn);
      this.add(buttonPanel, "South");
      this.pack();
      this.setLocationRelativeTo(this.getParent());
   }

   private void setAllSelected(JTable table, boolean selected) {
      for (int i = 0; i < table.getRowCount(); i++) {
         table.setValueAt(selected, i, 0);
      }
   }

   private void updateRequestSelection(JTable table, List<RequestPreviewDialog.RequestPreview> requests) {
      for (int i = 0; i < table.getRowCount(); i++) {
         requests.get(i).selected = (Boolean)table.getValueAt(i, 0);
      }
   }

   public boolean isApproved() {
      return this.approved;
   }

   public static class RequestPreview {
      public String name;
      public String method;
      public String url;
      public boolean selected = true;

      public RequestPreview(String name, String method, String url) {
         this.name = name;
         this.method = method;
         this.url = url;
      }
   }
}
