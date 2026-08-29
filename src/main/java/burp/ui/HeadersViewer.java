package burp.ui;

import burp.models.PostmanCollection;
import java.awt.BorderLayout;
import java.awt.Font;
import java.util.List;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

public class HeadersViewer extends JPanel {
   private JTable headersTable;
   private DefaultTableModel tableModel;

   public HeadersViewer() {
      this.setLayout(new BorderLayout());
      this.initializeComponents();
   }

   private void initializeComponents() {
      this.tableModel = new DefaultTableModel(new String[]{"Header Name", "Value"}, 0) {
         @Override
         public boolean isCellEditable(int row, int column) {
            return false;
         }
      };
      this.headersTable = new JTable(this.tableModel);
      this.headersTable.setFont(new Font("Monospaced", 0, 11));
      this.headersTable.setSelectionMode(0);
      this.headersTable.setAutoResizeMode(3);
      this.headersTable.getColumnModel().getColumn(0).setPreferredWidth(150);
      this.headersTable.getColumnModel().getColumn(1).setPreferredWidth(300);
      JScrollPane scrollPane = new JScrollPane(this.headersTable);
      scrollPane.setHorizontalScrollBarPolicy(30);
      scrollPane.setVerticalScrollBarPolicy(20);
      this.add(scrollPane, "Center");
   }

   public void displayHeaders(List<PostmanCollection.Header> headers) {
      this.tableModel.setRowCount(0);
      if (headers != null) {
         for (PostmanCollection.Header header : headers) {
            this.tableModel.addRow(new Object[]{header.key != null ? header.key : "", header.value != null ? header.value : ""});
         }
      }
   }

   public void clear() {
      this.tableModel.setRowCount(0);
   }
}
