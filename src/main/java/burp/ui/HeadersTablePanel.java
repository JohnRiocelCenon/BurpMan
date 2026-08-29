package burp.ui;

import burp.models.PostmanCollection;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;

public class HeadersTablePanel extends JPanel {
   private final JTable headersTable;
   private final HeadersTablePanel.HeadersTableModel tableModel;
   private boolean lockAuthorization = false;
   private final List<Runnable> changeListeners = new CopyOnWriteArrayList<>();

   public void addChangeListener(Runnable r) {
      if (r != null) {
         this.changeListeners.add(r);
      }
   }

   public void removeChangeListener(Runnable r) {
      if (r != null) {
         this.changeListeners.remove(r);
      }
   }

   private void fireChange() {
      for (Runnable r : this.changeListeners) {
         try {
            r.run();
         } catch (Throwable var4) {
         }
      }
   }

   public void setAuthorizationLocked(boolean locked) {
      if (this.lockAuthorization != locked) {
         this.lockAuthorization = locked;
         this.tableModel.fireTableDataChanged();
      }
   }

   public HeadersTablePanel() {
      this.setLayout(new BorderLayout(5, 5));
      this.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
      this.tableModel = new HeadersTablePanel.HeadersTableModel();
      this.tableModel.addTableModelListener(e -> this.fireChange());
      this.headersTable = new JTable(this.tableModel);
      this.headersTable.getColumnModel().getColumn(0).setPreferredWidth(30);
      this.headersTable.getColumnModel().getColumn(1).setPreferredWidth(200);
      this.headersTable.getColumnModel().getColumn(2).setPreferredWidth(400);
      JScrollPane scrollPane = new JScrollPane(this.headersTable);
      this.add(scrollPane, "Center");
      DefaultTableCellRenderer lockAware = new DefaultTableCellRenderer() {
         @Override
         public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            boolean isAuthRow = false;
            boolean isScriptManaged = false;

            try {
               Object k = table.getModel().getValueAt(row, 1);
               isAuthRow = k != null && "authorization".equalsIgnoreCase(k.toString().trim());
               if (row >= 0 && row < HeadersTablePanel.this.tableModel.rows.size()) {
                  isScriptManaged = HeadersTablePanel.this.tableModel.rows.get(row).scriptManaged;
               }
            } catch (Exception var11) {
            }

            if (isScriptManaged) {
               if (!isSelected) {
                  c.setBackground(new Color(227, 242, 253));
                  c.setForeground(new Color(13, 71, 161));
               }

               if (column == 1) {
                  this.setText("\ud83d\udcdc " + (value == null ? "" : value.toString()));
                  this.setToolTipText("Added by pre-request script (read-only). Edit the script to change.");
               } else {
                  this.setToolTipText("Added by pre-request script (read-only).");
               }
            } else if (HeadersTablePanel.this.lockAuthorization && isAuthRow) {
               if (!isSelected) {
                  c.setBackground(new Color(245, 240, 220));
                  c.setForeground(new Color(120, 110, 90));
               }

               if (column == 1) {
                  this.setText("\ud83d\udd12 " + (value == null ? "" : value.toString()));
                  this.setToolTipText("Locked: managed by Authorization tab (Inherit). Switch to Bearer/No Auth to edit.");
               } else {
                  this.setToolTipText("Locked: managed by Authorization tab (Inherit).");
               }
            } else {
               if (!isSelected) {
                  c.setBackground(table.getBackground());
                  c.setForeground(table.getForeground());
               }

               this.setToolTipText(null);
            }

            return c;
         }
      };
      this.headersTable.getColumnModel().getColumn(1).setCellRenderer(lockAware);
      this.headersTable.getColumnModel().getColumn(2).setCellRenderer(lockAware);
      JPanel buttonPanel = new JPanel(new FlowLayout(0, 5, 5));
      JButton addBtn = new JButton("Add Header");
      addBtn.addActionListener(e -> this.tableModel.addRow());
      buttonPanel.add(addBtn);
      JButton removeBtn = new JButton("Remove");
      removeBtn.addActionListener(e -> {
         int row = this.headersTable.getSelectedRow();
         if (row >= 0) {
            this.tableModel.removeRow(row);
         }
      });
      buttonPanel.add(removeBtn);
      JButton clearBtn = new JButton("Clear All");
      clearBtn.addActionListener(e -> this.tableModel.clear());
      buttonPanel.add(clearBtn);
      this.add(buttonPanel, "North");
   }

   public List<PostmanCollection.Header> getHeaders() {
      List<PostmanCollection.Header> headers = new ArrayList<>();

      for (HeadersTablePanel.HeaderRow row : this.tableModel.getRows()) {
         if (!row.scriptManaged && row.enabled && !row.key.isEmpty()) {
            PostmanCollection.Header h = new PostmanCollection.Header();
            h.key = row.key;
            h.value = row.value;
            headers.add(h);
         }
      }

      return headers;
   }

   public void setHeaders(List<PostmanCollection.Header> headers) {
      this.tableModel.clear();
      if (headers != null) {
         for (PostmanCollection.Header h : headers) {
            HeadersTablePanel.HeaderRow row = new HeadersTablePanel.HeaderRow();
            row.enabled = !h.disabled;
            row.key = h.key;
            row.value = h.value;
            this.tableModel.addRow(row);
         }
      }
   }

   public void setScriptManagedHeaders(List<PostmanCollection.Header> headers) {
      this.tableModel.removeScriptManagedRows();
      if (headers != null) {
         for (PostmanCollection.Header h : headers) {
            if (h != null && h.key != null && !h.key.isEmpty()) {
               HeadersTablePanel.HeaderRow row = new HeadersTablePanel.HeaderRow();
               row.enabled = true;
               row.key = h.key;
               row.value = h.value == null ? "" : h.value;
               row.scriptManaged = true;
               this.tableModel.addRow(row);
            }
         }
      }
   }

   public void clearScriptManagedHeaders() {
      this.tableModel.removeScriptManagedRows();
   }

   public void clear() {
      this.tableModel.clear();
   }

   private static class HeaderRow {
      boolean enabled = true;
      String key = "";
      String value = "";
      boolean scriptManaged = false;
   }

   private class HeadersTableModel extends AbstractTableModel {
      private final List<HeadersTablePanel.HeaderRow> rows = new ArrayList<>();
      private final String[] columns = new String[]{"", "Header Name", "Value"};

      @Override
      public int getRowCount() {
         return this.rows.size();
      }

      @Override
      public int getColumnCount() {
         return this.columns.length;
      }

      @Override
      public String getColumnName(int col) {
         return this.columns[col];
      }

      @Override
      public Object getValueAt(int row, int col) {
         if (row >= 0 && row < this.rows.size()) {
            HeadersTablePanel.HeaderRow hr = this.rows.get(row);
            switch (col) {
               case 0:
                  return hr.enabled;
               case 1:
                  return hr.key;
               case 2:
                  return hr.value;
               default:
                  return "";
            }
         } else {
            return "";
         }
      }

      @Override
      public void setValueAt(Object value, int row, int col) {
         if (row >= 0 && row < this.rows.size()) {
            HeadersTablePanel.HeaderRow hr = this.rows.get(row);
            switch (col) {
               case 0:
                  hr.enabled = (Boolean)value;
                  break;
               case 1:
                  hr.key = value.toString();
                  break;
               case 2:
                  hr.value = value.toString();
            }

            this.fireTableCellUpdated(row, col);
         }
      }

      @Override
      public Class<?> getColumnClass(int col) {
         return col == 0 ? Boolean.class : String.class;
      }

      @Override
      public boolean isCellEditable(int row, int col) {
         if (row >= 0 && row < this.rows.size()) {
            HeadersTablePanel.HeaderRow hr = this.rows.get(row);
            if (hr.scriptManaged) {
               return false;
            }

            if (HeadersTablePanel.this.lockAuthorization && hr.key != null && "authorization".equalsIgnoreCase(hr.key.trim())) {
               return false;
            }
         }

         return true;
      }

      public void addRow() {
         this.rows.add(new HeadersTablePanel.HeaderRow());
         this.fireTableRowsInserted(this.rows.size() - 1, this.rows.size() - 1);
      }

      public void addRow(HeadersTablePanel.HeaderRow row) {
         this.rows.add(row);
         this.fireTableRowsInserted(this.rows.size() - 1, this.rows.size() - 1);
      }

      public void removeRow(int row) {
         if (row >= 0 && row < this.rows.size()) {
            if (this.rows.get(row).scriptManaged) {
               return;
            }

            this.rows.remove(row);
            this.fireTableRowsDeleted(row, row);
         }
      }

      public void removeScriptManagedRows() {
         boolean changed = false;

         for (int i = this.rows.size() - 1; i >= 0; i--) {
            if (this.rows.get(i).scriptManaged) {
               this.rows.remove(i);
               changed = true;
            }
         }

         if (changed) {
            this.fireTableDataChanged();
         }
      }

      public void clear() {
         this.rows.clear();
         this.fireTableDataChanged();
      }

      public List<HeadersTablePanel.HeaderRow> getRows() {
         return new ArrayList<>(this.rows);
      }
   }
}
