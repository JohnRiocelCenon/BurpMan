package burp.ui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;

public class ParametersPanel extends JPanel {
   private final JTable paramsTable;
   private final ParametersPanel.ParametersTableModel tableModel;

   public ParametersPanel() {
      this.setLayout(new BorderLayout(5, 5));
      this.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
      this.tableModel = new ParametersPanel.ParametersTableModel();
      this.paramsTable = new JTable(this.tableModel);
      this.paramsTable.getColumnModel().getColumn(0).setPreferredWidth(30);
      this.paramsTable.getColumnModel().getColumn(1).setPreferredWidth(200);
      this.paramsTable.getColumnModel().getColumn(2).setPreferredWidth(400);
      JScrollPane scrollPane = new JScrollPane(this.paramsTable);
      this.add(scrollPane, "Center");
      JPanel buttonPanel = new JPanel(new FlowLayout(0, 5, 5));
      JButton addBtn = new JButton("Add Parameter");
      addBtn.addActionListener(e -> this.tableModel.addRow());
      buttonPanel.add(addBtn);
      JButton removeBtn = new JButton("Remove");
      removeBtn.addActionListener(e -> {
         int row = this.paramsTable.getSelectedRow();
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

   public List<ParametersPanel.ParamRow> getParameters() {
      List<ParametersPanel.ParamRow> params = new ArrayList<>();

      for (ParametersPanel.ParamRow row : this.tableModel.getRows()) {
         if (row.enabled && !row.key.isEmpty()) {
            params.add(row);
         }
      }

      return params;
   }

   public void setParameters(List<ParametersPanel.ParamRow> params) {
      this.tableModel.clear();
      if (params != null) {
         for (ParametersPanel.ParamRow p : params) {
            this.tableModel.addRow(p);
         }
      }
   }

   public void clear() {
      this.tableModel.clear();
   }

   public void addChangeListener(Runnable listener) {
      this.tableModel.addTableModelListener(e -> listener.run());
   }

   public static class ParamRow {
      public boolean enabled = true;
      public String key = "";
      public String value = "";

      public ParamRow() {
      }

      public ParamRow(String key, String value) {
         this.key = key;
         this.value = value;
      }
   }

   private class ParametersTableModel extends AbstractTableModel {
      private final List<ParametersPanel.ParamRow> rows = new ArrayList<>();
      private final String[] columns = new String[]{"", "Key", "Value"};

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
            ParametersPanel.ParamRow pr = this.rows.get(row);
            switch (col) {
               case 0:
                  return pr.enabled;
               case 1:
                  return pr.key;
               case 2:
                  return pr.value;
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
            ParametersPanel.ParamRow pr = this.rows.get(row);
            switch (col) {
               case 0:
                  pr.enabled = (Boolean)value;
                  break;
               case 1:
                  pr.key = value.toString();
                  break;
               case 2:
                  pr.value = value.toString();
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
         return true;
      }

      public void addRow() {
         this.rows.add(new ParametersPanel.ParamRow());
         this.fireTableRowsInserted(this.rows.size() - 1, this.rows.size() - 1);
      }

      public void addRow(ParametersPanel.ParamRow row) {
         this.rows.add(row);
         this.fireTableRowsInserted(this.rows.size() - 1, this.rows.size() - 1);
      }

      public void removeRow(int row) {
         if (row >= 0 && row < this.rows.size()) {
            this.rows.remove(row);
            this.fireTableRowsDeleted(row, row);
         }
      }

      public void clear() {
         this.rows.clear();
         this.fireTableDataChanged();
      }

      public List<ParametersPanel.ParamRow> getRows() {
         return new ArrayList<>(this.rows);
      }
   }
}
