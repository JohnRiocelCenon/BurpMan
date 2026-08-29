package burp.ui;

import burp.service.CookieJar;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.GridLayout;
import java.awt.Window;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;

public final class CookieManagerDialog extends JDialog {
   private final CookieJar jar;
   private CookieManagerDialog.CookieTableModel model;
   private JTable table;

   public static void show(Component owner, CookieJar jar) {
      Window w = SwingUtilities.getWindowAncestor(owner);
      CookieManagerDialog dlg;
      if (w instanceof Frame) {
         dlg = new CookieManagerDialog((Frame)w, jar);
      } else if (w instanceof Dialog) {
         dlg = new CookieManagerDialog((Dialog)w, jar);
      } else {
         dlg = new CookieManagerDialog((Frame)null, jar);
      }

      dlg.setLocationRelativeTo(owner);
      dlg.setVisible(true);
   }

   private CookieManagerDialog(Frame owner, CookieJar jar) {
      super(owner, "Manage Cookies", true);
      this.jar = jar;
      this.init();
   }

   private CookieManagerDialog(Dialog owner, CookieJar jar) {
      super(owner, "Manage Cookies", true);
      this.jar = jar;
      this.init();
   }

   private void init() {
      this.setSize(720, 480);
      this.setLayout(new BorderLayout(0, 4));
      this.model = new CookieManagerDialog.CookieTableModel(this.jar);
      this.table = new JTable(this.model);
      this.table.setRowHeight(24);
      this.table.setAutoCreateRowSorter(true);
      final TableRowSorter<CookieManagerDialog.CookieTableModel> sorter = new TableRowSorter<>(this.model);
      this.table.setRowSorter(sorter);
      JScrollPane scroll = new JScrollPane(this.table);
      JPanel toolbar = new JPanel(new FlowLayout(0, 6, 6));
      final JTextField filter = new JTextField(24);
      filter.putClientProperty("JTextField.placeholderText", "Filter by host or name…");
      filter.getDocument().addDocumentListener(new DocumentListener() {
         @Override
         public void insertUpdate(DocumentEvent e) {
            this.applyFilter();
         }

         @Override
         public void removeUpdate(DocumentEvent e) {
            this.applyFilter();
         }

         @Override
         public void changedUpdate(DocumentEvent e) {
            this.applyFilter();
         }

         private void applyFilter() {
            String t = filter.getText();
            sorter.setRowFilter(t != null && !t.isEmpty() ? RowFilter.regexFilter("(?i)" + Pattern.quote(t)) : null);
         }
      });
      toolbar.add(new JLabel("Search:"));
      toolbar.add(filter);
      JButton addBtn = new JButton("+ Add");
      addBtn.addActionListener(e -> this.promptAddCookie());
      toolbar.add(addBtn);
      JButton deleteBtn = new JButton("Delete selected");
      deleteBtn.addActionListener(e -> this.deleteSelected());
      toolbar.add(deleteBtn);
      JButton clearAllBtn = new JButton("Clear all");
      clearAllBtn.addActionListener(e -> {
         int yes = JOptionPane.showConfirmDialog(this, "Delete every cookie from every host?", "Confirm", 0, 2);
         if (yes == 0) {
            this.jar.clear();
            this.model.reload();
         }
      });
      toolbar.add(clearAllBtn);
      JButton closeBtn = new JButton("Close");
      closeBtn.addActionListener(e -> this.dispose());
      JPanel south = new JPanel(new BorderLayout());
      JPanel southRight = new JPanel(new FlowLayout(2, 6, 6));
      southRight.add(closeBtn);
      south.add(southRight, "East");
      this.add(toolbar, "North");
      this.add(scroll, "Center");
      this.add(south, "South");
      this.jar.addChangeListener(() -> SwingUtilities.invokeLater(this.model::reload));
   }

   private void deleteSelected() {
      int[] viewRows = this.table.getSelectedRows();
      if (viewRows.length != 0) {
         for (int viewRow : viewRows) {
            int modelRow = this.table.convertRowIndexToModel(viewRow);
            CookieJar.Cookie c = this.model.cookieAt(modelRow);
            if (c != null) {
               this.jar.remove(c.domain, c.name);
            }
         }

         this.model.reload();
      }
   }

   private void promptAddCookie() {
      JTextField host = new JTextField();
      JTextField name = new JTextField();
      JTextField value = new JTextField();
      JTextField path = new JTextField("/");
      JPanel form = new JPanel(new GridLayout(0, 2, 6, 6));
      form.add(new JLabel("Host:"));
      form.add(host);
      form.add(new JLabel("Name:"));
      form.add(name);
      form.add(new JLabel("Value:"));
      form.add(value);
      form.add(new JLabel("Path:"));
      form.add(path);
      int ok = JOptionPane.showConfirmDialog(this, form, "Add Cookie", 2, -1);
      if (ok == 0) {
         if (!host.getText().trim().isEmpty() && !name.getText().trim().isEmpty()) {
            CookieJar.Cookie c = new CookieJar.Cookie();
            c.domain = host.getText().trim().toLowerCase(Locale.ROOT);
            c.name = name.getText().trim();
            c.value = value.getText();
            c.path = path.getText().isEmpty() ? "/" : path.getText();
            this.jar.addOrUpdate(c);
            this.model.reload();
         } else {
            JOptionPane.showMessageDialog(this, "Host and name are required.");
         }
      }
   }

   private static final class CookieTableModel extends AbstractTableModel {
      private final CookieJar jar;
      private List<CookieJar.Cookie> rows;
      private static final SimpleDateFormat FMT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);

      CookieTableModel(CookieJar jar) {
         this.jar = jar;
         this.reload();
      }

      void reload() {
         this.rows = this.jar.getAll();
         this.fireTableDataChanged();
      }

      CookieJar.Cookie cookieAt(int row) {
         return this.rows != null && row >= 0 && row < this.rows.size() ? this.rows.get(row) : null;
      }

      @Override
      public int getRowCount() {
         return this.rows == null ? 0 : this.rows.size();
      }

      @Override
      public int getColumnCount() {
         return 5;
      }

      @Override
      public String getColumnName(int c) {
         return new String[]{"Host", "Name", "Value", "Path", "Expires"}[c];
      }

      @Override
      public Object getValueAt(int r, int c) {
         CookieJar.Cookie cookie = this.rows.get(r);
         switch (c) {
            case 0:
               return cookie.domain;
            case 1:
               return cookie.name;
            case 2:
               return cookie.value == null ? "" : (cookie.value.length() > 80 ? cookie.value.substring(0, 80) + "…" : cookie.value);
            case 3:
               return cookie.path;
            case 4:
               return cookie.expiresMs == 0L ? "session" : FMT.format(new Date(cookie.expiresMs));
            default:
               return "";
         }
      }
   }
}
