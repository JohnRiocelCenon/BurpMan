package burp.ui;

import burp.service.CookieJar;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;

public class CookieJarPanel extends JPanel {
   private final CookieJar jar;
   private final DefaultTableModel model;
   private final JTable table;

   public CookieJarPanel(CookieJar jar) {
      this.jar = jar;
      this.setLayout(new BorderLayout(6, 6));
      this.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
      this.model = new DefaultTableModel(new Object[]{"Host", "Name", "Value", "Path", "Expires"}, 0) {
         @Override
         public boolean isCellEditable(int r, int c) {
            return false;
         }
      };
      this.table = new JTable(this.model);
      this.table.setAutoResizeMode(3);
      this.table.getColumnModel().getColumn(0).setPreferredWidth(180);
      this.table.getColumnModel().getColumn(1).setPreferredWidth(120);
      this.table.getColumnModel().getColumn(2).setPreferredWidth(360);
      this.add(new JScrollPane(this.table), "Center");
      JPanel buttons = new JPanel(new FlowLayout(2));
      JButton refreshBtn = new JButton("Refresh");
      JButton removeBtn = new JButton("Remove Selected");
      JButton clearBtn = new JButton("Clear All");
      buttons.add(refreshBtn);
      buttons.add(removeBtn);
      buttons.add(clearBtn);
      this.add(buttons, "South");
      refreshBtn.addActionListener(e -> this.refresh());
      removeBtn.addActionListener(e -> {
         int row = this.table.getSelectedRow();
         if (row >= 0) {
            String host = String.valueOf(this.model.getValueAt(row, 0));
            String name = String.valueOf(this.model.getValueAt(row, 1));
            jar.remove(host, name);
         }
      });
      clearBtn.addActionListener(e -> {
         int ok = JOptionPane.showConfirmDialog(this, "Clear all cookies from the jar?", "Confirm", 2);
         if (ok == 0) {
            jar.clear();
         }
      });
      if (jar != null) {
         jar.addChangeListener(() -> SwingUtilities.invokeLater(this::refresh));
      }

      this.refresh();
   }

   public void refresh() {
      this.model.setRowCount(0);
      if (this.jar != null) {
         List<CookieJar.Cookie> all = this.jar.getAll();
         SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

         for (CookieJar.Cookie c : all) {
            String expires = c.expiresMs > 0L ? fmt.format(new Date(c.expiresMs)) : "Session";
            this.model.addRow(new Object[]{c.domain, c.name, c.value, c.path, expires});
         }
      }
   }
}
