package burp.ui;

import burp.models.AnalyzedRequest;
import burp.models.PostmanCollection;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Frame;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;

public final class GlobalSearchDialog extends JDialog {
   private final burp.PostmanImporter importer;
   private final GlobalSearchDialog.OnRequestOpened opener;
   private final JTextField queryField;
   private final GlobalSearchDialog.ResultTableModel model;
   private final JTable table;
   private final JCheckBox searchBody;
   private final JCheckBox searchHeaders;
   private final JLabel hintLabel;

   public static void show(Component owner, burp.PostmanImporter importer, GlobalSearchDialog.OnRequestOpened opener) {
      Window w = SwingUtilities.getWindowAncestor(owner);
      GlobalSearchDialog dlg;
      if (w instanceof Frame) {
         dlg = new GlobalSearchDialog((Frame)w, importer, opener);
      } else if (w instanceof Dialog) {
         dlg = new GlobalSearchDialog((Dialog)w, importer, opener);
      } else {
         dlg = new GlobalSearchDialog((Frame)null, importer, opener);
      }

      dlg.setLocationRelativeTo(owner);
      dlg.setVisible(true);
   }

   private GlobalSearchDialog(Frame owner, burp.PostmanImporter importer, GlobalSearchDialog.OnRequestOpened opener) {
      super(owner, "Search requests", false);
      this.importer = importer;
      this.opener = opener;
      this.queryField = new JTextField();
      this.model = new GlobalSearchDialog.ResultTableModel();
      this.table = new JTable(this.model);
      this.searchBody = new JCheckBox("body", false);
      this.searchHeaders = new JCheckBox("headers", true);
      this.hintLabel = new JLabel(" ");
      this.init();
   }

   private GlobalSearchDialog(Dialog owner, burp.PostmanImporter importer, GlobalSearchDialog.OnRequestOpened opener) {
      super(owner, "Search requests", false);
      this.importer = importer;
      this.opener = opener;
      this.queryField = new JTextField();
      this.model = new GlobalSearchDialog.ResultTableModel();
      this.table = new JTable(this.model);
      this.searchBody = new JCheckBox("body", false);
      this.searchHeaders = new JCheckBox("headers", true);
      this.hintLabel = new JLabel(" ");
      this.init();
   }

   private void init() {
      this.setSize(820, 520);
      this.setLayout(new BorderLayout(0, 4));
      JPanel north = new JPanel(new BorderLayout(6, 6));
      north.setBorder(BorderFactory.createEmptyBorder(8, 8, 4, 8));
      this.queryField.putClientProperty("JTextField.placeholderText", "Search name, path, method, URL…");
      this.queryField.setFont(this.queryField.getFont().deriveFont(0, 14.0F));
      north.add(this.queryField, "Center");
      JPanel filters = new JPanel();
      filters.add(new JLabel("Also search:"));
      filters.add(this.searchHeaders);
      filters.add(this.searchBody);
      north.add(filters, "East");
      this.add(north, "North");
      this.table.setRowHeight(24);
      this.table.setAutoCreateRowSorter(true);
      this.table.setSelectionMode(0);
      this.table.setShowVerticalLines(false);
      this.table.getColumnModel().getColumn(0).setPreferredWidth(60);
      this.table.getColumnModel().getColumn(1).setPreferredWidth(250);
      this.table.getColumnModel().getColumn(2).setPreferredWidth(450);
      this.table.setDefaultRenderer(Object.class, new GlobalSearchDialog.MethodColoringRenderer());
      this.add(new JScrollPane(this.table), "Center");
      this.hintLabel.setForeground(new Color(136, 136, 136));
      this.hintLabel.setBorder(BorderFactory.createEmptyBorder(4, 8, 6, 8));
      this.add(this.hintLabel, "South");
      this.queryField.getDocument().addDocumentListener(new DocumentListener() {
         @Override
         public void insertUpdate(DocumentEvent e) {
            GlobalSearchDialog.this.refresh();
         }

         @Override
         public void removeUpdate(DocumentEvent e) {
            GlobalSearchDialog.this.refresh();
         }

         @Override
         public void changedUpdate(DocumentEvent e) {
            GlobalSearchDialog.this.refresh();
         }
      });
      this.searchHeaders.addActionListener(e -> this.refresh());
      this.searchBody.addActionListener(e -> this.refresh());
      this.getRootPane().registerKeyboardAction(e -> this.dispose(), KeyStroke.getKeyStroke(27, 0), 2);
      this.queryField.addActionListener(this::openSelected);
      this.table.getInputMap(0).put(KeyStroke.getKeyStroke(10, 0), "open");
      this.table.getActionMap().put("open", new AbstractAction() {
         @Override
         public void actionPerformed(ActionEvent e) {
            GlobalSearchDialog.this.openSelected(e);
         }
      });
      this.table.addMouseListener(new MouseAdapter() {
         @Override
         public void mouseClicked(MouseEvent e) {
            if (e.getClickCount() == 2) {
               GlobalSearchDialog.this.openSelected(null);
            }
         }
      });
      this.queryField.requestFocusInWindow();
      this.refresh();
   }

   private void refresh() {
      String q = this.queryField.getText() == null ? "" : this.queryField.getText().trim().toLowerCase(Locale.ROOT);
      List<AnalyzedRequest> all = (List<AnalyzedRequest>)(this.importer != null && this.importer.getCurrentCollection() != null
         ? flattenAll(this.importer.getCurrentCollection())
         : new ArrayList<>());
      List<AnalyzedRequest> filtered = new ArrayList<>(all.size());

      for (AnalyzedRequest ar : all) {
         if (q.isEmpty() || this.matches(ar, q)) {
            filtered.add(ar);
         }
      }

      this.model.setRows(filtered);
      this.hintLabel.setText(filtered.size() + " of " + all.size() + " requests");
      if (filtered.size() > 0) {
         this.table.setRowSelectionInterval(0, 0);
      }
   }

   private boolean matches(AnalyzedRequest ar, String q) {
      if (ar == null) {
         return false;
      } else if (ar.getName() != null && ar.getName().toLowerCase(Locale.ROOT).contains(q)) {
         return true;
      } else if (ar.getPath() != null && ar.getPath().toLowerCase(Locale.ROOT).contains(q)) {
         return true;
      } else {
         PostmanCollection.Request r = ar.getRequest();
         if (r != null) {
            if (r.method != null && r.method.toLowerCase(Locale.ROOT).contains(q)) {
               return true;
            }

            if (r.url != null && r.url.toString().toLowerCase(Locale.ROOT).contains(q)) {
               return true;
            }

            if (this.searchHeaders.isSelected() && r.header != null) {
               for (PostmanCollection.Header h : r.header) {
                  if (h != null) {
                     if (h.key != null && h.key.toLowerCase(Locale.ROOT).contains(q)) {
                        return true;
                     }

                     if (h.value != null && h.value.toLowerCase(Locale.ROOT).contains(q)) {
                        return true;
                     }
                  }
               }
            }

            if (this.searchBody.isSelected() && r.body != null && r.body.raw != null && r.body.raw.toLowerCase(Locale.ROOT).contains(q)) {
               return true;
            }
         }

         return false;
      }
   }

   private void openSelected(ActionEvent unused) {
      int viewRow = this.table.getSelectedRow();
      if (viewRow < 0 && this.table.getRowCount() > 0) {
         viewRow = 0;
      }

      if (viewRow >= 0) {
         int modelRow = this.table.convertRowIndexToModel(viewRow);
         AnalyzedRequest ar = this.model.rowAt(modelRow);
         if (ar != null && this.opener != null) {
            this.opener.open(ar);
            this.dispose();
         }
      }
   }

   private static List<AnalyzedRequest> flattenAll(PostmanCollection collection) {
      List<AnalyzedRequest> out = new ArrayList<>();
      if (collection != null && collection.item != null) {
         flattenInto(collection.item, "", out);
         return out;
      } else {
         return out;
      }
   }

   private static void flattenInto(List<PostmanCollection.Item> items, String parentPath, List<AnalyzedRequest> out) {
      if (items != null) {
         for (PostmanCollection.Item it : items) {
            if (it != null) {
               String here = parentPath.isEmpty() ? (it.name == null ? "" : it.name) : parentPath + "/" + (it.name == null ? "" : it.name);
               if (it.request != null) {
                  String url = it.request.url == null ? "" : it.request.url.toString();
                  AnalyzedRequest ar = new AnalyzedRequest(it.name == null ? "" : it.name, here, it.request, "", url);
                  out.add(ar);
               }

               if (it.item != null) {
                  flattenInto(it.item, here, out);
               }
            }
         }
      }
   }

   private static final class MethodColoringRenderer extends DefaultTableCellRenderer {
      @Override
      public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
         Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
         if (column == 0 && value != null) {
            c.setForeground(methodColor(value.toString()));
            ((JLabel)c).setFont(c.getFont().deriveFont(1, 11.0F));
         } else if (!isSelected) {
            c.setForeground(table.getForeground());
         }

         return c;
      }

      private static Color methodColor(String m) {
         switch (m.hashCode()) {
            case -531492226:
               if (m.equals("OPTIONS")) {
                  return new Color(255, 112, 67);
               }
               break;
            case 70454:
               if (m.equals("GET")) {
                  return new Color(41, 182, 246);
               }
               break;
            case 79599:
               if (m.equals("PUT")) {
                  return new Color(255, 167, 38);
               }
               break;
            case 2213344:
               if (m.equals("HEAD")) {
                  return new Color(171, 71, 188);
               }
               break;
            case 2461856:
               if (m.equals("POST")) {
                  return new Color(102, 187, 106);
               }
               break;
            case 75900968:
               if (m.equals("PATCH")) {
                  return new Color(128, 203, 196);
               }
               break;
            case 2012838315:
               if (m.equals("DELETE")) {
                  return new Color(239, 83, 80);
               }
         }

         return new Color(144, 144, 144);
      }
   }

   public interface OnRequestOpened {
      void open(AnalyzedRequest var1);
   }

   private static final class ResultTableModel extends AbstractTableModel {
      private List<AnalyzedRequest> rows = new ArrayList<>();

      void setRows(List<AnalyzedRequest> r) {
         this.rows = (List<AnalyzedRequest>)(r == null ? new ArrayList<>() : r);
         this.fireTableDataChanged();
      }

      AnalyzedRequest rowAt(int i) {
         return i >= 0 && i < this.rows.size() ? this.rows.get(i) : null;
      }

      @Override
      public int getRowCount() {
         return this.rows.size();
      }

      @Override
      public int getColumnCount() {
         return 3;
      }

      @Override
      public String getColumnName(int c) {
         return new String[]{"Method", "Name", "Path / URL"}[c];
      }

      @Override
      public Object getValueAt(int r, int c) {
         AnalyzedRequest ar = this.rows.get(r);
         PostmanCollection.Request req = ar.getRequest();
         switch (c) {
            case 0:
               return req != null && req.method != null ? req.method.toUpperCase() : "GET";
            case 1:
               return ar.getName();
            case 2:
               String url = req != null && req.url != null ? req.url.toString() : "";
               return ar.getPath() + "    " + url;
            default:
               return "";
         }
      }
   }
}
