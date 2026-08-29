package burp.ui;

import burp.models.RequestPreview;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Dialog.ModalityType;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.EventObject;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

public class RequestSelectionDialog extends JDialog {
   private final List<RequestPreview> previews;
   private final burp.PostmanImporter importer;
   private final JTable table;
   private final RequestPreviewTableModel tableModel;
   private boolean importConfirmed = false;
   private JLabel statusLabel;

   public RequestSelectionDialog(List<RequestPreview> previews, burp.PostmanImporter importer, Component parent) {
      super(SwingUtilities.getWindowAncestor(parent), "Select Requests to Import", ModalityType.APPLICATION_MODAL);
      this.previews = previews;
      this.importer = importer;
      this.tableModel = new RequestPreviewTableModel(previews);
      this.table = new JTable(this.tableModel) {
         @Override
         public boolean editCellAt(int row, int column, EventObject e) {
            int modelRow = this.convertRowIndexToModel(row);
            int modelColumn = this.convertColumnIndexToModel(column);
            if (modelColumn == 1) {
               RequestPreview preview = RequestSelectionDialog.this.tableModel.getPreviewAt(modelRow);
               if (!RequestSelectionDialog.this.tableModel.canInjectBearer(preview)) {
                  preview.setAddAuthorizationHeader(false);
                  RequestSelectionDialog.this.tableModel.fireTableCellUpdated(modelRow, modelColumn);
                  return false;
               }
            }

            return super.editCellAt(row, column, e);
         }
      };
      this.tableModel.setSelectionChangeCallback(this::updateSelectionCount);
      this.initializeUI();
      this.setupTable();
      this.setLocationRelativeTo(parent);
   }

   private void initializeUI() {
      this.setLayout(new BorderLayout(10, 10));
      this.setSize(800, 600);
      JPanel headerPanel = new JPanel(new BorderLayout());
      JLabel titleLabel = new JLabel("Select Requests to Import");
      titleLabel.setFont(titleLabel.getFont().deriveFont(1, 16.0F));
      headerPanel.add(titleLabel, "West");
      JPanel statusPanel = new JPanel(new FlowLayout(2));
      JLabel totalLabel = new JLabel(String.format("Total: %d requests", this.previews.size()));
      this.statusLabel = new JLabel();
      this.updateSelectionCount();
      statusPanel.add(totalLabel);
      statusPanel.add(Box.createHorizontalStrut(10));
      statusPanel.add(this.statusLabel);
      headerPanel.add(statusPanel, "East");
      headerPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));
      this.add(headerPanel, "North");
      JScrollPane scrollPane = new JScrollPane(this.table);
      scrollPane.setBorder(BorderFactory.createTitledBorder("Requests"));
      this.add(scrollPane, "Center");
      JPanel buttonPanel = this.createButtonPanel();
      this.add(buttonPanel, "South");
   }

   private void setupTable() {
      this.table.setSelectionMode(0);
      this.table.setRowHeight(25);
      this.table.setRowSelectionAllowed(false);
      this.table.setColumnSelectionAllowed(false);
      TableColumnModel columnModel = this.table.getColumnModel();
      columnModel.getColumn(0).setPreferredWidth(70);
      columnModel.getColumn(1).setPreferredWidth(110);
      columnModel.getColumn(2).setPreferredWidth(80);
      columnModel.getColumn(3).setPreferredWidth(200);
      columnModel.getColumn(4).setPreferredWidth(250);
      columnModel.getColumn(5).setPreferredWidth(120);
      columnModel.getColumn(6).setPreferredWidth(120);
      columnModel.getColumn(7).setPreferredWidth(60);
      columnModel.getColumn(8).setPreferredWidth(60);
      columnModel.getColumn(9).setPreferredWidth(60);
      columnModel.getColumn(2).setCellRenderer(new RequestSelectionDialog.MethodCellRenderer());
      columnModel.getColumn(6).setCellRenderer(new RequestSelectionDialog.VariableCellRenderer());
      TableColumn selectColumn = columnModel.getColumn(0);
      selectColumn.setCellRenderer(new RequestSelectionDialog.CheckboxRenderer());
      selectColumn.setCellEditor(new RequestSelectionDialog.CheckboxEditor());
      selectColumn.setMaxWidth(70);
      selectColumn.setMinWidth(70);
      TableColumn addAuthColumn = columnModel.getColumn(1);
      addAuthColumn.setCellRenderer(new RequestSelectionDialog.CheckboxRenderer());
      addAuthColumn.setCellEditor(new RequestSelectionDialog.CheckboxEditor());
      addAuthColumn.setMaxWidth(110);
      addAuthColumn.setMinWidth(110);
      this.table.addMouseListener(new MouseAdapter() {
         @Override
         public void mousePressed(MouseEvent e) {
            RequestSelectionDialog.this.blockDisabledBearerClick(e);
         }

         @Override
         public void mouseReleased(MouseEvent e) {
            RequestSelectionDialog.this.blockDisabledBearerClick(e);
         }
      });
      this.forceDisabledBearerRowsUnchecked();
   }

   private void blockDisabledBearerClick(MouseEvent e) {
      int viewRow = this.table.rowAtPoint(e.getPoint());
      int viewColumn = this.table.columnAtPoint(e.getPoint());
      if (viewRow >= 0 && viewColumn >= 0) {
         int modelRow = this.table.convertRowIndexToModel(viewRow);
         int modelColumn = this.table.convertColumnIndexToModel(viewColumn);
         if (modelColumn == 1) {
            RequestPreview preview = this.tableModel.getPreviewAt(modelRow);
            if (!this.canInjectBearer(preview)) {
               if (this.table.isEditing()) {
                  this.table.getCellEditor().cancelCellEditing();
               }

               preview.setAddAuthorizationHeader(false);
               this.tableModel.fireTableCellUpdated(modelRow, modelColumn);
               e.consume();
            }
         }
      }
   }

   private boolean canInjectBearer(RequestPreview preview) {
      return this.tableModel.canInjectBearer(preview);
   }

   private void forceDisabledBearerRowsUnchecked() {
      this.tableModel.normalizeBearerSelections();
   }

   private JPanel createButtonPanel() {
      JPanel buttonPanel = new JPanel(new BorderLayout());
      buttonPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
      JPanel selectionPanel = new JPanel(new FlowLayout(0));
      JButton toggleImportBtn = new JButton("Select/Deselect All - Request");
      toggleImportBtn.addActionListener(e -> this.toggleImportReq());
      JButton toggleBearerBtn = new JButton("Select/Deselect All - Auth");
      toggleBearerBtn.addActionListener(e -> this.toggleBearerTokens());
      JButton selectByMethodBtn = new JButton("Select by Method...");
      selectByMethodBtn.addActionListener(e -> this.selectByMethod());
      selectionPanel.add(toggleImportBtn);
      selectionPanel.add(toggleBearerBtn);
      selectionPanel.add(selectByMethodBtn);
      buttonPanel.add(selectionPanel, "West");
      JPanel actionPanel = new JPanel(new FlowLayout(2));
      JButton previewBtn = new JButton("Preview Selected");
      previewBtn.addActionListener(e -> this.previewSelected());
      JButton cancelBtn = new JButton("Cancel");
      cancelBtn.addActionListener(e -> {
         this.importConfirmed = false;
         this.dispose();
      });
      JButton importBtn = new JButton("Import Selected");
      importBtn.addActionListener(e -> {
         this.importConfirmed = true;
         this.dispose();
      });
      actionPanel.add(previewBtn);
      actionPanel.add(cancelBtn);
      actionPanel.add(importBtn);
      buttonPanel.add(actionPanel, "East");
      return buttonPanel;
   }

   private void updateSelectionCount() {
      int selectedCount = 0;

      for (RequestPreview preview : this.previews) {
         if (preview.isSelected()) {
            selectedCount++;
         }
      }

      if (this.statusLabel != null) {
         this.statusLabel.setText(String.format("Selected: %d", selectedCount));
         this.statusLabel.setForeground(selectedCount > 0 ? new Color(0, 120, 0) : Color.GRAY);
      }
   }

   private void toggleImportReq() {
      boolean shouldSelect = false;

      for (RequestPreview preview : this.previews) {
         if (!preview.isSelected()) {
            shouldSelect = true;
            break;
         }
      }

      for (RequestPreview previewx : this.previews) {
         previewx.setSelected(shouldSelect);
      }

      this.tableModel.fireTableDataChanged();
      this.updateSelectionCount();
   }

   private void toggleBearerTokens() {
      boolean shouldEnable = false;
      this.forceDisabledBearerRowsUnchecked();

      for (RequestPreview preview : this.previews) {
         if (this.canInjectBearer(preview) && !preview.shouldAddAuthorizationHeader()) {
            shouldEnable = true;
            break;
         }
      }

      for (RequestPreview previewx : this.previews) {
         if (this.canInjectBearer(previewx)) {
            if (shouldEnable && this.isPossibleTokenEndpoint(previewx.getUrl())) {
               boolean confirmed = this.confirmBearerOnTokenEndpoint(previewx);
               if (!confirmed) {
                  continue;
               }
            }

            previewx.setAddAuthorizationHeader(shouldEnable);
         } else {
            previewx.setAddAuthorizationHeader(false);
         }
      }

      this.tableModel.fireTableDataChanged();
      this.updateSelectionCount();
   }

   private boolean isPossibleTokenEndpoint(String url) {
      if (url == null) {
         return false;
      } else {
         String lower = url.toLowerCase();
         return lower.contains("login.microsoftonline.com")
            || lower.contains("login.microsoft.com")
            || lower.contains("sts.windows.net")
            || lower.contains("accounts.google.com")
            || lower.contains("/oauth")
            || lower.contains("/token")
            || lower.contains("/authorize");
      }
   }

   private boolean confirmBearerOnTokenEndpoint(RequestPreview preview) {
      String message = "This request looks like a token / identity provider endpoint:\n\n"
         + preview.getUrl()
         + "\n\nInjecting Authorization: Bearer {{token}} here may break authentication.\n\nDo you want to continue anyway?";
      int result = JOptionPane.showConfirmDialog(this, message, "Possible Token Endpoint Detected", 0, 2);
      return result == 0;
   }

   private void selectByMethod() {
      String[] methods = new String[]{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"};
      String method = (String)JOptionPane.showInputDialog(this, "Select requests by HTTP method:", "Select by Method", 3, null, methods, "GET");
      if (method != null) {
         for (RequestPreview preview : this.previews) {
            preview.setSelected(method.equals(preview.getMethod()));
         }

         this.tableModel.fireTableDataChanged();
         this.updateSelectionCount();
      }
   }

   private void previewSelected() {
      List<RequestPreview> selected = this.getSelectedRequests();
      if (selected.isEmpty()) {
         JOptionPane.showMessageDialog(this, "No requests selected for preview.", "No Selection", 2);
      } else {
         StringBuilder preview = new StringBuilder();
         preview.append(String.format("Selected %d requests for import:\n\n", selected.size()));

         for (RequestPreview req : selected) {
            preview.append(String.format("[%s] %s\n", req.getMethod(), req.getName()));
            preview.append(String.format("    URL: %s\n", req.getUrl()));
            preview.append(String.format("    Path: %s\n", req.getPath()));
            if (req.hasAuth()) {
               preview.append("    • Has Authentication\n");
            }

            if (req.hasHeaders()) {
               preview.append("    • Has Custom Headers\n");
            }

            if (req.hasBody()) {
               preview.append("    • Has Request Body\n");
            }

            preview.append("\n");
         }

         JTextArea textArea = new JTextArea(preview.toString());
         textArea.setEditable(false);
         textArea.setFont(new Font("Monospaced", 0, 12));
         JScrollPane scrollPane = new JScrollPane(textArea);
         scrollPane.setPreferredSize(new Dimension(600, 400));
         JOptionPane.showMessageDialog(this, scrollPane, "Import Preview", 1);
      }
   }

   public List<RequestPreview> getSelectedRequests() {
      this.forceDisabledBearerRowsUnchecked();
      List<RequestPreview> selected = new ArrayList<>();

      for (RequestPreview preview : this.previews) {
         if (!this.canInjectBearer(preview)) {
            preview.setAddAuthorizationHeader(false);
         }

         if (preview.isSelected()) {
            selected.add(preview);
         }
      }

      return selected;
   }

   public boolean showDialog() {
      this.setVisible(true);
      return this.importConfirmed;
   }

   private class CheckboxEditor extends DefaultCellEditor {
      public CheckboxEditor() {
         super(new JCheckBox());
         JCheckBox checkBox = (JCheckBox)this.getComponent();
         checkBox.setHorizontalAlignment(0);
      }

      @Override
      public boolean isCellEditable(EventObject e) {
         if (!(e instanceof MouseEvent)) {
            return false;
         } else {
            MouseEvent me = (MouseEvent)e;
            JTable sourceTable = (JTable)me.getSource();
            int viewRow = sourceTable.rowAtPoint(me.getPoint());
            int viewColumn = sourceTable.columnAtPoint(me.getPoint());
            if (viewRow >= 0 && viewColumn >= 0) {
               int modelRow = sourceTable.convertRowIndexToModel(viewRow);
               int modelColumn = sourceTable.convertColumnIndexToModel(viewColumn);
               RequestPreview preview = RequestSelectionDialog.this.tableModel.getPreviewAt(modelRow);
               if (modelColumn == 1 && !RequestSelectionDialog.this.canInjectBearer(preview)) {
                  preview.setAddAuthorizationHeader(false);
                  RequestSelectionDialog.this.tableModel.fireTableCellUpdated(modelRow, modelColumn);
                  return false;
               } else {
                  return true;
               }
            } else {
               return false;
            }
         }
      }

      @Override
      public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column) {
         int modelRow = table.convertRowIndexToModel(row);
         int modelColumn = table.convertColumnIndexToModel(column);
         RequestPreview preview = RequestSelectionDialog.this.tableModel.getPreviewAt(modelRow);
         JCheckBox checkBox = (JCheckBox)this.getComponent();
         checkBox.setHorizontalAlignment(0);
         if (modelColumn == 1 && !RequestSelectionDialog.this.canInjectBearer(preview)) {
            preview.setAddAuthorizationHeader(false);
            checkBox.setSelected(false);
            checkBox.setEnabled(false);
         } else {
            checkBox.setSelected(Boolean.TRUE.equals(value));
            checkBox.setEnabled(true);
         }

         return checkBox;
      }
   }

   private class CheckboxRenderer extends JCheckBox implements TableCellRenderer {
      public CheckboxRenderer() {
         this.setHorizontalAlignment(0);
         this.setOpaque(true);
      }

      @Override
      public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
         int modelRow = table.convertRowIndexToModel(row);
         int modelColumn = table.convertColumnIndexToModel(column);
         RequestPreview preview = RequestSelectionDialog.this.tableModel.getPreviewAt(modelRow);
         boolean enabled = true;
         boolean checked = Boolean.TRUE.equals(value);
         if (modelColumn == 1) {
            enabled = RequestSelectionDialog.this.canInjectBearer(preview);
            if (!enabled) {
               checked = false;
               preview.setAddAuthorizationHeader(false);
               this.setToolTipText("Bearer {{token}} disabled because Auth is already configured or Authorization header exists");
            } else {
               this.setToolTipText("Inject Authorization: Bearer {{token}}");
            }
         } else {
            this.setToolTipText(null);
         }

         this.setEnabled(enabled);
         this.setSelected(checked);
         if (isSelected) {
            this.setBackground(table.getSelectionBackground());
         } else {
            this.setBackground(table.getBackground());
         }

         return this;
      }
   }

   private static class MethodCellRenderer extends DefaultTableCellRenderer {
      @Override
      public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
         super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
         String method = (String)value;
         label28:
         if (!isSelected) {
            switch (method.hashCode()) {
               case 70454:
                  if (method.equals("GET")) {
                     this.setForeground(new Color(0, 120, 0));
                     break label28;
                  }
                  break;
               case 79599:
                  if (method.equals("PUT")) {
                     this.setForeground(new Color(0, 0, 200));
                     break label28;
                  }
                  break;
               case 2461856:
                  if (method.equals("POST")) {
                     this.setForeground(new Color(255, 140, 0));
                     break label28;
                  }
                  break;
               case 2012838315:
                  if (method.equals("DELETE")) {
                     this.setForeground(new Color(200, 0, 0));
                     break label28;
                  }
            }

            this.setForeground(UITheme.foreground());
         }

         this.setHorizontalAlignment(0);
         this.setFont(this.getFont().deriveFont(1));
         return this;
      }
   }

   private static class VariableCellRenderer extends DefaultTableCellRenderer {
      @Override
      public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
         super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
         String variableStatus = (String)value;
         if (!isSelected) {
            if (variableStatus.startsWith("✅")) {
               this.setForeground(new Color(0, 120, 0));
            } else if (variableStatus.startsWith("⚠️")) {
               this.setForeground(new Color(255, 140, 0));
            } else if (variableStatus.startsWith("❌")) {
               this.setForeground(Color.RED);
            } else {
               this.setForeground(table.getForeground());
            }
         } else {
            this.setForeground(table.getSelectionForeground());
         }

         return this;
      }
   }
}
