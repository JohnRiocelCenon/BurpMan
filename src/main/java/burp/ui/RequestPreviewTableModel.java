package burp.ui;

import burp.models.RequestPreview;
import java.util.List;
import javax.swing.JOptionPane;
import javax.swing.table.AbstractTableModel;

public class RequestPreviewTableModel extends AbstractTableModel {
   private final String[] columnNames = new String[]{"Selected", "Inject Auth", "Method", "Name", "URL", "Path", "Variables", "Auth", "Headers", "Body"};
   private final Class<?>[] columnTypes = new Class[]{
      Boolean.class, Boolean.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class
   };
   private final List<RequestPreview> previews;
   private Runnable selectionChangeCallback;

   public RequestPreviewTableModel(List<RequestPreview> previews) {
      this.previews = previews;
   }

   public void setSelectionChangeCallback(Runnable callback) {
      this.selectionChangeCallback = callback;
   }

   @Override
   public int getRowCount() {
      return this.previews.size();
   }

   @Override
   public int getColumnCount() {
      return this.columnNames.length;
   }

   @Override
   public String getColumnName(int column) {
      return this.columnNames[column];
   }

   @Override
   public Class<?> getColumnClass(int columnIndex) {
      return this.columnTypes[columnIndex];
   }

   @Override
   public boolean isCellEditable(int rowIndex, int columnIndex) {
      if (columnIndex == 0) {
         return true;
      } else {
         return columnIndex == 1 ? this.canInjectBearer(this.previews.get(rowIndex)) : false;
      }
   }

   @Override
   public Object getValueAt(int rowIndex, int columnIndex) {
      RequestPreview preview = this.previews.get(rowIndex);
      switch (columnIndex) {
         case 0:
            return preview.isSelected();
         case 1:
            if (this.canInjectBearer(preview) && preview.shouldAddAuthorizationHeader()) {
               return true;
            }

            return false;
         case 2:
            return preview.getMethod();
         case 3:
            return preview.getName();
         case 4:
            return this.truncateUrl(preview.getUrl(), 50);
         case 5:
            return preview.getPath();
         case 6:
            return preview.getVariableStatus();
         case 7:
            return preview.hasAuth() ? "✓" : "";
         case 8:
            return preview.hasHeaders() ? "✓" : "";
         case 9:
            return preview.hasBody() ? "✓" : "";
         default:
            return "";
      }
   }

   @Override
   public void setValueAt(Object value, int rowIndex, int columnIndex) {
      if (value instanceof Boolean) {
         if (columnIndex == 0) {
            this.previews.get(rowIndex).setSelected((Boolean)value);
            this.fireTableCellUpdated(rowIndex, columnIndex);
         } else if (columnIndex == 1) {
            RequestPreview preview = this.previews.get(rowIndex);
            if (!this.canInjectBearer(preview)) {
               preview.setAddAuthorizationHeader(false);
               this.fireTableCellUpdated(rowIndex, columnIndex);
               return;
            }

            boolean newValue = (Boolean)value;
            if (newValue && this.isPossibleTokenEndpoint(preview.getUrl())) {
               boolean confirmed = this.confirmBearerOnTokenEndpoint(preview);
               if (!confirmed) {
                  this.fireTableCellUpdated(rowIndex, columnIndex);
                  return;
               }
            }

            preview.setAddAuthorizationHeader(newValue);
            this.fireTableCellUpdated(rowIndex, columnIndex);
         }

         if (this.selectionChangeCallback != null) {
            this.selectionChangeCallback.run();
         }
      }
   }

   public boolean canInjectBearer(RequestPreview preview) {
      if (preview == null) {
         return false;
      } else {
         return preview.hasAuth() ? false : preview.isMissingAuthorizationHeader();
      }
   }

   public void normalizeBearerSelections() {
      for (int i = 0; i < this.previews.size(); i++) {
         RequestPreview preview = this.previews.get(i);
         if (!this.canInjectBearer(preview) && preview.shouldAddAuthorizationHeader()) {
            preview.setAddAuthorizationHeader(false);
            this.fireTableCellUpdated(i, 1);
         }
      }
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
      int result = JOptionPane.showConfirmDialog(null, message, "Possible Token Endpoint Detected", 0, 2);
      return result == 0;
   }

   private String truncateUrl(String url, int maxLength) {
      if (url == null) {
         return "";
      } else {
         return url.length() <= maxLength ? url : url.substring(0, maxLength - 3) + "...";
      }
   }

   public RequestPreview getPreviewAt(int rowIndex) {
      return this.previews.get(rowIndex);
   }
}
