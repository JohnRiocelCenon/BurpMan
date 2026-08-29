package burp.ui;

import burp.models.ExecutedRequest;
import burp.models.PostmanCollection;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Dialog.ModalityType;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

public class RequestDetailDialog extends JDialog {
   public RequestDetailDialog(Component parent, ExecutedRequest request) {
      super(SwingUtilities.getWindowAncestor(parent), "Request Details", ModalityType.APPLICATION_MODAL);
      this.setLayout(new BorderLayout(5, 5));
      JTabbedPane tabbedPane = new JTabbedPane();
      tabbedPane.addTab("Request", this.createRequestPanel(request));
      tabbedPane.addTab("Response", this.createResponsePanel(request));
      tabbedPane.addTab("Details", this.createDetailsPanel(request));
      this.add(tabbedPane, "Center");
      JPanel buttonPanel = new JPanel(new FlowLayout(2));
      JButton closeBtn = new JButton("Close");
      closeBtn.addActionListener(e -> this.dispose());
      buttonPanel.add(closeBtn);
      this.add(buttonPanel, "South");
      this.setSize(800, 600);
      this.setLocationRelativeTo(parent);
      this.setMinimumSize(new Dimension(600, 400));
   }

   private JPanel createRequestPanel(ExecutedRequest request) {
      JPanel panel = new JPanel(new BorderLayout());
      JTextArea textArea = new JTextArea();
      textArea.setEditable(false);
      textArea.setFont(new Font("Monospaced", 0, 11));
      StringBuilder sb = new StringBuilder();
      sb.append(request.getMethod()).append(" ").append(request.getUrl()).append("\n\n");
      sb.append("Headers:\n");
      if (request.getRequestHeaders() != null) {
         for (PostmanCollection.Header h : request.getRequestHeaders()) {
            sb.append(h.key).append(": ").append(h.value).append("\n");
         }
      }

      sb.append("\nBody:\n");
      if (request.getRequestBody() != null && !request.getRequestBody().isEmpty()) {
         sb.append(request.getRequestBody());
      } else {
         sb.append("(empty)");
      }

      textArea.setText(sb.toString());
      JScrollPane scrollPane = new JScrollPane(textArea);
      panel.add(scrollPane, "Center");
      return panel;
   }

   private JPanel createResponsePanel(ExecutedRequest request) {
      JPanel panel = new JPanel(new BorderLayout());
      JTextArea textArea = new JTextArea();
      textArea.setEditable(false);
      textArea.setFont(new Font("Monospaced", 0, 11));
      StringBuilder sb = new StringBuilder();
      sb.append("HTTP/1.1 ").append(request.getStatusCode()).append(" ").append(request.getStatusText()).append("\n\n");
      sb.append("Headers:\n");
      if (request.getResponseHeaders() != null) {
         for (PostmanCollection.Header h : request.getResponseHeaders()) {
            sb.append(h.key).append(": ").append(h.value).append("\n");
         }
      }

      sb.append("\nBody:\n");
      if (request.getResponseBody() != null && !request.getResponseBody().isEmpty()) {
         sb.append(request.getResponseBody());
      } else {
         sb.append("(empty)");
      }

      textArea.setText(sb.toString());
      JScrollPane scrollPane = new JScrollPane(textArea);
      panel.add(scrollPane, "Center");
      return panel;
   }

   private JPanel createDetailsPanel(ExecutedRequest request) {
      JPanel panel = new JPanel();
      panel.setLayout(new BoxLayout(panel, 1));
      panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
      SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
      this.addDetailRow(panel, "Request ID:", request.getId());
      this.addDetailRow(panel, "Timestamp:", sdf.format(new Date(request.getTimestamp())));
      this.addDetailRow(panel, "Duration:", request.getDurationMs() + " ms");
      this.addDetailRow(panel, "Status Code:", request.getStatusCode() + " " + (request.isSuccess() ? "Success" : "Failed"));
      this.addDetailRow(panel, "Content Type:", request.getContentType() != null ? request.getContentType() : "-");
      if (request.getError() != null) {
         this.addDetailRow(panel, "Error:", request.getError());
      }

      JScrollPane scrollPane = new JScrollPane(panel);
      JPanel containerPanel = new JPanel(new BorderLayout());
      containerPanel.add(scrollPane, "Center");
      return containerPanel;
   }

   private void addDetailRow(JPanel panel, String label, String value) {
      JPanel row = new JPanel(new FlowLayout(0));
      row.add(new JLabel(label));
      row.add(new JLabel(value));
      panel.add(row);
   }
}
