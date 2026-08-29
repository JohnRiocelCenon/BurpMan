package burp.ui;

import burp.utils.FormatUtils;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.border.EmptyBorder;

public class BodyViewer extends JPanel {
   private JTextArea bodyArea;
   private JButton copyButton;
   private JButton formatButton;
   private String currentBody;
   private String currentContentType;

   public BodyViewer() {
      this.setLayout(new BorderLayout());
      this.initializeComponents();
   }

   private void initializeComponents() {
      JPanel toolbarPanel = new JPanel(new FlowLayout(0, 5, 5));
      toolbarPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
      this.copyButton = new JButton("Copy");
      this.copyButton.addActionListener(e -> this.copyToClipboard());
      toolbarPanel.add(this.copyButton);
      this.formatButton = new JButton("Format");
      this.formatButton.addActionListener(e -> this.reformat());
      toolbarPanel.add(this.formatButton);
      this.bodyArea = new JTextArea();
      this.bodyArea.setEditable(false);
      this.bodyArea.setFont(new Font("Monospaced", 0, 11));
      this.bodyArea.setLineWrap(false);
      this.bodyArea.setWrapStyleWord(false);
      JScrollPane scrollPane = new JScrollPane(this.bodyArea);
      scrollPane.setHorizontalScrollBarPolicy(30);
      scrollPane.setVerticalScrollBarPolicy(20);
      this.add(toolbarPanel, "North");
      this.add(scrollPane, "Center");
   }

   public void displayBody(String body, String contentType) {
      this.currentBody = body;
      this.currentContentType = contentType;
      if (body != null && !body.isEmpty()) {
         String formatted = FormatUtils.autoFormat(body, contentType);
         this.bodyArea.setText(formatted);
         this.bodyArea.setCaretPosition(0);
      } else {
         this.bodyArea.setText("(empty response)");
      }
   }

   private void copyToClipboard() {
      String text = this.bodyArea.getText();
      if (text != null && !text.isEmpty()) {
         StringSelection selection = new StringSelection(text);
         Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
         JOptionPane.showMessageDialog(this, "Copied to clipboard", "Success", 1);
      }
   }

   private void reformat() {
      if (this.currentBody != null && !this.currentBody.isEmpty()) {
         String formatted = FormatUtils.autoFormat(this.currentBody, this.currentContentType);
         this.bodyArea.setText(formatted);
         this.bodyArea.setCaretPosition(0);
      }
   }

   public void clear() {
      this.bodyArea.setText("");
      this.currentBody = null;
      this.currentContentType = null;
   }
}
