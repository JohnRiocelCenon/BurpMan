package burp.ui;

import burp.codegen.CodeGenerator;
import burp.codegen.CodeGeneratorRegistry;
import burp.codegen.GenRequest;
import burp.models.PostmanCollection;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileWriter;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

public final class SnippetPanel extends JPanel {
   private final burp.PostmanImporter importer;
   private final JComboBox<String> langCombo;
   private final JTextArea snippetArea;
   private PostmanCollection.Request currentRequest;
   private String currentDisplayName = "request";

   public SnippetPanel(burp.PostmanImporter importer) {
      this.importer = importer;
      this.setLayout(new BorderLayout(0, 4));
      this.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
      JPanel top = new JPanel(new BorderLayout(4, 0));
      JPanel topLeft = new JPanel(new FlowLayout(0, 4, 0));
      JLabel hdr = new JLabel("Code");
      hdr.setFont(hdr.getFont().deriveFont(1, 13.0F));
      topLeft.add(hdr);
      this.langCombo = new JComboBox<>();

      for (CodeGenerator g : CodeGeneratorRegistry.all()) {
         this.langCombo.addItem(g.label());
      }

      this.langCombo.setSelectedItem("Python — requests");
      this.langCombo.addActionListener(e -> this.rerender());
      topLeft.add(this.langCombo);
      top.add(topLeft, "West");
      JPanel topRight = new JPanel(new FlowLayout(2, 4, 0));
      JButton copyBtn = new JButton("Copy");
      copyBtn.addActionListener(e -> this.copyToClipboard());
      topRight.add(copyBtn);
      JButton saveBtn = new JButton("Save…");
      saveBtn.addActionListener(e -> this.saveToFile());
      topRight.add(saveBtn);
      top.add(topRight, "East");
      this.add(top, "North");
      this.snippetArea = new JTextArea();
      this.snippetArea.setEditable(false);
      this.snippetArea.setFont(new Font("Monospaced", 0, 12));
      this.snippetArea.setTabSize(2);
      this.snippetArea.setLineWrap(false);
      this.snippetArea.setText("// Select a request to see its code snippet here.");
      this.add(new JScrollPane(this.snippetArea), "Center");
      this.setPreferredSize(new Dimension(420, 0));
   }

   public void setRequest(PostmanCollection.Request req, String displayName) {
      this.currentRequest = req;
      this.currentDisplayName = displayName == null ? "request" : displayName;
      this.rerender();
   }

   private void rerender() {
      if (this.currentRequest == null) {
         this.snippetArea.setText("// Select a request to see its code snippet here.");
      } else {
         try {
            CodeGenerator gen = CodeGeneratorRegistry.byLabel((String)this.langCombo.getSelectedItem());
            if (gen == null) {
               return;
            }

            GenRequest g = GenRequest.from(this.currentRequest, this.currentDisplayName, this.importer == null ? null : this.importer.getVariableResolver());
            this.snippetArea.setText(gen.generate(g));
            this.snippetArea.setCaretPosition(0);
         } catch (Throwable var3) {
            this.snippetArea.setText("// Snippet generation failed: " + var3.getMessage());
         }
      }
   }

   private void copyToClipboard() {
      Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(this.snippetArea.getText()), null);

      try {
         ToastManager.show(this, "Copied " + this.snippetArea.getText().length() + " chars", ToastManager.Level.SUCCESS);
      } catch (Throwable var2) {
      }
   }

   private void saveToFile() {
      CodeGenerator gen = CodeGeneratorRegistry.byLabel((String)this.langCombo.getSelectedItem());
      String ext = gen == null ? "txt" : gen.fileExtension();
      JFileChooser chooser = new JFileChooser();
      chooser.setSelectedFile(new File(safeFileName(this.currentDisplayName) + "." + ext));
      if (chooser.showSaveDialog(this) == 0) {
         try {
            try (FileWriter w = new FileWriter(chooser.getSelectedFile())) {
               w.write(this.snippetArea.getText());
            }
         } catch (Exception var5) {
            JOptionPane.showMessageDialog(this, "Save failed: " + var5.getMessage(), "Error", 0);
         }
      }
   }

   private static String safeFileName(String s) {
      return s == null ? "snippet" : s.replaceAll("[^A-Za-z0-9._-]", "_");
   }
}
