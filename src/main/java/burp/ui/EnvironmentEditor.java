package burp.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.Window;
import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;

public class EnvironmentEditor extends JPanel {
   private final burp.PostmanImporter importer;
   private final DefaultTableModel tableModel;
   private File currentEnvFile;
   private static final Pattern KEY_PATTERN = Pattern.compile("^[A-Za-z0-9_.-]+$");

   public EnvironmentEditor() {
      this.importer = null;
      this.tableModel = new DefaultTableModel(new Object[]{"Variable", "Value"}, 0);
      this.initializeUI();
   }

   public EnvironmentEditor(burp.PostmanImporter importer) {
      this.importer = importer;
      this.tableModel = new DefaultTableModel(new Object[]{"Variable", "Value"}, 0);
      this.initializeUI();
   }

   private void initializeUI() {
      this.setLayout(new BorderLayout(8, 8));
      JPanel top = new JPanel(new FlowLayout(0));
      JButton loadBtn = new JButton("Load Env File");
      JButton refreshBtn = new JButton("Refresh from Importer");
      JButton saveBtn = new JButton("Save Env File");
      JButton validateBtn = new JButton("Validate");
      JButton applyBtn = new JButton("Apply to Importer");
      saveBtn.setEnabled(false);
      top.add(loadBtn);
      top.add(refreshBtn);
      top.add(saveBtn);
      top.add(validateBtn);
      top.add(applyBtn);
      this.add(top, "North");
      JTable table = new JTable(this.tableModel);
      table.setFillsViewportHeight(true);
      table.setRowHeight(24);
      JScrollPane scroll = new JScrollPane(table);
      this.add(scroll, "Center");
      loadBtn.addActionListener(e -> {
         if (this.importer == null) {
            JOptionPane.showMessageDialog(this, "Importer not initialized", "Error", 0);
         } else {
            JFileChooser chooser = new JFileChooser();
            chooser.setFileSelectionMode(0);
            chooser.setFileFilter(new FileNameExtensionFilter("Postman/Bruno environment (json, bru, yml, env)", "json", "bru", "yml", "yaml", "env"));
            if (chooser.showOpenDialog(this) == 0) {
               File f = chooser.getSelectedFile();

               try {
                  Map<String, String> loaded = this.importer.importEnvironmentFile(f);
                  if (loaded != null && !loaded.isEmpty()) {
                     this.currentEnvFile = f;
                     this.loadVariablesIntoTable(loaded);
                     saveBtn.setEnabled(true);
                  } else {
                     JOptionPane.showMessageDialog(this, "No variables found in selected environment.");
                     this.currentEnvFile = f;
                     saveBtn.setEnabled(true);
                  }
               } catch (Exception var6x) {
                  JOptionPane.showMessageDialog(this, "Failed to load environment: " + var6x.getMessage(), "Error", 0);
               }
            }
         }
      });
      refreshBtn.addActionListener(e -> {
         if (this.importer == null) {
            JOptionPane.showMessageDialog(this, "Importer not initialized", "Error", 0);
         } else {
            Map<String, String> current = this.importer.getCurrentVariablesSnapshot();
            this.loadVariablesIntoTable(current);
            JOptionPane.showMessageDialog(this, "Refreshed " + current.size() + " variables from importer.");
         }
      });
      saveBtn.addActionListener(
         e -> {
            try {
               Map<String, String> vars = this.collectTableVariables();
               List<String> invalid = this.validateKeys(vars);
               if (!invalid.isEmpty()) {
                  String msg = "Invalid variable names found:\n"
                     + String.join("\n", invalid)
                     + "\n\nOnly alphanumeric, underscore(_), dot(.) and hyphen(-) are allowed. Fix them before saving.";
                  JOptionPane.showMessageDialog(this, msg, "Validation Error", 0);
                  return;
               }

               File target = this.currentEnvFile;
               if (target == null) {
                  JFileChooser chooser = new JFileChooser();
                  chooser.setDialogTitle("Save environment as...");
                  chooser.setSelectedFile(new File("environment.json"));
                  if (chooser.showSaveDialog(this) != 0) {
                     return;
                  }

                  target = chooser.getSelectedFile();
               }

               if (!target.getName().toLowerCase().endsWith(".json")) {
                  target = new File(target.getAbsolutePath() + ".json");
               }

               boolean ok = this.importer.saveEnvironmentFile(target, vars);
               if (ok) {
                  JOptionPane.showMessageDialog(this, "Environment saved to: " + target.getAbsolutePath());
                  this.currentEnvFile = target;
                  saveBtn.setEnabled(true);
               } else {
                  JOptionPane.showMessageDialog(this, "Failed to save environment.", "Error", 0);
               }
            } catch (Exception var7x) {
               JOptionPane.showMessageDialog(this, "Failed to save environment: " + var7x.getMessage(), "Error", 0);
            }
         }
      );
      validateBtn.addActionListener(
         e -> {
            Map<String, String> vars = this.collectTableVariables();
            List<String> invalid = this.validateKeys(vars);
            if (invalid.isEmpty()) {
               JOptionPane.showMessageDialog(this, "All variable names are valid.");
            } else {
               String msg = "Invalid variable names found:\n"
                  + String.join("\n", invalid)
                  + "\n\nOnly alphanumeric, underscore(_), dot(.) and hyphen(-) are allowed.";
               JOptionPane.showMessageDialog(this, msg, "Validation Results", 2);
            }
         }
      );
      applyBtn.addActionListener(e -> {
         if (this.importer == null) {
            JOptionPane.showMessageDialog(this, "Importer not initialized", "Error", 0);
         } else {
            Map<String, String> vars = this.collectTableVariables();
            this.importer.addCustomVariables(vars);
            JOptionPane.showMessageDialog(this, "Environment variables applied.");
         }
      });
   }

   private Map<String, String> collectTableVariables() {
      Map<String, String> map = new LinkedHashMap<>();

      for (int i = 0; i < this.tableModel.getRowCount(); i++) {
         Object k = this.tableModel.getValueAt(i, 0);
         Object v = this.tableModel.getValueAt(i, 1);
         if (k != null) {
            String key = k.toString().trim();
            String value = v != null ? v.toString() : "";
            if (!key.isEmpty()) {
               map.put(key, value);
            }
         }
      }

      return map;
   }

   private List<String> validateKeys(Map<String, String> vars) {
      List<String> invalid = new ArrayList<>();
      if (vars == null) {
         return invalid;
      } else {
         for (String key : vars.keySet()) {
            if (key != null && !key.trim().isEmpty()) {
               Matcher m = KEY_PATTERN.matcher(key);
               if (!m.matches()) {
                  invalid.add(key);
               }
            } else {
               invalid.add("(empty key)");
            }
         }

         return invalid;
      }
   }

   private void loadVariablesIntoTable(Map<String, String> vars) {
      this.tableModel.setRowCount(0);
      if (vars != null) {
         for (Entry<String, String> e : vars.entrySet()) {
            this.tableModel.addRow(new Object[]{e.getKey(), e.getValue()});
         }
      }
   }

   public void showDialog() {
      this.showDialog(null);
   }

   public void showDialog(Component parent) {
      Window owner = parent != null ? SwingUtilities.getWindowAncestor(parent) : null;
      JDialog dialog;
      if (owner instanceof Frame) {
         dialog = new JDialog((Frame)owner, "Environment Editor", true);
      } else if (owner instanceof Dialog) {
         dialog = new JDialog((Dialog)owner, "Environment Editor", true);
      } else {
         dialog = new JDialog((Frame)null, "Environment Editor", true);
      }

      dialog.setContentPane(this);
      dialog.setSize(600, 400);
      dialog.setLocationRelativeTo(parent);
      dialog.setVisible(true);
   }
}
