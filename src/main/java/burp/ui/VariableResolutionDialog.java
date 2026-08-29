package burp.ui;

import burp.models.VariableAnalysis;
import burp.utils.VariableDetector;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.Dialog.ModalityType;
import java.io.File;
import java.util.HashMap;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;

public class VariableResolutionDialog extends JDialog {
   private final VariableAnalysis analysis;
   private final VariableDetector detector;
   private final Component parent;
   private VariableResolutionDialog.ResolutionChoice choice = VariableResolutionDialog.ResolutionChoice.CANCEL;
   private File selectedEnvironmentFile;
   private Map<String, String> manualVariables = new HashMap<>();

   public VariableResolutionDialog(Component parent, VariableAnalysis analysis, VariableDetector detector) {
      super(SwingUtilities.getWindowAncestor(parent), "Unresolved Variables Detected", ModalityType.APPLICATION_MODAL);
      this.parent = parent;
      this.analysis = analysis;
      this.detector = detector;
      this.initializeUI();
      this.setLocationRelativeTo(parent);
   }

   private void initializeUI() {
      this.setLayout(new BorderLayout(10, 10));
      this.setSize(600, 500);
      JPanel headerPanel = this.createHeaderPanel();
      this.add(headerPanel, "North");
      JPanel analysisPanel = this.createAnalysisPanel();
      this.add(analysisPanel, "Center");
      JPanel optionsPanel = this.createOptionsPanel();
      this.add(optionsPanel, "South");
   }

   private JPanel createHeaderPanel() {
      JPanel panel = new JPanel(new BorderLayout());
      panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 10, 15));
      JPanel titlePanel = new JPanel(new FlowLayout(0));
      JLabel iconLabel = new JLabel("⚠️");
      iconLabel.setFont(iconLabel.getFont().deriveFont(24.0F));
      JLabel titleLabel = new JLabel("Unresolved Variables Detected");
      titleLabel.setFont(titleLabel.getFont().deriveFont(1, 16.0F));
      titlePanel.add(iconLabel);
      titlePanel.add(Box.createHorizontalStrut(10));
      titlePanel.add(titleLabel);
      panel.add(titlePanel, "West");
      JLabel impactLabel = new JLabel(this.analysis.getImpactDescription());
      impactLabel.setForeground(this.getImpactColor());
      panel.add(impactLabel, "East");
      return panel;
   }

   private Color getImpactColor() {
      switch (this.analysis.getImpact()) {
         case LOW:
            return new Color(255, 140, 0);
         case MEDIUM:
            return new Color(255, 69, 0);
         case HIGH:
            return Color.RED;
         default:
            return Color.GRAY;
      }
   }

   private JPanel createAnalysisPanel() {
      JPanel panel = new JPanel(new BorderLayout());
      panel.setBorder(BorderFactory.createEmptyBorder(0, 15, 0, 15));
      JLabel descLabel = new JLabel("Your Postman collection contains variables that need to be resolved. Choose how you'd like to handle them:");
      descLabel.setFont(descLabel.getFont().deriveFont(12.0F));
      panel.add(descLabel, "North");
      JPanel variablesPanel = new JPanel(new BorderLayout());
      variablesPanel.setBorder(BorderFactory.createTitledBorder("Unresolved Variables"));
      DefaultListModel<String> listModel = new DefaultListModel<>();
      Map<String, String> suggestions = this.detector.generateVariableSuggestions(this.analysis.getUnresolvedVariables());

      for (String variable : this.analysis.getUnresolvedVariables()) {
         String suggestion = suggestions.get(variable);
         String display = suggestion != null ? "{{" + variable + "}} → suggested: " + suggestion : "{{" + variable + "}}";
         listModel.addElement(display);
      }

      JList<String> variablesList = new JList<>(listModel);
      variablesList.setSelectionMode(0);
      variablesList.setVisibleRowCount(6);
      JScrollPane scrollPane = new JScrollPane(variablesList);
      variablesPanel.add(scrollPane, "Center");
      panel.add(variablesPanel, "Center");
      return panel;
   }

   private JPanel createOptionsPanel() {
      JPanel panel = new JPanel(new BorderLayout());
      panel.setBorder(BorderFactory.createEmptyBorder(10, 15, 15, 15));
      JPanel optionsGrid = new JPanel(new GridLayout(2, 2, 10, 10));
      JButton uploadBtn = this.createOptionButton(
         "\ud83d\udcc1 Upload Environment File",
         "Browse for your Postman environment file (.json)",
         "Recommended for production use",
         () -> this.handleUploadEnvironment()
      );
      JButton manualBtn = this.createOptionButton(
         "✏️ Set Variables Manually", "Enter variable values manually", "Perfect for quick testing or demo", () -> this.handleManualEntry()
      );
      JButton ignoreBtn = this.createOptionButton(
         "⚠️ Ignore and Continue", "Continue with unresolved variables", "Requests will likely fail", () -> this.handleIgnoreAndContinue()
      );
      JButton skipBtn = this.createOptionButton(
         "\ud83c\udfaf Skip Variable Requests",
         "Import only requests without variables",
         "Import " + (this.analysis.getTotalRequests() - this.analysis.getRequestsWithVariables()) + " variable-free requests",
         () -> this.handleSkipVariableRequests()
      );
      optionsGrid.add(uploadBtn);
      optionsGrid.add(manualBtn);
      optionsGrid.add(ignoreBtn);
      optionsGrid.add(skipBtn);
      panel.add(optionsGrid, "Center");
      JPanel cancelPanel = new JPanel(new FlowLayout(2));
      JButton cancelBtn = new JButton("Cancel");
      cancelBtn.addActionListener(e -> {
         this.choice = VariableResolutionDialog.ResolutionChoice.CANCEL;
         this.dispose();
      });
      cancelPanel.add(cancelBtn);
      panel.add(cancelPanel, "South");
      return panel;
   }

   private JButton createOptionButton(String title, String description, String detail, Runnable action) {
      JButton button = new JButton();
      button.setLayout(new BorderLayout());
      button.setPreferredSize(new Dimension(250, 80));
      JLabel titleLabel = new JLabel(title);
      titleLabel.setFont(titleLabel.getFont().deriveFont(1, 12.0F));
      JLabel descLabel = new JLabel(description);
      descLabel.setFont(descLabel.getFont().deriveFont(10.0F));
      JLabel detailLabel = new JLabel(detail);
      detailLabel.setFont(detailLabel.getFont().deriveFont(2, 9.0F));
      detailLabel.setForeground(Color.GRAY);
      JPanel contentPanel = new JPanel(new BorderLayout(5, 2));
      contentPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
      contentPanel.add(titleLabel, "North");
      contentPanel.add(descLabel, "Center");
      contentPanel.add(detailLabel, "South");
      button.add(contentPanel, "Center");
      button.addActionListener(e -> action.run());
      return button;
   }

   private void handleUploadEnvironment() {
      JFileChooser chooser = new JFileChooser();
      chooser.setFileFilter(new FileNameExtensionFilter("Auto-detect: Postman JSON, Bruno .bru/.json/.yml/.env environment", "json", "bru", "yml", "yaml", "env"));
      chooser.setAcceptAllFileFilterUsed(true);
      chooser.setDialogTitle("Select Environment File");
      if (chooser.showOpenDialog(this) == 0) {
         this.selectedEnvironmentFile = chooser.getSelectedFile();
         this.choice = VariableResolutionDialog.ResolutionChoice.UPLOAD_ENVIRONMENT;
         this.dispose();
      }
   }

   private void handleManualEntry() {
      ManualVariableEntryDialog entryDialog = new ManualVariableEntryDialog(this, this.analysis.getUnresolvedVariables(), this.detector);
      if (entryDialog.showDialog()) {
         this.manualVariables = entryDialog.getVariables();
         this.choice = VariableResolutionDialog.ResolutionChoice.MANUAL_ENTRY;
         this.dispose();
      }
   }

   private void handleIgnoreAndContinue() {
      int result = JOptionPane.showConfirmDialog(
         this,
         "⚠️ Warning: Continuing with unresolved variables will likely cause import failures.\n\nURLs like 'https://{{api_base_url}}/users' will remain unresolved.\nAre you sure you want to continue?",
         "Confirm: Ignore Variables",
         0,
         2
      );
      if (result == 0) {
         this.choice = VariableResolutionDialog.ResolutionChoice.IGNORE_CONTINUE;
         this.dispose();
      }
   }

   private void handleSkipVariableRequests() {
      int variableFreeRequests = this.analysis.getTotalRequests() - this.analysis.getRequestsWithVariables();
      int result = JOptionPane.showConfirmDialog(
         this,
         "This will import only requests without unresolved variables.\n\nRequests to import: "
            + variableFreeRequests
            + "/"
            + this.analysis.getTotalRequests()
            + "\nRequests to skip: "
            + this.analysis.getRequestsWithVariables()
            + "\n\nContinue with selective import?",
         "Confirm: Skip Variable Requests",
         0,
         3
      );
      if (result == 0) {
         this.choice = VariableResolutionDialog.ResolutionChoice.SKIP_VARIABLE_REQUESTS;
         this.dispose();
      }
   }

   public boolean showDialog() {
      this.setVisible(true);
      return this.choice != VariableResolutionDialog.ResolutionChoice.CANCEL;
   }

   public VariableResolutionDialog.ResolutionChoice getChoice() {
      return this.choice;
   }

   public File getSelectedEnvironmentFile() {
      return this.selectedEnvironmentFile;
   }

   public Map<String, String> getManualVariables() {
      return this.manualVariables;
   }

   public static enum ResolutionChoice {
      UPLOAD_ENVIRONMENT,
      MANUAL_ENTRY,
      IGNORE_CONTINUE,
      SKIP_VARIABLE_REQUESTS,
      CANCEL;
   }
}
