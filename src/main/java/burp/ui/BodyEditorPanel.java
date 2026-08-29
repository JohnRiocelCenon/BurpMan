package burp.ui;

import burp.parser.VariableResolver;
import burp.utils.FormatUtils;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.awt.Point;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionAdapter;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.BorderFactory;
import javax.swing.DefaultCellEditor;
import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.ToolTipManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.JTextComponent;
import javax.swing.text.DefaultHighlighter.DefaultHighlightPainter;
import javax.swing.text.Highlighter.HighlightPainter;
import javax.swing.table.DefaultTableModel;

public class BodyEditorPanel extends JPanel {
   public static final String MODE_RAW = "raw";
   public static final String MODE_JSON = "JSON";
   public static final String MODE_XML = "XML";
   public static final String MODE_FORM_DATA = "form-data";
   public static final String MODE_URLENC = "x-www-form-urlencoded";
   public static final String MODE_GRAPHQL = "GraphQL";
   private final JComboBox<String> modeCombo;
   private final JTextArea bodyTextArea;
   private final JTextArea gqlQueryArea;
   private final JTextArea gqlVarsArea;
   private final DefaultTableModel formDataModel;
   private final JTable formDataTable;
   private final JButton formatButton;
   private final JLabel sizeLabel;
   private final CardLayout cards;
   private final JPanel cardHost;
   private static final String CARD_TEXT = "TEXT";
   private static final String CARD_GQL = "GQL";
   private static final String CARD_FORM = "FORM";
   private static final String FORM_TYPE_TEXT = "text";
   private static final String FORM_TYPE_FILE = "file";
   private static final int FORM_COL_ENABLED = 0;
   private static final int FORM_COL_KEY = 1;
   private static final int FORM_COL_TYPE = 2;
   private static final int FORM_COL_VALUE = 3;
   private String currentMode = "raw";
   private VariableResolver variableResolver;
   private static final Pattern EDITABLE_VAR_PATTERN = Pattern.compile("\\{\\{(?!\\$)([^{}]+)\\}\\}");
   private static final class VarSpan {
      final int start;
      final int end;
      final String name;
      final boolean resolved;

      VarSpan(int start, int end, String name, boolean resolved) {
         this.start = start;
         this.end = end;
         this.name = name;
         this.resolved = resolved;
      }
   }
   private final Map<JTextComponent, List<Object>> variableHighlightTags = new HashMap<>();
   private final Map<JTextComponent, List<VarSpan>> variableSpans = new HashMap<>();
   private final HighlightPainter resolvedVarPainter = new DefaultHighlightPainter(new Color(223, 245, 227));
   private final HighlightPainter unresolvedVarPainter = new DefaultHighlightPainter(new Color(249, 224, 224));
   private final List<Runnable> changeListeners = new CopyOnWriteArrayList<>();

   public void addChangeListener(Runnable r) {
      if (r != null) {
         this.changeListeners.add(r);
      }
   }

   public void removeChangeListener(Runnable r) {
      if (r != null) {
         this.changeListeners.remove(r);
      }
   }

   private void fireChange() {
      for (Runnable r : this.changeListeners) {
         try {
            r.run();
         } catch (Throwable var4) {
         }
      }
   }

   public void setVariableResolver(VariableResolver resolver) {
      this.variableResolver = resolver;
      this.scheduleVariableHighlightRefresh();
   }

   public void refreshFromVariables() {
      this.scheduleVariableHighlightRefresh();
   }

   public BodyEditorPanel() {
      this.setLayout(new BorderLayout(5, 5));
      this.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
      JPanel topPanel = new JPanel(new FlowLayout(0, 5, 5));
      topPanel.add(new JLabel("Body Type:"));
      this.modeCombo = new JComboBox<>(new String[]{"raw", "JSON", "XML", "form-data", "x-www-form-urlencoded", "GraphQL"});
      this.modeCombo.addActionListener(e -> {
         String sel = (String)this.modeCombo.getSelectedItem();
         if (sel != null) {
            this.applyMode(sel);
         }
      });
      topPanel.add(this.modeCombo);
      this.formatButton = new JButton("Format");
      this.formatButton.addActionListener(e -> this.handleFormat());
      topPanel.add(this.formatButton);
      this.sizeLabel = new JLabel("Size: 0 B");
      topPanel.add(this.sizeLabel);
      this.add(topPanel, "North");
      this.bodyTextArea = new JTextArea(18, 120);
      this.bodyTextArea.setFont(new Font("Monospaced", 0, 12));
      this.bodyTextArea.setTabSize(2);
      this.bodyTextArea.setLineWrap(false);
      this.bodyTextArea.setEditable(true);
      UndoSupport.install(this.bodyTextArea);
      this.installVariableInteractivity(this.bodyTextArea);
      DocumentListener sizeL = new DocumentListener() {
         @Override
         public void insertUpdate(DocumentEvent e) {
            this.onEdit();
         }

         @Override
         public void removeUpdate(DocumentEvent e) {
            this.onEdit();
         }

         @Override
         public void changedUpdate(DocumentEvent e) {
            this.onEdit();
         }

         private void onEdit() {
            BodyEditorPanel.this.updateSize();
            BodyEditorPanel.this.scheduleVariableHighlightRefresh();
            BodyEditorPanel.this.fireChange();
         }
      };
      this.bodyTextArea.getDocument().addDocumentListener(sizeL);
      this.gqlQueryArea = new JTextArea(12, 120);
      this.gqlQueryArea.setFont(new Font("Courier New", 0, 11));
      this.gqlQueryArea.setTabSize(2);
      UndoSupport.install(this.gqlQueryArea);
      this.installVariableInteractivity(this.gqlQueryArea);
      this.gqlQueryArea.getDocument().addDocumentListener(sizeL);
      this.gqlVarsArea = new JTextArea(8, 120);
      this.gqlVarsArea.setFont(new Font("Courier New", 0, 11));
      this.gqlVarsArea.setTabSize(2);
      UndoSupport.install(this.gqlVarsArea);
      this.installVariableInteractivity(this.gqlVarsArea);
      this.gqlVarsArea.getDocument().addDocumentListener(sizeL);
      JPanel gqlPanel = new JPanel(new BorderLayout(0, 4));
      JPanel queryHeader = new JPanel(new FlowLayout(0, 4, 0));
      queryHeader.add(new JLabel("Query"));
      JPanel varsHeader = new JPanel(new FlowLayout(0, 4, 0));
      varsHeader.add(new JLabel("Variables (JSON)"));
      JPanel queryWrap = new JPanel(new BorderLayout());
      queryWrap.add(queryHeader, "North");
      queryWrap.add(createPayloadScroll(this.gqlQueryArea), "Center");
      JPanel varsWrap = new JPanel(new BorderLayout());
      varsWrap.add(varsHeader, "North");
      varsWrap.add(createPayloadScroll(this.gqlVarsArea), "Center");
      JSplitPane gqlSplit = new JSplitPane(0, queryWrap, varsWrap);
      gqlSplit.setResizeWeight(0.65);
      gqlSplit.setDividerLocation(180);
      gqlPanel.add(gqlSplit, "Center");
      this.formDataModel = new DefaultTableModel(new Object[]{"Use", "Key", "Type", "Value / File Path"}, 0) {
         @Override
         public boolean isCellEditable(int row, int column) {
            return true;
         }

         @Override
         public Class<?> getColumnClass(int columnIndex) {
            return columnIndex == FORM_COL_ENABLED ? Boolean.class : String.class;
         }
      };
      this.formDataTable = new JTable(this.formDataModel);
      this.formDataTable.setRowHeight(22);
      this.formDataTable.getColumnModel().getColumn(FORM_COL_ENABLED).setMaxWidth(58);
      this.formDataTable.getColumnModel().getColumn(FORM_COL_TYPE).setCellEditor(new DefaultCellEditor(
         new JComboBox<>(new String[]{FORM_TYPE_TEXT, FORM_TYPE_FILE})
      ));
      this.formDataModel.addTableModelListener(e -> {
         BodyEditorPanel.this.updateSize();
         BodyEditorPanel.this.fireChange();
      });

      JPanel formToolbar = new JPanel(new FlowLayout(0, 4, 2));
      JButton addRow = new JButton("+ Row");
      JButton removeRow = new JButton("- Row");
      JButton browseFile = new JButton("Browse File...");
      JButton clearRows = new JButton("Clear");
      addRow.addActionListener(e -> {
         this.formDataModel.addRow(new Object[]{Boolean.TRUE, "", FORM_TYPE_TEXT, ""});
         int idx = this.formDataModel.getRowCount() - 1;
         if (idx >= 0) {
            this.formDataTable.getSelectionModel().setSelectionInterval(idx, idx);
         }
      });
      removeRow.addActionListener(e -> {
         int row = this.formDataTable.getSelectedRow();
         if (row >= 0) {
            this.formDataModel.removeRow(row);
         }
      });
      browseFile.addActionListener(e -> this.chooseFileForSelectedFormRow());
      clearRows.addActionListener(e -> this.formDataModel.setRowCount(0));
      formToolbar.add(addRow);
      formToolbar.add(removeRow);
      formToolbar.add(browseFile);
      formToolbar.add(clearRows);
      JLabel formHint = new JLabel("Use Type=file to upload. Browse fills the file path.");
      formHint.setForeground(new Color(110, 110, 110));
      JPanel formNorth = new JPanel(new BorderLayout(0, 3));
      formNorth.add(formToolbar, "North");
      formNorth.add(formHint, "South");
      JPanel formPanel = new JPanel(new BorderLayout(0, 4));
      formPanel.add(formNorth, "North");
      formPanel.add(createPayloadScroll(this.formDataTable), "Center");

      this.cards = new CardLayout();
      this.cardHost = new JPanel(this.cards);
      this.cardHost.add(createPayloadScroll(this.bodyTextArea), "TEXT");
      this.cardHost.add(gqlPanel, "GQL");
      this.cardHost.add(formPanel, "FORM");
      this.cards.show(this.cardHost, "TEXT");
      this.add(this.cardHost, "Center");
      this.scheduleVariableHighlightRefresh();
   }

   private static JScrollPane createPayloadScroll(java.awt.Component view) {
      JScrollPane sp = new JScrollPane(view, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
      sp.setPreferredSize(new Dimension(560, 220));
      sp.setMinimumSize(new Dimension(180, 120));
      sp.getVerticalScrollBar().setUnitIncrement(16);
      sp.getHorizontalScrollBar().setUnitIncrement(16);
      return sp;
   }

   private void applyMode(String mode) {
      this.currentMode = mode;
      if ("GraphQL".equalsIgnoreCase(mode)) {
         this.cards.show(this.cardHost, "GQL");
      } else if (MODE_FORM_DATA.equalsIgnoreCase(mode)) {
         this.cards.show(this.cardHost, CARD_FORM);
      } else {
         this.cards.show(this.cardHost, "TEXT");
      }

      this.updateSize();
   }

   private void updateSize() {
      String text;
      if ("GraphQL".equalsIgnoreCase(this.currentMode)) {
         text = this.buildGraphQLBody();
      } else if (MODE_FORM_DATA.equalsIgnoreCase(this.currentMode)) {
         text = this.serializeFormDataRows();
      } else {
         text = this.bodyTextArea.getText();
      }

      long bytes = text == null ? 0 : text.getBytes().length;
      this.sizeLabel.setText("Size: " + FormatUtils.formatBytes(bytes));
   }

   private void scheduleVariableHighlightRefresh() {
      SwingUtilities.invokeLater(() -> {
         this.refreshVariableHighlights(this.bodyTextArea);
         this.refreshVariableHighlights(this.gqlQueryArea);
         this.refreshVariableHighlights(this.gqlVarsArea);
      });
   }

   private void refreshVariableHighlights(JTextComponent area) {
      if (area != null) {
         List<Object> old = this.variableHighlightTags.remove(area);
         this.variableSpans.remove(area);
         if (old != null) {
            for (Object tag : old) {
               try {
                  area.getHighlighter().removeHighlight(tag);
               } catch (Exception var10) {
               }
            }
         }

         String text = area.getText();
         if (text != null && !text.isEmpty()) {
            Matcher m = EDITABLE_VAR_PATTERN.matcher(text);
            List<Object> tags = new ArrayList<>();
            List<VarSpan> spans = new ArrayList<>();

            while (m.find()) {
               String key = m.group(1) == null ? "" : m.group(1).trim();
               boolean resolved = this.isVariableResolved(key);
               spans.add(new VarSpan(m.start(), m.end(), key, resolved));

               try {
                  Object tag = area.getHighlighter().addHighlight(m.start(), m.end(), resolved ? this.resolvedVarPainter : this.unresolvedVarPainter);
                  tags.add(tag);
               } catch (BadLocationException var9) {
               }
            }

            if (!tags.isEmpty()) {
               this.variableHighlightTags.put(area, tags);
            }
           if (!spans.isEmpty()) {
              this.variableSpans.put(area, spans);
           }
         }
      }
   }

   private void installVariableInteractivity(JTextComponent area) {
     if (area == null) return;
     ToolTipManager.sharedInstance().registerComponent(area);
     area.addMouseMotionListener(new MouseMotionAdapter() {
        @Override
        public void mouseMoved(MouseEvent e) {
           String tip = variableTooltipAt(area, e.getPoint());
           if (!Objects.equals(tip, area.getToolTipText())) {
              area.setToolTipText(tip);
           }
           String varName = variableNameAt(area, e.getPoint());
           area.setCursor(varName == null
              ? Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR)
              : Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        }
     });
     area.addMouseListener(new MouseAdapter() {
        @Override
        public void mouseClicked(MouseEvent e) {
           if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
              String varName = variableNameAt(area, e.getPoint());
              if (varName != null && !varName.isEmpty()) {
                 e.consume();
                 showVariableEditor(varName, area, e.getPoint());
              }
           }
        }
     });
   }

   private String variableNameAt(JTextComponent area, Point point) {
     if (area == null || point == null) return null;
     int pos = area.viewToModel(point);
     if (pos < 0) return null;

     List<VarSpan> spans = this.variableSpans.get(area);
     if (spans != null) {
        for (VarSpan span : spans) {
           if (pos >= span.start && pos < span.end) {
              return span.name;
           }
        }
     }
     return null;
   }

   private String variableTooltipAt(JTextComponent area, Point point) {
     if (area == null || point == null) return null;
     int pos = area.viewToModel(point);
     if (pos < 0) return null;
     List<VarSpan> spans = this.variableSpans.get(area);
     if (spans == null) return null;
     for (VarSpan span : spans) {
        if (pos >= span.start && pos < span.end) {
           String key = span.name == null ? "" : span.name.trim();
           if (key.isEmpty()) return null;
           if (this.variableResolver == null) {
              return "{{" + key + "}}";
           }
           try {
              String value = this.variableResolver.getVariables().get(key);
              if (value == null) return "{{" + key + "}}  —  not defined";
              String shown = value.length() > 96 ? value.substring(0, 96) + "…" : value;
              return "{{" + key + "}}  =  " + shown;
           } catch (Throwable ignore) {
              return "{{" + key + "}}";
           }
        }
     }
     return null;
   }

   private void showVariableEditor(String varName, JTextComponent anchor, Point clickAt) {
     if (this.variableResolver == null || varName == null || varName.trim().isEmpty()) return;
     String current = "";
     try {
        String got = this.variableResolver.getVariables().get(varName);
        current = got == null ? "" : got;
     } catch (Throwable ignore) {
     }

     Window owner = SwingUtilities.getWindowAncestor(this);
     final JDialog dlg;
     if (owner instanceof Frame) {
        dlg = new JDialog((Frame) owner, false);
     } else if (owner instanceof Dialog) {
        dlg = new JDialog((Dialog) owner, false);
     } else {
        dlg = new JDialog((Frame) null, false);
     }

     dlg.setUndecorated(true);
     dlg.setFocusableWindowState(true);
     JPanel content = new JPanel(new BorderLayout(6, 6));
     content.setBorder(BorderFactory.createCompoundBorder(
        BorderFactory.createLineBorder(new Color(153, 153, 153)),
        BorderFactory.createEmptyBorder(8, 10, 8, 10)));
     content.setBackground(new Color(250, 250, 250));

     JLabel header = new JLabel("Edit {{" + varName + "}}");
     header.setFont(header.getFont().deriveFont(Font.BOLD, 12f));
     content.add(header, BorderLayout.NORTH);

     JTextField valueField = new JTextField(current, 40);
     valueField.setFont(new Font("Courier New", Font.PLAIN, 12));
     content.add(valueField, BorderLayout.CENTER);

     JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
     buttons.setOpaque(false);
     JButton cancelBtn = new JButton("Cancel");
     JButton saveBtn = new JButton("Save");
     buttons.add(cancelBtn);
     buttons.add(saveBtn);
     content.add(buttons, BorderLayout.SOUTH);
     dlg.setContentPane(content);
     dlg.pack();

     Point anchorScreen = anchor.getLocationOnScreen();
     dlg.setLocation(anchorScreen.x + clickAt.x, anchorScreen.y + clickAt.y + 18);

     Runnable dismiss = dlg::dispose;
     cancelBtn.addActionListener(e -> dismiss.run());
     Runnable commit = () -> {
        try {
           this.variableResolver.updateVariableEverywhere(varName, valueField.getText());
        } catch (Throwable ignore) {
        }
        dismiss.run();
        this.scheduleVariableHighlightRefresh();
        this.fireChange();
        this.firePropertyChange("varEdited", null, varName);
     };
     saveBtn.addActionListener(e -> commit.run());
     valueField.addActionListener(e -> commit.run());
     valueField.getInputMap().put(KeyStroke.getKeyStroke("ESCAPE"), "cancel-edit");
     valueField.getActionMap().put("cancel-edit", new AbstractAction() {
        @Override
        public void actionPerformed(ActionEvent e) {
           dismiss.run();
        }
     });
     dlg.addWindowFocusListener(new WindowAdapter() {
        @Override
        public void windowLostFocus(WindowEvent e) {
           Timer t = new Timer(120, ev -> {
              if (!dlg.isFocused()) dlg.dispose();
           });
           t.setRepeats(false);
           t.start();
        }
     });
     dlg.setVisible(true);
     SwingUtilities.invokeLater(() -> {
        valueField.requestFocusInWindow();
        valueField.selectAll();
     });
   }

   private boolean isVariableResolved(String key) {
      if (this.variableResolver != null && key != null && !key.isEmpty()) {
         String token = "{{" + key + "}}";

         try {
            String resolved = this.variableResolver.resolve(token);
            return resolved != null && !resolved.isEmpty() && !token.equals(resolved);
         } catch (Exception var4) {
            return false;
         }
      } else {
         return false;
      }
   }

   private void handleFormat() {
      if ("GraphQL".equalsIgnoreCase(this.currentMode)) {
         String vars = this.gqlVarsArea.getText();
         if (vars != null && !vars.trim().isEmpty()) {
            this.gqlVarsArea.setText(FormatUtils.prettyPrintJson(vars));
         }
      } else if (MODE_FORM_DATA.equalsIgnoreCase(this.currentMode)) {
         // Form-data is row-based UI; no text formatting needed.
      } else {
         String content = this.bodyTextArea.getText();
         if (!content.isEmpty()) {
            String formatted;
            if ("JSON".equalsIgnoreCase(this.currentMode)) {
               formatted = FormatUtils.prettyPrintJson(stripJsonComments(content));
            } else if ("XML".equalsIgnoreCase(this.currentMode)) {
               formatted = FormatUtils.prettyPrintXml(content);
            } else if (looksLikeJson(content)) {
               formatted = FormatUtils.prettyPrintJson(stripJsonComments(content));
            } else {
               formatted = FormatUtils.autoFormat(content, this.currentMode);
            }

            this.bodyTextArea.setText(formatted);
         }
      }
   }

   private String buildGraphQLBody() {
      String query = this.gqlQueryArea.getText();
      String vars = this.gqlVarsArea.getText();
      if (query != null && !query.isEmpty() || vars != null && !vars.trim().isEmpty()) {
         StringBuilder sb = new StringBuilder();
         sb.append("{\"query\":");
         sb.append(jsonEscape(query == null ? "" : query));
         if (vars != null && !vars.trim().isEmpty()) {
            sb.append(",\"variables\":");
            String t = vars.trim();
            boolean looksJson = t.startsWith("{") && t.endsWith("}") || t.startsWith("[") && t.endsWith("]");
            if (looksJson) {
               sb.append(t);
            } else {
               sb.append(jsonEscape(vars));
            }
         }

         sb.append("}");
         return sb.toString();
      } else {
         return "";
      }
   }

   private static String jsonEscape(String s) {
      StringBuilder b = new StringBuilder(s.length() + 8);
      b.append('"');

      for (int i = 0; i < s.length(); i++) {
         char c = s.charAt(i);
         switch (c) {
            case '\t':
               b.append("\\t");
               break;
            case '\n':
               b.append("\\n");
               break;
            case '\r':
               b.append("\\r");
               break;
            case '"':
               b.append("\\\"");
               break;
            case '\\':
               b.append("\\\\");
               break;
            default:
               if (c < ' ') {
                  b.append(String.format("\\u%04x", Integer.valueOf(c)));
               } else {
                  b.append(c);
               }
         }
      }

      b.append('"');
      return b.toString();
   }

   public String getBody() {
      if ("GraphQL".equalsIgnoreCase(this.currentMode)) {
         String s = this.buildGraphQLBody();
         return s.isEmpty() ? null : s;
      } else if (MODE_FORM_DATA.equalsIgnoreCase(this.currentMode)) {
         String text = this.serializeFormDataRows();
         return text.isEmpty() ? null : text;
      } else {
         String text = this.bodyTextArea.getText();
         if (text.isEmpty()) {
            return null;
         } else {
            if ("JSON".equalsIgnoreCase(this.currentMode) || looksLikeJson(text)) {
               text = stripJsonComments(text);
            }

            return text;
         }
      }
   }

   private static boolean looksLikeJson(String s) {
      if (s == null) {
         return false;
      } else {
         String t = s.trim();
         if (t.length() < 2) {
            return false;
         } else {
            char first = t.charAt(0);
            char last = t.charAt(t.length() - 1);
            return first == '{' && last == '}' || first == '[' && last == ']';
         }
      }
   }

   static String stripJsonComments(String src) {
      if (src != null && !src.isEmpty()) {
         StringBuilder out = new StringBuilder(src.length());
         int i = 0;
         int n = src.length();
         boolean inString = false;
         char stringQuote = 0;

         while (i < n) {
            char c = src.charAt(i);
            if (inString) {
               out.append(c);
               if (c == '\\' && i + 1 < n) {
                  out.append(src.charAt(i + 1));
                  i += 2;
               } else {
                  if (c == stringQuote) {
                     inString = false;
                  }

                  i++;
               }
            } else if (c != '"' && c != '\'') {
               if (c == '/' && i + 1 < n) {
                  char d = src.charAt(i + 1);
                  if (d == '/') {
                     int j = i + 2;

                     while (j < n && src.charAt(j) != '\n' && src.charAt(j) != '\r') {
                        j++;
                     }

                     i = j;
                     continue;
                  }

                  if (d == '*') {
                     int j = i + 2;

                     while (j + 1 < n && (src.charAt(j) != '*' || src.charAt(j + 1) != '/')) {
                        j++;
                     }

                     i = Math.min(n, j + 2);
                     continue;
                  }
               }

               out.append(c);
               i++;
            } else {
               inString = true;
               stringQuote = c;
               out.append(c);
               i++;
            }
         }

         return out.toString();
      } else {
         return src;
      }
   }

   public void setBody(String body) {
      if (MODE_FORM_DATA.equalsIgnoreCase(this.currentMode)) {
         this.loadFormDataRows(body);
      } else {
         UndoSupport.setTextWithoutUndo(this.bodyTextArea, body != null ? body : "");
      }
      this.scheduleVariableHighlightRefresh();
      this.updateSize();
   }

   public void setGraphQL(String query, String variables) {
      UndoSupport.setTextWithoutUndo(this.gqlQueryArea, query != null ? query : "");
      UndoSupport.setTextWithoutUndo(this.gqlVarsArea, variables != null ? variables : "");
      this.scheduleVariableHighlightRefresh();
   }

   public String getGraphQLQuery() {
      return this.gqlQueryArea.getText();
   }

   public String getGraphQLVariables() {
      return this.gqlVarsArea.getText();
   }

   public void setMode(String mode) {
      if (mode == null) {
         mode = "raw";
      }

      if ("graphql".equalsIgnoreCase(mode)) {
         mode = "GraphQL";
      }

      this.modeCombo.setSelectedItem(mode);
      this.applyMode(mode);
   }

   public String getMode() {
      return this.currentMode;
   }

   public void clear() {
      UndoSupport.setTextWithoutUndo(this.bodyTextArea, "");
      UndoSupport.setTextWithoutUndo(this.gqlQueryArea, "");
      UndoSupport.setTextWithoutUndo(this.gqlVarsArea, "");
      this.formDataModel.setRowCount(0);
      this.modeCombo.setSelectedIndex(0);
      this.currentMode = "raw";
      this.cards.show(this.cardHost, "TEXT");
      this.scheduleVariableHighlightRefresh();
   }

   private void chooseFileForSelectedFormRow() {
      int row = this.formDataTable.getSelectedRow();
      if (row < 0) {
         row = findPreferredFileRow();
         if (row < 0) {
            this.formDataModel.addRow(new Object[]{Boolean.TRUE, "attachment", FORM_TYPE_FILE, ""});
            row = this.formDataModel.getRowCount() - 1;
         }
         this.formDataTable.getSelectionModel().setSelectionInterval(row, row);
      }
      JFileChooser chooser = new JFileChooser();
      chooser.setDialogTitle("Select upload file");
      if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
         File f = chooser.getSelectedFile();
         if (f != null) {
         Object keyObj = this.formDataModel.getValueAt(row, FORM_COL_KEY);
            String key = keyObj == null ? "" : keyObj.toString().trim();
         if (key.isEmpty()) this.formDataModel.setValueAt("attachment", row, FORM_COL_KEY);
         this.formDataModel.setValueAt(Boolean.TRUE, row, FORM_COL_ENABLED);
         this.formDataModel.setValueAt(FORM_TYPE_FILE, row, FORM_COL_TYPE);
         this.formDataModel.setValueAt(f.getAbsolutePath(), row, FORM_COL_VALUE);
         }
      }
   }

   private int findPreferredFileRow() {
      for (int i = 0; i < this.formDataModel.getRowCount(); i++) {
         String type = normalizeFormType(this.formDataModel.getValueAt(i, FORM_COL_TYPE));
         if (FORM_TYPE_FILE.equals(type)) return i;
      }
      for (int i = 0; i < this.formDataModel.getRowCount(); i++) {
         Object keyObj = this.formDataModel.getValueAt(i, FORM_COL_KEY);
         String key = keyObj == null ? "" : keyObj.toString().trim();
         if (!key.isEmpty()) return i;
      }
      return -1;
   }

   private void loadFormDataRows(String kvText) {
      this.formDataModel.setRowCount(0);
      if (kvText == null || kvText.isEmpty()) {
         return;
      }
      for (String pair : kvText.split("&")) {
         if (pair == null || pair.isEmpty()) continue;
         int eq = pair.indexOf('=');
         String key = eq >= 0 ? pair.substring(0, eq) : pair;
         String value = eq >= 0 ? pair.substring(eq + 1) : "";
         key = urlDecode(key);
         value = urlDecode(value);
         boolean enabled = true;
         if (key.startsWith("~")) {
            enabled = false;
            key = key.substring(1);
         }

         String type = FORM_TYPE_TEXT;
         String visibleValue = value == null ? "" : value;
         if (visibleValue.startsWith("@") && visibleValue.length() > 1) {
            type = FORM_TYPE_FILE;
            visibleValue = visibleValue.substring(1).trim();
            if ("[]".equals(visibleValue)) visibleValue = "";
            if ((visibleValue.startsWith("\"") && visibleValue.endsWith("\""))
               || (visibleValue.startsWith("'") && visibleValue.endsWith("'"))) {
               visibleValue = visibleValue.substring(1, visibleValue.length() - 1);
            }
         }
         this.formDataModel.addRow(new Object[]{Boolean.valueOf(enabled), key, type, visibleValue});
      }
   }

   private String serializeFormDataRows() {
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < this.formDataModel.getRowCount(); i++) {
         Object enabledObj = this.formDataModel.getValueAt(i, FORM_COL_ENABLED);
         Object keyObj = this.formDataModel.getValueAt(i, FORM_COL_KEY);
         Object typeObj = this.formDataModel.getValueAt(i, FORM_COL_TYPE);
         Object valueObj = this.formDataModel.getValueAt(i, FORM_COL_VALUE);
         boolean enabled = asEnabledFlag(enabledObj);
         String key = keyObj == null ? "" : keyObj.toString().trim();
         String type = normalizeFormType(typeObj);
         String value = valueObj == null ? "" : valueObj.toString().trim();
         if (key.isEmpty()) continue;
         if (FORM_TYPE_FILE.equals(type)) {
            if (!value.isEmpty() && value.startsWith("@")) {
               value = value.substring(1).trim();
            }
            if (!value.isEmpty()) {
               value = "@" + value;
            }
         }
         if (sb.length() > 0) sb.append("&");
         if (!enabled) {
            key = "~" + key;
         }
         sb.append(urlEncode(key)).append("=").append(urlEncode(value));
      }
      return sb.toString();
   }

   public String getFormDataBody() {
      String text = this.serializeFormDataRows();
      return text.isEmpty() ? null : text;
   }

   public boolean hasFormDataRows() {
      for (int i = 0; i < this.formDataModel.getRowCount(); i++) {
         Object keyObj = this.formDataModel.getValueAt(i, FORM_COL_KEY);
         if (keyObj != null && !keyObj.toString().trim().isEmpty()) {
            return true;
         }
      }
      return false;
   }

   private static String normalizeFormType(Object rawType) {
      String type = rawType == null ? FORM_TYPE_TEXT : rawType.toString().trim().toLowerCase();
      return FORM_TYPE_FILE.equals(type) ? FORM_TYPE_FILE : FORM_TYPE_TEXT;
   }

   private static boolean asEnabledFlag(Object rawEnabled) {
      if (rawEnabled instanceof Boolean) {
         return ((Boolean)rawEnabled).booleanValue();
      }
      if (rawEnabled == null) {
         return true;
      }
      String s = rawEnabled.toString().trim();
      if (s.isEmpty()) {
         return true;
      }
      return !"false".equalsIgnoreCase(s) && !"0".equals(s) && !"no".equalsIgnoreCase(s);
   }

   private static String urlEncode(String s) {
      try {
         return URLEncoder.encode(s == null ? "" : s, "UTF-8");
      } catch (Exception ignore) {
         return s == null ? "" : s;
      }
   }

   private static String urlDecode(String s) {
      try {
         return URLDecoder.decode(s == null ? "" : s, "UTF-8");
      } catch (Exception ignore) {
         return s == null ? "" : s;
      }
   }
}
