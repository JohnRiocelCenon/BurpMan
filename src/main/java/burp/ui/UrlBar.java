package burp.ui;

import burp.parser.VariableResolver;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dialog;
import java.awt.Dimension;
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
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.JViewport;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.ToolTipManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import javax.swing.text.DocumentFilter.FilterBypass;

public class UrlBar extends JPanel {
   private final JComboBox<String> methodCombo;
   private final JTextPane urlField;
   private final SimpleAttributeSet baseAttr = new SimpleAttributeSet();
   private final SimpleAttributeSet varResolvedAttr = new SimpleAttributeSet();
   private final SimpleAttributeSet varUnresolvedAttr = new SimpleAttributeSet();
   private final SimpleAttributeSet varEmptyAttr = new SimpleAttributeSet();
   private static final Pattern VAR_PATTERN = Pattern.compile("\\{\\{([^{}]+)\\}\\}");
   private VariableResolver variableResolver;
   private volatile boolean recoloring = false;
   private List<VariableResolver.Span> activeSpans = Collections.emptyList();
   private volatile boolean suppressInvalidate = false;

   public UrlBar() {
      this.setLayout(new BorderLayout(5, 0));
      this.methodCombo = new JComboBox<>(new String[]{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"});
      this.methodCombo.setPreferredSize(new Dimension(80, 30));
      this.add(this.methodCombo, "West");
      this.urlField = new JTextPane() {
         @Override
         public boolean getScrollableTracksViewportWidth() {
            return false;
         }
      };
      this.urlField.setFont(new Font("Courier New", 0, 12));
      this.urlField.setEditable(true);
      UndoSupport.install(this.urlField);
      this.urlField.setCursor(Cursor.getPredefinedCursor(2));
      this.urlField
         .setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(new Color(189, 189, 189)), BorderFactory.createEmptyBorder(4, 6, 4, 6)));
      ((AbstractDocument)this.urlField.getDocument()).setDocumentFilter(new DocumentFilter() {
         @Override
         public void insertString(FilterBypass fb, int offs, String str, AttributeSet a) throws BadLocationException {
            super.insertString(fb, offs, this.stripWs(str), a);
         }

         @Override
         public void replace(FilterBypass fb, int offs, int len, String str, AttributeSet a) throws BadLocationException {
            super.replace(fb, offs, len, this.stripWs(str), a);
         }

         private String stripWs(String s) {
            if (s != null && !s.isEmpty()) {
               StringBuilder sb = new StringBuilder(s.length());

               for (int i = 0; i < s.length(); i++) {
                  char c = s.charAt(i);
                  if (c != ' ' && c != '\t' && c != '\r' && c != '\n' && c != 8232 && c != 8233 && c != 133) {
                     sb.append(c);
                  }
               }

               return sb.toString();
            } else {
               return s;
            }
         }
      });
      StyleConstants.setForeground(this.baseAttr, Color.BLACK);
      StyleConstants.setForeground(this.varResolvedAttr, new Color(46, 125, 50));
      StyleConstants.setBold(this.varResolvedAttr, true);
      StyleConstants.setForeground(this.varUnresolvedAttr, new Color(211, 47, 47));
      StyleConstants.setBold(this.varUnresolvedAttr, true);
      // Amber: variable IS defined but its value is empty. Distinct from
      // red (undefined) so users can see "you set this to '', not that
      // it's missing entirely" — helps diagnose why {{CASE_ID}} produces
      // a URL that looks truncated.
      StyleConstants.setForeground(this.varEmptyAttr, new Color(230, 130, 0));
      StyleConstants.setBold(this.varEmptyAttr, true);
      StyleConstants.setItalic(this.varEmptyAttr, true);
      JScrollPane sp = new JScrollPane(this.urlField, 21, 30);
      sp.setBorder(BorderFactory.createEmptyBorder());
      sp.setPreferredSize(new Dimension(0, 30));
      sp.setMinimumSize(new Dimension(0, 30));
      sp.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
      this.add(sp, "Center");
      this.urlField.getInputMap().put(KeyStroke.getKeyStroke("ENTER"), "none");
      this.urlField.getDocument().addDocumentListener(new DocumentListener() {
         @Override
         public void insertUpdate(DocumentEvent e) {
            UrlBar.this.invalidateSpansAndRecolor();
         }

         @Override
         public void removeUpdate(DocumentEvent e) {
            UrlBar.this.invalidateSpansAndRecolor();
         }

         @Override
         public void changedUpdate(DocumentEvent e) {
         }
      });
      ToolTipManager.sharedInstance().registerComponent(this.urlField);
      this.urlField.addMouseMotionListener(new MouseMotionAdapter() {
         @Override
         public void mouseMoved(MouseEvent e) {
            String tip = UrlBar.this.tipForPosition(e.getPoint());
            if (!Objects.equals(tip, UrlBar.this.urlField.getToolTipText())) {
               UrlBar.this.urlField.setToolTipText(tip);
            }

            String varName = UrlBar.this.varNameAt(e.getPoint());
            UrlBar.this.urlField.setCursor(varName != null ? Cursor.getPredefinedCursor(12) : Cursor.getPredefinedCursor(2));
         }
      });
      this.urlField.addMouseListener(new MouseAdapter() {
         @Override
         public void mouseClicked(MouseEvent e) {
            if (e.getClickCount() == 2 && e.getButton() == 1) {
               String varName = UrlBar.this.varNameAt(e.getPoint());
               if (varName != null) {
                  e.consume();
                  UrlBar.this.showVariableEditor(varName, e.getPoint());
               }
            }
         }
      });
   }

   private String varNameAt(Point p) {
      int pos = this.urlField.viewToModel(p);
      if (pos < 0) {
         return null;
      } else {
         for (VariableResolver.Span s : this.activeSpans) {
            if (pos >= s.start && pos < s.end) {
               return s.varName;
            }
         }

         try {
            String text = this.urlField.getDocument().getText(0, this.urlField.getDocument().getLength());
            Matcher m = VAR_PATTERN.matcher(text);

            while (m.find()) {
               if (pos >= m.start() && pos < m.end()) {
                  return m.group(1).trim();
               }
            }
         } catch (BadLocationException var5) {
         }

         return null;
      }
   }

   private void showVariableEditor(String varName, Point clickAt) {
      if (this.variableResolver != null) {
         String current = null;

         try {
            current = this.variableResolver.getVariables().get(varName);
         } catch (Throwable var16) {
         }

         if (current == null) {
            current = "";
         }

         Window owner = SwingUtilities.getWindowAncestor(this);
         final JDialog dlg;
         if (owner instanceof Frame) {
            dlg = new JDialog((Frame)owner, false);
         } else if (owner instanceof Dialog) {
            dlg = new JDialog((Dialog)owner, false);
         } else {
            dlg = new JDialog((Frame)null, false);
         }

         dlg.setUndecorated(true);
         dlg.setFocusableWindowState(true);
         JPanel content = new JPanel(new BorderLayout(6, 6));
         content.setBorder(
            BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(new Color(153, 153, 153)), BorderFactory.createEmptyBorder(8, 10, 8, 10))
         );
         content.setBackground(new Color(250, 250, 250));
         JLabel header = new JLabel("Edit {{" + varName + "}}");
         header.setFont(header.getFont().deriveFont(1, 12.0F));
         content.add(header, "North");
         JTextField valueField = new JTextField(current, 40);
         valueField.setFont(new Font("Courier New", 0, 12));
         content.add(valueField, "Center");
         JPanel buttons = new JPanel(new FlowLayout(2, 4, 0));
         buttons.setOpaque(false);
         JButton saveBtn = new JButton("Save");
         JButton cancelBtn = new JButton("Cancel");
         buttons.add(cancelBtn);
         buttons.add(saveBtn);
         content.add(buttons, "South");
         dlg.setContentPane(content);
         dlg.pack();
         Point anchorScreen = this.urlField.getLocationOnScreen();
         dlg.setLocation(anchorScreen.x + clickAt.x, anchorScreen.y + clickAt.y + 18);
         final Runnable dismiss = dlg::dispose;
         cancelBtn.addActionListener(e -> dismiss.run());
         Runnable commit = () -> {
            String newValue = valueField.getText();

            try {
               this.variableResolver.updateVariableEverywhere(varName, newValue);
            } catch (Throwable var6x) {
            }

            dismiss.run();
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
                  if (!dlg.isFocused()) {
                     dlg.dispose();
                  }
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
   }

   public void setVariableResolver(VariableResolver resolver) {
      this.variableResolver = resolver;
      this.scheduleRecolor();
   }

   private void invalidateSpansAndRecolor() {
      if (!this.suppressInvalidate) {
         this.activeSpans = Collections.emptyList();
         this.scheduleRecolor();
      }
   }

   private void scheduleRecolor() {
      SwingUtilities.invokeLater(this::recolor);
   }

   private void recolor() {
      if (!this.recoloring) {
         this.recoloring = true;

         try {
            StyledDocument doc = this.urlField.getStyledDocument();
            int len = doc.getLength();
            doc.setCharacterAttributes(0, len, this.baseAttr, true);

            for (VariableResolver.Span s : this.activeSpans) {
               if (s.start >= 0 && s.end <= len && s.start < s.end) {
                  SimpleAttributeSet attr;
                  if (s.value == null) {
                     attr = this.varUnresolvedAttr;
                  } else if (s.value.isEmpty()) {
                     attr = this.varEmptyAttr;
                  } else {
                     attr = this.varResolvedAttr;
                  }
                  doc.setCharacterAttributes(s.start, s.end - s.start, attr, true);
               }
            }

            String text;
            try {
               text = doc.getText(0, len);
            } catch (BadLocationException var10) {
               return;
            }

            Matcher m = VAR_PATTERN.matcher(text);

            while (m.find()) {
               String key = m.group(1).trim();
               SimpleAttributeSet attr;
               if (this.variableResolver == null || this.variableResolver.getVariables() == null) {
                  attr = this.varUnresolvedAttr;
               } else {
                  String val = this.variableResolver.getVariables().get(key);
                  if (val == null) {
                     attr = this.varUnresolvedAttr;
                  } else if (val.isEmpty()) {
                     attr = this.varEmptyAttr;
                  } else {
                     attr = this.varResolvedAttr;
                  }
               }
               doc.setCharacterAttributes(m.start(), m.end() - m.start(), attr, true);
            }
         } finally {
            this.recoloring = false;
         }
      }
   }

   private String tipForPosition(Point p) {
      int pos = this.urlField.viewToModel(p);
      if (pos < 0) {
         return null;
      } else {
         for (VariableResolver.Span s : this.activeSpans) {
            if (pos >= s.start && pos < s.end) {
               if (s.value == null) {
                  return "{{" + s.varName + "}}  —  not defined";
               }
               if (s.value.isEmpty()) {
                  return "{{" + s.varName + "}}  —  defined but empty (will send as empty)";
               }

               String shown = s.value.length() > 120 ? s.value.substring(0, 120) + "…" : s.value;
               return "{{" + s.varName + "}}  =  " + shown;
            }
         }

         String text;
         try {
            text = this.urlField.getDocument().getText(0, this.urlField.getDocument().getLength());
         } catch (BadLocationException var9) {
            return null;
         }

         Matcher m = VAR_PATTERN.matcher(text);

         while (m.find()) {
            if (pos >= m.start() && pos < m.end()) {
               String key = m.group(1).trim();
               String value = this.variableResolver != null && this.variableResolver.getVariables() != null
                  ? this.variableResolver.getVariables().get(key)
                  : null;
               if (value == null) {
                  return "{{" + key + "}}  —  not defined";
               }
               if (value.isEmpty()) {
                  return "{{" + key + "}}  —  defined but empty (will send as empty)";
               }
               try {
                  value = this.variableResolver.resolve(value);
               } catch (Throwable var8) {
               }

               String shown = value.length() > 120 ? value.substring(0, 120) + "…" : value;
               return "{{" + key + "}}  =  " + shown;
            }
         }

         return null;
      }
   }

   private static String esc(String s) {
      return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
   }

   public String getMethod() {
      return (String)this.methodCombo.getSelectedItem();
   }

   public void setMethod(String method) {
      this.methodCombo.setSelectedItem(method.toUpperCase());
   }

   public String getUrl() {
      try {
         String t = this.urlField.getDocument().getText(0, this.urlField.getDocument().getLength());
         return t == null ? "" : t.replace("\r", "").replace("\n", "").trim();
      } catch (BadLocationException var2) {
         return "";
      }
   }

   public void setUrl(Object urlObj) {
      this.setUrl(urlObj == null ? "" : urlObj.toString(), null);
   }

   public void setUrl(String resolvedUrl, String rawTemplate) {
      String t = resolvedUrl == null ? "" : resolvedUrl;
      t = t.replace("\r", "").replace("\n", "");
      List<VariableResolver.Span> spans = Collections.emptyList();
      if (rawTemplate != null && !rawTemplate.isEmpty() && this.variableResolver != null) {
         try {
            VariableResolver.Resolution r = this.variableResolver.resolveTracked(rawTemplate);
            if (r != null && r.resolved != null) {
               t = r.resolved.replace("\r", "").replace("\n", "");
               spans = r.spans == null ? Collections.emptyList() : r.spans;
            }
         } catch (Throwable var9) {
         }
      }

      this.suppressInvalidate = true;

      try {
         UndoSupport.setTextWithoutUndo(this.urlField, t);
      } finally {
         this.suppressInvalidate = false;
      }

      this.activeSpans = spans;
      this.scheduleRecolor();
      SwingUtilities.invokeLater(() -> {
         try {
            this.urlField.setCaretPosition(0);
            JViewport vp = (JViewport)SwingUtilities.getAncestorOfClass(JViewport.class, this.urlField);
            if (vp != null) {
               vp.setViewPosition(new Point(0, 0));
            }
         } catch (Throwable var2x) {
         }
      });
   }

   public void clear() {
      this.suppressInvalidate = true;

      try {
         UndoSupport.setTextWithoutUndo(this.urlField, "");
      } finally {
         this.suppressInvalidate = false;
      }

      this.activeSpans = Collections.emptyList();
      this.methodCombo.setSelectedIndex(0);
   }

   public void addUrlChangeListener(final Runnable listener) {
      this.urlField.getDocument().addDocumentListener(new DocumentListener() {
         @Override
         public void insertUpdate(DocumentEvent e) {
            listener.run();
         }

         @Override
         public void removeUpdate(DocumentEvent e) {
            listener.run();
         }

         @Override
         public void changedUpdate(DocumentEvent e) {
         }
      });
   }
}
