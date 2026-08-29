package burp.utils;

import java.awt.Color;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.UIManager;

public class UIHelpers {
   public static JLabel createFormattedLabel(String text, boolean italic, boolean bold, float fontSize, Color color) {
      JLabel label = new JLabel(text);
      int style = 0;
      if (italic) {
         style |= 2;
      }

      if (bold) {
         style |= 1;
      }

      label.setFont(label.getFont().deriveFont(style, fontSize));
      if (color != null) {
         label.setForeground(color);
      }

      return label;
   }

   public static JLabel createHintLabel(String text, float fontSize) {
      return createFormattedLabel(text, true, false, fontSize, Color.GRAY);
   }

   public static JLabel createTitleLabel(String text, float fontSize) {
      return createFormattedLabel(text, false, true, fontSize, null);
   }

   public static JTextArea createMultiLineLabel(String text, float fontSize) {
      JTextArea textArea = new JTextArea(text);
      textArea.setEditable(false);
      textArea.setOpaque(false);
      textArea.setWrapStyleWord(true);
      textArea.setLineWrap(true);
      textArea.setFont(textArea.getFont().deriveFont(fontSize));
      textArea.setForeground(UIManager.getColor("Label.foreground"));
      textArea.setBorder(null);
      return textArea;
   }

   public static JComponent createHTMLLabel(String htmlText) {
      return new JLabel(htmlText);
   }
}
