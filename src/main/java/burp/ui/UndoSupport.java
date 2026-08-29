package burp.ui;

import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.lang.reflect.Method;
import javax.swing.AbstractAction;
import javax.swing.KeyStroke;
import javax.swing.event.UndoableEditEvent;
import javax.swing.event.UndoableEditListener;
import javax.swing.text.JTextComponent;
import javax.swing.undo.CannotRedoException;
import javax.swing.undo.CannotUndoException;
import javax.swing.undo.UndoManager;

public final class UndoSupport {
   private static final String UNDO_ACTION = "burpman-undo";
   private static final String REDO_ACTION = "burpman-redo";

   private UndoSupport() {
   }

   public static UndoManager install(JTextComponent component) {
      if (component == null) {
         return null;
      } else {
         try {
            Class<?> rstaCls = Class.forName("org.fife.ui.rsyntaxtextarea.RSyntaxTextArea");
            if (rstaCls.isInstance(component)) {
               return null;
            }
         } catch (Throwable var4) {
         }

         Object existing = component.getClientProperty("burpman-undo");
         if (existing instanceof UndoManager) {
            return (UndoManager)existing;
         } else {
            final UndoManager manager = new UndoManager();
            manager.setLimit(1000);
            component.putClientProperty("burpman-undo", manager);
            component.getDocument().addUndoableEditListener(new UndoableEditListener() {
               @Override
               public void undoableEditHappened(UndoableEditEvent e) {
                  manager.addEdit(e.getEdit());
               }
            });
            int modifier = getMenuShortcutMaskCompat();
            component.getInputMap(0).put(KeyStroke.getKeyStroke(90, modifier), "burpman-undo");
            component.getInputMap(0).put(KeyStroke.getKeyStroke(89, modifier), "burpman-redo");
            component.getInputMap(0).put(KeyStroke.getKeyStroke(90, modifier | InputEvent.SHIFT_DOWN_MASK), "burpman-redo");
            component.getActionMap().put("burpman-undo", new AbstractAction() {
               @Override
               public void actionPerformed(ActionEvent e) {
                  try {
                     if (manager.canUndo()) {
                        manager.undo();
                     }
                  } catch (CannotUndoException var3) {
                  }
               }
            });
            component.getActionMap().put("burpman-redo", new AbstractAction() {
               @Override
               public void actionPerformed(ActionEvent e) {
                  try {
                     if (manager.canRedo()) {
                        manager.redo();
                     }
                  } catch (CannotRedoException var3) {
                  }
               }
            });
            return manager;
         }
      }
   }

   public static int getMenuShortcutMaskCompat() {
      Toolkit toolkit = Toolkit.getDefaultToolkit();

      try {
         Method modern = Toolkit.class.getMethod("getMenuShortcutKeyMaskEx");
         Object value = modern.invoke(toolkit);
         if (value instanceof Integer) {
            return (Integer)value;
         }
      } catch (Throwable ignore) {
      }

      try {
         Method legacy = Toolkit.class.getMethod("getMenuShortcutKeyMask");
         Object value = legacy.invoke(toolkit);
         if (value instanceof Integer) {
            return (Integer)value;
         }
      } catch (Throwable ignore) {
      }

      return InputEvent.CTRL_DOWN_MASK;
   }

   public static void setTextWithoutUndo(JTextComponent component, String text) {
      if (component != null) {
         try {
            Class<?> rstaCls = Class.forName("org.fife.ui.rtextarea.RTextArea");
            if (rstaCls.isInstance(component)) {
               component.setText(text == null ? "" : text);
               Method m = rstaCls.getMethod("discardAllEdits");
               m.invoke(component);
               return;
            }
         } catch (Throwable var4) {
         }

         UndoManager mgr = install(component);
         component.setText(text == null ? "" : text);
         if (mgr != null) {
            mgr.discardAllEdits();
         }
      }
   }
}
