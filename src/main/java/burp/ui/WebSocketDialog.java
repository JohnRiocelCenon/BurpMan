package burp.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.awt.Window;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

public final class WebSocketDialog extends JDialog {
   private static final SimpleDateFormat TS = new SimpleDateFormat("HH:mm:ss.SSS", Locale.US);
   private final JTextField urlField = new JTextField("wss://echo.websocket.events");
   private final JTextArea sendArea = new JTextArea(3, 60);
   private final JTextPane logArea = new JTextPane();
   private final JButton connectBtn = new JButton("Connect");
   private final JButton sendBtn = new JButton("Send");
   private final JButton closeBtn = new JButton("Disconnect");
   private final JLabel statusLbl = new JLabel("Disconnected");
   private final AtomicReference<WebSocket> socketRef = new AtomicReference<>();

   public static void show(Component owner) {
      Window w = SwingUtilities.getWindowAncestor(owner);
      WebSocketDialog dlg;
      if (w instanceof Frame) {
         dlg = new WebSocketDialog((Frame)w);
      } else if (w instanceof Dialog) {
         dlg = new WebSocketDialog((Dialog)w);
      } else {
         dlg = new WebSocketDialog((Frame)null);
      }

      dlg.setLocationRelativeTo(owner);
      dlg.setVisible(true);
   }

   private WebSocketDialog(Frame owner) {
      super(owner, "WebSocket Client", false);
      this.init();
   }

   private WebSocketDialog(Dialog owner) {
      super(owner, "WebSocket Client", false);
      this.init();
   }

   private void init() {
      this.setSize(820, 560);
      this.setLayout(new BorderLayout(0, 4));
      JPanel north = new JPanel(new BorderLayout(6, 6));
      north.setBorder(BorderFactory.createEmptyBorder(8, 8, 4, 8));
      this.urlField.setFont(this.urlField.getFont().deriveFont(0, 13.0F));
      north.add(this.urlField, "Center");
      JPanel northRight = new JPanel(new FlowLayout(0, 4, 0));
      this.connectBtn.addActionListener(e -> this.connect());
      this.closeBtn.addActionListener(e -> this.disconnect(1000, "user closed"));
      this.closeBtn.setEnabled(false);
      northRight.add(this.connectBtn);
      northRight.add(this.closeBtn);
      north.add(northRight, "East");
      this.add(north, "North");
      this.logArea.setEditable(false);
      this.logArea.setFont(new Font("Monospaced", 0, 12));
      UndoSupport.install(this.logArea);
      this.add(new JScrollPane(this.logArea), "Center");
      this.sendArea.setFont(new Font("Monospaced", 0, 12));
      this.sendArea.setLineWrap(true);
      UndoSupport.install(this.sendArea);
      this.sendBtn.setEnabled(false);
      this.sendBtn.addActionListener(e -> this.sendCurrent());
      JPanel sendPanel = new JPanel(new BorderLayout(6, 4));
      sendPanel.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
      sendPanel.add(new JScrollPane(this.sendArea), "Center");
      JPanel sendRight = new JPanel(new BorderLayout());
      sendRight.add(this.sendBtn, "North");
      sendPanel.add(sendRight, "East");
      this.statusLbl.setBorder(BorderFactory.createEmptyBorder(4, 8, 6, 8));
      this.statusLbl.setForeground(new Color(136, 136, 136));
      JPanel south = new JPanel(new BorderLayout());
      south.add(sendPanel, "Center");
      south.add(this.statusLbl, "South");
      this.add(south, "South");
   }

   private void connect() {
      String url = this.urlField.getText().trim();
      if (!url.isEmpty()) {
         URI uri;
         try {
            uri = URI.create(url);
         } catch (Exception var6) {
            this.append(WebSocketDialog.Level.ERROR, "Invalid URL: " + var6.getMessage());
            return;
         }

         this.connectBtn.setEnabled(false);
         this.statusLbl.setText("Connecting to " + url + " …");
         this.append(WebSocketDialog.Level.INFO, "→ connect " + url);

         try {
            HttpClient http = HttpClient.newHttpClient();
            CompletableFuture<WebSocket> fut = http.newWebSocketBuilder().buildAsync(uri, new WebSocketDialog.Listener());
            fut.whenComplete((ws, err) -> SwingUtilities.invokeLater(() -> {
               if (err != null) {
                  this.append(WebSocketDialog.Level.ERROR, "Connect failed: " + err.getMessage());
                  this.statusLbl.setText("Disconnected");
                  this.connectBtn.setEnabled(true);
               } else {
                  this.socketRef.set(ws);
                  this.append(WebSocketDialog.Level.INFO, "✓ connected");
                  this.statusLbl.setText("Connected to " + url);
                  this.sendBtn.setEnabled(true);
                  this.closeBtn.setEnabled(true);
               }
            }));
         } catch (Throwable var5) {
            this.append(WebSocketDialog.Level.ERROR, "Connect failed: " + var5.getMessage());
            this.connectBtn.setEnabled(true);
            this.statusLbl.setText("Disconnected");
         }
      }
   }

   private void sendCurrent() {
      WebSocket ws = this.socketRef.get();
      if (ws != null) {
         String text = this.sendArea.getText();
         if (text != null && !text.isEmpty()) {
            this.append(WebSocketDialog.Level.OUT, text);
            ws.sendText(text, true);
            this.sendArea.setText("");
         }
      }
   }

   private void disconnect(int code, String reason) {
      WebSocket ws = this.socketRef.get();
      if (ws != null) {
         try {
            ws.sendClose(code, reason).whenComplete((v, err) -> SwingUtilities.invokeLater(() -> {
               this.append(WebSocketDialog.Level.INFO, "✓ closed (" + code + " " + reason + ")");
               this.statusLbl.setText("Disconnected");
               this.sendBtn.setEnabled(false);
               this.closeBtn.setEnabled(false);
               this.connectBtn.setEnabled(true);
               this.socketRef.set(null);
            }));
         } catch (Throwable var5) {
            this.append(WebSocketDialog.Level.ERROR, "Close failed: " + var5.getMessage());
         }
      }
   }

   private void append(WebSocketDialog.Level level, String msg) {
      SwingUtilities.invokeLater(() -> {
         StyledDocument doc = this.logArea.getStyledDocument();

         try {
            SimpleAttributeSet ts = new SimpleAttributeSet();
            StyleConstants.setForeground(ts, new Color(144, 144, 144));
            doc.insertString(doc.getLength(), TS.format(new Date()) + " ", ts);
            SimpleAttributeSet lvl = new SimpleAttributeSet();
            Color c;
            String tag;
            switch (level) {
               case IN:
                  c = new Color(41, 182, 246);
                  tag = "← ";
                  break;
               case OUT:
                  c = new Color(102, 187, 106);
                  tag = "→ ";
                  break;
               case ERROR:
                  c = new Color(239, 83, 80);
                  tag = "⚠ ";
                  break;
               default:
                  c = new Color(85, 85, 85);
                  tag = "  ";
            }

            StyleConstants.setForeground(lvl, c);
            StyleConstants.setBold(lvl, true);
            doc.insertString(doc.getLength(), tag, lvl);
            doc.insertString(doc.getLength(), msg + "\n", null);
            this.logArea.setCaretPosition(doc.getLength());
         } catch (Exception var8) {
         }
      });
   }

   private static enum Level {
      INFO,
      IN,
      OUT,
      ERROR;
   }

   private final class Listener implements WebSocket.Listener {
      private final StringBuilder buf = new StringBuilder();

      @Override
      public void onOpen(WebSocket webSocket) {
         WebSocket.Listener.super.onOpen(webSocket);
      }

      @Override
      public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
         this.buf.append(data);
         if (last) {
            String msg = this.buf.toString();
            this.buf.setLength(0);
            WebSocketDialog.this.append(WebSocketDialog.Level.IN, msg);
         }

         webSocket.request(1L);
         return null;
      }

      @Override
      public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last) {
         byte[] bytes = new byte[data.remaining()];
         data.get(bytes);
         WebSocketDialog.this.append(WebSocketDialog.Level.IN, "[binary " + bytes.length + " bytes]");
         webSocket.request(1L);
         return null;
      }

      @Override
      public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
         SwingUtilities.invokeLater(() -> {
            WebSocketDialog.this.append(WebSocketDialog.Level.INFO, "← server closed (" + statusCode + " " + reason + ")");
            WebSocketDialog.this.statusLbl.setText("Disconnected");
            WebSocketDialog.this.sendBtn.setEnabled(false);
            WebSocketDialog.this.closeBtn.setEnabled(false);
            WebSocketDialog.this.connectBtn.setEnabled(true);
            WebSocketDialog.this.socketRef.set(null);
         });
         return null;
      }

      @Override
      public void onError(WebSocket webSocket, Throwable error) {
         WebSocketDialog.this.append(WebSocketDialog.Level.ERROR, "transport error: " + error.getMessage());
      }
   }
}
