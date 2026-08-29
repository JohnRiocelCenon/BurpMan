package burp.ui;

import burp.models.CollectionTreeNode;
import burp.models.CollectionTreeNode.NodeType;

import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.*;
import java.awt.*;

/**
 * Custom renderer for CollectionTreeNode in JTree.
 * Burp's Look & Feel renders HTML literally in JLabel, so we use a JPanel
 * with two JLabels (colored bold METHOD + theme-colored name) for request rows.
 */
public class TreeCellRenderer extends DefaultTreeCellRenderer {

    private final RequestRowRenderer requestRow = new RequestRowRenderer();

    public TreeCellRenderer() {
        setClosedIcon(createFolderIcon());
        setOpenIcon(createFolderIcon());
        setLeafIcon(createRequestIcon());
    }

    @Override
    public Component getTreeCellRendererComponent(
            JTree tree, Object value, boolean selected, boolean expanded,
            boolean leaf, int row, boolean hasFocus) {

        super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus);

        if (value instanceof CollectionTreeNode) {
            CollectionTreeNode node = (CollectionTreeNode) value;

            if (node.getNodeType() == NodeType.REQUEST) {
                String method = node.getMethod() == null ? "" : node.getMethod().toUpperCase();
                String name = node.getUserObject() == null ? "" : node.getUserObject().toString();
                Color selBg = new Color(0x32, 0x7E, 0xFF);
                Color rowBg = selected ? selBg : UITheme.surface();
                Color rowFg = selected ? Color.WHITE : UITheme.foreground();
                requestRow.configure(method, name, getMethodColor(method),
                        createMethodIcon(node.getMethod()), selected,
                        rowBg, rowFg, Color.WHITE, getFont());
                return requestRow;
            } else if (node.getNodeType() == NodeType.COLLECTION) {
                String label = node.getDisplayName();
                boolean analyzed = node.isAnalyzed();
                boolean pending = !analyzed && node.getRawItem() != null && node.getRawItem().isCollectionWrapper;
                setText(label);
                setIcon(createCollectionStatusIcon(analyzed, pending));
                Font f = getFont();
                if (f != null) setFont(f.deriveFont(Font.BOLD));
                Color fg = selected ? Color.WHITE
                        : (analyzed ? new Color(0x2E, 0x7D, 0x32) : UITheme.foreground());
                setForeground(fg);
                setBackgroundSelectionColor(new Color(0x32, 0x7E, 0xFF));
                setBackgroundNonSelectionColor(UITheme.surface());
            } else { // FOLDER
                setText(node.getDisplayName());
                Font f = getFont();
                if (f != null) setFont(f.deriveFont(Font.PLAIN));
                setForeground(selected ? Color.WHITE : UITheme.subtleText());
                setBackgroundSelectionColor(new Color(0x32, 0x7E, 0xFF));
                setBackgroundNonSelectionColor(UITheme.surface());
            }
        }

        return this;
    }

    private Color getMethodColor(String method) {
        if (method == null) return Color.BLACK;
        switch (method.toUpperCase()) {
            case "GET":     return new Color(33, 150, 243);
            case "POST":    return new Color(255, 152, 0);
            case "PUT":     return new Color(76, 175, 80);
            case "DELETE":  return new Color(244, 67, 54);
            case "PATCH":   return new Color(156, 39, 176);
            case "OPTIONS": return new Color(96, 125, 139);
            case "HEAD":    return new Color(0, 150, 136);
            default:        return Color.DARK_GRAY;
        }
    }

    private Icon createRequestIcon() {
        return new Icon() {
            public void paintIcon(Component c, Graphics g, int x, int y) {
                g.setColor(Color.DARK_GRAY);
                g.fillOval(x + 3, y + 8, 4, 4);
            }
            public int getIconWidth() { return 12; }
            public int getIconHeight() { return 12; }
        };
    }

    private Icon createMethodIcon(final String method) {
        return new Icon() {
            public void paintIcon(Component c, Graphics g, int x, int y) {
                g.setColor(getMethodColor(method));
                g.fillOval(x + 2, y + 7, 6, 6);
            }
            public int getIconWidth() { return 12; }
            public int getIconHeight() { return 12; }
        };
    }

    private Icon createFolderIcon() {
        return new Icon() {
            public void paintIcon(Component c, Graphics g, int x, int y) {
                g.setColor(new Color(184, 134, 11));
                g.fillRect(x + 1, y + 7, 10, 5);
                g.fillRect(x + 1, y + 5, 4, 2);
            }
            public int getIconWidth() { return 12; }
            public int getIconHeight() { return 12; }
        };
    }

    /**
     * Status dot for collection nodes:
     *   • green  = analyzed (scripts ran, vars resolved)
     *   • orange = pending  (loaded but not yet analyzed)
     *   • grey   = neutral
     */
    private Icon createCollectionStatusIcon(boolean analyzed, boolean pending) {
        final Color fill = analyzed
                ? new Color(0x2E, 0xCC, 0x71)
                : (pending ? new Color(0xFF, 0x8C, 0x00) : new Color(0x9E, 0x9E, 0x9E));
        return new Icon() {
            public void paintIcon(Component c, Graphics g, int x, int y) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(fill);
                g2.fillOval(x + 2, y + 4, 8, 8);
                g2.setColor(new Color(0, 0, 0, 60));
                g2.drawOval(x + 2, y + 4, 8, 8);
                g2.dispose();
            }
            public int getIconWidth() { return 14; }
            public int getIconHeight() { return 14; }
        };
    }

    /** Two-label row: colored bold METHOD + theme-colored request name. */
    private static class RequestRowRenderer extends JPanel {
        private final JLabel iconLabel = new JLabel();
        private final JLabel methodLabel = new JLabel();
        private final JLabel nameLabel = new JLabel();

        RequestRowRenderer() {
            super(new FlowLayout(FlowLayout.LEFT, 4, 0));
            setOpaque(true);
            iconLabel.setOpaque(false);
            methodLabel.setOpaque(false);
            nameLabel.setOpaque(false);
            add(iconLabel);
            add(methodLabel);
            add(nameLabel);
        }

        void configure(String method, String name, Color methodColor, Icon icon,
                       boolean selected, Color bg, Color fgNormal, Color fgSelected, Font font) {
            iconLabel.setIcon(icon);
            methodLabel.setText(method);
            nameLabel.setText(name == null ? "" : name);
            if (font != null) {
                methodLabel.setFont(font.deriveFont(Font.BOLD));
                nameLabel.setFont(font.deriveFont(Font.PLAIN));
            }
            methodLabel.setForeground(methodColor);
            nameLabel.setForeground(selected ? fgSelected : fgNormal);
            setBackground(bg);
        }
    }
}
