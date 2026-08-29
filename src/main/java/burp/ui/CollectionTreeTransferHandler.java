package burp.ui;

import burp.models.CollectionTreeNode;
import burp.models.PostmanCollection;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JComponent;
import javax.swing.JTree;
import javax.swing.TransferHandler;
import javax.swing.TransferHandler.TransferSupport;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

public class CollectionTreeTransferHandler extends TransferHandler {
   private static final DataFlavor NODE_FLAVOR = DataFlavor.stringFlavor;
   private static CollectionTreeNode draggingNode;
   private final CollectionTreePanel panel;

   public CollectionTreeTransferHandler(CollectionTreePanel panel) {
      this.panel = panel;
   }

   @Override
   public int getSourceActions(JComponent c) {
      return 2;
   }

   @Override
   protected Transferable createTransferable(JComponent c) {
      JTree tree = (JTree)c;
      TreePath path = tree.getSelectionPath();
      if (path == null) {
         return null;
      } else {
         Object o = path.getLastPathComponent();
         if (!(o instanceof CollectionTreeNode)) {
            return null;
         } else {
            CollectionTreeNode node = (CollectionTreeNode)o;
            if (node.getNodeType() == CollectionTreeNode.NodeType.COLLECTION) {
               return null;
            } else {
               draggingNode = node;
               return new StringSelection("ctn:" + System.identityHashCode(node));
            }
         }
      }
   }

   @Override
   protected void exportDone(JComponent source, Transferable data, int action) {
      draggingNode = null;
   }

   @Override
   public boolean canImport(TransferSupport support) {
      if (!support.isDrop()) {
         return false;
      } else if (draggingNode == null) {
         return false;
      } else {
         support.setShowDropLocation(true);
         JTree.DropLocation dl = (JTree.DropLocation)support.getDropLocation();
         TreePath dest = dl.getPath();
         if (dest == null) {
            return false;
         } else {
            Object dst = dest.getLastPathComponent();
            if (!(dst instanceof CollectionTreeNode)) {
               return false;
            } else {
               CollectionTreeNode dstNode = (CollectionTreeNode)dst;
               CollectionTreeNode src = draggingNode;
               if (src == dstNode) {
                  return false;
               } else {
                  for (TreePath p = dest; p != null; p = p.getParentPath()) {
                     if (p.getLastPathComponent() == src) {
                        return false;
                     }
                  }

                  return dstNode.getNodeType() == CollectionTreeNode.NodeType.REQUEST ? dl.getChildIndex() != -1 : true;
               }
            }
         }
      }
   }

   @Override
   public boolean importData(TransferSupport support) {
      if (!this.canImport(support)) {
         return false;
      } else {
         JTree tree = (JTree)support.getComponent();
         DefaultTreeModel model = (DefaultTreeModel)tree.getModel();
         JTree.DropLocation dl = (JTree.DropLocation)support.getDropLocation();
         TreePath destPath = dl.getPath();
         CollectionTreeNode destNode = (CollectionTreeNode)destPath.getLastPathComponent();
         CollectionTreeNode src = draggingNode;
         if (src == null) {
            return false;
         } else {
            CollectionTreeNode oldParent = (CollectionTreeNode)src.getParent();
            if (oldParent == null) {
               return false;
            } else {
               CollectionTreeNode newParent;
               int newIndex;
               if (dl.getChildIndex() == -1) {
                  if (destNode.getNodeType() == CollectionTreeNode.NodeType.REQUEST) {
                     newParent = (CollectionTreeNode)destNode.getParent();
                     newIndex = newParent.getIndex(destNode) + 1;
                  } else {
                     newParent = destNode;
                     newIndex = destNode.getChildCount();
                  }
               } else {
                  newParent = destNode;
                  newIndex = dl.getChildIndex();
               }

               if (oldParent == newParent) {
                  int oldIndex = oldParent.getIndex(src);
                  if (oldIndex < newIndex) {
                     newIndex--;
                  }

                  if (oldIndex == newIndex) {
                     return false;
                  }
               }

               model.removeNodeFromParent(src);
               model.insertNodeInto(src, newParent, Math.max(0, Math.min(newIndex, newParent.getChildCount())));
               this.syncRawModel(oldParent, newParent, src);
               TreePath newPath = new TreePath(src.getPath());
               tree.setSelectionPath(newPath);
               tree.scrollPathToVisible(newPath);
               return true;
            }
         }
      }
   }

   private void syncRawModel(CollectionTreeNode oldParent, CollectionTreeNode newParent, CollectionTreeNode moved) {
      this.rebuildItemList(oldParent);
      if (newParent != oldParent) {
         this.rebuildItemList(newParent);
      }
   }

   private void rebuildItemList(CollectionTreeNode parent) {
      List<PostmanCollection.Item> rebuilt = new ArrayList<>();

      for (int i = 0; i < parent.getChildCount(); i++) {
         Object child = parent.getChildAt(i);
         if (child instanceof CollectionTreeNode) {
            PostmanCollection.Item raw = ((CollectionTreeNode)child).getRawItem();
            if (raw != null) {
               rebuilt.add(raw);
            }
         }
      }

      if (parent.getNodeType() == CollectionTreeNode.NodeType.COLLECTION) {
         PostmanCollection coll = this.panel.getImporter().getCurrentCollection();
         if (coll != null) {
            coll.item = rebuilt;
         }
      } else {
         PostmanCollection.Item raw = parent.getRawItem();
         if (raw != null) {
            raw.item = rebuilt;
         }
      }
   }

   private static class NodeTransferable {
   }
}
