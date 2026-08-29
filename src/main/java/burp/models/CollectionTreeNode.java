package burp.models;

import java.util.ArrayList;
import java.util.List;
import javax.swing.tree.DefaultMutableTreeNode;

public class CollectionTreeNode extends DefaultMutableTreeNode {
   private final CollectionTreeNode.NodeType type;
   private final String name;
   private String method;
   private final AnalyzedRequest request;
   private final String path;
   private PostmanCollection.Item rawItem;

   public CollectionTreeNode(String name, CollectionTreeNode.NodeType type) {
      this(name, type, null, null, null);
   }

   public CollectionTreeNode(String name, CollectionTreeNode.NodeType type, String path) {
      this(name, type, null, null, path);
   }

   public CollectionTreeNode(String name, CollectionTreeNode.NodeType type, String method, AnalyzedRequest request, String path) {
      super(name);
      this.type = type;
      this.name = name;
      this.method = method;
      this.request = request;
      this.path = path;
   }

   public CollectionTreeNode.NodeType getNodeType() {
      return this.type;
   }

   public String getDisplayName() {
      return this.type == CollectionTreeNode.NodeType.REQUEST && this.method != null ? String.format("[%s] %s", this.method, this.name) : this.name;
   }

   public String getMethod() {
      return this.method;
   }

   public void setMethod(String method) {
      this.method = method;
   }

   public AnalyzedRequest getRequest() {
      return this.request;
   }

   public String getNodePath() {
      return this.path;
   }

   public PostmanCollection.Item getRawItem() {
      return this.rawItem;
   }

   public void setRawItem(PostmanCollection.Item rawItem) {
      this.rawItem = rawItem;
   }

   public boolean isAnalyzed() {
      return this.type == CollectionTreeNode.NodeType.COLLECTION && this.rawItem != null && this.rawItem.analyzed;
   }

   public List<AnalyzedRequest> getAllRequests() {
      List<AnalyzedRequest> requests = new ArrayList<>();
      if (this.type == CollectionTreeNode.NodeType.REQUEST && this.request != null) {
         requests.add(this.request);
      }

      for (int i = 0; i < this.getChildCount(); i++) {
         CollectionTreeNode child = (CollectionTreeNode)this.getChildAt(i);
         requests.addAll(child.getAllRequests());
      }

      return requests;
   }

   @Override
   public boolean isLeaf() {
      return this.type == CollectionTreeNode.NodeType.REQUEST;
   }

   @Override
   public boolean getAllowsChildren() {
      return this.type != CollectionTreeNode.NodeType.REQUEST;
   }

   public static enum NodeType {
      COLLECTION,
      FOLDER,
      REQUEST;
   }
}
