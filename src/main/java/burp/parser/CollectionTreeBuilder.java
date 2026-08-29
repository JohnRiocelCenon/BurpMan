package burp.parser;

import burp.models.AnalyzedRequest;
import burp.models.CollectionTreeNode;
import burp.models.PostmanCollection;
import java.util.List;

public class CollectionTreeBuilder {
   public CollectionTreeNode buildTree(PostmanCollection collection, List<AnalyzedRequest> requests) {
      String collectionName = collection != null && collection.info != null && collection.info.name != null && !collection.info.name.trim().isEmpty()
         ? collection.info.name
         : "Unnamed Collection";
      CollectionTreeNode root = new CollectionTreeNode(collectionName, CollectionTreeNode.NodeType.COLLECTION);
      if (collection.item != null) {
         this.buildTreeRecursive(collection.item, root, requests, "");
      }

      return root;
   }

   private void buildTreeRecursive(List<PostmanCollection.Item> items, CollectionTreeNode parentNode, List<AnalyzedRequest> requests, String pathPrefix) {
      if (items != null && !items.isEmpty()) {
         for (PostmanCollection.Item item : items) {
            String itemName = item.name != null ? item.name : "Unnamed";
            String currentPath = pathPrefix.isEmpty() ? itemName : pathPrefix + " > " + itemName;
            if (item.request != null) {
               AnalyzedRequest analyzedReq = this.findRequestByPath(item, currentPath, requests);
               if (analyzedReq == null) {
                  analyzedReq = this.findRequestByName(item, requests);
               }

               if (analyzedReq == null) {
                  String synthPath = currentPath == null ? itemName : currentPath.replace(" > ", "/");
                  String collName = parentNode != null ? parentNode.toString() : "Collection";
                  String rawUrl = "";

                  try {
                     if (item.request.url != null) {
                        rawUrl = item.request.url.toString();
                     }
                  } catch (Throwable var14) {
                  }

                  analyzedReq = new AnalyzedRequest(itemName, synthPath, item.request, collName, rawUrl);
               }

               String method = item.request.method != null ? item.request.method.toUpperCase() : "REQUEST";
               CollectionTreeNode requestNode = new CollectionTreeNode(itemName, CollectionTreeNode.NodeType.REQUEST, method, analyzedReq, currentPath);
               requestNode.setRawItem(item);
               parentNode.add(requestNode);
            }

            boolean isFolderNode = item.item != null;
            boolean hasChildren = isFolderNode && !item.item.isEmpty();
            if (isFolderNode || item.isCollectionWrapper) {
               CollectionTreeNode.NodeType nt = item.isCollectionWrapper ? CollectionTreeNode.NodeType.COLLECTION : CollectionTreeNode.NodeType.FOLDER;
               CollectionTreeNode folderNode = new CollectionTreeNode(itemName, nt, currentPath);
               folderNode.setRawItem(item);
               parentNode.add(folderNode);
               if (hasChildren) {
                  this.buildTreeRecursive(item.item, folderNode, requests, currentPath);
               }
            }
         }
      }
   }

   private AnalyzedRequest findRequestByPath(PostmanCollection.Item item, String treePath, List<AnalyzedRequest> requests) {
      if (item != null && item.name != null && treePath != null && requests != null && !requests.isEmpty()) {
         String wantPath = treePath.replace(" > ", "/");

         for (AnalyzedRequest req : requests) {
            if (req != null) {
               String p = req.getPath();
               if (p != null && p.equals(wantPath)) {
                  return req;
               }
            }
         }

         String wantLower = wantPath.toLowerCase();

         for (AnalyzedRequest reqx : requests) {
            if (reqx != null) {
               String p = reqx.getPath();
               if (p != null && p.toLowerCase().equals(wantLower)) {
                  return reqx;
               }
            }
         }

         return null;
      } else {
         return null;
      }
   }

   private AnalyzedRequest findRequestByName(PostmanCollection.Item item, List<AnalyzedRequest> requests) {
      if (item.name != null && requests != null) {
         String targetName = item.name;

         for (AnalyzedRequest req : requests) {
            if (targetName.equalsIgnoreCase(req.getName())) {
               return req;
            }
         }

         for (AnalyzedRequest reqx : requests) {
            if (reqx.getName().contains(targetName) || targetName.contains(reqx.getName())) {
               return reqx;
            }
         }

         return null;
      } else {
         return null;
      }
   }
}
