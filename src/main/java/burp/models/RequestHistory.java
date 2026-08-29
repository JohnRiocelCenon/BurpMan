package burp.models;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class RequestHistory {
   private static final int MAX_HISTORY_SIZE = 100;
   private final List<ExecutedRequest> requests = new CopyOnWriteArrayList<>();
   private final List<RequestHistory.HistoryListener> listeners = new CopyOnWriteArrayList<>();

   public void add(ExecutedRequest request) {
      if (this.requests.size() >= 100) {
         ExecutedRequest removed = this.requests.remove(0);
         this.notifyRemoved(removed);
      }

      this.requests.add(request);
      this.notifyAdded(request);
   }

   public List<ExecutedRequest> getAll() {
      return new ArrayList<>(this.requests);
   }

   public ExecutedRequest getById(String id) {
      return this.requests.stream().filter(r -> r.getId().equals(id)).findFirst().orElse(null);
   }

   public void clear() {
      this.requests.clear();
      this.notifyCleared();
   }

   public void remove(ExecutedRequest request) {
      if (this.requests.remove(request)) {
         this.notifyRemoved(request);
      }
   }

   public int size() {
      return this.requests.size();
   }

   public void addListener(RequestHistory.HistoryListener listener) {
      this.listeners.add(listener);
   }

   public void removeListener(RequestHistory.HistoryListener listener) {
      this.listeners.remove(listener);
   }

   private void notifyAdded(ExecutedRequest request) {
      for (RequestHistory.HistoryListener listener : this.listeners) {
         try {
            listener.onRequestAdded(request);
         } catch (Exception var5) {
            var5.printStackTrace();
         }
      }
   }

   private void notifyCleared() {
      for (RequestHistory.HistoryListener listener : this.listeners) {
         try {
            listener.onHistoryCleared();
         } catch (Exception var4) {
            var4.printStackTrace();
         }
      }
   }

   private void notifyRemoved(ExecutedRequest request) {
      for (RequestHistory.HistoryListener listener : this.listeners) {
         try {
            listener.onRequestRemoved(request);
         } catch (Exception var5) {
            var5.printStackTrace();
         }
      }
   }

   public interface HistoryListener {
      void onRequestAdded(ExecutedRequest var1);

      void onHistoryCleared();

      void onRequestRemoved(ExecutedRequest var1);
   }
}
