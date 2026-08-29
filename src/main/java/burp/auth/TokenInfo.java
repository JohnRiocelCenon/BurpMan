package burp.auth;

public class TokenInfo {
   private String accessToken;
   private String refreshToken;
   private String tokenType = "Bearer";
   private long expiresAtEpochMs;

   public String getAccessToken() {
      return this.accessToken;
   }

   public void clear() {
      this.accessToken = null;
      this.refreshToken = null;
      this.tokenType = "Bearer";
      this.expiresAtEpochMs = 0L;
   }

   public void setAccessToken(String accessToken) {
      this.accessToken = accessToken;
   }

   public String getRefreshToken() {
      return this.refreshToken;
   }

   public void setRefreshToken(String refreshToken) {
      this.refreshToken = refreshToken;
   }

   public String getTokenType() {
      return this.tokenType != null && !this.tokenType.trim().isEmpty() ? this.tokenType : "Bearer";
   }

   public void setTokenType(String tokenType) {
      this.tokenType = tokenType;
   }

   public long getExpiresAtEpochMs() {
      return this.expiresAtEpochMs;
   }

   public void setExpiresAtEpochMs(long expiresAtEpochMs) {
      this.expiresAtEpochMs = expiresAtEpochMs;
   }

   public boolean hasAccessToken() {
      return this.accessToken != null && !this.accessToken.trim().isEmpty();
   }

   public boolean isExpiredOrNearExpiry() {
      if (this.expiresAtEpochMs <= 0L) {
         return false;
      } else {
         long now = System.currentTimeMillis();
         long bufferMs = 60000L;
         return now + bufferMs >= this.expiresAtEpochMs;
      }
   }
}
