package burp.service;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.models.ExecutedRequest;
import burp.models.PostmanCollection;
import burp.utils.HttpUtils;
import burp.utils.RequestBuilder;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class RequestExecutor {
    
    private static final long HTTP_SEND_TIMEOUT_MS = 45000L;
    private final MontoyaApi api;
    private final List<ExecutionListener> listeners = new CopyOnWriteArrayList<>();
    private volatile Thread currentThread;
    private volatile String currentRequestId;
    private volatile boolean cancelRequested;
    
    private burp.parser.VariableResolver variableResolver;
    private burp.service.CookieJar cookieJar;
    private burp.auth.AuthManager authManager;
    
    public void setAuthManager(burp.auth.AuthManager am) { this.authManager = am; }
    
    public interface ExecutionListener {
        void onRequestStart(ExecutedRequest request);
        void onRequestComplete(ExecutedRequest request);
        void onRequestError(ExecutedRequest request, Throwable error);
    }
    
    public RequestExecutor(MontoyaApi api) {
        this.api = api;
    }
    
    public MontoyaApi getApi() {
        return api;
    }
    
    public void setVariableResolver(burp.parser.VariableResolver resolver) {
        this.variableResolver = resolver;
    }

    public burp.parser.VariableResolver getVariableResolver() {
        return variableResolver;
    }
    
    public void setCookieJar(burp.service.CookieJar jar) {
        this.cookieJar = jar;
    }
    
    public burp.service.CookieJar getCookieJar() {
        return cookieJar;
    }
    
    private String resolve(String input) {
        if (input == null || variableResolver == null) return input;
        try {
            return variableResolver.resolve(input);
        } catch (Exception e) {
            return input;
        }
    }

    private static final java.util.regex.Pattern UNRESOLVED_VAR_PATTERN =
        java.util.regex.Pattern.compile("\\{\\{([^{}]+)\\}\\}");

    private static int countLiterals(String s) {
        if (s == null || s.indexOf("{{") < 0) return 0;
        java.util.regex.Matcher m = UNRESOLVED_VAR_PATTERN.matcher(s);
        int n = 0;
        while (m.find()) n++;
        return n;
    }

    private static java.util.Set<String> extractLiteralVarNames(String s) {
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
        if (s == null || s.indexOf("{{") < 0) return out;
        java.util.regex.Matcher m = UNRESOLVED_VAR_PATTERN.matcher(s);
        while (m.find()) out.add(m.group(1).trim());
        return out;
    }
    
    /**
     * Execute a request asynchronously and notify listeners
     */
    public void executeAsync(String method, String url, List<PostmanCollection.Header> headers, String body) {
        cancelRequested = false;
        Thread thread = new Thread(() -> {
            try {
                execute(method, url, headers, body);
            } finally {
                cancelRequested = false;
                currentThread = null;
                currentRequestId = null;
            }
        });
        thread.setDaemon(true);
        currentThread = thread;
        thread.start();
    }

    /**
     * Execute a request asynchronously with raw body bytes (used for multipart
     * file uploads where body text conversion would corrupt binary content).
     */
    public void executeAsync(String method, String url, List<PostmanCollection.Header> headers, byte[] bodyBytes) {
        cancelRequested = false;
        Thread thread = new Thread(() -> {
            try {
                execute(method, url, headers, bodyBytes);
            } finally {
                cancelRequested = false;
                currentThread = null;
                currentRequestId = null;
            }
        });
        thread.setDaemon(true);
        currentThread = thread;
        thread.start();
    }
    
    /** Cancel any in-flight request. Best-effort: interrupts the executing thread. */
    public boolean cancelCurrent() {
        cancelRequested = true;
        Thread t = currentThread;
        if (t != null && t.isAlive()) {
            t.interrupt();
            return true;
        }
        return false;
    }
    
    public boolean isBusy() {
        Thread t = currentThread;
        return t != null && t.isAlive();
    }
    
    /**
     * Execute a request synchronously using Burp's Montoya API
     */
    public ExecutedRequest execute(String method, String url, List<PostmanCollection.Header> headers, String body) {
        return executeInternal(method, url, headers, body, null);
    }

    /**
     * Execute request with raw body bytes.
     */
    public ExecutedRequest execute(String method, String url, List<PostmanCollection.Header> headers, byte[] bodyBytes) {
        return executeInternal(method, url, headers, null, bodyBytes);
    }

    private ExecutedRequest executeInternal(String method,
                                            String url,
                                            List<PostmanCollection.Header> headers,
                                            String bodyText,
                                            byte[] bodyBytesRaw) {
        String requestId = UUID.randomUUID().toString();
        long timestamp = System.currentTimeMillis();

        String requestBodyForHistory = bodyText;
        if (requestBodyForHistory == null && bodyBytesRaw != null && bodyBytesRaw.length > 0) {
            requestBodyForHistory = "[binary body: " + bodyBytesRaw.length + " bytes]";
        }
        ExecutedRequest executed = new ExecutedRequest(
            requestId, timestamp, method, url, headers, requestBodyForHistory);
        
        try {
            notifyStart(executed);

            if (cancelRequested || Thread.currentThread().isInterrupted()) {
                executed.setError("Request cancelled by user");
                notifyComplete(executed);
                return executed;
            }
            
            // ATOR-style: if auto-refresh is on and the bearer is expiring/expired,
            // refresh it before sending and rewrite the Authorization header in-place.
            if (authManager != null && authManager.isAutoRefreshEnabled()) {
                try {
                    String fresh = authManager.ensureFreshTokenBlocking(15000);
                    if (fresh != null && !fresh.isEmpty()) {
                        List<PostmanCollection.Header> rewritten = new ArrayList<>();
                        for (PostmanCollection.Header h : headers) {
                            if (h != null && h.key != null && "authorization".equalsIgnoreCase(h.key.trim())
                                    && h.value != null && h.value.toLowerCase().startsWith("bearer ")) {
                                PostmanCollection.Header nh = new PostmanCollection.Header();
                                nh.key = h.key;
                                nh.value = "Bearer " + fresh;
                                rewritten.add(nh);
                            } else {
                                rewritten.add(h);
                            }
                        }
                        headers = rewritten;
                    }
                } catch (Exception ignore) { }
            }
            
            // Resolve variables in URL, headers, and body
            String urlBeforeResolve = url;
            String bodyBeforeResolve = bodyText;
            url = resolve(url);
            if (bodyText != null) bodyText = resolve(bodyText);
            // Diagnostic — surface any {{var}} that made it past the resolver.
            // The 1-by-1 Send path was silently sending bodies with literal
            // {{jwt_carrier_token}} because the earlier request in the chain
            // failed and its test script never populated the var. Without this
            // log the user just sees a 401/400 with no clue where it broke.
            try {
                if (burp.service.ScriptExecutor.UI_LOG != null) {
                    String rid = "req@" + Integer.toHexString(System.identityHashCode(executed));
                    int leftInBody = bodyText == null ? 0 : countLiterals(bodyText);
                    int leftInUrl  = url == null ? 0 : countLiterals(url);
                    String tag = "📤 " + rid + " method=" + method
                            + " url=" + (url == null ? "<null>" : url)
                            + " bodyLen=" + (bodyText == null ? 0 : bodyText.length())
                            + " unresolvedInUrl=" + leftInUrl
                            + " unresolvedInBody=" + leftInBody
                            + " resolver@" + (variableResolver == null ? "null" : Integer.toHexString(System.identityHashCode(variableResolver)));
                    burp.service.ScriptExecutor.UI_LOG.accept(tag);
                    if (leftInBody > 0) {
                        java.util.Set<String> names = extractLiteralVarNames(bodyText);
                        burp.service.ScriptExecutor.UI_LOG.accept(
                            "⚠ " + rid + " body still contains unresolved vars: " + names);
                        // Also show the template BEFORE resolve so we can see
                        // whether the resolver stripped/altered it or the vars
                        // were simply not in the resolver map.
                        String preview = bodyBeforeResolve == null ? "<null>" : bodyBeforeResolve;
                        if (preview.length() > 300) preview = preview.substring(0, 300) + "...";
                        burp.service.ScriptExecutor.UI_LOG.accept(
                            "   ↳ body-template: " + preview.replace("\n", "\\n"));
                    }
                    if (leftInUrl > 0) {
                        java.util.Set<String> names = extractLiteralVarNames(url);
                        burp.service.ScriptExecutor.UI_LOG.accept(
                            "⚠ " + rid + " URL still contains unresolved vars: " + names);
                        String preview = urlBeforeResolve == null ? "<null>" : urlBeforeResolve;
                        if (preview.length() > 300) preview = preview.substring(0, 300) + "...";
                        burp.service.ScriptExecutor.UI_LOG.accept(
                            "   ↳ url-template: " + preview);
                    }
                }
            } catch (Throwable ignore) {}
            // Strip any embedded newlines/CRs in the URL — Postman's URL
            // editor stores user-typed wrap breaks (between query params)
            // as literal "\n", and they'd otherwise be written into the raw
            // HTTP request line and Burp Repeater shows them as \r \n
            // markers, while the server returns 400 Bad Request.
            if (url != null && (url.indexOf('\n') >= 0 || url.indexOf('\r') >= 0)) {
                url = url.replace("\r", "").replace("\n", "");
            }
            List<PostmanCollection.Header> resolvedHeaders = new ArrayList<>();
            boolean hasAuthorization = false;
            for (PostmanCollection.Header h : headers) {
                PostmanCollection.Header newH = new PostmanCollection.Header();
                newH.key = resolve(h.key);
                newH.value = resolve(h.value);
                // Drop empty Authorization or Authorization with empty scheme token
                // (e.g. "Bearer ", "Basic ") which Postman silently omits. Sending
                // these crashes some servers and is never desirable.
                if (newH.key != null && "authorization".equalsIgnoreCase(newH.key.trim())) {
                    String v = newH.value == null ? "" : newH.value.trim();
                    String vl = v.toLowerCase();
                    if (v.isEmpty()
                            || vl.equals("bearer")  || vl.startsWith("bearer ")  && v.substring(6).trim().isEmpty()
                            || vl.equals("basic")   || vl.startsWith("basic ")   && v.substring(5).trim().isEmpty()
                            || vl.equals("digest")  || vl.startsWith("digest ")  && v.substring(6).trim().isEmpty()) {
                        continue; // skip this header entirely
                    }
                    hasAuthorization = true;
                }
                resolvedHeaders.add(newH);
            }
            headers = resolvedHeaders;
            try {
                if (burp.service.ScriptExecutor.UI_LOG != null && !hasAuthorization) {
                    String rid = "req@" + Integer.toHexString(System.identityHashCode(executed));
                    burp.service.ScriptExecutor.UI_LOG.accept(
                        "ℹ " + rid + " no Authorization header (auth may have been dropped as empty {{token}})");
                }
            } catch (Throwable ignore) {}
            
            long startTime = System.currentTimeMillis();
            
            try {
                // Parse URL to get host info
                java.net.URL parsedUrl = new java.net.URL(url);
                String host = parsedUrl.getHost();
                int port = parsedUrl.getPort();
                boolean isHttps = "https".equalsIgnoreCase(parsedUrl.getProtocol());
                if (port == -1) port = isHttps ? 443 : 80;
                
                String path = parsedUrl.getPath();
                if (parsedUrl.getQuery() != null) {
                    path += "?" + parsedUrl.getQuery();
                }
                if (path.isEmpty()) path = "/";
                // Strip whitespace from the request line. The UI may show
                // "q=Washington, DC" (space comes from a Postman env value),
                // but a literal space inside the request line is forbidden
                // by HTTP and produces a 400 Bad Request. We strip rather
                // than URL-encode because:
                //   • Server expects "q=Washington,DC" exactly (per the
                //     Postman team's working request).
                //   • URL-encoding the space to %20 would still differ
                //     from what the server accepts.
                // Also strips any tab/CR/LF that snuck through earlier defenses.
                if (path.indexOf(' ') >= 0 || path.indexOf('\t') >= 0
                        || path.indexOf('\r') >= 0 || path.indexOf('\n') >= 0) {
                    path = path.replace(" ", "")
                               .replace("\t", "")
                               .replace("\r", "")
                               .replace("\n", "");
                }
                
                // Build raw HTTP request
                StringBuilder rawRequest = new StringBuilder();
                rawRequest.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
                rawRequest.append("Host: ").append(host).append("\r\n");
                
                boolean hasContentLength = false;
                boolean hasHost = false;
                boolean hasCookie = false;
                for (PostmanCollection.Header h : headers) {
                    if (h.key != null && h.value != null) {
                        if ("host".equalsIgnoreCase(h.key)) { hasHost = true; continue; }
                        if ("content-length".equalsIgnoreCase(h.key)) hasContentLength = true;
                        if ("cookie".equalsIgnoreCase(h.key)) hasCookie = true;
                        rawRequest.append(h.key).append(": ").append(h.value).append("\r\n");
                    }
                }
                // Inject Cookie header from jar if not already provided
                if (!hasCookie && cookieJar != null) {
                    String cookieHeader = cookieJar.buildCookieHeader(host);
                    if (cookieHeader != null && !cookieHeader.isEmpty()) {
                        rawRequest.append("Cookie: ").append(cookieHeader).append("\r\n");
                    }
                }
                
                byte[] bodyBytes = bodyBytesRaw != null
                    ? bodyBytesRaw
                    : ((bodyText != null && !bodyText.isEmpty())
                        ? bodyText.getBytes(StandardCharsets.UTF_8)
                        : new byte[0]);
                // PUT/POST/PATCH/DELETE always need Content-Length (even if 0)
                // — many servers reject these methods without it.
                if (!hasContentLength && requiresContentLength(method, bodyBytes.length)) {
                    rawRequest.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
                }
                rawRequest.append("\r\n");
                
                byte[] headerBytes = rawRequest.toString().getBytes(StandardCharsets.UTF_8);
                byte[] fullRequest = new byte[headerBytes.length + bodyBytes.length];
                System.arraycopy(headerBytes, 0, fullRequest, 0, headerBytes.length);
                System.arraycopy(bodyBytes, 0, fullRequest, headerBytes.length, bodyBytes.length);
                
                // Build Montoya HttpRequest
                burp.api.montoya.http.HttpService httpService = 
                    burp.api.montoya.http.HttpService.httpService(host, port, isHttps);
                
                burp.api.montoya.http.message.requests.HttpRequest httpRequest = 
                    burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                        httpService,
                        burp.api.montoya.core.ByteArray.byteArray(fullRequest)
                    );

                if (cancelRequested || Thread.currentThread().isInterrupted()) {
                    executed.setError("Request cancelled by user");
                    long endTime = System.currentTimeMillis();
                    executed.setDurationMs(endTime - startTime);
                    notifyComplete(executed);
                    return executed;
                }
                
                // Send via Burp with a hard timeout so a stuck socket can't
                // hold the extension worker forever.
                burp.api.montoya.http.message.HttpRequestResponse response =
                    sendRequestWithTimeout(httpRequest, HTTP_SEND_TIMEOUT_MS);

                if (cancelRequested || Thread.currentThread().isInterrupted()) {
                    executed.setError("Request cancelled by user");
                } else if (response != null && response.response() != null) {
                    burp.api.montoya.http.message.responses.HttpResponse httpResp = response.response();
                    
                    executed.setStatusCode(httpResp.statusCode());
                    executed.setStatusText(HttpUtils.getStatusText(httpResp.statusCode()));
                    
                    // Extract response body
                    String responseBody = httpResp.bodyToString();
                    executed.setResponseBody(responseBody);
                    
                    // Extract response headers
                    List<PostmanCollection.Header> responseHeaders = new ArrayList<>();
                    for (burp.api.montoya.http.message.HttpHeader hdr : httpResp.headers()) {
                        PostmanCollection.Header h = new PostmanCollection.Header();
                        h.key = hdr.name();
                        h.value = hdr.value();
                        responseHeaders.add(h);
                        if ("content-type".equalsIgnoreCase(hdr.name())) {
                            executed.setContentType(hdr.value());
                        }
                    }
                    executed.setResponseHeaders(responseHeaders);
                    
                    // Capture Set-Cookie into the cookie jar
                    if (cookieJar != null) {
                        cookieJar.capture(host, responseHeaders);
                    }
                    
                    // Add to Burp sitemap
                    api.siteMap().add(response);
                } else {
                    executed.setError("No response received");
                }
                
            } catch (Exception e) {
                if (cancelRequested || Thread.currentThread().isInterrupted()) {
                    executed.setError("Request cancelled by user");
                } else if (e instanceof TimeoutException) {
                    executed.setError("Request timed out after " + HTTP_SEND_TIMEOUT_MS + " ms");
                } else {
                    executed.setError("Failed to send request: " + e.getMessage());
                    /* swallowed */
                }
            }
            
            long endTime = System.currentTimeMillis();
            executed.setDurationMs(endTime - startTime);
            
            notifyComplete(executed);
            
        } catch (Exception e) {
            executed.setError(e.getMessage());
            notifyError(executed, e);
        }
        
        return executed;
    }

    private burp.api.montoya.http.message.HttpRequestResponse sendRequestWithTimeout(
            burp.api.montoya.http.message.requests.HttpRequest request,
            long timeoutMs) throws Exception {
        long waitMs = Math.max(1000L, timeoutMs);
        ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "burpman-http-request");
            t.setDaemon(true);
            return t;
        });
        Future<burp.api.montoya.http.message.HttpRequestResponse> future =
            executor.submit(() -> burp.service.ProxyRouter.sendRequest(api, request));
        try {
            return future.get(waitMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException ex) {
            future.cancel(true);
            throw new TimeoutException(
                "Timed out waiting for response after " + waitMs + " ms");
        } catch (InterruptedException ex) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw ex;
        } catch (ExecutionException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw new RuntimeException(cause);
        } finally {
            executor.shutdownNow();
        }
    }
    
    public void addListener(ExecutionListener listener) {
        listeners.add(listener);
    }
    
    public void removeListener(ExecutionListener listener) {
        listeners.remove(listener);
    }
    
    private void notifyStart(ExecutedRequest request) {
        for (ExecutionListener listener : listeners) {
            try {
                listener.onRequestStart(request);
            } catch (Exception e) {
                /* swallowed */
            }
        }
    }
    
    private void notifyComplete(ExecutedRequest request) {
        for (ExecutionListener listener : listeners) {
            try {
                listener.onRequestComplete(request);
            } catch (Exception e) {
                /* swallowed */
            }
        }
    }
    
    private void notifyError(ExecutedRequest request, Throwable error) {
        for (ExecutionListener listener : listeners) {
            try {
                listener.onRequestError(request, error);
            } catch (Exception e) {
                /* swallowed */
            }
        }
    }

    /** Methods that semantically carry a body always need Content-Length, even
     *  when the body is empty — many servers reject PUT/POST/PATCH/DELETE
     *  without it. For body-less methods we only emit one if there's an actual
     *  body to send (uncommon but legal for e.g. GET with a body). */
    private static boolean requiresContentLength(String method, int bodyLen) {
        if (method == null) return bodyLen > 0;
        String m = method.toUpperCase();
        switch (m) {
            case "POST":
            case "PUT":
            case "PATCH":
            case "DELETE":
                return true;
            default:
                return bodyLen > 0;
        }
    }
}
