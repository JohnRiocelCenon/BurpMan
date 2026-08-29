package burp.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

final class OAuthProxyCallbackCapture {
    private OAuthProxyCallbackCapture() {
    }

    static boolean canCapture(String callbackUrl) {
        URI cb = parseUri(callbackUrl);
        return cb != null && cb.getHost() != null && !cb.getHost().trim().isEmpty();
    }

    static String awaitCodeFromProxy(
            MontoyaApi api,
            String callbackUrl,
            int timeoutSeconds,
            long startedAtMillis) throws Exception {
        if (api == null || !canCapture(callbackUrl)) return null;

        URI cb = parseUri(callbackUrl);
        if (cb == null) return null;

        String host = normalizeHost(cb.getHost());
        String path = cb.getPath();
        if (path == null || path.trim().isEmpty()) path = "/";

        Set<String> seenUrls = new HashSet<>();
        long deadline = System.currentTimeMillis() + Math.max(10, timeoutSeconds) * 1000L;

        while (System.currentTimeMillis() < deadline) {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            for (ProxyHttpRequestResponse row : history) {
                if (!matches(row, host, path, startedAtMillis)) continue;
                HttpRequest req = effectiveRequest(row);
                if (req == null) continue;

                String reqUrl = req.url();
                if (reqUrl != null && !seenUrls.add(reqUrl)) continue;

                String code = req.parameterValue("code", HttpParameterType.URL);
                if (code != null && !code.trim().isEmpty()) {
                    return urlDecode(code.trim());
                }

                String error = req.parameterValue("error", HttpParameterType.URL);
                if (error != null && !error.trim().isEmpty()) {
                    String errorDesc = req.parameterValue("error_description", HttpParameterType.URL);
                    String message = urlDecode(error.trim());
                    if (errorDesc != null && !errorDesc.trim().isEmpty()) {
                        message = message + ": " + urlDecode(errorDesc.trim());
                    }
                    throw new IllegalStateException("OAuth callback error: " + message);
                }
            }
            Thread.sleep(400L);
        }

        return null;
    }

    static String awaitAnyCodeFromProxy(
            MontoyaApi api,
            int timeoutSeconds,
            long startedAtMillis) throws Exception {
        if (api == null) return null;

        Set<String> seenUrls = new HashSet<>();
        long deadline = System.currentTimeMillis() + Math.max(10, timeoutSeconds) * 1000L;

        while (System.currentTimeMillis() < deadline) {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            for (ProxyHttpRequestResponse row : history) {
                if (!matchesAny(row, startedAtMillis)) continue;
                HttpRequest req = effectiveRequest(row);
                if (req == null) continue;

                String reqUrl = req.url();
                if (reqUrl != null && !seenUrls.add(reqUrl)) continue;

                String code = req.parameterValue("code", HttpParameterType.URL);
                if (code != null && !code.trim().isEmpty()) {
                    return urlDecode(code.trim());
                }

                String error = req.parameterValue("error", HttpParameterType.URL);
                if (error != null && !error.trim().isEmpty()) {
                    String errorDesc = req.parameterValue("error_description", HttpParameterType.URL);
                    String message = urlDecode(error.trim());
                    if (errorDesc != null && !errorDesc.trim().isEmpty()) {
                        message = message + ": " + urlDecode(errorDesc.trim());
                    }
                    throw new IllegalStateException("OAuth callback error: " + message);
                }
            }
            Thread.sleep(400L);
        }

        return null;
    }

    private static boolean matches(ProxyHttpRequestResponse row, String host, String path, long startedAtMillis) {
        if (row == null) return false;
        ZonedDateTime zdt = row.time();
        if (zdt != null && zdt.toInstant().toEpochMilli() + 1000L < startedAtMillis) return false;

        HttpRequest req = effectiveRequest(row);
        if (req == null || req.httpService() == null) return false;

        String rowHost = normalizeHost(req.httpService().host());
        if (!host.equals(rowHost)) return false;

        String rowPath = req.pathWithoutQuery();
        if (rowPath == null || rowPath.trim().isEmpty()) rowPath = "/";
        return rowPath.equals(path);
    }

    private static boolean matchesAny(ProxyHttpRequestResponse row, long startedAtMillis) {
        if (row == null) return false;
        ZonedDateTime zdt = row.time();
        return zdt == null || zdt.toInstant().toEpochMilli() + 1000L >= startedAtMillis;
    }

    private static HttpRequest effectiveRequest(ProxyHttpRequestResponse row) {
        if (row == null) return null;
        return row.finalRequest() != null ? row.finalRequest() : row.request();
    }

    private static URI parseUri(String value) {
        if (value == null || value.trim().isEmpty()) return null;
        try {
            return URI.create(value.trim());
        } catch (Exception ex) {
            return null;
        }
    }

    private static String normalizeHost(String host) {
        if (host == null) return "";
        String h = host.trim().toLowerCase(Locale.ROOT);
        if (h.startsWith("[") && h.endsWith("]")) {
            return h.substring(1, h.length() - 1);
        }
        return h;
    }

    private static String urlDecode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }
}
