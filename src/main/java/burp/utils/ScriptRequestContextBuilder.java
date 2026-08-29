package burp.utils;

import burp.models.PostmanCollection;
import burp.parser.VariableResolver;
import com.google.gson.Gson;

import java.util.ArrayList;
import java.util.List;

/**
 * Builds a script-safe snapshot of the current request context so post-response
 * scripts (pm.request.* in Tests tab) see the resolved values that were sent.
 */
public final class ScriptRequestContextBuilder {
    private ScriptRequestContextBuilder() {}

    public static PostmanCollection.Request fromTemplate(
            PostmanCollection.Request template,
            VariableResolver resolver,
            String resolvedUrl) {
        if (template == null) return null;

        PostmanCollection.Request snapshot = null;
        try {
            Gson gson = new Gson();
            snapshot = gson.fromJson(gson.toJsonTree(template), PostmanCollection.Request.class);
        } catch (Exception ignore) {}
        if (snapshot == null) return template;

        if (resolvedUrl != null && !resolvedUrl.isEmpty()) {
            snapshot.url = resolvedUrl;
        } else if (snapshot.url instanceof String) {
            snapshot.url = resolve(resolver, (String) snapshot.url);
        } else if (snapshot.url instanceof PostmanCollection.Url) {
            resolveUrl((PostmanCollection.Url) snapshot.url, resolver);
        }

        if (snapshot.header != null) {
            for (PostmanCollection.Header h : snapshot.header) {
                if (h == null) continue;
                h.key = resolve(resolver, h.key);
                h.value = resolve(resolver, h.value);
            }
        }

        if (snapshot.body != null) {
            snapshot.body.raw = resolve(resolver, snapshot.body.raw);
            if (snapshot.body.graphql != null) {
                snapshot.body.graphql.query = resolve(resolver, snapshot.body.graphql.query);
                snapshot.body.graphql.variables = resolve(resolver, snapshot.body.graphql.variables);
            }
            if (snapshot.body.urlencoded != null) {
                for (PostmanCollection.UrlEncoded p : snapshot.body.urlencoded) {
                    if (p == null) continue;
                    p.key = resolve(resolver, p.key);
                    p.value = resolve(resolver, p.value);
                }
            }
            if (snapshot.body.formdata != null) {
                for (PostmanCollection.FormData f : snapshot.body.formdata) {
                    if (f == null) continue;
                    f.key = resolve(resolver, f.key);
                    f.value = resolve(resolver, f.value);
                    f.src = resolveFormDataSource(resolver, f.src);
                }
            }
        }

        return snapshot;
    }

    private static String resolve(VariableResolver resolver, String value) {
        if (resolver == null || value == null) return value;
        return resolver.resolve(value);
    }

    private static Object resolveFormDataSource(VariableResolver resolver, Object src) {
        if (resolver == null || src == null) return src;
        if (src instanceof String) {
            return resolver.resolve((String) src);
        }
        if (src instanceof List) {
            List<?> in = (List<?>) src;
            List<Object> out = new ArrayList<>(in.size());
            for (Object v : in) {
                if (v instanceof String) out.add(resolver.resolve((String) v));
                else out.add(v);
            }
            return out;
        }
        return src;
    }

    private static void resolveUrl(PostmanCollection.Url url, VariableResolver resolver) {
        if (url == null || resolver == null) return;
        url.raw = resolve(resolver, url.raw);
        url.protocol = resolve(resolver, url.protocol);
        url.port = resolve(resolver, url.port);
        if (url.host != null) {
            for (int i = 0; i < url.host.size(); i++) {
                url.host.set(i, resolve(resolver, url.host.get(i)));
            }
        }
        if (url.path != null) {
            for (int i = 0; i < url.path.size(); i++) {
                url.path.set(i, resolve(resolver, url.path.get(i)));
            }
        }
        if (url.query != null) {
            for (PostmanCollection.Query q : url.query) {
                if (q == null) continue;
                q.key = resolve(resolver, q.key);
                q.value = resolve(resolver, q.value);
            }
        }
    }
}
