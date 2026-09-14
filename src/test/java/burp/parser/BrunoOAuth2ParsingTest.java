package burp.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.models.PostmanCollection;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * OAuth2 config in a Bruno JSON export.
 *
 * <p>The auth type was recorded as {@code oauth2} but the parser had no case
 * for it, so every field arrived empty: the OAuth2 dialog opened blank and the
 * token request failed with "OAuth2 config is missing auth URL". That points at
 * the collection rather than at the parser that dropped its contents, which is
 * why it read as "BurpMan can't understand this collection".
 */
class BrunoOAuth2ParsingTest {

    @TempDir
    Path tmp;

    private static final String OAUTH2_COLLECTION =
            "{\n"
                    + "  \"name\": \"Sample\",\n"
                    + "  \"items\": [\n"
                    + "    { \"type\": \"http\", \"name\": \"01\", \"seq\": 1,\n"
                    + "      \"request\": { \"url\": \"localhost\", \"method\": \"GET\",\n"
                    + "        \"headers\": [], \"params\": [],\n"
                    + "        \"auth\": { \"mode\": \"oauth2\", \"oauth2\": {\n"
                    + "            \"grantType\": \"authorization_code\",\n"
                    + "            \"callbackUrl\": \"https://app.example.com/cb\",\n"
                    + "            \"authorizationUrl\": \"https://login.example.com/{{tenant}}/authorize\",\n"
                    + "            \"accessTokenUrl\": \"https://login.example.com/{{tenant}}/token\",\n"
                    + "            \"clientId\": \"{{client_id}}\",\n"
                    + "            \"clientSecret\": \"\",\n"
                    + "            \"scope\": \"{{scope}}\",\n"
                    + "            \"credentialsPlacement\": \"body\",\n"
                    + "            \"pkce\": true,\n"
                    + "            \"tokenPlacement\": \"header\",\n"
                    + "            \"tokenHeaderPrefix\": \"\",\n"
                    + "            \"additionalParameters\": { \"token\": [\n"
                    + "                { \"name\": \"Origin\", \"value\": \"https://app.example.com\",\n"
                    + "                  \"enabled\": true, \"sendIn\": \"headers\" } ] }\n"
                    + "        } } } }\n"
                    + "  ],\n"
                    + "  \"brunoConfig\": { \"version\": \"1\", \"name\": \"Sample\", \"type\": \"collection\" }\n"
                    + "}\n";

    @SuppressWarnings("unchecked")
    private List<PostmanCollection.AuthAttribute> oauth2Of(String json) throws Exception {
        File f = tmp.resolve("c.json").toFile();
        Files.write(f.toPath(), json.getBytes(StandardCharsets.UTF_8));
        PostmanCollection c = new PostmanParser().parseCollection(f);
        PostmanCollection.Auth auth = c.item.get(0).request.auth;
        assertNotNull(auth, "auth block must parse");
        assertEquals("oauth2", auth.type);
        return (List<PostmanCollection.AuthAttribute>) auth.oauth2;
    }

    private String attr(List<PostmanCollection.AuthAttribute> attrs, String key) {
        for (PostmanCollection.AuthAttribute a : attrs) {
            if (a.key != null && a.key.equalsIgnoreCase(key)) return a.value;
        }
        return null;
    }

    @Test
    void oauth2AttributesAreNoLongerDropped() throws Exception {
        List<PostmanCollection.AuthAttribute> attrs = oauth2Of(OAUTH2_COLLECTION);

        assertNotNull(attrs, "oauth2 config must not be null");
        assertTrue(attrs.size() >= 10, "expected the full config, got " + attrs.size());
    }

    /** The exact field whose absence produced "missing auth URL". */
    @Test
    void authUrlIsPresentUnderBrunoSpelling() throws Exception {
        List<PostmanCollection.AuthAttribute> attrs = oauth2Of(OAUTH2_COLLECTION);

        assertEquals("https://login.example.com/{{tenant}}/authorize",
                attr(attrs, "authorizationUrl"));
    }

    @Test
    void coreEndpointsAndCredentialsSurvive() throws Exception {
        List<PostmanCollection.AuthAttribute> attrs = oauth2Of(OAUTH2_COLLECTION);

        assertEquals("authorization_code", attr(attrs, "grantType"));
        assertEquals("https://login.example.com/{{tenant}}/token", attr(attrs, "accessTokenUrl"));
        assertEquals("https://app.example.com/cb", attr(attrs, "callbackUrl"));
        assertEquals("{{client_id}}", attr(attrs, "clientId"));
        assertEquals("{{scope}}", attr(attrs, "scope"));
        assertEquals("true", attr(attrs, "pkce"));
    }

    /** Bruno's names have no Postman counterpart, so both spellings are emitted. */
    @Test
    void postmanAliasesAreEmittedAlongsideBrunoNames() throws Exception {
        List<PostmanCollection.AuthAttribute> attrs = oauth2Of(OAUTH2_COLLECTION);

        assertEquals("body", attr(attrs, "credentialsPlacement"));
        assertEquals("body", attr(attrs, "client_authentication"));
        assertEquals("header", attr(attrs, "tokenPlacement"));
        assertEquals("header", attr(attrs, "addTokenTo"));
    }

    /** basic_auth_header is Bruno's spelling of what Postman calls header. */
    @Test
    void basicAuthHeaderPlacementMapsToHeader() throws Exception {
        List<PostmanCollection.AuthAttribute> attrs = oauth2Of(OAUTH2_COLLECTION
                .replace("\"credentialsPlacement\": \"body\"",
                         "\"credentialsPlacement\": \"basic_auth_header\""));

        assertEquals("basic_auth_header", attr(attrs, "credentialsPlacement"));
        assertEquals("header", attr(attrs, "client_authentication"));
    }

    /** A nested block is not a scalar setting; flattening it would be noise. */
    @Test
    void additionalParametersIsNotFlattenedIntoAttributes() throws Exception {
        List<PostmanCollection.AuthAttribute> attrs = oauth2Of(OAUTH2_COLLECTION);

        assertNull(attr(attrs, "additionalParameters"));
        for (PostmanCollection.AuthAttribute a : attrs) {
            assertNotNull(a.value, "every attribute must carry a scalar value");
        }
    }

    /** Values keep their {{placeholders}} so the resolver substitutes later. */
    @Test
    void variablePlaceholdersAreLeftForTheResolver() throws Exception {
        File f = tmp.resolve("c2.json").toFile();
        Files.write(f.toPath(), OAUTH2_COLLECTION
                .replace("\"brunoConfig\"",
                         "\"environments\": [ { \"name\": \"UAT\", \"variables\": ["
                       + " { \"name\": \"tenant\", \"value\": \"abc-123\", \"enabled\": true },"
                       + " { \"name\": \"client_id\", \"value\": \"cid-9\", \"enabled\": true } ] } ],\n"
                       + "  \"brunoConfig\"")
                .getBytes(StandardCharsets.UTF_8));
        PostmanCollection c = new PostmanParser().parseCollection(f);

        @SuppressWarnings("unchecked")
        List<PostmanCollection.AuthAttribute> attrs =
                (List<PostmanCollection.AuthAttribute>) c.item.get(0).request.auth.oauth2;

        VariableResolver r = new VariableResolver();
        r.addCollectionVariables(c);

        assertEquals("https://login.example.com/abc-123/authorize",
                r.resolve(attr(attrs, "authorizationUrl")));
        assertEquals("cid-9", r.resolve(attr(attrs, "clientId")));
    }

    /** The other auth modes must keep working. */
    @Test
    void bearerAuthIsUnaffected() throws Exception {
        File f = tmp.resolve("c3.json").toFile();
        Files.write(f.toPath(), ("{\n"
                + "  \"name\": \"X\",\n"
                + "  \"items\": [ { \"type\": \"http\", \"name\": \"R\", \"seq\": 1,\n"
                + "      \"request\": { \"url\": \"https://e.com/\", \"method\": \"GET\",\n"
                + "        \"auth\": { \"mode\": \"bearer\", \"bearer\": { \"token\": \"{{t}}\" } } } } ],\n"
                + "  \"brunoConfig\": { \"version\": \"1\", \"name\": \"X\", \"type\": \"collection\" }\n"
                + "}\n").getBytes(StandardCharsets.UTF_8));
        PostmanCollection c = new PostmanParser().parseCollection(f);

        assertEquals("bearer", c.item.get(0).request.auth.type);
        assertNotNull(c.item.get(0).request.auth.bearer);
    }
}
