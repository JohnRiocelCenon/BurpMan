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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Bruno's single-file JSON export.
 *
 * <p>Unlike Postman, this format carries its environments inside the collection
 * file, and Bruno resolves against them on load. Ignoring the array meant a user
 * who opened the one file they were given saw every {{var}} unresolved and had
 * to know a second environment file existed somewhere - the collection looked
 * broken rather than merely unconfigured.
 */
class BrunoCollectionJsonTest {

    @TempDir
    Path tmp;

    private PostmanCollection parse(String json) throws Exception {
        File f = tmp.resolve("c.json").toFile();
        Files.write(f.toPath(), json.getBytes(StandardCharsets.UTF_8));
        return new PostmanParser().parseCollection(f);
    }

    private String varValue(PostmanCollection c, String key) {
        if (c.variable == null) return null;
        for (PostmanCollection.Variable v : c.variable) {
            if (key.equals(v.key)) return v.value;
        }
        return null;
    }

    private static String collection(String extra, String envs) {
        return "{\n"
                + "  \"name\": \"Sample\",\n"
                + "  \"version\": \"1\",\n"
                + extra
                + "  \"items\": [\n"
                + "    { \"type\": \"http\", \"name\": \"R\", \"seq\": 1,\n"
                + "      \"request\": { \"url\": \"{{api_url}}/v1/go\", \"method\": \"POST\",\n"
                + "        \"headers\": [], \"params\": [],\n"
                + "        \"auth\": { \"mode\": \"bearer\", \"bearer\": { \"token\": \"{{tok}}\" } } } }\n"
                + "  ],\n"
                + envs
                + "  \"brunoConfig\": { \"version\": \"1\", \"name\": \"Sample\", \"type\": \"collection\" }\n"
                + "}\n";
    }

    @Test
    void detectsTheBrunoJsonExportFormat() throws Exception {
        File f = tmp.resolve("c.json").toFile();
        Files.write(f.toPath(), collection("", "").getBytes(StandardCharsets.UTF_8));

        assertEquals(CollectionFormatDetector.Format.BRUNO_COLLECTION_JSON,
                CollectionFormatDetector.detect(f));
    }

    @Test
    void embeddedEnvironmentVariablesAreLoaded() throws Exception {
        PostmanCollection c = parse(collection("",
                "  \"environments\": [\n"
                        + "    { \"name\": \"UAT\", \"variables\": [\n"
                        + "        { \"name\": \"api_url\", \"value\": \"https://uat.example.com\", \"enabled\": true },\n"
                        + "        { \"name\": \"tok\", \"value\": \"abc\", \"enabled\": true }\n"
                        + "    ] }\n"
                        + "  ],\n"));

        assertEquals("https://uat.example.com", varValue(c, "api_url"));
        assertEquals("abc", varValue(c, "tok"));
    }

    /** The whole point: one file, and the request URL resolves. */
    @Test
    void requestUrlResolvesFromTheEmbeddedEnvironmentAlone() throws Exception {
        PostmanCollection c = parse(collection("",
                "  \"environments\": [\n"
                        + "    { \"name\": \"UAT\", \"variables\": [\n"
                        + "        { \"name\": \"api_url\", \"value\": \"https://uat.example.com\", \"enabled\": true }\n"
                        + "    ] }\n"
                        + "  ],\n"));

        VariableResolver r = new VariableResolver();
        r.addCollectionVariables(c);

        assertEquals("https://uat.example.com/v1/go",
                r.resolve(String.valueOf(c.item.get(0).request.url)));
    }

    /** A named active environment wins over document order, as Bruno shows it. */
    @Test
    void activeEnvironmentUidSelectsWhichEnvironmentApplies() throws Exception {
        PostmanCollection c = parse(collection("  \"activeEnvironmentUid\": \"env-prod\",\n",
                "  \"environments\": [\n"
                        + "    { \"uid\": \"env-uat\",  \"name\": \"UAT\",  \"variables\": [\n"
                        + "        { \"name\": \"api_url\", \"value\": \"https://uat.example.com\", \"enabled\": true } ] },\n"
                        + "    { \"uid\": \"env-prod\", \"name\": \"PROD\", \"variables\": [\n"
                        + "        { \"name\": \"api_url\", \"value\": \"https://prod.example.com\", \"enabled\": true } ] }\n"
                        + "  ],\n"));

        assertEquals("https://prod.example.com", varValue(c, "api_url"));
    }

    /** With no active uid named, the first environment is used. */
    @Test
    void firstEnvironmentIsUsedWhenNoActiveUidIsNamed() throws Exception {
        PostmanCollection c = parse(collection("",
                "  \"environments\": [\n"
                        + "    { \"name\": \"UAT\",  \"variables\": [\n"
                        + "        { \"name\": \"api_url\", \"value\": \"https://uat.example.com\", \"enabled\": true } ] },\n"
                        + "    { \"name\": \"PROD\", \"variables\": [\n"
                        + "        { \"name\": \"api_url\", \"value\": \"https://prod.example.com\", \"enabled\": true } ] }\n"
                        + "  ],\n"));

        assertEquals("https://uat.example.com", varValue(c, "api_url"));
    }

    @Test
    void disabledEmbeddedVariableIsSkipped() throws Exception {
        PostmanCollection c = parse(collection("",
                "  \"environments\": [\n"
                        + "    { \"name\": \"UAT\", \"variables\": [\n"
                        + "        { \"name\": \"live\", \"value\": \"yes\", \"enabled\": true },\n"
                        + "        { \"name\": \"off\",  \"value\": \"no\",  \"enabled\": false }\n"
                        + "    ] }\n"
                        + "  ],\n"));

        assertEquals("yes", varValue(c, "live"));
        assertNull(varValue(c, "off"), "a disabled variable must not be loaded");
    }

    /** A secret keeps its type so the UI can mask it. */
    @Test
    void secretVariablesAreTyped() throws Exception {
        PostmanCollection c = parse(collection("",
                "  \"environments\": [\n"
                        + "    { \"name\": \"UAT\", \"variables\": [\n"
                        + "        { \"name\": \"client_secret\", \"value\": \"\", \"enabled\": true, \"secret\": true }\n"
                        + "    ] }\n"
                        + "  ],\n"));

        assertNotNull(c.variable);
        for (PostmanCollection.Variable v : c.variable) {
            if ("client_secret".equals(v.key)) assertEquals("secret", v.type);
        }
    }

    /** A collection with no environments block must still parse. */
    @Test
    void collectionWithoutEnvironmentsStillParses() throws Exception {
        PostmanCollection c = parse(collection("", ""));

        assertEquals(1, c.item.size());
        assertEquals("R", c.item.get(0).name);
        assertTrue(c.variable == null || c.variable.isEmpty());
    }

    /** Requests keep parsing normally alongside the new environment handling. */
    @Test
    void requestsAreUnaffected() throws Exception {
        PostmanCollection c = parse(collection("",
                "  \"environments\": [ { \"name\": \"UAT\", \"variables\": [] } ],\n"));

        PostmanCollection.Item r = c.item.get(0);
        assertEquals("POST", r.request.method);
        assertNotNull(r.request.auth);
        assertEquals("bearer", r.request.auth.type);
    }
}
