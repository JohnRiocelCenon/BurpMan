package burp.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.models.PostmanEnvironment;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Environment parsing for Bruno's {@code opencollection: 1.0.0} format.
 *
 * <p>These collections do not store a bare scalar. A value arrives wrapped as
 * {@code {type: object, data: "<json>"}}, and requests address the pieces by
 * dotted path — {@code {{gb.exp.apim.url}}}, never {@code {{gb}}}. Keeping only
 * the declared name leaves every reference unresolved while the environment
 * still reports a plausible variable count, so the failure surfaces as "loaded,
 * but nothing resolves" rather than as a parse error.
 */
class BrunoYamlEnvironmentTest {

    @TempDir
    Path tmp;

    private PostmanEnvironment parse(String yaml) throws Exception {
        File f = tmp.resolve("env.yml").toFile();
        Files.write(f.toPath(), yaml.getBytes(StandardCharsets.UTF_8));
        return BrunoYamlParser.parseEnvironment(f);
    }

    private String value(PostmanEnvironment env, String key) {
        String found = null;
        for (PostmanEnvironment.Value v : env.values) {
            // Last enabled write wins, matching VariableResolver's merge order.
            if (key.equals(v.key) && v.enabled && v.value != null) found = v.value;
        }
        return found;
    }

    private String resolved(PostmanEnvironment env, String text) {
        VariableResolver r = new VariableResolver();
        r.addEnvironmentVariables(env);
        return r.resolve(text);
    }

    @Test
    void flattensObjectValuesIntoDottedPaths() throws Exception {
        PostmanEnvironment env = parse(
                "name: uat\n"
                        + "variables:\n"
                        + "  - name: gb\n"
                        + "    value:\n"
                        + "      type: object\n"
                        + "      data: |-\n"
                        + "        {\n"
                        + "          \"exp\": {\n"
                        + "            \"apim\": {\n"
                        + "              \"url\": \"https://api.uat.example.com/ext\",\n"
                        + "              \"base\": { \"path\": \"/group/ca\" }\n"
                        + "            }\n"
                        + "          }\n"
                        + "        }\n");

        assertEquals("https://api.uat.example.com/ext", value(env, "gb.exp.apim.url"));
        assertEquals("/group/ca", value(env, "gb.exp.apim.base.path"));
    }

    @Test
    void resolvesAUrlBuiltFromTwoNestedVariables() throws Exception {
        PostmanEnvironment env = parse(
                "name: uat\n"
                        + "variables:\n"
                        + "  - name: gb\n"
                        + "    value:\n"
                        + "      type: object\n"
                        + "      data: |-\n"
                        + "        { \"exp\": { \"apim\": {\n"
                        + "            \"url\": \"https://api.uat.example.com/ext\",\n"
                        + "            \"base\": { \"path\": \"/group/ca\" } } } }\n");

        assertEquals("https://api.uat.example.com/ext/group/ca/v1/benefits/identity/authorize",
                resolved(env, "{{gb.exp.apim.url}}{{gb.exp.apim.base.path}}/v1/benefits/identity/authorize"));
    }

    /**
     * OpenCollection switches an entry off with {@code disabled: true}, not
     * {@code enabled: false}. Reading only the latter activates variables the
     * author turned off, and because a stale duplicate normally sits after the
     * live one, the dead value wins — silently, with the right variable count.
     */
    @Test
    void disabledDuplicateDoesNotOverrideTheLiveValue() throws Exception {
        PostmanEnvironment env = parse(
                "name: uat\n"
                        + "variables:\n"
                        + "  - name: user\n"
                        + "    value:\n"
                        + "      type: object\n"
                        + "      data: |-\n"
                        + "        { \"cert\": \"114652:257461\" }\n"
                        + "  - name: user\n"
                        + "    value:\n"
                        + "      type: object\n"
                        + "      data: |-\n"
                        + "        { \"cert\": \"97500:9\" }\n"
                        + "    disabled: true\n");

        assertEquals("114652:257461", value(env, "user.cert"));
    }

    /** The mirror of the case above: the live entry is the second one. */
    @Test
    void enabledDuplicateWinsWhenItComesSecond() throws Exception {
        PostmanEnvironment env = parse(
                "name: uat\n"
                        + "variables:\n"
                        + "  - name: user\n"
                        + "    value:\n"
                        + "      type: object\n"
                        + "      data: |-\n"
                        + "        { \"cert\": \"114652:257461\" }\n"
                        + "    disabled: true\n"
                        + "  - name: user\n"
                        + "    value:\n"
                        + "      type: object\n"
                        + "      data: |-\n"
                        + "        { \"cert\": \"97500:9\" }\n");

        assertEquals("97500:9", value(env, "user.cert"));
    }

    /**
     * A declared-but-unset secret must not resolve. Substituting an empty value
     * produces a 401 that reads as a credentials fault, when the real problem is
     * that the variable was never supplied.
     */
    @Test
    void declaredSecretWithNoValueStaysUnresolved() throws Exception {
        PostmanEnvironment env = parse(
                "name: uat\n"
                        + "variables:\n"
                        + "  - secret: true\n"
                        + "    name: gb.apim.client.secret\n"
                        + "    disabled: true\n");

        assertNull(value(env, "gb.apim.client.secret"));
        assertEquals("{{gb.apim.client.secret}}", resolved(env, "{{gb.apim.client.secret}}"));
    }

    /** A disabled secret placeholder must not mask the same key from an object. */
    @Test
    void objectValueSurvivesADisabledSecretOfTheSameName() throws Exception {
        PostmanEnvironment env = parse(
                "name: uat\n"
                        + "variables:\n"
                        + "  - name: gb\n"
                        + "    value:\n"
                        + "      type: object\n"
                        + "      data: |-\n"
                        + "        { \"apim\": { \"client\": { \"id\": \"K169Azz\" } } }\n"
                        + "  - secret: true\n"
                        + "    name: gb.apim.client.id\n"
                        + "    disabled: true\n");

        assertEquals("K169Azz", value(env, "gb.apim.client.id"));
    }

    /** Numbers and booleans substitute as written, not as quoted JSON. */
    @Test
    void primitivesKeepTheirUnquotedForm() throws Exception {
        PostmanEnvironment env = parse(
                "name: uat\n"
                        + "variables:\n"
                        + "  - name: cfg\n"
                        + "    value:\n"
                        + "      type: object\n"
                        + "      data: |-\n"
                        + "        { \"index\": 1, \"specific\": true }\n");

        assertEquals("1", value(env, "cfg.index"));
        assertEquals("true", value(env, "cfg.specific"));
    }

    /** The declared name keeps the whole document, so {{gb}} still works. */
    @Test
    void containerKeepsItsJson() throws Exception {
        PostmanEnvironment env = parse(
                "name: uat\n"
                        + "variables:\n"
                        + "  - name: gb\n"
                        + "    value:\n"
                        + "      type: object\n"
                        + "      data: |-\n"
                        + "        { \"apim\": { \"id\": \"x\" } }\n");

        assertEquals("{\"id\":\"x\"}", value(env, "gb.apim"));
        assertTrue(value(env, "gb").contains("\"apim\""));
    }

    /** A plain scalar must keep working exactly as before. */
    @Test
    void plainScalarValuesAreUnchanged() throws Exception {
        PostmanEnvironment env = parse(
                "name: uat\n"
                        + "variables:\n"
                        + "  - name: host\n"
                        + "    value: https://example.com\n"
                        + "  - name: off\n"
                        + "    value: nope\n"
                        + "    enabled: false\n");

        assertEquals("https://example.com", value(env, "host"));
        assertNull(value(env, "off"));
    }

    /** A value that merely looks like JSON but is malformed stays a string. */
    @Test
    void malformedJsonIsKeptAsAScalar() throws Exception {
        PostmanEnvironment env = parse(
                "name: uat\n"
                        + "variables:\n"
                        + "  - name: broken\n"
                        + "    value: \"{not json\"\n");

        assertEquals("{not json", value(env, "broken"));
        assertFalse(env.values.stream().anyMatch(v -> v.key.startsWith("broken.")));
    }
}
