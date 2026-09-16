package burp.service;

import burp.models.ScriptContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Bruno collections read an OAuth token back through
 * {@code req.req.oauth2CredentialVariables["$oauth2.<id>.access_token"]} and copy it into an
 * environment variable. Without those entries the script dies on an undefined lookup.
 */
class OAuth2CredentialVariablesTest {

   private static void runScript(ScriptContext ctx, String script) {
      try {
         new RhinoScriptEngine(ctx, null).run(script);
      } catch (Exception ex) {
         throw new IllegalStateException("script failed: " + ex.getMessage(), ex);
      }
   }

   private static ScriptContext contextWith(Map<String, String> credentials) {
      ScriptContext ctx = new ScriptContext();
      ctx.setOauth2CredentialVariables(credentials);
      return ctx;
   }

   @Test
   @DisplayName("a script can read the access token and store it in an environment variable")
   void readsAccessTokenIntoEnvVar() {
      Map<String, String> credentials = new LinkedHashMap<>();
      credentials.put("$oauth2.credentials.access_token", "TOKEN-ABC-123");
      ScriptContext ctx = contextWith(credentials);

      runScript(ctx, "let token = req.req.oauth2CredentialVariables[\"$oauth2.credentials.access_token\"];\n"
            + "bru.setEnvVar(\"entra_access_token\", token);");

      assertEquals("TOKEN-ABC-123", ctx.getEnvironmentVariables().get("entra_access_token"));
   }

   @Test
   @DisplayName("a missing credential reads as undefined rather than throwing on the lookup")
   void missingCredentialDoesNotThrowOnLookup() {
      ScriptContext ctx = contextWith(new LinkedHashMap<>());

      // The lookup itself must not blow up; that is what made the collection fail with
      // "cannot read property 'oauth2CredentialVariables' of undefined".
      runScript(ctx, "let v = req.req.oauth2CredentialVariables[\"$oauth2.nope.access_token\"];\n"
            + "bru.setEnvVar(\"probe\", v === undefined ? \"absent\" : \"present\");");

      assertEquals("absent", ctx.getEnvironmentVariables().get("probe"));
   }

   @Test
   @DisplayName("a custom credentials id is honoured")
   void honoursCustomCredentialsId() {
      Map<String, String> credentials = new LinkedHashMap<>();
      credentials.put("$oauth2.mycreds.access_token", "CUSTOM-TOKEN");
      ScriptContext ctx = contextWith(credentials);

      runScript(ctx, "bru.setEnvVar(\"t\", req.req.oauth2CredentialVariables[\"$oauth2.mycreds.access_token\"]);");

      assertEquals("CUSTOM-TOKEN", ctx.getEnvironmentVariables().get("t"));
   }

   @Test
   @DisplayName("the credential bag is always present so property access never fails")
   void credentialBagAlwaysPresent() {
      ScriptContext ctx = new ScriptContext();

      runScript(ctx, "bru.setEnvVar(\"kind\", typeof req.req.oauth2CredentialVariables);");

      assertEquals("object", ctx.getEnvironmentVariables().get("kind"));
   }

   @Test
   @DisplayName("refresh and id tokens come through when the provider returned them")
   void exposesRefreshAndIdTokens() {
      Map<String, String> credentials = new LinkedHashMap<>();
      credentials.put("$oauth2.credentials.access_token", "A");
      credentials.put("$oauth2.credentials.refresh_token", "R");
      credentials.put("$oauth2.credentials.id_token", "I");
      ScriptContext ctx = contextWith(credentials);

      runScript(ctx, "const c = req.req.oauth2CredentialVariables;\n"
            + "bru.setEnvVar(\"joined\", c[\"$oauth2.credentials.access_token\"]"
            + " + c[\"$oauth2.credentials.refresh_token\"]"
            + " + c[\"$oauth2.credentials.id_token\"]);");

      assertEquals("ARI", ctx.getEnvironmentVariables().get("joined"));
   }

   @Test
   @DisplayName("the sample collection's own pre-request script runs to completion")
   void runsTheRealCollectionScript() {
      Map<String, String> credentials = new LinkedHashMap<>();
      credentials.put("$oauth2.credentials.access_token", "ENTRA-TOKEN");
      ScriptContext ctx = contextWith(credentials);

      // Verbatim from Sample Service.json, request "01 - Entra Generate Token".
      runScript(ctx, "let token = req.req.oauth2CredentialVariables[\"$oauth2.credentials.access_token\"];"
            + "bru.setEnvVar(\"entra_access_token\", token);");

      assertEquals("ENTRA-TOKEN", ctx.getEnvironmentVariables().get("entra_access_token"));
      assertTrue(ctx.getConsoleOutput() == null || !ctx.getConsoleOutput().contains("TypeError"),
         "script must not raise a TypeError: " + ctx.getConsoleOutput());
   }

   @Test
   @DisplayName("bru.getOauth2CredentialVar is available, as it is in Bruno")
   void supportsBruAccessor() {
      Map<String, String> credentials = new LinkedHashMap<>();
      credentials.put("$oauth2.credentials.access_token", "ENTRA-TOKEN");
      ScriptContext ctx = contextWith(credentials);

      // Verbatim from the OpenCollection "01 - Entra Generate Token.yml", including the
      // line breaks. req.req only exists in Bruno's developer mode, so collections are
      // expected to use this accessor instead.
      runScript(ctx, "const token = bru.getOauth2CredentialVar(\n"
            + "  \"$oauth2.credentials.access_token\"\n"
            + ");\n\n"
            + "bru.setEnvVar(\"entra_access_token\", token);");

      assertEquals("ENTRA-TOKEN", ctx.getEnvironmentVariables().get("entra_access_token"));
   }

   @Test
   @DisplayName("the accessor stores the bare token, with no scheme prefix")
   void accessorYieldsBareToken() {
      Map<String, String> credentials = new LinkedHashMap<>();
      credentials.put("$oauth2.credentials.access_token", "eyJhbGciOiJSUzI1NiJ9.body.sig");
      ScriptContext ctx = contextWith(credentials);

      runScript(ctx, "bru.setEnvVar(\"t\", bru.getOauth2CredentialVar(\"$oauth2.credentials.access_token\"));");

      String stored = ctx.getEnvironmentVariables().get("t");
      // A collection putting this in a header of its own choosing, such as x-authorization,
      // needs the token alone; a Bearer prefix there is not parseable by the gateway.
      assertFalse(stored.toLowerCase().startsWith("bearer"), "expected a bare token but got: " + stored);
      assertEquals("eyJhbGciOiJSUzI1NiJ9.body.sig", stored);
   }

   @Test
   @DisplayName("an unknown credential key reads as absent rather than failing the call")
   void unknownCredentialKeyIsAbsent() {
      ScriptContext ctx = contextWith(new LinkedHashMap<>());

      runScript(ctx, "const v = bru.getOauth2CredentialVar(\"$oauth2.nope.access_token\");\n"
            + "bru.setEnvVar(\"probe\", v ? \"present\" : \"absent\");");

      assertEquals("absent", ctx.getEnvironmentVariables().get("probe"));
   }
}

