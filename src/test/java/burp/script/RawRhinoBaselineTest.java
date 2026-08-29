package burp.script;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Scriptable;

/**
 * Characterisation probe: is a given behaviour our preprocessing, or the
 * engine underneath? Runs source through raw Rhino with no BurpMan rewriting.
 * Not an assertion suite — it prints so the answer is on the record.
 */
@DisplayName("Raw Rhino baseline (diagnostic)")
class RawRhinoBaselineTest {

    private static String raw(String js) {
        Context cx = Context.enter();
        try {
            cx.setOptimizationLevel(-1);
            cx.setLanguageVersion(Context.VERSION_ES6);
            Scriptable scope = cx.initStandardObjects();
            return String.valueOf(Context.toString(
                cx.evaluateString(scope, js, "<raw>", 1, null)));
        } catch (Throwable t) {
            return "THREW " + t.getClass().getSimpleName();
        } finally {
            Context.exit();
        }
    }

    @Test
    @DisplayName("record raw-engine behaviour for the two known gaps")
    void recordBaseline() {
        System.out.println("[raw rhino] for(let) capture      = "
            + raw("var f=[];for(let i=0;i<3;i++){f.push(function(){return i;});}"
                + "f[0]()+','+f[1]()+','+f[2]();"));
        System.out.println("[raw rhino] const reassign        = "
            + raw("(function(){const a=1;try{a=2;return 'no-throw:'+a;}"
                + "catch(e){return 'TypeError';}})();"));
        System.out.println("[raw rhino] let block shadowing   = "
            + raw("let x='outer';{let x='inner';}x;"));
    }
}
