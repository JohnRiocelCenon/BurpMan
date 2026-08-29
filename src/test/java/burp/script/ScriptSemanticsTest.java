package burp.script;

import burp.models.ScriptContext;
import burp.service.RhinoScriptEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static burp.script.ScriptFixture.lastLog;
import static burp.script.ScriptFixture.lastLogQuiet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Guards ECMAScript semantics that Postman and Bruno collections rely on.
 *
 * <p>Every expectation here is the value Node.js/V8 produces — the runtime
 * collection authors actually test against. BurpMan 1.0.0 failed the first
 * three because it rewrote every {@code let}/{@code const} to {@code var}
 * unconditionally, which silently changes scoping and produces wrong values
 * rather than an error. That class of bug surfaces as an unexplainable 401
 * far downstream, so these are regression-critical.
 */
@DisplayName("Script semantics match V8")
class ScriptSemanticsTest {

    @Test
    @DisplayName("for(let i) gives each closure its own binding")
    void forLetClosureCapture() throws Exception {
        // Classic loop-capture. Rhino has no per-iteration binding, so the
        // engine alone returns 3,3,3 (see RawRhinoBaselineTest). The
        // preprocessor restores V8 behaviour by wrapping the body. Common in
        // pm.sendRequest fan-out loops.
        assertEquals("0,1,2", lastLog(
            "var f=[];"
          + "for(let i=0;i<3;i++){f.push(function(){return i;});}"
          + "console.log(f[0]()+','+f[1]()+','+f[2]());"));
    }

    @Test
    @DisplayName("a loop body that cannot be wrapped safely is left alone and warned about")
    void forLetWithControlFlowIsNotSilentlyBroken() {
        // `break` cannot cross a function boundary, so the rewrite is skipped.
        // The contract is that the user is TOLD, rather than silently getting
        // the wrong captured value.
        ScriptContext ctx = new ScriptContext();
        try {
            new RhinoScriptEngine(ctx, null).run(
                "var f=[];"
              + "for(let i=0;i<3;i++){ if(i>5) break; f.push(function(){return i;}); }"
              + "console.log('done');");
        } catch (Throwable t) {
            fail("the loop must still execute, not throw: " + t);
        }
        String logged = String.valueOf(ctx.getConsoleOutput());
        assertTrue(logged.contains("warning:") && logged.contains("per-iteration"),
            "expected an explicit warning about the capture, log was:\n" + logged);
    }

    @Test
    @DisplayName("const cannot be silently reassigned")
    void constIsImmutable() {
        // V8 throws TypeError; Rhino 1.7.15 silently discards the assignment
        // (verified in RawRhinoBaselineTest). Both are acceptable — what must
        // never happen is the write landing, because a mutated `const
        // jwtSecret` signs with the wrong key and surfaces as a 401.
        String result = lastLogQuiet(
            "try{const a=1;a=2;console.log('value:'+a);}"
          + "catch(e){console.log('TypeError');}");
        assertTrue("TypeError".equals(result) || "value:1".equals(result),
            "const was reassigned — got [" + result + "]");
    }

    @Test
    @DisplayName("let in a nested block does not leak to the enclosing scope")
    void letBlockShadowing() throws Exception {
        // The dangerous one: if the inner binding leaks, a script that
        // shadows `jwtSecret` inside a branch signs with the wrong key.
        assertEquals("outer", lastLog(
            "let x='outer';{let x='inner';}console.log(x);"));
    }

    @Test
    @DisplayName("let redeclaration across sibling blocks is tolerated")
    void letRedeclarationAcrossBlocksStillWorks() throws Exception {
        // Why the downgrade existed in the first place. Cascaded collection
        // scripts get concatenated, so the same name is declared twice at
        // top level. This must keep working after the semantics fix.
        assertEquals("second", lastLog(
            "let token='first';\nlet token='second';\nconsole.log(token);"));
    }

    @Test
    @DisplayName("const redeclaration in concatenated scripts is tolerated")
    void constRedeclarationAcrossConcatenatedScripts() throws Exception {
        assertEquals("B", lastLog(
            "const CryptoJS='A';\nconst CryptoJS='B';\nconsole.log(CryptoJS);"));
    }

    @Test
    @DisplayName("'?.' inside a string literal is not rewritten")
    void optionalChainingInStringSurvives() throws Exception {
        assertEquals("is a?.b ok", lastLog("var s='is a?.b ok';console.log(s);"));
    }

    @Test
    @DisplayName("'??' inside a string literal is not rewritten")
    void nullishInStringSurvives() throws Exception {
        assertEquals("q??q", lastLog("var s='q??q';console.log(s);"));
    }

    @Test
    @DisplayName("the word 'await' inside a string survives")
    void awaitWordInStringSurvives() throws Exception {
        assertEquals("please await confirmation",
            lastLog("var s='please await confirmation';console.log(s);"));
    }

    @Test
    @DisplayName("split() on a regex metacharacter splits literally")
    void splitOnRegexMetachar() throws Exception {
        // Postman scripts do Location.split('?')[1].split('&') constantly.
        assertEquals("b", lastLog("console.log('a?b'.split('?')[1]);"));
    }

    @Test
    @DisplayName("object spread is supported")
    void objectSpread() throws Exception {
        assertEquals("12", lastLog("var a={x:1},b={...a,y:2};console.log(b.x+''+b.y);"));
    }

    @Test
    @DisplayName("optional chaining short-circuits on null")
    void optionalChainingWorks() throws Exception {
        assertEquals("undefined",
            lastLog("var o=null;console.log(String(o?.a?.b));"));
    }

    @Test
    @DisplayName("nullish coalescing keeps falsy-but-defined values")
    void nullishCoalescingWorks() throws Exception {
        // `0 ?? 9` is 0, unlike `0 || 9` which is 9.
        assertEquals("0", lastLog("var v=0;console.log(String(v ?? 9));"));
    }

    @Test
    @DisplayName("template literals interpolate")
    void templateLiterals() throws Exception {
        assertEquals("a-b", lastLog("var x='a',y='b';console.log(`${x}-${y}`);"));
    }

    @Test
    @DisplayName("arrow functions and array methods work")
    void arrowFunctions() throws Exception {
        assertEquals("2,4,6",
            lastLog("console.log([1,2,3].map(n=>n*2).join(','));"));
    }

    @Test
    @DisplayName("destructuring assignment works")
    void destructuring() throws Exception {
        assertEquals("1|2", lastLog("const {a,b}={a:1,b:2};console.log(a+'|'+b);"));
    }
}
