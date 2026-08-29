package burp.codegen;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class CodeGeneratorRegistry {
   private static final Map<String, CodeGenerator> GENERATORS = new LinkedHashMap<>();

   static {
      register(new CurlGenerator(true));
      register(new CurlGenerator(false));
      register(new PythonRequestsGenerator());
      register(new PythonHttpxGenerator());
      register(new JavaScriptFetchGenerator());
      register(new JavaScriptAxiosGenerator());
      register(new NodeHttpGenerator());
      register(new JavaOkHttpGenerator());
      register(new JavaHttpClient5Generator());
      register(new GoNetHttpGenerator());
      register(new PowerShellGenerator());
      register(new PhpCurlGenerator());
      register(new RubyNetHttpGenerator());
      register(new RustReqwestGenerator());
      register(new CSharpHttpClientGenerator());
   }

   private CodeGeneratorRegistry() {
   }

   private static void register(CodeGenerator g) {
      GENERATORS.put(g.label(), g);
   }

   public static List<CodeGenerator> all() {
      return Collections.unmodifiableList(new ArrayList<>(GENERATORS.values()));
   }

   public static CodeGenerator byLabel(String label) {
      return GENERATORS.get(label);
   }
}
