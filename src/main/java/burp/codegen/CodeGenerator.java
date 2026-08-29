package burp.codegen;

public interface CodeGenerator {
   String label();

   String fileExtension();

   String generate(GenRequest var1);
}
