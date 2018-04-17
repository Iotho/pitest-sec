package org.pitest.mutationtest.engine.gregor.mutators.experimental.security;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodInfo;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

public enum DisableDOCTYPEVerificationOnXMLParserWithSAXMutator
    implements MethodMutatorFactory {

  XML_PARSER_VULNERABLE_TO_XXE_WITH_SAX;

  @Override
  public MethodVisitor create(final MutationContext context,
      final MethodInfo methodInfo, final MethodVisitor methodVisitor) {
    return new DisableDOCTYPEVerificationOnXMLParserWithSAXVisitor(context,
        methodVisitor, this);
  }

  @Override
  public String getGloballyUniqueId() {
    return this.getClass().getName();
  }

  @Override
  public String getName() {
    return name();
  }
}

class DisableDOCTYPEVerificationOnXMLParserWithSAXVisitor
    extends MethodVisitor {

  private final MethodMutatorFactory factory;
  private final MutationContext      context;

  DisableDOCTYPEVerificationOnXMLParserWithSAXVisitor(
      final MutationContext context, final MethodVisitor writer,
      final MethodMutatorFactory factory) {
    super(Opcodes.ASM5, writer);
    this.factory = factory;
    this.context = context;
  }

  @Override
  public void visitMethodInsn(int opcode, String owner, String name,
      String desc, boolean itf) {

    if ((opcode == Opcodes.INVOKEVIRTUAL) && (owner
        .equals("javax/xml/parsers/SAXParserFactory")) && (name
        .equals("newSAXParser")) && (desc
        .equals("()Ljavax/xml/parsers/SAXParser;")) && (!itf)) {

      final MutationIdentifier newId = this.context
          .registerMutation(this.factory,
              "*SECURITY* added SAXParserFactory.setFeature(http://apache.org/xml/features/disallow-doctype-decl,false) before this line");

      if (this.context.shouldMutate(newId)) {

        // copy reference to SAXParserFactory
        mv.visitInsn(Opcodes.DUP);

        // set disallow-doctype-decl to false
        mv.visitLdcInsn("http://apache.org/xml/features/disallow-doctype-decl");
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "javax/xml/parsers/SAXParserFactory",
            "setFeature", "(Ljava/lang/String;Z)V", false);

        // create the SAXParser (original code)
        mv.visitMethodInsn(opcode, owner, name, desc, itf);

        return;
      }
    }
    mv.visitMethodInsn(opcode, owner, name, desc, itf);
  }

}
