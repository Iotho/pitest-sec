package org.pitest.mutationtest.engine.gregor.mutators.experimental.security;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodInfo;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

public enum DisableDOCTYPEVerificationOnXMLParserWithXMLReaderMutator
    implements MethodMutatorFactory {

  XML_PARSER_VULNERABLE_TO_XXE_WITH_XMLREADER;

  @Override
  public MethodVisitor create(final MutationContext context,
      final MethodInfo methodInfo, final MethodVisitor methodVisitor) {
    return new DisableDOCTYPEVerificationOnXMLParserWithXMLReaderVisitor(
        context, methodVisitor, this);
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

class DisableDOCTYPEVerificationOnXMLParserWithXMLReaderVisitor
    extends MethodVisitor {

  private final MethodMutatorFactory factory;
  private final MutationContext      context;

  DisableDOCTYPEVerificationOnXMLParserWithXMLReaderVisitor(
      final MutationContext context, final MethodVisitor writer,
      final MethodMutatorFactory factory) {
    super(Opcodes.ASM5, writer);
    this.factory = factory;
    this.context = context;
  }

  @Override
  public void visitMethodInsn(int opcode, String owner, String name,
      String desc, boolean itf) {

    if ((opcode == Opcodes.INVOKEINTERFACE) && (owner.equals("org/xml/sax/XMLReader"))
        && (name.equals("parse")) && (desc
        .equals("(Lorg/xml/sax/InputSource;)V")) && (itf)) {

      final MutationIdentifier newId = this.context
          .registerMutation(this.factory,
              "*SECURITY* added XMLReader.setFeature(http://apache.org/xml/features/disallow-doctype-decl, false) before this line");

      if (this.context.shouldMutate(newId)) {

        // have the reference to XMLReader
        mv.visitInsn(Opcodes.SWAP);

        // copy it
        mv.visitInsn(Opcodes.DUP);

        // set dissalow-doctype to false
        mv.visitLdcInsn("http://apache.org/xml/features/disallow-doctype-decl");
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitMethodInsn(Opcodes.INVOKEINTERFACE, "org/xml/sax/XMLReader",
            "setFeature", "(Ljava/lang/String;Z)V", true);

        // SWAP to put the stack the way it was.
        mv.visitInsn(Opcodes.SWAP);

        // Perform original call (parsing)
        mv.visitMethodInsn(opcode, owner, name, desc, itf);
        return;
      }
    }
    mv.visitMethodInsn(opcode, owner, name, desc, itf);
  }
}

