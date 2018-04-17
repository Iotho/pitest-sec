package org.pitest.mutationtest.engine.gregor.mutators.experimental.security;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodInfo;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

public enum HostNameVerifyToTrueMutator implements MethodMutatorFactory {

  HOST_NAME_VERIFY_TO_TRUE;

  @Override
  public MethodVisitor create(final MutationContext context,
      final MethodInfo methodInfo, final MethodVisitor methodVisitor) {
    return new HostNameVerifyToTrueVisitor(context, methodVisitor, this);
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

class HostNameVerifyToTrueVisitor extends MethodVisitor {

  private final MethodMutatorFactory factory;
  private final MutationContext      context;

  HostNameVerifyToTrueVisitor(final MutationContext context,
      final MethodVisitor writer, final MethodMutatorFactory factory) {
    super(Opcodes.ASM5, writer);
    this.factory = factory;
    this.context = context;
  }

  @Override
  public void visitMethodInsn(int opcode, String owner, String name,
      String desc, boolean itf) {

    if ((opcode == Opcodes.INVOKEINTERFACE) && (owner
        .equals("javax/net/ssl/HostnameVerifier")) && (name.equals("verify"))
        && (desc.equals("(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z"))
        && (itf)) {

      final MutationIdentifier newId = this.context
          .registerMutation(this.factory,
              "*SECURITY* Replaced HostNameVerifier.verify(String, SSLSession) with \"true\"");

      if (this.context.shouldMutate(newId)) {
        // pop the arguments
        mv.visitInsn(Opcodes.POP);
        mv.visitInsn(Opcodes.POP);

        // push true
        mv.visitInsn(Opcodes.ICONST_1);
        return;
      }
    }
    mv.visitMethodInsn(opcode, owner, name, desc, itf);
  }
}
