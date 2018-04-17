package org.pitest.mutationtest.engine.gregor.mutators.experimental.security;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodInfo;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;


public enum UseMD5ForEncryptionJAVAStandardMutator
    implements MethodMutatorFactory {

  USE_MD5_FOR_ENCRYPTION_JAVA_STANDARD_MUTATOR;

  @Override
  public MethodVisitor create(final MutationContext context,
      final MethodInfo methodInfo, final MethodVisitor methodVisitor) {
    return new UseMD5ForEncryptionJAVAStandardVisitor(context, methodVisitor,
        this);
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

class UseMD5ForEncryptionJAVAStandardVisitor extends MethodVisitor {

  private final MethodMutatorFactory factory;
  private final MutationContext      context;

  UseMD5ForEncryptionJAVAStandardVisitor(final MutationContext context,
      final MethodVisitor writer, final MethodMutatorFactory factory) {
    super(Opcodes.ASM5, writer);
    this.factory = factory;
    this.context = context;
  }

  @Override
  public void visitMethodInsn(int opcode, String owner, String name,
      String desc, boolean itf) {

    if ((opcode == Opcodes.INVOKESTATIC) && (owner
        .equals("java/security/MessageDigest")) && (name.equals("getInstance"))
        && (desc.equals("(Ljava/lang/String;)Ljava/security/MessageDigest;"))
        && (!itf)) {

      final MutationIdentifier newId = this.context
          .registerMutation(this.factory,
              "*SECURITY* Replaced MessageDigest.getInstance(String) with MessageDigest.getInstance(\"MD5\")");

      if (this.context.shouldMutate(newId)) {
        mv.visitInsn(Opcodes.POP);          // pop definition of the message digest
        mv.visitLdcInsn("MD5");     // push MD5
        mv.visitMethodInsn(opcode, owner, name, desc, itf);
        return;
      }
    }
    mv.visitMethodInsn(opcode, owner, name, desc, itf);
  }
}
