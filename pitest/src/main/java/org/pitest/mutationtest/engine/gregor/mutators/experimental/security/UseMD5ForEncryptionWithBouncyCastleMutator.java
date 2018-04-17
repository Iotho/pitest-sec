package org.pitest.mutationtest.engine.gregor.mutators.experimental.security;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodInfo;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

public enum UseMD5ForEncryptionWithBouncyCastleMutator
    implements MethodMutatorFactory {

  USE_MD5_FOR_ENCRYPTION_WITH_BOUNCY_CASTLE;

  @Override
  public MethodVisitor create(final MutationContext context,
      final MethodInfo methodInfo, final MethodVisitor methodVisitor) {
    return new UseMD5ForEncryptionWithBouncyCastleVisitor(context,
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

class UseMD5ForEncryptionWithBouncyCastleVisitor extends MethodVisitor {

  private final MethodMutatorFactory factory;
  private final MutationContext      context;

  UseMD5ForEncryptionWithBouncyCastleVisitor(final MutationContext context,
      final MethodVisitor writer, final MethodMutatorFactory factory) {
    super(Opcodes.ASM5, writer);
    this.factory = factory;
    this.context = context;
  }

  @Override
  public void visitMethodInsn(int opcode, String owner, String name,
      String desc, boolean itf) {

    if ((opcode == Opcodes.INVOKESPECIAL) && (owner.equals(
        "org/bouncycastle/crypto/generators/PKCS5S2ParametersGenerator"))
        && (name.equals("<init>")) && (desc
        .equals("(Lorg/bouncycastle/crypto/Digest;)V")) && (!itf)) {

      final MutationIdentifier newId = this.context
          .registerMutation(this.factory,
              "*Security* Replaced the digest used in \"new PKCS5S2ParametersGenerator(Digest)\" with a MD5Digest");

      if (this.context.shouldMutate(newId)) {
        // 1: Remove the reference to SHA256Digest Object
        mv.visitInsn(Opcodes.POP);

        // 2: Put a reference to an initialized MD5Digest Object
        mv.visitTypeInsn(Opcodes.NEW, "org/bouncycastle/crypto/digests/MD5Digest");
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL,
            "org/bouncycastle/crypto/digests/MD5Digest", "<init>", "()V",
            false);

        // NOW PROCEED WITH ORIGINAL CALL:
        mv.visitMethodInsn(opcode, owner, name, desc, itf);
        return;
      }
    }
    mv.visitMethodInsn(opcode, owner, name, desc, itf);
  }
}
