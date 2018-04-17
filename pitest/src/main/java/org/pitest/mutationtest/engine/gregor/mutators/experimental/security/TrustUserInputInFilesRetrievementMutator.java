package org.pitest.mutationtest.engine.gregor.mutators.experimental.security;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodInfo;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;


public enum TrustUserInputInFilesRetrievementMutator
    implements MethodMutatorFactory {

  TRUST_USER_INPUT_IN_FILES_RETRIEVEMENT;

  @Override
  public MethodVisitor create(final MutationContext context,
      final MethodInfo methodInfo, final MethodVisitor methodVisitor) {
    return new TrustUserInputInFilesRetrievementVisitor(context, methodVisitor,
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

class TrustUserInputInFilesRetrievementVisitor extends MethodVisitor {

  private final MethodMutatorFactory factory;
  private final MutationContext      context;

  TrustUserInputInFilesRetrievementVisitor(final MutationContext context,
      final MethodVisitor writer, final MethodMutatorFactory factory) {
    super(Opcodes.ASM5, writer);
    this.factory = factory;
    this.context = context;
  }

  @Override
  public void visitMethodInsn(int opcode, String owner, String name,
      String desc, boolean itf) {

    if ((opcode == Opcodes.INVOKESTATIC) && (owner
        .equals("org/apache/commons/io/FilenameUtils")) && (name
        .equals("getName")) && (desc
        .equals("(Ljava/lang/String;)Ljava/lang/String;")) && (!itf)) {

      final MutationIdentifier newId = this.context
          .registerMutation(this.factory,
              "*Security* removed FileNameUtils.getName(String)");

      if (this.context.shouldMutate(newId)) {
        // remove everything
        return;
      }
    }
    mv.visitMethodInsn(opcode, owner, name, desc, itf);
  }

}

