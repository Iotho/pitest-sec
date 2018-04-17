package org.pitest.mutationtest.engine.gregor.mutators.experimental.security;

import org.objectweb.asm.MethodVisitor;
import org.pitest.mutationtest.engine.gregor.MethodInfo;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

public enum UseDESForSymmetricEncryptionMutator
    implements MethodMutatorFactory {

  USE_DES_FOR_SYMMETRIC_ENCRYPTION;

  @Override
  public MethodVisitor create(final MutationContext context,
      final MethodInfo methodInfo, final MethodVisitor methodVisitor) {
    return new UseDESForSymmetricEncryptionVisitor(context, methodVisitor,
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
