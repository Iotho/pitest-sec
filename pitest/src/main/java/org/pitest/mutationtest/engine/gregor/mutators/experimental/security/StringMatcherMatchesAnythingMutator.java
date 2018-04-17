package org.pitest.mutationtest.engine.gregor.mutators.experimental.security;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodInfo;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;


public enum StringMatcherMatchesAnythingMutator
    implements MethodMutatorFactory {

  STRING_MATCHER_MATCHES_ANYTHING_MUTATOR;

  @Override
  public MethodVisitor create(final MutationContext context,
      final MethodInfo methodInfo, final MethodVisitor methodVisitor) {
    return new StringMatcherMatchesAnythingVisitor(context, methodVisitor,
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

class StringMatcherMatchesAnythingVisitor extends MethodVisitor {

  private final MethodMutatorFactory factory;
  private final MutationContext      context;

  StringMatcherMatchesAnythingVisitor(final MutationContext context,
      final MethodVisitor writer, final MethodMutatorFactory factory) {
    super(Opcodes.ASM5, writer);
    this.factory = factory;
    this.context = context;
  }

  @Override
  public void visitMethodInsn(int opcode, String owner, String name,
      String desc, boolean itf) {

    if ((opcode == Opcodes.INVOKEVIRTUAL) && (owner.equals("java/lang/String")) && (name
        .equals("matches")) && (desc.equals("(Ljava/lang/String;)Z"))
        && (!itf)) {

      final MutationIdentifier newId = this.context
          .registerMutation(this.factory,
              "*NEW* changed String.matches(String regex) to String.matches(\"([^¤]*)\")");

      if (this.context.shouldMutate(newId)) {
        mv.visitInsn(Opcodes.POP);
        mv.visitLdcInsn("([^\u00a4]*)"); // == ([^¤]*)
        mv.visitMethodInsn(opcode, owner, name, desc, itf);
        return;
      }
    }
    mv.visitMethodInsn(opcode, owner, name, desc, itf);
  }
}