package org.pitest.mutationtest.engine.gregor.mutators.experimental.security;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodInfo;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

public enum UseWeakPseudoRandomNumberGeneratorMutator
    implements MethodMutatorFactory {

  USE_WEAK_PSEUDO_RANDOM_NUMBER_GENERATOR_MUTATOR;

  @Override
  public MethodVisitor create(final MutationContext context,
      final MethodInfo methodInfo, final MethodVisitor methodVisitor) {
    return new UseWeakPseudoRandomNumberGeneratorVisitor(context, methodVisitor,
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

class UseWeakPseudoRandomNumberGeneratorVisitor extends MethodVisitor {

  private final MethodMutatorFactory factory;
  private final MutationContext      context;

  UseWeakPseudoRandomNumberGeneratorVisitor(final MutationContext context,
      final MethodVisitor writer, final MethodMutatorFactory factory) {
    super(Opcodes.ASM5, writer);
    this.factory = factory;
    this.context = context;
  }

  @Override
  public void visitMethodInsn(int opcode, String owner, String name,
      String desc, boolean itf) {

    if ((opcode == Opcodes.INVOKEVIRTUAL) && (owner
        .equals("java/security/SecureRandom")) && (name.equals("nextBytes"))
        && (desc.equals("([B)V")) && (!itf)) {

      final MutationIdentifier newId = this.context
          .registerMutation(this.factory,
              "*SECURITY* Replaced call to SecureRandom.nextBytes(byteArray) with call to Random.nextBytes(byteArray)");

      if (this.context.shouldMutate(newId)) {
        // create new Random object
        mv.visitTypeInsn(Opcodes.NEW, "java/util/Random");

        // duplicate ref
        mv.visitInsn(Opcodes.DUP);

        // initialize it
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/util/Random", "<init>", "()V",
            false);

        // have the byte array over the Random Object
        mv.visitInsn(Opcodes.SWAP);

        // proceed to Random.nextBytes(byteArray)
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Random", "nextBytes",
            "([B)V", false); // call

        // delete the ref to the SecureRandom
        mv.visitInsn(Opcodes.POP);
        return;
      }
    }
    mv.visitMethodInsn(opcode, owner, name, desc, itf);
  }
}
