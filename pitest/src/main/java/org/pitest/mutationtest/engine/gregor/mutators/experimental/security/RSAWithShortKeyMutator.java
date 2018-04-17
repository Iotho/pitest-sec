package org.pitest.mutationtest.engine.gregor.mutators.experimental.security;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodInfo;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public enum RSAWithShortKeyMutator implements MethodMutatorFactory {

  RSA_WITH_SHORT_KEY_MUTATOR;

  @Override
  public MethodVisitor create(final MutationContext context,
      final MethodInfo methodInfo, final MethodVisitor methodVisitor) {
    return new RSAWithShortKeyVisitor(context, methodVisitor, this);
  }

  @Override
  public String getGloballyUniqueId() {
    return this.getClass().getName();
  }

  @Override
  public String getName() {
    return name();
  }

  public class RSAWithShortKeyVisitor extends AbstractVisitorSimplified {

    private final MethodMutatorFactory factory;
    private final MutationContext      context;
    private final int seen1stInstruction1RSADecl                     = 11;
    private final int seen1stInstruction2KeypairgeneratorGetinstance = 12;
    private final int seen1stInstruction3KeypairgeneratorStore       = 13;
    private final int seen2dInstructionKeypairgeneratorLoad          = 21;
    private final int seen2dInstructionSipush                        = 22;
    private int sipushOperand;
    private int keyPairGeneratorLocalVariableIndex = 0;

    RSAWithShortKeyVisitor(final MutationContext context,
        final MethodVisitor writer, final MethodMutatorFactory factory) {
      super(context, writer, factory);
      this.factory = factory;
      this.context = context;
    }

    @Override
    public void visitIntInsn(int opcode, int operand) {
      if (state == seen2dInstructionKeypairgeneratorLoad) {
        if ((opcode == Opcodes.SIPUSH) && (operand >= 2048)) {
          state = seen2dInstructionSipush;
          sipushOperand = operand;
          mv.visitIntInsn(opcode, operand);
          return;
        }
      }

      visitInsn();
      mv.visitIntInsn(opcode, operand);
    }

    @Override
    public void visitVarInsn(int opcode, int var) {
      if (state == seen1stInstruction2KeypairgeneratorGetinstance) {
        if (opcode == Opcodes.ASTORE) {
          keyPairGeneratorLocalVariableIndex = var;
          state = seen1stInstruction3KeypairgeneratorStore;
          mv.visitVarInsn(opcode, var);
          return;
        }
      }

      if (state == seen1stInstruction3KeypairgeneratorStore) {
        if (opcode == Opcodes.ALOAD && var == keyPairGeneratorLocalVariableIndex) {
          state = seen2dInstructionKeypairgeneratorLoad;
          mv.visitVarInsn(opcode, var);
          return;
        }
      }
      visitInsn();
      mv.visitVarInsn(opcode, var);
    }

    @Override
    public void visitLdcInsn(Object cst) {
      if ((cst instanceof Integer) && (state
          == seen2dInstructionKeypairgeneratorLoad)) {
        Integer pushed = (Integer) cst;
        if (pushed.intValue() >= 2048) {
          state = seen2dInstructionSipush;
          sipushOperand = pushed.intValue();
          mv.visitLdcInsn(cst);
          return;
        }
      }

      if ((cst instanceof String) && (state == seennothing)) {
        if (isRSA((String) cst)) {
          state = seen1stInstruction1RSADecl;
          mv.visitLdcInsn(cst);
          return;
        }
      }
      visitInsn();
      mv.visitLdcInsn(cst);
    }

    @Override
    public void visitMethodInsn(int opcode, String owner, String name,
        String desc, boolean itf) {

      if ((opcode == Opcodes.INVOKESTATIC) && (owner
          .equals("java/security/KeyPairGenerator")) && (name
          .equals("getInstance")) && (desc
          .equals("(Ljava/lang/String;)Ljava/security/KeyPairGenerator;"))
          && (!itf) && (state == seen1stInstruction1RSADecl)) {

        state = seen1stInstruction2KeypairgeneratorGetinstance;
        mv.visitMethodInsn(opcode, owner, name, desc, itf);
        return;
      }

      if ((opcode == Opcodes.INVOKEVIRTUAL) && (owner
          .equals("java/security/KeyPairGenerator")) && (name
          .equals("initialize")) && (desc.equals("(I)V")) && (!itf) && (state
          == seen2dInstructionSipush)) {
        final MutationIdentifier newId = this.context
            .registerMutation(this.factory,
                "*SECURITY* replaced KeyPairGenerator.initialize("
                    + sipushOperand
                    + ") with KeyPairGenerator.initialize(512) ");

        if (this.context.shouldMutate(newId)) {
          mv.visitInsn(Opcodes.POP);
          mv.visitIntInsn(Opcodes.SIPUSH, 512);
        }

        mv.visitMethodInsn(opcode, owner, name, desc, itf);
        state = seennothing;
        return;
      }

      visitInsn();
      mv.visitMethodInsn(opcode, owner, name, desc, itf);
    }

    private boolean isRSA(String argument) {
      try {
        String begining = argument.substring(0, 3);

        String stringpattern = "[rR][sS][aA]";
        Pattern pattern = Pattern.compile(stringpattern);

        Matcher matcher = pattern.matcher(begining);
        return matcher.find();

      } catch (IndexOutOfBoundsException e) {
        // wasn't RSA.
        return false;
      }

    }

    @Override
    protected void visitInsn() {
      if (state >= seen1stInstruction3KeypairgeneratorStore) {
        state = seen1stInstruction3KeypairgeneratorStore;
        return;
      }
      state = seennothing;
    }
  }
}
