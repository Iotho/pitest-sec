package org.pitest.mutationtest.engine.gregor.mutators.experimental.security;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UseBLOWFISHWithShortKeyVisitor extends AbstractVisitorSimplified {

  private final MethodMutatorFactory factory;
  private final MutationContext      context;
  private final int seenFirstInstruction1BlowfishDecl            = 11;
  private final int seenFirstInstruction2KeygeneratorGetinstance = 12;
  private final int seenFirstInstruction3KeygeneratorStore       = 13;
  private final int seenSecondInstruction1KeygeneratorLoad       = 21;
  private final int seenSecondInstruction2Bipush                 = 22;
  private int bipushOperand;
  private int keyGeneratorLocalVariableIndex = 0;

  UseBLOWFISHWithShortKeyVisitor(final MutationContext context,
      final MethodVisitor writer, final MethodMutatorFactory factory) {
    super(context, writer, factory);
    this.factory = factory;
    this.context = context;
  }

  @Override
  public void visitIntInsn(int opcode, int operand) {
    if (state == seenSecondInstruction1KeygeneratorLoad) {
      if ((opcode == Opcodes.SIPUSH) && (operand >= 128)) {
        state = seenSecondInstruction2Bipush;
        bipushOperand = operand;
        mv.visitIntInsn(opcode, operand);
        return;
      }
    }

    visitInsn();
    mv.visitIntInsn(opcode, operand);
  }

  @Override
  public void visitVarInsn(int opcode, int var) {
    if (state == seenFirstInstruction2KeygeneratorGetinstance) {
      if (opcode == Opcodes.ASTORE) {
        keyGeneratorLocalVariableIndex = var;
        state = seenFirstInstruction3KeygeneratorStore;
        mv.visitVarInsn(opcode, var);
        return;
      }
    }

    if (state == seenFirstInstruction3KeygeneratorStore) {
      if (opcode == Opcodes.ALOAD && var == keyGeneratorLocalVariableIndex) {
        state = seenSecondInstruction1KeygeneratorLoad;
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
        == seenSecondInstruction1KeygeneratorLoad)) {
      Integer pushed = (Integer) cst;
      if (pushed.intValue() >= 128) {
        state = seenSecondInstruction2Bipush;
        bipushOperand = pushed.intValue();
        mv.visitLdcInsn(cst);
        return;
      }
    }

    if ((cst instanceof String) && state == seennothing) {
      if (isBlowFish((String) cst)) {
        state = seenFirstInstruction1BlowfishDecl;
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

    // BEFORE DOING: mv.visitMethodInsn(INVOKESTATIC,
    // "javax/crypto/KeyGenerator", "getInstance",
    // "(Ljava/lang/String;)Ljavax/crypto/KeyGenerator;", false);
    if ((opcode == Opcodes.INVOKESTATIC) && (owner.equals("javax/crypto/KeyGenerator"))
        && (name.equals("getInstance")) && (desc
        .equals("(Ljava/lang/String;)Ljavax/crypto/KeyGenerator;")) && (!itf)
        && (state == seenFirstInstruction1BlowfishDecl)) {

      state = seenFirstInstruction2KeygeneratorGetinstance;
      mv.visitMethodInsn(opcode, owner, name, desc, itf);
      return;

    }

    // BEFORE DOING: mv.visitMethodInsn(INVOKEVIRTUAL,
    // "javax/crypto/KeyGenerator", "init", "(I)V", false);
    if ((opcode == Opcodes.INVOKEVIRTUAL) && (owner.equals("javax/crypto/KeyGenerator"))
        && (name.equals("init")) && (desc.equals("(I)V")) && (!itf) && (state
        == seenSecondInstruction2Bipush)) {

      final MutationIdentifier newId = this.context
          .registerMutation(this.factory,
              "*NEW* replaced KeyGenerator.init(" + bipushOperand + ")"
                  + " with KeyGenerator.init(64)");

      if (this.context.shouldMutate(newId)) {
        mv.visitInsn(Opcodes.POP);
        mv.visitIntInsn(Opcodes.BIPUSH, 64);
      }

      mv.visitMethodInsn(opcode, owner, name, desc, itf);
      state = seennothing;
      return;
    }

    visitInsn();
    mv.visitMethodInsn(opcode, owner, name, desc, itf);

  }

  private boolean isBlowFish(String argument) {
    try {
      String begining = argument.substring(0, 8);

      String stringpattern = "[bB][lL][oO][wW][fF][iI][sS][hH]";
      Pattern pattern = Pattern.compile(stringpattern);

      Matcher matcher = pattern.matcher(begining);
      return matcher.find();
    } catch (IndexOutOfBoundsException e) {
      // wasn't blowfish.
      return false;
    }
  }

  @Override
  protected void visitInsn() {
    if (state >= seenFirstInstruction3KeygeneratorStore) {
      state = seenFirstInstruction3KeygeneratorStore;
      return;
    }
    state = seennothing;
  }

}