package org.pitest.mutationtest.engine.gregor.mutators.experimental.security;

import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

public abstract class AbstractVisitorForBigPatterns extends MethodVisitor {

  protected final int seennothing = 0;
  private final MethodMutatorFactory factory;
  private final MutationContext      context;
  protected int state = seennothing;

  AbstractVisitorForBigPatterns(final MutationContext context,
      final MethodVisitor writer, final MethodMutatorFactory factory) {
    super(Opcodes.ASM5, writer);
    this.factory = factory;
    this.context = context;
  }

  @Override
  public void visitFieldInsn(int opcode, String owner, String name,
      String desc) {
    visitInsn();
    mv.visitFieldInsn(opcode, owner, name, desc);
  }

  @Override
  public void visitIincInsn(int var, int increment) {
    visitInsn();
    mv.visitIincInsn(var, increment);
  }

  @Override
  public void visitInsn(int opcode) {
    visitInsn();
    mv.visitInsn(opcode);
  }

  @Override
  public void visitIntInsn(int opcode, int operand) {
    visitInsn();
    mv.visitIntInsn(opcode, operand);
  }

  @Override
  public void visitInvokeDynamicInsn(String name, String desc, Handle bsm,
      Object... bsmArgs) {
    visitInsn();
    mv.visitInvokeDynamicInsn(name, desc, bsm, bsmArgs);
  }

  @Override
  public void visitJumpInsn(int opcode, Label label) {
    visitInsn();
    mv.visitJumpInsn(opcode, label);
  }

  @Override
  public void visitLdcInsn(Object cst) {
    visitInsn();
    mv.visitLdcInsn(cst);
  }

  @Override
  public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
    visitInsn();
    mv.visitLookupSwitchInsn(dflt, keys, labels);
  }

  @Override
  public void visitMethodInsn(int opcode, String owner, String name,
      String desc, boolean itf) {
    visitInsn();
    mv.visitMethodInsn(opcode, owner, name, desc, itf);
  }

  @Override
  public void visitMultiANewArrayInsn(String desc, int dims) {
    visitInsn();
    mv.visitMultiANewArrayInsn(desc, dims);
  }

  @Override
  public void visitTableSwitchInsn(int min, int max, Label dflt,
      Label... labels) {
    visitInsn();
    mv.visitTableSwitchInsn(min, max, dflt, labels);
  }

  @Override
  public void visitMethodInsn(int opcode, String owner, String name,
      String desc) {
    visitInsn();
    mv.visitMethodInsn(opcode, owner, name, desc);
  }

  @Override
  public void visitTypeInsn(int opcode, String type) {
    visitInsn();
    mv.visitTypeInsn(opcode, type);
  }

  @Override
  public void visitVarInsn(int opcode, int var) {
    visitInsn();
    mv.visitVarInsn(opcode, var);
  }

  @Override
  public void visitMaxs(int maxStack, int maxLocals) {
    visitInsn();
    mv.visitMaxs(maxStack, maxLocals);
  }

  @Override
  public void visitFrame(int type, int nLocal, Object[] local, int nStack,
      Object[] stack) {
    visitInsn();
    //System.out.println("asking reinit from visitFrame " + nLocal);
    mv.visitFrame(type, nLocal, local, nStack, stack);
  }

  @Override
  public void visitLabel(Label label) {
    visitInsn();
    //System.out.println("asking reinit from visitLabel ");
    mv.visitLabel(label);
  }

  protected abstract void visitInsn();
}