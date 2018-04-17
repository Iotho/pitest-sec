package org.pitest.mutationtest.engine.gregor.mutators.experimental.security;

import org.objectweb.asm.MethodVisitor;

public class RunnableForSQLInjection implements Runnable {
  private MethodVisitor mv;
  private int           opcodef;
  private int           varf;

  public RunnableForSQLInjection(MethodVisitor mv, int opcode, int var) {
    this.mv = mv;
    this.opcodef = opcode;
    this.varf = var;
  }

  @Override
  public void run() {
    mv.visitVarInsn(opcodef, varf);
  }

}
