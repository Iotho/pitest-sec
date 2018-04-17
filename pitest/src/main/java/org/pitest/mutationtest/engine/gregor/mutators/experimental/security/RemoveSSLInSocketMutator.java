package org.pitest.mutationtest.engine.gregor.mutators.experimental.security;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodInfo;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

public enum RemoveSSLInSocketMutator implements MethodMutatorFactory {

  REMOVE_SECURE_SOCKET_MUTATOR;

  @Override
  public MethodVisitor create(final MutationContext context,
      final MethodInfo methodInfo, final MethodVisitor methodVisitor) {
    return new RemoveSSLInSocketVisitor(context, methodVisitor, this);
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

class RemoveSSLInSocketVisitor extends MethodVisitor {

  private final MethodMutatorFactory factory;
  private final MutationContext      context;

  RemoveSSLInSocketVisitor(final MutationContext context,
      final MethodVisitor writer, final MethodMutatorFactory factory) {
    super(Opcodes.ASM5, writer);
    this.factory = factory;
    this.context = context;
  }

  @Override
  public void visitMethodInsn(int opcode, String owner, String name,
      String desc, boolean itf) {

    if ((opcode == Opcodes.INVOKEVIRTUAL) && (owner.equals("javax/net/SocketFactory"))
        && (name.equals("createSocket")) && (desc
        .equals("(Ljava/lang/String;I)Ljava/net/Socket;")) && (!itf)) {

      final MutationIdentifier newId = this.context
          .registerMutation(this.factory,
              "*Security* Replaced SocketFactory.createSocket(String host,int port) with SocketFactory.getDefault().createSocket(host,port)");

      if (this.context.shouldMutate(newId)) {
        // remove the short 443
        mv.visitInsn(Opcodes.POP);

        // access to the SocketFactory
        mv.visitInsn(Opcodes.SWAP);

        // remove the SocketFactory
        mv.visitInsn(Opcodes.POP);

        // Push a default SocketFactory
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "javax/net/SocketFactory",
            "getDefault", "()Ljavax/net/SocketFactory;", false);

        // to have a proper stack
        mv.visitInsn(Opcodes.SWAP);

        // port number
        mv.visitIntInsn(Opcodes.SIPUSH, 80);

        // perform original call
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "javax/net/SocketFactory",
            "createSocket", "(Ljava/lang/String;I)Ljava/net/Socket;", false);
        return;
      }
    }
    mv.visitMethodInsn(opcode, owner, name, desc, itf);
  }
}
