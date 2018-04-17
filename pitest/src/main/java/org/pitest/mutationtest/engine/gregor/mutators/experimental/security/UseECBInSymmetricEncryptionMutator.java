package org.pitest.mutationtest.engine.gregor.mutators.experimental.security;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodInfo;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public enum UseECBInSymmetricEncryptionMutator implements MethodMutatorFactory {

  USE_ECB_IN_SYMMETRIC_ENCRYPTION;

  @Override
  public MethodVisitor create(final MutationContext context,
      final MethodInfo methodInfo, final MethodVisitor methodVisitor) {
    return new UseECBInSymmetricEncryptionVisitor(context, methodVisitor, this);
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

class UseECBInSymmetricEncryptionVisitor extends AbstractVisitorSimplified {

  private final MethodMutatorFactory factory;
  private final MutationContext      context;
  private final int    seenPushString = 11;
  private       String pushedString   = "";

  UseECBInSymmetricEncryptionVisitor(final MutationContext context,
      final MethodVisitor writer, final MethodMutatorFactory factory) {
    super(context, writer, factory);
    this.factory = factory;
    this.context = context;
  }

  @Override
  public void visitLdcInsn(Object cst) {
    if ((cst instanceof String) && state == seennothing) {
      if (!containsECB((String) cst)) {
        state = seenPushString;
        pushedString = (String) cst;
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

    if ((opcode == Opcodes.INVOKESTATIC) && (owner.equals("javax/crypto/Cipher"))
        && (name.equals("getInstance")) && (desc
        .equals("(Ljava/lang/String;)Ljavax/crypto/Cipher;")) && (!itf) && (
        state == seenPushString)) {

      int indexOfMode = pushedString.indexOf('/');
      String toPush = new String("");

      if (indexOfMode == -1) {
        toPush = pushedString + "/ECB/PKCS5Padding";
      } else {
        String rest = pushedString
            .substring(indexOfMode + 1, pushedString.length());
        int indexOfPaddingInRest = rest.indexOf('/');
        String beginning = pushedString.substring(0, indexOfMode);
        String padding = rest.substring(indexOfPaddingInRest, rest.length());
        toPush = beginning + "/ECB" + padding;
      }

      final MutationIdentifier newId = this.context
          .registerMutation(this.factory,
              "*SECURITY* Replaced Cipher.getInstance(" + pushedString
                  + ") with Cipher.getInstance(" + toPush + ")");

      if (context.shouldMutate(newId)) {
        mv.visitInsn(Opcodes.POP);          // pop the String definition of the Cipher
        mv.visitLdcInsn(toPush);    // push ours
      }

      mv.visitMethodInsn(opcode, owner, name, desc, itf);
      state = seennothing;
      return;
    }

    visitInsn();
    mv.visitMethodInsn(opcode, owner, name, desc, itf);
  }

  private boolean containsECB(String argument) {
    try {
      String stringpattern = "[/][eE][cC][bB][/]";
      Pattern pattern = Pattern.compile(stringpattern);
      Matcher matcher = pattern.matcher(argument);
      return matcher.find();
    } catch (IndexOutOfBoundsException e) {
      // wasn't ECB.
      return false;
    }
  }

  @Override
  protected void visitInsn() {
    state = seennothing;
  }

}