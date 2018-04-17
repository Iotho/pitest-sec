package org.pitest.mutationtest.engine.gregor.mutators.experimental.security;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UseDESForSymmetricEncryptionVisitor
    extends AbstractVisitorForBigPatterns {

  private final MethodMutatorFactory factory;
  private final MutationContext      context;
  // ============= FIRST INSTRUCTION BLOCK =================================
  // first thing to recognize: mv.visitLdcInsn("AES/CBC/PKCS5Padding");
  private final int seen1stInstruction1PushString        = 11;
  // Second: mv.visitMethodInsn(INVOKESTATIC,
  // "javax/crypto/Cipher","getInstance",
  // "(Ljava/lang/String;)Ljavax/crypto/Cipher;", false);
  private final int seen1stInstruction2CipherGetInstance = 12;
  // Third : mv.visitVarInsn(ASTORE, cipherLocalVariableIndex);
  private final int seen1stInstruction3ASTORE            = 13;
  // ============= SECOND INSTRUCTION BLOCK ===============================
  // first thing to recognize :
  // mv.visitVarInsn(ALOAD,cipherLocalVariableIndex);
  private final int seen2dInstruction1ALOAD              = 21;
  // Second: mv.visitInsn(ICONST_1); // ENCRYPT_MODE; DECRYPT_MODE IS ICONST_2
  private final int seen2dInstruction2ICONST             = 22;
  // Third: mv.visitVarInsn(ALOAD, 1); // KeyReference
  private final int seen2dInstruction3ALOADKeyReference  = 23;
  MutationIdentifier newId = null;
  private int cipherLocalVariableIndex;
  private int keyReferenceLocalVariableIndex;

  UseDESForSymmetricEncryptionVisitor(final MutationContext context,
      final MethodVisitor writer, final MethodMutatorFactory factory) {
    super(context, writer, factory);
    this.factory = factory;
    this.context = context;
  }

  // Fourth: mv.visitMethodInsn(INVOKEVIRTUAL, "javax/crypto/Cipher",
  // "init","(ILjava/security/Key;)V", false);

  @Override
  public void visitLdcInsn(Object cst) {
    if ((cst.getClass().equals((new String()).getClass())) && (state
        == seennothing)) {
      if (containsAESorBLOWFISHorRC2orRC5((String) cst)) {
        state = seen1stInstruction1PushString;
        mv.visitLdcInsn(cst);
        return;
      }
    }
    visitInsn();
    mv.visitLdcInsn(cst);
  }

  private boolean containsAESorBLOWFISHorRC2orRC5(String argument) {
    try {
      String begining = argument.substring(0, 3);

      String stringpattern = "([aA][eE][sS]|[rR][cC][2]|[rR][cC][5])";
      Pattern pattern = Pattern.compile(stringpattern);
      Matcher matcher = pattern.matcher(begining);

      if (matcher.find()) {
        return true;
      }

      begining = argument.substring(0, 8);
      stringpattern = "[bB][lL][oO][wW][fF][iI][sS][hH]";
      pattern = Pattern.compile(stringpattern);
      matcher = pattern.matcher(begining);

      if (matcher.find()) {
        return true;
      }

      return false;

    } catch (IndexOutOfBoundsException e) {
      // wasn't good.
      return false;
    }
  }

  @Override
  public void visitVarInsn(int opcode, int var) {

    if ((opcode == Opcodes.ASTORE) && (state == seen1stInstruction2CipherGetInstance)) {
      state = seen1stInstruction3ASTORE;
      cipherLocalVariableIndex = var;
      mv.visitVarInsn(opcode, var);
      return;
    }

    if ((opcode == Opcodes.ALOAD) && (state == seen1stInstruction3ASTORE) && (var
        == cipherLocalVariableIndex)) {
      state = seen2dInstruction1ALOAD;
      mv.visitVarInsn(opcode, var);
      return;
    }

    if ((opcode == Opcodes.ALOAD) && (state == seen2dInstruction2ICONST)) {
      state = seen2dInstruction3ALOADKeyReference;
      keyReferenceLocalVariableIndex = var;
      mv.visitVarInsn(opcode, var);
      return;
    }

    visitInsn();
    mv.visitVarInsn(opcode, var);
  }

  @Override
  public void visitInsn(int opcode) {
    if (state == seen2dInstruction1ALOAD) {
      if ((opcode == Opcodes.ICONST_1) || (opcode == Opcodes.ICONST_2)) {
        state = seen2dInstruction2ICONST;
        mv.visitInsn(opcode);
        return;
      }
    }
    visitInsn();
    mv.visitInsn(opcode);
  }

  @Override
  public void visitMethodInsn(int opcode, String owner, String name,
      String desc, boolean itf) {
    // BEFORE DOING: mv.visitMethodInsn(INVOKEVIRTUAL,
    // "javax/crypto/Cipher", "init", "(ILjava/security/Key;)V", false);
    if ((opcode == Opcodes.INVOKEVIRTUAL) && (owner.equals("javax/crypto/Cipher"))
        && (name.equals("init")) && (desc.equals("(ILjava/security/Key;)V"))
        && (!itf) && (state == seen2dInstruction3ALOADKeyReference)) {

      //final MutationIdentifier newId = this.context.registerMutation(this.factory,
      //       "*NEW* replaced Cipher.init(int,key) with Cipher.init(int,new SecretKeySpec(key.getEncoded(),0,8,\"DES\")");

      if (newId != null) {
        if (this.context.shouldMutate(newId)) {

          // remove old key from stack
          mv.visitInsn(Opcodes.POP);

          // create new one
          mv.visitTypeInsn(Opcodes.NEW, "javax/crypto/spec/SecretKeySpec");
          mv.visitInsn(Opcodes.DUP);

          // push the existing key
          mv.visitVarInsn(Opcodes.ALOAD, keyReferenceLocalVariableIndex);

          // create the key with existing one
          mv.visitMethodInsn(Opcodes.INVOKEINTERFACE, "java/security/Key", "getEncoded",
              "()[B", true);
          mv.visitInsn(Opcodes.ICONST_0);
          mv.visitIntInsn(Opcodes.BIPUSH, 8);
          mv.visitLdcInsn("DES");
          mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "javax/crypto/spec/SecretKeySpec",
              "<init>", "([BIILjava/lang/String;)V", false);

          // finally, do the original call
          mv.visitMethodInsn(opcode, owner, name, desc, itf);

          state = seennothing; // reinit state
          return;
        }
      }
      mv.visitMethodInsn(opcode, owner, name, desc, itf); // do original call
      state = seennothing;
      return;
    }
    if ((opcode == Opcodes.INVOKESTATIC) && (owner.equals("javax/crypto/Cipher"))
        && (name.equals("getInstance")) && (desc
        .equals("(Ljava/lang/String;)Ljavax/crypto/Cipher;")) && (!itf) && (
        state == seen1stInstruction1PushString)) {

      newId = this.context.registerMutation(this.factory,
          "*NEW* replaced Cipher.init(int,key) with Cipher.init(int,new SecretKeySpec(key.getEncoded(),0,8,\"DES\")");

      if (newId != null) {
        if (this.context.shouldMutate(newId)) {
          state = seen1stInstruction2CipherGetInstance;

          // remove the String
          mv.visitInsn(Opcodes.POP);

          // push our String
          mv.visitLdcInsn("DES/ECB/PKCS5Padding");

          // perform the call
          mv.visitMethodInsn(opcode, owner, name, desc, itf);
          return;
        } else {
          mv.visitMethodInsn(opcode, owner, name, desc, itf);
          state = seen1stInstruction2CipherGetInstance;
          return;
        }
      } else {
        mv.visitMethodInsn(opcode, owner, name, desc, itf);
        state = seen1stInstruction2CipherGetInstance;
        return;
      }
    }
    visitInsn();
    mv.visitMethodInsn(opcode, owner, name, desc, itf);
  }

  @Override
  protected void visitInsn() {

    if (state >= seen1stInstruction3ASTORE) {
      state = seen1stInstruction3ASTORE;
      return;
    }

    state = seennothing;
  }

}