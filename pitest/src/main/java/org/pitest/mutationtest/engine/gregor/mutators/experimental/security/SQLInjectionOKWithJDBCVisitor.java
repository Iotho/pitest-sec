package org.pitest.mutationtest.engine.gregor.mutators.experimental.security;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.pitest.mutationtest.engine.MutationIdentifier;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.MutationContext;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class SQLInjectionOKWithJDBCVisitor extends AbstractVisitorSimplified {

  private final MethodMutatorFactory factory;
  private final MutationContext      context;
  // ========= FIRST INSTRUCTION BLOCK =========
  private final int            seen1stInstruction1ALOADConnection                  = 11;
  private final int            seen1stInstruction2LDCINSNQuerry                    = 12;
  private final int            seen1stInstruction3INVOKEINTERFACEPreparedStatement = 13;
  private final int            seen1stInstruction4ASTOREPreparedStatement          = 14;
  // ========= SECOND INSTRUCTION BLOCK =========
  private final int            seen2dInstruction1ALOADPreparedStatement            = 21;
  private final int            seen2dInstruction2ICONST                            = 22;
  private final int            seen2dInstructionLOAD                               = 23;
  private       int            connectionLocalVariableIndex                        = 0;
  private       int            preparedStatementVariableIndex                      = 0;
  private       String         querry                                              = "";
  private       int            numberOfVariablesToSet                              = 0;
  // ========= UsefulStuff ======
  private       List<Runnable> listOfMethods                                       = new ArrayList();
  private       List<Type>     listOfTypes                                         = new ArrayList();
  private       String         connectionDescription                               = "";

  SQLInjectionOKWithJDBCVisitor(final MutationContext context,
      final MethodVisitor writer, final MethodMutatorFactory factory) {
    super(context, writer, factory);
    this.factory = factory;
    this.context = context;
  }

  @Override
  public void visitInsn(int opcode) {
    if (state == seen2dInstruction1ALOADPreparedStatement) {
      if ((opcode >= Opcodes.ICONST_1) && (opcode <= Opcodes.ICONST_5)) {
        state = seen2dInstruction2ICONST;
        mv.visitInsn(opcode);
        return;
      }
    }
    visitInsn();
    mv.visitInsn(opcode);
  }

  @Override
  public void visitIntInsn(int opcode, int operand) {
    if (state == seen2dInstruction1ALOADPreparedStatement) {
      if ((opcode == Opcodes.BIPUSH) && (operand == numberOfVariablesToSet + 1)) {
        state = seen2dInstruction2ICONST;
        mv.visitIntInsn(opcode, operand);
        return;
      }
    }

    visitInsn();
    mv.visitIntInsn(opcode, operand);
  }

  @Override
  public void visitVarInsn(int opcode, int var) {
    if (state == seennothing) {
      // maybe connection?
      if (opcode == Opcodes.ALOAD) {
        // assuming it is the connection.
        connectionLocalVariableIndex = var;
        state = seen1stInstruction1ALOADConnection;
        mv.visitVarInsn(opcode, var);
        return;
      }
    }

    if (state == seen1stInstruction3INVOKEINTERFACEPreparedStatement) {
      if (opcode == Opcodes.ASTORE) {
        preparedStatementVariableIndex = var;
        state = seen1stInstruction4ASTOREPreparedStatement;
        mv.visitVarInsn(opcode, var);
        return;
      }
    }

    if (state == seen1stInstruction4ASTOREPreparedStatement) {
      if ((opcode == Opcodes.ALOAD) && (var == preparedStatementVariableIndex)) {
        state = seen2dInstruction1ALOADPreparedStatement;
        mv.visitVarInsn(opcode, var);
        return;
      }
    }

    if (state == seen2dInstruction2ICONST) {
      if ((opcode >= Opcodes.ILOAD) && (opcode <= Opcodes.ALOAD)) {
        final int opcodef = opcode;
        final int varf = var;
        Runnable methodCall = null;
        // ALOAD, ILOAD, ETC...
        if (opcode == Opcodes.ALOAD) {
          methodCall = new RunnableForSQLInjection(mv, opcodef, varf);
        } else {
          methodCall = new Runnable() {
            public void run() {
              mv.visitVarInsn(opcodef, varf);
            }
          };
        }
        listOfMethods.add(methodCall);
        mv.visitVarInsn(opcode, var);
        state = seen2dInstructionLOAD;
        return;
      }
    }

    visitInsn();
    mv.visitVarInsn(opcode, var);
  }

  @Override
  public void visitLdcInsn(Object cst) {
    if ((cst instanceof String)
        && state == seen1stInstruction1ALOADConnection) {
      if (containsValues((String) cst)) {
        state = seen1stInstruction2LDCINSNQuerry;
        querry = (String) cst;
        mv.visitLdcInsn(cst);
        return;
      }
    }

    if (state == seen2dInstruction1ALOADPreparedStatement) {
      if (cst instanceof Integer) {
        int operand = (Integer) cst;
        if (operand == numberOfVariablesToSet + 1) {
          state = seen2dInstruction2ICONST;
          mv.visitLdcInsn(cst);
          return;
        }
      }
    }

    // Push a constant to initiate a '?'
    if (state == seen2dInstruction2ICONST) {
      final Object cstf = cst;
      Runnable methodCall = new Runnable() {

        public void run() {
          mv.visitLdcInsn(cstf);
        }
      };
      listOfMethods.add(methodCall);
      mv.visitLdcInsn(cst);
      state = seen2dInstructionLOAD;
      return;
    }
    visitInsn();
    mv.visitLdcInsn(cst);
  }

  @Override
  public void visitMethodInsn(int opcode, String owner, String name,
      String desc, boolean itf) {
    // =================================================================
    // ================== STATE == seen2dInstructionLOAD ===============
    // =================================================================

    // Floats
    if ((opcode == Opcodes.INVOKEINTERFACE) && (owner
        .equals("java/sql/PreparedStatement")) && (name.equals("setFloat"))
        && (desc.equals("(IF)V")) && (itf) && (state
        == seen2dInstructionLOAD)) {
      numberOfVariablesToSet++;
      state = seen1stInstruction4ASTOREPreparedStatement;
      Type t = Type.FLOAT_TYPE;
      listOfTypes.add(t);
      mv.visitMethodInsn(opcode, owner, name, desc, itf);
      return;
    }

    // Doubles
    if ((opcode == Opcodes.INVOKEINTERFACE) && (owner
        .equals("java/sql/PreparedStatement")) && (name.equals("setDouble"))
        && (desc.equals("(ID)V")) && (itf) && (state
        == seen2dInstructionLOAD)) {
      numberOfVariablesToSet++;
      state = seen1stInstruction4ASTOREPreparedStatement;
      Type t = Type.DOUBLE_TYPE;
      listOfTypes.add(t);
      mv.visitMethodInsn(opcode, owner, name, desc, itf);
      return;
    }

    // Booleans
    if ((opcode == Opcodes.INVOKEINTERFACE) && (owner
        .equals("java/sql/PreparedStatement")) && (name.equals("setBoolean"))
        && (desc.equals("(IZ)V")) && (itf) && (state
        == seen2dInstructionLOAD)) {
      numberOfVariablesToSet++;
      state = seen1stInstruction4ASTOREPreparedStatement;
      Type t = Type.BOOLEAN_TYPE;
      listOfTypes.add(t);
      mv.visitMethodInsn(opcode, owner, name, desc, itf);
      return;
    }

    // Longs
    if ((opcode == Opcodes.INVOKEINTERFACE) && (owner
        .equals("java/sql/PreparedStatement")) && (name.equals("setLong"))
        && (desc.equals("(IJ)V")) && (itf) && (state
        == seen2dInstructionLOAD)) {
      numberOfVariablesToSet++;
      state = seen1stInstruction4ASTOREPreparedStatement;
      Type t = Type.LONG_TYPE;
      listOfTypes.add(t);
      mv.visitMethodInsn(opcode, owner, name, desc, itf);
      return;
    }

    // Strings
    if ((opcode == Opcodes.INVOKEINTERFACE) && (owner
        .equals("java/sql/PreparedStatement")) && (name.equals("setString"))
        && (desc.equals("(ILjava/lang/String;)V")) && (itf) && (state
        == seen2dInstructionLOAD)) {
      numberOfVariablesToSet++;
      state = seen1stInstruction4ASTOREPreparedStatement; // waiting for
      // ALOAD(PreparedStatement)
      Type t = Type.getType(String.class);
      listOfTypes.add(t);
      mv.visitMethodInsn(opcode, owner, name, desc, itf);
      return;
    }

    // Ints
    if ((opcode == Opcodes.INVOKEINTERFACE) && (owner
        .equals("java/sql/PreparedStatement")) && (name.equals("setInt"))
        && (desc.equals("(II)V")) && (itf) && (state
        == seen2dInstructionLOAD)) {
      numberOfVariablesToSet++;
      state = seen1stInstruction4ASTOREPreparedStatement;
      Type t = Type.INT_TYPE;
      listOfTypes.add(t);
      mv.visitMethodInsn(opcode, owner, name, desc, itf);
      return;
    }

    // =================================================================
    // =========== STATE == seen1stInstruction2LDCINSNQuerry ===========
    // =================================================================

    if ((opcode == Opcodes.INVOKEINTERFACE) && (owner
        .equals("com/mysql/jdbc/Connection")) && (name
        .equals("prepareStatement")) && (desc
        .equals("(Ljava/lang/String;)Ljava/sql/PreparedStatement;")) && (itf)
        && (state == seen1stInstruction2LDCINSNQuerry)) {
      state = seen1stInstruction3INVOKEINTERFACEPreparedStatement;
      connectionDescription = owner;
      mv.visitMethodInsn(opcode, owner, name, desc, itf);
      return;
    }

    if ((opcode == Opcodes.INVOKEINTERFACE) && (owner.equals("java/sql/Connection"))
        && (name.equals("prepareStatement")) && (desc
        .equals("(Ljava/lang/String;)Ljava/sql/PreparedStatement;")) && (itf)
        && (state == seen1stInstruction2LDCINSNQuerry)) {
      state = seen1stInstruction3INVOKEINTERFACEPreparedStatement;
      connectionDescription = owner;
      mv.visitMethodInsn(opcode, owner, name, desc, itf);
      return;

    }
    // =================================================================
    // =========== STATE == seen2dInstruction1ALOADPreparedStatement
    // =================================================================

    // CAN BE: execute, excecuteQuerry, executeUpdate !!!

    // executeUpdate
    if ((opcode == Opcodes.INVOKEINTERFACE) && (owner
        .equals("java/sql/PreparedStatement")) && (name.equals("executeUpdate"))
        && (desc.equals("()I")) && (itf) && (state
        == seen2dInstruction1ALOADPreparedStatement)) {

      if ((numberOfVariablesToSet == numberOfVariablesToSetInQuerry(querry))
          && (aStringIsPushedByReference(listOfMethods, listOfTypes))) {
        String toDisplay = "";
        int i = 0;
        while (i < listOfTypes.size()) {
          toDisplay = new String(toDisplay + listOfTypes.get(i).toString());
          i++;
        }

        final MutationIdentifier newId = this.context
            .registerMutation(this.factory,
                "*SECURITY* replaced PreparedStatement.executeUpdate()"
                    + " with new Statement.executeUpdate() with argument types : "
                    + toDisplay);

        if (this.context.shouldMutate(newId)) {
          createStatementThenPrepareStackThenExecute(name, desc);
        } else {
          mv.visitMethodInsn(opcode, owner, name, desc, itf);
        }

      } else {
        mv.visitMethodInsn(opcode, owner, name, desc, itf);
      }

      listOfMethods = new ArrayList<Runnable>();
      listOfTypes = new ArrayList<Type>();
      numberOfVariablesToSet = 0;

      state = seennothing;
      return;
    }

    // executeQuerry
    if ((opcode == Opcodes.INVOKEINTERFACE) && (owner
        .equals("java/sql/PreparedStatement")) && (name.equals("executeQuery"))
        && (desc.equals("()Ljava/sql/ResultSet;")) && (itf) && (state
        == seen2dInstruction1ALOADPreparedStatement)) {

      if ((numberOfVariablesToSet == numberOfVariablesToSetInQuerry(querry))
          && (aStringIsPushedByReference(listOfMethods, listOfTypes))) {

        String toDisplay = "";
        int i = 0;
        while (i < listOfTypes.size()) {
          toDisplay = new String(toDisplay + listOfTypes.get(i).toString());
          i++;
        }

        final MutationIdentifier newId = this.context
            .registerMutation(this.factory,
                "*SECURITY* replaced PreparedStatement.executeQuery()"
                    + " with new Statement.executeQuery() with argument types : "
                    + toDisplay);

        if (this.context.shouldMutate(newId)) {
          createStatementThenPrepareStackThenExecute(name, desc);
        } else {
          mv.visitMethodInsn(opcode, owner, name, desc, itf);
        }

      } else {
        mv.visitMethodInsn(opcode, owner, name, desc, itf);
      }
      listOfMethods = new ArrayList<Runnable>();
      listOfTypes = new ArrayList<Type>();
      numberOfVariablesToSet = 0;

      state = seennothing;
      return;
    }

    // execute
    if ((opcode == Opcodes.INVOKEINTERFACE) && (owner
        .equals("java/sql/PreparedStatement")) && (name.equals("execute"))
        && (desc.equals("()Z")) && (itf) && (state
        == seen2dInstruction1ALOADPreparedStatement)) {

      if ((numberOfVariablesToSet == numberOfVariablesToSetInQuerry(querry))
          && (aStringIsPushedByReference(listOfMethods, listOfTypes))) {
        String toDisplay = "";
        int i = 0;
        while (i < listOfTypes.size()) {
          toDisplay = new String(toDisplay + listOfTypes.get(i).toString());
          i++;
        }

        final MutationIdentifier newId = this.context
            .registerMutation(this.factory,
                "*SECURITY* replaced PreparedStatement.execute()"
                    + " with new Statement.execute() with argument types : "
                    + toDisplay);

        if (this.context.shouldMutate(newId)) {
          createStatementThenPrepareStackThenExecute(name, desc);
        } else {
          mv.visitMethodInsn(opcode, owner, name, desc, itf);
        }

      } else {
        mv.visitMethodInsn(opcode, owner, name, desc, itf);
      }

      listOfMethods = new ArrayList<Runnable>();
      listOfTypes = new ArrayList<Type>();
      numberOfVariablesToSet = 0;

      state = seennothing;
      return;
    }
    visitInsn();
    mv.visitMethodInsn(opcode, owner, name, desc, itf);
  }

  private int numberOfVariablesToSetInQuerry(String aQuerry) {
    String theQuerry = aQuerry;
    int count = 0;
    int lastIndex = theQuerry.lastIndexOf('?');
    while (lastIndex != -1) {
      count++;
      theQuerry = theQuerry.substring(0, lastIndex);
      lastIndex = theQuerry.lastIndexOf('?');
    }
    return count;
  }

  /**
   * Pushes a Connection reference, creates a statement, creates the querry
   * with the arguments at their proper place, runs @method on the Statement
   * created with corresponding @description
   *
   * @param method      = name of the method to run on the created Statement
   * @param description = description of the method to run on the created Statement
   */
  private void createStatementThenPrepareStackThenExecute(String method,
      String description) {
    // remove ref to preparedStatement.
    mv.visitInsn(Opcodes.POP);

    // push reference to Connection.
    mv.visitVarInsn(Opcodes.ALOAD, connectionLocalVariableIndex);

    // create a Statement
    mv.visitMethodInsn(Opcodes.INVOKEINTERFACE, connectionDescription,
        "createStatement", "()Ljava/sql/Statement;", true);

    // build the StringBuilder
    mv.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder");
    mv.visitInsn(Opcodes.DUP);
    mv.visitLdcInsn("");
    mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>",
        "(Ljava/lang/String;)V", false);

    // build the querry String with arguments
    appendQuerryInString(querry, listOfMethods, listOfTypes);

    // finish the statement
    String removeParenthesisDescription = description.substring(2);
    String addStringInDescription =
        "(Ljava/lang/String;)" + removeParenthesisDescription;
    mv.visitMethodInsn(Opcodes.INVOKEINTERFACE, "java/sql/Statement", method,
        addStringInDescription, true);
  }

  public boolean aStringIsPushedByReference(List<Runnable> pushedList,
      List<Type> listOfTypes) {
    if (pushedList.size() != listOfTypes.size()) {
      return false;
    }
    Iterator<Runnable> it = pushedList.iterator();
    Iterator<Type> itType = listOfTypes.iterator();
    boolean toReturn = false;

    while (it.hasNext()) {
      Type nextType = itType.next();
      Runnable nextRunnable = it.next();
      if (nextType.equals(Type.getType(String.class))) {
        if (nextRunnable instanceof RunnableForSQLInjection) {
          toReturn = true;
        }
      }

    }

    return toReturn;
  }

  /**
   * Takes the splittedQuerry, the methods to apply between, the listOfTypes
   * corresponding to return type of the methodCalls and generates a String
   * Querry suitable for a Statement.
   *
   * @param querry        : a PrepareStatement SQL querry
   * @param listOfMethods : a list of methods that should be called to push the querries
   *                      arguments
   * @param listOfTypes   : the types of the arguments pushed by listOfMethods
   */
  private void appendQuerryInString(String querry, List<Runnable> listOfMethods,
      List<Type> listOfTypes) {
    String regex = "[?]";
    String[] splittedQuerry = querry.split(regex);

    int index = 0;
    while (index < numberOfVariablesToSet) {
      if (index < splittedQuerry.length) {
        mv.visitLdcInsn(splittedQuerry[index]);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
            "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
      }

      Type nextType = listOfTypes.get(index);

      if (nextType.equals(Type.getType(String.class))) {
        // Add 'stuff' for statements
        mv.visitLdcInsn("'");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
            "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
      }

      Runnable toRun = listOfMethods.get(index);
      toRun.run(); // now we have ALOAD, ILOAD,... (pushed parameter)

      // 1
      if (nextType.equals(Type.FLOAT_TYPE)) {
        // replace mv.visitMethodInsn(INVOKEINTERFACE,
        // "java/sql/PreparedStatement", "setFloat", "(IF)V", true);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
            "(F)Ljava/lang/StringBuilder;", false);
      }

      // 2
      if (nextType.equals(Type.DOUBLE_TYPE)) {
        // replace mv.visitMethodInsn(INVOKEINTERFACE,
        // "java/sql/PreparedStatement", "setDouble", "(ID)V", true);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
            "(D)Ljava/lang/StringBuilder;", false);
      }

      // 3
      if (nextType.equals(Type.BOOLEAN_TYPE)) {
        // replace mv.visitMethodInsn(INVOKEINTERFACE,
        // "java/sql/PreparedStatement", "setBoolean", "(IZ)V", true);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
            "(Z)Ljava/lang/StringBuilder;", false);
      }

      // 4
      if (nextType.equals(Type.LONG_TYPE)) {
        // replace mv.visitMethodInsn(INVOKEINTERFACE,
        // "java/sql/PreparedStatement", "setLong", "(IJ)V", true);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
            "(J)Ljava/lang/StringBuilder;", false);
      }

      // 5
      if (nextType.equals(Type.getType(String.class))) {

        // replace
        // mv.visitMethodInsn(INVOKEINTERFACE,"java/sql/PreparedStatement",
        // "setString", "(ILjava/lang/String;)V",true);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
            "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);

        // Add 'stuff' for statements
        mv.visitLdcInsn("'");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
            "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
      }

      // 6
      if (nextType.equals(Type.INT_TYPE)) {
        // replace
        // mv.visitMethodInsn(INVOKEINTERFACE,"java/sql/PreparedStatement",
        // "setInt", "(II)V", true);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
            "(I)Ljava/lang/StringBuilder;", false);
      }
      index++;
    }

    while (index < splittedQuerry.length) {
      mv.visitLdcInsn(splittedQuerry[index]);
      mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
          "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
      index++;
    }

    mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
        "()Ljava/lang/String;", false);

  }

  private boolean containsValues(String argument) {
    try {
      String stringpattern = "[?]"; // searching for "?"
      Pattern pattern = Pattern.compile(stringpattern);
      Matcher matcher = pattern.matcher(argument);
      return matcher.find();

    } catch (IndexOutOfBoundsException e) {
      // wasn't a SQL Statement with "?" values to do.
      return false;
    }

  }

  @Override
  protected void visitInsn() {
    listOfMethods = new ArrayList<Runnable>();
    listOfTypes = new ArrayList<Type>();
    state = seennothing;
  }
}
