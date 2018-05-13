# Pitest-sec
A fork of PITEST version 1.1.11, introducing additional mutation operators, designed for security testing. 

All information regarding the original project available at http://pitest.org, original repository available at https://github.com/hcoles/pitest.


## Introduction
The tool extension introduces 15 new security-aware mutation operators which, in a nutshell, introduce vulnerabilities in code patterns. Following the regression testing technique, a test suite covering the vulnerabilities introduced by the tool ensures that these vulnerabilities will not be introduced in the future.

All the mutation operators are based on introducing vulnerable code patterns which can be discovered by security-static analysis. Moreover, our mutation operators are based on the open-source tool FindBugs-Sec available at https://find-sec-bugs.github.io/.

## Changes
The new mutation operators are located in https://github.com/Iotho/pitest-sec/tree/master/pitest/src/main/java/org/pitest/mutationtest/engine/gregor/mutators/experimental/security.

The mutation operators are then referenced to the mutation engine in https://github.com/Iotho/pitest-sec/blob/master/pitest/src/main/java/org/pitest/mutationtest/engine/gregor/config/Mutator.java.

## Usage
Build PIT's jar and place it in the appropriate location. 

### Command line
```
java -cp <your classpath including pit command line jar and dependencies> \
    org.pitest.mutationtest.commandline.MutationCoverageReport \
    --reportDir <outputdir> \
    --targetClasses com.your.package.tobemutated* \
    --targetTests com.your.package.*
    --sourceDirs <pathtosource>
```

## HOW TO's

### Create new security aware mutation operators
PIT is a JAVA mutation testing tool working at byte-code level, i.e it does not have to compile its mutants but rather mutates the code of the program under test at byte-code level. The tool relies strongly on a byte-code manipulation library named ASM for its mutation operators’ implementation. Moreover, it introduces faults in java methods by using the ASM library's <code>MethodVisitor</code>. ASM's documentation is available at http://asm.ow2.io/index.html.

#### 1. Find a vulnerable pattern and resolve it
First, find a common vulnerability which may come up in java code and resolve it. For instance, using <code>java.util.Random</code> could be a vulnerability in a java code snippet. In order to resolve it, a developer should rather use <code>java.security.SecureRandom</code>. Therefore, a mutation operator which introduces the use of a <code>java.util.Random</code> rather than a <code>java.security.SecureRandom</code> forms a security mutation operator. Let us implement this mutation operator together.

In order to compare the usage of <code>java.util.Random</code>, and <code>java.security.SecureRandom</code>, let's write two classes, <code>Foo.java</code> which utilizes <code>java.security.SecureRandom</code>, and <code>FooMutated.java</code> which forms the mutated version of <code>Foo.java</code> and therefore utilizes <code>java.util.Random</code>.

```java
public class Foo {

  public int returnRandomInt() {
    java.security.SecureRandom random = new java.security.SecureRandom();
    return random.nextInt();
  }

}
```

```java
public class FooMutated {

  public int returnRandomInt() {
    java.util.Random random = new java.util.Random();
    return random.nextInt();
  }

}
```

#### 2. Use ASMifier
The ASM library proposes a tool, ASMifier, which takes in entry a compilated java class (.class), and outputs the way to generate this class using the ASM library. 

For instance, after using the following command line, <b>Foo.asm</b> contains the instructions necessary to generate Foo.class using the ASM library.
```
java -classpath asm-all-3.3.1.jar;asm-util-3.3.1.jar org.objectweb.asm.util.ASMifierClassVisitor Foo.class>Foo.asm
```

Hence, Foo.asm contains code which generates the <code>returnRandomInt</code> method in <code>Foo.class</code> using ASM is the following :
```java
{
mv = cw.visitMethod(ACC_PUBLIC, "returnRandomInt", "()I", null, null);
mv.visitCode();
mv.visitTypeInsn(NEW, "java/security/SecureRandom");
mv.visitInsn(DUP);
mv.visitMethodInsn(INVOKESPECIAL, "java/security/SecureRandom", "<init>", "()V");
mv.visitVarInsn(ASTORE, 1);
mv.visitVarInsn(ALOAD, 1);
mv.visitMethodInsn(INVOKEVIRTUAL, "java/security/SecureRandom", "nextInt", "()I");
mv.visitInsn(IRETURN);
mv.visitMaxs(2, 2);
mv.visitEnd();
}
```

The code which generates the <code>returnRandomInt</code> method in <code>FooMutated.clas</code> using ASM is the following :
```java
{
mv = cw.visitMethod(ACC_PUBLIC, "returnRandomInt", "()I", null, null);
mv.visitCode();
mv.visitTypeInsn(NEW, "java/util/Random");
mv.visitInsn(DUP);
mv.visitMethodInsn(INVOKESPECIAL, "java/util/Random", "<init>", "()V");
mv.visitVarInsn(ASTORE, 1);
mv.visitVarInsn(ALOAD, 1);
mv.visitMethodInsn(INVOKEVIRTUAL, "java/util/Random", "nextInt", "()I");
mv.visitInsn(IRETURN);
mv.visitMaxs(2, 2);
mv.visitEnd();
}
```

Download ASM at https://repository.ow2.org/nexus/#nexus-search;gav~asm~asm-all.
Download ASM-Util at https://repository.ow2.org/nexus/#nexus-search;gav~asm~asm-util.

#### 3. Compare ASMifier's output for the legit and the vulnerable code
As one can see, the differences between the two compiled methods are located in 
<ul>
	<li>The initialization of either a <code>java.util.Random</code> object or a <code>java.security.SecureRandom</code> object;</li>
	<li>And also in the usage of <code>"java/util/Random", "nextInt"</code> or <code>"java/security/SecureRandom", "nextInt"</code>.</li>
</ul>

After analysis, the best way to insert the vulnerability seems to detect the usage of the <code>java.security.SecureRandom,nextInt,()I</code> method and replace it by the initialization of a <code>Random</code> object and the call of <code>java.util.Random,nextInt,()I</code>.

#### 4. Implement the mutation operator in PIT
Mutation operators in PIT are located in <code>org.pitest.mutationtest.engine.gregor.mutators</code>.

Those are usually composed of an <i>enumeration</i> which implements <code>org.pitest.mutationtest.engine.gregor.MethodMutatorFactory</code> and a <i>class</i> which extends <code>org.objectweb.asm.MethodVisitor</code>.

By overriding the method <code>visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf)</code> of the MethodVisitor, one may select an instruction which triggers the mutation.

Here, the instruction which triggers the mutation is the usage of the <code>java.security.SecureRandom,nextInt,()I</code> method. Whenever this method is used, the ASM library should :
<ul>
	<li>Create new Random object : <code>mv.visitTypeInsn(Opcodes.NEW, "java/util/Random");</code></li>
	<li>Duplicate the object's reference : <code>mv.visitInsn(Opcodes.DUP);</code></li>
	<li>Initialize the object : <code>mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/util/Random", "<init>", "()V",false);</code></li>
  <li>Call the nextInt method : <code>mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Random", "nextInt","()I", false); </code></li>
  <li>Delete the ref to the SecureRandom object on the stack : <code>mv.visitInsn(Opcodes.POP);</code> (introduced by <code>mv.visitVarInsn(ALOAD, 1);</code>)</li>
</ul>

A complete implementation of a comparable mutation operator is available at https://github.com/Iotho/pitest-sec/blob/master/pitest/src/main/java/org/pitest/mutationtest/engine/gregor/mutators/experimental/security/UseWeakPseudoRandomNumberGeneratorMutator.java.
