package zknox.kcprof;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Java agent that profiles a Java Card applet running in jCardSim.
 *
 * Applet code (im/status/keycard/* and im/status/keycard/math/*): every executed JVM bytecode is counted per method,
 * except i2s (folded by the Java Card converter into the short arithmetic opcode), array allocations are recorded, and
 * calls into the Java Card API that the cost model does not price are counted.
 *
 * jCardSim implementation classes: the entry of each priced API method records an event (method, algorithm, data
 * length) when the immediate caller is applet code.
 */
public final class Agent {
  private Agent() {}

  public static void premain(String args, Instrumentation inst) {
    inst.addTransformer(new Transformer(), false);
  }

  static final String TRACE = "zknox/kcprof/Trace";

  /** API methods priced by the cost model: their call sites are not counted as "other API calls". */
  static final Set<String> PRICED = Set.of(
      "init", "doFinal", "update", "sign", "verify", "signPreComputedHash", "generateSecret", "generateData",
      "nextBytes", "reset", "setS", "getS", "setW", "getW", "clearKey", "setA", "setB", "setFieldFP", "setG", "setR",
      "setK", "setExponent", "setModulus", "arrayCopy", "arrayCopyNonAtomic", "arrayFillNonAtomic", "arrayCompare",
      "makeTransientByteArray", "makeTransientShortArray", "makeTransientBooleanArray", "makeTransientObjectArray",
      "buildKey");

  /** Hook: event name and index of the "length" argument in the local variables (-1 if none). */
  static final class Hook {
    final String event;
    final int lenLocal;
    final int kind; // 0 = API event, 1 = transient allocation, 2 = key, 3 = key pair

    Hook(String event, int lenLocal, int kind) {
      this.event = event;
      this.lenLocal = lenLocal;
      this.kind = kind;
    }
  }

  static final Map<String, Hook> HOOKS = new HashMap<>();

  private static void hook(String cls, String method, String descPrefix, String event, int lenLocal) {
    HOOKS.put(cls + "#" + method + "#" + descPrefix, new Hook(event, lenLocal, 0));
  }

  static {
    String c = "com/licel/jcardsim/crypto/";
    hook(c + "KeyAgreementImpl", "init", "", "KeyAgreement.init", -1);
    hook(c + "KeyAgreementImpl", "generateSecret", "", "KeyAgreement.generateSecret", 3);
    for (String impl : new String[] {"AsymmetricCipherImpl", "SymmetricCipherImpl"}) {
      hook(c + impl, "init", "", "Cipher.init", -1);
      hook(c + impl, "doFinal", "", "Cipher.doFinal", 3);
      hook(c + impl, "update", "", "Cipher.update", 3);
    }
    for (String impl : new String[] {"AsymmetricSignatureImpl", "SymmetricSignatureImpl"}) {
      hook(c + impl, "init", "", "Signature.init", -1);
      hook(c + impl, "sign", "", "Signature.sign", 3);
      hook(c + impl, "signPreComputedHash", "", "Signature.signPreComputedHash", 3);
      hook(c + impl, "verify", "", "Signature.verify", 3);
      hook(c + impl, "update", "", "Signature.update", 3);
    }
    hook(c + "MessageDigestImpl", "doFinal", "", "MessageDigest.doFinal", 3);
    hook(c + "MessageDigestImpl", "update", "", "MessageDigest.update", 3);
    hook(c + "MessageDigestImpl", "reset", "", "MessageDigest.reset", -1);
    hook(c + "RandomDataImpl", "generateData", "", "RandomData.generateData", 3);
    hook(c + "RandomDataImpl", "nextBytes", "", "RandomData.nextBytes", 3);
    hook(c + "ECPrivateKeyImpl", "setS", "", "ECPrivateKey.setS", 3);
    hook(c + "ECPrivateKeyImpl", "getS", "", "ECPrivateKey.getS", -1);
    hook(c + "ECPrivateKeyImpl", "clearKey", "", "ECKey.clearKey", -1);
    hook(c + "ECPublicKeyImpl", "setW", "", "ECPublicKey.setW", 3);
    hook(c + "ECPublicKeyImpl", "getW", "", "ECPublicKey.getW", -1);
    hook(c + "ECPublicKeyImpl", "clearKey", "", "ECKey.clearKey", -1);
    for (String m : new String[] {"setA", "setB", "setFieldFP", "setG", "setR"}) {
      hook(c + "ECKeyImpl", m, "", "ECKey." + m, 3);
    }
    hook(c + "ECKeyImpl", "setK", "", "ECKey.setK", -1);
    hook(c + "RSAKeyImpl", "setExponent", "", "RSAKey.setExponent", 3);
    hook(c + "RSAKeyImpl", "setModulus", "", "RSAKey.setModulus", 3);
    String u = "javacard/framework/Util";
    hook(u, "arrayCopyNonAtomic", "", "Util.arrayCopyNonAtomic", 4);
    hook(u, "arrayCopy", "", "Util.arrayCopy", 4);
    hook(u, "arrayFillNonAtomic", "", "Util.arrayFillNonAtomic", 2);
    hook(u, "arrayCompare", "", "Util.arrayCompare", 4);
    String j = "javacard/framework/JCSystem";
    HOOKS.put(j + "#makeTransientByteArray#(SB)", new Hook("transient byte[]", 0, 1));
    HOOKS.put(j + "#makeTransientBooleanArray#(SB)", new Hook("transient boolean[]", 0, 1));
    HOOKS.put(j + "#makeTransientShortArray#(SB)", new Hook("transient short[]", 0, 1));
    HOOKS.put(j + "#makeTransientObjectArray#(SB)", new Hook("transient Object[]", 0, 1));
    HOOKS.put("javacard/security/KeyBuilder#buildKey#(BSZ)", new Hook("key", 0, 2));
    HOOKS.put("javacard/security/KeyPair#<init>#(BS)", new Hook("keypair", 1, 3));
  }

  static Hook findHook(String cls, String method, String desc) {
    Hook h = HOOKS.get(cls + "#" + method + "#");
    if (h != null) {
      return h;
    }
    for (Map.Entry<String, Hook> e : HOOKS.entrySet()) {
      String k = e.getKey();
      String prefix = cls + "#" + method + "#";
      if (k.startsWith(prefix) && desc.startsWith(k.substring(prefix.length()))) {
        return e.getValue();
      }
    }
    return null;
  }

  static boolean isAppletClass(String name) {
    if (!name.startsWith("im/status/keycard/")) {
      return false;
    }
    String rest = name.substring("im/status/keycard/".length());
    return rest.indexOf('/') < 0 || (rest.startsWith("math/") && rest.indexOf('/', 5) < 0);
  }

  static boolean isHookedClass(String name) {
    return name.startsWith("com/licel/jcardsim/crypto/") || name.equals("javacard/framework/Util")
        || name.equals("javacard/framework/JCSystem") || name.equals("javacard/security/KeyBuilder")
        || name.equals("javacard/security/KeyPair");
  }

  static final class Transformer implements ClassFileTransformer {
    @Override
    public byte[] transform(ClassLoader loader, String name, Class<?> redefined, ProtectionDomain pd, byte[] bytes) {
      if (name == null) {
        return null;
      }
      try {
        if (isAppletClass(name)) {
          return rewrite(bytes, cv -> new AppletClassVisitor(cv));
        }
        if (isHookedClass(name)) {
          return rewrite(bytes, cv -> new HookClassVisitor(cv));
        }
      } catch (Throwable t) {
        System.err.println("[kcprof] instrumentation de " + name + " impossible : " + t);
      }
      return null;
    }
  }

  interface VisitorFactory {
    ClassVisitor wrap(ClassVisitor cv);
  }

  static byte[] rewrite(byte[] bytes, VisitorFactory f) {
    ClassReader cr = new ClassReader(bytes);
    ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
    cr.accept(f.wrap(cw), 0);
    return cw.toByteArray();
  }

  /** Counts bytecodes per method, records array allocations and unpriced API calls in applet code. */
  static final class AppletClassVisitor extends ClassVisitor {
    private String owner;

    AppletClassVisitor(ClassVisitor cv) {
      super(Opcodes.ASM9, cv);
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
      owner = name;
      super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
      MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
      if (mv == null || (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
        return mv;
      }
      int id = Trace.registerMethod(owner.replace('/', '.') + "." + name);
      return new CountingMethodVisitor(mv, id, owner);
    }
  }

  static final class CountingMethodVisitor extends MethodVisitor {
    private final int id;
    private final String owner;
    private int pending;

    CountingMethodVisitor(MethodVisitor mv, int id, String owner) {
      super(Opcodes.ASM9, mv);
      this.id = id;
      this.owner = owner;
    }

    private void flush() {
      if (pending == 0) {
        return;
      }
      super.visitFieldInsn(Opcodes.GETSTATIC, TRACE, "BC", "[J");
      super.visitLdcInsn(id);
      super.visitInsn(Opcodes.DUP2);
      super.visitInsn(Opcodes.LALOAD);
      super.visitLdcInsn((long) pending);
      super.visitInsn(Opcodes.LADD);
      super.visitInsn(Opcodes.LASTORE);
      pending = 0;
    }

    private void count() {
      pending++;
    }

    private void countAndFlush() {
      pending++;
      flush();
    }

    @Override
    public void visitLabel(Label label) {
      flush();
      super.visitLabel(label);
    }

    @Override
    public void visitInsn(int opcode) {
      if (opcode == Opcodes.I2S) {
        super.visitInsn(opcode);
        return;
      }
      if ((opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) || opcode == Opcodes.ATHROW) {
        countAndFlush();
      } else {
        count();
      }
      super.visitInsn(opcode);
    }

    @Override
    public void visitIntInsn(int opcode, int operand) {
      count();
      if (opcode == Opcodes.NEWARRAY) {
        int size = (operand == Opcodes.T_SHORT || operand == Opcodes.T_CHAR) ? 2
            : (operand == Opcodes.T_INT || operand == Opcodes.T_FLOAT) ? 4
            : (operand == Opcodes.T_LONG || operand == Opcodes.T_DOUBLE) ? 8 : 1;
        super.visitInsn(Opcodes.DUP);
        super.visitLdcInsn(size);
        super.visitLdcInsn(owner);
        super.visitMethodInsn(Opcodes.INVOKESTATIC, TRACE, "newArray", "(IILjava/lang/String;)V", false);
      }
      super.visitIntInsn(opcode, operand);
    }

    @Override
    public void visitVarInsn(int opcode, int var) {
      count();
      super.visitVarInsn(opcode, var);
    }

    @Override
    public void visitTypeInsn(int opcode, String type) {
      count();
      if (opcode == Opcodes.ANEWARRAY) {
        super.visitInsn(Opcodes.DUP);
        super.visitLdcInsn(2);
        super.visitLdcInsn(owner);
        super.visitMethodInsn(Opcodes.INVOKESTATIC, TRACE, "newArray", "(IILjava/lang/String;)V", false);
      }
      super.visitTypeInsn(opcode, type);
    }

    @Override
    public void visitFieldInsn(int opcode, String fOwner, String name, String desc) {
      count();
      super.visitFieldInsn(opcode, fOwner, name, desc);
    }

    @Override
    public void visitMethodInsn(int opcode, String mOwner, String name, String desc, boolean itf) {
      countAndFlush();
      if ((mOwner.startsWith("javacard/") || mOwner.startsWith("javacardx/")) && !PRICED.contains(name)) {
        super.visitLdcInsn(mOwner.substring(mOwner.lastIndexOf('/') + 1) + "." + name);
        super.visitMethodInsn(Opcodes.INVOKESTATIC, TRACE, "otherApi", "(Ljava/lang/String;)V", false);
      }
      super.visitMethodInsn(opcode, mOwner, name, desc, itf);
    }

    @Override
    public void visitInvokeDynamicInsn(String name, String desc, Handle bsm, Object... args) {
      countAndFlush();
      super.visitInvokeDynamicInsn(name, desc, bsm, args);
    }

    @Override
    public void visitJumpInsn(int opcode, Label label) {
      countAndFlush();
      super.visitJumpInsn(opcode, label);
    }

    @Override
    public void visitLdcInsn(Object value) {
      count();
      super.visitLdcInsn(value);
    }

    @Override
    public void visitIincInsn(int var, int increment) {
      count();
      super.visitIincInsn(var, increment);
    }

    @Override
    public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) {
      countAndFlush();
      super.visitTableSwitchInsn(min, max, dflt, labels);
    }

    @Override
    public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
      countAndFlush();
      super.visitLookupSwitchInsn(dflt, keys, labels);
    }

    @Override
    public void visitMultiANewArrayInsn(String desc, int dims) {
      count();
      super.visitMultiANewArrayInsn(desc, dims);
    }

    @Override
    public void visitMaxs(int maxStack, int maxLocals) {
      flush();
      super.visitMaxs(maxStack, maxLocals);
    }
  }

  /** Inserts an event call at the entry of the priced jCardSim API implementations. */
  static final class HookClassVisitor extends ClassVisitor {
    private String owner;

    HookClassVisitor(ClassVisitor cv) {
      super(Opcodes.ASM9, cv);
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
      owner = name;
      super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
      MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
      if (mv == null || (access & Opcodes.ACC_PUBLIC) == 0 || (access & Opcodes.ACC_ABSTRACT) != 0) {
        return mv;
      }
      Hook h = findHook(owner, name, desc);
      if (h == null) {
        return mv;
      }
      boolean isStatic = (access & Opcodes.ACC_STATIC) != 0;
      Type[] args = Type.getArgumentTypes(desc);
      int lenLocal = h.lenLocal;
      if (lenLocal >= 0) {
        int argIndex = lenLocal - (isStatic ? 0 : 1);
        if (argIndex < 0 || argIndex >= args.length || args[argIndex].getSort() != Type.SHORT) {
          lenLocal = -1;
        }
      }
      final int len = lenLocal;
      return new MethodVisitor(Opcodes.ASM9, mv) {
        @Override
        public void visitCode() {
          super.visitCode();
          if (h.kind == 0) {
            super.visitLdcInsn(h.event);
            if (isStatic) {
              super.visitInsn(Opcodes.ACONST_NULL);
            } else {
              super.visitVarInsn(Opcodes.ALOAD, 0);
            }
            if (len >= 0) {
              super.visitVarInsn(Opcodes.ILOAD, len);
            } else {
              super.visitInsn(Opcodes.ICONST_M1);
            }
            super.visitMethodInsn(Opcodes.INVOKESTATIC, TRACE, "api", "(Ljava/lang/String;Ljava/lang/Object;I)V", false);
          } else if (h.kind == 1) {
            super.visitLdcInsn(h.event);
            super.visitVarInsn(Opcodes.ILOAD, 0);
            super.visitVarInsn(Opcodes.ILOAD, 1);
            super.visitMethodInsn(Opcodes.INVOKESTATIC, TRACE, "transientArray", "(Ljava/lang/String;II)V", false);
          } else if (h.kind == 2) {
            super.visitVarInsn(Opcodes.ILOAD, 0);
            super.visitVarInsn(Opcodes.ILOAD, 1);
            super.visitMethodInsn(Opcodes.INVOKESTATIC, TRACE, "key", "(II)V", false);
          } else {
            // constructor KeyPair(byte algorithm, short keyLength): only the arguments are read before super()
            super.visitVarInsn(Opcodes.ILOAD, 1);
            super.visitVarInsn(Opcodes.ILOAD, 2);
            super.visitMethodInsn(Opcodes.INVOKESTATIC, TRACE, "keyPair", "(II)V", false);
          }
        }
      };
    }
  }
}
