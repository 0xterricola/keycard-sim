package zknox.kcprof;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Runtime side of the profiler: counters written by instrumented code, read by the bench. */
public final class Trace {
  private Trace() {}

  /** Executed bytecodes per instrumented method id. */
  public static final long[] BC = new long[1 << 16];

  private static final List<String> METHODS = Collections.synchronizedList(new ArrayList<>());
  private static final StackWalker WALKER = StackWalker.getInstance();

  /** A priced API call made by applet code. */
  public static final class Event {
    public final String key;
    public final int len;
    public final String caller;

    Event(String key, int len, String caller) {
      this.key = key;
      this.len = len;
      this.caller = caller;
    }
  }

  /** An allocation made by applet code. */
  public static final class Alloc {
    public final String owner;
    public final String kind;
    public final int count;
    public final int bytes;
    public final boolean transientMemory;

    Alloc(String owner, String kind, int count, int bytes, boolean transientMemory) {
      this.owner = owner;
      this.kind = kind;
      this.count = count;
      this.bytes = bytes;
      this.transientMemory = transientMemory;
    }
  }

  private static final List<Event> EVENTS = new ArrayList<>();
  private static final Map<String, Long> OTHER_API = new TreeMap<>();
  private static final List<Alloc> ALLOCS = new ArrayList<>();

  static int registerMethod(String name) {
    synchronized (METHODS) {
      METHODS.add(name);
      return METHODS.size() - 1;
    }
  }

  public static boolean active() {
    return true;
  }

  // ---------------------------------------------------------------- called by instrumented code

  public static void api(String base, Object self, int len) {
    String caller = appletCaller();
    if (caller == null) {
      return;
    }
    EVENTS.add(new Event(base + algorithmSuffix(self), len, caller));
  }

  public static void otherApi(String name) {
    OTHER_API.merge(name, 1L, Long::sum);
  }

  public static void newArray(int count, int elemSize, String owner) {
    ALLOCS.add(new Alloc(owner.replace('/', '.'), "array", count, count * elemSize, false));
  }

  public static void transientArray(String kind, int count, int event) {
    String caller = appletCaller();
    if (caller == null) {
      return;
    }
    int elem = kind.contains("short") || kind.contains("Object") ? 2 : 1;
    ALLOCS.add(new Alloc(ownerOf(caller), kind, count, count * elem, true));
  }

  public static void key(int type, int length) {
    String caller = appletCaller();
    if (caller == null) {
      return;
    }
    ALLOCS.add(new Alloc(ownerOf(caller), "key " + keyTypeName(type) + " " + length, 1, 0, keyTypeName(type).contains("TRANSIENT")));
  }

  public static void keyPair(int algorithm, int length) {
    String caller = appletCaller();
    if (caller == null) {
      return;
    }
    String alg = algorithm == 1 ? "RSA" : algorithm == 2 ? "RSA_CRT" : algorithm == 5 ? "EC_FP" : "alg" + algorithm;
    ALLOCS.add(new Alloc(ownerOf(caller), "keypair " + alg + " " + length, 1, 0, false));
  }

  // ---------------------------------------------------------------- read by the bench

  public static void reset() {
    synchronized (METHODS) {
      java.util.Arrays.fill(BC, 0, METHODS.size(), 0L);
    }
    EVENTS.clear();
    OTHER_API.clear();
  }

  /** Bytecodes executed since the last reset, per method (only methods with a non-zero count). */
  public static Map<String, Long> bytecodes() {
    Map<String, Long> out = new LinkedHashMap<>();
    synchronized (METHODS) {
      for (int i = 0; i < METHODS.size(); i++) {
        if (BC[i] != 0) {
          out.merge(METHODS.get(i), BC[i], Long::sum);
        }
      }
    }
    return out;
  }

  public static List<Event> events() {
    return new ArrayList<>(EVENTS);
  }

  public static Map<String, Long> otherApi() {
    return new TreeMap<>(OTHER_API);
  }

  public static List<Alloc> allocations() {
    return new ArrayList<>(ALLOCS);
  }

  public static void clearAllocations() {
    ALLOCS.clear();
  }

  // ---------------------------------------------------------------- helpers

  private static boolean isAppletClassName(String cls) {
    if (!cls.startsWith("im.status.keycard.")) {
      return false;
    }
    String rest = cls.substring("im.status.keycard.".length());
    return rest.indexOf('.') < 0 || (rest.startsWith("math.") && rest.indexOf('.', 5) < 0);
  }

  /** "class.method" of the frame that called the hooked API method, if it is applet code. */
  private static String appletCaller() {
    StackWalker.StackFrame f = WALKER.walk(s -> s.skip(3).findFirst().orElse(null));
    if (f == null || !isAppletClassName(f.getClassName())) {
      return null;
    }
    return f.getClassName() + "." + f.getMethodName();
  }

  private static String ownerOf(String caller) {
    return caller.substring(0, caller.lastIndexOf('.'));
  }

  private static final Map<Class<?>, Map<Byte, String>> ALG_NAMES = new HashMap<>();

  private static String algorithmSuffix(Object self) {
    try {
      if (self instanceof javacardx.crypto.Cipher) {
        return "/" + constantName(javacardx.crypto.Cipher.class, "ALG_", ((javacardx.crypto.Cipher) self).getAlgorithm());
      }
      if (self instanceof javacard.security.Signature) {
        return "/" + constantName(javacard.security.Signature.class, "ALG_", ((javacard.security.Signature) self).getAlgorithm());
      }
      if (self instanceof javacard.security.MessageDigest) {
        return "/" + constantName(javacard.security.MessageDigest.class, "ALG_", ((javacard.security.MessageDigest) self).getAlgorithm());
      }
      if (self instanceof javacard.security.KeyAgreement) {
        return "/" + constantName(javacard.security.KeyAgreement.class, "ALG_", ((javacard.security.KeyAgreement) self).getAlgorithm());
      }
    } catch (Throwable t) {
      return "/?";
    }
    return "";
  }

  private static synchronized String constantName(Class<?> api, String prefix, byte value) {
    Map<Byte, String> names = ALG_NAMES.computeIfAbsent(api, c -> {
      Map<Byte, String> m = new TreeMap<>();
      List<Field> fields = new ArrayList<>(List.of(c.getFields()));
      fields.sort((a, b) -> a.getName().compareTo(b.getName()));
      for (Field fd : fields) {
        if (fd.getName().startsWith(prefix) && fd.getType() == byte.class && Modifier.isStatic(fd.getModifiers())) {
          try {
            m.putIfAbsent(fd.getByte(null), fd.getName().substring(prefix.length()));
          } catch (IllegalAccessException e) {
            // ignore
          }
        }
      }
      return m;
    });
    String n = names.get(value);
    return n != null ? n : Byte.toString(value);
  }

  private static String keyTypeName(int type) {
    try {
      for (Field fd : javacard.security.KeyBuilder.class.getFields()) {
        if (fd.getName().startsWith("TYPE_") && fd.getType() == byte.class && fd.getByte(null) == (byte) type) {
          return fd.getName().substring(5);
        }
      }
    } catch (IllegalAccessException e) {
      // ignore
    }
    return "type" + type;
  }
}
