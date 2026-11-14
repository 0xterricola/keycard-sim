package zknox.kcsim;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Helpers for cap.sh.
 *   classversion DIR MAJOR : rewrites the class file major version (the Oracle converter rejects Java 8 classes)
 *   compare A.cap B.cap    : prints the size of each CAP component for both files
 */
public final class CapTools {
  private CapTools() {}

  public static void main(String[] args) throws Exception {
    if (args.length == 3 && args[0].equals("classversion")) {
      classVersion(Path.of(args[1]), Integer.parseInt(args[2]));
    } else if (args.length == 3 && args[0].equals("compare")) {
      compare(Path.of(args[1]), Path.of(args[2]));
    } else {
      System.err.println("usage: CapTools classversion DIR MAJOR | compare A.cap B.cap");
      System.exit(1);
    }
  }

  static void classVersion(Path dir, int major) throws IOException {
    List<Path> files;
    try (Stream<Path> st = Files.walk(dir)) {
      files = st.filter(p -> p.toString().endsWith(".class")).collect(Collectors.toList());
    }
    for (Path p : files) {
      byte[] b = Files.readAllBytes(p);
      if (b.length < 8 || (b[0] & 0xFF) != 0xCA || (b[1] & 0xFF) != 0xFE) {
        throw new IOException("pas un fichier class : " + p);
      }
      b[6] = (byte) (major >> 8);
      b[7] = (byte) major;
      Files.write(p, b);
    }
  }

  static Map<String, Long> components(Path cap) throws IOException {
    Map<String, Long> out = new LinkedHashMap<>();
    try (ZipFile z = new ZipFile(cap.toFile())) {
      Enumeration<? extends ZipEntry> en = z.entries();
      while (en.hasMoreElements()) {
        ZipEntry e = en.nextElement();
        String n = e.getName();
        if (n.endsWith(".cap")) {
          out.put(n.substring(n.lastIndexOf('/') + 1, n.length() - 4), e.getSize());
        }
      }
    }
    return out;
  }

  static void compare(Path a, Path b) throws IOException {
    Map<String, Long> ca = components(a);
    Map<String, Long> cb = components(b);
    TreeSet<String> names = new TreeSet<>(ca.keySet());
    names.addAll(cb.keySet());
    System.out.printf("%-14s %10s %10s %8s%n", "composant", "original", "+ BJJ", "delta");
    long ta = 0;
    long tb = 0;
    for (String n : names) {
      long va = ca.getOrDefault(n, 0L);
      long vb = cb.getOrDefault(n, 0L);
      ta += va;
      tb += vb;
      System.out.printf("%-14s %10d %10d %+8d%n", n, va, vb, vb - va);
    }
    System.out.printf("%-14s %10d %10d %+8d%n", "total", ta, tb, tb - ta);
    System.out.println("Method = bytecode, StaticField = tableaux constants (courbe), Descriptor/RefLocation/Debug = métadonnées");
  }
}
