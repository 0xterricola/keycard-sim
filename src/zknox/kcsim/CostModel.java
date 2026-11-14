package zknox.kcsim;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * Per-call cost of Java Card API methods on the target card (costs/*.tsv, from JCAlgTest). Three kinds of entries:
 * fixed (ms per call), len (data-dependent profile, linear interpolation clamped at both ends) and per256 (ms for a
 * 256-byte call, scaled linearly).
 */
final class CostModel {
  private static final class Entry {
    final String kind;
    final int[] lens;
    final double[] ms;

    Entry(String kind, int[] lens, double[] ms) {
      this.kind = kind;
      this.lens = lens;
      this.ms = ms;
    }
  }

  private final Map<String, Entry> entries = new HashMap<>();
  final String source;
  final TreeSet<String> unpriced = new TreeSet<>();

  CostModel(Path tsv) throws IOException {
    source = tsv.toString();
    List<String> lines = Files.readAllLines(tsv, StandardCharsets.UTF_8);
    for (String line : lines) {
      if (line.isBlank() || line.startsWith("#")) {
        continue;
      }
      String[] f = line.split("\t");
      String kind = f[1];
      if (kind.equals("len")) {
        String[] pts = f[2].split(",");
        int[] l = new int[pts.length];
        double[] v = new double[pts.length];
        for (int i = 0; i < pts.length; i++) {
          String[] kv = pts[i].split(":");
          l[i] = Integer.parseInt(kv[0]);
          v[i] = Double.parseDouble(kv[1]);
        }
        entries.put(f[0], new Entry(kind, l, v));
      } else {
        entries.put(f[0], new Entry(kind, null, new double[] {Double.parseDouble(f[2])}));
      }
    }
  }

  boolean has(String key) {
    return entries.containsKey(key);
  }

  /** Cost in ms of one call; 0 (and recorded as unpriced) if the key is unknown. */
  double ms(String key, int len) {
    Entry e = entries.get(key);
    if (e == null) {
      unpriced.add(key);
      return 0;
    }
    switch (e.kind) {
      case "fixed":
        return e.ms[0];
      case "per256":
        return len < 0 ? e.ms[0] : e.ms[0] * len / 256.0;
      default:
        if (len <= e.lens[0] || len < 0) {
          return e.ms[0];
        }
        for (int i = 1; i < e.lens.length; i++) {
          if (len <= e.lens[i]) {
            double f = (len - e.lens[i - 1]) / (double) (e.lens[i] - e.lens[i - 1]);
            return e.ms[i - 1] + f * (e.ms[i] - e.ms[i - 1]);
          }
        }
        return e.ms[e.ms.length - 1];
    }
  }
}
