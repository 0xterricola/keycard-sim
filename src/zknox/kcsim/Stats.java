package zknox.kcsim;

import java.util.Arrays;

/** Summary statistics over a series of durations (nanoseconds in, milliseconds out). */
final class Stats {
  final int n;
  final double min, median, p95, max, mean, stdev;

  Stats(long[] nanos) {
    if (nanos.length == 0) {
      throw new IllegalArgumentException("empty series");
    }
    double[] ms = new double[nanos.length];
    for (int i = 0; i < nanos.length; i++) {
      ms[i] = nanos[i] / 1e6;
    }
    Arrays.sort(ms);
    n = ms.length;
    min = ms[0];
    max = ms[n - 1];
    median = quantile(ms, 0.5);
    p95 = quantile(ms, 0.95);
    double sum = 0;
    for (double v : ms) {
      sum += v;
    }
    mean = sum / n;
    double var = 0;
    for (double v : ms) {
      var += (v - mean) * (v - mean);
    }
    stdev = n > 1 ? Math.sqrt(var / (n - 1)) : 0;
  }

  private static double quantile(double[] sorted, double q) {
    double pos = q * (sorted.length - 1);
    int lo = (int) Math.floor(pos);
    int hi = (int) Math.ceil(pos);
    return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
  }

  static String header() {
    return String.format("%-22s %5s %9s %9s %9s %9s %9s %8s",
        "mesure", "n", "min", "median", "p95", "max", "mean", "stdev");
  }

  String row(String label) {
    return String.format("%-22s %5d %9.3f %9.3f %9.3f %9.3f %9.3f %8.3f",
        label, n, min, median, p95, max, mean, stdev);
  }
}
