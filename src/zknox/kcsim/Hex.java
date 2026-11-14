package zknox.kcsim;

final class Hex {
  private static final char[] DIGITS = "0123456789abcdef".toCharArray();

  private Hex() {}

  static String of(byte[] b) {
    char[] out = new char[b.length * 2];
    for (int i = 0; i < b.length; i++) {
      out[2 * i] = DIGITS[(b[i] >> 4) & 0xf];
      out[2 * i + 1] = DIGITS[b[i] & 0xf];
    }
    return new String(out);
  }

  static byte[] parse(String s) {
    s = s.replaceAll("\\s", "");
    if ((s.length() & 1) != 0) {
      throw new IllegalArgumentException("odd hex length");
    }
    byte[] out = new byte[s.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
    }
    return out;
  }
}
