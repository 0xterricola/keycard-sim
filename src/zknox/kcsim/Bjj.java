package zknox.kcsim;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * BabyJubJub on the host: twisted Edwards arithmetic, the birational map to and from the short Weierstrass image used
 * by the card, circomlib point packing and EdDSA-Poseidon verification.
 */
final class Bjj {
  static final BigInteger P = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
  static final BigInteger L = new BigInteger("2736030358979909402780800718157159386076813972158567259200215660948447373041");
  static final BigInteger A = BigInteger.valueOf(168700);
  static final BigInteger D = BigInteger.valueOf(168696);
  /** Montgomery coefficient (B = 1). */
  static final BigInteger MA = BigInteger.valueOf(168698);
  static final BigInteger MA_DIV3 = MA.multiply(BigInteger.valueOf(3).modInverse(P)).mod(P);
  static final BigInteger AW = BigInteger.valueOf(3).subtract(MA.pow(2)).multiply(BigInteger.valueOf(3).modInverse(P)).mod(P);
  static final BigInteger BW = MA.pow(3).shiftLeft(1).subtract(MA.multiply(BigInteger.valueOf(9)))
      .multiply(BigInteger.valueOf(27).modInverse(P)).mod(P);
  static final BigInteger[] B8 = {
      new BigInteger("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
      new BigInteger("16950150798460657717958625567821834550301663161624707787222815936182638968203")};
  static final BigInteger[] ZERO = {BigInteger.ZERO, BigInteger.ONE};
  private static final BigInteger HALF_P = P.subtract(BigInteger.ONE).shiftRight(1);

  private Bjj() {}

  static boolean onCurve(BigInteger[] q) {
    BigInteger x2 = q[0].multiply(q[0]).mod(P);
    BigInteger y2 = q[1].multiply(q[1]).mod(P);
    return A.multiply(x2).add(y2).subtract(BigInteger.ONE).subtract(D.multiply(x2).multiply(y2)).mod(P).signum() == 0;
  }

  static boolean onWeierstrass(BigInteger x, BigInteger y) {
    return y.multiply(y).subtract(x.pow(3)).subtract(AW.multiply(x)).subtract(BW).mod(P).signum() == 0;
  }

  static BigInteger[] add(BigInteger[] p, BigInteger[] q) {
    BigInteger t = D.multiply(p[0]).multiply(q[0]).multiply(p[1]).multiply(q[1]).mod(P);
    BigInteger x = p[0].multiply(q[1]).add(p[1].multiply(q[0])).multiply(BigInteger.ONE.add(t).modInverse(P)).mod(P);
    BigInteger y = p[1].multiply(q[1]).subtract(A.multiply(p[0]).multiply(q[0]))
        .multiply(BigInteger.ONE.subtract(t).mod(P).modInverse(P)).mod(P);
    return new BigInteger[] {x, y};
  }

  static BigInteger[] mul(BigInteger k, BigInteger[] p) {
    BigInteger[] r = ZERO;
    for (int i = k.bitLength() - 1; i >= 0; i--) {
      r = add(r, r);
      if (k.testBit(i)) {
        r = add(r, p);
      }
    }
    return r;
  }

  static boolean eq(BigInteger[] p, BigInteger[] q) {
    return p[0].equals(q[0]) && p[1].equals(q[1]);
  }

  /**
   * Weierstrass -> Edwards: u = X - A/3, x = u / Y, y = (u - 1) / (u + 1), with one inversion
   * (t = 1 / (Y.(u + 1)), x = u.(u + 1).t, y = (u - 1).Y.t). Valid for every point of the order-l subgroup but the
   * neutral element.
   */
  static BigInteger[] toEdwards(BigInteger wx, BigInteger wy) {
    BigInteger u = wx.subtract(MA_DIV3).mod(P);
    BigInteger up1 = u.add(BigInteger.ONE).mod(P);
    BigInteger t = wy.multiply(up1).mod(P).modInverse(P);
    BigInteger x = u.multiply(up1).multiply(t).mod(P);
    BigInteger y = u.subtract(BigInteger.ONE).multiply(wy).multiply(t).mod(P);
    return new BigInteger[] {x, y};
  }

  /** Edwards -> Weierstrass: X = (1 + y) / (1 - y) + A/3, Y = (1 + y) / ((1 - y).x). */
  static BigInteger[] toWeierstrass(BigInteger[] e) {
    BigInteger u = BigInteger.ONE.add(e[1]).multiply(BigInteger.ONE.subtract(e[1]).mod(P).modInverse(P)).mod(P);
    BigInteger v = u.multiply(e[0].modInverse(P)).mod(P);
    return new BigInteger[] {u.add(MA_DIV3).mod(P), v};
  }

  /** Parses the card's 04 || X || Y and converts it to Edwards coordinates. */
  static BigInteger[] fromCard(byte[] w) {
    if (w.length != 65 || w[0] != 0x04) {
      throw new IllegalArgumentException("point carte inattendu : " + Hex.of(w));
    }
    BigInteger x = new BigInteger(1, Arrays.copyOfRange(w, 1, 33));
    BigInteger y = new BigInteger(1, Arrays.copyOfRange(w, 33, 65));
    if (!onWeierstrass(x, y)) {
      throw new IllegalArgumentException("point hors de la courbe de Weierstrass");
    }
    return toEdwards(x, y);
  }

  static byte[] be32(BigInteger v) {
    byte[] b = v.toByteArray();
    byte[] out = new byte[32];
    int n = Math.min(b.length, 32);
    System.arraycopy(b, b.length - n, out, 32 - n, n);
    return out;
  }

  /** circomlib packPoint: y little-endian, bit 255 set when x > (p - 1) / 2. */
  static byte[] pack(BigInteger[] q) {
    byte[] be = be32(q[1]);
    byte[] le = new byte[32];
    for (int i = 0; i < 32; i++) {
      le[i] = be[31 - i];
    }
    if (q[0].compareTo(HALF_P) > 0) {
      le[31] |= (byte) 0x80;
    }
    return le;
  }

  /** circomlib packSignature: packPoint(R8) || S little-endian. */
  static byte[] packSignature(BigInteger[] r8, BigInteger s) {
    byte[] out = new byte[64];
    System.arraycopy(pack(r8), 0, out, 0, 32);
    byte[] be = be32(s);
    for (int i = 0; i < 32; i++) {
      out[32 + i] = be[31 - i];
    }
    return out;
  }

  /** circomlib eddsa.verifyPoseidon. */
  static boolean verify(BigInteger msg, BigInteger[] r8, BigInteger s, BigInteger[] pub) {
    if (!onCurve(r8) || !onCurve(pub) || s.compareTo(L) >= 0) {
      return false;
    }
    BigInteger hm = Poseidon.hash(r8[0], r8[1], pub[0], pub[1], msg);
    BigInteger[] left = mul(s, B8);
    BigInteger[] right = add(r8, mul(hm.shiftLeft(3), pub));
    return eq(left, right);
  }
}
