package im.status.keycard;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

/**
 * Blind two-move EdDSA signer on BabyJubJub (circomlib EdDSA-Poseidon compatible).
 *
 * The card never sees the message: the host computes c = Poseidon(R8, A, msg) mod l.
 *   COMMIT  : r uniform in [1, l-1] (rejection sampling), R = r.B8 (Weierstrass image), session armed
 *   RESPOND : S = r + c.s mod l, session disarmed and r invalidated before any computation
 * Only one session can be armed at a time (sequential blind Schnorr, see DECISIONS.md ADR-008).
 *
 * Variants, selected by P1 (see DECISIONS.md ADR-010 and ADR-011):
 *   modular : S = r + c.s mod l with keycard-math (software reduction mod l)
 *   integer : COMMIT also draws t (320 bits) and keeps r' = r + l.t; RESPOND returns S' = r' + c.s over the integers
 *             (products by the RSA squaring trick, no reduction on card); the host computes S = S' mod l
 *   chain   : RESPOND also opens the next session and appends its R (one APDU per signature)
 *
 * The secret scalar s is the circomlib pruned scalar. The card keeps s mod l and A = (s >> 3).B8.
 */
final class BjjSigner {
  static final byte INS_BJJ_LOAD_KEY = (byte) 0xB0;
  static final byte INS_BJJ_GET_PUBLIC = (byte) 0xB1;
  static final byte INS_BJJ_COMMIT = (byte) 0xB2;
  static final byte INS_BJJ_RESPOND = (byte) 0xB3;
  static final byte INS_BJJ_CALIBRATE = (byte) 0xB4;

  /** RESPOND P1 bit (modular): split s = s1 + m with a fresh m before multiplying by c. */
  static final byte P1_MASKED = (byte) 0x01;
  /** RESPOND P1 bit: compute the response once instead of twice (cost comparison only). */
  static final byte P1_SINGLE = (byte) 0x02;
  /** COMMIT and RESPOND P1 bit: integer response S' = r + l.t + c.s. */
  static final byte P1_INTEGER = (byte) 0x04;
  /** RESPOND P1 bit: open the next session and append its R to the response. */
  static final byte P1_CHAIN = (byte) 0x08;

  static final short SW_FAULT = (short) 0x6F0F;

  private static final byte ARMED_0 = (byte) 0xA5;
  private static final byte ARMED_MOD = (byte) 0x5A;
  private static final byte ARMED_INT = (byte) 0xC3;

  private static final short SZ = BabyJubJub.SCALAR_SIZE;
  /** Integer response size: S' < 2^576. */
  static final short INT_SIZE = 72;
  /** Size of t for the integer response (320 bits: hides floor((r + c.s)/l) within 2^-69). */
  private static final short T_SIZE = 40;
  /** RSA-736 block used for exact squaring (no reduction below 2^735). */
  private static final short RSA_SIZE = 92;
  private static final short WIN_RESP = 64;
  private static final short WIN_COMMIT = 82;

  // crypto.scratch layout (176 bytes, transient)
  private static final short W_OFF = 0;    // working copy of r
  private static final short SK_OFF = 32;  // s mod l
  private static final short T1_OFF = 64;  // first computation of the response
  private static final short T2_OFF = 96;  // second computation of S (modular)
  private static final short T_OFF = 136;  // t (integer COMMIT)

  // APDU buffer temporaries (the command data stays at OFFSET_CDATA)
  private static final short M_OFF = 40;
  private static final short S1_OFF = 72;
  private static final short X_OFF = 40;
  private static final short Y_OFF = 132;

  private final Crypto crypto;
  private final SECP256k1 secp256k1;
  private final ECPrivateKey secretKey;
  private final ECPrivateKey nonceKey;
  private final byte[] publicKey;
  private final byte[] nonce;
  private final byte[] noncePrime;
  private final byte[] state;
  private final Cipher square;

  BjjSigner(Crypto crypto, SECP256k1 secp256k1) {
    this.crypto = crypto;
    this.secp256k1 = secp256k1;
    secretKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, BabyJubJub.KEY_SIZE, false);
    BabyJubJub.setCurveParameters(secretKey);
    nonceKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, BabyJubJub.KEY_SIZE, false);
    BabyJubJub.setCurveParameters(nonceKey);
    publicKey = new byte[BabyJubJub.POINT_SIZE];
    nonce = JCSystem.makeTransientByteArray(SZ, JCSystem.CLEAR_ON_DESELECT);
    noncePrime = JCSystem.makeTransientByteArray(INT_SIZE, JCSystem.CLEAR_ON_DESELECT);
    state = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_DESELECT);

    // Same construction as keycard-math: a generated RSA-736 modulus with public exponent 2
    KeyPair kp = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_736);
    kp.genKeyPair();
    RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
    nonce[0] = 2;
    pub.setExponent(nonce, (short) 0, (short) 1);
    nonce[0] = 0;
    square = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    square.init(pub, Cipher.MODE_ENCRYPT);
  }

  /** Transient key domain parameters are lost on deselect: set them again on every select. */
  void onSelect() {
    BabyJubJub.setCurveParameters(nonceKey);
  }

  /** Erases the BabyJubJub key (REMOVE KEY, factory reset). */
  void clear() {
    disarm();
    publicKey[0] = 0;
    secretKey.clearKey();
    BabyJubJub.setCurveParameters(secretKey);
  }

  /**
   * Processes a BJJ command already decrypted by the secure channel. Returns the response length; the response is at
   * ISO7816.OFFSET_CDATA.
   */
  short process(byte[] buf, boolean pinValidated) {
    if (!pinValidated) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    switch (buf[ISO7816.OFFSET_INS]) {
      case INS_BJJ_LOAD_KEY:
        return loadKey(buf);
      case INS_BJJ_GET_PUBLIC:
        return getPublic(buf);
      case INS_BJJ_COMMIT:
        return commit(buf);
      case INS_BJJ_RESPOND:
        return respond(buf);
      case INS_BJJ_CALIBRATE:
        return calibrate(buf);
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        return 0;
    }
  }

  /** LOAD KEY: data = circomlib pruned scalar s (32 bytes, big-endian). Returns A in Weierstrass form. */
  private short loadKey(byte[] buf) {
    checkLc(buf, SZ);
    if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
    }
    byte[] t = crypto.scratch;
    disarm();

    Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, t, SK_OFF, SZ);
    crypto.bigMath.modRed(t, SK_OFF, SZ, BabyJubJub.R, (short) 0, SZ);
    if (crypto.isZero256(t, SK_OFF)) {
      Util.arrayFillNonAtomic(t, (short) 0, T1_OFF, (byte) 0);
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // a = (s >> 3) mod l, A = a.B8 (s is pruned, so s = 8a exactly)
    Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, t, W_OFF, SZ);
    shiftRight3(t, W_OFF);
    crypto.bigMath.modRed(t, W_OFF, SZ, BabyJubJub.R, (short) 0, SZ);
    nonceKey.setS(t, W_OFF, SZ);
    short len = secp256k1.multiplyPoint(nonceKey, BabyJubJub.G, (short) 0, BabyJubJub.POINT_SIZE, buf, ISO7816.OFFSET_CDATA);

    publicKey[0] = 0;
    secretKey.setS(t, SK_OFF, SZ);
    Util.arrayFillNonAtomic(t, (short) 0, T1_OFF, (byte) 0);
    invalidateNonce();
    Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, publicKey, (short) 0, BabyJubJub.POINT_SIZE);
    return len;
  }

  private short getPublic(byte[] buf) {
    requireKey();
    Util.arrayCopyNonAtomic(publicKey, (short) 0, buf, ISO7816.OFFSET_CDATA, BabyJubJub.POINT_SIZE);
    return BabyJubJub.POINT_SIZE;
  }

  /** COMMIT (P1 = 0 or P1_INTEGER): returns R = r.B8 (65 bytes). A new COMMIT destroys any pending session. */
  private short commit(byte[] buf) {
    requireKey();
    byte p1 = buf[ISO7816.OFFSET_P1];
    if ((p1 != 0 && p1 != P1_INTEGER) || buf[ISO7816.OFFSET_P2] != 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
    }
    return openSession(buf, ISO7816.OFFSET_CDATA, p1 == P1_INTEGER);
  }

  /** Draws r (and r' = r + l.t in integer mode), writes R at buf[outOff] and arms the session. */
  private short openSession(byte[] buf, short outOff, boolean integer) {
    disarm();

    do {
      crypto.random.generateData(nonce, (short) 0, SZ);
      nonce[0] &= (byte) 0x07;
    } while ((lessThan(nonce, (short) 0, BabyJubJub.R, (short) 0) == 0) || crypto.isZero256(nonce, (short) 0));

    if (integer) {
      // r' = r + l.t with l.t = ((l + t)^2 - l^2 - t^2) / 2, exact below the RSA-736 modulus
      byte[] t = crypto.scratch;
      crypto.random.generateData(t, T_OFF, T_SIZE);
      setRight(buf, X_OFF, t, T_OFF, T_SIZE);
      addRight(buf, X_OFF, WIN_COMMIT, BabyJubJub.R, (short) 0, SZ);
      squareInPlace(buf, X_OFF);
      subRight(buf, X_OFF, WIN_COMMIT, BabyJubJub.R_SQUARED, (short) 0, (short) BabyJubJub.R_SQUARED.length);
      setRight(buf, Y_OFF, t, T_OFF, T_SIZE);
      squareInPlace(buf, Y_OFF);
      subRight(buf, X_OFF, WIN_COMMIT, buf, (short) (Y_OFF + RSA_SIZE - WIN_COMMIT), WIN_COMMIT);
      shiftRight1(buf, (short) (X_OFF + RSA_SIZE - WIN_COMMIT), WIN_COMMIT);
      addRight(buf, X_OFF, WIN_COMMIT, nonce, (short) 0, SZ);
      Util.arrayCopyNonAtomic(buf, (short) (X_OFF + RSA_SIZE - INT_SIZE), noncePrime, (short) 0, INT_SIZE);
      Util.arrayFillNonAtomic(t, T_OFF, T_SIZE, (byte) 0);
      Util.arrayFillNonAtomic(buf, X_OFF, (short) (2 * RSA_SIZE), (byte) 0);
    }

    nonceKey.setS(nonce, (short) 0, SZ);
    short len = secp256k1.multiplyPoint(nonceKey, BabyJubJub.G, (short) 0, BabyJubJub.POINT_SIZE, buf, outOff);

    if (integer) {
      // r stays in noncePrime only (mod l it is r): the modular nonce is not needed any more
      invalidateNonce();
    }
    state[0] = ARMED_0;
    state[1] = integer ? ARMED_INT : ARMED_MOD;
    return len;
  }

  /** RESPOND: data = c (32 bytes, big-endian, c < l). Returns S (32 bytes) or S' (72 bytes), then R if chained. */
  private short respond(byte[] buf) {
    checkLc(buf, SZ);
    byte p1 = buf[ISO7816.OFFSET_P1];
    boolean masked = (p1 & P1_MASKED) != 0;
    boolean integer = (p1 & P1_INTEGER) != 0;
    if ((p1 & (byte) 0xF0) != 0 || (masked && integer) || buf[ISO7816.OFFSET_P2] != 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
    }
    byte[] t = crypto.scratch;

    if (state[0] != ARMED_0) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (state[1] != (integer ? ARMED_INT : ARMED_MOD)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    disarm();

    // The stored nonce is replaced by fresh randomness before any computation: a replayed RESPOND (skipped state
    // check) yields r'' + c.s with r'' never published, and never c.s alone.
    short resLen;
    if (integer) {
      Util.arrayCopyNonAtomic(noncePrime, (short) 0, t, T1_OFF, INT_SIZE);
      crypto.random.generateData(noncePrime, (short) 0, INT_SIZE);
      if (crypto.isZero256(t, (short) (T1_OFF + INT_SIZE - SZ)) || (lessThan(buf, ISO7816.OFFSET_CDATA, BabyJubJub.R, (short) 0) == 0)) {
        Util.arrayFillNonAtomic(t, T1_OFF, INT_SIZE, (byte) 0);
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
      secretKey.getS(t, SK_OFF);
      resLen = respondInteger(buf, t, (p1 & P1_SINGLE) == 0);
    } else {
      Util.arrayCopyNonAtomic(nonce, (short) 0, t, W_OFF, SZ);
      invalidateNonce();
      if (crypto.isZero256(t, W_OFF) || (lessThan(buf, ISO7816.OFFSET_CDATA, BabyJubJub.R, (short) 0) == 0)) {
        Util.arrayFillNonAtomic(t, W_OFF, SZ, (byte) 0);
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
      secretKey.getS(t, SK_OFF);
      resLen = respondModular(buf, t, masked, (p1 & P1_SINGLE) == 0);
    }

    // The response is in scratch[T1_OFF], s and r are wiped
    if ((p1 & P1_CHAIN) != 0) {
      short rLen = openSession(buf, (short) (ISO7816.OFFSET_CDATA + resLen), integer);
      Util.arrayCopyNonAtomic(t, T1_OFF, buf, ISO7816.OFFSET_CDATA, resLen);
      Util.arrayFillNonAtomic(t, T1_OFF, resLen, (byte) 0);
      return (short) (resLen + rLen);
    }
    Util.arrayCopyNonAtomic(t, T1_OFF, buf, ISO7816.OFFSET_CDATA, resLen);
    Util.arrayFillNonAtomic(t, T1_OFF, resLen, (byte) 0);
    return resLen;
  }

  /** S = r + c.s mod l into t[T1_OFF], computed twice unless single. */
  private short respondModular(byte[] buf, byte[] t, boolean masked, boolean twice) {
    computeS(buf, t, T1_OFF, masked);
    if (twice) {
      computeS(buf, t, T2_OFF, masked);
    } else {
      Util.arrayCopyNonAtomic(t, T1_OFF, t, T2_OFF, SZ);
    }
    Util.arrayFillNonAtomic(t, W_OFF, (short) (2 * SZ), (byte) 0);
    if (Util.arrayCompare(t, T1_OFF, t, T2_OFF, SZ) != 0) {
      Util.arrayFillNonAtomic(t, T1_OFF, (short) (2 * SZ), (byte) 0);
      ISOException.throwIt(SW_FAULT);
    }
    Util.arrayFillNonAtomic(t, T2_OFF, SZ, (byte) 0);
    return SZ;
  }

  /** t[dst] = r + c.s mod l, with c at buf[OFFSET_CDATA], r at t[W_OFF], s at t[SK_OFF]. */
  private void computeS(byte[] buf, byte[] t, short dst, boolean masked) {
    Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, t, dst, SZ);
    if (!masked) {
      crypto.bigMath.modMul(t, dst, SZ, t, SK_OFF, SZ, BabyJubJub.R, (short) 0, SZ);
    } else {
      // s = s1 + m with m fresh (m < 2^250 < l): c.s = c.s1 + c.m
      crypto.random.generateData(buf, M_OFF, SZ);
      buf[M_OFF] &= (byte) 0x03;
      Util.arrayCopyNonAtomic(t, SK_OFF, buf, S1_OFF, SZ);
      crypto.bigMath.modSub(buf, S1_OFF, SZ, buf, M_OFF, SZ, BabyJubJub.R, (short) 0, SZ);
      crypto.bigMath.modMul(t, dst, SZ, buf, S1_OFF, SZ, BabyJubJub.R, (short) 0, SZ);
      Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, buf, S1_OFF, SZ);
      crypto.bigMath.modMul(buf, S1_OFF, SZ, buf, M_OFF, SZ, BabyJubJub.R, (short) 0, SZ);
      crypto.bigMath.modAdd(t, dst, SZ, buf, S1_OFF, SZ, BabyJubJub.R, (short) 0, SZ);
      Util.arrayFillNonAtomic(buf, M_OFF, (short) (2 * SZ), (byte) 0);
    }
    crypto.bigMath.modAdd(t, dst, SZ, t, W_OFF, SZ, BabyJubJub.R, (short) 0, SZ);
  }

  /**
   * S' = r' + c.s over the integers into t[T1_OFF] (r' was moved there by respond), computed twice unless single.
   * c.s = ((c + s)^2 - c^2 - s^2) / 2 with three exact RSA-736 squarings.
   */
  private short respondInteger(byte[] buf, byte[] t, boolean twice) {
    short res = (short) (X_OFF + RSA_SIZE - INT_SIZE);
    short hi = (short) (INT_SIZE - T_SIZE);
    productCS(buf, t);
    addRight(buf, X_OFF, RSA_SIZE, t, T1_OFF, INT_SIZE);
    if (twice) {
      // keep the first result in the free scratch areas (32 + 40 bytes), recompute into X
      Util.arrayCopyNonAtomic(buf, res, t, W_OFF, hi);
      Util.arrayCopyNonAtomic(buf, (short) (res + hi), t, T_OFF, T_SIZE);
      productCS(buf, t);
      addRight(buf, X_OFF, RSA_SIZE, t, T1_OFF, INT_SIZE);
      if (Util.arrayCompare(buf, res, t, W_OFF, hi) != 0
          || Util.arrayCompare(buf, (short) (res + hi), t, T_OFF, T_SIZE) != 0) {
        Util.arrayFillNonAtomic(buf, X_OFF, (short) (2 * RSA_SIZE), (byte) 0);
        Util.arrayFillNonAtomic(t, (short) 0, (short) t.length, (byte) 0);
        ISOException.throwIt(SW_FAULT);
      }
      Util.arrayFillNonAtomic(t, W_OFF, hi, (byte) 0);
      Util.arrayFillNonAtomic(t, T_OFF, T_SIZE, (byte) 0);
    }
    Util.arrayCopyNonAtomic(buf, res, t, T1_OFF, INT_SIZE);
    Util.arrayFillNonAtomic(t, SK_OFF, SZ, (byte) 0);
    Util.arrayFillNonAtomic(buf, X_OFF, (short) (2 * RSA_SIZE), (byte) 0);
    return INT_SIZE;
  }

  /** X = c.s (exact), with c at buf[OFFSET_CDATA] and s at t[SK_OFF]; Y is scratch space. */
  private void productCS(byte[] buf, byte[] t) {
    short yWin = (short) (Y_OFF + RSA_SIZE - WIN_RESP);
    setRight(buf, X_OFF, buf, ISO7816.OFFSET_CDATA, SZ);
    addRight(buf, X_OFF, WIN_RESP, t, SK_OFF, SZ);
    squareInPlace(buf, X_OFF);
    setRight(buf, Y_OFF, buf, ISO7816.OFFSET_CDATA, SZ);
    squareInPlace(buf, Y_OFF);
    subRight(buf, X_OFF, WIN_RESP, buf, yWin, WIN_RESP);
    setRight(buf, Y_OFF, t, SK_OFF, SZ);
    squareInPlace(buf, Y_OFF);
    subRight(buf, X_OFF, WIN_RESP, buf, yWin, WIN_RESP);
    shiftRight1(buf, (short) (X_OFF + RSA_SIZE - WIN_RESP), WIN_RESP);
  }

  /**
   * CALIBRATE: runs P1P2 iterations of a fixed loop body. On a real card, the slope of the APDU time against the
   * iteration count, divided by the bytecodes per iteration reported by the profiler, gives the cost of a bytecode.
   */
  private short calibrate(byte[] buf) {
    short n = Util.getShort(buf, ISO7816.OFFSET_P1);
    byte[] t = crypto.scratch;
    short acc = 0;
    for (short i = 0; i < n; i++) {
      acc = (short) (acc + t[(short) (i & 0x1F)]);
    }
    buf[ISO7816.OFFSET_CDATA] = (byte) acc;
    return 1;
  }

  private void disarm() {
    state[0] = 0;
    state[1] = 0;
  }

  /** Replaces the nonce (array and key object) with fresh randomness below 2^250 < l. */
  private void invalidateNonce() {
    crypto.random.generateData(nonce, (short) 0, SZ);
    nonce[0] &= (byte) 0x03;
    nonceKey.setS(nonce, (short) 0, SZ);
  }

  private void requireKey() {
    if (publicKey[0] != (byte) 0x04) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  private static void checkLc(byte[] buf, short expected) {
    if ((short) (buf[ISO7816.OFFSET_LC] & 0xFF) != expected) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
  }

  /** In-place exact square of the RSA-size block at buf[off] (the value must be below 2^367). */
  private void squareInPlace(byte[] buf, short off) {
    square.doFinal(buf, off, RSA_SIZE, buf, off);
  }

  /** dst[dstOff .. dstOff + RSA_SIZE) = src right-aligned, zero-padded. */
  private static void setRight(byte[] dst, short dstOff, byte[] src, short srcOff, short len) {
    Util.arrayFillNonAtomic(dst, dstOff, (short) (RSA_SIZE - len), (byte) 0);
    Util.arrayCopyNonAtomic(src, srcOff, dst, (short) (dstOff + RSA_SIZE - len), len);
  }

  /** Adds b (bLen bytes) to the last win bytes of the RSA-size block at a[aOff]; carry out of the window dropped. */
  private static void addRight(byte[] a, short aOff, short win, byte[] b, short bOff, short bLen) {
    short carry = 0;
    short aEnd = (short) (aOff + RSA_SIZE - 1);
    for (short i = 0; i < win; i++) {
      short x = (short) (a[(short) (aEnd - i)] & 0xFF);
      short y = i < bLen ? (short) (b[(short) (bOff + bLen - 1 - i)] & 0xFF) : 0;
      short sum = (short) (x + y + carry);
      a[(short) (aEnd - i)] = (byte) sum;
      carry = (short) ((sum >> 8) & 1);
    }
  }

  /** Subtracts b (bLen bytes) from the last win bytes of the RSA-size block at a[aOff]; borrow out dropped. */
  private static void subRight(byte[] a, short aOff, short win, byte[] b, short bOff, short bLen) {
    short borrow = 0;
    short aEnd = (short) (aOff + RSA_SIZE - 1);
    for (short i = 0; i < win; i++) {
      short x = (short) (a[(short) (aEnd - i)] & 0xFF);
      short y = i < bLen ? (short) (b[(short) (bOff + bLen - 1 - i)] & 0xFF) : 0;
      short d = (short) (x - y - borrow);
      a[(short) (aEnd - i)] = (byte) d;
      borrow = (short) ((short) (d >> 8) & 1);
    }
  }

  /** In-place logical right shift by 1 of a len-byte big-endian number. */
  private static void shiftRight1(byte[] a, short off, short len) {
    for (short i = (short) (len - 1); i > 0; i--) {
      a[(short) (off + i)] = (byte) (((a[(short) (off + i)] & 0xFF) >>> 1) | ((a[(short) (off + i - 1)] & 0x01) << 7));
    }
    a[off] = (byte) ((a[off] & 0xFF) >>> 1);
  }

  /** Constant-time unsigned comparison of two 256-bit big-endian numbers: 1 if a < b, else 0. */
  private static short lessThan(byte[] a, short aOff, byte[] b, short bOff) {
    short borrow = 0;
    for (short i = (short) (SZ - 1); i >= 0; i--) {
      short d = (short) ((short) (a[(short) (aOff + i)] & 0xFF) - (short) (b[(short) (bOff + i)] & 0xFF) - borrow);
      borrow = (short) ((short) (d >> 8) & 1);
    }
    return borrow;
  }

  /** In-place logical right shift by 3 of a 256-bit big-endian number. */
  private static void shiftRight3(byte[] a, short off) {
    for (short i = (short) (SZ - 1); i > 0; i--) {
      a[(short) (off + i)] = (byte) (((a[(short) (off + i)] & 0xFF) >>> 3) | ((a[(short) (off + i - 1)] & 0x07) << 5));
    }
    a[off] = (byte) ((a[off] & 0xFF) >>> 3);
  }
}
