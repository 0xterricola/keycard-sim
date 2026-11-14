package zknox.kcsim;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Host-side reference crypto used to check what the applet returns. Not timed. */
final class HostCrypto {
  static final X9ECParameters K1 = CustomNamedCurves.getByName("secp256k1");
  static final ECDomainParameters DOMAIN = new ECDomainParameters(K1.getCurve(), K1.getG(), K1.getN(), K1.getH());
  static final BigInteger N = K1.getN();
  static final BigInteger HALF_N = N.shiftRight(1);

  private HostCrypto() {}

  static byte[] sha256(byte[] in) {
    SHA256Digest d = new SHA256Digest();
    d.update(in, 0, in.length);
    byte[] out = new byte[32];
    d.doFinal(out, 0);
    return out;
  }

  static byte[] taggedHash(String tag, byte[]... parts) {
    byte[] th = sha256(tag.getBytes(StandardCharsets.UTF_8));
    SHA256Digest d = new SHA256Digest();
    d.update(th, 0, 32);
    d.update(th, 0, 32);
    for (byte[] p : parts) {
      d.update(p, 0, p.length);
    }
    byte[] out = new byte[32];
    d.doFinal(out, 0);
    return out;
  }

  static byte[] hmacSha512(byte[] key, byte[] data) {
    HMac mac = new HMac(new SHA512Digest());
    mac.init(new KeyParameter(key));
    mac.update(data, 0, data.length);
    byte[] out = new byte[64];
    mac.doFinal(out, 0);
    return out;
  }

  /** BIP32 private derivation from a BIP39 seed; returns the uncompressed public key (65 bytes). */
  static byte[] bip32PublicKey(byte[] seed, String path) {
    byte[] i = hmacSha512("Bitcoin seed".getBytes(StandardCharsets.US_ASCII), seed);
    BigInteger k = new BigInteger(1, Arrays.copyOfRange(i, 0, 32));
    byte[] c = Arrays.copyOfRange(i, 32, 64);

    String[] elems = path.trim().split("/");
    if (!elems[0].equals("m")) {
      throw new IllegalArgumentException("path must start with m: " + path);
    }
    for (int e = 1; e < elems.length; e++) {
      String s = elems[e];
      boolean hardened = s.endsWith("'") || s.endsWith("h");
      long idx = Long.parseLong(hardened ? s.substring(0, s.length() - 1) : s);
      if (hardened) {
        idx += 0x80000000L;
      }
      byte[] data = new byte[37];
      if (hardened) {
        System.arraycopy(BigIntegers.asUnsignedByteArray(32, k), 0, data, 1, 32);
      } else {
        System.arraycopy(K1.getG().multiply(k).getEncoded(true), 0, data, 0, 33);
      }
      data[33] = (byte) (idx >>> 24);
      data[34] = (byte) (idx >>> 16);
      data[35] = (byte) (idx >>> 8);
      data[36] = (byte) idx;
      i = hmacSha512(c, data);
      k = new BigInteger(1, Arrays.copyOfRange(i, 0, 32)).add(k).mod(N);
      c = Arrays.copyOfRange(i, 32, 64);
    }
    return K1.getG().multiply(k).normalize().getEncoded(false);
  }

  static String ethAddress(byte[] pub65) {
    KeccakDigest d = new KeccakDigest(256);
    d.update(pub65, 1, 64);
    byte[] h = new byte[32];
    d.doFinal(h, 0);
    return "0x" + Hex.of(Arrays.copyOfRange(h, 12, 32));
  }

  /** Lenient DER parse: {r, s}. Accepts non-minimal INTEGER encodings. */
  static BigInteger[] parseDerLenient(byte[] der) {
    if (der.length < 8 || der[0] != 0x30 || (der[1] & 0xff) != der.length - 2 || der[2] != 0x02) {
      throw new IllegalArgumentException("DER invalide");
    }
    int lr = der[3] & 0xff;
    int sTag = 4 + lr;
    if (der[sTag] != 0x02) {
      throw new IllegalArgumentException("DER invalide");
    }
    int ls = der[sTag + 1] & 0xff;
    if (sTag + 2 + ls != der.length) {
      throw new IllegalArgumentException("DER invalide");
    }
    return new BigInteger[] {
        new BigInteger(1, Arrays.copyOfRange(der, 4, 4 + lr)),
        new BigInteger(1, Arrays.copyOfRange(der, sTag + 2, sTag + 2 + ls))};
  }

  /** True if the signature is strict DER (what BouncyCastle, OpenSSL and BIP66 parsers require). */
  static boolean isStrictDer(byte[] der) {
    try {
      ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(der);
      ASN1Integer.getInstance(seq.getObjectAt(0));
      ASN1Integer.getInstance(seq.getObjectAt(1));
      return Arrays.equals(seq.getEncoded("DER"), der);
    } catch (Exception e) {
      return false;
    }
  }

  /** ECDSA check on a precomputed hash, plus low-s. DER strictness is reported separately. */
  static boolean ecdsaVerify(byte[] pub65, byte[] hash, byte[] der) {
    try {
      BigInteger[] rs = parseDerLenient(der);
      if (rs[1].compareTo(HALF_N) > 0) {
        return false;
      }
      ECDSASigner v = new ECDSASigner();
      v.init(false, new ECPublicKeyParameters(K1.getCurve().decodePoint(pub65), DOMAIN));
      return v.verifySignature(hash, rs[0], rs[1]);
    } catch (Exception e) {
      return false;
    }
  }

  /** BIP340 verification against the x-only key of pub65 (zero tweak). */
  static boolean bip340Verify(byte[] pub65, byte[] msg32, byte[] sig64) {
    byte[] px = Arrays.copyOfRange(pub65, 1, 33);
    byte[] compressed = new byte[33];
    compressed[0] = 0x02;
    System.arraycopy(px, 0, compressed, 1, 32);
    ECPoint p = K1.getCurve().decodePoint(compressed);
    byte[] rb = Arrays.copyOfRange(sig64, 0, 32);
    BigInteger r = new BigInteger(1, rb);
    BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig64, 32, 64));
    if (r.compareTo(K1.getCurve().getField().getCharacteristic()) >= 0 || s.compareTo(N) >= 0) {
      return false;
    }
    BigInteger e = new BigInteger(1, taggedHash("BIP0340/challenge", rb, px, msg32)).mod(N);
    ECPoint rp = K1.getG().multiply(s).add(p.multiply(N.subtract(e))).normalize();
    if (rp.isInfinity()) {
      return false;
    }
    return !rp.getAffineYCoord().testBitZero() && rp.getAffineXCoord().toBigInteger().equals(r);
  }
}
