package zknox.kcsim;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * circomlib Poseidon for 5 inputs (t = 6, 8 full rounds, 60 partial rounds), reference implementation of circomlibjs
 * 0.1.7 (poseidon_reference.js). Constants: res poseidon_t6.txt, extracted from circomlibjs src/poseidon_constants.json.
 */
final class Poseidon {
  private static final int T = 6;
  private static final int RF = 8;
  private static final int RP = 60;
  private static final BigInteger[] C;
  private static final BigInteger[][] M;

  static {
    try (InputStream in = Poseidon.class.getResourceAsStream("poseidon_t6.txt")) {
      if (in == null) {
        throw new IllegalStateException("ressource poseidon_t6.txt absente");
      }
      BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.US_ASCII));
      String line = r.readLine();
      while (line.startsWith("#")) {
        line = r.readLine();
      }
      int nc = Integer.parseInt(line.substring(2).trim());
      C = new BigInteger[nc];
      for (int i = 0; i < nc; i++) {
        C[i] = parse(r.readLine());
      }
      int nm = Integer.parseInt(r.readLine().substring(2).trim());
      M = new BigInteger[nm][];
      for (int i = 0; i < nm; i++) {
        String[] parts = r.readLine().trim().split("\\s+");
        M[i] = new BigInteger[parts.length];
        for (int j = 0; j < parts.length; j++) {
          M[i][j] = parse(parts[j]);
        }
      }
      if (nc != T * (RF + RP) || nm != T) {
        throw new IllegalStateException("constantes Poseidon inattendues");
      }
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private Poseidon() {}

  private static BigInteger parse(String s) {
    s = s.trim();
    return s.startsWith("0x") ? new BigInteger(s.substring(2), 16) : new BigInteger(s);
  }

  private static BigInteger pow5(BigInteger a) {
    BigInteger a2 = a.multiply(a).mod(Bjj.P);
    return a2.multiply(a2).mod(Bjj.P).multiply(a).mod(Bjj.P);
  }

  static BigInteger hash(BigInteger... inputs) {
    if (inputs.length != T - 1) {
      throw new IllegalArgumentException("Poseidon t=6 : 5 entrées attendues");
    }
    BigInteger[] s = new BigInteger[T];
    s[0] = BigInteger.ZERO;
    for (int i = 0; i < inputs.length; i++) {
      s[i + 1] = inputs[i].mod(Bjj.P);
    }
    for (int r = 0; r < RF + RP; r++) {
      for (int i = 0; i < T; i++) {
        s[i] = s[i].add(C[r * T + i]).mod(Bjj.P);
      }
      if (r < RF / 2 || r >= RF / 2 + RP) {
        for (int i = 0; i < T; i++) {
          s[i] = pow5(s[i]);
        }
      } else {
        s[0] = pow5(s[0]);
      }
      BigInteger[] n = new BigInteger[T];
      for (int i = 0; i < T; i++) {
        BigInteger acc = BigInteger.ZERO;
        for (int j = 0; j < T; j++) {
          acc = acc.add(M[i][j].multiply(s[j]));
        }
        n[i] = acc.mod(Bjj.P);
      }
      s = n;
    }
    return s[0];
  }
}
