package zknox.kcsim;

import im.status.keycard.applet.ApplicationInfo;
import im.status.keycard.applet.KeycardCommandSet;
import im.status.keycard.io.APDUResponse;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Times the Keycard SIGN command, either on the jCardSim simulator or on a real card through PC/SC.
 *
 * Simulator timings are host JVM timings: they validate the flow and give relative costs,
 * not secure element latencies.
 */
public final class KcBench {
  /** BIP39 seed of "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about". */
  static final byte[] TEST_SEED = Hex.parse(
      "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
          + "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4");

  enum Algo { ECDSA, SCHNORR }

  static final class Opts {
    String target = "sim";
    String algo = "both";
    String path = "m/44'/60'/0'/0/0";
    int iters = 200;
    int warmup = 50;
    String csv = null;
    String pin = "000000";
    String puk = "012345678901";
    String pairingPassword = "KeycardDefaultPairing";
    boolean provision = false;

    static Opts parse(String[] args) {
      Opts o = new Opts();
      for (int i = 0; i < args.length; i++) {
        String a = args[i];
        switch (a) {
          case "--target": o.target = args[++i]; break;
          case "--algo": o.algo = args[++i]; break;
          case "--path": o.path = args[++i]; break;
          case "--iters": o.iters = Integer.parseInt(args[++i]); break;
          case "--warmup": o.warmup = Integer.parseInt(args[++i]); break;
          case "--csv": o.csv = args[++i]; break;
          case "--pin": o.pin = args[++i]; break;
          case "--puk": o.puk = args[++i]; break;
          case "--pairing-password": o.pairingPassword = args[++i]; break;
          case "--provision": o.provision = true; break;
          case "-h":
          case "--help":
            usage();
            System.exit(0);
            break;
          default:
            System.err.println("option inconnue: " + a);
            usage();
            System.exit(1);
        }
      }
      if (!o.target.equals("sim") && !o.target.equals("pcsc")) {
        throw new IllegalArgumentException("--target sim|pcsc");
      }
      if (o.iters < 1 || o.warmup < 0) {
        throw new IllegalArgumentException("--iters >= 1, --warmup >= 0");
      }
      return o;
    }

    List<Algo> algos() {
      switch (algo) {
        case "ecdsa": return List.of(Algo.ECDSA);
        case "schnorr": return List.of(Algo.SCHNORR);
        case "both": return List.of(Algo.ECDSA, Algo.SCHNORR);
        default: throw new IllegalArgumentException("--algo ecdsa|schnorr|both");
      }
    }
  }

  static void usage() {
    System.out.println(String.join("\n",
        "usage: run.sh [options]",
        "  --target sim|pcsc        simulateur jCardSim (défaut) ou vrai lecteur PC/SC",
        "  --algo ecdsa|schnorr|both",
        "  --path m/44'/60'/0'/0/0  SIGN P1=01 : l'applet 4.0 dérive le chemin à chaque appel",
        "                           --path m : clé maître sans dérivation (isole le coût BIP32)",
        "  --iters 200 --warmup 50",
        "  --csv fichier.csv        une ligne par signature mesurée",
        "  --pin 000000             (pcsc) PIN utilisateur",
        "  --pairing-password X     (pcsc, cartes SC v1 < 4.0)",
        "  --provision              (pcsc) autorise INIT si vierge et LOAD KEY de la seed de test",
        "                           ÉCRASE la clé de la carte : uniquement sur carte de dev"));
  }

  public static void main(String[] args) throws Exception {
    Opts o = Opts.parse(args);
    boolean sim = o.target.equals("sim");

    CardSession session = CardSession.open(o.target, o.pin, o.puk, o.pairingPassword, o.provision);
    CardTerminal terminal = session.terminal;
    Card card = session.card;
    TimedChannel ch = session.ch;
    KeycardCommandSet cmd = session.cmd;
    ApplicationInfo info = session.info;

    byte[] expectedPub = null;
    if (sim || o.provision) {
      cmd.loadKey(TEST_SEED).checkOK();
      expectedPub = HostCrypto.bip32PublicKey(TEST_SEED, o.path);
    } else if (!info.hasMasterKey()) {
      throw new IllegalStateException("pas de clé maître sur la carte : relancer avec --provision (carte de dev uniquement)");
    }

    System.out.println("cible        : " + (sim
        ? "simulateur jCardSim 3.0.5 (temps JVM hôte, non représentatif d'un secure element)"
        : "PC/SC « " + terminal.getName() + " »"));
    System.out.println("applet       : Keycard " + info.getAppVersionString());
    System.out.println("chemin       : " + o.path + " (SIGN P1=01, dérivation à chaque appel)");
    System.out.println("itérations   : " + o.iters + " (+ " + o.warmup + " de chauffe)");
    System.out.println("JVM          : " + System.getProperty("java.vm.name") + " " + System.getProperty("java.version"));

    List<String[]> csvRows = new ArrayList<>();
    List<String> table = new ArrayList<>();
    int failures = 0;
    int nonStrictDer = 0;
    int ecdsaCount = 0;

    for (Algo algo : o.algos()) {
      int p2 = algo == Algo.ECDSA ? KeycardCommandSet.SIGN_P2_ECDSA : KeycardCommandSet.SIGN_P2_BIP340_SCHNORR;

      long[] cardNs = new long[o.iters];
      long[] totalNs = new long[o.iters];
      String address = null;

      for (int i = 0; i < o.warmup + o.iters; i++) {
        byte[] hash = HostCrypto.sha256(("kcsim-" + algo + "-" + i).getBytes(StandardCharsets.US_ASCII));

        ch.resetWindow();
        long t0 = System.nanoTime();
        APDUResponse r = cmd.signWithPath(hash, o.path, p2, false);
        long t1 = System.nanoTime();

        if (!r.isOK()) {
          throw new IllegalStateException(algo + " SIGN SW=" + String.format("%04X", r.getSw()));
        }
        if (ch.windowApdus() != 1) {
          throw new IllegalStateException(algo + " SIGN a émis " + ch.windowApdus() + " APDU");
        }

        byte[][] parsed = parseSignResponse(r.getData());
        byte[] pub = parsed[0];
        boolean ok = algo == Algo.ECDSA
            ? HostCrypto.ecdsaVerify(pub, hash, parsed[1])
            : HostCrypto.bip340Verify(pub, hash, parsed[1]);
        if (expectedPub != null && !Arrays.equals(expectedPub, pub)) {
          ok = false;
        }
        if (algo == Algo.ECDSA) {
          ecdsaCount++;
          if (!HostCrypto.isStrictDer(parsed[1])) {
            nonStrictDer++;
          }
        }
        if (!ok) {
          failures++;
          System.err.println("ÉCHEC " + algo + " iter=" + i + " hash=" + Hex.of(hash)
              + " pub=" + Hex.of(pub) + " sig=" + Hex.of(parsed[1]));
        }
        if (address == null) {
          address = HostCrypto.ethAddress(pub);
        }

        if (i >= o.warmup) {
          int k = i - o.warmup;
          cardNs[k] = ch.windowNanos();
          totalNs[k] = t1 - t0;
          csvRows.add(new String[] {
              o.target, algo.name().toLowerCase(), o.path, Integer.toString(k),
              String.format("%.4f", cardNs[k] / 1e6), String.format("%.4f", totalNs[k] / 1e6), ok ? "1" : "0"});
        }
      }

      String tag = algo.name().toLowerCase();
      table.add(new Stats(cardNs).row(tag + " carte"));
      table.add(new Stats(totalNs).row(tag + " total hôte"));
      if (algo == Algo.ECDSA) {
        System.out.println("clé dérivée  : " + address
            + (expectedPub != null ? " (dérivation BIP32 hôte identique)" : ""));
      }
    }

    System.out.println();
    System.out.println("temps en ms ; « carte » = transmit de l'APDU chiffré, « total hôte » = + secure channel côté hôte");
    System.out.println(Stats.header());
    table.forEach(System.out::println);
    System.out.println();
    System.out.println("signatures vérifiées côté hôte : " + (failures == 0 ? "toutes valides" : failures + " ÉCHEC(S)"));
    if (ecdsaCount > 0) {
      System.out.println("ECDSA en DER non strict      : " + nonStrictDer + " / " + ecdsaCount
          + (nonStrictDer > 0 ? " (INTEGER s à zéro de tête après la normalisation low-s de l'applet)" : ""));
    }

    if (o.csv != null) {
      try (PrintWriter w = new PrintWriter(o.csv, StandardCharsets.UTF_8)) {
        w.println("target,algo,path,iter,card_ms,total_ms,verified");
        for (String[] row : csvRows) {
          w.println(String.join(",", row[0], row[1], "\"" + row[2] + "\"", row[3], row[4], row[5], row[6]));
        }
      }
      System.out.println("CSV : " + o.csv);
    }

    card.disconnect(false);
    System.exit(failures == 0 ? 0 : 2);
  }

  /** Splits the A0 signature template into {uncompressed pubkey, signature}: DER for ECDSA, r||s (64 bytes) for BIP340. */
  static byte[][] parseSignResponse(byte[] d) {
    if (d.length < 5 || d[0] != (byte) 0xA0 || d[3] != (byte) 0x80) {
      throw new IllegalArgumentException("réponse SIGN inattendue: " + Hex.of(d));
    }
    int pubLen = d[4] & 0xff;
    byte[] pub = Arrays.copyOfRange(d, 5, 5 + pubLen);
    int off = 5 + pubLen;
    byte[] sig;
    if (d[off] == (byte) 0x88) {
      sig = Arrays.copyOfRange(d, off + 2, off + 2 + (d[off + 1] & 0xff));
    } else if (d[off] == (byte) 0x30) {
      sig = Arrays.copyOfRange(d, off, off + 2 + (d[off + 1] & 0xff));
    } else {
      throw new IllegalArgumentException("signature non reconnue: " + Hex.of(d));
    }
    return new byte[][] {pub, sig};
  }
}
