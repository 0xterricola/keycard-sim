package zknox.kcsim;

import im.status.keycard.io.APDUResponse;
import zknox.kcprof.Trace;

import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Blind EdDSA-Poseidon signer on BabyJubJub (COMMIT / RESPOND): functional checks, signatures verified with the
 * circomlib equation, and a per-APDU profile (bytecodes, priced API calls, allocations) turned into an estimate for an
 * NXP JCOP4 (J3R180 data from JCAlgTest). With --target pcsc, the times are measured on the real card.
 */
public final class BjjBench {
  static final int INS_LOAD_KEY = 0xB0;
  static final int INS_GET_PUBLIC = 0xB1;
  static final int INS_COMMIT = 0xB2;
  static final int INS_RESPOND = 0xB3;
  static final int INS_CALIBRATE = 0xB4;

  /** RESPOND variant: COMMIT P1, RESPOND P1, chained (RESPOND opens the next session). */
  static final class Mode {
    final int commitP1;
    final int respondP1;
    final boolean integer;
    final boolean chain;

    Mode(int commitP1, int respondP1) {
      this.commitP1 = commitP1;
      this.respondP1 = respondP1;
      this.integer = (respondP1 & 0x04) != 0;
      this.chain = (respondP1 & 0x08) != 0;
    }

    String commitLabel() {
      return integer ? "COMMIT integer" : "COMMIT";
    }
  }

  static final Map<String, Mode> MODES = new LinkedHashMap<>();

  static {
    MODES.put("plain", new Mode(0x00, 0x00));
    MODES.put("masked", new Mode(0x00, 0x01));
    MODES.put("single", new Mode(0x00, 0x02));
    MODES.put("integer", new Mode(0x04, 0x04));
    MODES.put("integer-single", new Mode(0x04, 0x06));
    MODES.put("chain", new Mode(0x00, 0x08));
    MODES.put("integer-chain", new Mode(0x04, 0x0C));
  }

  static final class Opts {
    String target = "sim";
    int iters = 100;
    int warmup = 10;
    List<String> modes = new ArrayList<>(MODES.keySet());
    double[] tbc = {0.5, 1.0, 2.0};
    double apiOtherUs = 0;
    String csv = null;
    String export = null;
    String costs = "costs/jcop4_j3r180.tsv";
    String vectors = "vectors/circomlib_vectors.json";
    int top = 12;
    List<String> details = List.of("COMMIT", "RESPOND plain", "COMMIT integer", "RESPOND integer");
    boolean reference = true;
    int calN = 2000;
    String pin = "000000";
    String puk = "012345678901";
    String pairingPassword = "KeycardDefaultPairing";
    boolean provision = false;

    static Opts parse(String[] args) {
      Opts o = new Opts();
      for (int i = 0; i < args.length; i++) {
        switch (args[i]) {
          case "--target": o.target = args[++i]; break;
          case "--iters": o.iters = Integer.parseInt(args[++i]); break;
          case "--warmup": o.warmup = Integer.parseInt(args[++i]); break;
          case "--modes": o.modes = Arrays.asList(args[++i].split(",")); break;
          case "--tbc": o.tbc = Arrays.stream(args[++i].split(",")).mapToDouble(Double::parseDouble).toArray(); break;
          case "--api-other-us": o.apiOtherUs = Double.parseDouble(args[++i]); break;
          case "--csv": o.csv = args[++i]; break;
          case "--export": o.export = args[++i]; break;
          case "--costs": o.costs = args[++i]; break;
          case "--vectors": o.vectors = args[++i]; break;
          case "--top": o.top = Integer.parseInt(args[++i]); break;
          case "--details": o.details = Arrays.asList(args[++i].split(",")); break;
          case "--no-reference": o.reference = false; break;
          case "--cal-n": o.calN = Integer.parseInt(args[++i]); break;
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
            System.err.println("option inconnue: " + args[i]);
            usage();
            System.exit(1);
        }
      }
      for (String m : o.modes) {
        if (!MODES.containsKey(m)) {
          throw new IllegalArgumentException("--modes " + String.join(",", MODES.keySet()));
        }
      }
      if (!o.target.equals("sim") && !o.target.equals("pcsc")) {
        throw new IllegalArgumentException("--target sim|pcsc");
      }
      return o;
    }
  }

  static void usage() {
    System.out.println(String.join("\n",
        "usage: bjj.sh [options]",
        "  --target sim|pcsc          simulateur jCardSim profilé (défaut) ou vraie carte (applet forkée chargée)",
        "  --iters 100 --warmup 10    signatures mesurées par mode RESPOND",
        "  --modes plain,masked,single,integer,integer-single,chain,integer-chain",
        "      plain : S mod l calculé deux fois ; masked : s = s1 + m frais ; single : une seule fois",
        "      integer : S' = r + l.t + c.s sur les entiers (pas de réduction mod l sur carte), S = S' mod l sur l'hôte",
        "      chain : RESPOND ouvre la session suivante et renvoie son R (une APDU par signature)",
        "  --tbc 0.5,1,2              coût d'un bytecode Java Card en µs (à calibrer sur carte, voir CALIBRATE)",
        "  --api-other-us 0           coût par appel API non chiffré (getBuffer, throwIt...)",
        "  --costs costs/jcop4_j3r180.tsv",
        "  --csv f.csv                une ligne par APDU mesurée",
        "  --export sigs.json         signatures au format circomlib (tools/verify-circomlib.mjs)",
        "  --top 12                   méthodes affichées par APDU",
        "  --details all|L1,L2        APDU détaillées (défaut : COMMIT,RESPOND plain,COMMIT integer,RESPOND integer)",
        "  --no-reference             pas de mesure de référence SIGN ECDSA / Schnorr secp256k1 de l'applet",
        "  --cal-n 2000               itérations de la boucle CALIBRATE",
        "  --pin 000000 --provision   (pcsc) INIT si vierge et LOAD KEY du scalaire de test : carte de dev uniquement"));
  }

  /** Profile of one APDU. */
  static final class Sample {
    long jvmNs;
    long bc;
    double apiMs;
    long other;
    final Map<String, Long> bcByCat = new TreeMap<>();
    final Map<String, Double> apiByCat = new TreeMap<>();
    final Map<String, Long> bcByMethod = new TreeMap<>();
    final Map<String, Long> eventCount = new TreeMap<>();
    final Map<String, Double> eventMs = new TreeMap<>();
    final Map<String, Long> otherByName = new TreeMap<>();
  }

  static String category(String classMethod) {
    String cls = classMethod.substring(0, classMethod.lastIndexOf('.'));
    String method = classMethod.substring(classMethod.lastIndexOf('.') + 1);
    if (cls.endsWith(".BjjSigner") || cls.endsWith(".BabyJubJub")) {
      return "bjj";
    }
    if (cls.startsWith("im.status.keycard.math.")) {
      return "keycard-math";
    }
    if (cls.endsWith(".SecureChannelV2") || (cls.endsWith(".Crypto") && method.startsWith("aes"))) {
      return "transport SC v2";
    }
    if (cls.endsWith(".KeycardApplet")) {
      return "dispatch";
    }
    if (cls.endsWith(".SECP256k1")) {
      return "moteur EC (PLAIN_XY)";
    }
    return "applet (autre)";
  }

  private final Opts o;
  private final CostModel costs;
  private final SecureRandom rnd = new SecureRandom();
  private final Map<String, List<Sample>> samples = new LinkedHashMap<>();
  private final List<String> checks = new ArrayList<>();
  private int failures;
  private CardSession s;

  BjjBench(Opts o) throws Exception {
    this.o = o;
    this.costs = new CostModel(Path.of(o.costs));
  }

  public static void main(String[] args) throws Exception {
    Opts o = Opts.parse(args);
    BjjBench b = new BjjBench(o);
    int rc = b.run();
    System.exit(rc);
  }

  private void check(String what, boolean ok) {
    checks.add((ok ? "  ok     " : "  ÉCHEC  ") + what);
    if (!ok) {
      failures++;
    }
  }

  private Sample profile(APDUResponse r, long jvmNs, boolean record) {
    Sample sm = new Sample();
    sm.jvmNs = jvmNs;
    for (Map.Entry<String, Long> e : Trace.bytecodes().entrySet()) {
      sm.bc += e.getValue();
      sm.bcByCat.merge(category(e.getKey()), e.getValue(), Long::sum);
      sm.bcByMethod.merge(e.getKey(), e.getValue(), Long::sum);
    }
    for (Trace.Event e : Trace.events()) {
      double ms = costs.ms(e.key, e.len);
      String k = e.key + (e.len >= 0 ? " [" + e.len + " o]" : "");
      sm.eventCount.merge(k, 1L, Long::sum);
      sm.eventMs.merge(k, ms, Double::sum);
      sm.apiMs += ms;
      sm.apiByCat.merge(category(e.caller), ms, Double::sum);
    }
    for (Map.Entry<String, Long> e : Trace.otherApi().entrySet()) {
      sm.other += e.getValue();
      sm.otherByName.merge(e.getKey(), e.getValue(), Long::sum);
    }
    return sm;
  }

  private APDUResponse send(String label, int ins, int p1, int p2, byte[] data, boolean record) throws Exception {
    Trace.reset();
    s.ch.resetWindow();
    APDUResponse r = s.secured(ins, p1, p2, data);
    long ns = s.ch.windowNanos();
    if (record) {
      samples.computeIfAbsent(label, k -> new ArrayList<>()).add(profile(r, ns, true));
    }
    return r;
  }

  private BigInteger[] commit(Mode m, boolean record) throws Exception {
    APDUResponse rc = send(m.commitLabel(), INS_COMMIT, m.commitP1, 0, new byte[0], record);
    if (rc.getSw() != 0x9000) {
      throw new IllegalStateException("COMMIT SW=" + sw(rc));
    }
    return Bjj.fromCard(rc.getData());
  }

  private BigInteger randomField() {
    return new BigInteger(Bjj.P.bitLength() + 64, rnd).mod(Bjj.P);
  }

  int run() throws Exception {
    // ------------------------------------------------------------ host self-tests against circomlibjs vectors
    Object vec = Json.parse(Files.readString(Path.of(o.vectors), StandardCharsets.UTF_8));
    BigInteger[] five = {BigInteger.ONE, BigInteger.TWO, BigInteger.valueOf(3), BigInteger.valueOf(4), BigInteger.valueOf(5)};
    check("Poseidon(1..5) = circomlibjs", Poseidon.hash(five).equals(big(vec, "poseidon5", "output")));
    BigInteger sPruned = big(vec, "eddsa", "s_pruned");
    BigInteger[] vecA = {big(vec, "eddsa", "A", "0"), big(vec, "eddsa", "A", "1")};
    BigInteger[] vecR8 = {big(vec, "eddsa", "R8", "0"), big(vec, "eddsa", "R8", "1")};
    BigInteger vecS = big(vec, "eddsa", "S");
    BigInteger vecMsg = big(vec, "eddsa", "msg");
    check("A = (s >> 3)·B8 = circomlibjs prv2pub", Bjj.eq(Bjj.mul(sPruned.shiftRight(3), Bjj.B8), vecA));
    check("signature circomlibjs vérifiée par l'hôte", Bjj.verify(vecMsg, vecR8, vecS, vecA));
    check("packSignature = circomlibjs", Hex.of(Bjj.packSignature(vecR8, vecS))
        .equals(Json.path(vec, "eddsa", "packedSignature")));
    BigInteger[] aw = Bjj.toWeierstrass(vecA);
    check("Edwards → Weierstrass → Edwards (A)", Bjj.onWeierstrass(aw[0], aw[1]) && Bjj.eq(Bjj.toEdwards(aw[0], aw[1]), vecA));

    // ------------------------------------------------------------ session, allocations made at installation
    s = CardSession.open(o.target, o.pin, o.puk, o.pairingPassword, o.provision);
    List<Trace.Alloc> installAllocs = Trace.allocations();

    // ------------------------------------------------------------ calibration (bytecodes per loop iteration)
    double bcPerIter = calibrationBytecodes();
    System.out.println("cible        : " + s.describe());
    System.out.println("applet       : Keycard " + s.info.getAppVersionString() + " + BjjSigner (INS B0..B4)");
    System.out.println("modèle coûts : " + costs.source);
    System.out.println("JVM          : " + System.getProperty("java.vm.name") + " " + System.getProperty("java.version"));

    BigInteger[] pub;
    if (s.sim || o.provision) {
      APDUResponse r = send("LOAD_KEY", INS_LOAD_KEY, 0, 0, Bjj.be32(sPruned), true);
      check("LOAD_KEY SW=9000", r.getSw() == 0x9000);
      pub = Bjj.fromCard(r.getData());
      check("A renvoyé par la carte = circomlibjs prv2pub", Bjj.eq(pub, vecA));
    }
    APDUResponse rp = send("GET_PUBLIC", INS_GET_PUBLIC, 0, 0, new byte[0], true);
    if (rp.getSw() != 0x9000) {
      throw new IllegalStateException("pas de clé BabyJubJub sur la carte (GET_PUBLIC SW=" + sw(rp) + ") : --provision");
    }
    pub = Bjj.fromCard(rp.getData());
    if (s.sim || o.provision) {
      check("GET_PUBLIC = A chargé", Bjj.eq(pub, vecA));
    }

    functionalChecks(pub);

    // ------------------------------------------------------------ measured signatures
    List<String> exported = new ArrayList<>();
    long hostNs = 0;
    int hostN = 0;
    for (String mode : o.modes) {
      Mode m = MODES.get(mode);
      BigInteger[] r8 = null;
      if (m.chain) {
        r8 = commit(m, false);
      }
      for (int i = 0; i < o.warmup + o.iters; i++) {
        boolean rec = i >= o.warmup;
        if (!m.chain) {
          r8 = commit(m, rec);
        }
        long h0 = System.nanoTime();
        BigInteger msg = randomField();
        BigInteger c = Poseidon.hash(r8[0], r8[1], pub[0], pub[1], msg).mod(Bjj.L);
        hostNs += System.nanoTime() - h0;
        hostN++;
        APDUResponse rr = send("RESPOND " + mode, INS_RESPOND, m.respondP1, 0, Bjj.be32(c), rec);
        if (rr.getSw() != 0x9000) {
          throw new IllegalStateException("RESPOND " + mode + " SW=" + sw(rr));
        }
        byte[] d = rr.getData();
        int sLen = m.integer ? 72 : 32;
        if (d.length != sLen + (m.chain ? 65 : 0)) {
          throw new IllegalStateException("RESPOND " + mode + " : longueur " + d.length);
        }
        BigInteger sv = new BigInteger(1, Arrays.copyOfRange(d, 0, sLen)).mod(Bjj.L);
        boolean ok = Bjj.verify(msg, r8, sv, pub);
        if (!ok) {
          failures++;
          System.err.println("ÉCHEC vérification " + mode + " iter=" + i + " msg=" + msg + " S=" + sv);
        }
        if (o.export != null && i < o.warmup + 10) {
          exported.add(String.format("{\"mode\":\"%s\",\"msg\":\"%s\",\"A\":[\"%s\",\"%s\"],\"R8\":[\"%s\",\"%s\"],"
              + "\"S\":\"%s\",\"packed\":\"%s\"}", mode, msg, pub[0], pub[1], r8[0], r8[1], sv,
              Hex.of(Bjj.packSignature(r8, sv))));
        }
        if (m.chain) {
          long h1 = System.nanoTime();
          r8 = Bjj.fromCard(Arrays.copyOfRange(d, sLen, d.length));
          hostNs += System.nanoTime() - h1;
        }
      }
    }
    int nsig = o.modes.size() * (o.warmup + o.iters);
    check(nsig + " signatures vérifiées (équation circomlib verifyPoseidon)", failures == 0);

    // ------------------------------------------------------------ reference: the applet's own SIGN (secp256k1)
    if (o.reference && (s.sim || o.provision)) {
      s.cmd.loadKey(KcBench.TEST_SEED).checkOK();
      String path = "m/44'/60'/0'/0/0";
      int[] p2s = {0x00, 0x03};
      String[] labels = {"SIGN ECDSA k1", "SIGN Schnorr k1"};
      for (int a = 0; a < 2; a++) {
        for (int i = 0; i < o.warmup + Math.max(1, o.iters / 2); i++) {
          byte[] hash = HostCrypto.sha256(("ref-" + a + "-" + i).getBytes(StandardCharsets.US_ASCII));
          Trace.reset();
          s.ch.resetWindow();
          APDUResponse r = s.cmd.signWithPath(hash, path, p2s[a], false);
          long ns = s.ch.windowNanos();
          if (!r.isOK()) {
            throw new IllegalStateException(labels[a] + " SW=" + sw(r));
          }
          if (i >= o.warmup) {
            samples.computeIfAbsent(labels[a], k -> new ArrayList<>()).add(profile(r, ns, true));
          }
        }
      }
    }

    // ------------------------------------------------------------ calibration on the target
    double tbcMeasured = Double.NaN;
    if (!s.sim) {
      tbcMeasured = measureTbcOnCard(bcPerIter);
    }

    report(installAllocs, bcPerIter, tbcMeasured, hostNs / (double) Math.max(1, hostN));

    if (o.csv != null) {
      writeCsv();
    }
    if (o.export != null) {
      Files.writeString(Path.of(o.export), "[\n" + String.join(",\n", exported) + "\n]\n", StandardCharsets.UTF_8);
      System.out.println("signatures exportées : " + o.export + " (cd tools && npm install && node verify-circomlib.mjs <chemin absolu>)");
    }
    s.close();
    System.out.println();
    System.out.println("contrôles :");
    checks.forEach(System.out::println);
    return failures == 0 ? 0 : 2;
  }

  private void functionalChecks(BigInteger[] pub) throws Exception {
    APDUResponse r = send("x", INS_RESPOND, 0, 0, Bjj.be32(BigInteger.ONE), false);
    check("RESPOND sans COMMIT refusé (6985)", r.getSw() == 0x6985);

    r = send("x", INS_COMMIT, 0, 0, new byte[0], false);
    r = send("x", INS_RESPOND, 0, 0, Bjj.be32(Bjj.L), false);
    check("RESPOND avec c ≥ l refusé (6A80)", r.getSw() == 0x6A80);
    r = send("x", INS_RESPOND, 0, 0, Bjj.be32(BigInteger.TEN), false);
    check("session consommée même après un refus (6985)", r.getSw() == 0x6985);

    APDUResponse c1 = send("x", INS_COMMIT, 0, 0, new byte[0], false);
    APDUResponse c2 = send("x", INS_COMMIT, 0, 0, new byte[0], false);
    BigInteger[] r1 = Bjj.fromCard(c1.getData());
    BigInteger[] r2 = Bjj.fromCard(c2.getData());
    BigInteger msg = randomField();
    BigInteger c = Poseidon.hash(r2[0], r2[1], pub[0], pub[1], msg).mod(Bjj.L);
    r = send("x", INS_RESPOND, 0, 0, Bjj.be32(c), false);
    BigInteger sv = new BigInteger(1, r.getData());
    check("COMMIT remplace la session précédente (signature valide avec le second R)",
        r.getSw() == 0x9000 && Bjj.verify(msg, r2, sv, pub) && !Bjj.verify(msg, r1, sv, pub));
    r = send("x", INS_RESPOND, 0, 0, Bjj.be32(c), false);
    check("second RESPOND sur la même session refusé (6985)", r.getSw() == 0x6985);

    send("x", INS_COMMIT, 0, 0, new byte[0], false);
    r = send("x", INS_RESPOND, 0, 0, new byte[31], false);
    check("RESPOND de longueur incorrecte refusé (6700)", r.getSw() == 0x6700);
    r = send("x", INS_RESPOND, 0x10, 0, Bjj.be32(BigInteger.ONE), false);
    check("RESPOND P1 inconnu refusé (6B00)", r.getSw() == 0x6B00);
    r = send("x", INS_RESPOND, 0x05, 0, Bjj.be32(BigInteger.ONE), false);
    check("RESPOND masked + integer refusé (6B00)", r.getSw() == 0x6B00);

    // integer response: S' = r + l.t + c.s, S = S' mod l
    BigInteger[] ri = Bjj.fromCard(send("x", INS_COMMIT, 0x04, 0, new byte[0], false).getData());
    r = send("x", INS_RESPOND, 0x00, 0, Bjj.be32(BigInteger.ONE), false);
    check("session integer refusée par un RESPOND modulaire (6985)", r.getSw() == 0x6985);
    ri = Bjj.fromCard(send("x", INS_COMMIT, 0x04, 0, new byte[0], false).getData());
    msg = randomField();
    c = Poseidon.hash(ri[0], ri[1], pub[0], pub[1], msg).mod(Bjj.L);
    r = send("x", INS_RESPOND, 0x04, 0, Bjj.be32(c), false);
    BigInteger sInt = new BigInteger(1, r.getData());
    check("RESPOND integer : S' de 72 octets, S' mod l vérifié, S' ≥ 2^500 (masque l.t présent)",
        r.getSw() == 0x9000 && r.getData().length == 72 && Bjj.verify(msg, ri, sInt.mod(Bjj.L), pub)
            && sInt.bitLength() > 500);

    // chained responses: the R returned with S opens the next session
    BigInteger[] rc = Bjj.fromCard(send("x", INS_COMMIT, 0, 0, new byte[0], false).getData());
    boolean chainOk = true;
    for (int k = 0; k < 3; k++) {
      msg = randomField();
      c = Poseidon.hash(rc[0], rc[1], pub[0], pub[1], msg).mod(Bjj.L);
      r = send("x", INS_RESPOND, 0x08, 0, Bjj.be32(c), false);
      byte[] d = r.getData();
      chainOk &= r.getSw() == 0x9000 && d.length == 97
          && Bjj.verify(msg, rc, new BigInteger(1, Arrays.copyOfRange(d, 0, 32)), pub);
      rc = Bjj.fromCard(Arrays.copyOfRange(d, 32, 97));
    }
    msg = randomField();
    c = Poseidon.hash(rc[0], rc[1], pub[0], pub[1], msg).mod(Bjj.L);
    r = send("x", INS_RESPOND, 0x00, 0, Bjj.be32(c), false);
    chainOk &= r.getSw() == 0x9000 && Bjj.verify(msg, rc, new BigInteger(1, r.getData()), pub);
    check("RESPOND chaîné : 3 signatures enchaînées puis une signature sur le dernier R", chainOk);
  }

  /** Bytecodes executed per iteration of the CALIBRATE loop, from a profiled simulator session. */
  private double calibrationBytecodes() throws Exception {
    CardSession cal = s.sim ? s : CardSession.open("sim", o.pin, o.puk, o.pairingPassword, false);
    CardSession saved = s;
    s = cal;
    long[] bc = new long[2];
    int[] ns = {0, o.calN};
    for (int k = 0; k < 2; k++) {
      Trace.reset();
      APDUResponse r = s.secured(INS_CALIBRATE, (ns[k] >> 8) & 0xFF, ns[k] & 0xFF, new byte[0]);
      if (r.getSw() != 0x9000) {
        throw new IllegalStateException("CALIBRATE SW=" + sw(r));
      }
      bc[k] = Trace.bytecodes().entrySet().stream().filter(e -> e.getKey().endsWith("BjjSigner.calibrate"))
          .mapToLong(Map.Entry::getValue).sum();
    }
    if (cal != saved) {
      cal.close();
    }
    s = saved;
    return (bc[1] - bc[0]) / (double) o.calN;
  }

  /** On a real card: t_bc = (T(n) - T(0)) / (n x bytecodes per iteration). */
  private double measureTbcOnCard(double bcPerIter) throws Exception {
    int reps = 10;
    long[] t0 = new long[reps];
    long[] t1 = new long[reps];
    for (int i = 0; i < reps; i++) {
      t0[i] = timeCalibrate(0);
      t1[i] = timeCalibrate(o.calN);
    }
    Arrays.sort(t0);
    Arrays.sort(t1);
    double delta = (t1[reps / 2] - t0[reps / 2]) / 1e3;
    return delta / (o.calN * bcPerIter);
  }

  private long timeCalibrate(int n) throws Exception {
    s.ch.resetWindow();
    APDUResponse r = s.secured(INS_CALIBRATE, (n >> 8) & 0xFF, n & 0xFF, new byte[0]);
    if (r.getSw() != 0x9000) {
      throw new IllegalStateException("CALIBRATE SW=" + sw(r));
    }
    return s.ch.windowNanos();
  }

  // ---------------------------------------------------------------------------------------------- report

  private static double mean(List<Sample> l, java.util.function.ToDoubleFunction<Sample> f) {
    return l.stream().mapToDouble(f).average().orElse(0);
  }

  private static double min(List<Sample> l, java.util.function.ToDoubleFunction<Sample> f) {
    return l.stream().mapToDouble(f).min().orElse(0);
  }

  private static double max(List<Sample> l, java.util.function.ToDoubleFunction<Sample> f) {
    return l.stream().mapToDouble(f).max().orElse(0);
  }

  private static double transport(Sample sm, double tbcUs) {
    String k = "transport SC v2";
    return sm.apiByCat.getOrDefault(k, 0.0) + sm.bcByCat.getOrDefault(k, 0L) * tbcUs / 1000.0;
  }

  private double estimate(Sample sm, double tbcUs) {
    return sm.apiMs + sm.bc * tbcUs / 1000.0 + sm.other * o.apiOtherUs / 1000.0;
  }

  private void report(List<Trace.Alloc> allocs, double bcPerIter, double tbcMeasured, double hostNs) {
    boolean profiled = s.sim;
    System.out.println();
    if (profiled) {
      System.out.println("== Estimation JCOP4 (ms) = API chiffrées JCAlgTest + bytecodes × t_bc ; transport T=1 non compté");
      double tMid = o.tbc[o.tbc.length / 2];
      StringBuilder h = new StringBuilder(String.format("%-23s %4s %22s %8s", "APDU", "n", "bytecodes moy/min/max", "API ms"));
      for (double t : o.tbc) {
        h.append(String.format(" %9s", "@" + t + "µs"));
      }
      h.append(String.format(" %12s %8s", "dont SC v2*", "JVM ms"));
      System.out.println(h);
      for (Map.Entry<String, List<Sample>> e : samples.entrySet()) {
        List<Sample> l = e.getValue();
        StringBuilder row = new StringBuilder(String.format("%-23s %4d %8.0f/%6.0f/%6.0f %8.2f", e.getKey(), l.size(),
            mean(l, x -> x.bc), min(l, x -> x.bc), max(l, x -> x.bc), mean(l, x -> x.apiMs)));
        for (double t : o.tbc) {
          row.append(String.format(" %9.1f", mean(l, x -> estimate(x, t))));
        }
        row.append(String.format(" %12.1f %8.3f", mean(l, x -> transport(x, tMid)), mean(l, x -> x.jvmNs / 1e6)));
        System.out.println(row);
      }
      System.out.printf("* part du secure channel v2 (AES-CCM, identique pour toute commande Keycard) à %sµs/bytecode%n", tMid);
      System.out.println();
      System.out.println("signature complète (COMMIT + RESPOND) :");
      for (String mode : o.modes) {
        Mode m = MODES.get(mode);
        List<Sample> commit = m.chain ? List.of() : samples.get(m.commitLabel());
        List<Sample> resp = samples.get("RESPOND " + mode);
        StringBuilder row = new StringBuilder(String.format("  %-15s %-7s", mode, m.chain ? "1 APDU" : "2 APDU"));
        for (double t : o.tbc) {
          row.append(String.format("  %6.1f ms @%sµs", mean(commit, x -> estimate(x, t)) + mean(resp, x -> estimate(x, t)), t));
        }
        System.out.println(row);
      }
      System.out.printf("hôte (Java) : conversion Weierstrass→Edwards + Poseidon t=6 = %.3f ms par signature%n", hostNs / 1e6);
      System.out.printf("CALIBRATE : %.2f bytecodes par itération (%d itérations) ; sur carte, t_bc = ΔT / (n × %.2f)%n",
          bcPerIter, o.calN, bcPerIter);

      for (String label : samples.keySet()) {
        if (o.details.contains("all") || o.details.contains(label)) {
          detail(label, samples.get(label));
        }
      }
      memory(allocs);
      if (!costs.unpriced.isEmpty()) {
        System.out.println();
        System.out.println("appels API sans entrée dans le modèle (comptés 0 ms) : " + costs.unpriced);
      }
    } else {
      System.out.println("== Mesures sur carte (ms, transmit de l'APDU chiffré, lecteur compris)");
      System.out.printf("%-16s %5s %9s %9s %9s %9s%n", "APDU", "n", "min", "médiane", "p95", "max");
      for (Map.Entry<String, List<Sample>> e : samples.entrySet()) {
        long[] ns = e.getValue().stream().mapToLong(x -> x.jvmNs).toArray();
        Stats st = new Stats(ns);
        System.out.printf("%-16s %5d %9.2f %9.2f %9.2f %9.2f%n", e.getKey(), st.n, st.min, st.median, st.p95, st.max);
      }
      System.out.printf("t_bc mesuré (CALIBRATE, %d itérations × %.2f bytecodes) : %.3f µs par bytecode%n",
          o.calN, bcPerIter, tbcMeasured);
    }
  }

  private void detail(String label, List<Sample> l) {
    int n = l.size();
    System.out.println();
    System.out.println("-- " + label + " (moyenne par APDU)");
    Map<String, Double> bcCat = new TreeMap<>();
    Map<String, Double> apiCat = new TreeMap<>();
    Map<String, Double> bcMethod = new TreeMap<>();
    Map<String, Double> evCount = new TreeMap<>();
    Map<String, Double> evMs = new TreeMap<>();
    Map<String, Double> other = new TreeMap<>();
    for (Sample sm : l) {
      sm.bcByCat.forEach((k, v) -> bcCat.merge(k, v / (double) n, Double::sum));
      sm.apiByCat.forEach((k, v) -> apiCat.merge(k, v / n, Double::sum));
      sm.bcByMethod.forEach((k, v) -> bcMethod.merge(k, v / (double) n, Double::sum));
      sm.eventCount.forEach((k, v) -> evCount.merge(k, v / (double) n, Double::sum));
      sm.eventMs.forEach((k, v) -> evMs.merge(k, v / n, Double::sum));
      sm.otherByName.forEach((k, v) -> other.merge(k, v / (double) n, Double::sum));
    }
    TreeMap<String, Boolean> cats = new TreeMap<>();
    bcCat.keySet().forEach(k -> cats.put(k, true));
    apiCat.keySet().forEach(k -> cats.put(k, true));
    System.out.printf("   %-18s %12s %10s%n", "catégorie", "bytecodes", "API ms");
    for (String c : cats.keySet()) {
      System.out.printf("   %-18s %12.0f %10.2f%n", c, bcCat.getOrDefault(c, 0.0), apiCat.getOrDefault(c, 0.0));
    }
    System.out.printf("   %-52s %8s %9s %9s%n", "appel API (modèle JCAlgTest)", "appels", "ms/appel", "ms");
    evMs.entrySet().stream().sorted((a, b) -> Double.compare(b.getValue(), a.getValue())).forEach(e -> {
      double cnt = evCount.get(e.getKey());
      System.out.printf("   %-52s %8.2f %9.3f %9.2f%n", e.getKey(), cnt, cnt == 0 ? 0 : e.getValue() / cnt, e.getValue());
    });
    System.out.printf("   %-52s %12s%n", "méthode (top " + o.top + ")", "bytecodes");
    bcMethod.entrySet().stream().sorted((a, b) -> Double.compare(b.getValue(), a.getValue())).limit(o.top)
        .forEach(e -> System.out.printf("   %-52s %12.0f%n", e.getKey().replace("im.status.keycard.", ""), e.getValue()));
    if (!other.isEmpty()) {
      double tot = other.values().stream().mapToDouble(Double::doubleValue).sum();
      System.out.printf("   autres appels API (non chiffrés) : %.1f par APDU %s%n", tot, compact(other));
    }
  }

  private static String compact(Map<String, Double> m) {
    StringBuilder b = new StringBuilder("(");
    m.entrySet().stream().sorted((a, c) -> Double.compare(c.getValue(), a.getValue())).limit(6)
        .forEach(e -> b.append(e.getKey()).append(" ").append(String.format("%.1f", e.getValue())).append(", "));
    if (b.length() > 1) {
      b.setLength(b.length() - 2);
    }
    return b.append(")").toString();
  }

  /** Rough storage of a key object on the card: key value + EC domain parameters (p, a, b, G, r, k). */
  static int keyBytes(String kind) {
    String[] f = kind.split(" ");
    int bits = Integer.parseInt(f[f.length - 1]);
    int n = (bits + 7) / 8;
    if (kind.startsWith("keypair RSA")) {
      return 3 * n + 3;
    }
    if (kind.contains("EC_FP_PRIVATE")) {
      return n + 4 * n + (2 * n + 1) + 2;
    }
    if (kind.contains("EC_FP_PUBLIC")) {
      return (2 * n + 1) + 4 * n + (2 * n + 1) + 2;
    }
    if (kind.contains("HMAC")) {
      return 64;
    }
    return n;
  }

  private void memory(List<Trace.Alloc> allocs) {
    System.out.println();
    System.out.println("== Mémoire allouée à l'installation (tableaux comptés à l'octet ; clés estimées : valeur + paramètres)");
    Map<String, long[]> byOwner = new TreeMap<>();
    Map<String, List<String>> keys = new TreeMap<>();
    for (Trace.Alloc a : allocs) {
      String owner = a.owner.replace("im.status.keycard.", "");
      long[] acc = byOwner.computeIfAbsent(owner, k -> new long[3]);
      if (a.kind.startsWith("key")) {
        String k = a.kind.startsWith("keypair") ? a.kind : a.kind.substring(4);
        keys.computeIfAbsent(owner, x -> new ArrayList<>()).add(k);
        acc[2] += keyBytes(a.kind);
      } else if (a.transientMemory) {
        acc[1] += a.bytes;
      } else {
        acc[0] += a.bytes;
      }
    }
    long[] tot = new long[3];
    long[] bjj = new long[3];
    System.out.printf("   %-20s %10s %10s %12s   %s%n", "classe", "EEPROM (o)", "RAM (o)", "clés ≈ (o)", "objets clés");
    for (Map.Entry<String, long[]> e : byOwner.entrySet()) {
      long[] v = e.getValue();
      boolean isBjj = e.getKey().equals("BjjSigner") || e.getKey().equals("BabyJubJub");
      for (int i = 0; i < 3; i++) {
        tot[i] += v[i];
        if (isBjj) {
          bjj[i] += v[i];
        }
      }
      System.out.printf("   %-20s %10d %10d %12d   %s%n", e.getKey(), v[0], v[1], v[2], keys.getOrDefault(e.getKey(), List.of()));
    }
    System.out.printf("   %-20s %10d %10d %12d%n", "total applet", tot[0], tot[1], tot[2]);
    System.out.printf("   %-20s %10d %10d %12d%n", "dont BabyJubJub", bjj[0], bjj[1], bjj[2]);
    System.out.println("   sur carte, la clé nonce de BjjSigner est TRANSIENT_DESELECT (RAM) ; le build simulateur la rend");
    System.out.println("   persistante (ADR-002), elle apparaît donc ici comme EC_FP_PRIVATE");
    System.out.println("   budget J3R180 (JCAlgTest, avant installation) : persistant 139 360 o, transient CLEAR_ON_RESET 4 084 o");
    System.out.println("   RAM de travail du signer : crypto.scratch (176 o, partagé) + tampon APDU (octets 40 à 224)");
    System.out.println("   taille du code (CAP) : ./cap.sh");
  }

  private void writeCsv() throws Exception {
    try (PrintWriter w = new PrintWriter(o.csv, StandardCharsets.UTF_8)) {
      StringBuilder h = new StringBuilder("apdu,iter,jvm_ms,bytecodes,api_ms,other_api");
      for (double t : o.tbc) {
        h.append(",est_ms_tbc_").append(t);
      }
      w.println(h);
      for (Map.Entry<String, List<Sample>> e : samples.entrySet()) {
        int i = 0;
        for (Sample sm : e.getValue()) {
          StringBuilder row = new StringBuilder(String.format("%s,%d,%.4f,%d,%.4f,%d", e.getKey(), i++, sm.jvmNs / 1e6, sm.bc,
              sm.apiMs, sm.other));
          for (double t : o.tbc) {
            row.append(String.format(",%.4f", estimate(sm, t)));
          }
          w.println(row);
        }
      }
    }
    System.out.println("CSV : " + o.csv);
  }

  private static BigInteger big(Object root, String... path) {
    return new BigInteger((String) Json.path(root, path));
  }

  private static String sw(APDUResponse r) {
    return String.format("%04X", r.getSw());
  }
}
