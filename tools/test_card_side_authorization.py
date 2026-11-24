#!/usr/bin/env python3
"""M3.45c.4a — isolated randomized synthetic permit issuer test.

This script does NOT edit or push either repository. It generates an ephemeral
synthetic P-256 keypair, pins only its public key into a temporary applet overlay,
and keeps the private key in a restricted temporary file for the test JVM only.
This tests rejection of a wrong issuer, NOT trusted Shell key provisioning.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path.home() / 'Developer/keycard-sim'
JDK = Path('/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home')
PIN = 'b99e160cb8aa'
BRANCH = 'feat/railgun-two-phase-signing'
report = []
success = False

P256 = {
    'P': 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
    'A': 'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc',
    'B': '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
    'N': 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
    'G': ('04'
          '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'
          '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'),
}

def arrays_java():
    out = []
    for name, h in P256.items():
        raw = bytes.fromhex(h)
        values = ', '.join('(byte)0x%02x' % b for b in raw)
        out.append('  private static final byte[] PERMIT_P256_%s = new byte[] {%s};' % (name, values))
    return '\n'.join(out)

PERMIT_IMPL = r'''
  // M3.45c.4a ISOLATED SIMULATOR EXPERIMENT ONLY.
  // The public verification key is synthesized at build-time for the test.
  // Private issuer material is held by a separate simulated host fixture.
  // No trusted Shell provisioning or production security is established.
  static final byte INS_BJJ_GET_SESSION = (byte) 0xB5;
  static final byte INS_BJJ_AUTHORIZE = (byte) 0xB6;
  static final byte INS_BJJ_CANCEL = (byte) 0xB7;
  private static final byte[] PERMIT_DOMAIN = new byte[] {
      0x52, 0x4c, 0x47, 0x4e, 0x2d, 0x50, 0x45,
      0x52, 0x4d, 0x49, 0x54, 0x2d, 0x56, 0x31
  };
__P256_CONSTANTS__
  private final byte[] permitCardTag;
  private final byte[] permitSessionTag;
  private final byte[] permitCommitPoint;
  private final byte[] permitApprovedChallenge;
  private final byte[] permitPayload;
  private final byte[] permitAuthorized;
  private final javacard.security.ECPublicKey permitIssuer;
  private final javacard.security.Signature permitVerifier;

  private void initPermitIssuer() {
    permitIssuer.setFieldFP(PERMIT_P256_P, (short)0, (short)32);
    permitIssuer.setA(PERMIT_P256_A, (short)0, (short)32);
    permitIssuer.setB(PERMIT_P256_B, (short)0, (short)32);
    permitIssuer.setG(PERMIT_P256_G, (short)0, (short)65);
    permitIssuer.setR(PERMIT_P256_N, (short)0, (short)32);
    permitIssuer.setK((short)1);
    permitIssuer.setW(PERMIT_P256_W, (short)0, (short)65);
    permitVerifier.init(permitIssuer, javacard.security.Signature.MODE_VERIFY);
  }

  private short permitContext(byte[] buf) {
    if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
    }
    checkLc(buf, (short)0);
    if (state[0] != ARMED_0) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    Util.arrayCopyNonAtomic(permitCardTag, (short)0, buf, ISO7816.OFFSET_CDATA, (short)16);
    Util.arrayCopyNonAtomic(permitSessionTag, (short)0, buf, (short)(ISO7816.OFFSET_CDATA + 16), (short)16);
    return (short)32;
  }

  /** AUTHORIZE input: intentDigest[32] || challenge[32] || DER ECDSA[8..72]. */
  private short permitAuthorize(byte[] buf) {
    if (state[0] != ARMED_0 || state[1] != ARMED_MOD || permitAuthorized[0] != 0) {
      permitRevoke();
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short lc = (short)(buf[ISO7816.OFFSET_LC] & 0xFF);
    if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0
        || lc < (short)72 || lc > (short)136) {
      permitRevoke();
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    final short cd = ISO7816.OFFSET_CDATA;
    // Exact 240-byte domain-separated binding; reconstruct on card.
    Util.arrayCopyNonAtomic(PERMIT_DOMAIN, (short)0, permitPayload, (short)0, (short)14);
    Util.arrayCopyNonAtomic(permitCardTag, (short)0, permitPayload, (short)14, (short)16);
    Util.arrayCopyNonAtomic(permitSessionTag, (short)0, permitPayload, (short)30, (short)16);
    Util.arrayCopyNonAtomic(publicKey, (short)0, permitPayload, (short)46, (short)65);
    Util.arrayCopyNonAtomic(permitCommitPoint, (short)0, permitPayload, (short)111, (short)65);
    Util.arrayCopyNonAtomic(buf, cd, permitPayload, (short)176, (short)32);
    Util.arrayCopyNonAtomic(buf, (short)(cd + 32), permitPayload, (short)208, (short)32);
    boolean approved = permitVerifier.verify(
        permitPayload, (short)0, (short)240,
        buf, (short)(cd + 64), (short)(lc - 64));
    Util.arrayFillNonAtomic(permitPayload, (short)0, (short)240, (byte)0);
    if (!approved || lessThan(buf, (short)(cd + 32), BabyJubJub.R, (short)0) == 0) {
      permitRevoke();
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    Util.arrayCopyNonAtomic(buf, (short)(cd + 32), permitApprovedChallenge, (short)0, SZ);
    permitAuthorized[0] = (byte)0x5A;
    return 0;
  }

  private short permitCancel(byte[] buf) {
    if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
    }
    checkLc(buf, (short)0);
    permitRevoke();
    return 0;
  }
  private void permitRevoke() {
    disarm();
    invalidateNonce();
  }
'''

KEYGEN_JAVA = r'''
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.HexFormat;

public final class IssuerFixtureGen {
  static byte[] fixed(BigInteger v) {
    byte[] src = v.toByteArray();
    if (v.signum() < 0 || src.length > 33 || (src.length == 33 && src[0] != 0))
      throw new IllegalArgumentException("Invalid curve coordinate");
    byte[] out = new byte[32];
    int count = Math.min(src.length, 32);
    System.arraycopy(src, src.length - count, out, 32 - count, count);
    return out;
  }
  public static void main(String[] args) throws Exception {
    if (args.length != 2) throw new IllegalArgumentException("Output paths required");
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
    KeyPair pair = generator.generateKeyPair();
    ECPublicKey publicKey = (ECPublicKey)pair.getPublic();
    byte[] point = new byte[65];
    point[0] = 4;
    System.arraycopy(fixed(publicKey.getW().getAffineX()), 0, point, 1, 32);
    System.arraycopy(fixed(publicKey.getW().getAffineY()), 0, point, 33, 32);
    Path privatePath = Path.of(args[0]);
    Files.write(privatePath, pair.getPrivate().getEncoded(),
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    Files.setPosixFilePermissions(privatePath, PosixFilePermissions.fromString("rw-------"));
    Files.writeString(Path.of(args[1]), HexFormat.of().formatHex(point),
                      StandardCharsets.US_ASCII,
                      StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
  }
}
'''

JAVA = r'''
package zknox.kcsim;
import im.status.keycard.io.APDUResponse;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.Arrays;

public final class M345c4aPermit {
  private static CardSession s;
  private static BigInteger[] pub;
  private static PrivateKey shellFixtureKey;
  private static int checks;

  private static void check(String label, boolean success) {
    System.out.println("M345_" + label + ": " + (success ? "PASS" : "FAIL"));
    if (!success) throw new IllegalStateException(label);
    checks++;
  }
  private static APDUResponse apdu(int ins, int p1, byte[] data) throws Exception {
    return s.secured(ins, p1, 0, data);
  }
  private static byte[] be32(BigInteger n) { return Bjj.be32(n); }
  private static BigInteger challenge(BigInteger[] r, long message) {
    return Poseidon.hash(r[0], r[1], pub[0], pub[1], BigInteger.valueOf(message)).mod(Bjj.L);
  }
  private static byte[] digest(String msg) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(msg.getBytes(StandardCharsets.UTF_8));
  }
  private static final class Pending {
    byte[] point;
    byte[] context;
    BigInteger[] edwards;
    BigInteger challenge;
    byte[] digest;
  }
  private static Pending prepare(long msg) throws Exception {
    APDUResponse commitment = apdu(0xB2, 0, new byte[0]);
    if (commitment.getSw() != 0x9000 || commitment.getData().length != 65)
      throw new IllegalStateException("COMMIT");
    APDUResponse context = apdu(0xB5, 0, new byte[0]);
    if (context.getSw() != 0x9000 || context.getData().length != 32)
      throw new IllegalStateException("GET_SESSION");
    Pending p = new Pending();
    p.point = commitment.getData();
    p.edwards = Bjj.fromCard(p.point);
    p.context = context.getData();
    p.challenge = challenge(p.edwards, msg);
    p.digest = digest("synthetic-authorized-intent-" + msg);
    return p;
  }
  private static byte[] payload(Pending p) throws Exception {
    byte[] out = new byte[240];
    byte[] domain = "RLGN-PERMIT-V1".getBytes(StandardCharsets.US_ASCII);
    System.arraycopy(domain, 0, out, 0, 14);
    System.arraycopy(p.context, 0, out, 14, 32);
    System.arraycopy(syntheticPublic(), 0, out, 46, 65);
    System.arraycopy(p.point, 0, out, 111, 65);
    System.arraycopy(p.digest, 0, out, 176, 32);
    System.arraycopy(be32(p.challenge), 0, out, 208, 32);
    return out;
  }
  private static byte[] pubRaw;
  private static byte[] syntheticPublic() { return pubRaw; }
  private static byte[] sign(byte[] message) throws Exception {
    Signature sig = Signature.getInstance("SHA256withECDSA");
    sig.initSign(shellFixtureKey);
    sig.update(message);
    return sig.sign();
  }
  private static byte[] authorizeData(Pending p, byte[] signedPayload) throws Exception {
    byte[] proof = sign(signedPayload);
    if (proof.length > 72) throw new IllegalStateException("DER_LEN");
    byte[] input = new byte[64 + proof.length];
    System.arraycopy(p.digest, 0, input, 0, 32);
    System.arraycopy(be32(p.challenge), 0, input, 32, 32);
    System.arraycopy(proof, 0, input, 64, proof.length);
    return input;
  }
  private static void initFixture() throws Exception {
    byte[] privateBytes = Files.readAllBytes(Path.of(System.getProperty("railgun.test.issuerKey")));
    try {
      shellFixtureKey = KeyFactory.getInstance("EC")
          .generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
    } finally {
      Arrays.fill(privateBytes, (byte)0);
    }
  }
  private static boolean valid(Pending p, long msg, APDUResponse resp) {
    return resp.getSw() == 0x9000 && resp.getData().length == 32
        && Bjj.verify(BigInteger.valueOf(msg), p.edwards,
            new BigInteger(1, resp.getData()), pub);
  }
  public static void main(String[] args) throws Exception {
    System.out.println("M345_MODE: SIMULATOR_ONLY_EPHEMERAL_ISSUER");
    if (!Boolean.getBoolean("zknox.jcardsim.rng.secure"))
      throw new IllegalStateException("SEEDED_RNG_REQUIRED");
    initFixture();
    try {
      s = CardSession.open("sim", "000000", "012345678901", "KeycardDefaultPairing", false);
      Object vectors = Json.parse(Files.readString(Path.of("vectors/circomlib_vectors.json")));
      BigInteger sk = new BigInteger((String)Json.path(vectors, "eddsa", "s_pruned"));
      APDUResponse loaded = apdu(0xB0, 0, be32(sk));
      check("SYNTHETIC_BJJ_KEY", loaded.getSw() == 0x9000);
      pubRaw = loaded.getData();
      pub = Bjj.fromCard(pubRaw);

      Pending raw = prepare(400);
      check("RAW_RESPOND_WITHOUT_PERMIT_REJECTED",
          apdu(0xB3, 0, be32(raw.challenge)).getSw() == 0x6985);
      check("RAW_RESPOND_DISARMS_SESSION",
          apdu(0xB5, 0, new byte[0]).getSw() == 0x6985);

      Pending authorized = prepare(401);
      check("VALID_CARD_SIDE_PERMIT_ACCEPTED",
          apdu(0xB6, 0, authorizeData(authorized, payload(authorized))).getSw() == 0x9000);
      check("AUTHORIZED_SIGNATURE_VALID",
          valid(authorized, 401, apdu(0xB3, 0, be32(authorized.challenge))));
      check("PERMIT_ONE_TIME_CONSUMPTION",
          apdu(0xB3, 0, be32(authorized.challenge)).getSw() == 0x6985);

      Pending forged = prepare(402);
      byte[] badProof = authorizeData(forged, payload(forged));
      badProof[badProof.length - 1] ^= 1;
      check("MUTATED_PERMIT_REJECTED",
          apdu(0xB6, 0, badProof).getSw() != 0x9000);
      check("BAD_PERMIT_DISARMS_SESSION",
          apdu(0xB3, 0, be32(forged.challenge)).getSw() == 0x6985);

      // Wrong issuer test: identical authorized fields, forged with a different
      // synthetic key. Card-side verification must reject, then disarm.
      Pending foreign = prepare(408);
      KeyPairGenerator attackerGenerator = KeyPairGenerator.getInstance("EC");
      attackerGenerator.initialize(new ECGenParameterSpec("secp256r1"));
      PrivateKey legitimateIssuer = shellFixtureKey;
      byte[] forgedPermit;
      try {
        shellFixtureKey = attackerGenerator.generateKeyPair().getPrivate();
        forgedPermit = authorizeData(foreign, payload(foreign));
      } finally { shellFixtureKey = legitimateIssuer; }
      check("FOREIGN_ISSUER_PERMIT_REJECTED",
          apdu(0xB6, 0, forgedPermit).getSw() != 0x9000);
      check("FOREIGN_ISSUER_FAILURE_DISARMS_SESSION",
          apdu(0xB3, 0, be32(foreign.challenge)).getSw() == 0x6985);

      Pending stale = prepare(403);
      byte[] oldPermit = authorizeData(stale, payload(stale));
      Pending newer = prepare(404);
      check("OLD_SESSION_PERMIT_REJECTED",
          apdu(0xB6, 0, oldPermit).getSw() != 0x9000);
      check("REPLAY_AFTER_SESSION_REPLACEMENT_REJECTED",
          apdu(0xB3, 0, be32(newer.challenge)).getSw() == 0x6985);

      Pending alteredDomain = prepare(405);
      byte[] wrongDomain = payload(alteredDomain);
      wrongDomain[0] ^= 1;
      check("WRONG_DOMAIN_PERMIT_REJECTED",
          apdu(0xB6, 0, authorizeData(alteredDomain, wrongDomain)).getSw() != 0x9000);

      Pending cancelled = prepare(406);
      check("CANCEL_APDU_ACCEPTED", apdu(0xB7, 0, new byte[0]).getSw() == 0x9000);
      check("CANCEL_DISARMS_SESSION",
          apdu(0xB3, 0, be32(cancelled.challenge)).getSw() == 0x6985);

      Pending chain = prepare(407);
      check("CHAIN_REQUIRES_SEPARATE_AUTHORIZATION",
          apdu(0xB6, 0, authorizeData(chain, payload(chain))).getSw() == 0x9000
          && apdu(0xB3, 0x08, be32(chain.challenge)).getSw() == 0x6985);
      check("CHAIN_REJECTION_FAILS_CLOSED",
          apdu(0xB3, 0, be32(chain.challenge)).getSw() == 0x6985);
      System.out.println("M345_CHECKS: " + checks);
      System.out.println("M345_RESULT: PASS");
    } finally { if (s != null) s.close(); }
  }
}
'''

def emit(key, value):
    line = f'{key}: {value}'
    report.append(line)
    print(line, flush=True)

def require(ok, label):
    emit(label, 'PASS' if ok else 'FAIL')
    if not ok:
        raise RuntimeError(label)

def run(argv, *, env=None, cwd=ROOT, timeout=240):
    return subprocess.run(argv, cwd=cwd, env=env, capture_output=True,
                          text=True, errors='replace', timeout=timeout, check=False)

def once(text, needle, replacement, label):
    require(text.count(needle) == 1, label)
    return text.replace(needle, replacement, 1)

def err(result, label):
    lines = (result.stderr + '\n' + result.stdout).splitlines()
    hits = [line for line in lines if re.search(r'error:|Exception|Caused by:|FAIL|VerifyError', line, re.I)]
    for number, line in enumerate((hits or lines[-12:])[-10:], 1):
        line = re.sub(r'\b[0-9a-fA-F]{48,}\b', '[REDACTED_HEX]', line)
        line = re.sub(r'(?i)(password|token|secret|seed|pin)\s*[:=]\s*\S+',
                      r'\1=[REDACTED]', line)
        emit(f'{label}_{number:02d}', line[:220].strip())

print('\033[38;5;110m◆ M3.45c.4a — EPHEMERAL ISSUER ENFORCEMENT\033[0m')
emit('MODE', 'ISOLATED_SIMULATOR_OVERLAY')
emit('CARD_OPERATIONS', 0)
emit('WALLET_OPERATIONS', 0)
emit('REPOSITORY_MODIFICATIONS', 0)
emit('GITHUB_PUSH', 'NO')
emit('SHELL_ISSUER_FIXTURE', 'EPHEMERAL_SYNTHETIC_KEYPAIR')
emit('HARDWARE_SECURITY_CLAIM', 'NONE')

try:
    require(ROOT.is_dir(), 'FORK_WORKSPACE')
    head = run(['git', 'rev-parse', 'HEAD'])
    require(head.returncode == 0 and run(['git', 'merge-base', '--is-ancestor', PIN, 'HEAD']).returncode == 0, 'SOURCE_BASELINE_ANCESTOR')
    branch = run(['git', 'branch', '--show-current'])
    require(branch.returncode == 0 and branch.stdout.strip() == BRANCH, 'FEATURE_BRANCH')
    before = run(['git', 'status', '--porcelain', '--untracked-files=all'])
    require(before.returncode == 0 and not before.stdout.strip(), 'WORKTREE_CLEAN')
    cp_file = ROOT / 'build/classpath.txt'
    agent = ROOT / 'build/kcprof-agent.jar'
    require(cp_file.is_file() and agent.is_file(), 'SIMULATOR_BUILD')
    cp = cp_file.read_text(encoding='utf-8').strip()
    require(bool(cp), 'SIMULATOR_CLASSPATH')
    require((JDK / 'bin/java').is_file() and (JDK / 'bin/javac').is_file(), 'JDK17_AVAILABLE')
    source_dir = ROOT / 'build/applet-src'
    require((source_dir / 'BjjSigner.java').is_file() and
            (source_dir / 'KeycardApplet.java').is_file(), 'PINNED_APPLET_SOURCES')
    env = os.environ.copy()
    env['JAVA_HOME'] = str(JDK)
    env['PATH'] = str(JDK / 'bin') + os.pathsep + env['PATH']
    env['GIT_TERMINAL_PROMPT'] = '0'
    env.pop('JAVA_TOOL_OPTIONS', None)

    with tempfile.TemporaryDirectory(prefix='keycard-permit-overlay-') as folder:
        tmp = Path(folder)
        os.chmod(tmp, 0o700)
        keygen_src = tmp / 'IssuerFixtureGen.java'
        keygen_src.write_text(KEYGEN_JAVA, encoding='utf-8')
        keygen_classes = tmp / 'keygen-classes'
        keygen_classes.mkdir()
        keygen_compile = run([str(JDK/'bin/javac'), '--release', '17',
                              '-d', str(keygen_classes), str(keygen_src)], env=env)
        if keygen_compile.returncode:
            err(keygen_compile, 'ISSUER_GEN_COMPILER')
        require(keygen_compile.returncode == 0, 'ISSUER_KEYGEN_COMPILED')
        issuer_private = tmp / 'issuer-private.pk8'
        issuer_public = tmp / 'issuer-public.hex'
        keygen_run = run([str(JDK/'bin/java'), '-cp', str(keygen_classes),
                          'IssuerFixtureGen', str(issuer_private), str(issuer_public)], env=env)
        if keygen_run.returncode:
            err(keygen_run, 'ISSUER_GEN_RUNTIME')
        require(keygen_run.returncode == 0, 'EPHEMERAL_ISSUER_GENERATED')
        pubhex = issuer_public.read_text(encoding='ascii').strip()
        require(len(pubhex) == 130 and pubhex.startswith('04')
                and bytes.fromhex(pubhex) != bytes.fromhex(P256['G']),
                'ISSUER_DISTINCT_FROM_PUBLIC_D1_FIXTURE')
        require((issuer_private.stat().st_mode & 0o077) == 0,
                'ISSUER_PRIVATE_FILE_PERMISSIONS')
        P256['W'] = pubhex
        # No private key bytes are displayed, logged or copied to the clipboard.
        src = tmp / 'applet-src'
        src.mkdir()
        for f in source_dir.glob('*.java'):
            shutil.copy2(f, src / f.name)
        signer = src / 'BjjSigner.java'
        code = signer.read_text(encoding='utf-8')
        require('INS_BJJ_AUTHORIZE' not in code, 'ISOLATED_PATCH_ONLY')
        code = once(code, '  /** Erases the BabyJubJub key (REMOVE KEY, factory reset). */',
                    PERMIT_IMPL.replace('__P256_CONSTANTS__', arrays_java()) +
                    '\n  /** Erases the BabyJubJub key (REMOVE KEY, factory reset). */',
                    'PERMIT_IMPL_ANCHOR')
        code = once(code, '    square.init(pub, Cipher.MODE_ENCRYPT);',
                    '''    square.init(pub, Cipher.MODE_ENCRYPT);
    permitCardTag = new byte[16];
    crypto.random.generateData(permitCardTag, (short)0, (short)16);
    permitSessionTag = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
    permitCommitPoint = JCSystem.makeTransientByteArray((short)65, JCSystem.CLEAR_ON_DESELECT);
    permitApprovedChallenge = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
    permitPayload = JCSystem.makeTransientByteArray((short)240, JCSystem.CLEAR_ON_DESELECT);
    permitAuthorized = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_DESELECT);
    permitIssuer = (javacard.security.ECPublicKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_EC_FP_PUBLIC, (short)256, false);
    permitVerifier = javacard.security.Signature.getInstance(
        javacard.security.Signature.ALG_ECDSA_SHA_256, false);
    initPermitIssuer();''', 'CONSTRUCTOR_ANCHOR')
        code = once(code, '''      case INS_BJJ_CALIBRATE:
        return calibrate(buf);''',
                    '''      case INS_BJJ_CALIBRATE:
        return calibrate(buf);
      case INS_BJJ_GET_SESSION:
        return permitContext(buf);
      case INS_BJJ_AUTHORIZE:
        return permitAuthorize(buf);
      case INS_BJJ_CANCEL:
        return permitCancel(buf);''', 'DISPATCH_ANCHOR')
        code = once(code, '''    state[1] = integer ? ARMED_INT : ARMED_MOD;
    return len;''',
                    '''    state[1] = integer ? ARMED_INT : ARMED_MOD;
    crypto.random.generateData(permitSessionTag, (short)0, (short)16);
    Util.arrayCopyNonAtomic(buf, outOff, permitCommitPoint, (short)0, (short)65);
    permitAuthorized[0] = 0;
    return len;''', 'COMMIT_STATE_ANCHOR')
        code = once(code, '''  private short respond(byte[] buf) {
    checkLc(buf, SZ);''',
                    '''  private short respond(byte[] buf) {
    if (state[0] != ARMED_0 || permitAuthorized[0] != (byte)0x5A) {
      permitRevoke();
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Narrow prototype: plain modular mode only; chained signing forbidden.
    if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0
        || (short)(buf[ISO7816.OFFSET_LC] & 0xFF) != SZ
        || Util.arrayCompare(buf, ISO7816.OFFSET_CDATA,
                             permitApprovedChallenge, (short)0, SZ) != 0) {
      permitRevoke();
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    permitAuthorized[0] = 0;
    checkLc(buf, SZ);''', 'RESPOND_GATE_ANCHOR')
        code = once(code, '''  private void disarm() {
    state[0] = 0;
    state[1] = 0;
  }''',
                    '''  private void disarm() {
    state[0] = 0;
    state[1] = 0;
    permitAuthorized[0] = 0;
    Util.arrayFillNonAtomic(permitApprovedChallenge, (short)0, SZ, (byte)0);
  }''', 'DISARM_ANCHOR')
        signer.write_text(code, encoding='utf-8')

        applet = src / 'KeycardApplet.java'
        app = applet.read_text(encoding='utf-8')
        app = once(app, '''      case BjjSigner.INS_BJJ_CALIBRATE:
''',
                   '''      case BjjSigner.INS_BJJ_CALIBRATE:
      case BjjSigner.INS_BJJ_GET_SESSION:
      case BjjSigner.INS_BJJ_AUTHORIZE:
      case BjjSigner.INS_BJJ_CANCEL:
''', 'APPLET_ROUTING_ANCHOR')
        applet.write_text(app, encoding='utf-8')
        emit('ISOLATED_APPLET_PATCH', 'PASS')

        output = tmp / 'applet-classes'
        output.mkdir()
        jcsim = ROOT / 'deps/status-keycard/jcardsim/jcardsim-3.0.5-SNAPSHOT.jar'
        math = ROOT / 'deps/status-keycard/keycard-math/keycard-math.jar'
        require(jcsim.is_file() and math.is_file(), 'PINNED_JAVACARD_DEPENDENCIES')
        compiled = run([str(JDK/'bin/javac'), '-nowarn', '-encoding', 'UTF-8',
                        '--release', '8', '-cp', str(jcsim)+os.pathsep+str(math),
                        '-d', str(output)] + [str(f) for f in sorted(src.glob('*.java'))], env=env, timeout=400)
        if compiled.returncode:
            err(compiled, 'APPLET_COMPILER')
        require(compiled.returncode == 0, 'ISOLATED_APPLET_COMPILED')
        require((output/'im/status/keycard/BjjSigner.class').is_file(), 'BJJ_SIGNER_OVERLAY')

        harness = tmp / 'M345c4aPermit.java'
        harness.write_text(JAVA, encoding='utf-8')
        classes = tmp / 'harness-classes'
        classes.mkdir()
        overlay_cp = str(output) + os.pathsep + cp
        harness_compiler = run([str(JDK/'bin/javac'), '--release', '11', '-cp', overlay_cp,
                                '-d', str(classes), str(harness)], env=env, timeout=120)
        if harness_compiler.returncode:
            err(harness_compiler, 'HARNESS_COMPILER')
        require(harness_compiler.returncode == 0, 'PERMIT_HARNESS_COMPILED')
        executed = run([str(JDK/'bin/java'), '-XX:+UnlockDiagnosticVMOptions',
                        '-XX:-BytecodeVerificationRemote',
                        '-Dzknox.jcardsim.rng.secure=true',
                        '-Drailgun.test.issuerKey='+str(issuer_private),
                        '-javaagent:'+str(agent),
                        '-cp', str(classes)+os.pathsep+overlay_cp,
                        'zknox.kcsim.M345c4aPermit'], env=env, timeout=600)
        for line in executed.stdout.splitlines():
            if re.fullmatch(r'M345_[A-Z0-9_]+: (PASS|FAIL|[0-9]+|SIMULATOR_ONLY_INSECURE_ISSUER_FIXTURE)', line):
                report.append(line)
                print(line, flush=True)
        if executed.returncode:
            err(executed, 'PERMIT_RUNTIME')
        require(executed.returncode == 0 and 'M345_RESULT: PASS' in executed.stdout,
                'CARD_SIDE_PERMIT_ENFORCEMENT_TEST')

    after = run(['git', 'status', '--porcelain', '--untracked-files=all'])
    require(after.returncode == 0 and after.stdout == before.stdout, 'REPOSITORY_UNCHANGED')
    emit('NEXT', 'PROTECTED_ISSUER_PROVISIONING_AND_SHELL_TRUST_ROOT')
    success = True
except Exception as e:
    emit('ERROR_CLASS', type(e).__name__)
finally:
    emit('M3.45c.4a', 'PASS' if success else 'REVIEW_REQUIRED')
    try:
        copied = subprocess.run(['pbcopy'], input='\n'.join(report)+'\n',
                                text=True, capture_output=True, check=False)
        print('CLIPBOARD:', 'PASS' if copied.returncode == 0 else 'FAIL')
    except OSError:
        print('CLIPBOARD: UNAVAILABLE')
sys.exit(0 if success else 1)
