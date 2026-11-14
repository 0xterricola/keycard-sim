package zknox.kcsim;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import im.status.keycard.IdentApplet;
import im.status.keycard.KeycardApplet;
import im.status.keycard.applet.ApplicationInfo;
import im.status.keycard.applet.Certificate;
import im.status.keycard.applet.IdentCommandSet;
import im.status.keycard.applet.Identifiers;
import im.status.keycard.applet.KeycardCommandSet;
import im.status.keycard.applet.SecureChannelV2;
import im.status.keycard.desktop.PCSCCardChannel;
import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Security;
import java.util.Collections;
import java.util.List;

/**
 * A Keycard session up to a verified PIN, on the jCardSim simulator (applet installed with an identity certificate
 * signed by a fixed CA) or on a real card through PC/SC.
 */
final class CardSession {
  /** Fixed CA key used to sign the simulated card identity certificate (same as the applet test suite). */
  static final BigInteger SIM_CA_PRIV =
      new BigInteger("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", 16);

  final boolean sim;
  final CardTerminal terminal;
  final Card card;
  final TimedChannel ch;
  final KeycardCommandSet cmd;
  final ApplicationInfo info;

  private CardSession(boolean sim, CardTerminal terminal, Card card, TimedChannel ch, KeycardCommandSet cmd,
      ApplicationInfo info) {
    this.sim = sim;
    this.terminal = terminal;
    this.card = card;
    this.ch = ch;
    this.cmd = cmd;
    this.info = info;
  }

  static CardSession open(String target, String pin, String puk, String pairingPassword, boolean provision)
      throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }
    boolean sim = target.equals("sim");
    KeyPair ca = simCaKeyPair();
    CardTerminal terminal = sim ? CardTerminalSimulator.terminal(buildSimulator(ca)) : pickPcscTerminal();
    Card card = terminal.connect("*");
    TimedChannel ch = new TimedChannel(new PCSCCardChannel(card.getBasicChannel()));

    byte[] simCa = ((org.bouncycastle.jce.interfaces.ECPublicKey) ca.getPublic()).getQ().getEncoded(true);
    KeycardCommandSet cmd;
    if (sim) {
      cmd = new KeycardCommandSet(ch, simCa);
    } else if (provision) {
      // Dev card loaded with the fork: the Ident applet has no certificate yet, give it one signed by the test CA
      provisionIdentity(ch, ca);
      cmd = new KeycardCommandSet(ch, List.of(KeycardCommandSet.DEFAULT_CA_PUBLIC_KEY, simCa), Collections.emptyList());
    } else {
      cmd = new KeycardCommandSet(ch);
    }
    cmd.select().checkOK();
    ApplicationInfo info = cmd.getApplicationInfo();

    if (!info.isInitializedCard()) {
      if (!sim && !provision) {
        throw new IllegalStateException("carte non initialisée : relancer avec --provision (carte de dev uniquement)");
      }
      if (sim) {
        cmd.init(pin, "024680", puk, new byte[0], (byte) 3, (byte) 5).checkOK();
      } else if (cmd.getSecureChannel() instanceof SecureChannelV2) {
        // Applet 4.0: INIT carries PIN and PUK only (no pairing secret)
        cmd.init(pin, null, puk, new byte[0], (byte) 0, (byte) 0).checkOK();
      } else {
        cmd.init(pin, puk, pairingPassword).checkOK();
      }
      cmd.select().checkOK();
      info = cmd.getApplicationInfo();
    }

    if (info.hasSecureChannelCapability()) {
      if (info.getAppVersion() < 0x0400) {
        cmd.autoPair(pairingPassword);
      }
      cmd.autoOpenSecureChannel();
    }
    if (info.hasCredentialsManagementCapability()) {
      cmd.verifyPIN(pin).checkAuthOK();
    }
    return new CardSession(sim, terminal, card, ch, cmd, info);
  }

  /** Sends a command through the secure channel; the response carries the inner (decrypted) status word. */
  APDUResponse secured(int ins, int p1, int p2, byte[] data) throws IOException {
    APDUCommand c = cmd.getSecureChannel().protectedCommand(0x80, ins, p1, p2, data);
    return cmd.getSecureChannel().transmit(ch, c);
  }

  String describe() {
    return sim
        ? "simulateur jCardSim 3.0.5 (temps JVM hôte, non représentatif d'un secure element)"
        : "PC/SC « " + terminal.getName() + " »";
  }

  void close() throws Exception {
    card.disconnect(false);
  }

  static KeyPair simCaKeyPair() throws Exception {
    ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    KeyFactory kf = KeyFactory.getInstance("EC", "BC");
    return new KeyPair(
        kf.generatePublic(new ECPublicKeySpec(spec.getG().multiply(SIM_CA_PRIV), spec)),
        kf.generatePrivate(new ECPrivateKeySpec(SIM_CA_PRIV, spec)));
  }

  /** Stores an identity certificate signed by the test CA if the Ident applet has none (dev card only). */
  static void provisionIdentity(TimedChannel ch, KeyPair ca) throws Exception {
    IdentCommandSet ident = new IdentCommandSet(ch);
    APDUResponse sel = ident.select();
    if (sel.getSw() != 0x9000) {
      System.out.println("applet Ident absente (SW=" + String.format("%04X", sel.getSw()) + ") : certificat non installé");
      return;
    }
    if (sel.getData().length == 0) {
      Certificate cert = Certificate.createCertificate(ca, Certificate.generateIdentKeyPair());
      ident.storeData(cert.toStoreData()).checkOK();
      System.out.println("certificat d'identité installé (CA de test du simulateur)");
    }
  }

  /** Installs the Keycard and Ident applets in jCardSim and provisions the identity certificate. */
  static CardSimulator buildSimulator(KeyPair ca) throws Exception {
    CardSimulator simulator = new CardSimulator();
    ByteArrayOutputStream bos = new ByteArrayOutputStream();

    byte[] kcInstance = Identifiers.getKeycardInstanceAID();
    bos.write(kcInstance.length);
    bos.write(kcInstance);
    simulator.installApplet(AIDUtil.create(Identifiers.KEYCARD_AID), KeycardApplet.class,
        bos.toByteArray(), (short) 0, (byte) bos.size());
    bos.reset();

    bos.write(Identifiers.IDENT_INSTANCE_AID.length);
    bos.write(Identifiers.IDENT_INSTANCE_AID);
    bos.write(new byte[] {0x01, 0x00, 0x02, (byte) 0xC9, 0x00});
    simulator.installApplet(AIDUtil.create(Identifiers.IDENT_AID), IdentApplet.class,
        bos.toByteArray(), (short) 0, (byte) bos.size());

    CardTerminal t = CardTerminalSimulator.terminal(simulator);
    Card c = t.connect("*");
    IdentCommandSet ident = new IdentCommandSet(new PCSCCardChannel(c.getBasicChannel()));
    ident.select().checkOK();
    Certificate cert = Certificate.createCertificate(ca, Certificate.generateIdentKeyPair());
    ident.storeData(cert.toStoreData()).checkOK();
    c.disconnect(false);
    simulator.reset();
    return simulator;
  }

  static CardTerminal pickPcscTerminal() throws Exception {
    for (CardTerminal t : TerminalFactory.getDefault().terminals().list()) {
      if (t.isCardPresent()) {
        return t;
      }
    }
    throw new IllegalStateException("aucun lecteur PC/SC avec carte présente");
  }
}
