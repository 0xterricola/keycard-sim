# Changelog

## 0.3.0 : 2026-11-14

- `shell/bjj_shell.c` : côté Keycard Shell de la signature (Weierstrass vers Edwards, Poseidon t = 6 optimisé et de
  référence, c = hm mod l, S' mod l, packSignature), C portable pour Cortex-M33.
- `shell/run.py` et `shell.sh` : compilation clang pour thumbv8m.main, exécution dans Unicorn (Cortex-M33), contrôle
  contre le vecteur circomlibjs et une référence Python, compte d'instructions et estimation des cycles, temps T=1
  des APDU d'après l'ATR et la PPS de la Shell.
- `vectors/poseidon_t6_opt.txt` : constantes de la permutation optimisée de circomlibjs, produites par
  `tools/gen-vectors.mjs`.
- README : tableau de la signature complète, Shell, transport et carte.

## 0.2.0 : 2026-11-14

- Fork de l'applet avec `BjjSigner` : signature EdDSA-Poseidon aveugle sur BabyJubJub, compatible circomlib, en deux
  APDU (COMMIT, RESPOND) avec sessions séquentielles. INS B0 à B4 branchés par `patches/applet-bjj.patch`.
- Courbe chargée sous sa forme de Weierstrass courte ; conversion Edwards ↔ Weierstrass et Poseidon t = 6 sur l'hôte.
- Variantes de RESPOND : plain, masked, single, integer (S' sur les entiers, pas de réduction modulo l sur carte),
  chain (une APDU par signature).
- `BjjBench` (`bjj.sh`) : contrôles fonctionnels et de refus, vérification de chaque signature, estimation JCOP4 par
  APDU et par signature, détail par méthode et par appel API, mémoire allouée, référence SIGN secp256k1, CSV et export
  circomlib.
- Agent de profilage ASM 9.6 : bytecodes par méthode, appels API avec longueur, allocations à l'installation.
- Modèle de coût `costs/jcop4_j3r180.tsv` extrait des données JCAlgTest J3R180 ; INS CALIBRATE pour mesurer t_bc sur
  carte.
- `cap.sh` : conversion CAP de l'applet d'origine et du fork (kit JC 3.1, cible 3.0.5), comparaison des composants.
- Vecteurs et vérification externe avec circomlibjs 0.1.7 (`tools/`).
- `CardSession` partagé par les deux bancs. En PC/SC avec `--provision` : certificat Ident signé par la CA de test,
  INIT au format de l'applet 4.0.

## 0.1.0 : 2026-10-27

- Build sans Gradle ni Maven : sources épinglées sur GitHub, compilation `javac` (BouncyCastle 1.65, SDK
  status-keycard-java, applet status-keycard 4.0).
- Applet installée dans jCardSim avec certificat d'identité (CA fixe), secure channel v2, PIN, LOAD KEY de la seed
  de test.
- `KcBench` : boucle SIGN ECDSA et BIP340 avec chauffe ; statistiques min, médiane, p95, max, moyenne et écart-type ;
  temps « carte » (APDU chiffré) et « total hôte » ; export CSV.
- Vérification hôte de chaque signature, dérivation BIP32 indépendante et compteur de DER non strict.
- Correctif jCardSim `ALG_RSA_NOPAD` (nécessaire à Schnorr via keycard-math).
- Cible `--target pcsc` pour une vraie carte (non testée).
