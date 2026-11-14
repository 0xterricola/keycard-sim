# keycard-sim

Banc de mesure pour l'applet Keycard (status-keycard 4.0), sur simulateur jCardSim ou sur carte réelle via PC/SC.

- `bjj.sh` (`BjjBench`) : fork de l'applet avec un signataire EdDSA-Poseidon aveugle sur BabyJubJub, compatible
  circomlib. Contrôles fonctionnels, signatures vérifiées, estimation des temps sur JCOP4.
- `shell.sh` : côté Keycard Shell (STM32H573) de la même signature, exécuté en émulation Cortex-M33, et temps de
  transfert T=1 de chaque APDU.
- `cap.sh` : conversion en CAP de l'applet d'origine et du fork, comparaison des tailles.
- `run.sh` (`KcBench`) : `SIGN` ECDSA et BIP340 de l'applet d'origine.

## Prérequis

JDK ≥ 11 et git. Node ≥ 18 seulement pour `tools/` (régénération des vecteurs, vérification par circomlibjs).
`shell.sh` demande clang, lld et trois modules Python :

```
sudo apt install clang lld
python3 -m pip install unicorn capstone pyelftools
```

Le build ne passe ni par Gradle ni par Maven : `build.sh` récupère les sources sur GitHub à des révisions épinglées
et compile avec `javac`.

| Dépôt | Révision |
|---|---|
| keycard-tech/status-keycard (applet) | 37393a2c (4.0), sous-modules jcardsim et sdks |
| keycard-tech/status-keycard-java (SDK hôte) | b79a0319 |
| bcgit/bc-java | r1rv65 (BouncyCastle 1.65) |

Le sous-module `sdks` fournit le convertisseur du kit Java Card 3.1 (`cap.sh`) et ASM 9.6 (agent de profilage).

## Usage

```
./build.sh
./bjj.sh                                     # 7 modes × 100 signatures, référence SIGN secp256k1, rapport complet
./bjj.sh --modes integer-chain --iters 1000 --details none
./bjj.sh --tbc 0.8 --details all             # t_bc mesuré sur carte, détail de chaque APDU
./bjj.sh --export /tmp/sigs.json             # puis : cd tools && npm install && node verify-circomlib.mjs /tmp/sigs.json
./bjj.sh --help
./cap.sh
./shell.sh                                   # coût Shell, contrôles contre circomlibjs, temps T=1
./run.sh --help
```

## Signataire BabyJubJub aveugle

### Protocole

Signature circomlib EdDSA-Poseidon, en deux APDU. La carte ne voit jamais le message.

- Clé : s est le scalaire élagué de circomlib (BLAKE-512 de la clé privée, élagué), A = (s >> 3)·B8. L'hôte calcule s
  avant LOAD_KEY : Java Card n'a pas BLAKE-512.
- COMMIT : la carte tire r uniforme dans [1, l−1] et renvoie R = r·B8.
- L'hôte calcule c = Poseidon(R.x, R.y, A.x, A.y, msg) mod l (Poseidon t = 6).
- RESPOND : la carte renvoie S = r + c·s mod l.
- Vérification circomlib inchangée : S·B8 = R + 8c·A. circomlib dérive r du message ; ici r est aléatoire, ce que la
  vérification ne voit pas.

### Courbe sur la carte

Le moteur EC de JCOP ne traite que les courbes de Weierstrass courtes. La carte travaille sur l'image de BabyJubJub,
et l'hôte convertit R et A en coordonnées d'Edwards.

- Edwards : a·x² + y² = 1 + d·x²·y², a = 168700, d = 168696, sur F_p avec p = r de BN254.
- Montgomery : B·v² = u³ + A·u² + u, A = 168698, B = 1.
- Weierstrass : Y² = X³ + aW·X + bW, aW = (3 − A²)/3, bW = (2A³ − 9A)/27.

Aller, Edwards → Weierstrass :

```
X = (1 + y) / (1 − y) + A/3
Y = (1 + y) / ((1 − y)·x)
```

Retour, Weierstrass → Edwards, avec une seule inversion :

```
u = X − A/3
t = 1 / (Y·(u + 1))
x = u·(u + 1)·t
y = (u − 1)·Y·t
```

Dans le sous-groupe d'ordre l, seul le neutre (0, 1) est exceptionnel (il va à l'infini). La carte ne le produit
jamais, car r et s sont non nuls modulo l.

Les clés EC de la carte reçoivent p, aW, bW, G = image de B8, R = l (251 bits) et K = 8 (`BabyJubJub.java`). La
multiplication scalaire passe par `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY`, via `SECP256k1.multiplyPoint` de l'applet.
La conversion vers Edwards et Poseidon tournent sur l'hôte (Java : 0,45 ms par signature).

### APDU

Toutes les commandes passent par le secure channel v2 (CLA 80) et exigent le PIN vérifié. Les INS B0 à B4 sont
libres dans l'applet 4.0.

| INS | Commande | P1 | Données | Réponse |
|---|---|---|---|---|
| B0 | LOAD_KEY | 00 | s, 32 o big-endian | A en Weierstrass, 04‖X‖Y (65 o) |
| B1 | GET_PUBLIC | 00 | aucune | A (65 o) |
| B2 | COMMIT | 00 ou 04 | aucune | R (65 o) |
| B3 | RESPOND | bits 01, 02, 04, 08 | c, 32 o big-endian, c < l | S (32 o) ou S' (72 o), puis R suivant (65 o) avec 08 |
| B4 | CALIBRATE | P1P2 = n | aucune | 1 o |

| SW | Cause |
|---|---|
| 6985 | PIN non vérifié, pas de clé, aucune session armée, session d'un autre type (integer ou modulaire) |
| 6A80 | c ≥ l ; s nul modulo l au LOAD_KEY |
| 6700 | longueur incorrecte |
| 6B00 | P1 ou P2 invalide (bits 10 à 80, masked avec integer) |
| 6F0F | les deux calculs de la réponse diffèrent (faute) |

### Variantes de RESPOND

| P1 | Mode | Calcul sur carte |
|---|---|---|
| 00 | plain | S = r + c·s mod l avec keycard-math (`modMul`, `modAdd`), calculé deux fois et comparé |
| 01 | masked | idem, avec s = s1 + m et m frais à chaque signature |
| 02 | single | un seul calcul (mesure le coût de la redondance) |
| 04 | integer | S' = r' + c·s sur les entiers, avec r' = r + l·t préparé au COMMIT (P1 = 04) et t de 320 bits ; l'hôte calcule S = S' mod l |
| 08 | chain | la réponse est suivie du R de la session suivante : une APDU par signature |

Le banc mesure aussi integer-single (06) et integer-chain (0C). La combinaison masked + integer est refusée.

En mode integer, la carte ne fait aucune réduction modulo l. Les produits sont exacts sous le module RSA-736, avec la
technique de keycard-math (exposant public 2, `ALG_RSA_NOPAD`) : c·s = ((c + s)² − c² − s²)/2, trois carrés, deux fois.
Au COMMIT, l·t = ((l + t)² − l² − t²)/2 avec l² en constante. S' < 2^576 ; S' mod l = S, et le quotient
⌊(r + c·s)/l⌋ < 2^251 est masqué par t à 2^−69 près en distance statistique.

### Sécurité face à ROS

- Sessions séquentielles : COMMIT détruit la session en cours, une seule session est armée. Les attaques ROS
  (Benhamouda et al., 2021) exigent des sessions concurrentes. En séquentiel, le Schnorr aveugle à deux passes est sûr
  sous OMDL, dans AGM + ROM (Kastner, Loss, Xu, PKC 2022). Le mode chain respecte cette règle : le R suivant n'est
  émis qu'après S.
- La session est désarmée avant tout calcul, y compris sur refus : un RESPOND en 6A80 consomme la session.
- Le nonce est remplacé par de l'aléa avant le calcul, sans `clearKey`. Un RESPOND rejoué, ou une faute qui saute le
  test d'état, donne r'' + c·s avec r'' jamais publié.
- La réponse est calculée deux fois et comparée (6F0F).
- `lessThan` est à temps constant ; r est tiré par rejet sur 251 bits, sans biais.
- La carte signe tout c < l qu'on lui présente. Le contrôle de ce qui est signé (plafond, confirmation) relève de
  l'hôte.

## Estimation des temps

Le simulateur exécute l'applet dans la JVM, et ses temps ne disent rien d'une carte. Le banc estime le temps JCOP4 à
partir de deux relevés faits dans le simulateur :

1. Un agent Java (`agent/`, ASM 9.6) instrumente les classes de l'applet et compte les bytecodes exécutés par méthode.
   Les `i2s` insérés par javac sont exclus, le convertisseur Java Card les supprime.
2. Des sondes sur l'implémentation jCardSim de l'API (Cipher, Signature, KeyAgreement, MessageDigest, RandomData,
   setters de clés, Util, allocations) relèvent chaque appel issu de l'applet, avec la longueur des données.

Estimation = Σ coûts des appels API (`costs/jcop4_j3r180.tsv`) + bytecodes × t_bc.

- Les coûts API viennent des mesures JCAlgTest d'une NXP J3R180 (JCOP4 P71) : coût fixe, plus coût par longueur
  quand il dépend de la taille (`costs/extract_jcalgtest.py`).
- t_bc, coût moyen d'un bytecode Java Card, n'est pas publié. Le rapport donne 0,5, 1 et 2 µs. CALIBRATE exécute n
  itérations de 16 bytecodes (compte JVM) : sur carte, t_bc = (T(n) − T(0)) / (16·n).
- La part du secure channel v2 (AES-CCM, la même pour toute commande Keycard) est donnée à part.

Limites :

- un bytecode JVM n'est pas un bytecode Java Card (le convertisseur fusionne certaines séquences, par exemple en
  `sinc`) : le compte est une approximation ;
- les coûts API sont ceux d'une J3R180, les Keycard récentes sont sur J3R200 (même famille JCOP4 P71) ;
- `ALG_EC_SVDP_DH_PLAIN_XY` est absent des données JCAlgTest et compté au prix de `ALG_EC_SVDP_DH` ;
- `RSAPublicKey.setExponent` et `setModulus` sont comptés au prix des setters de clé privée RSA ;
- les appels API sans entrée dans le modèle valent 0 ms et sont listés à la fin du rapport (`--api-other-us` pour
  les chiffrer) ;
- le transport (T=1 ou NFC) et le lecteur ne sont pas comptés ;
- la clé nonce est persistante dans le build simulateur (ADR-002), transitoire sur carte.

`math.cap`, chargé sur les cartes, n'importe que les paquetages Java Card standard et embarque la même classe que
`keycard-math.jar` : le code de keycard-math simulé est celui de la carte.

## Résultats

Simulateur, modèle J3R180, 100 signatures par mode, temps en ms. « dont SC v2 » est calculé à 1 µs.

| APDU | bytecodes | API | @0,5 µs | @1 µs | @2 µs | dont SC v2 |
|---|---:|---:|---:|---:|---:|---:|
| COMMIT | 5 728 | 82,5 | 85,4 | 88,2 | 94,0 | 53,5 |
| RESPOND plain | 215 417 | 67,9 | 175,6 | 283,3 | 498,7 | 51,4 |
| RESPOND masked | 421 315 | 84,5 | 295,1 | 505,8 | 927,1 | 51,4 |
| RESPOND single | 109 271 | 60,5 | 115,1 | 169,8 | 279,0 | 51,4 |
| COMMIT integer | 24 055 | 92,7 | 104,7 | 116,7 | 140,8 | 53,5 |
| RESPOND integer | 39 286 | 68,5 | 88,1 | 107,8 | 147,0 | 56,7 |
| RESPOND integer-single | 22 954 | 61,1 | 72,5 | 84,0 | 107,0 | 56,7 |
| RESPOND chain | 217 706 | 107,9 | 216,7 | 325,6 | 543,3 | 61,1 |
| RESPOND integer-chain | 61 885 | 118,3 | 149,3 | 180,2 | 242,1 | 65,9 |
| SIGN ECDSA secp256k1 (applet) | 36 463 | 196,2 | 214,4 | 232,7 | 269,1 | 68,7 |
| SIGN Schnorr secp256k1 (applet) | 121 315 | 278,6 | 339,3 | 399,9 | 521,2 | 73,3 |

Signature complète :

| Mode | APDU | @0,5 µs | @1 µs | @2 µs |
|---|---:|---:|---:|---:|
| plain | 2 | 260,9 | 371,5 | 592,6 |
| masked | 2 | 380,5 | 594,0 | 1 021,1 |
| single | 2 | 200,5 | 258,0 | 373,0 |
| integer | 2 | 192,8 | 224,5 | 287,8 |
| integer-single | 2 | 177,2 | 200,7 | 247,7 |
| chain | 1 | 216,7 | 325,6 | 543,3 |
| integer-chain | 1 | 149,3 | 180,2 | 242,1 |

- COMMIT : 53 ms de secure channel et 28 ms de multiplication scalaire (init et `generateSecret` du KeyAgreement).
- RESPOND plain : 210 000 bytecodes dans keycard-math, dont 144 000 dans `timesMinus`, la réduction modulo l
  logicielle. Elle domine dès 0,5 µs par bytecode.
- RESPOND integer supprime la réduction : 6 carrés RSA (14 ms) et 34 000 bytecodes, surtout des additions et
  soustractions octet par octet.
- integer-chain : une APDU, 180 ms à 1 µs, sous le SIGN ECDSA secp256k1 de l'applet (233 ms dans le même modèle).
- Le secure channel v2 coûte 51 à 66 ms par APDU (init AES et MAC à chaque commande). Le mode chain en économise une.

### Signature complète, Shell et carte

Une signature complète enchaîne : COMMIT, transfert T=1, Shell (R vers Edwards, Poseidon, c = hm mod l), RESPOND,
transfert T=1, Shell (S' mod l en mode integer, signature compactée). Le message est supposé prêt sur la Shell.

Côté Shell (`./shell.sh`) : `shell/bjj_shell.c`, C portable (8 limbes de 32 bits, Montgomery CIOS), compilé par
clang -O2 pour Cortex-M33 et exécuté dans Unicorn. Chaque sortie est comparée au vecteur circomlibjs et à une
référence Python, chaque signature aléatoire vérifiée par S·B8 = R8 + c·A. Les cycles sont estimés par classe
d'instruction (chargement 2, branche prise 3, LDM/STM 1 + N, le reste 1), à 250 MHz, code et constantes en cache.

| Opération Shell | instructions | cycles estimés | ms |
|---|---:|---:|---:|
| multiplication F_p (avec conversions) | 2 556 | 3 567 | 0,014 |
| conversion Weierstrass → Edwards (inversion de Fermat) | 312 164 | 433 781 | 1,74 |
| Poseidon t = 6 optimisé (circomlibjs `buildPoseidon`) | 1 127 184 | 1 551 611 | 6,21 |
| Poseidon t = 6 référence | 2 500 520 | 3 434 788 | 13,74 |
| après COMMIT : conversion, Poseidon optimisé, c | 1 443 968 | 1 991 754 | 7,97 |
| après RESPOND : S' mod l, compactage (integer) | 4 961 | 6 606 | 0,03 |

Transfert T=1 : TA1 = 18 de l'ATR JCOP4 par défaut (Fi = 372, Di = 12), horloge carte de 5 MHz choisie par la Shell
(`app/iso7816/pps.c`), soit 161 kbit/s ; secure channel v2 (en-tête interne, tag CCM de 8 octets, SW interne), une
I-block par sens, 11 etu par caractère.

| APDU | commande | réponse | T=1 |
|---|---:|---:|---:|
| COMMIT | 19 o | 77 o | 7,2 ms |
| RESPOND plain | 51 o | 44 o | 7,2 ms |
| RESPOND integer | 51 o | 84 o | 9,9 ms |
| RESPOND chain | 51 o | 109 o | 11,6 ms |
| RESPOND integer-chain | 51 o | 149 o | 14,3 ms |

Total, en ms, selon t_bc de la carte :

| Mode | APDU | carte @1 µs | T=1 | Shell | total @0,5 µs | total @1 µs | total @2 µs |
|---|---:|---:|---:|---:|---:|---:|---:|
| plain | 2 | 371,5 | 14,4 | 8,0 | 283,4 | 393,9 | 615,1 |
| masked | 2 | 594,0 | 14,4 | 8,0 | 402,9 | 616,4 | 1 043,5 |
| single | 2 | 258,0 | 14,4 | 8,0 | 222,9 | 280,4 | 395,4 |
| integer | 2 | 224,5 | 17,1 | 8,0 | 217,9 | 249,6 | 312,9 |
| integer-single | 2 | 200,7 | 17,1 | 8,0 | 202,3 | 225,8 | 272,9 |
| chain | 1 | 325,6 | 11,6 | 8,0 | 236,3 | 345,2 | 562,9 |
| integer-chain | 1 | 180,2 | 14,3 | 8,0 | 171,6 | 202,5 | 264,4 |

- En mode chain, le R vient de la réponse précédente ; la première signature après mise sous tension coûte un
  COMMIT de plus (la session est en RAM CLEAR_ON_DESELECT).
- Non comptés : AES-CCM du secure channel côté Shell (AES matériel, une dizaine de blocs par APDU), préparation du
  message, affichage et confirmation.
- Vérification optionnelle de la signature par la Shell, sur l'image de Weierstrass : un double-base ladder du PKA,
  2 768 000 cycles en moyenne pour 256 bits (RM0481, table 382), soit 11,1 ms à 250 MHz.
- Le C portable n'utilise ni le PKA ni d'assembleur : 800 instructions environ par multiplication modulaire.

### Mémoire et code

- CAP (convertisseur JC 3.1, cible 3.0.5, 0 erreur) : 15 885 → 19 653 o (+3 768), dont Method +2 428 et StaticField
  +274 (constantes de courbe).
- Installation : +321 o de tableaux persistants, +106 o de RAM (CLEAR_ON_DESELECT), environ 733 o de clés (2 clés
  EC, paire RSA-736).
- Travail : `crypto.scratch` (176 o, partagé avec l'applet) et tampon APDU (octets 40 à 224).
- Budget J3R180 avant installation (JCAlgTest) : 139 360 o persistants, 4 084 o transitoires CLEAR_ON_RESET.

### Contrôles

`bjj.sh` sort en code 2 si un contrôle échoue :

- vecteurs circomlibjs 0.1.7 : Poseidon(1..5), prv2pub, signature, packSignature ;
- aller-retour Edwards → Weierstrass → Edwards ;
- LOAD_KEY, GET_PUBLIC, chaque refus du tableau des SW, modes integer et chain ;
- vérification sur l'hôte de chaque signature mesurée (équation de `verifyPoseidon`).

`--export` écrit les signatures au format circomlib, et `tools/verify-circomlib.mjs` les vérifie avec circomlibjs.
`tools/gen-vectors.mjs` régénère `vectors/`.

## Sur carte réelle

Carte de dev JCOP4 avec clés ISD connues, et GlobalPlatformPro (`gp`). `--provision` initialise la carte et charge des
clés de test : carte de dev uniquement.

```
./cap.sh
gp --delete A0000008040001 --force
gp --load deps/status-keycard/keycard-math/im/status/keycard/math/javacard/math.cap   # si absent (paquetage A0000008040002)
gp --load build/cap/bjj/out/im/status/keycard/javacard/keycard.cap
gp --package A0000008040001 --applet A000000804000101 --create A00000080400010101    # Keycard
gp --package A0000008040001 --applet A000000804000104 --create A00000080400010401    # Ident
./bjj.sh --target pcsc --provision
```

`--provision` fait INIT si la carte est vierge, installe un certificat d'identité signé par la CA de test du
simulateur si l'applet Ident n'en a pas, charge le scalaire BabyJubJub de test et, pour la référence, la seed de test.
Le rapport PC/SC donne les temps réels par APDU (lecteur compris) et t_bc mesuré par CALIBRATE. `./bjj.sh --tbc <t_bc>`
recalcule alors l'estimation du simulateur pour la comparer.

Sous Ubuntu, il faut `pcscd` et `libpcsclite1` ; `bjj.sh` et `run.sh` renseignent `sun.security.smartcardio.library`.
Le mode PC/SC n'a pas été testé faute de lecteur.

## Banc SIGN secp256k1 (`run.sh`)

```
./run.sh                                   # ECDSA + Schnorr, m/44'/60'/0'/0/0, 200 itérations + 50 de chauffe
./run.sh --algo ecdsa --iters 1000 --csv ecdsa.csv
./run.sh --path m                          # clé maître : isole le coût de la dérivation BIP32
./run.sh --target pcsc --pin 000000        # vraie carte, clé existante
./run.sh --target pcsc --provision         # carte de dev : INIT si vierge + LOAD KEY de la seed de test
```

- « carte » : durée du transmit de l'APDU chiffré, mesurée sous le secure channel.
- « total hôte » : inclut en plus le chiffrement et le déchiffrement côté hôte.
- Chaque signature est vérifiée côté hôte : ECDSA low-s, BIP340 contre la clé x-only, clé publique comparée à une
  dérivation BIP32 indépendante.
- La seed de test est celle de la mnémonique `abandon ×11 about`. L'adresse attendue en `m/44'/60'/0'/0/0` est
  `0x9858effd232b4033e47d90003d41ec34ecaeda94`.

CSV : `target,algo,path,iter,card_ms,total_ms,verified`. Pour une carte < 4.0 (secure channel v1), l'appairage se
fait avec `--pairing-password`.

### Constat sur l'applet

Après normalisation low-s, `Crypto.fixS` écrit toujours `s` sur 32 octets. Quand `n − s < 2^247`, l'INTEGER DER
commence par un `00` superflu, soit environ une signature ECDSA sur 512. La signature reste valide, mais un décodeur
DER strict (BouncyCastle, OpenSSL strict, BIP66) la rejette. Le banc vérifie avec un parseur tolérant et compte ces
cas à part.

## Adaptations pour jCardSim

Voir `DECISIONS.md`.

- `TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT` est remplacé par `TYPE_EC_FP_PRIVATE` dans une copie des sources de
  l'applet et du fork : le jar jCardSim fourni par le dépôt ne gère pas les clés EC transitoires.
- `patches/jcardsim/.../AsymmetricCipherImpl.java` corrige `ALG_RSA_NOPAD`, qui doit accepter un bloc de la taille du
  module comme sur carte. Sans ce correctif, Schnorr et le mode integer échouent en `6F05`.
- La vérification de bytecode est désactivée au lancement : les classes Java Card de jCardSim n'ont pas de stack map
  frames.

## Arborescence

| Chemin | Contenu |
|---|---|
| `applet-ext/` | `BjjSigner.java`, `BabyJubJub.java` (code carte ajouté) |
| `patches/applet-bjj.patch` | branchement dans `KeycardApplet.java` (INS B0 à B4, select, effacement) |
| `agent/` | agent de profilage (bytecodes, appels API, allocations) |
| `src/zknox/kcsim/` | bancs, session carte, BabyJubJub et Poseidon côté hôte, modèle de coût, outils CAP |
| `costs/` | modèle de coût J3R180 et données JCAlgTest sources |
| `vectors/` | constantes Poseidon t = 6 (référence et optimisées), vecteurs circomlibjs |
| `shell/` | côté Shell en C (`bjj_shell.c`) et banc d'émulation (`run.py`) |
| `tools/` | scripts Node (circomlibjs 0.1.7) |

## Licences et sources tierces

- `costs/source/` : profils JCAlgTest de la J3R180 (CRoCS, université Masaryk), dépôt crocs-muni/jcalgtest_results,
  commit 845324d6, licence MIT (`costs/source/LICENSE`).
- `vectors/` : constantes et vecteurs produits par circomlibjs 0.1.7 (`tools/gen-vectors.mjs`). circomlibjs n'est
  pas redistribué, `npm install` le récupère.
