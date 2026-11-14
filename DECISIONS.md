# Décisions

## ADR-001 : Build javac sans Gradle ni Maven

Le build Gradle de status-keycard dépend d'un plugin javacard (dépôt fidesmo en http), de Maven Central et de jitpack,
avec une version de Gradle ancienne. Maven Central n'est pas joignable depuis l'environnement de développement de
Claude. `build.sh` récupère donc les sources par git à des révisions épinglées et compile tout avec `javac`, y compris
BouncyCastle 1.65 (core + prov). Le build est reproductible et ne dépend que de GitHub.

## ADR-002 : Clés EC transitoires remplacées pour le simulateur

L'applet 4.0 alloue `TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT` (`SECP256k1.tmpECPrivateKey`,
`SecureChannelV2.ephemeralPriv`). Le jar `jcardsim-3.0.5-SNAPSHOT.jar` du sous-module lève `NO_SUCH_ALGORITHM` à
l'installation. `build.sh` remplace ce type par `TYPE_EC_FP_PRIVATE` dans une copie des sources. Cette adaptation ne
change que la persistance de l'objet clé, pas les calculs. Les sources originales ne sont pas modifiées.

## ADR-003 : Corriger jCardSim plutôt que remplacer keycard-math

Schnorr BIP340 utilise `keycard-math` (binaire seul), qui élève au carré via `ALG_RSA_NOPAD` avec une clé de 736 bits
et un exposant 2. Dans jCardSim, le tampon NOPAD est dimensionné sur le bloc d'entrée de chiffrement de BouncyCastle,
soit k−1 octets, ce qui rejette le bloc de k octets attendu par la spécification Java Card (`6F05`, `ILLEGAL_USE`).
Le correctif réécrit `AsymmetricCipherImpl` (NOPAD par `BigInteger.modPow`, entrée de la taille du module, sortie
complétée à gauche). Il est placé devant le jar dans le classpath. L'applet et `keycard-math` restent intacts.

## ADR-004 : Point de mesure

Le temps « carte » est pris autour de `CardChannel.send` sur le canal brut, sous le secure channel du SDK. Il contient
l'exécution de l'APDU dans le simulateur, ou le temps lecteur + carte en PC/SC, sans la crypto hôte du secure channel.
Le temps « total hôte » encadre l'appel SDK complet. Le banc vérifie qu'un SIGN produit exactement un APDU.

## ADR-005 : Vérification DER tolérante, strictness comptée à part

La normalisation low-s de l'applet peut produire un INTEGER `s` non minimal (environ 1/512). La vérification
cryptographique utilise un parseur tolérant. La conformité DER stricte est rapportée par un compteur distinct, pour ne
pas confondre signature invalide et encodage non canonique.

## ADR-006 : Pas de mode « clé courante »

L'applet 4.0 n'accepte plus que `SIGN P1=01` (dérivation à chaque appel) et répond `6B00` aux autres P1. Le banc
mesure donc toujours avec dérivation. `--path m` signe avec la clé maître pour isoler le coût de la dérivation.

## ADR-007 : BabyJubJub par son image de Weierstrass, conversion sur l'hôte

Le moteur EC de JCOP n'accepte que des courbes de Weierstrass courtes. BabyJubJub (Edwards tordue sur le corps de
BN254) est isomorphe à une courbe de Weierstrass via sa forme de Montgomery (A = 168698, B = 1). Les clés EC de la
carte reçoivent p, aW, bW, l'image de B8, l et le cofacteur 8, et la multiplication scalaire passe par
`ALG_EC_SVDP_DH_PLAIN_XY`, comme `SECP256k1.multiplyPoint`. La carte renvoie R et A en Weierstrass ; l'hôte les
convertit en Edwards, avec une seule inversion, et calcule Poseidon. Une arithmétique d'Edwards écrite en bytecode
n'utiliserait pas le coprocesseur EC. Le neutre est le seul point exceptionnel du sous-groupe d'ordre l, et la carte
ne le produit pas (r et s non nuls modulo l).

## ADR-008 : Signature aveugle en deux APDU, sessions séquentielles

COMMIT renvoie R = r·B8, RESPOND reçoit c et renvoie S = r + c·s mod l. La carte ne voit ni le message ni Poseidon, et
reçoit c déjà réduit (c ≥ l refusé). Une seule session est armée : COMMIT détruit la précédente, RESPOND désarme la
session avant tout calcul, y compris sur refus. Les attaques ROS demandent des sessions concurrentes ; en séquentiel,
le Schnorr aveugle à deux passes est sûr sous OMDL dans AGM + ROM (Kastner, Loss, Xu, PKC 2022). La clé BabyJubJub est
distincte de l'arbre BIP32 : LOAD_KEY reçoit le scalaire élagué circomlib, que l'hôte dérive par BLAKE-512 (absent de
Java Card). Les INS B0 à B4 sont libres dans l'applet 4.0.

## ADR-009 : Nonce invalidé par de l'aléa, paramètres réécrits au select

Après usage, le nonce (tableau et clé EC) est remplacé par une valeur aléatoire inférieure à 2^250, sans `clearKey`.
Un RESPOND rejoué, ou une faute qui saute le test d'état, calcule alors r'' + c·s avec r'' jamais publié, et jamais
c·s seul. `clearKey` coûte 1,5 ms et impose de réécrire les paramètres de domaine. La clé nonce est
`TRANSIENT_DESELECT` sur carte : ses paramètres sont perdus au deselect, `onSelect` les réécrit. La réponse est
calculée deux fois et comparée (6F0F), `lessThan` est à temps constant, r est tiré par rejet sur 251 bits.

## ADR-010 : Réponse entière

La réduction modulo l de keycard-math (`timesMinus`) coûte environ 210 000 bytecodes par réponse. Le mode integer
l'évite : COMMIT prépare r' = r + l·t avec t de 320 bits, RESPOND renvoie S' = r' + c·s sur les entiers (72 octets) et
l'hôte réduit. Les produits sont exacts sous un module RSA-736 généré, avec l'exposant 2 (même technique que
keycard-math) : xy = ((x + y)² − x² − y²)/2. t masque le quotient ⌊(r + c·s)/l⌋ < 2^251 à 2^−69 près. Le masquage
additif de s (mode masked) n'est pas combiné avec ce mode.

## ADR-011 : Mode chaîné

Le secure channel v2 coûte de 51 à 66 ms par APDU. Avec P1 = 08, RESPOND ouvre la session suivante et ajoute son R à
la réponse : une APDU par signature en régime établi. Le R suivant n'est émis qu'après S, les sessions restent
séquentielles (ADR-008).

## ADR-012 : Profilage par agent ASM, bytecodes JVM

Les temps JVM du simulateur ne prédisent rien sur carte. Un agent `-javaagent` (ASM 9.6, pris dans le sous-module
`sdks`) instrumente les classes de l'applet et compte les bytecodes exécutés par bloc de base, et pose des sondes à
l'entrée des implémentations jCardSim de l'API, filtrées sur l'appelant (StackWalker) pour ne garder que les appels de
l'applet. Les `i2s` sont exclus, le convertisseur Java Card les supprime. Les autres écarts entre bytecode JVM et
bytecode Java Card (`sinc`, `sadd`, accès aux tableaux) sont acceptés : le compte sert d'ordre de grandeur, et t_bc
se calibre sur carte avec la même boucle (CALIBRATE) que celle comptée dans le simulateur.

## ADR-013 : Modèle de coût JCAlgTest J3R180

Pas de données publiques pour la J3R200. JCAlgTest publie des mesures fixes et variables (par longueur) pour une
J3R180, même famille JCOP4 P71. `costs/extract_jcalgtest.py` en tire `costs/jcop4_j3r180.tsv`. Deux substitutions :
`ALG_EC_SVDP_DH_PLAIN_XY` au prix de `ALG_EC_SVDP_DH` (absent des mesures), et les setters de clé publique RSA au prix
de ceux de la clé privée (JCAlgTest renvoie NO_SUCH_ALGORITHM pour les publics). Les appels sans entrée valent 0 ms et
sont listés dans le rapport.

## ADR-014 : Contrôle par le convertisseur Java Card 3.1

jCardSim accepte du Java que le convertisseur refuse (types `int`, API absentes). `cap.sh` convertit l'applet
d'origine et le fork avec le kit 3.1 du sous-module `sdks`, cible 3.0.5, après avoir ramené les classes au format 51.
Le fork passe sans erreur ni avertissement, et la comparaison des composants donne le surcoût en code.

## ADR-015 : Provisionnement d'une carte de dev

Une carte de dev chargée avec le fork n'a pas de certificat d'identité, et le SDK refuse d'ouvrir le secure channel v2
sans certificat signé par une CA connue. Avec `--target pcsc --provision`, `CardSession` installe dans l'applet Ident
un certificat signé par la CA de test du simulateur (seulement si elle n'en a pas) et accepte cette CA en plus de la
CA de production. L'INIT de l'applet 4.0 ne prend que le PIN et le PUK : le secret d'appairage n'est envoyé qu'aux
cartes en secure channel v1.

## ADR-016 : Coût Shell par émulation Cortex-M33

La Shell (STM32H573, Cortex-M33 à 250 MHz) n'est pas disponible pour mesurer. Son code est écrit en C portable,
compilé par clang pour thumbv8m.main et exécuté dans Unicorn avec le modèle Cortex-M33 ; chaque sortie est comparée
au vecteur circomlibjs et à une référence Python. Unicorn ne donne pas de cycles : le banc compte les instructions
exécutées et applique un modèle par classe (chargement 2, branche prise 3, LDM/STM 1 + N, le reste 1), avec code et
constantes supposés en cache. Le compte à CPI = 1 est donné à côté comme borne basse. Le PKA n'est pas utilisé :
la table de temps de RM0481 ne donne pas la multiplication de Montgomery seule, et l'aller-retour par la RAM du PKA
pour chaque produit de Poseidon n'a pas de coût publié. Poseidon suit la variante optimisée de circomlibjs
(`buildPoseidon`, tours partiels creux), environ deux fois moins de produits que la référence. Le transfert T=1 est
calculé depuis la PPS de la Shell (`app/iso7816/pps.c`) et l'ATR JCOP4 par défaut (TA1 = 18).
