#!/usr/bin/env bash
# Builds the Keycard simulation bench without Gradle or Maven: everything comes from GitHub at pinned revisions
# and is compiled with javac (JDK >= 11).
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$PWD
DEPS=$ROOT/deps
OUT=$ROOT/build

KEYCARD_REPO=https://github.com/keycard-tech/status-keycard.git
KEYCARD_REV=37393a2cbe9a54352cc8d69e97fc7ea08a840625   # applet 4.0, 2026-10-12
SDK_REPO=https://github.com/keycard-tech/status-keycard-java.git
SDK_REV=b79a031932e14a718e082241934c2fbef4bec431
BC_REPO=https://github.com/bcgit/bc-java.git
BC_TAG=r1rv65                                          # BouncyCastle 1.65, as in the applet test suite

fetch_rev() { # repo dir rev
  local repo=$1 dir=$2 rev=$3
  if [ ! -d "$dir/.git" ]; then
    git init -q "$dir"
    git -C "$dir" remote add origin "$repo"
  fi
  if [ "$(git -C "$dir" rev-parse -q --verify HEAD 2>/dev/null || true)" != "$rev" ]; then
    git -C "$dir" fetch -q --depth 1 origin "$rev"
    git -C "$dir" checkout -q FETCH_HEAD
  fi
}

mkdir -p "$DEPS" "$OUT"

echo "[1/8] sources"
fetch_rev "$KEYCARD_REPO" "$DEPS/status-keycard" "$KEYCARD_REV"
git -C "$DEPS/status-keycard" submodule update -q --init --depth 1 jcardsim sdks
fetch_rev "$SDK_REPO" "$DEPS/status-keycard-java" "$SDK_REV"
if [ ! -d "$DEPS/bc-java/.git" ]; then
  git clone -q --depth 1 --branch "$BC_TAG" "$BC_REPO" "$DEPS/bc-java"
fi

JCARDSIM=$DEPS/status-keycard/jcardsim/jcardsim-3.0.5-SNAPSHOT.jar
KCMATH=$DEPS/status-keycard/keycard-math/keycard-math.jar
ASM=$DEPS/status-keycard/sdks/jc320v24.1_kit/lib/asm-9.6.jar
JAVAC=(javac -nowarn -encoding UTF-8 -J-Xmx2g)

echo "[2/8] BouncyCastle 1.65 (core + prov)"
if [ ! -f "$OUT/bcprov-1.65.jar" ]; then
  rm -rf "$OUT/bc" && mkdir -p "$OUT/bc"
  find "$DEPS/bc-java/core/src/main/java" "$DEPS/bc-java/prov/src/main/java" -name '*.java' > "$OUT/bc-sources.txt"
  "${JAVAC[@]}" --release 8 -d "$OUT/bc" @"$OUT/bc-sources.txt"
  cp -r "$DEPS/bc-java/prov/src/main/resources/." "$OUT/bc/"
  (cd "$OUT/bc" && jar cf "$OUT/bcprov-1.65.jar" .)
fi

echo "[3/8] SDK Java Keycard (lib + desktop)"
rm -rf "$OUT/sdk" && mkdir -p "$OUT/sdk"
find "$DEPS/status-keycard-java/lib/src/main/java" "$DEPS/status-keycard-java/desktop/src/main/java" -name '*.java' > "$OUT/sdk-sources.txt"
"${JAVAC[@]}" --release 11 -cp "$OUT/bcprov-1.65.jar" -d "$OUT/sdk" @"$OUT/sdk-sources.txt"
(cd "$OUT/sdk" && jar cf "$OUT/keycard-sdk.jar" .)

echo "[4/8] applet Keycard + BjjSigner (adaptée au simulateur, cf. DECISIONS.md)"
rm -rf "$OUT/applet-src" "$OUT/applet" && mkdir -p "$OUT/applet-src" "$OUT/applet"
cp "$DEPS/status-keycard/src/main/java/im/status/keycard/"*.java "$OUT/applet-src/"
cp "$ROOT/applet-ext/im/status/keycard/"*.java "$OUT/applet-src/"
(cd "$OUT/applet-src" && patch -s -p0 < "$ROOT/patches/applet-bjj.patch")
perl -pi -e 's/KeyBuilder\.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT/KeyBuilder.TYPE_EC_FP_PRIVATE/g' "$OUT/applet-src/"*.java
"${JAVAC[@]}" --release 8 -cp "$JCARDSIM:$KCMATH" -d "$OUT/applet" "$OUT/applet-src/"*.java

echo "[5/8] correctif jCardSim (RSA NOPAD)"
rm -rf "$OUT/jcardsim-patch" && mkdir -p "$OUT/jcardsim-patch"
mkdir -p "$OUT/jcardsim-patch-src/com/licel/jcardsim/crypto"
python3 "$ROOT/tools/prepare_jcardsim_rng.py" \
  "$DEPS/status-keycard/jcardsim/src/main/java/com/licel/jcardsim/crypto/RandomDataImpl.java" \
  "$OUT/jcardsim-patch-src/com/licel/jcardsim/crypto/RandomDataImpl.java"
"${JAVAC[@]}" --release 8 -cp "$JCARDSIM:$OUT/bcprov-1.65.jar" -d "$OUT/jcardsim-patch" \
  "$ROOT/patches/jcardsim/com/licel/jcardsim/crypto/AsymmetricCipherImpl.java" \
  "$OUT/jcardsim-patch-src/com/licel/jcardsim/crypto/RandomDataImpl.java"

echo "[6/8] agent de profilage (ASM 9.6)"
rm -rf "$OUT/agent" && mkdir -p "$OUT/agent"
"${JAVAC[@]}" --release 11 -cp "$ASM:$JCARDSIM" -d "$OUT/agent" "$ROOT/agent/zknox/kcprof/"*.java
cp "$ASM" "$OUT/asm-9.6.jar"
printf 'Premain-Class: zknox.kcprof.Agent\nClass-Path: asm-9.6.jar\n' > "$OUT/agent-manifest.txt"
(cd "$OUT/agent" && jar cfm "$OUT/kcprof-agent.jar" "$OUT/agent-manifest.txt" .)

echo "[7/8] bancs de mesure"
CP="$OUT/jcardsim-patch:$JCARDSIM:$KCMATH:$OUT/applet:$OUT/keycard-sdk.jar:$OUT/bcprov-1.65.jar"
rm -rf "$OUT/classes" && mkdir -p "$OUT/classes/zknox/kcsim"
"${JAVAC[@]}" --release 11 -cp "$CP:$OUT/kcprof-agent.jar" -d "$OUT/classes" "$ROOT/src/zknox/kcsim/"*.java
cp "$ROOT/vectors/poseidon_t6.txt" "$OUT/classes/zknox/kcsim/"
echo "$OUT/classes:$CP" > "$OUT/classpath.txt"

echo "[8/8] ok : ./run.sh --help (ECDSA/Schnorr), ./bjj.sh --help (BabyJubJub), ./cap.sh (taille CAP)"
