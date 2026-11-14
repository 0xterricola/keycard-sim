#!/usr/bin/env bash
# Converts the original Keycard applet and the BabyJubJub fork to CAP files with the Oracle converter (JC 3.1 kit,
# target 3.0.5) and compares the component sizes. This also checks that the fork stays within the Java Card subset.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$PWD
[ -f build/classpath.txt ] || ./build.sh

KIT=$ROOT/deps/status-keycard/sdks/jc310r20210706_kit
KMATH=$ROOT/deps/status-keycard/keycard-math
API=$KIT/lib/api_classic-3.0.5.jar
KIT_CP=$(ls "$KIT"/lib/*.jar | tr '\n' ':')
OUT=$ROOT/build/cap
AIDS=(-applet 0xA0:0x00:0x00:0x08:0x04:0x00:0x01:0x01 KeycardApplet
      -applet 0xA0:0x00:0x00:0x08:0x04:0x00:0x01:0x04 IdentApplet
      -applet 0xA0:0x00:0x00:0x08:0x04:0x00:0x01:0x02 NDEFApplet
      -applet 0xA0:0x00:0x00:0x08:0x04:0x00:0x01:0x03 CashApplet)

for v in original bjj; do
  rm -rf "$OUT/$v" && mkdir -p "$OUT/$v/src" "$OUT/$v/classes" "$OUT/$v/out"
  cp "$ROOT/deps/status-keycard/src/main/java/im/status/keycard/"*.java "$OUT/$v/src/"
  if [ "$v" = bjj ]; then
    cp "$ROOT/applet-ext/im/status/keycard/"*.java "$OUT/$v/src/"
    (cd "$OUT/$v/src" && patch -s -p0 < "$ROOT/patches/applet-bjj.patch")
  fi
  javac -nowarn -g:none -encoding UTF-8 --release 8 -cp "$API:$KMATH/keycard-math.jar" -d "$OUT/$v/classes" "$OUT/$v/src/"*.java
  java -cp "$ROOT/build/classes" zknox.kcsim.CapTools classversion "$OUT/$v/classes" 51
  java -Dstdout.encoding=UTF-8 -Djc.home="$KIT" -cp "$KIT_CP" com.sun.javacard.converter.Main -target 3.0.5 \
    -classdir "$OUT/$v/classes" -exportpath "$KMATH" -d "$OUT/$v/out" -out CAP EXP "${AIDS[@]}" \
    im.status.keycard 0xA0:0x00:0x00:0x08:0x04:0x00:0x01 4.0 2>&1 \
    | grep -E "error|warning|conversion completed" | grep -v "older export file format" || true
done

echo
java -Dstdout.encoding=UTF-8 -cp "$ROOT/build/classes" zknox.kcsim.CapTools compare \
  "$OUT/original/out/im/status/keycard/javacard/keycard.cap" "$OUT/bjj/out/im/status/keycard/javacard/keycard.cap"
echo "CAP du fork : $OUT/bjj/out/im/status/keycard/javacard/keycard.cap"
