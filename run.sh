#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
[ -f build/classpath.txt ] || ./build.sh

# jCardSim ships Java Card API classes without stack map frames: bytecode verification must be off.
JAVA_OPTS=(-Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8
           -XX:+UnlockDiagnosticVMOptions -XX:-BytecodeVerificationRemote)

# PC/SC on Debian/Ubuntu: point javax.smartcardio at pcsclite.
for lib in /usr/lib/x86_64-linux-gnu/libpcsclite.so.1 /usr/lib/aarch64-linux-gnu/libpcsclite.so.1; do
  if [ -e "$lib" ]; then
    JAVA_OPTS+=("-Dsun.security.smartcardio.library=$lib")
    break
  fi
done

exec java "${JAVA_OPTS[@]}" -cp "$(cat build/classpath.txt)" zknox.kcsim.KcBench "$@"
