#!/usr/bin/env bash
# Blind EdDSA-Poseidon signer on BabyJubJub: functional checks, verified signatures and JCOP4 cost estimate.
set -euo pipefail
cd "$(dirname "$0")"
[ -f build/classpath.txt ] && [ -f build/kcprof-agent.jar ] || ./build.sh

# jCardSim ships Java Card API classes without stack map frames: bytecode verification must be off.
JAVA_OPTS=(-Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8
           -XX:+UnlockDiagnosticVMOptions -XX:-BytecodeVerificationRemote
           -javaagent:build/kcprof-agent.jar)

for lib in /usr/lib/x86_64-linux-gnu/libpcsclite.so.1 /usr/lib/aarch64-linux-gnu/libpcsclite.so.1; do
  if [ -e "$lib" ]; then
    JAVA_OPTS+=("-Dsun.security.smartcardio.library=$lib")
    break
  fi
done

exec java "${JAVA_OPTS[@]}" -cp "$(cat build/classpath.txt)" zknox.kcsim.BjjBench "$@"
