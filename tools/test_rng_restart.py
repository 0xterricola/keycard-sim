#!/usr/bin/env python3
"""Cross-JVM nonce uniqueness and circomlib regression; simulator only."""
from pathlib import Path
import copy
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JDK = Path("/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home")
PROPERTY = "zknox.jcardsim.rng.secure"

def check(ok, name):
    print(f"{name}: {'PASS' if ok else 'FAIL'}", flush=True)
    if not ok:
        raise RuntimeError(name)

def invoke(argv, cwd=ROOT, env=None):
    return subprocess.run(
        argv, cwd=cwd, env=env,
        capture_output=True, text=True, errors="replace",
        timeout=900, check=False,
    )

def main():
    print("MODE: SEEDED_SIMULATOR_REGRESSION", flush=True)
    print("CARD_OPERATIONS: 0", flush=True)

    check((ROOT / "build/classpath.txt").is_file(), "SIMULATOR_BUILD")
    check(
        (ROOT / "build/jcardsim-patch/com/licel/jcardsim/"
         "crypto/RandomDataImpl.class").is_file(),
        "RNG_OVERRIDE_CLASS",
    )
    check(
        (ROOT / "tools/node_modules/circomlibjs/package.json").is_file(),
        "CIRCOMLIB_AVAILABLE",
    )
    check((JDK / "bin/java").is_file(), "JDK17")

    env = os.environ.copy()
    env["JAVA_HOME"] = str(JDK)
    env["PATH"] = str(JDK / "bin") + os.pathsep + env["PATH"]
    env["JAVA_TOOL_OPTIONS"] = (
        env.get("JAVA_TOOL_OPTIONS", "") +
        " -D" + PROPERTY + "=true"
    ).strip()
    env["GIT_TERMINAL_PROMPT"] = "0"

    with tempfile.TemporaryDirectory(
        prefix="keycard-nonce-regression-"
    ) as directory:
        folder = Path(directory)
        batches = []

        for idx in (1, 2):
            export = folder / f"batch-{idx}.json"
            result = invoke([
                "bash", "./bjj.sh",
                "--target", "sim",
                "--modes", "plain",
                "--iters", "10",
                "--warmup", "0",
                "--no-reference",
                "--details", "none",
                "--export", str(export),
            ], env=env)

            check(
                result.returncode == 0 and export.is_file(),
                f"BATCH_{idx}_SIGNING",
            )

            data = json.loads(export.read_text("utf-8"))

            check(
                isinstance(data, list) and len(data) == 10
                and all(
                    isinstance(s, dict)
                    and s.get("mode") == "plain"
                    and isinstance(s.get("A"), list)
                    and len(s["A"]) == 2
                    and isinstance(s.get("R8"), list)
                    and len(s["R8"]) == 2
                    and all(
                        k in s for k in ("S", "msg", "packed")
                    )
                    for s in data
                ),
                f"BATCH_{idx}_EXPORT_SHAPE",
            )

            points = {
                tuple(map(str, s["R8"])) for s in data
            }
            print(
                f"BATCH_{idx}_UNIQUE_R8: {len(points)}/10",
                flush=True,
            )
            check(
                len(points) == 10,
                f"BATCH_{idx}_NONCE_UNIQUENESS",
            )
            batches.append(data)

        signatures = batches[0] + batches[1]
        points_a = {
            tuple(map(str, s["R8"])) for s in batches[0]
        }
        points_b = {
            tuple(map(str, s["R8"])) for s in batches[1]
        }

        shared = len(points_a & points_b)
        unique = len(points_a | points_b)

        print(f"CROSS_BATCH_SHARED_R8: {shared}", flush=True)
        print(f"TOTAL_UNIQUE_R8: {unique}/20", flush=True)

        check(
            shared == 0 and unique == 20,
            "CROSS_PROCESS_NONCE_UNIQUENESS",
        )
        check(
            len({str(s["msg"]) for s in signatures}) == 20,
            "DISTINCT_MESSAGES",
        )
        check(
            len({
                tuple(map(str, s["A"]))
                for s in signatures
            }) == 1,
            "SAME_SIGNING_PUBLIC_KEY",
        )

        combined = folder / "combined.json"
        combined.write_text(
            json.dumps(signatures), encoding="utf-8"
        )

        verified = invoke([
            "node", "verify-circomlib.mjs", str(combined)
        ], cwd=ROOT / "tools", env=env)

        match = re.search(
            r"(\d+)/(\d+)\s+signatures valides",
            verified.stdout,
        )

        print(
            "CIRCOMLIB_VALID_SIGNATURES: " +
            (
                f"{match.group(1)}/{match.group(2)}"
                if match else "NOT_PARSED"
            ),
            flush=True,
        )

        check(
            verified.returncode == 0
            and match is not None
            and (
                int(match.group(1)),
                int(match.group(2))
            ) == (20, 20),
            "CIRCOMLIB_20_OF_20",
        )

        # Cryptographic negative control: alter the message
        # while preserving its signature and packed encoding.
        corrupted = copy.deepcopy(signatures)
        corrupted[0]["msg"] = (
            "0" if str(corrupted[0]["msg"]) != "0" else "1"
        )

        mutated = folder / "mutated.json"
        mutated.write_text(
            json.dumps(corrupted), encoding="utf-8"
        )

        negative = invoke([
            "node", "verify-circomlib.mjs", str(mutated)
        ], cwd=ROOT / "tools", env=env)

        bad = re.search(
            r"(\d+)/(\d+)\s+signatures valides",
            negative.stdout,
        )

        print(
            "MUTATED_VALID_SIGNATURES: " +
            (
                f"{bad.group(1)}/{bad.group(2)}"
                if bad else "NOT_PARSED"
            ),
            flush=True,
        )

        check(
            negative.returncode != 0
            and bad is not None
            and (
                int(bad.group(1)),
                int(bad.group(2))
            ) == (19, 20),
            "MUTATED_MESSAGE_REJECTED",
        )

    print("RESULT: PASS", flush=True)

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(
            f"ERROR_CLASS: {type(exc).__name__}",
            flush=True,
        )
        print("RESULT: STOPPED", flush=True)
        sys.exit(1)
