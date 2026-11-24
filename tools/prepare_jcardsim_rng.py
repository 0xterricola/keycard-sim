#!/usr/bin/env python3
"""Build-only, opt-in RNG seeding for the pinned jCardSim simulator.

Not included in a JavaCard CAP. Deterministic behavior remains the default.
"""
from pathlib import Path
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])

original = source.read_text(encoding="utf-8")
needle = "engine = new DigestRandomGenerator(new SHA1Digest());"

if original.count(needle) != 1:
    raise SystemExit("Unexpected pinned RandomDataImpl source")

replacement = needle + """
        if (Boolean.getBoolean("zknox.jcardsim.rng.secure")) {
            byte[] entropy = new byte[32];
            new java.security.SecureRandom().nextBytes(entropy);
            engine.addSeedMaterial(entropy);
            java.util.Arrays.fill(entropy, (byte) 0);
        }
"""

destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text(
    original.replace(needle, replacement),
    encoding="utf-8",
)
