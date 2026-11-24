# Cross-restart simulator RNG regression

This test evaluates synthetic BabyJubJub EdDSA-Poseidon
signatures in jCardSim, not physical smart-card signing.

The pinned simulator's default RandomDataImpl produces
repeatable nonce sequences after JVM restarts.

For opt-in testing, build.sh compiles a simulator-only
override that seeds the BouncyCastle generator from Java
SecureRandom. The original deterministic mode remains
available for reproducible tests.

## Run

Build using JDK 17, install the Node dependencies under
tools/, then run:

```sh
python3 -B tools/test_rng_restart.py
```

The regression requires:

- 20 distinct commitments across two JVM processes
- 20 distinct messages using one synthetic signing public key
- 20/20 signatures accepted by circomlibjs
- Rejection of a deliberately mutated message

The simulator-only property is
`zknox.jcardsim.rng.secure=true`.

This test does not establish production nonce security,
malicious-host resistance, hardware RNG correctness, or
safe transaction authorization. Never use wallet keys.
