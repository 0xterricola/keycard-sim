# M3.45 — Trusted RAILGUN signing authorization

**Status:** Proposed design; not implemented or hardware-validated.

**Scope:** BabyJubJub EdDSA-Poseidon COMMIT/RESPOND using
synthetic keys on the ZKNOX Keycard simulator.

## Current implementation

- [BjjSigner](../applet-ext/im/status/keycard/BjjSigner.java)
  requires PIN validation and accepts a host-supplied challenge.
- [CardSession](../src/zknox/kcsim/CardSession.java)
  transports the commands through an authenticated secure channel.
- [Shell-side Poseidon](../shell/bjj_shell.c)
  computes the challenge in an emulated, freestanding C implementation.

Neither PIN authentication nor secure-channel possession proves
that the user approved a particular RAILGUN transaction.

The current implementation has no trusted approval permit.
A host with authorized APDU access can call RESPOND directly.

## Trust boundaries

| Component | Responsibility |
| --- | --- |
| Untrusted host | Propose a transaction, transport messages and APDUs |
| Trusted Shell | Independently interpret intent, display it, obtain physical approval and compute Poseidon T6 |
| Secure element | Hold the signing scalar and nonce; verify authorization before RESPOND |
| RAILGUN verifier | Check the final EdDSA-Poseidon signature |

The trusted Shell approval workflow and authenticated Shell-to-card
permit channel are proposed components, not current functionality.

## Proposed authorized session

1. Host proposes a canonically encoded, domain-separated signing intent.
2. Trusted Shell independently interprets the intent and determines the
   exact field-element message committed to EdDSA-Poseidon.
3. User approves that intent through a trusted physical interface.
4. Card opens a signing session, producing R and a fresh session identifier.
5. Shell verifies A and R, calculates c = Poseidon(R8, A, msg) mod l,
   and creates an authenticated, single-use authorization permit.
6. Card validates the permit, its trusted issuer, the current session,
   A, R, c, and required domain bindings before releasing a response.
7. Card irreversibly consumes the pending nonce and authorization
   before computing the signature response.

The permit must bind protocol/version, card identity, key identity,
session identity, R, A, approved-intent digest, domain and challenge.

The card does not independently calculate Poseidon T6 in this design.
It must rely on an authenticated Shell that independently computes c
from the exact user-approved message.

## Enforcement requirements

**AUTH-01:** Raw RESPOND without a valid permit must fail.

**AUTH-02:** A permit cannot be forged by the transport host.
Shell authorization credentials must not be exposed to the host.

**AUTH-03:** A permit for another R, A, session or card must fail.

**AUTH-04:** Challenge, approved intent and domain must be bound.
A substituted challenge must fail even with valid PIN authentication.

**AUTH-05:** Permit replay must fail, including after applet reselect,
session replacement, cancellation and card reset.

**AUTH-06:** Explicit CANCEL must disarm the pending session on-card.
Host-side abandonment alone is not cancellation.

**AUTH-07:** A rejected privileged RESPOND must fail closed and
invalidate or otherwise safely terminate the pending authorization.

**AUTH-08:** Chained signing cannot silently authorize a subsequent
response. Every signature needs its own authorized intent.

**AUTH-09:** Key loading and authorization-key provisioning require
separate, explicitly defined trust boundaries. The current host-supplied
synthetic scalar is not a production provisioning protocol.

**AUTH-10:** Secure-channel authentication and PIN validation are
necessary access controls, but not transaction approval.

## Required adversarial tests

| Scenario | Required result |
| --- | --- |
| Direct RESPOND without permit | Reject |
| Correct signed permit and challenge | Accept once |
| Message substitution | Reject |
| Challenge substitution | Reject |
| Wrong public key | Reject |
| Wrong commitment | Reject |
| Wrong card or session | Reject |
| Wrong protocol domain | Reject |
| Replayed permit | Reject |
| Previously cancelled session | Reject |
| Reselect or reset with stale permit | Reject |
| Malformed RESPOND or permit | Fail closed |
| Chained response without fresh approval | Reject |

## Unresolved implementation decisions

- Shell authorization-key provisioning, isolation and recovery
- Whether a card-verifiable MAC or asymmetric permit is appropriate
- On-card permit verification cost and JCOP3/JCOP4 compatibility
- Persistent anti-replay state versus transient session binding
- Canonical RAILGUN intent representation and trusted display contents
- Explicit cancellation APDU and interrupted-session behavior
- Card storage, rollback protection and fault-injection resistance

## Evidence boundary

Simulator signing correctness, nonce uniqueness and lifecycle
behavior have been tested with synthetic keys.

M3.44a–c also demonstrated that a host-only approval wrapper
can be bypassed through direct APDU access.

No production authorization, actual Shell user approval,
JCOP4 hardware signing or private-wallet-key isolation has
been established by these tests.

This document is a security contract, not a claim of implementation.
