/*
 * Shell side of the blind BabyJubJub signer, as it would run on the Keycard Shell (STM32H573, Cortex-M33).
 * Freestanding C, 8 x 32-bit limbs, Montgomery CIOS. Built for thumbv8m.main and executed in an emulator by
 * shell/run.py, which checks every output against a Python reference and counts the executed instructions.
 *
 * Steps per signature:
 *   - R from the card (short Weierstrass) to twisted Edwards;
 *   - hm = Poseidon(R.x, R.y, A.x, A.y, msg), t = 6, optimized (sparse) or reference permutation;
 *   - c = hm mod l, sent in RESPOND;
 *   - integer mode only: S = S' mod l, S' being the 72-byte integer response;
 *   - packed signature (R8 compressed, S little-endian), circomlib packSignature.
 */
#include <stdint.h>
#include <stddef.h>
#include "consts.h"

typedef uint32_t fe[8];

/* clang may lower struct and array copies to these */
void *memcpy(void *d, const void *s, size_t n) {
  uint8_t *dd = d;
  const uint8_t *ss = s;
  while (n--) *dd++ = *ss++;
  return d;
}

void *memset(void *d, int c, size_t n) {
  uint8_t *dd = d;
  while (n--) *dd++ = (uint8_t)c;
  return d;
}

/* ---------- multi-precision helpers (little-endian limbs) ---------- */

static inline uint32_t mp_sub(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) {
  uint64_t borrow = 0;
  for (int i = 0; i < 8; i++) {
    uint64_t d = (uint64_t)a[i] - b[i] - borrow;
    r[i] = (uint32_t)d;
    borrow = (d >> 63) & 1;
  }
  return (uint32_t)borrow;
}

static inline uint32_t mp_add(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) {
  uint64_t carry = 0;
  for (int i = 0; i < 8; i++) {
    uint64_t s = (uint64_t)a[i] + b[i] + carry;
    r[i] = (uint32_t)s;
    carry = s >> 32;
  }
  return (uint32_t)carry;
}

/* r = a if mask == 0, b if mask == 0xffffffff */
static inline void mp_select(uint32_t r[8], const uint32_t a[8], const uint32_t b[8], uint32_t mask) {
  for (int i = 0; i < 8; i++) r[i] = (a[i] & ~mask) | (b[i] & mask);
}

/* r = a - m if a >= m, else a (constant time) */
static inline void mp_csub(uint32_t r[8], const uint32_t a[8], const uint32_t m[8]) {
  uint32_t t[8];
  uint32_t borrow = mp_sub(t, a, m);
  mp_select(r, t, a, (uint32_t)0 - borrow);
}

/* Montgomery multiplication, CIOS: r = a.b.2^-256 mod m, for m < 2^254 (no final carry word overflow) */
static inline void mont_mul(uint32_t r[8], const uint32_t a[8], const uint32_t b[8], const uint32_t m[8],
                            uint32_t m0inv) {
  uint32_t t[10] = {0};
  for (int i = 0; i < 8; i++) {
    uint64_t c = 0;
    for (int j = 0; j < 8; j++) {
      c = (uint64_t)a[j] * b[i] + t[j] + (c >> 32);
      t[j] = (uint32_t)c;
    }
    c = (uint64_t)t[8] + (c >> 32);
    t[8] = (uint32_t)c;
    t[9] = (uint32_t)(c >> 32);

    uint32_t q = t[0] * m0inv;
    c = (uint64_t)q * m[0] + t[0];
    for (int j = 1; j < 8; j++) {
      c = (uint64_t)q * m[j] + t[j] + (c >> 32);
      t[j - 1] = (uint32_t)c;
    }
    c = (uint64_t)t[8] + (c >> 32);
    t[7] = (uint32_t)c;
    t[8] = t[9] + (uint32_t)(c >> 32);
  }
  mp_csub(r, t, m);
}

/* ---------- F_p, p = BN254 r, Montgomery form ---------- */

static inline void fp_mul(fe r, const fe a, const fe b) { mont_mul(r, a, b, FP_P, FP_M0INV); }

static inline void fp_add(fe r, const fe a, const fe b) {
  fe t;
  mp_add(t, a, b); /* a, b < p < 2^254: no carry out */
  mp_csub(r, t, FP_P);
}

static inline void fp_sub(fe r, const fe a, const fe b) {
  fe t, u;
  uint32_t borrow = mp_sub(t, a, b);
  mp_add(u, t, FP_P);
  mp_select(r, t, u, (uint32_t)0 - borrow);
}

static void fp_pow5(fe r, const fe a) {
  fe a2, a4;
  fp_mul(a2, a, a);
  fp_mul(a4, a2, a2);
  fp_mul(r, a4, a);
}

/* a^(p-2), square and multiply over the public exponent */
static void fp_inv(fe r, const fe a) {
  fe acc;
  for (int i = 0; i < 8; i++) acc[i] = FP_ONE[i];
  for (int bit = 253; bit >= 0; bit--) {
    fp_mul(acc, acc, acc);
    if ((FP_PM2[bit >> 5] >> (bit & 31)) & 1) fp_mul(acc, acc, a);
  }
  for (int i = 0; i < 8; i++) r[i] = acc[i];
}

static void be_to_limbs(uint32_t r[8], const uint8_t in[32]) {
  for (int i = 0; i < 8; i++) {
    const uint8_t *p = in + 28 - 4 * i;
    r[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
  }
}

static void limbs_to_be(uint8_t out[32], const uint32_t a[8]) {
  for (int i = 0; i < 8; i++) {
    uint8_t *p = out + 28 - 4 * i;
    p[0] = (uint8_t)(a[i] >> 24);
    p[1] = (uint8_t)(a[i] >> 16);
    p[2] = (uint8_t)(a[i] >> 8);
    p[3] = (uint8_t)a[i];
  }
}

static void fp_from_be(fe r, const uint8_t in[32]) {
  fe t;
  be_to_limbs(t, in);
  fp_mul(r, t, FP_R2);
}

static void fp_to_limbs(uint32_t r[8], const fe a) {
  static const uint32_t one[8] = {1, 0, 0, 0, 0, 0, 0, 0};
  fp_mul(r, a, one);
}

/* ---------- Poseidon t = 6 ---------- */

static void mix(fe st[6], const uint32_t (*m)[8]) {
  /* new[i] = sum_j m[j][i] . st[j], m given row-major as m[j * 6 + i] */
  fe out[6];
  for (int i = 0; i < 6; i++) {
    fe acc, prod;
    fp_mul(acc, m[i], st[0]);
    for (int j = 1; j < 6; j++) {
      fp_mul(prod, m[j * 6 + i], st[j]);
      fp_add(acc, acc, prod);
    }
    for (int k = 0; k < 8; k++) out[i][k] = acc[k];
  }
  for (int i = 0; i < 6; i++)
    for (int k = 0; k < 8; k++) st[i][k] = out[i][k];
}

/* circomlibjs buildPoseidonReference */
static void poseidon_ref(fe out, const fe in[5]) {
  fe st[6];
  for (int k = 0; k < 8; k++) st[0][k] = 0;
  for (int i = 0; i < 5; i++)
    for (int k = 0; k < 8; k++) st[i + 1][k] = in[i][k];
  for (int r = 0; r < 68; r++) {
    for (int i = 0; i < 6; i++) fp_add(st[i], st[i], PREF_C[r * 6 + i]);
    if (r < 4 || r >= 64) {
      for (int i = 0; i < 6; i++) fp_pow5(st[i], st[i]);
    } else {
      fp_pow5(st[0], st[0]);
    }
    mix(st, PREF_M);
  }
  for (int k = 0; k < 8; k++) out[k] = st[0][k];
}

/* circomlibjs buildPoseidon (sparse partial rounds, filecoin neptune optimization) */
static void poseidon_opt(fe out, const fe in[5]) {
  fe st[6];
  for (int k = 0; k < 8; k++) st[0][k] = 0;
  for (int i = 0; i < 5; i++)
    for (int k = 0; k < 8; k++) st[i + 1][k] = in[i][k];

  for (int i = 0; i < 6; i++) fp_add(st[i], st[i], POPT_C[i]);
  for (int r = 0; r < 3; r++) {
    for (int i = 0; i < 6; i++) {
      fp_pow5(st[i], st[i]);
      fp_add(st[i], st[i], POPT_C[(r + 1) * 6 + i]);
    }
    mix(st, POPT_M);
  }
  for (int i = 0; i < 6; i++) {
    fp_pow5(st[i], st[i]);
    fp_add(st[i], st[i], POPT_C[4 * 6 + i]);
  }
  mix(st, POPT_P);

  for (int r = 0; r < 60; r++) {
    fe s0, prod;
    fp_pow5(st[0], st[0]);
    fp_add(st[0], st[0], POPT_C[5 * 6 + r]);
    fp_mul(s0, POPT_S[11 * r], st[0]);
    for (int j = 1; j < 6; j++) {
      fp_mul(prod, POPT_S[11 * r + j], st[j]);
      fp_add(s0, s0, prod);
    }
    for (int k = 1; k < 6; k++) {
      fp_mul(prod, st[0], POPT_S[11 * r + 6 + k - 1]);
      fp_add(st[k], st[k], prod);
    }
    for (int k = 0; k < 8; k++) st[0][k] = s0[k];
  }

  for (int r = 0; r < 3; r++) {
    for (int i = 0; i < 6; i++) {
      fp_pow5(st[i], st[i]);
      fp_add(st[i], st[i], POPT_C[5 * 6 + 60 + r * 6 + i]);
    }
    mix(st, POPT_M);
  }
  for (int i = 0; i < 6; i++) fp_pow5(st[i], st[i]);
  mix(st, POPT_M);
  for (int k = 0; k < 8; k++) out[k] = st[0][k];
}

/* ---------- curve map, scalar reductions, packing ---------- */

/* Weierstrass (X, Y) to Edwards (x, y): u = X - A/3, t = 1/(Y(u+1)), x = u(u+1)t, y = (u-1)Yt */
static void w2e(fe x, fe y, const fe X, const fe Y) {
  fe u, u1, um1, t, d;
  fp_sub(u, X, FP_A3);
  fp_add(u1, u, FP_ONE);
  fp_sub(um1, u, FP_ONE);
  fp_mul(d, Y, u1);
  fp_inv(t, d);
  fp_mul(d, u, u1);
  fp_mul(x, d, t);
  fp_mul(d, um1, Y);
  fp_mul(y, d, t);
}

/* hm < p < 8l: three conditional subtractions give hm mod l */
static void mod_l_small(uint32_t r[8], const uint32_t a[8]) {
  uint32_t t[8];
  mp_csub(t, a, L_X4);
  mp_csub(t, t, L_X2);
  mp_csub(r, t, L_N);
}

/* a < 2^256 < 64l: six conditional subtractions */
static void mod_l_256(uint32_t r[8], const uint32_t a[8]) {
  uint32_t t[8];
  mp_csub(t, a, L_X32);
  mp_csub(t, t, L_X16);
  mp_csub(t, t, L_X8);
  mp_csub(t, t, L_X4);
  mp_csub(t, t, L_X2);
  mp_csub(r, t, L_N);
}

/* S' (72 bytes big-endian) = h2.2^512 + h1.2^256 + h0, S = h0 + h1.K1 + h2.K2 mod l, K_i = 2^(256 i) mod l */
static void sprime_mod_l(uint32_t r[8], const uint8_t in[72]) {
  uint32_t h0[8], h1[8], h2[8] = {0}, t[8], u[8];
  be_to_limbs(h0, in + 40);
  be_to_limbs(h1, in + 8);
  h2[1] = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | in[3];
  h2[0] = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 8) | in[7];
  mod_l_256(h0, h0);
  mod_l_256(h1, h1);
  mont_mul(t, h1, L_K1R, L_N, L_M0INV); /* h1.K1 mod l */
  mont_mul(u, h2, L_K2R, L_N, L_M0INV); /* h2.K2 mod l */
  mp_add(t, t, u);
  mp_csub(t, t, L_N);
  mp_add(t, t, h0);
  mp_csub(r, t, L_N);
}

/* circomlib packSignature: R8 compressed (y LE, bit 255 = x > (p-1)/2), then S LE */
static void pack(uint8_t out[64], const uint32_t x[8], const uint32_t y[8], const uint32_t s[8]) {
  uint32_t t[8];
  uint32_t gt = mp_sub(t, FP_HALF, x); /* borrow iff x > (p-1)/2 */
  for (int i = 0; i < 8; i++) {
    uint32_t w = y[i];
    if (i == 7) w |= gt << 31;
    out[4 * i] = (uint8_t)w;
    out[4 * i + 1] = (uint8_t)(w >> 8);
    out[4 * i + 2] = (uint8_t)(w >> 16);
    out[4 * i + 3] = (uint8_t)(w >> 24);
  }
  for (int i = 0; i < 8; i++) {
    out[32 + 4 * i] = (uint8_t)s[i];
    out[32 + 4 * i + 1] = (uint8_t)(s[i] >> 8);
    out[32 + 4 * i + 2] = (uint8_t)(s[i] >> 16);
    out[32 + 4 * i + 3] = (uint8_t)(s[i] >> 24);
  }
}

/* ---------- I/O block and entry points called by the emulator ---------- */

struct io {
  uint8_t rw[65];      /* card point R, 04 || X || Y */
  uint8_t a_ed[64];    /* A in Edwards, x || y big-endian (computed once, at LOAD_KEY) */
  uint8_t msg[32];     /* message field element, big-endian */
  uint8_t s_card[72];  /* RESPOND payload: S (32 bytes) or S' (72 bytes), big-endian */
  uint8_t r_ed[64];    /* out: R in Edwards, x || y big-endian */
  uint8_t hm[32];      /* out: Poseidon hash, big-endian */
  uint8_t c[32];       /* out: hm mod l, big-endian (RESPOND data) */
  uint8_t s[32];       /* out: S mod l, big-endian */
  uint8_t packed[64];  /* out: circomlib packed signature */
  uint32_t opt;        /* in: 1 = optimized Poseidon */
};

struct io io;

/* kept between the two half-steps of a signature */
static fe g_rx, g_ry;

static void out_fe(uint8_t out[32], const fe a) {
  uint32_t t[8];
  fp_to_limbs(t, a);
  limbs_to_be(out, t);
}

/* after COMMIT: map R, hash, reduce. Leaves c in io.c */
void step_challenge(void) {
  fe X, Y, ax, ay, m, h;
  fp_from_be(X, io.rw + 1);
  fp_from_be(Y, io.rw + 33);
  w2e(g_rx, g_ry, X, Y);
  fp_from_be(ax, io.a_ed);
  fp_from_be(ay, io.a_ed + 32);
  fp_from_be(m, io.msg);
  fe in[5];
  for (int k = 0; k < 8; k++) {
    in[0][k] = g_rx[k];
    in[1][k] = g_ry[k];
    in[2][k] = ax[k];
    in[3][k] = ay[k];
    in[4][k] = m[k];
  }
  if (io.opt) poseidon_opt(h, in); else poseidon_ref(h, in);
  uint32_t hl[8], cl[8];
  fp_to_limbs(hl, h);
  limbs_to_be(io.hm, hl);
  mod_l_small(cl, hl);
  limbs_to_be(io.c, cl);
  out_fe(io.r_ed, g_rx);
  out_fe(io.r_ed + 32, g_ry);
}

static void finish(const uint32_t s[8]) {
  uint32_t x[8], y[8];
  fp_to_limbs(x, g_rx);
  fp_to_limbs(y, g_ry);
  limbs_to_be(io.s, s);
  pack(io.packed, x, y, s);
}

/* after RESPOND, modular mode: S already reduced by the card */
void step_finish_mod(void) {
  uint32_t s[8];
  be_to_limbs(s, io.s_card);
  finish(s);
}

/* after RESPOND, integer mode: S = S' mod l */
void step_finish_int(void) {
  uint32_t s[8];
  sprime_mod_l(s, io.s_card);
  finish(s);
}

/* isolated parts, for the per-operation breakdown */
void op_w2e(void) {
  fe X, Y;
  fp_from_be(X, io.rw + 1);
  fp_from_be(Y, io.rw + 33);
  w2e(g_rx, g_ry, X, Y);
}

void op_poseidon(void) {
  fe in[5], h;
  for (int i = 0; i < 5; i++)
    for (int k = 0; k < 8; k++) in[i][k] = FP_ONE[k];
  if (io.opt) poseidon_opt(h, in); else poseidon_ref(h, in);
  out_fe(io.hm, h);
}

void op_fp_mul(void) {
  fe a, b;
  fp_from_be(a, io.msg);
  fp_mul(b, a, a);
  out_fe(io.hm, b);
}

void op_inv(void) {
  fe a, b;
  fp_from_be(a, io.msg);
  fp_inv(b, a);
  out_fe(io.hm, b);
}
