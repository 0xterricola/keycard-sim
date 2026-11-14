#!/usr/bin/env python3
"""Builds costs/jcop4_j3r180.tsv from the two JCAlgTest profiles of an NXP JCOP4 J3R180 SecID P71.

Usage: python3 -I costs/extract_jcalgtest.py <fixed.csv> <variable.csv> <out.tsv>

Each row: key, kind, values, JCAlgTest method name.
  fixed  : one value in ms per call
  len    : "len:ms,len:ms,..." (data-dependent profile), linear interpolation, clamped at both ends
  per256 : ms for a 256-byte call (fixed profile), scaled linearly with the call length
"""
import sys

WANTED = [
    # key used by the profiler                          kind     JCAlgTest method name
    ("KeyAgreement.init/EC_SVDP_DH_PLAIN_XY",           "fixed", "ALG_EC_FP LENGTH_EC_FP_256 ALG_EC_SVDP_DH KeyAgreement_init()"),
    ("KeyAgreement.generateSecret/EC_SVDP_DH_PLAIN_XY", "fixed", "ALG_EC_FP LENGTH_EC_FP_256 ALG_EC_SVDP_DH KeyAgreement_generateSecret()"),
    ("KeyAgreement.init/EC_SVDP_DH",                    "fixed", "ALG_EC_FP LENGTH_EC_FP_256 ALG_EC_SVDP_DH KeyAgreement_init()"),
    ("KeyAgreement.generateSecret/EC_SVDP_DH",          "fixed", "ALG_EC_FP LENGTH_EC_FP_256 ALG_EC_SVDP_DH KeyAgreement_generateSecret()"),
    ("ECPrivateKey.setS",                               "fixed", "TYPE_EC_FP_PRIVATE LENGTH_EC_FP_256 setS()"),
    ("ECPrivateKey.getS",                               "fixed", "TYPE_EC_FP_PRIVATE LENGTH_EC_FP_256 getS()"),
    ("ECKey.clearKey",                                  "fixed", "TYPE_EC_FP_PRIVATE LENGTH_EC_FP_256 clearKey()"),
    ("ECPublicKey.setW",                                "fixed", "TYPE_EC_FP_PUBLIC LENGTH_EC_FP_256 setW()"),
    ("ECPublicKey.getW",                                "fixed", "TYPE_EC_FP_PUBLIC LENGTH_EC_FP_256 getW()"),
    ("Cipher.init/RSA_NOPAD",                           "fixed", "TYPE_RSA_PUBLIC LENGTH_RSA_736 ALG_RSA_NOPAD Cipher_init()"),
    ("Cipher.doFinal/RSA_NOPAD",                        "fixed", "TYPE_RSA_PUBLIC LENGTH_RSA_736 ALG_RSA_NOPAD Cipher_doFinal()"),
    ("RSAKey.setExponent",                              "fixed", "TYPE_RSA_PRIVATE LENGTH_RSA_736 setExponent()"),
    ("RSAKey.setModulus",                               "fixed", "TYPE_RSA_PRIVATE LENGTH_RSA_736 setModulus()"),
    ("Signature.sign/ECDSA_SHA_256",                    "fixed", "KeyPair_ALG_EC_FP KeyBuilder_LENGTH_EC_FP_256 Signature_ALG_ECDSA_SHA Signature_sign()"),
    ("Signature.signPreComputedHash/ECDSA_SHA_256",     "fixed", "KeyPair_ALG_EC_FP KeyBuilder_LENGTH_EC_FP_256 Signature_ALG_ECDSA_SHA Signature_sign()"),
    ("Signature.init/ECDSA_SHA_256",                    "fixed", "KeyPair_ALG_EC_FP KeyBuilder_LENGTH_EC_FP_256 Signature_ALG_ECDSA_SHA Signature_init()"),
    ("Cipher.init/AES_BLOCK_128_ECB_NOPAD",             "fixed", "TYPE_AES LENGTH_AES_128 ALG_AES_BLOCK_128_ECB_NOPAD Cipher_init()"),
    ("Cipher.doFinal/AES_BLOCK_128_ECB_NOPAD",          "len",   "TYPE_AES LENGTH_AES_128 ALG_AES_BLOCK_128_ECB_NOPAD Cipher_doFinal()"),
    ("Signature.init/AES_MAC_128_NOPAD",                "fixed", "TYPE_AES LENGTH_AES_128 ALG_AES_MAC_128_NOPAD Signature_init()"),
    ("Signature.sign/AES_MAC_128_NOPAD",                "len",   "TYPE_AES LENGTH_AES_128 ALG_AES_MAC_128_NOPAD Signature_sign()"),
    ("Signature.update/AES_MAC_128_NOPAD",              "len",   "TYPE_AES LENGTH_AES_128 ALG_AES_MAC_128_NOPAD Signature_sign()"),
    ("MessageDigest.doFinal/SHA_256",                   "len",   "ALG_SHA_256 MessageDigest_doFinal()"),
    ("MessageDigest.update/SHA_256",                    "per256", "ALG_SHA_256 MessageDigest_update()"),
    ("MessageDigest.doFinal/SHA_512",                   "len",   "ALG_SHA_512 MessageDigest_doFinal()"),
    ("MessageDigest.update/SHA_512",                    "per256", "ALG_SHA_512 MessageDigest_update()"),
    ("MessageDigest.reset/SHA_256",                     "fixed", "ALG_SHA_256 MessageDigest_reset()"),
    ("MessageDigest.reset/SHA_512",                     "fixed", "ALG_SHA_512 MessageDigest_reset()"),
    ("RandomData.generateData",                         "len",   "ALG_SECURE_RANDOM RandomData_generateData()"),
    ("RandomData.nextBytes",                            "len",   "ALG_SECURE_RANDOM RandomData_generateData()"),
    ("Util.arrayCopyNonAtomic",                         "per256", "UTIL Util_arrayCopyNonAtomic_RAM()"),
    ("Util.arrayCopy",                                  "per256", "UTIL Util_arrayCopy_RAM()"),
    ("Util.arrayFillNonAtomic",                         "per256", "UTIL Util_arrayFillNonAtomic_RAM()"),
    ("Util.arrayCompare",                               "per256", "UTIL Util_arrayCompare_RAM()"),
]


def parse(path):
    """Returns {method name: [(data length, avg ms/op), ...]}."""
    out, method = {}, None
    avg = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            cols = [c.strip() for c in line.rstrip("\n").split(";")]
            if cols[0] == "method name:":
                method, avg = cols[1], None
            elif method and cols[0] == "operation stats (ms/op):" and len(cols) > 2:
                try:
                    avg = float(cols[2])
                except ValueError:
                    avg = None
            elif method and cols[0] == "operation info:" and avg is not None:
                length = int(cols[2]) if len(cols) > 2 and cols[2].isdigit() else 256
                out.setdefault(method, []).append((length, avg))
                avg = None
    return out


def main(fixed_csv, variable_csv, out_tsv):
    fixed, variable = parse(fixed_csv), parse(variable_csv)
    rows, missing = [], []
    for key, kind, name in WANTED:
        if kind == "len":
            pts = sorted(dict(variable.get(name, [])).items())
            if not pts:
                missing.append(name)
                continue
            rows.append((key, kind, ",".join(f"{l}:{v:.3f}" for l, v in pts), name))
        else:
            pts = fixed.get(name)
            if not pts:
                missing.append(name)
                continue
            rows.append((key, kind, f"{pts[0][1]:.3f}", name))
    with open(out_tsv, "w", encoding="utf-8") as f:
        f.write("# Generated by costs/extract_jcalgtest.py from JCAlgTest profiles of NXP JCOP4 J3R180 SecID P71\n")
        f.write("# key\tkind\tvalues_ms\tjcalgtest_method\n")
        for r in rows:
            f.write("\t".join(r) + "\n")
    for m in missing:
        print("absent du profil :", m, file=sys.stderr)
    print(f"{len(rows)} entrées écrites dans {out_tsv}")


if __name__ == "__main__":
    main(*sys.argv[1:4])
