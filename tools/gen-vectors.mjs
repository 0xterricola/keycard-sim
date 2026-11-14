// Regenerates vectors/poseidon_t6.txt and vectors/circomlib_vectors.json. Usage: cd tools && npm install && node gen-vectors.mjs ../vectors
import fs from "fs";
import { buildEddsa, buildPoseidonReference } from "circomlibjs";
const consts = JSON.parse(fs.readFileSync(new URL("./node_modules/circomlibjs/src/poseidon_constants.json", import.meta.url), "utf8"));

import path from "path";

const out = process.argv[2];
const t = 6;
const C = consts.C[t - 2];
const M = consts.M[t - 2];
let txt = `# circomlibjs 0.1.7 src/poseidon_constants.js, t=${t} (5 inputs), RF=8, RP=60\n`;
txt += `C ${C.length}\n` + C.join("\n") + "\n";
txt += `M ${M.length}\n` + M.map(r => r.join(" ")).join("\n") + "\n";
fs.writeFileSync(path.join(out, "poseidon_t6.txt"), txt);

// Constants of the optimized permutation (sparse partial rounds), as used by circomlibjs buildPoseidon
const opt = JSON.parse(fs.readFileSync(new URL("./node_modules/circomlibjs/src/poseidon_constants_opt.json", import.meta.url), "utf8"));
const mat = (name, m) => `${name} ${m.length}\n` + m.map(r => r.join(" ")).join("\n") + "\n";
let otxt = `# circomlibjs 0.1.7 src/poseidon_constants_opt.json, t=${t} (5 inputs), RF=8, RP=60\n`;
otxt += `C ${opt.C[t - 2].length}\n` + opt.C[t - 2].join("\n") + "\n";
otxt += `S ${opt.S[t - 2].length}\n` + opt.S[t - 2].join("\n") + "\n";
otxt += mat("M", opt.M[t - 2]) + mat("P", opt.P[t - 2]);
fs.writeFileSync(path.join(out, "poseidon_t6_opt.txt"), otxt);

const poseidon = await buildPoseidonReference();
const F = poseidon.F;
const eddsa = await buildEddsa();
const bj = eddsa.babyJub;
const s = (x) => bj.F.toObject(x).toString();

const inputs = [1n, 2n, 3n, 4n, 5n];
const ph = F.toObject(poseidon(inputs)).toString();

const prv = Buffer.from("0001020304050607080900010203040506070809000102030405060708090001", "hex");
const { createHash } = await import("crypto");
const blakeHash = (await import("blake-hash")).default;
const h = blakeHash("blake512").update(prv).digest();
const sBuff = eddsa.pruneBuffer(Buffer.from(h.slice(0, 32)));
let sLE = 0n; for (let i = 31; i >= 0; i--) sLE = (sLE << 8n) | BigInt(sBuff[i]);
const A = eddsa.prv2pub(prv);
const msg = F.e(1234567890n);
const sig = eddsa.signPoseidon(prv, msg);
const ok = eddsa.verifyPoseidon(msg, sig, A);
const vec = {
  source: "circomlibjs 0.1.7 (buildEddsa, buildPoseidonReference)",
  poseidon5: { inputs: inputs.map(String), output: ph },
  eddsa: {
    prv: prv.toString("hex"),
    s_pruned: sLE.toString(),
    A: [s(A[0]), s(A[1])],
    msg: F.toObject(msg).toString(),
    R8: [s(sig.R8[0]), s(sig.R8[1])],
    S: sig.S.toString(),
    verifyPoseidon: ok,
    packedSignature: Buffer.from(eddsa.packSignature(sig)).toString("hex"),
    packedA: Buffer.from(bj.packPoint(A)).toString("hex")
  }
};
fs.writeFileSync(path.join(out, "circomlib_vectors.json"), JSON.stringify(vec, null, 2) + "\n");
console.log(JSON.stringify(vec, null, 1));
