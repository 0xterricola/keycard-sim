// Verifies the signatures exported by bjj.sh --export with circomlibjs (eddsa.verifyPoseidon, unpackSignature).
// Usage: cd tools && npm install && node verify-circomlib.mjs ../sigs.json
import fs from "fs";
import { buildEddsa } from "circomlibjs";

const sigs = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const eddsa = await buildEddsa();
const F = eddsa.babyJub.F;
let ok = 0;
const failed = [];
for (const s of sigs) {
  const A = [F.e(BigInt(s.A[0])), F.e(BigInt(s.A[1]))];
  const sig = { R8: [F.e(BigInt(s.R8[0])), F.e(BigInt(s.R8[1]))], S: BigInt(s.S) };
  const unpacked = eddsa.unpackSignature(Buffer.from(s.packed, "hex"));
  const samePacking = F.eq(unpacked.R8[0], sig.R8[0]) && F.eq(unpacked.R8[1], sig.R8[1]) && unpacked.S === sig.S;
  if (eddsa.verifyPoseidon(F.e(BigInt(s.msg)), sig, A) && samePacking) {
    ok++;
  } else {
    failed.push(s.mode);
  }
}
console.log(`circomlibjs verifyPoseidon : ${ok}/${sigs.length} signatures valides` + (failed.length ? `, échecs : ${failed}` : ""));
process.exit(failed.length ? 1 : 0);
