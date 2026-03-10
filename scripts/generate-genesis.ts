/**
 * GEP Genesis Cache Generator
 * 
 * Exact Merkle: R0-R5 (fits in memory)
 * Deterministic approximation: R6-R8 (seed-based, still cryptographically bound)
 * 
 * Run once: pnpm generate-genesis
 */

import { computeEpochChain, verifyEpochChain } from "../src/index.js";
import { writeFileSync } from "fs";

console.log("🌍 GEP Genesis Cache Generator");
console.log("Computing epoch chain R0-R8...\n");
console.log("  (R0-R5 exact, R6-R8 deterministic approximation)\n");

const chain = await computeEpochChain(8, (r) => {
  const counts: Record<number, string> = {
    0: "122", 1: "842", 2: "5,882", 3: "41,162",
    4: "288,122", 5: "2,016,842", 6: "14,117,882 (approx)",
    7: "98,825,162 (approx)", 8: "691,776,122 (approx)"
  };
  console.log(`  ✓ R${r} — ${counts[r]} cells`);
});

console.log("\nVerifying chain integrity...");
const violations = verifyEpochChain(chain);
if (violations.length > 0) {
  console.error("❌ Chain verification failed:", violations);
  process.exit(1);
}

console.log("  ✓ All epochs valid");
console.log(`  ✓ Genesis hash: ${chain[0].epoch_hash}`);

const genesis = {
  protocol_version: 1,
  generated_at: new Date().toISOString(),
  generator_version: "0.1.0",
  note: "R0-R5 exact Merkle. R6-R8 deterministic seed approximation.",
  genesis_hash: chain[0].epoch_hash,
  chain: chain.map(e => ({
    ...e,
    cell_count: e.cell_count.toString(),
  })),
};

writeFileSync("src/genesis.json", JSON.stringify(genesis, null, 2));
console.log("\n✅ Genesis cache written to src/genesis.json");
console.log(`   Genesis hash: ${chain[0].epoch_hash}`);
console.log("\n   Commit this file. It is the cryptographic anchor of GEP.");
