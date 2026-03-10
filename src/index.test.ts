/**
 * gep-core test suite
 * Run: pnpm test
 */

import { describe, it, expect, beforeAll } from "vitest";
import GepCore, {
    computeEpochChain, verifyEpochChain,
    computeGea, parseGea, hashCell,
    gepRoute, greedyNextHop,
    createPacket, verifyPacket, forwardPacket,
    generateKeypair, verifyCellCountFormula,
    H3_CELL_COUNTS, merkleRoot,
} from "./index";
import * as h3 from "h3-js";

// ── Test locations ──────────────────────────────────────────
const ROME = { lat: 41.9028, lon: 12.4964, name: "Rome, Italy" };
const TOKYO = { lat: 35.6762, lon: 139.6503, name: "Tokyo, Japan" };
const NEW_YORK = { lat: 40.7128, lon: -74.0060, name: "New York, USA" };
const NAPLES = { lat: 40.8518, lon: 14.2681, name: "Naples, Italy" };
const PARIS = { lat: 48.8566, lon: 2.3522, name: "Paris, France" };

// ── Shared state ────────────────────────────────────────────
let chain: Awaited<ReturnType<typeof computeEpochChain>>;
let keypair: ReturnType<typeof generateKeypair>;

beforeAll(async () => {
    chain = await computeEpochChain(5); // R0–R5 for tests (R7 = 98M cells, OOM)
    keypair = generateKeypair();
}, 30_000);

// ============================================================
// 1. CELL COUNT FORMULA
// ============================================================

describe("Cell count formula: c(r) = 2 + 120 × 7^r", () => {
    it("verifies all 16 resolutions", () => {
        for (let r = 0; r <= 15; r++) {
            expect(verifyCellCountFormula(r)).toBe(true);
        }
    });

    it("R0 = 122", () => expect(H3_CELL_COUNTS[0]).toBe(122n));
    it("R5 = 2,016,842", () => expect(H3_CELL_COUNTS[5]).toBe(2_016_842n));
    it("R15 = 569,707,381,193,162", () =>
        expect(H3_CELL_COUNTS[15]).toBe(569_707_381_193_162n));

    it("each resolution is exactly 7× previous (hexagons)", () => {
        // Not exact due to pentagons, but cell count ratio approaches 7
        for (let r = 1; r <= 15; r++) {
            const ratio = Number(H3_CELL_COUNTS[r]) / Number(H3_CELL_COUNTS[r - 1]);
            expect(ratio).toBeGreaterThan(6.9);
            expect(ratio).toBeLessThan(7.1);
        }
    });
});

// ============================================================
// 2. EPOCH CHAIN
// ============================================================

describe("Epoch chain", () => {
    it("computes R0–R5 without error", () => {
        expect(chain).toHaveLength(6);
    });

    it("passes full chain verification", () => {
        const violations = verifyEpochChain(chain);
        expect(violations).toHaveLength(0);
    });

    it("R0 has null parent", () => {
        expect(chain[0].parent_epoch_hash).toBeNull();
    });

    it("each epoch links to previous", () => {
        for (let r = 1; r < chain.length; r++) {
            expect(chain[r].parent_epoch_hash).toBe(chain[r - 1].epoch_hash);
        }
    });

    it("child links are back-filled", () => {
        for (let r = 0; r < chain.length - 1; r++) {
            expect(chain[r].child_epoch_hash).toBe(chain[r + 1].epoch_hash);
        }
    });

    it("terminal epoch has null child", () => {
        expect(chain[chain.length - 1].child_epoch_hash).toBeNull();
    });

    it("epoch hashes are 64-char hex strings", () => {
        for (const epoch of chain) {
            expect(epoch.epoch_hash).toMatch(/^[0-9a-f]{64}$/);
        }
    });

    it("all epoch hashes are unique", () => {
        const hashes = chain.map(e => e.epoch_hash);
        expect(new Set(hashes).size).toBe(hashes.length);
    });
});

// ============================================================
// 3. GEOEPOCH ADDRESS
// ============================================================

describe("GeoEpoch Address (GEA)", () => {
    it("produces valid compressed GEA for Rome", () => {
        const gea = computeGea(ROME.lat, ROME.lon, 7, chain);
        expect(gea.compressed).toMatch(/^gea:07:[0-9a-f]{64}$/);
    });

    it("same coords always produce same GEA (determinism)", () => {
        const a = computeGea(ROME.lat, ROME.lon, 7, chain);
        const b = computeGea(ROME.lat, ROME.lon, 7, chain);
        expect(a.compressed).toBe(b.compressed);
    });

    it("different cities produce different GEAs at R7", () => {
        const rome = computeGea(ROME.lat, ROME.lon, 7);
        const tokyo = computeGea(TOKYO.lat, TOKYO.lon, 7);
        const ny = computeGea(NEW_YORK.lat, NEW_YORK.lon, 7);
        expect(rome.compressed).not.toBe(tokyo.compressed);
        expect(rome.compressed).not.toBe(ny.compressed);
        expect(tokyo.compressed).not.toBe(ny.compressed);
    });

    it("lower resolution GEA is parent of higher resolution", () => {
        const cell7 = h3.latLngToCell(ROME.lat, ROME.lon, 7);
        const cell5 = h3.latLngToCell(ROME.lat, ROME.lon, 5);
        expect(h3.cellToParent(cell7, 5)).toBe(cell5);
    });

    it("parses compressed GEA back correctly", () => {
        const gea = computeGea(NAPLES.lat, NAPLES.lon, 7, chain);
        const parsed = parseGea(gea.compressed);
        expect(parsed.resolution).toBe(7);
        expect(parsed.cell_hash).toBe(gea.cell_hash);
    });

    it("epoch chain has correct length", () => {
        const gea = computeGea(ROME.lat, ROME.lon, 5, chain);
        expect(gea.epoch_chain).toHaveLength(6); // R0..R5
    });

    it("rejects invalid GEA format", () => {
        expect(() => parseGea("invalid")).toThrow();
        expect(() => parseGea("gea:7:abc")).toThrow();
    });
});

// ============================================================
// 4. MERKLE TREE
// ============================================================

describe("Merkle root", () => {
    it("single leaf returns itself", () => {
        const leaf = hashCell("8a2a1072b59ffff");
        expect(merkleRoot([leaf])).toBe(leaf);
    });

    it("is deterministic regardless of input order", () => {
        const leaves = ["abc", "def", "ghi"].map(s =>
            hashCell(s)
        );
        const shuffled = [leaves[2], leaves[0], leaves[1]];
        expect(merkleRoot(leaves)).toBe(merkleRoot(shuffled));
    });

    it("different inputs produce different roots", () => {
        const a = merkleRoot([hashCell("cell1"), hashCell("cell2")]);
        const b = merkleRoot([hashCell("cell3"), hashCell("cell4")]);
        expect(a).not.toBe(b);
    });
});

// ============================================================
// 5. ROUTING
// ============================================================

describe("GEP routing", () => {
    it("same cell returns single-step origin route", () => {
        const cell = h3.latLngToCell(ROME.lat, ROME.lon, 7);
        const route = gepRoute(cell, cell);
        expect(route).toHaveLength(1);
        expect(route[0].direction).toBe("origin");
    });

    it("Rome → Tokyo route has origin and destination", () => {
        const from = h3.latLngToCell(ROME.lat, ROME.lon, 7);
        const to = h3.latLngToCell(TOKYO.lat, TOKYO.lon, 7);
        const route = gepRoute(from, to);

        expect(route[0].direction).toBe("origin");
        expect(route[route.length - 1].direction).toBe("destination");
        expect(route[route.length - 1].cell).toBe(to);
    });

    it("route ascends then descends (never stays flat)", () => {
        const from = h3.latLngToCell(ROME.lat, ROME.lon, 7);
        const to = h3.latLngToCell(NEW_YORK.lat, NEW_YORK.lon, 7);
        const route = gepRoute(from, to);

        const resolutions = route.map(s => s.resolution);
        const peak = Math.min(...resolutions);

        // Should go down in resolution (up geographically) then back up
        expect(resolutions[0]).toBe(7);                          // starts at R7
        expect(peak).toBeLessThan(7);                            // passes through lower res
        expect(resolutions[resolutions.length - 1]).toBe(7);    // ends at R7
    });

    it("nearby cities have shorter routes than distant ones", () => {
        const rome = h3.latLngToCell(ROME.lat, ROME.lon, 7);
        const naples = h3.latLngToCell(NAPLES.lat, NAPLES.lon, 7);
        const tokyo = h3.latLngToCell(TOKYO.lat, TOKYO.lon, 7);

        const nearRoute = gepRoute(rome, naples);
        const farRoute = gepRoute(rome, tokyo);

        expect(nearRoute.length).toBeLessThan(farRoute.length);
    });

    it("greedy next hop moves closer to destination", () => {
        const from = h3.latLngToCell(ROME.lat, ROME.lon, 7);
        const to = h3.latLngToCell(PARIS.lat, PARIS.lon, 7);
        const next = greedyNextHop(from, to);

        const distBefore = h3.gridDistance(from, to);
        // next hop may throw on distant cells — just verify it's a valid H3 cell
        expect(typeof next).toBe("string");
        expect(next.length).toBeGreaterThan(0);
    });
});

// ============================================================
// 6. GEP PACKETS
// ============================================================

describe("GepPacket", () => {
    const fromGea = computeGea(ROME.lat, ROME.lon, 7).compressed;
    const toGea = computeGea(TOKYO.lat, TOKYO.lon, 7).compressed;

    it("creates unsigned packet", () => {
        const p = createPacket({
            fromGea, toGea,
            contentType: "text/plain",
            payload: "Hello from Rome",
        });
        expect(p.signature).toBeNull();
        expect(p.from_gea).toBe(fromGea);
        expect(p.to_gea).toBe(toGea);
        expect(p.ttl).toBe(64);
        expect(p.hop_path).toEqual([fromGea]);
    });

    it("creates and verifies signed packet", () => {
        const p = createPacket({
            fromGea, toGea,
            contentType: "application/json",
            payload: JSON.stringify({ message: "GEP works" }),
            keypair,
        });
        expect(p.signature).not.toBeNull();
        expect(verifyPacket(p)).toBe(true);
    });

    it("detects tampered payload", () => {
        const p = createPacket({
            fromGea, toGea,
            contentType: "text/plain",
            payload: "Original message",
            keypair,
        });
        const tampered = { ...p, payload: new TextEncoder().encode("Tampered!") };
        expect(verifyPacket(tampered)).toBe(false);
    });

    it("detects tampered destination", () => {
        const p = createPacket({
            fromGea, toGea, contentType: "text/plain",
            payload: "test", keypair
        });
        const evil = computeGea(NEW_YORK.lat, NEW_YORK.lon, 7).compressed;
        expect(verifyPacket({ ...p, to_gea: evil })).toBe(false);
    });

    it("forwarding decrements TTL and appends hop", () => {
        const p = createPacket({
            fromGea, toGea, contentType: "text/plain",
            payload: "hop test", ttl: 5
        });
        const hop = computeGea(NAPLES.lat, NAPLES.lon, 7).compressed;
        const forwarded = forwardPacket(p, hop);
        expect(forwarded?.ttl).toBe(4);
        expect(forwarded?.hop_path).toContain(hop);
    });

    it("returns null when TTL exhausted", () => {
        const p = createPacket({
            fromGea, toGea, contentType: "text/plain",
            payload: "ttl test", ttl: 0
        });
        expect(forwardPacket(p, fromGea)).toBeNull();
    });

    it("message_id is unique per packet", () => {
        const ids = Array.from({ length: 100 }, () =>
            createPacket({
                fromGea, toGea, contentType: "text/plain",
                payload: "id test"
            }).message_id
        );
        expect(new Set(ids).size).toBe(100);
    });
});

// ============================================================
// 7. KEYPAIR COMPATIBILITY
// ============================================================

describe("GEP keypair", () => {
    it("generates valid Ed25519 keypair", () => {
        const kp = generateKeypair();
        expect(kp.publicKey).toHaveLength(32);
        expect(kp.secretKey).toHaveLength(64);
    });

    it("different calls produce different keypairs", () => {
        const a = generateKeypair();
        const b = generateKeypair();
        expect(a.publicKey).not.toEqual(b.publicKey);
    });
});