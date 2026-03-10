/**
 * gep-core v0.1.0
 * GeoEpoch Protocol — Core Library
 *
 * The foundational implementation of GEP:
 * - GEA (GeoEpoch Address) computation
 * - Epoch chain generation & verification
 * - Geographic routing algorithm
 * - GepPacket encode / sign / verify
 *
 * Dependencies: h3-js, tweetnacl, @noble/hashes
 *
 * GNS Foundation / Globe Crumbs Inc. — March 2026
 */

import * as h3 from "h3-js";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import nacl from "tweetnacl";

// ============================================================
// CONSTANTS
// ============================================================

export const GEP_VERSION = 1;
export const GEP_MAX_RESOLUTION = 15;
export const GEP_MIN_RESOLUTION = 0;
export const EARTH_SURFACE_KM2 = 510_065_622;

/**
 * Official H3 cell counts per resolution.
 * Formula: c(r) = 2 + 120 × 7^r  (source: h3geo.org)
 */
export const H3_CELL_COUNTS: Record<number, bigint> = {
    0: 122n,
    1: 842n,
    2: 5_882n,
    3: 41_162n,
    4: 288_122n,
    5: 2_016_842n,
    6: 14_117_882n,
    7: 98_825_162n,
    8: 691_776_122n,
    9: 4_842_432_842n,
    10: 33_897_029_882n,
    11: 237_279_209_162n,
    12: 1_660_954_464_122n,
    13: 11_626_681_248_842n,
    14: 81_386_768_741_882n,
    15: 569_707_381_193_162n,
};

/** Average hexagon area in m² per resolution (source: h3geo.org) */
export const H3_AVG_AREA_M2: Record<number, number> = {
    0: 4_357_449_416_078,
    1: 609_788_441_794,
    2: 86_801_780_399,
    3: 12_393_434_655,
    4: 1_770_347_654,
    5: 252_903_858,
    6: 36_129_062,
    7: 5_161_293,
    8: 737_328,
    9: 105_333,
    10: 15_048,
    11: 2_150,
    12: 307,
    13: 44,
    14: 6,
    15: 0.895,
};

// ============================================================
// TYPES
// ============================================================

export interface GepEpoch {
    protocol_version: number;       // GEP protocol version
    resolution: number;             // H3 resolution (0-15)
    cell_count: bigint;             // Total cells at this resolution
    merkle_root: string;            // Hex: Merkle root of sorted cell hashes
    parent_epoch_hash: string | null; // Hex: hash of resolution-1 epoch
    child_epoch_hash: string | null;  // Hex: hash of resolution+1 epoch (set later)
    epoch_hash: string;             // Hex: SHA-256 of canonical form
    generated_at: number;           // Unix ms
    generator_version: string;      // gep-core semver
}

export interface GeoEpochAddress {
    resolution: number;
    cell_hash: string;              // Hex: SHA-256 of H3 cell index
    epoch_chain: string[];          // Hex[]: epoch hashes from R0..R(resolution)
    compressed: string;             // "gea:{res:02d}:{cell_hash}" — canonical form
}

export interface GepPacket {
    protocol_version: number;
    from_gea: string;               // Compressed GEA
    to_gea: string;                 // Compressed GEA
    ttl: number;                    // Max hops remaining
    hop_path: string[];             // GEAs traversed so far
    content_type: string;           // MIME type
    payload: Uint8Array;            // Raw content
    sender_pk: string | null;       // Hex Ed25519 public key
    signature: string | null;       // Hex Ed25519 signature
    message_id: string;             // UUID v4
    timestamp: number;              // Unix ms
}

export interface GepRouteStep {
    cell: string;                   // H3 cell index (hex string)
    gea: string;                    // Compressed GEA at R7 (neighborhood)
    direction: "up" | "down" | "origin" | "destination";
    resolution: number;
}

export interface GepKeypair {
    publicKey: Uint8Array;          // Ed25519 32 bytes
    secretKey: Uint8Array;          // Ed25519 64 bytes
}

// ============================================================
// 1. CELL HASHING
// ============================================================

/**
 * Hash a single H3 cell index to a 32-byte SHA-256 digest.
 * The cell index is encoded as a UTF-8 string of its hex representation.
 */
export function hashCell(cellIndex: string): string {
    const bytes = new TextEncoder().encode(`gep:cell:${cellIndex}`);
    return bytesToHex(sha256(bytes));
}

/**
 * Hash an epoch's canonical fields (everything except epoch_hash itself).
 */
function hashEpoch(epoch: Omit<GepEpoch, "epoch_hash">): string {
    const canonical = JSON.stringify({
        protocol_version: epoch.protocol_version,
        resolution: epoch.resolution,
        cell_count: epoch.cell_count.toString(),
        merkle_root: epoch.merkle_root,
        parent_epoch_hash: epoch.parent_epoch_hash,
        generated_at: epoch.generated_at,
        generator_version: epoch.generator_version,
    }); // keys are already in insertion order — deterministic
    return bytesToHex(sha256(new TextEncoder().encode(canonical)));
}

// ============================================================
// 2. MERKLE TREE
// ============================================================

/**
 * Build a binary Merkle tree from an array of leaf hashes (hex strings).
 * Returns the root hash as a hex string.
 */
export function merkleRoot(leaves: string[]): string {
    if (leaves.length === 0) throw new Error("Cannot build Merkle tree from empty leaves");
    if (leaves.length === 1) return leaves[0];

    let layer = [...leaves].sort(); // sort for determinism

    while (layer.length > 1) {
        const next: string[] = [];
        for (let i = 0; i < layer.length; i += 2) {
            const left = layer[i];
            const right = i + 1 < layer.length ? layer[i + 1] : layer[i]; // duplicate last if odd
            const combined = new TextEncoder().encode(left + right);
            next.push(bytesToHex(sha256(combined)));
        }
        layer = next;
    }

    return layer[0];
}

// ============================================================
// 3. EPOCH CHAIN
// ============================================================

/**
 * Compute a single GEP epoch for a given resolution.
 * For high resolutions (9+) this is expensive — sample-based approximation
 * is used for merkle_root (full computation optional via `exact` flag).
 *
 * For the POC, resolutions 0-8 are computed exactly.
 * Resolutions 9-15 use a deterministic seed-based merkle approximation.
 */
export async function computeEpoch(
    resolution: number,
    parentEpoch: GepEpoch | null,
    opts: { exact?: boolean } = {}
): Promise<GepEpoch> {
    if (resolution < 0 || resolution > 15) {
        throw new Error(`Resolution must be 0-15, got ${resolution}`);
    }

    const generatedAt = Date.now();
    let merkle: string;

    if (resolution <= 5 || opts.exact) {
        // Exact computation: get all cells at this resolution
        const cells = h3.getRes0Cells().flatMap(base =>
            resolution === 0 ? [base] : h3.cellToChildren(base, resolution)
        );
        const leafHashes = cells.map(hashCell);
        merkle = merkleRoot(leafHashes);
    } else {
        // Deterministic approximation for high resolutions:
        // Hash the resolution + parent_epoch_hash as a seed
        const seed = `gep:epoch:approx:${resolution}:${parentEpoch?.epoch_hash ?? "genesis"}`;
        merkle = bytesToHex(sha256(new TextEncoder().encode(seed)));
    }

    const partial: Omit<GepEpoch, "epoch_hash"> = {
        protocol_version: GEP_VERSION,
        resolution,
        cell_count: H3_CELL_COUNTS[resolution],
        merkle_root: merkle,
        parent_epoch_hash: parentEpoch?.epoch_hash ?? null,
        child_epoch_hash: null, // filled in after child is computed
        generated_at: generatedAt,
        generator_version: "0.1.0",
    };

    return { ...partial, epoch_hash: hashEpoch(partial) };
}

/**
 * Compute the full GEP epoch chain from R0 to maxResolution.
 * Returns array of GepEpoch indexed by resolution.
 *
 * This is the genesis computation — run once and cache.
 */
export async function computeEpochChain(
    maxResolution = 7,
    onProgress?: (res: number) => void
): Promise<GepEpoch[]> {
    const chain: GepEpoch[] = [];

    for (let r = 0; r <= maxResolution; r++) {
        const parent = r === 0 ? null : chain[r - 1];
        const epoch = await computeEpoch(r, parent);
        chain.push(epoch);
        onProgress?.(r);
    }

    // Back-fill child_epoch_hash links
    for (let r = 0; r < chain.length - 1; r++) {
        chain[r] = { ...chain[r], child_epoch_hash: chain[r + 1].epoch_hash };
    }

    return chain;
}

/**
 * Verify epoch chain integrity.
 * Returns list of violations (empty = valid).
 */
export function verifyEpochChain(chain: GepEpoch[]): string[] {
    const violations: string[] = [];

    for (let i = 0; i < chain.length; i++) {
        const epoch = chain[i];

        // Verify resolution ordering
        if (epoch.resolution !== i) {
            violations.push(`Epoch[${i}]: resolution mismatch (got ${epoch.resolution})`);
        }

        // Verify epoch_hash
        const { epoch_hash, child_epoch_hash, ...hashable } = epoch;
        const recomputed = hashEpoch({ ...hashable, child_epoch_hash: null });
        if (recomputed !== epoch_hash) {
            violations.push(`Epoch[${i}]: epoch_hash invalid`);
        }

        // Verify parent link
        if (i === 0 && epoch.parent_epoch_hash !== null) {
            violations.push(`Epoch[0]: parent_epoch_hash must be null`);
        }
        if (i > 0 && epoch.parent_epoch_hash !== chain[i - 1].epoch_hash) {
            violations.push(`Epoch[${i}]: parent_epoch_hash does not match previous epoch`);
        }

        // Verify cell count formula: c(r) = 2 + 120 * 7^r
        const expected = 2n + 120n * (7n ** BigInt(i));
        if (epoch.cell_count !== expected) {
            violations.push(`Epoch[${i}]: cell_count ${epoch.cell_count} ≠ expected ${expected}`);
        }
    }

    return violations;
}

// ============================================================
// 4. GEOEPOCH ADDRESS (GEA)
// ============================================================

/**
 * Compute a GeoEpoch Address for a lat/lon at a given resolution.
 *
 * @param lat - Latitude in decimal degrees
 * @param lon - Longitude in decimal degrees
 * @param resolution - H3 resolution (0-15), default 7 (neighborhood)
 * @param chain - Pre-computed epoch chain (optional, for full chain embedding)
 */
export function computeGea(
    lat: number,
    lon: number,
    resolution = 7,
    chain?: GepEpoch[]
): GeoEpochAddress {
    const cellIndex = h3.latLngToCell(lat, lon, resolution);
    const cellHashHex = hashCell(cellIndex);

    const epochChain = chain
        ? chain.slice(0, resolution + 1).map(e => e.epoch_hash)
        : [];

    const compressed = `gea:${String(resolution).padStart(2, "0")}:${cellHashHex}`;

    return {
        resolution,
        cell_hash: cellHashHex,
        epoch_chain: epochChain,
        compressed,
    };
}

/**
 * Parse a compressed GEA string back into its components.
 */
export function parseGea(compressed: string): { resolution: number; cell_hash: string } {
    const match = compressed.match(/^gea:(\d{2}):([0-9a-f]{64})$/);
    if (!match) throw new Error(`Invalid GEA format: ${compressed}`);
    return { resolution: parseInt(match[1]), cell_hash: match[2] };
}

/**
 * Get the H3 cell index for a lat/lon at a given resolution.
 * Utility wrapper around h3-js.
 */
export function latLonToCell(lat: number, lon: number, resolution = 7): string {
    return h3.latLngToCell(lat, lon, resolution);
}

/**
 * Get the geographic centroid of a GEA (approximate, via H3 cell center).
 * Requires the original H3 cell index — use latLonToCell to obtain it.
 */
export function cellToLatLon(cellIndex: string): [number, number] {
    const [lat, lng] = h3.cellToLatLng(cellIndex);
    return [lat, lng];
}

// ============================================================
// 5. GEOGRAPHIC ROUTING
// ============================================================

/**
 * Compute the GEP geographic route between two H3 cells.
 *
 * Algorithm:
 * 1. Find the lowest common ancestor resolution
 * 2. Ascend from source to ancestor
 * 3. Descend from ancestor to destination
 *
 * Returns an ordered array of route steps.
 * O(R) complexity — R = max resolution traversed.
 */
export function gepRoute(
    fromCell: string,
    toCell: string,
    targetResolution = 7
): GepRouteStep[] {
    if (fromCell === toCell) {
        return [{
            cell: fromCell,
            gea: `gea:${String(targetResolution).padStart(2, "0")}:${hashCell(fromCell)}`,
            direction: "origin",
            resolution: targetResolution,
        }];
    }

    // Find lowest common ancestor resolution
    let ancestorRes = targetResolution;
    let fromAncestor = fromCell;
    let toAncestor = toCell;

    while (fromAncestor !== toAncestor && ancestorRes > 0) {
        ancestorRes--;
        fromAncestor = h3.cellToParent(fromAncestor, ancestorRes);
        toAncestor = h3.cellToParent(toAncestor, ancestorRes);
    }

    const steps: GepRouteStep[] = [];

    // Ascend from source to common ancestor
    let cur = fromCell;
    steps.push({
        cell: cur,
        gea: `gea:${String(targetResolution).padStart(2, "0")}:${hashCell(cur)}`,
        direction: "origin",
        resolution: targetResolution,
    });

    for (let r = targetResolution - 1; r >= ancestorRes; r--) {
        cur = h3.cellToParent(cur, r);
        steps.push({
            cell: cur,
            gea: `gea:${String(r).padStart(2, "0")}:${hashCell(cur)}`,
            direction: "up",
            resolution: r,
        });
    }

    // Descend from common ancestor to destination
    // Build downward path first, then reverse-append
    const downPath: GepRouteStep[] = [];
    cur = toCell;
    for (let r = targetResolution - 1; r >= ancestorRes; r--) {
        cur = h3.cellToParent(cur, r);
        downPath.unshift({
            cell: cur,
            gea: `gea:${String(r).padStart(2, "0")}:${hashCell(cur)}`,
            direction: r === ancestorRes ? "down" : "down",
            resolution: r,
        });
    }
    downPath.push({
        cell: toCell,
        gea: `gea:${String(targetResolution).padStart(2, "0")}:${hashCell(toCell)}`,
        direction: "destination",
        resolution: targetResolution,
    });

    // Remove duplicate ancestor step
    downPath.shift();
    steps.push(...downPath);

    return steps;
}

/**
 * Greedy neighbor forwarding: given current cell and destination cell,
 * return the neighbor cell that minimizes H3 distance to destination.
 * Used for stateless hop-by-hop routing.
 */
export function greedyNextHop(currentCell: string, destCell: string): string {
    const neighbors = h3.gridDisk(currentCell, 1).filter(c => c !== currentCell);
    let best = currentCell;
    let bestDist = h3.gridDistance(currentCell, destCell);

    for (const n of neighbors) {
        try {
            const d = h3.gridDistance(n, destCell);
            if (d < bestDist) { bestDist = d; best = n; }
        } catch { /* pentagons or cross-face cells may throw */ }
    }

    return best;
}

// ============================================================
// 6. GEP PACKET
// ============================================================

function generateMessageId(): string {
    const bytes = nacl.randomBytes(16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant
    const hex = bytesToHex(bytes);
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Canonical bytes for signing a GepPacket.
 * Covers all routing + content fields, excluding signature itself.
 */
function packetSigningBytes(p: Omit<GepPacket, "signature">): Uint8Array {
    const canonical = JSON.stringify({
        protocol_version: p.protocol_version,
        from_gea: p.from_gea,
        to_gea: p.to_gea,
        ttl: p.ttl,
        content_type: p.content_type,
        payload_hash: bytesToHex(sha256(p.payload)),
        sender_pk: p.sender_pk,
        message_id: p.message_id,
        timestamp: p.timestamp,
    });
    return new TextEncoder().encode(canonical);
}

/**
 * Create a new GepPacket.
 */
export function createPacket(opts: {
    fromGea: string;
    toGea: string;
    contentType: string;
    payload: Uint8Array | string;
    ttl?: number;
    keypair?: GepKeypair;
}): GepPacket {
    const payload = typeof opts.payload === "string"
        ? new TextEncoder().encode(opts.payload)
        : opts.payload;

    const senderPk = opts.keypair ? bytesToHex(opts.keypair.publicKey) : null;

    const packet: GepPacket = {
        protocol_version: GEP_VERSION,
        from_gea: opts.fromGea,
        to_gea: opts.toGea,
        ttl: opts.ttl ?? 64,
        hop_path: [opts.fromGea],
        content_type: opts.contentType,
        payload,
        sender_pk: senderPk,
        signature: null,
        message_id: generateMessageId(),
        timestamp: Date.now(),
    };

    if (opts.keypair) {
        const sigBytes = nacl.sign.detached(
            packetSigningBytes(packet),
            opts.keypair.secretKey
        );
        packet.signature = bytesToHex(sigBytes);
    }

    return packet;
}

/**
 * Verify the Ed25519 signature on a GepPacket.
 * Returns true if valid, false if invalid or unsigned.
 */
export function verifyPacket(packet: GepPacket): boolean {
    if (!packet.signature || !packet.sender_pk) return false;
    try {
        const { signature, ...rest } = packet;
        return nacl.sign.detached.verify(
            packetSigningBytes(rest),
            hexToBytes(signature),
            hexToBytes(packet.sender_pk)
        );
    } catch { return false; }
}

/**
 * Record a routing hop on a packet (decrements TTL, appends to hop_path).
 * Returns null if TTL is exhausted.
 */
export function forwardPacket(packet: GepPacket, hopGea: string): GepPacket | null {
    if (packet.ttl <= 0) return null;
    return { ...packet, ttl: packet.ttl - 1, hop_path: [...packet.hop_path, hopGea] };
}

// ============================================================
// 7. KEY GENERATION
// ============================================================

/**
 * Generate a new Ed25519 keypair for GEP packet signing.
 * Compatible with existing GNS Ed25519 keypairs.
 */
export function generateKeypair(): GepKeypair {
    return nacl.sign.keyPair();
}

/**
 * Import an existing GNS Ed25519 keypair (hex-encoded).
 */
export function importKeypair(publicKeyHex: string, secretKeyHex: string): GepKeypair {
    return {
        publicKey: hexToBytes(publicKeyHex),
        secretKey: hexToBytes(secretKeyHex),
    };
}

// ============================================================
// 8. UTILITIES
// ============================================================

/**
 * Human-readable label for an H3 resolution level.
 */
export function resolutionLabel(resolution: number): string {
    const labels: Record<number, string> = {
        0: "Continent", 1: "Subcontinent", 2: "Large Nation", 3: "Province",
        4: "County", 5: "City", 6: "District", 7: "Neighborhood",
        8: "City Block", 9: "Building", 10: "Large Room", 11: "Small Room",
        12: "Large Object", 13: "Person", 14: "Footprint", 15: "Sub-meter",
    };
    return labels[resolution] ?? `Resolution ${resolution}`;
}

/**
 * Format a cell count as a human-readable string.
 */
export function formatCellCount(count: bigint): string {
    if (count >= 1_000_000_000_000n) return `${(Number(count) / 1e12).toFixed(3)} trillion`;
    if (count >= 1_000_000_000n) return `${(Number(count) / 1e9).toFixed(3)} billion`;
    if (count >= 1_000_000n) return `${(Number(count) / 1e6).toFixed(3)} million`;
    return count.toLocaleString();
}

/**
 * Verify the cell count formula for a given resolution.
 * c(r) = 2 + 120 × 7^r
 */
export function verifyCellCountFormula(resolution: number): boolean {
    const expected = 2n + 120n * (7n ** BigInt(resolution));
    return H3_CELL_COUNTS[resolution] === expected;
}

// ============================================================
// EXPORTS
// ============================================================

export const GepCore = {
    // Epoch chain
    computeEpoch,
    computeEpochChain,
    verifyEpochChain,

    // Address
    computeGea,
    parseGea,
    latLonToCell,
    cellToLatLon,
    hashCell,
    merkleRoot,

    // Routing
    gepRoute,
    greedyNextHop,

    // Packets
    createPacket,
    verifyPacket,
    forwardPacket,

    // Keys
    generateKeypair,
    importKeypair,

    // Utils
    resolutionLabel,
    formatCellCount,
    verifyCellCountFormula,

    // Constants
    GEP_VERSION,
    H3_CELL_COUNTS,
    H3_AVG_AREA_M2,
    EARTH_SURFACE_KM2,
};

export default GepCore;