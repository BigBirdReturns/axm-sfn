// Faithful JS port of the axm-sfn cryptographic chain constructions.
//
// Every hash here uses the SAME algorithm and domain-separation bytes as the
// Go daemon. Cross-references:
//   - computePacketBLAKE3  -> internal/custody/packetizer.go
//   - computeMerkleRoot    -> internal/uploader/uploader.go
//   - canonical packet     -> internal/telemetry/packet.go (CustodyPacket json tags)
//
// The empty Merkle root BLAKE3(0x01) is asserted against the Go test vector
// in internal/uploader/merkle_test.go: 48fc721f...188652b.

import { blake3, sha256, bytesToHex, utf8ToBytes } from "./hashes.bundle.js";

export { bytesToHex };

const enc = new TextEncoder();

// uint64 little-endian, matching binary.LittleEndian.PutUint64.
function u64le(n) {
  const b = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

function concat(...parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// canonicalPacketBytes serializes the pre-hash CustodyPacket fields in the exact
// struct field order from internal/telemetry/packet.go, honoring the same
// omitempty rules. This is the byte payload that gets SHA-256'd and folded into
// the BLAKE3 chain link.
export function canonicalPacketBytes(pkt) {
  // Stable, ordered key/value pairs. Mirrors Go struct json tags + order.
  const parts = [];
  const add = (k, v) => parts.push(JSON.stringify(k) + ":" + JSON.stringify(v));

  add("session_id", pkt.session_id);
  add("node_label", pkt.node_label);
  add("printer_id", pkt.printer_id);
  add("seq", pkt.seq);
  add("tick", pkt.tick);
  add("tick_mono_ns", pkt.tick_mono_ns);
  add("extruder_temp", round3(pkt.extruder_temp));
  add("extruder_target", round3(pkt.extruder_target));
  add("extruder_power", round3(pkt.extruder_power));
  add("bed_temp", round3(pkt.bed_temp));
  add("bed_target", round3(pkt.bed_target));
  add("bed_power", round3(pkt.bed_power));
  if (pkt.chamber_present) {
    add("chamber_temp", round3(pkt.chamber_temp));
    add("chamber_present", true);
  }
  add("live_velocity", round3(pkt.live_velocity));
  add("live_extruder_velocity", round3(pkt.live_extruder_velocity));
  add("live_position", pkt.live_position);
  add("print_state", pkt.print_state);
  add("filament_used_mm", round3(pkt.filament_used_mm));
  add("print_duration_s", round3(pkt.print_duration_s));
  add("mcu_version", pkt.mcu_version);
  add("mcu_build_versions", pkt.mcu_build_versions);
  if (pkt.decision) add("decision", pkt.decision);
  if (pkt.prev_packet_blake3) add("prev_packet_blake3", pkt.prev_packet_blake3);

  return enc.encode("{" + parts.join(",") + "}");
}

function round3(x) {
  return Math.round((x + Number.EPSILON) * 1000) / 1000;
}

// sha256Hex returns the SHA-256 of the canonical payload (the digest the TPM
// would sign). Matches sha256.Sum256(canonical) in the Go hot path.
export function sha256Hex(canonicalBytes) {
  return bytesToHex(sha256(canonicalBytes));
}

// packetBlake3 reproduces computePacketBLAKE3:
//   BLAKE3( 0x00 || seq_le8 || session_id || canonical || tpm_sig? || prev_hash? )
// 0x00 is the AXM Genesis leaf domain byte. tpm_sig and prev_hash are appended
// only when present (software-only mode omits tpm_sig, seq 0 omits prev_hash).
export function packetBlake3(seq, sessionID, canonicalBytes, tpmSigBytes, prevHashBytes) {
  const parts = [
    new Uint8Array([0x00]),
    u64le(seq),
    utf8ToBytes(sessionID),
    canonicalBytes,
  ];
  if (tpmSigBytes) parts.push(tpmSigBytes);
  if (prevHashBytes) parts.push(prevHashBytes);
  return blake3(concat(...parts));
}

// ── Merkle root (AXM Genesis convention, mirrors uploader.computeMerkleRoot) ──
//   Leaf:  BLAKE3( 0x00 || index_le8 || 0x00 || packet_blake3 )
//   Node:  BLAKE3( 0x01 || left || right )
//   Odd:   promote last element unchanged (RFC 6962)
//   Empty: BLAKE3( 0x01 )
export function merkleRoot(packetHashes) {
  if (packetHashes.length === 0) {
    return blake3(new Uint8Array([0x01]));
  }
  let level = packetHashes.map((h, i) =>
    blake3(concat(new Uint8Array([0x00]), u64le(i), new Uint8Array([0x00]), h))
  );
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i + 1 < level.length; i += 2) {
      next.push(blake3(concat(new Uint8Array([0x01]), level[i], level[i + 1])));
    }
    if (level.length % 2 === 1) next.push(level[level.length - 1]);
    level = next;
  }
  return level[0];
}

// simulatedTpmSig generates a deterministic stand-in for a TPM2_Sign RSA-PSS
// signature so the demo can show the per-packet hardware-attestation field.
// On a provisioned node this comes from the TPM 2.0 chip over the SHA-256
// digest; here it is derived deterministically and clearly labeled as such.
export function simulatedTpmSig(sha256hex) {
  return blake3(utf8ToBytes("SIM-TPM2-RSAPSS:" + sha256hex));
}
