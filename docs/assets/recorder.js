// Pure, deterministic port of the custody packetizer's onTick loop
// (internal/custody/packetizer.go). Given a scenario run + MPF profile it returns
// the complete recorded session: packets, provenance faults, and Merkle
// segments. Because it is a pure function of (run, mpf, tamper), the live
// playback, the tamper test, and deterministic replay all derive from one
// source of truth.

import {
  canonicalPacketBytes,
  sha256Hex,
  packetBlake3,
  merkleRoot,
  simulatedTpmSig,
  bytesToHex,
} from "./chain.js";
import { blake3, utf8ToBytes } from "./hashes.bundle.js";
import { PolicyEngine, telemetryFromCustody } from "./policy.js";

const MAX_SILENT_TICKS = 10; // config.custody.max_silent_ticks
const BATCH_SIZE = 15;       // segment size (smaller than prod 60 so the demo shows several)
const QUOTE_INTERVAL = 20;   // ticks between TPM quotes
const BASE_TIME = Date.parse("2026-05-28T00:00:00Z");

function isActive(state) {
  return state === "printing" || state === "paused";
}

function deriveHex(seed, label, nbytes) {
  return bytesToHex(blake3(utf8ToBytes(label + ":" + seed))).slice(0, nbytes * 2);
}

// computeRun replays the scenario through the packetizer logic.
// tamper (optional): { atSeq, field, value } overrides one recorded packet's
// telemetry before hashing, so the caller can show the chain break.
export function computeRun(run, mpf, tamper = null) {
  const engine = new PolicyEngine();
  if (mpf) engine.loadProfile(mpf);

  const sessionID = deriveHex(run.seed, "session", 16);
  const packets = [];
  const faults = [];
  const segments = [];

  let cached = null;       // printer state cache (updated by deltas)
  let sessionStarted = false;
  let seq = 0;
  let prevHex = null;      // prev packet_blake3 as hex
  let prevBytes = null;    // prev packet_blake3 as bytes (for chain input)
  let silentTicks = 0;
  let lastQuoteTick = -1;
  const quoteSeqs = [];

  run.frames.forEach((frame, t) => {
    // applyDelta: a delta refreshes the cache and resets the silence counter.
    if (frame.deltaArrived) {
      cached = frame.state;
      silentTicks = 0;
    }
    if (!cached) return; // no state observed yet

    // onTick: only record during active prints.
    if (!isActive(cached.print_state)) return;

    if (!sessionStarted) {
      sessionStarted = true;
      seq = 0;
      prevHex = null;
      prevBytes = null;
      lastQuoteTick = -1;
    }

    // Silence / provenance fault accounting (REQ-5).
    silentTicks++;
    if (silentTicks > MAX_SILENT_TICKS) {
      faults.push({
        seq,
        reason: "printer telemetry silence exceeded threshold",
        silent_ticks: silentTicks,
        tick: new Date(BASE_TIME + t * 1000).toISOString(),
      });
      silentTicks = 0; // reset so we don't flood
    }

    // TPM quote on session start + on interval.
    let quoted = false;
    if (lastQuoteTick < 0 || t - lastQuoteTick >= QUOTE_INTERVAL) {
      quoted = true;
      lastQuoteTick = t;
      quoteSeqs.push(seq);
    }

    // Build the packet.
    const pkt = {
      session_id: sessionID,
      node_label: run.node_label,
      printer_id: run.printer_id,
      seq,
      tick: new Date(BASE_TIME + t * 1000).toISOString(),
      tick_mono_ns: t * 1_000_000_000,
      extruder_temp: cached.extruder_temp,
      extruder_target: cached.extruder_target,
      extruder_power: cached.extruder_power,
      bed_temp: cached.bed_temp,
      bed_target: cached.bed_target,
      bed_power: cached.bed_power,
      chamber_temp: cached.chamber_temp,
      chamber_present: cached.chamber_present,
      live_velocity: cached.live_velocity,
      live_extruder_velocity: cached.live_extruder_velocity,
      live_position: cached.live_position,
      print_state: cached.print_state,
      filament_used_mm: cached.filament_used_mm,
      print_duration_s: cached.print_duration_s,
      mcu_version: cached.mcu_version,
      mcu_build_versions: cached.mcu_build_versions,
      prev_packet_blake3: prevHex,
    };

    // Optional tamper: mutate this packet's telemetry before hashing.
    let tampered = false;
    if (tamper && tamper.atSeq === seq) {
      pkt[tamper.field] = tamper.value;
      tampered = true;
    }

    // Policy evaluation against the active MPF.
    const verdict = engine.evaluate(telemetryFromCustody(pkt));
    if (verdict.profile_id !== "null") pkt.decision = verdict;

    // Canonical bytes -> SHA-256 (the TPM-signed digest) -> simulated TPM sig.
    const canonical = canonicalPacketBytes(pkt);
    const sha = sha256Hex(canonical);
    const tpmSig = simulatedTpmSig(sha);

    // BLAKE3 chain link.
    const b3 = packetBlake3(seq, sessionID, canonical, tpmSig, prevBytes);
    const b3hex = bytesToHex(b3);

    packets.push({
      seq,
      tick: pkt.tick,
      print_state: pkt.print_state,
      telemetry: {
        extruder_temp: round3(pkt.extruder_temp),
        extruder_target: round3(pkt.extruder_target),
        bed_temp: round3(pkt.bed_temp),
        bed_target: round3(pkt.bed_target),
        chamber_temp: round3(pkt.chamber_temp),
        live_velocity: round3(pkt.live_velocity),
      },
      verdict,
      canonical: new TextDecoder().decode(canonical),
      packet_sha256: sha,
      tpm_sig: bytesToHex(tpmSig).slice(0, 32) + "…",
      tpm_sig_full: bytesToHex(tpmSig),
      prev_packet_blake3: prevHex,
      packet_blake3: b3hex,
      quoted,
      tampered,
      b3bytes: b3,
    });

    prevHex = b3hex;
    prevBytes = b3;
    seq++;
  });

  // Build Merkle segments over contiguous batches.
  for (let i = 0; i < packets.length; i += BATCH_SIZE) {
    const batch = packets.slice(i, i + BATCH_SIZE);
    const root = merkleRoot(batch.map((p) => p.b3bytes));
    segments.push({
      seq_start: batch[0].seq,
      seq_end: batch[batch.length - 1].seq,
      packet_count: batch.length,
      merkle_root: bytesToHex(root),
    });
  }

  return { sessionID, mpfId: mpf ? mpf.profile_id : "null", packets, faults, segments, quoteSeqs };
}

// diffRuns returns the first seq at which two runs' chain hashes diverge,
// plus the set of segment indices whose Merkle root changed.
export function diffRuns(base, tampered) {
  let firstDiverge = -1;
  for (let i = 0; i < base.packets.length; i++) {
    if (base.packets[i].packet_blake3 !== tampered.packets[i].packet_blake3) {
      firstDiverge = base.packets[i].seq;
      break;
    }
  }
  const changedSegments = [];
  for (let i = 0; i < base.segments.length; i++) {
    if (base.segments[i].merkle_root !== tampered.segments[i].merkle_root) {
      changedSegments.push(i);
    }
  }
  return { firstDiverge, changedSegments };
}

function round3(x) { return Math.round((x + Number.EPSILON) * 1000) / 1000; }
