// Deterministic printer simulation. A given (scenario, seed) always produces
// the identical frame sequence — and therefore the identical hash chain — which
// is what makes the "deterministic replay" claim demonstrable.
//
// Each frame carries the full machine state plus deltaArrived: when false, the
// custody clock still ticks (independent of the source) but the
// silence counter climbs, exactly as in internal/custody/packetizer.go.

const NODE_LABEL = "sfn-node-001";
const PRINTER_ID = "voron-2.4-001";
const MCU_VERSION = "v0.12.0-294-g7a3f1b2";
const MCU_BUILD = "gcc: 12.2.1 binutils: 2.40";

const EXTRUDER_TARGET = 240.0;
const BED_TARGET = 110.0;
const CHAMBER_MIN = 95.0;

// mulberry32 — tiny seedable PRNG for reproducible thermal noise.
function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function baseState() {
  return {
    print_state: "standby",
    extruder_temp: 24.0,
    extruder_target: 0.0,
    extruder_power: 0.0,
    bed_temp: 24.0,
    bed_target: 0.0,
    bed_power: 0.0,
    chamber_temp: 24.0,
    chamber_present: true,
    live_velocity: 0.0,
    live_extruder_velocity: 0.0,
    live_position: [0, 0, 0],
    filament_used_mm: 0.0,
    print_duration_s: 0.0,
    mcu_version: MCU_VERSION,
    mcu_build_versions: MCU_BUILD,
  };
}

const HEAT_TICKS = 8; // pre-print heating, shown but not recorded
const PRINT_TICKS = 60; // active printing
const TOTAL = HEAT_TICKS + PRINT_TICKS + 1; // +1 for the "complete" frame

export const SCENARIOS = {
  clean: {
    id: "clean",
    label: "Clean print",
    blurb: "Heat, print, complete. Unbroken BLAKE3 chain, every verdict PASS.",
  },
  thermal: {
    id: "thermal",
    label: "Thermal excursion",
    blurb: "Extruder sags 22°C below target mid-print. Grace absorbs 3 ticks, then the verdict flips to FAIL.",
  },
  provenance: {
    id: "provenance",
    label: "Provenance fault",
    blurb: "Printer telemetry goes silent for 12s. The custody clock keeps ticking and records a provenance fault — the REQ-5 guarantee.",
  },
};

// build returns the full deterministic frame list for a scenario.
export function build(scenarioId, seed = 0x5f3759df) {
  const rnd = mulberry32(seed ^ hashStr(scenarioId));
  const jitter = (amp) => (rnd() - 0.5) * 2 * amp;

  const frames = [];
  let filament = 0;
  let printT = 0;

  for (let t = 0; t < TOTAL; t++) {
    const s = baseState();
    s.node_label = NODE_LABEL;
    s.printer_id = PRINTER_ID;
    let deltaArrived = true;

    if (t < HEAT_TICKS) {
      // Heating ramp toward targets (not recorded — print not yet active).
      const frac = (t + 1) / HEAT_TICKS;
      s.print_state = "standby";
      s.extruder_target = EXTRUDER_TARGET;
      s.bed_target = BED_TARGET;
      s.extruder_temp = 24 + (EXTRUDER_TARGET - 24) * frac + jitter(1.5);
      s.bed_temp = 24 + (BED_TARGET - 24) * frac + jitter(0.8);
      s.chamber_temp = 24 + (CHAMBER_MIN + 2 - 24) * frac + jitter(0.5);
      s.extruder_power = 1.0;
      s.bed_power = 1.0;
    } else if (t < HEAT_TICKS + PRINT_TICKS) {
      // Active printing.
      printT++;
      const pt = t - HEAT_TICKS; // 0-based print tick
      s.print_state = "printing";
      s.extruder_target = EXTRUDER_TARGET;
      s.bed_target = BED_TARGET;
      s.extruder_temp = EXTRUDER_TARGET + jitter(1.2);
      s.bed_temp = BED_TARGET + jitter(0.6);
      s.chamber_temp = CHAMBER_MIN + 2 + jitter(0.7);
      s.extruder_power = 0.35 + jitter(0.05);
      s.bed_power = 0.5 + jitter(0.05);
      s.live_velocity = 80 + jitter(40);
      s.live_extruder_velocity = 3.2 + jitter(1.5);
      s.live_position = [
        round2(110 + 40 * Math.sin(pt / 4)),
        round2(110 + 40 * Math.cos(pt / 5)),
        round2(0.2 + pt * 0.05),
      ];
      filament += Math.max(0, s.live_extruder_velocity);
      printT += 1;

      // Scenario-specific fault injection during printing.
      if (scenarioId === "thermal" && pt >= 20 && pt < 26) {
        // Extruder sags well below the -5 envelope for 6 consecutive ticks.
        s.extruder_temp = EXTRUDER_TARGET - 22 + jitter(0.8);
        s.extruder_power = 1.0;
      }
      if (scenarioId === "provenance" && pt >= 20 && pt < 32) {
        // Source goes silent: no delta this tick. State is held stale by the
        // cache; the custody clock keeps recording and the gap counter climbs.
        deltaArrived = false;
      }

      s.print_duration_s = printT;
      s.filament_used_mm = round3(filament);
    } else {
      // Print complete.
      s.print_state = "complete";
      s.extruder_target = 0;
      s.bed_target = 0;
      s.extruder_temp = EXTRUDER_TARGET - 30 + jitter(2);
      s.bed_temp = BED_TARGET - 5 + jitter(1);
      s.chamber_temp = CHAMBER_MIN + jitter(0.5);
      s.filament_used_mm = round3(filament);
      s.print_duration_s = PRINT_TICKS;
    }

    frames.push({ state: s, deltaArrived });
  }

  return {
    scenarioId,
    seed,
    node_label: NODE_LABEL,
    printer_id: PRINTER_ID,
    heatTicks: HEAT_TICKS,
    frames,
  };
}

function hashStr(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}
function round2(x) { return Math.round(x * 100) / 100; }
function round3(x) { return Math.round(x * 1000) / 1000; }
