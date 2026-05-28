// Faithful JS port of internal/policy/engine.go.
//
// Same rule types (absolute_minimum, absolute_maximum, dynamic_offset), same
// grace-window semantics: a violation only escalates to a verdict failure once
// the consecutive AND total allowances are both exhausted; the consecutive
// counter resets on any passing custody tick. Null profile passes everything.

export class PolicyEngine {
  constructor() {
    this.profile = null;
    this.consecutive = {};
    this.total = {};
  }

  loadProfile(profile) {
    if (!profile || !profile.profile_id) throw new Error("profile_id required");
    this.profile = profile;
    this.consecutive = {};
    this.total = {};
  }

  clearProfile() {
    this.profile = null;
    this.consecutive = {};
    this.total = {};
  }

  // evaluate runs the active profile against a flat {field: value} map.
  evaluate(telemetry) {
    if (!this.profile) return { pass: true, profile_id: "null", violations: [] };

    const violations = [];
    for (const rule of this.profile.validation_rules) {
      const val = telemetry[rule.field];
      if (val === undefined) continue; // sensor absent — skip silently

      let violated = false;
      let reason = "";

      switch (rule.rule_type) {
        case "absolute_minimum":
          if (val < rule.min_value) {
            violated = true;
            reason = `${rule.field}=${fmt(val)} below minimum ${fmt(rule.min_value)}`;
          }
          break;
        case "absolute_maximum":
          if (val > rule.max_value) {
            violated = true;
            reason = `${rule.field}=${fmt(val)} above maximum ${fmt(rule.max_value)}`;
          }
          break;
        case "dynamic_offset": {
          const target = telemetry[rule.target_field];
          if (target === undefined) continue;
          const delta = val - target;
          const negDev = rule.max_negative_deviation || 0;
          const posDev = rule.max_positive_deviation || 0;
          if (delta < -negDev || delta > posDev) {
            violated = true;
            reason = `${rule.field} delta=${fmt(delta)} outside envelope [${fmt(-negDev)}, +${fmt(posDev)}] (target=${fmt(target)})`;
          }
          break;
        }
        default:
          continue;
      }

      if (violated) {
        this.consecutive[rule.field] = (this.consecutive[rule.field] || 0) + 1;
        this.total[rule.field] = (this.total[rule.field] || 0) + 1;
        const maxConsec = rule.allowed_consecutive_violation_epochs || 0;
        const maxTotal = rule.allowed_total_violation_epochs || 0;
        if (
          (maxConsec === 0 || this.consecutive[rule.field] > maxConsec) &&
          (maxTotal === 0 || this.total[rule.field] > maxTotal)
        ) {
          violations.push(reason);
        }
      } else {
        this.consecutive[rule.field] = 0;
      }
    }

    return {
      pass: violations.length === 0,
      profile_id: this.profile.profile_id,
      violations,
    };
  }
}

// telemetryFromCustody mirrors policy.TelemetryFromCustody — chamber key is only
// present when the sensor reported.
export function telemetryFromCustody(s) {
  const m = {
    "extruder.temperature": s.extruder_temp,
    "extruder.target": s.extruder_target,
    "extruder.power": s.extruder_power,
    "heater_bed.temperature": s.bed_temp,
    "heater_bed.target": s.bed_target,
    "heater_bed.power": s.bed_power,
    "motion_report.live_velocity": s.live_velocity,
    "motion_report.live_extruder_velocity": s.live_extruder_velocity,
  };
  if (s.chamber_present) m["temperature_sensor.chamber.temperature"] = s.chamber_temp;
  return m;
}

function fmt(x) {
  return (Math.round(x * 1000) / 1000).toFixed(3);
}
