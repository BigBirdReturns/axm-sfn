// Package policy implements the Material-Process Profile evaluator.
//
// The evaluator runs each 1Hz custody tick against a set of validation rules
// defined in the active MPF (Material-Process Profile). Rules map
// telemetry field names to mathematical envelopes (absolute thresholds,
// dynamic offsets from a target field).
//
// If no profile is loaded, Evaluate returns a passing decision — the null
// policy passes everything. This preserves daemon operation on nodes that
// haven't been assigned an MPF yet.
//
// Design: flat float map. The packetizer extracts the fields it knows about
// into a map[string]float64 before calling Evaluate. No JSON Pointer parsing
// in the hot path; the mapping happens once per tick at the struct level.
package policy

import (
	"encoding/json"
	"fmt"
	"log/slog"
)

// Profile is a versioned Material-Process Profile. It defines the validation
// rules the daemon enforces at 1Hz during a print session.
//
// Profile JSON schema version: mpf-v1
type Profile struct {
	ProfileID                  string           `json:"profile_id"`
	MaterialCooldownAllowanceS int              `json:"material_cooldown_allowance_s,omitempty"`
	ValidationRules            []ValidationRule `json:"validation_rules"`
}

// ValidationRule maps a telemetry field to an evaluation envelope.
// RuleType values:
//   - "absolute_minimum": value must be >= MinValue
//   - "absolute_maximum": value must be <= MaxValue
//   - "dynamic_offset":   value must be within [target+MaxNegDev, target+MaxPosDev]
//     where target is read from TargetField in the same telemetry map
type ValidationRule struct {
	Field                        string  `json:"field"`                  // key in the flat telemetry map
	TargetField                  string  `json:"target_field,omitempty"` // for dynamic_offset
	RuleType                     string  `json:"rule_type"`              // see above
	MinValue                     float64 `json:"min_value,omitempty"`
	MaxValue                     float64 `json:"max_value,omitempty"`
	MaxNegativeDev               float64 `json:"max_negative_deviation,omitempty"`
	MaxPositiveDev               float64 `json:"max_positive_deviation,omitempty"`
	AllowedConsecutiveViolations int     `json:"allowed_consecutive_violation_epochs,omitempty"`
	AllowedTotalViolations       int     `json:"allowed_total_violation_epochs,omitempty"`
}

// Decision is the per-tick policy result.
type Decision struct {
	Pass       bool     `json:"pass"`
	ProfileID  string   `json:"profile_id"`
	Violations []string `json:"violations,omitempty"`
}

// Evaluator evaluates custody ticks against a loaded Profile.
type Evaluator struct {
	profile     *Profile
	consecutive map[string]int // consecutive violation counts per rule field
	total       map[string]int // total violation counts per rule field
	log         *slog.Logger
}

// NewEvaluator creates an Evaluator with no active profile (null policy).
func NewEvaluator(log *slog.Logger) *Evaluator {
	return &Evaluator{
		consecutive: make(map[string]int),
		total:       make(map[string]int),
		log:         log,
	}
}

// LoadProfile replaces the active profile and resets all violation counters.
// profileJSON must be a valid MPF JSON document.
func (e *Evaluator) LoadProfile(profileJSON []byte) error {
	var p Profile
	if err := json.Unmarshal(profileJSON, &p); err != nil {
		return fmt.Errorf("policy: parse profile: %w", err)
	}
	if p.ProfileID == "" {
		return fmt.Errorf("policy: profile_id is required")
	}
	e.profile = &p
	e.consecutive = make(map[string]int)
	e.total = make(map[string]int)
	e.log.Info("policy: profile loaded", "profile_id", p.ProfileID, "rules", len(p.ValidationRules))
	return nil
}

// ClearProfile unloads the active profile (null policy — all custody ticks pass).
func (e *Evaluator) ClearProfile() {
	e.profile = nil
	e.consecutive = make(map[string]int)
	e.total = make(map[string]int)
}

// Evaluate runs the active profile against the flat telemetry snapshot.
// telemetry is a map[string]float64 with keys matching ValidationRule.Field.
// If no profile is loaded, returns a passing decision.
func (e *Evaluator) Evaluate(telemetry map[string]float64) Decision {
	if e.profile == nil {
		return Decision{Pass: true, ProfileID: "null"}
	}

	var violations []string

	for _, rule := range e.profile.ValidationRules {
		val, ok := telemetry[rule.Field]
		if !ok {
			// Field absent — skip silently (sensor may not be installed)
			continue
		}

		violated := false
		var reason string

		switch rule.RuleType {
		case "absolute_minimum":
			if val < rule.MinValue {
				violated = true
				reason = fmt.Sprintf("%s=%.3f below minimum %.3f", rule.Field, val, rule.MinValue)
			}

		case "absolute_maximum":
			if val > rule.MaxValue {
				violated = true
				reason = fmt.Sprintf("%s=%.3f above maximum %.3f", rule.Field, val, rule.MaxValue)
			}

		case "dynamic_offset":
			target, targetOK := telemetry[rule.TargetField]
			if !targetOK {
				continue // target field absent — skip
			}
			delta := val - target
			if delta < -rule.MaxNegativeDev || delta > rule.MaxPositiveDev {
				violated = true
				reason = fmt.Sprintf("%s delta=%.3f outside envelope [%.3f, +%.3f] (target=%.3f)",
					rule.Field, delta, -rule.MaxNegativeDev, rule.MaxPositiveDev, target)
			}

		default:
			e.log.Warn("policy: unknown rule type", "rule_type", rule.RuleType, "field", rule.Field)
			continue
		}

		if violated {
			e.consecutive[rule.Field]++
			e.total[rule.Field]++

			// Only escalate to a verdict violation if grace epochs exhausted.
			maxConsec := rule.AllowedConsecutiveViolations
			maxTotal := rule.AllowedTotalViolations
			if (maxConsec == 0 || e.consecutive[rule.Field] > maxConsec) &&
				(maxTotal == 0 || e.total[rule.Field] > maxTotal) {
				violations = append(violations, reason)
			}
		} else {
			e.consecutive[rule.Field] = 0 // reset consecutive counter on pass
		}
	}

	return Decision{
		Pass:       len(violations) == 0,
		ProfileID:  e.profile.ProfileID,
		Violations: violations,
	}
}

// TelemetryFromCustody extracts the flat float map from the fields the
// packetizer captures. Add fields here as new sensors are supported.
// chamberTemp is only included in the map if chamberPresent is true.
func TelemetryFromCustody(
	extruderTemp, extruderTarget, extruderPower float64,
	bedTemp, bedTarget, bedPower float64,
	liveVelocity, liveExtruderVelocity float64,
	chamberTemp float64, chamberPresent bool,
) map[string]float64 {
	m := map[string]float64{
		"extruder.temperature":                 extruderTemp,
		"extruder.target":                      extruderTarget,
		"extruder.power":                       extruderPower,
		"heater_bed.temperature":               bedTemp,
		"heater_bed.target":                    bedTarget,
		"heater_bed.power":                     bedPower,
		"motion_report.live_velocity":          liveVelocity,
		"motion_report.live_extruder_velocity": liveExtruderVelocity,
	}
	if chamberPresent {
		m["temperature_sensor.chamber.temperature"] = chamberTemp
	}
	return m
}
