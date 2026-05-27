package policy_test

import (
	"log/slog"
	"os"
	"testing"

	"github.com/bigbirdreturns/axm-sfn/internal/policy"
)

var testLog = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

func TestNullPolicyPassesEverything(t *testing.T) {
	e := policy.NewEngine(testLog)
	telemetry := map[string]float64{
		"extruder.temperature": 400.0, // wildly out of range
		"extruder.target":      200.0,
	}
	v := e.Evaluate(telemetry)
	if !v.Pass {
		t.Fatalf("null policy should pass everything, got violations: %v", v.Violations)
	}
	if v.ProfileID != "null" {
		t.Fatalf("expected profile_id=null, got %q", v.ProfileID)
	}
}

func TestDynamicOffsetPass(t *testing.T) {
	e := policy.NewEngine(testLog)
	profile := []byte(`{
		"profile_id": "test-v1",
		"validation_rules": [{
			"field": "extruder.temperature",
			"target_field": "extruder.target",
			"rule_type": "dynamic_offset",
			"max_negative_deviation": 5.0,
			"max_positive_deviation": 10.0
		}]
	}`)
	if err := e.LoadProfile(profile); err != nil {
		t.Fatal(err)
	}

	// Within envelope: target=240, actual=238 → delta=-2, within [-5, +10]
	v := e.Evaluate(map[string]float64{
		"extruder.temperature": 238.0,
		"extruder.target":      240.0,
	})
	if !v.Pass {
		t.Fatalf("expected pass, got violations: %v", v.Violations)
	}
}

func TestDynamicOffsetFail(t *testing.T) {
	e := policy.NewEngine(testLog)
	profile := []byte(`{
		"profile_id": "test-v1",
		"validation_rules": [{
			"field": "extruder.temperature",
			"target_field": "extruder.target",
			"rule_type": "dynamic_offset",
			"max_negative_deviation": 5.0,
			"max_positive_deviation": 10.0,
			"allowed_consecutive_violation_epochs": 0
		}]
	}`)
	if err := e.LoadProfile(profile); err != nil {
		t.Fatal(err)
	}

	// Outside envelope: target=240, actual=230 → delta=-10, below -5
	v := e.Evaluate(map[string]float64{
		"extruder.temperature": 230.0,
		"extruder.target":      240.0,
	})
	if v.Pass {
		t.Fatal("expected fail for out-of-envelope extruder temp")
	}
	if len(v.Violations) == 0 {
		t.Fatal("expected at least one violation")
	}
}

func TestAbsoluteMinimumPass(t *testing.T) {
	e := policy.NewEngine(testLog)
	profile := []byte(`{
		"profile_id": "test-v1",
		"validation_rules": [{
			"field": "temperature_sensor.chamber.temperature",
			"rule_type": "absolute_minimum",
			"min_value": 90.0
		}]
	}`)
	if err := e.LoadProfile(profile); err != nil {
		t.Fatal(err)
	}

	v := e.Evaluate(map[string]float64{
		"temperature_sensor.chamber.temperature": 95.0,
	})
	if !v.Pass {
		t.Fatalf("expected pass at 95°C with min 90°C, got: %v", v.Violations)
	}
}

func TestAbsoluteMinimumFail(t *testing.T) {
	e := policy.NewEngine(testLog)
	profile := []byte(`{
		"profile_id": "test-v1",
		"validation_rules": [{
			"field": "temperature_sensor.chamber.temperature",
			"rule_type": "absolute_minimum",
			"min_value": 90.0,
			"allowed_total_violation_epochs": 0
		}]
	}`)
	if err := e.LoadProfile(profile); err != nil {
		t.Fatal(err)
	}

	v := e.Evaluate(map[string]float64{
		"temperature_sensor.chamber.temperature": 85.0,
	})
	if v.Pass {
		t.Fatal("expected fail at 85°C with min 90°C")
	}
}

func TestAbsentFieldSkippedSilently(t *testing.T) {
	e := policy.NewEngine(testLog)
	profile := []byte(`{
		"profile_id": "test-v1",
		"validation_rules": [{
			"field": "temperature_sensor.chamber.temperature",
			"rule_type": "absolute_minimum",
			"min_value": 90.0
		}]
	}`)
	if err := e.LoadProfile(profile); err != nil {
		t.Fatal(err)
	}

	// No chamber field in telemetry — sensor absent. Should pass silently.
	v := e.Evaluate(map[string]float64{
		"extruder.temperature": 240.0,
	})
	if !v.Pass {
		t.Fatalf("absent sensor field should pass silently, got: %v", v.Violations)
	}
}

func TestConsecutiveViolationGrace(t *testing.T) {
	e := policy.NewEngine(testLog)
	profile := []byte(`{
		"profile_id": "test-v1",
		"validation_rules": [{
			"field": "extruder.temperature",
			"target_field": "extruder.target",
			"rule_type": "dynamic_offset",
			"max_negative_deviation": 5.0,
			"max_positive_deviation": 10.0,
			"allowed_consecutive_violation_epochs": 3
		}]
	}`)
	if err := e.LoadProfile(profile); err != nil {
		t.Fatal(err)
	}

	badTelemetry := map[string]float64{
		"extruder.temperature": 220.0, // -20 from target — bad
		"extruder.target":      240.0,
	}

	// Epochs 1-3: within grace window, should pass
	for i := 1; i <= 3; i++ {
		v := e.Evaluate(badTelemetry)
		if !v.Pass {
			t.Fatalf("epoch %d: expected grace pass, got violations: %v", i, v.Violations)
		}
	}

	// Epoch 4: grace exhausted, should fail
	v := e.Evaluate(badTelemetry)
	if v.Pass {
		t.Fatal("epoch 4: expected fail after grace exhausted")
	}
}

func TestClearProfileRestoresNullPolicy(t *testing.T) {
	e := policy.NewEngine(testLog)
	profile := []byte(`{
		"profile_id": "test-v1",
		"validation_rules": [{
			"field": "extruder.temperature",
			"rule_type": "absolute_maximum",
			"max_value": 100.0
		}]
	}`)
	if err := e.LoadProfile(profile); err != nil {
		t.Fatal(err)
	}

	// Should fail with profile loaded
	v := e.Evaluate(map[string]float64{"extruder.temperature": 200.0})
	if v.Pass {
		t.Fatal("expected fail with restrictive profile")
	}

	e.ClearProfile()

	// Should pass after clear
	v = e.Evaluate(map[string]float64{"extruder.temperature": 200.0})
	if !v.Pass {
		t.Fatal("expected pass after ClearProfile (null policy)")
	}
}

func TestTelemetryFromEpoch(t *testing.T) {
	m := policy.TelemetryFromEpoch(
		240.0, 240.0, 0.8,
		110.0, 110.0, 0.6,
		150.0, 5.0,
		95.0, true,
	)
	checks := map[string]float64{
		"extruder.temperature":                     240.0,
		"extruder.target":                          240.0,
		"heater_bed.temperature":                   110.0,
		"temperature_sensor.chamber.temperature":   95.0,
	}
	for k, want := range checks {
		if got := m[k]; got != want {
			t.Errorf("TelemetryFromEpoch[%q] = %v, want %v", k, got, want)
		}
	}
}

func TestTelemetryFromEpochNoChamber(t *testing.T) {
	m := policy.TelemetryFromEpoch(
		240.0, 240.0, 0.8,
		110.0, 110.0, 0.6,
		150.0, 5.0,
		0.0, false, // no chamber
	)
	if _, ok := m["temperature_sensor.chamber.temperature"]; ok {
		t.Error("chamber key should be absent when chamberPresent=false")
	}
}

func TestLoadProfileRejectsEmptyID(t *testing.T) {
	e := policy.NewEngine(testLog)
	if err := e.LoadProfile([]byte(`{"profile_id": "", "validation_rules": []}`)); err == nil {
		t.Fatal("expected error for empty profile_id")
	}
}

func TestLoadProfileRejectsInvalidJSON(t *testing.T) {
	e := policy.NewEngine(testLog)
	if err := e.LoadProfile([]byte(`not json`)); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
