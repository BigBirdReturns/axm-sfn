// Package telemetry defines the canonical EpochPacket and Segment types
// for the axm-sfn fabrication node.
package telemetry

import "time"

// EpochPacket is one second of fabrication telemetry, sealed into the
// BLAKE3 chain. Fields are JSON-tagged for deterministic canonical
// serialization. The zero value for numeric fields means "not observed."
//
// Canonical serialization (for TPM signing and chain hashing) uses
// encoding/json with struct field order — Go's encoder is deterministic
// for a given struct layout. Do not reorder fields without bumping the
// packet format version.
type EpochPacket struct {
	// ── Identity ──────────────────────────────────────────────────────────
	SessionID string `json:"session_id"`
	NodeLabel string `json:"node_label"`
	PrinterID string `json:"printer_id"`
	Seq       uint64 `json:"seq"`

	// ── Timing ────────────────────────────────────────────────────────────
	Tick       time.Time `json:"tick"`
	TickMonoNs int64     `json:"tick_mono_ns"`

	// ── Thermal telemetry ─────────────────────────────────────────────────
	ExtruderTemp   float64 `json:"extruder_temp"`
	ExtruderTarget float64 `json:"extruder_target"`
	ExtruderPower  float64 `json:"extruder_power"`
	BedTemp        float64 `json:"bed_temp"`
	BedTarget      float64 `json:"bed_target"`
	BedPower       float64 `json:"bed_power"`
	ChamberTemp    float64 `json:"chamber_temp,omitempty"`    // 0 if sensor absent
	ChamberPresent bool    `json:"chamber_present,omitempty"` // false if sensor absent

	// ── Motion telemetry ──────────────────────────────────────────────────
	LiveVelocity         float64   `json:"live_velocity"`
	LiveExtruderVelocity float64   `json:"live_extruder_velocity"`
	LivePosition         []float64 `json:"live_position"`

	// ── Print state ───────────────────────────────────────────────────────
	PrintState     string  `json:"print_state"`
	FilamentUsedMM float64 `json:"filament_used_mm"`
	PrintDurationS float64 `json:"print_duration_s"`

	// ── Firmware identity ─────────────────────────────────────────────────
	MCUVersion       string `json:"mcu_version"`
	MCUBuildVersions string `json:"mcu_build_versions"`

	// ── Policy verdict (replaces hardcoded anomaly flags) ─────────────────
	// Populated by internal/policy.Engine.Evaluate() before hashing.
	// Null/absent means no active profile — passes silently.
	PolicyVerdict *PolicyVerdict `json:"policy_verdict,omitempty"`

	// ── Anomaly flags (deprecated — kept for wire compat during migration) ─
	// TODO: remove after policy engine is wired in (Track 2.2)
	AnomalyExtruderThermal bool `json:"anomaly_extruder_thermal,omitempty"`
	AnomalyBedThermal      bool `json:"anomaly_bed_thermal,omitempty"`
	AnomalyLoadCell        bool `json:"anomaly_load_cell,omitempty"`
	RecoveredFromCache     bool `json:"recovered_from_cache,omitempty"`

	// ── Chain fields (filled after initial marshal) ───────────────────────
	// These are NOT included in the canonical pre-TPM serialization.
	// They are set after signing and before the final buffer write.
	PrevPacketBLAKE3 []byte `json:"prev_packet_blake3,omitempty"`
	PacketSHA256     []byte `json:"packet_sha256,omitempty"`
	PacketBLAKE3     []byte `json:"packet_blake3,omitempty"`
	TPMSig           []byte `json:"tpm_sig,omitempty"`
	QuoteRef         int64  `json:"quote_ref,omitempty"`
}

// PolicyVerdict is the output of the policy engine for one epoch.
// Pass=true means all active rules were satisfied.
type PolicyVerdict struct {
	Pass       bool     `json:"pass"`
	ProfileID  string   `json:"profile_id"`
	Violations []string `json:"violations,omitempty"`
}

// Segment is a BLAKE3 Merkle batch of EpochPackets, ready for upload
// to the NodalFlow routing layer.
type Segment struct {
	SessionID   string `json:"session_id"`
	NodeLabel   string `json:"node_label"`
	SeqStart    uint64 `json:"seq_start"`
	SeqEnd      uint64 `json:"seq_end"`
	PacketCount int    `json:"packet_count"`
	MerkleRoot  []byte `json:"merkle_root"` // BLAKE3 Merkle over packet_blake3 hashes
}
