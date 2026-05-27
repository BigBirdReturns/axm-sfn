// Package moonraker implements the Moonraker JSON-RPC WebSocket client
// and defines the printer state types axm-edge captures.
package moonraker

import "encoding/json"

// ── JSON-RPC wire types ───────────────────────────────────────────────────────

// Request is a Moonraker JSON-RPC 2.0 request frame.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a Moonraker JSON-RPC 2.0 response or notification frame.
// For responses, ID is non-zero and either Result or Error is set.
// For notifications, ID is zero and Method + Params are set.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is the error object in a failed JSON-RPC response.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// IdentifyParams is sent to server.connection.identify on connect.
type IdentifyParams struct {
	ClientName string `json:"client_name"`
	Version    string `json:"version"`
	Type       string `json:"type"`
	URL        string `json:"url"`
}

// SubscribeParams is sent to printer.objects.subscribe.
type SubscribeParams struct {
	Objects map[string]interface{} `json:"objects"`
}

// ── Printer state types ───────────────────────────────────────────────────────

// PrinterState is the full cached state of the printer, assembled from
// incremental notify_status_update deltas.
type PrinterState struct {
	Extruder       ExtruderState
	HeaterBed      HeaterBedState
	MotionReport   MotionReportState
	PrintStats     PrintStatsState
	MCU            MCUState
	ChamberTempC   float64 // from temperature_sensor chamber, 0 if absent
	ChamberPresent bool    // true once chamber sensor has reported
}

// IsActive returns true when a print is underway and telemetry should
// be recorded. Paused prints continue to record.
func (s *PrinterState) IsActive() bool {
	st := s.PrintStats.State
	return st == "printing" || st == "paused"
}

type ExtruderState struct {
	Temperature float64 `json:"temperature"`
	Target      float64 `json:"target"`
	Power       float64 `json:"power"`
}

type HeaterBedState struct {
	Temperature float64 `json:"temperature"`
	Target      float64 `json:"target"`
	Power       float64 `json:"power"`
}

type MotionReportState struct {
	LiveVelocity         float64   `json:"live_velocity"`
	LiveExtruderVelocity float64   `json:"live_extruder_velocity"`
	LivePosition         []float64 `json:"live_position"`
}

type PrintStatsState struct {
	State         string  `json:"state"`
	FilamentUsed  float64 `json:"filament_used"`
	PrintDuration float64 `json:"print_duration"`
}

type MCUState struct {
	MCUVersion       string `json:"mcu_version"`
	MCUBuildVersions string `json:"mcu_build_versions"`
}

// DefaultSubscribeObjects returns the minimal set of Moonraker printer
// objects axm-edge subscribes to. Includes the chamber temperature sensor;
// if the printer has no chamber sensor, Moonraker silently omits it from
// updates and the policy engine skips the field.
func DefaultSubscribeObjects() map[string]interface{} {
	return map[string]interface{}{
		"extruder":                          nil,
		"heater_bed":                        nil,
		"motion_report":                     nil,
		"print_stats":                       nil,
		"mcu":                               nil,
		"temperature_sensor chamber":        nil, // optional — absent on printers without enclosure
	}
}
