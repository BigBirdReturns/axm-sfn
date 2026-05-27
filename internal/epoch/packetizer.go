// Package epoch implements the 1-second custody clock.
//
// The epoch packetizer is the core of REQ-5 compliance: it materializes a
// full EpochPacket every second during an active print, regardless of whether
// Moonraker emitted a delta in that interval. Moonraker's notify_status_update
// is the state feeder; the epoch ticker is the custody clock.
package epoch

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/zeebo/blake3"

	moonclient "github.com/bigbirdreturns/axm-sfn/internal/moonraker"
	"github.com/bigbirdreturns/axm-sfn/internal/policy"
	"github.com/bigbirdreturns/axm-sfn/internal/telemetry"
	"github.com/bigbirdreturns/axm-sfn/internal/trustbuffer"
	tpmworker "github.com/bigbirdreturns/axm-sfn/internal/tpm"
)

// Packetizer drives the epoch loop and coordinates the Moonraker state cache,
// the trust buffer, and the TPM worker.
type Packetizer struct {
	cfg    Config
	buf    *trustbuffer.Buffer
	tpm    *tpmworker.Worker // may be nil if TPM is unavailable
	policy *policy.Engine
	log    *slog.Logger

	// Moonraker state cache, updated by applyDelta.
	mu    sync.RWMutex
	state moonclient.PrinterState

	// Session state.
	sessionID    string
	sessionNonce []byte
	seq          uint64
	prevBlake3   []byte
	lastQuoteID  int64
	silentTicks  int

	// Quote scheduling.
	immediateQuote bool // set by scheduleImmediateQuote(), cleared after quote
	lastQuoteAt    time.Time
	quoteInterval  time.Duration
}

// Config is extracted from the top-level daemon config for the packetizer.
type Config struct {
	NodeLabel        string
	PrinterID        string
	EpochPeriod      time.Duration
	MaxSilentTicks   int
	QuoteInterval    time.Duration
	QuoteOnLifecycle bool
	PCRs             []uint
	AKHandle         uint32 // TPM persistent AK handle — must match tpm.Worker config
}

// NewPacketizer creates a Packetizer but does not start the epoch loop.
func NewPacketizer(cfg Config, buf *trustbuffer.Buffer, tpm *tpmworker.Worker, log *slog.Logger) *Packetizer {
	return &Packetizer{
		cfg:           cfg,
		buf:           buf,
		tpm:           tpm,
		policy:        policy.NewEngine(log),
		log:           log,
		quoteInterval: cfg.QuoteInterval,
	}
}

// Run starts the epoch loop. It reads deltas from updates and ticks at
// cfg.EpochPeriod. Blocks until ctx is cancelled.
func (p *Packetizer) Run(ctx context.Context, updates <-chan moonclient.StatusDelta) {
	ticker := time.NewTicker(p.cfg.EpochPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case delta, ok := <-updates:
			if !ok {
				return
			}
			p.applyDelta(delta)
			p.silentTicks = 0 // a delta resets the silence counter

		case tick := <-ticker.C:
			p.onTick(ctx, tick)
		}
	}
}

// applyDelta merges a Moonraker status delta into the local state cache.
// Only the fields present in the delta are updated; absent fields keep
// their previous values. This correctly handles Moonraker's delta-only
// notify_status_update protocol.
func (p *Packetizer) applyDelta(delta moonclient.StatusDelta) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for obj, raw := range delta.Status {
		switch obj {
		case "extruder":
			json.Unmarshal(raw, &p.state.Extruder)
		case "heater_bed":
			json.Unmarshal(raw, &p.state.HeaterBed)
		case "motion_report":
			json.Unmarshal(raw, &p.state.MotionReport)
		case "print_stats":
			old := p.state.PrintStats
			json.Unmarshal(raw, &p.state.PrintStats)
			p.detectLifecycleEdge(old.State, p.state.PrintStats.State)
		case "mcu":
			json.Unmarshal(raw, &p.state.MCU)
		case "temperature_sensor chamber":
			var cs struct {
				Temperature float64 `json:"temperature"`
			}
			if json.Unmarshal(raw, &cs) == nil {
				p.state.ChamberTempC = cs.Temperature
				p.state.ChamberPresent = true
			}
		}
	}
}

func (p *Packetizer) detectLifecycleEdge(prev, next string) {
	if prev == next {
		return
	}
	p.log.Info("epoch: print state transition", "from", prev, "to", next)
	// Session management.
	switch {
	case next == "printing" && prev != "paused":
		p.startNewSession()
	case next == "complete" || next == "cancelled" || next == "error":
		p.log.Info("epoch: session ended", "session_id", p.sessionID, "seq", p.seq)
	}
	// Quote on lifecycle edge if configured.
	if p.cfg.QuoteOnLifecycle && p.tpm != nil {
		p.scheduleImmediateQuote()
	}
}

func (p *Packetizer) startNewSession() {
	id := make([]byte, 16)
	rand.Read(id)
	nonce := make([]byte, 32)
	rand.Read(nonce)
	p.sessionID = fmt.Sprintf("%x", id)
	p.sessionNonce = nonce
	p.seq = 0
	p.prevBlake3 = nil
	p.lastQuoteID = 0
	p.silentTicks = 0
	p.lastQuoteAt = time.Time{}
	p.log.Info("epoch: new session started", "session_id", p.sessionID)
}

func (p *Packetizer) scheduleImmediateQuote() {
	p.immediateQuote = true
}

// onTick is called once per epoch. It materializes the current printer state
// into a packet, computes the chain hashes, optionally drives a TPM quote,
// and writes the packet to the trust buffer.
func (p *Packetizer) onTick(ctx context.Context, tick time.Time) {
	p.mu.RLock()
	state := p.state // snapshot
	p.mu.RUnlock()

	// Only record during active prints.
	if !state.IsActive() {
		return
	}

	if p.sessionID == "" {
		p.startNewSession()
	}

	p.silentTicks++
	if p.silentTicks > p.cfg.MaxSilentTicks {
		p.log.Warn("epoch: provenance fault — printer silent",
			"silent_ticks", p.silentTicks,
			"session_id", p.sessionID,
			"seq", p.seq)
		if err := p.buf.RecordProvenanceFault(ctx, p.sessionID, p.seq, "printer telemetry silence exceeded threshold"); err != nil {
			p.log.Error("epoch: failed to record provenance fault", "error", err)
		}
		// Reset so we don't flood the fault table.
		p.silentTicks = 0
	}

	monoNs := monoNow()

	// Evaluate against active Material-Process Profile (Track 2 policy engine).
	// Flat float map — no JSON Pointer parsing in the hot path.
	telemetryMap := policy.TelemetryFromEpoch(
		state.Extruder.Temperature, state.Extruder.Target, state.Extruder.Power,
		state.HeaterBed.Temperature, state.HeaterBed.Target, state.HeaterBed.Power,
		state.MotionReport.LiveVelocity, state.MotionReport.LiveExtruderVelocity,
		state.ChamberTempC, state.ChamberPresent,
	)
	verdict := p.policy.Evaluate(telemetryMap)
	var policyVerdict *telemetry.PolicyVerdict
	if verdict.ProfileID != "null" {
		policyVerdict = &telemetry.PolicyVerdict{
			Pass:       verdict.Pass,
			ProfileID:  verdict.ProfileID,
			Violations: verdict.Violations,
		}
	}

	// Build the pre-TPM payload (all fields except TPMSig, PacketSHA256, PacketBLAKE3).
	pkt := &telemetry.EpochPacket{
		SessionID:            p.sessionID,
		NodeLabel:            p.cfg.NodeLabel,
		PrinterID:            p.cfg.PrinterID,
		Seq:                  p.seq,
		Tick:                 tick.UTC(),
		TickMonoNs:           monoNs,
		ExtruderTemp:         state.Extruder.Temperature,
		ExtruderTarget:       state.Extruder.Target,
		ExtruderPower:        state.Extruder.Power,
		BedTemp:              state.HeaterBed.Temperature,
		BedTarget:            state.HeaterBed.Target,
		BedPower:             state.HeaterBed.Power,
		ChamberTemp:          state.ChamberTempC,
		ChamberPresent:       state.ChamberPresent,
		LiveVelocity:         state.MotionReport.LiveVelocity,
		LiveExtruderVelocity: state.MotionReport.LiveExtruderVelocity,
		LivePosition:         state.MotionReport.LivePosition,
		PrintState:           state.PrintStats.State,
		FilamentUsedMM:       state.PrintStats.FilamentUsed,
		PrintDurationS:       state.PrintStats.PrintDuration,
		MCUVersion:           state.MCU.MCUVersion,
		MCUBuildVersions:     state.MCU.MCUBuildVersions,
		PolicyVerdict:        policyVerdict,
		PrevPacketBLAKE3:     p.prevBlake3,
		QuoteRef:             p.lastQuoteID,
	}

	// Canonical serialization for signing (deterministic).
	canonical, err := json.Marshal(pkt)
	if err != nil {
		p.log.Error("epoch: marshal packet", "error", err)
		return
	}

	// SHA-256 for TPM sign.
	sha := sha256.Sum256(canonical)
	pkt.PacketSHA256 = sha[:]

	// Optionally run a TPM quote.
	quoteID := p.lastQuoteID
	if p.tpm != nil && p.shouldQuote() {
		nonce := tpmworker.DeriveQuoteNonce(p.sessionNonce, sha[:], p.prevBlake3, p.seq)
		qr, err := p.tpm.Quote(nonce)
		if err != nil {
			p.log.Error("epoch: tpm quote failed", "error", err)
		} else {
			qid, err := p.buf.WriteQuote(ctx, trustbuffer.QuoteRow{
				SessionID:  p.sessionID,
				Seq:        p.seq,
				PCRs:       p.cfg.PCRs,
				Nonce:      qr.Nonce,
				AttestBlob: qr.AttestBlob,
				Sig:        qr.Sig,
				AKHandle:   p.cfg.AKHandle,
			})
			if err != nil {
				p.log.Error("epoch: write quote", "error", err)
			} else {
				quoteID = qid
				p.lastQuoteID = qid
				p.lastQuoteAt = tick
				p.immediateQuote = false
			}
		}
	}
	pkt.QuoteRef = quoteID

	// TPM sign the packet SHA-256.
	var tpmSig []byte
	if p.tpm != nil {
		tpmSig, err = p.tpm.SignPacket(canonical)
		if err != nil {
			p.log.Error("epoch: tpm sign failed", "error", err)
			// Continue without TPM sig — note the anomaly flag in a real impl.
		}
	}
	pkt.TPMSig = tpmSig

	// BLAKE3 chain link: BLAKE3(seq_le || session_id || canonical || tpm_sig || prev_blake3)
	pkt.PacketBLAKE3 = computePacketBLAKE3(p.seq, p.sessionID, canonical, tpmSig, p.prevBlake3)

	// Write to trust buffer.
	row := trustbuffer.PacketRow{
		SessionID:          p.sessionID,
		Seq:                p.seq,
		TickUTC:            tick.UTC(),
		TickMonoNs:         monoNs,
		TelemetryJSON:      canonical,
		AnomalyExtruder:    policyVerdict != nil && !policyVerdict.Pass,
		AnomalyBed:         false, // deprecated — verdict covers all rules
		AnomalyLoadCell:    false, // deprecated — verdict covers all rules
		RecoveredFromCache: pkt.RecoveredFromCache,
		PrevPacketBLAKE3:   p.prevBlake3,
		PacketSHA256:       pkt.PacketSHA256,
		PacketBLAKE3:       pkt.PacketBLAKE3,
	}

	rowID, err := p.buf.WritePacket(ctx, row)
	if err != nil {
		p.log.Error("epoch: write packet to trust buffer", "seq", p.seq, "error", err)
		return
	}

	// Backfill TPM sig if we have one (separate update avoids blocking the hot path).
	if tpmSig != nil {
		if err := p.buf.SetTPMSig(ctx, rowID, tpmSig, quoteID); err != nil {
			p.log.Warn("epoch: failed to set tpm sig", "row_id", rowID, "error", err)
		}
	}

	// Advance chain state.
	p.prevBlake3 = pkt.PacketBLAKE3
	p.seq++
}

func (p *Packetizer) shouldQuote() bool {
	if p.immediateQuote {
		return true
	}
	if p.lastQuoteAt.IsZero() {
		return true // first quote for session
	}
	return time.Since(p.lastQuoteAt) >= p.quoteInterval
}

// computePacketBLAKE3 computes the BLAKE3 chain hash for a packet.
// Uses the domain-separated construction from AXM Genesis (0x00 prefix).
func computePacketBLAKE3(seq uint64, sessionID string, canonical, tpmSig, prevHash []byte) []byte {
	h := blake3.New()
	h.Write([]byte{0x00}) // domain: leaf (matches AXM Genesis leaf convention)
	seqBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(seqBytes, seq)
	h.Write(seqBytes)
	h.Write([]byte(sessionID))
	h.Write(canonical)
	if tpmSig != nil {
		h.Write(tpmSig)
	}
	if prevHash != nil {
		h.Write(prevHash)
	}
	return h.Sum(nil)
}

// monoNow returns wall clock nanoseconds. On Linux with a real monotonic clock
// this would use clock_gettime(CLOCK_MONOTONIC) directly; for portability
// we use time.Now().UnixNano() which includes monotonic component on Go 1.9+.
func monoNow() int64 {
	return time.Now().UnixNano()
}
