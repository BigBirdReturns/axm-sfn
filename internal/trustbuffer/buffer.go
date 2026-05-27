// Package trustbuffer implements the local append-only SQLite WAL custody ledger.
//
// Design invariants:
//   - Writer (epoch packetizer) is the only goroutine that INSERTs into packets.
//   - TPM worker UPDATEs packets with tpm_sig after signing.
//   - Uploader reads contiguous pending ranges and UPDATEs upload_state.
//   - WAL mode: readers never block the writer; checkpoint runs separately.
//
// The buffer is the local analogue of AXM REQ 5: a gap in seq during a
// printing session is a provenance fault, regardless of ledger availability.
package trustbuffer

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	driverName = "sqlite3"

	// pragma string applied on every connection open.
	pragmas = `
		PRAGMA journal_mode=WAL;
		PRAGMA synchronous=NORMAL;
		PRAGMA foreign_keys=ON;
		PRAGMA busy_timeout=5000;
	`
)

// Buffer is the local trust buffer. All public methods are safe for concurrent
// use from multiple goroutines; SQLite WAL handles the locking.
type Buffer struct {
	db  *sql.DB
	log *slog.Logger
}

// Open opens (or creates) the trust buffer at dbPath. Returns a ready Buffer.
func Open(dbPath string, log *slog.Logger) (*Buffer, error) {
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_synchronous=NORMAL&_foreign_keys=ON&_busy_timeout=5000", dbPath)
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("trustbuffer: open %s: %w", dbPath, err)
	}
	// Limit to one writer connection to avoid WAL contention; readers can share.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)

	b := &Buffer{db: db, log: log}
	if err := b.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("trustbuffer: migrate: %w", err)
	}
	return b, nil
}

// Close closes the underlying database connection.
func (b *Buffer) Close() error {
	return b.db.Close()
}

// ─── Schema ──────────────────────────────────────────────────────────────────

func (b *Buffer) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS packets (
		id                    INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id            TEXT    NOT NULL,
		seq                   INTEGER NOT NULL,
		tick_utc              TEXT    NOT NULL,
		tick_mono_ns          INTEGER NOT NULL,

		-- Telemetry fields (stored as a JSON blob for schema flexibility)
		telemetry_json        TEXT    NOT NULL,

		-- Anomaly flags
		anomaly_extruder      INTEGER NOT NULL DEFAULT 0,
		anomaly_bed           INTEGER NOT NULL DEFAULT 0,
		anomaly_load_cell     INTEGER NOT NULL DEFAULT 0,
		recovered_from_cache  INTEGER NOT NULL DEFAULT 0,

		-- Continuity chain
		prev_packet_blake3    BLOB,
		packet_sha256         BLOB    NOT NULL,
		packet_blake3         BLOB,

		-- TPM custody (filled in by tpm worker)
		tpm_sig               BLOB,
		quote_ref             INTEGER REFERENCES quotes(id),

		-- Upload lifecycle
		upload_state          TEXT    NOT NULL DEFAULT 'pending',  -- pending | uploaded | fault
		segment_id            INTEGER REFERENCES segments(id),

		UNIQUE (session_id, seq)
	);

	CREATE INDEX IF NOT EXISTS idx_packets_session_seq
		ON packets(session_id, seq);
	CREATE INDEX IF NOT EXISTS idx_packets_upload_state
		ON packets(upload_state);

	CREATE TABLE IF NOT EXISTS quotes (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id  TEXT    NOT NULL,
		seq         INTEGER NOT NULL,
		pcrs        TEXT    NOT NULL,  -- JSON array of PCR indices
		nonce       BLOB    NOT NULL,
		attest_blob BLOB    NOT NULL,
		sig         BLOB    NOT NULL,
		ak_handle   INTEGER NOT NULL,
		created_at  TEXT    NOT NULL
	);

	CREATE TABLE IF NOT EXISTS segments (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id   TEXT    NOT NULL,
		seq_start    INTEGER NOT NULL,
		seq_end      INTEGER NOT NULL,
		packet_count INTEGER NOT NULL,
		merkle_root  BLOB    NOT NULL,
		created_at   TEXT    NOT NULL,
		upload_state TEXT    NOT NULL DEFAULT 'pending'
	);

	CREATE TABLE IF NOT EXISTS provenance_faults (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id  TEXT    NOT NULL,
		seq         INTEGER NOT NULL,  -- seq where continuity broke
		reason      TEXT    NOT NULL,
		detected_at TEXT    NOT NULL
	);
	`
	_, err := b.db.Exec(schema)
	return err
}

// ─── Packet writes ───────────────────────────────────────────────────────────

// PacketRow is the data passed to WritePacket.
type PacketRow struct {
	SessionID           string
	Seq                 uint64
	TickUTC             time.Time
	TickMonoNs          int64
	TelemetryJSON       []byte // canonical JSON of the full EpochPacket (without TPM fields)
	AnomalyExtruder     bool
	AnomalyBed          bool
	AnomalyLoadCell     bool
	RecoveredFromCache  bool
	PrevPacketBLAKE3    []byte
	PacketSHA256        []byte
	PacketBLAKE3        []byte
}

// WritePacket appends a new epoch packet to the buffer.
// Returns the rowid of the inserted packet.
func (b *Buffer) WritePacket(ctx context.Context, p PacketRow) (int64, error) {
	res, err := b.db.ExecContext(ctx, `
		INSERT INTO packets (
			session_id, seq, tick_utc, tick_mono_ns,
			telemetry_json,
			anomaly_extruder, anomaly_bed, anomaly_load_cell, recovered_from_cache,
			prev_packet_blake3, packet_sha256, packet_blake3
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		p.SessionID,
		p.Seq,
		p.TickUTC.UTC().Format(time.RFC3339Nano),
		p.TickMonoNs,
		string(p.TelemetryJSON),
		boolInt(p.AnomalyExtruder),
		boolInt(p.AnomalyBed),
		boolInt(p.AnomalyLoadCell),
		boolInt(p.RecoveredFromCache),
		hexOrNil(p.PrevPacketBLAKE3),
		hex.EncodeToString(p.PacketSHA256),
		hexOrNil(p.PacketBLAKE3),
	)
	if err != nil {
		return 0, fmt.Errorf("trustbuffer: write packet seq=%d: %w", p.Seq, err)
	}
	return res.LastInsertId()
}

// SetTPMSig writes the TPM signature and quote reference back to an existing
// packet row. Called by the TPM worker after signing.
func (b *Buffer) SetTPMSig(ctx context.Context, rowID int64, tpmSig []byte, quoteRef int64) error {
	_, err := b.db.ExecContext(ctx,
		`UPDATE packets SET tpm_sig=?, quote_ref=? WHERE id=?`,
		tpmSig, quoteRef, rowID,
	)
	return err
}

// RecordProvenanceFault persists a continuity fault (missing epoch, bad chain, etc.).
func (b *Buffer) RecordProvenanceFault(ctx context.Context, sessionID string, seq uint64, reason string) error {
	_, err := b.db.ExecContext(ctx,
		`INSERT INTO provenance_faults (session_id, seq, reason, detected_at)
		 VALUES (?, ?, ?, ?)`,
		sessionID, seq, reason, time.Now().UTC().Format(time.RFC3339Nano),
	)
	return err
}

// ─── Quote writes ─────────────────────────────────────────────────────────────

// WriteQuote persists a TPM attestation quote.
func (b *Buffer) WriteQuote(ctx context.Context, q QuoteRow) (int64, error) {
	pcrsJSON, _ := json.Marshal(q.PCRs)
	res, err := b.db.ExecContext(ctx, `
		INSERT INTO quotes (session_id, seq, pcrs, nonce, attest_blob, sig, ak_handle, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`,
		q.SessionID, q.Seq, string(pcrsJSON),
		q.Nonce, q.AttestBlob, q.Sig, q.AKHandle,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return 0, fmt.Errorf("trustbuffer: write quote: %w", err)
	}
	return res.LastInsertId()
}

// QuoteRow is the data passed to WriteQuote.
type QuoteRow struct {
	SessionID  string
	Seq        uint64
	PCRs       []uint
	Nonce      []byte
	AttestBlob []byte
	Sig        []byte
	AKHandle   uint32
}

// ─── Segment and upload ────────────────────────────────────────────────────────

// PendingRange returns the oldest contiguous pending sequence range for a session,
// up to maxBatch packets. Returns (0, 0, nil) if nothing is pending.
func (b *Buffer) PendingRange(ctx context.Context, sessionID string, maxBatch int) (seqStart, seqEnd uint64, rowIDs []int64, err error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, seq FROM packets
		WHERE session_id=? AND upload_state='pending'
		ORDER BY seq ASC
		LIMIT ?
	`, sessionID, maxBatch)
	if err != nil {
		return 0, 0, nil, err
	}
	defer rows.Close()

	var seqs []uint64
	for rows.Next() {
		var id int64
		var seq uint64
		if err := rows.Scan(&id, &seq); err != nil {
			return 0, 0, nil, err
		}
		rowIDs = append(rowIDs, id)
		seqs = append(seqs, seq)
	}
	if len(seqs) == 0 {
		return 0, 0, nil, nil
	}

	// Only return a contiguous prefix.
	contiguous := 1
	for i := 1; i < len(seqs); i++ {
		if seqs[i] != seqs[i-1]+1 {
			break
		}
		contiguous++
	}
	return seqs[0], seqs[contiguous-1], rowIDs[:contiguous], nil
}

// WriteSegment persists a segment record and marks the included packets as uploaded.
func (b *Buffer) WriteSegment(ctx context.Context, sessionID string, seqStart, seqEnd uint64, packetCount int, merkleRoot []byte, rowIDs []int64) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
		INSERT INTO segments (session_id, seq_start, seq_end, packet_count, merkle_root, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, sessionID, seqStart, seqEnd, packetCount, merkleRoot, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	segID, _ := res.LastInsertId()

	for _, rowID := range rowIDs {
		if _, err := tx.ExecContext(ctx,
			`UPDATE packets SET upload_state='uploaded', segment_id=? WHERE id=?`,
			segID, rowID,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func hexOrNil(b []byte) interface{} {
	if b == nil {
		return nil
	}
	return hex.EncodeToString(b)
}
