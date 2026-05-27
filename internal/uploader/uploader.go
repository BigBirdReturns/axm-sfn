// Package uploader batches epoch packets from the trust buffer into
// BLAKE3 Merkle segments and ships them to the NodalFlow routing layer.
//
// Current implementation: if Endpoint is empty or unreachable, segments
// are logged to stdout as JSON. This keeps the daemon runnable without
// a live NodalFlow instance during development.
package uploader

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/zeebo/blake3"

	"github.com/bigbirdreturns/axm-sfn/internal/trustbuffer"
)

// Uploader reads pending segments from the trust buffer and ships them
// upstream. It runs as a background goroutine.
type Uploader struct {
	endpoint      string
	batchSize     int
	retryInterval time.Duration
	buf           *trustbuffer.Buffer
	log           *slog.Logger
	client        *http.Client
}

// New creates an Uploader. buf must already be open.
func New(endpoint string, batchSize int, retryInterval time.Duration, buf *trustbuffer.Buffer, log *slog.Logger) *Uploader {
	return &Uploader{
		endpoint:      endpoint,
		batchSize:     batchSize,
		retryInterval: retryInterval,
		buf:           buf,
		log:           log,
		client:        &http.Client{Timeout: 15 * time.Second},
	}
}

// Run polls the trust buffer on retryInterval and uploads any pending
// segments. Blocks until ctx is cancelled.
func (u *Uploader) Run(ctx context.Context, sessionID string) {
	ticker := time.NewTicker(u.retryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := u.flush(ctx, sessionID); err != nil {
				u.log.Warn("uploader: flush failed", "error", err)
			}
		}
	}
}

// flush drains one contiguous pending range from the buffer.
func (u *Uploader) flush(ctx context.Context, sessionID string) error {
	seqStart, seqEnd, rowIDs, err := u.buf.PendingRange(ctx, sessionID, u.batchSize)
	if err != nil {
		return fmt.Errorf("pending range: %w", err)
	}
	if len(rowIDs) == 0 {
		return nil // nothing pending
	}

	// Fetch the packet_blake3 hashes for these rows in order.
	hashes, err := u.buf.PacketHashes(ctx, rowIDs)
	if err != nil {
		return fmt.Errorf("fetch hashes: %w", err)
	}

	// Compute BLAKE3 Merkle root over the packet hashes.
	// Uses the AXM Genesis mldsa44 construction:
	//   Leaf:  BLAKE3(0x00 || seq_le || 0x00 || packet_blake3)
	//   Node:  BLAKE3(0x01 || left || right)
	//   Odd:   promote unchanged (RFC 6962)
	merkleRoot := computeMerkleRoot(hashes)

	seg := segmentPayload{
		SessionID:   sessionID,
		SeqStart:    seqStart,
		SeqEnd:      seqEnd,
		PacketCount: len(rowIDs),
		MerkleRoot:  hex.EncodeToString(merkleRoot),
	}

	if err := u.buf.WriteSegment(ctx, sessionID, seqStart, seqEnd, len(rowIDs), merkleRoot, rowIDs); err != nil {
		return fmt.Errorf("write segment: %w", err)
	}

	return u.ship(ctx, seg)
}

// ship sends the segment upstream, or logs it if no endpoint is configured.
func (u *Uploader) ship(ctx context.Context, seg segmentPayload) error {
	payload, err := json.Marshal(seg)
	if err != nil {
		return err
	}

	if u.endpoint == "" {
		u.log.Info("uploader: segment (stdout — no endpoint configured)",
			"session_id", seg.SessionID,
			"seq_start", seg.SeqStart,
			"seq_end", seg.SeqEnd,
			"packets", seg.PacketCount,
			"merkle_root", seg.MerkleRoot)
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.endpoint+"/segments", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", u.endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("upstream returned %d", resp.StatusCode)
	}

	u.log.Info("uploader: segment shipped",
		"session_id", seg.SessionID,
		"seq_start", seg.SeqStart,
		"seq_end", seg.SeqEnd,
		"packets", seg.PacketCount,
		"merkle_root", seg.MerkleRoot)
	return nil
}

// MerkleRootForHashes computes the BLAKE3 Merkle root over a slice of
// packet_blake3 hashes using the AXM Genesis mldsa44 construction.
// Exported for testing.
func MerkleRootForHashes(hashes [][]byte) []byte {
	return computeMerkleRoot(hashes)
}

// computeMerkleRoot is the internal implementation.
func computeMerkleRoot(hashes [][]byte) []byte {
	if len(hashes) == 0 {
		// Empty root: BLAKE3(0x01) — frozen Genesis constant
		h := blake3.New()
		h.Write([]byte{0x01})
		return h.Sum(nil)
	}

	// Build leaves with domain separation
	leaves := make([][]byte, len(hashes))
	for i, h := range hashes {
		leaf := blake3.New()
		leaf.Write([]byte{0x00}) // leaf domain prefix
		// seq as 8-byte little-endian (index within segment)
		seqBytes := [8]byte{}
		for j := 0; j < 8; j++ {
			seqBytes[j] = byte(uint64(i) >> (j * 8))
		}
		leaf.Write(seqBytes[:])
		leaf.Write([]byte{0x00})
		leaf.Write(h)
		leaves[i] = leaf.Sum(nil)
	}

	return merkleReduce(leaves)
}

func merkleReduce(level [][]byte) []byte {
	if len(level) == 1 {
		return level[0]
	}
	var next [][]byte
	for i := 0; i+1 < len(level); i += 2 {
		node := blake3.New()
		node.Write([]byte{0x01}) // node domain prefix
		node.Write(level[i])
		node.Write(level[i+1])
		next = append(next, node.Sum(nil))
	}
	if len(level)%2 == 1 {
		next = append(next, level[len(level)-1]) // RFC 6962: promote odd leaf
	}
	return merkleReduce(next)
}

type segmentPayload struct {
	SessionID   string `json:"session_id"`
	SeqStart    uint64 `json:"seq_start"`
	SeqEnd      uint64 `json:"seq_end"`
	PacketCount int    `json:"packet_count"`
	MerkleRoot  string `json:"merkle_root"`
}
