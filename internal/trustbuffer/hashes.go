package trustbuffer

import (
	"context"
	"encoding/hex"
	"fmt"
)

// PacketHashes returns the packet_blake3 hashes for the given row IDs,
// in the order provided. Called by the uploader to build the Merkle root.
func (b *Buffer) PacketHashes(ctx context.Context, rowIDs []int64) ([][]byte, error) {
	if len(rowIDs) == 0 {
		return nil, nil
	}

	// Build a positional map first so we can return results in input order.
	placeholders := make([]interface{}, len(rowIDs))
	query := "SELECT id, packet_blake3 FROM packets WHERE id IN ("
	for i, id := range rowIDs {
		if i > 0 {
			query += ","
		}
		query += "?"
		placeholders[i] = id
	}
	query += ")"

	rows, err := b.db.QueryContext(ctx, query, placeholders...)
	if err != nil {
		return nil, fmt.Errorf("trustbuffer: packet hashes: %w", err)
	}
	defer rows.Close()

	hashByID := make(map[int64][]byte, len(rowIDs))
	for rows.Next() {
		var id int64
		var hashHex *string
		if err := rows.Scan(&id, &hashHex); err != nil {
			return nil, err
		}
		if hashHex != nil {
			decoded, err := hex.DecodeString(*hashHex)
			if err != nil {
				return nil, fmt.Errorf("trustbuffer: decode blake3 hash for row %d: %w", id, err)
			}
			hashByID[id] = decoded
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([][]byte, len(rowIDs))
	for i, id := range rowIDs {
		out[i] = hashByID[id] // nil if not found — uploader handles gracefully
	}
	return out, nil
}
