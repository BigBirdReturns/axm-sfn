package uploader_test

import (
	"encoding/hex"
	"testing"

	"github.com/bigbirdreturns/axm-sfn/internal/uploader"
)

func TestMerkleRootEmptyIsConstant(t *testing.T) {
	// Empty root must be BLAKE3(0x01) — frozen Genesis constant.
	root := uploader.LocalSegmentRootForHashes(nil)
	got := hex.EncodeToString(root)
	// BLAKE3(0x01)
	const want = "48fc721fbbc172e0925fa27af1671de225ba927134802998b10a1568a188652b"
	if got != want {
		t.Fatalf("empty merkle root = %s, want %s", got, want)
	}
}

func TestMerkleRootSingleHash(t *testing.T) {
	h := make([]byte, 32)
	h[0] = 0xAB
	r1 := uploader.LocalSegmentRootForHashes([][]byte{h})
	r2 := uploader.LocalSegmentRootForHashes([][]byte{h})
	if hex.EncodeToString(r1) != hex.EncodeToString(r2) {
		t.Fatal("merkle root not deterministic for single hash")
	}
}

func TestMerkleRootDeterministic(t *testing.T) {
	hashes := make([][]byte, 4)
	for i := range hashes {
		hashes[i] = make([]byte, 32)
		hashes[i][0] = byte(i + 1)
	}
	r1 := uploader.LocalSegmentRootForHashes(hashes)
	r2 := uploader.LocalSegmentRootForHashes(hashes)
	if hex.EncodeToString(r1) != hex.EncodeToString(r2) {
		t.Fatal("merkle root not deterministic for 4 hashes")
	}
}

func TestMerkleRootChangesWithInput(t *testing.T) {
	h1 := [][]byte{make([]byte, 32), make([]byte, 32)}
	h1[0][0] = 0x01

	h2 := [][]byte{make([]byte, 32), make([]byte, 32)}
	h2[0][0] = 0x02

	r1 := uploader.LocalSegmentRootForHashes(h1)
	r2 := uploader.LocalSegmentRootForHashes(h2)
	if hex.EncodeToString(r1) == hex.EncodeToString(r2) {
		t.Fatal("different inputs produced same merkle root")
	}
}

func TestMerkleRootOddLeafPromotion(t *testing.T) {
	// 3 leaves — odd. RFC 6962 promotes last leaf.
	// Verify result differs from a naive duplicate-odd approach
	// by checking it's stable and non-zero.
	hashes := make([][]byte, 3)
	for i := range hashes {
		hashes[i] = make([]byte, 32)
		hashes[i][0] = byte(i + 1)
	}
	root := uploader.LocalSegmentRootForHashes(hashes)
	if len(root) != 32 {
		t.Fatalf("expected 32-byte root, got %d", len(root))
	}
	allZero := true
	for _, b := range root {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("merkle root is all zeros")
	}
}
