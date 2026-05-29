// Package tpm implements TPM 2.0 signing and attestation for the AXM Edge Daemon.
//
// Two distinct TPM operations:
//
//  1. Sign (per-packet): Signs the SHA-256 digest of a canonical packet
//     payload using a persistent TPM signing key. Proves a specific attested
//     host, not merely a process, produced each record.
//
//  2. Quote (lifecycle + periodic): Produces a TPM2_Quote over the selected
//     PCR set (default: 10, 11, 12, 15) using a nonce derived from session
//     context. Binds platform state to the telemetry chain.
//
// The design follows the research synthesis: "do not try to force the TPM to
// become the AXM shard signer." The TPM produces hardware attestation
// artifacts; the axm-sfn spoke embeds those artifacts into the shard during
// compilation (the shard is ML-DSA-44 signed by the kernel, not the TPM).
package tpm

import (
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Worker manages a single TPM device connection and exposes Sign and Quote.
// It is not safe for concurrent use from multiple goroutines; the caller
// (custody packetizer or a dedicated TPM goroutine) must serialize access.
type Worker struct {
	dev     io.ReadWriteCloser
	log     *slog.Logger
	cfg     Config
	signKey tpm2.AuthHandle
	akKey   tpm2.AuthHandle
}

// Config mirrors the TPMConfig from the top-level daemon config.
type Config struct {
	Device        string
	PCRs          []uint
	SignKeyHandle uint32
	AKHandle      uint32
}

// Open opens the TPM device and returns a ready Worker.
// The TPM persistent keys at cfg.SignKeyHandle and cfg.AKHandle must already
// exist (created by tpm2-tools provisioning or a one-time setup step).
// Call Close when done.
func Open(cfg Config, log *slog.Logger) (*Worker, error) {
	f, err := os.OpenFile(cfg.Device, os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("tpm: open %s: %w", cfg.Device, err)
	}

	w := &Worker{dev: f, log: log, cfg: cfg}

	// Verify the persistent handles exist by loading them.
	if err := w.checkHandles(); err != nil {
		f.Close()
		return nil, err
	}
	return w, nil
}

// Close releases the TPM device.
func (w *Worker) Close() error {
	return w.dev.Close()
}

func (w *Worker) checkHandles() error {
	t := transport.FromReadWriter(w.dev)

	// ReadPublic is a lightweight "does this handle exist?" check.
	signPub := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(w.cfg.SignKeyHandle)}
	if _, err := signPub.Execute(t); err != nil {
		return fmt.Errorf("tpm: sign key handle 0x%08x not found: %w", w.cfg.SignKeyHandle, err)
	}

	akPub := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(w.cfg.AKHandle)}
	if _, err := akPub.Execute(t); err != nil {
		return fmt.Errorf("tpm: AK handle 0x%08x not found: %w", w.cfg.AKHandle, err)
	}

	w.log.Info("tpm: persistent keys verified",
		"sign_handle", fmt.Sprintf("0x%08x", w.cfg.SignKeyHandle),
		"ak_handle", fmt.Sprintf("0x%08x", w.cfg.AKHandle))
	return nil
}

// SignPacket signs the SHA-256 digest of packetPayload using the TPM signing key.
// Returns the raw signature bytes (TPMT_SIGNATURE marshalled).
// The caller must serialize calls; TPM2_Sign is not thread-safe across a single fd.
func (w *Worker) SignPacket(packetPayload []byte) ([]byte, error) {
	digest := sha256.Sum256(packetPayload)

	t := transport.FromReadWriter(w.dev)
	sign := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(w.cfg.SignKeyHandle),
			Name:   tpm2.TPM2BName{},
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest[:]},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSAPSS,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSAPSS, &tpm2.TPMSSchemeHash{
				HashAlg: tpm2.TPMAlgSHA256,
			}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}

	resp, err := sign.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpm: sign: %w", err)
	}

	sig := tpm2.Marshal(resp.Signature)
	return sig, nil
}

// QuoteResult is the output of a TPM2_Quote operation.
type QuoteResult struct {
	Nonce      []byte // qualifying data used (for verifier anti-replay)
	AttestBlob []byte // TPM2B_ATTEST: the quoted attestation structure
	Sig        []byte // TPMT_SIGNATURE
}

// Quote produces a TPM2_Quote over the configured PCRs.
// nonce is the qualifying data (anti-replay); it should be derived as:
//
//	SHA-256(session_nonce || packet_sha256 || seq_bytes || prev_hash)
//
// This binds the platform evidence to a specific point in the telemetry chain.
func (w *Worker) Quote(nonce []byte) (*QuoteResult, error) {
	if len(nonce) > 64 {
		nonce = nonce[:64] // TPM qualifying data max 64 bytes in most implementations
	}

	t := transport.FromReadWriter(w.dev)

	// Build the PCR selection for the configured banks.
	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: pcrBitmap(w.cfg.PCRs),
			},
		},
	}

	quote := tpm2.Quote{
		SignHandle: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(w.cfg.AKHandle),
			Name:   tpm2.TPM2BName{},
		},
		QualifyingData: tpm2.TPM2BData{Buffer: nonce},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSAPSS,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSAPSS, &tpm2.TPMSSchemeHash{
				HashAlg: tpm2.TPMAlgSHA256,
			}),
		},
		PCRSelect: sel,
	}

	resp, err := quote.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpm: quote: %w", err)
	}

	attestBlob := tpm2.Marshal(resp.Quoted)
	sig := tpm2.Marshal(resp.Signature)

	return &QuoteResult{Nonce: nonce, AttestBlob: attestBlob, Sig: sig}, nil
}

// DeriveQuoteNonce computes the qualifying nonce for a quote:
//
//	SHA-256(sessionNonce || packetSHA256 || uint64_le(seq) || prevHash)
//
// This binds the quote to a specific packet in the session chain.
func DeriveQuoteNonce(sessionNonce, packetSHA256, prevHash []byte, seq uint64) []byte {
	h := crypto.SHA256.New()
	h.Write(sessionNonce)
	h.Write(packetSHA256)
	seqBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(seqBytes, seq)
	h.Write(seqBytes)
	h.Write(prevHash)
	return h.Sum(nil)
}

// pcrBitmap converts a list of PCR indices into the 3-byte PCRSelect bitmap
// expected by go-tpm.
func pcrBitmap(pcrs []uint) []byte {
	bm := make([]byte, 3)
	for _, p := range pcrs {
		if p < 24 {
			bm[p/8] |= 1 << (p % 8)
		}
	}
	return bm
}

// ─── Provisioning helpers (run once, not at daemon startup) ──────────────────

// ProvisionKeys creates the persistent signing key and attestation key
// if they do not already exist. Intended to be called from a one-time
// `axm-edge provision` subcommand, not from the hot path.
func ProvisionKeys(cfg Config, log *slog.Logger) error {
	f, err := os.OpenFile(cfg.Device, os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("tpm: open %s: %w", cfg.Device, err)
	}
	defer f.Close()

	t := transport.FromReadWriter(f)

	// Create signing key under the TPM's null primary.
	log.Info("tpm: provisioning signing key", "handle", fmt.Sprintf("0x%08x", cfg.SignKeyHandle))
	if err := createPersistentRSAPSSKey(t, cfg.SignKeyHandle); err != nil {
		return fmt.Errorf("tpm: create sign key: %w", err)
	}

	// Create attestation key (restricted signing key = AK).
	log.Info("tpm: provisioning attestation key", "handle", fmt.Sprintf("0x%08x", cfg.AKHandle))
	if err := createPersistentAK(t, cfg.AKHandle); err != nil {
		return fmt.Errorf("tpm: create AK: %w", err)
	}

	log.Info("tpm: provisioning complete")
	return nil
}

func createPersistentRSAPSSKey(t transport.TPM, handle uint32) error {
	primary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHNull,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				SignEncrypt:         true,
			},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSAPSS, &tpm2.TPMSSigSchemeRSAPSS{
						HashAlg: tpm2.TPMAlgSHA256,
					}),
				},
				KeyBits: 2048,
			}),
		}),
	}

	resp, err := primary.Execute(t)
	if err != nil {
		return err
	}
	defer tpm2.FlushContext{FlushHandle: resp.ObjectHandle}.Execute(t)

	persist := tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     resp.ObjectHandle,
		PersistentHandle: tpm2.TPMHandle(handle),
	}
	_, err = persist.Execute(t)
	return err
}

func createPersistentAK(t transport.TPM, handle uint32) error {
	primary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHNull,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				Restricted:          true, // AK must be restricted
				SignEncrypt:         true,
			},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSAPSS, &tpm2.TPMSSigSchemeRSAPSS{
						HashAlg: tpm2.TPMAlgSHA256,
					}),
				},
				KeyBits: 2048,
			}),
		}),
	}

	resp, err := primary.Execute(t)
	if err != nil {
		return err
	}
	defer tpm2.FlushContext{FlushHandle: resp.ObjectHandle}.Execute(t)

	persist := tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     resp.ObjectHandle,
		PersistentHandle: tpm2.TPMHandle(handle),
	}
	_, err = persist.Execute(t)
	return err
}
