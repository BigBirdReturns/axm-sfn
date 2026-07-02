# axm-sfn Stream Format v1

axm-sfn writes the **same** hot-stream format as `axm-embodied`: file
`cam_latents.bin`, file magic `AXLF`, record magic `AXLR`. Because the format
is identical, the frozen Genesis kernel's REQ-5 continuity check validates
fabrication shards with **zero changes** and **no spoke-specific verifier**.

> Earlier drafts used spoke-specific magic (`SFNF`/`SFNR`, `fab_latents.bin`).
> The Genesis verifier hardcodes `cam_latents.bin`/`AXLF`/`AXLR`, so those
> spoke-specific names made Genesis silently pass every SFN shard — REQ-5
> never fired. Adopting the embodied format verbatim closes that gap.

---

## Shared record header (little endian)

```
Struct: <4sBII  (13 bytes total)
  magic       [4 bytes]   — stream-type identifier (AXLR)
  ver         [1 byte]    — format version, currently 1
  frame_id    [4 bytes]   — uint32, zero-indexed, monotonically increasing
  payload_len [4 bytes]   — uint32, payload bytes following this header
```

---

## Fabrication Latents (hot stream)

| Field         | Value                                          |
|---------------|------------------------------------------------|
| File          | `cam_latents.bin`                              |
| File magic    | `AXLF` — 4 bytes at offset 0                   |
| Record magic  | `AXLR`                                          |
| Version       | `1`                                            |
| Payload       | 256 bytes (serialized CustodyPacket fields)    |
| Record length | 269 bytes (13-byte header + 256 payload)       |

**File layout:**
```
[AXLF (4 bytes)]          ← file-level header, skip before reading records
[record_0][record_1]...   ← sequential AXLR records, frame_id 0, 1, 2, ...
```

**Offset math:** `offset(fid) = 4 + fid * 269`

**Frame continuity (REQ 5):** Any gap in the monotone frame_id sequence
triggers `E_BUFFER_DISCONTINUITY` in the **frozen Genesis kernel** — the same
check that protects every other AXM spoke. A fabrication node that drops a
custody tick is non-conformant.

---

## Constants

```python
MAGIC_CAM_FILE  = b"AXLF"   # file-level header
MAGIC_CAM_REC   = b"AXLR"   # per-record magic
VERSION         = 1
REC_HEADER_FMT  = "<4sBII"
REC_HEADER_LEN  = 13
PAYLOAD_LEN     = 256
FILE_HEADER_LEN = 4
CAM_REC_LEN     = REC_HEADER_LEN + PAYLOAD_LEN  # 269
```

These constants are frozen for the v1 format and shared with `axm-embodied`.

---

## Relationship to axm-embodied

| Field        | axm-embodied       | axm-sfn               |
|--------------|--------------------|-----------------------|
| File         | `cam_latents.bin`  | `cam_latents.bin`     |
| File magic   | `AXLF`             | `AXLF`                |
| Record magic | `AXLR`             | `AXLR`                |
| Payload dim  | 256 (camera latent)| 256 (fab telemetry)   |
| REQ 5 check  | Genesis kernel     | Genesis kernel        |

The Genesis kernel does not change, and neither does the stream format.
Spokes differ only in what the 256-byte payload *means* — camera latents for
embodied, fabrication telemetry for sfn — not in the container or the
continuity guarantee.

---

## SFN payload layout (256 bytes, little-endian)

```
[0:32]    packet_blake3      — BLAKE3 chain link (zeros if not yet computed)
[32:64]   packet_sha256      — SHA-256 of canonical packet bytes (TPM-signed digest)
[64]      verdict            — 0=PASS  1=FAIL  0xFF=no active profile
[65]      tpm_present        — 1 if a TPM signature exists for this packet
[66:74]   seq                — uint64 LE (redundant with frame_id)
[74]      attestation_class  — 0=none  1=TPM 2.0
[75]      sig_alg            — 0=none  1=TPMT_SIGNATURE (RSA-PSS-2048/SHA-256)
[76:108]  sign_key_fp        — SHA-256 of the signing key's public area
                               (the TPM2B_PUBLIC bytes in ext/attestation@1);
                               zeros when unknown
[108:256] reserved           — zeros
```

Bytes 74–107 were reserved-as-zeros before the attestation-evidence change;
old streams parse as `attestation_class=0`. Identifier values are frozen once
assigned — new algorithms get new codes, never reused ones.

---

## Extension artifacts (spoke domain — Genesis treats `ext/` as opaque)

All three ride under the shard's ML-DSA-44 Merkle seal (the two-pass reseal
covers `ext/`), so they carry the same tamper-evidence as the core tables.

| Artifact | Contents |
|---|---|
| `ext/streams@1.parquet` | AXLR record locators (frame_id → offset/length/status/chain hash) |
| `ext/packets@1.parquet` | `(frame_id, canonical)` — the **verbatim** canonical packet bytes |
| `ext/attestation@1.parquet` | TPM evidence: per-packet signatures, quotes (PCRs, nonce, attest blob), signing-key + AK public areas, EK certificate chain |

### Archival verification rules (shard-only — no daemon, no buffer.db)

1. **Hash-over-stored-bytes.** For every AXLR record,
   `packet_sha256 == SHA-256(canonical)` where `canonical` comes from
   `ext/packets@1`. The Go canonicalization that produced the bytes is *not*
   part of the contract; only the stored bytes are.
2. **TPM packet signature.** Each `packet_sig` row in `ext/attestation@1`
   verifies over `packet_sha256` under the `sign_pub` key row whose
   fingerprint (SHA-256 of its `data` bytes) matches the record's
   `sign_key_fp` payload field.
3. **Chain recomputation.** The full BLAKE3 chain is recomputable from the
   shard alone:
   `packet_blake3 = BLAKE3(0x00 ‖ seq_le64 ‖ session_id ‖ canonical ‖ tpm_sig ‖ prev_blake3)`
   (absent `tpm_sig`/`prev_blake3` contribute nothing). `session_id` is bound
   in `source.txt` and inside each packet's canonical bytes.
4. **Quote binding.** Each quote's nonce is
   `SHA-256(session_nonce ‖ packet_sha256 ‖ seq_le64 ‖ prev_blake3)`, binding
   platform state (PCRs) to a specific point in the chain; the quote signature
   verifies under the `ak_pub` row, whose key traces to the `ek_cert` chain.

A session recorded without a TPM produces no `attestation@1` artifact —
absence of the extension is the explicit statement that no hardware evidence
exists (matching `tpm_present=0` / `attestation_class=0` in every record).
