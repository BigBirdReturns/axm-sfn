# axm-sfn Stream Format v1

Mirrors the `axm-embodied` AXLF/AXLR format with spoke-specific magic bytes.
The Genesis verifier extension for axm-sfn checks `fab_latents.bin` using
the same frame continuity logic as REQ 5, without modifying the Genesis kernel.

---

## Shared record header (little endian)

```
Struct: <4sBII  (13 bytes total)
  magic       [4 bytes]   — stream-type identifier (see below)
  ver         [1 byte]    — format version, currently 1
  frame_id    [4 bytes]   — uint32, zero-indexed, monotonically increasing
  payload_len [4 bytes]   — uint32, payload bytes following this header
```

---

## Fabrication Latents (hot stream)

| Field         | Value                                      |
|---------------|--------------------------------------------|
| File          | `fab_latents.bin`                          |
| File magic    | `SFNF` — 4 bytes at offset 0               |
| Record magic  | `SFNR`                                     |
| Version       | `1`                                        |
| Payload       | 256 bytes (serialized EpochPacket fields)  |
| Record length | 269 bytes (13-byte header + 256 payload)   |

**File layout:**
```
[SFNF (4 bytes)]          ← file-level header, skip before reading records
[record_0][record_1]...   ← sequential SFNR records, frame_id 0, 1, 2, ...
```

**Offset math:** `offset(fid) = 4 + fid * 269`

**Frame continuity (REQ 5):** Any gap in the monotone frame_id sequence
triggers `E_BUFFER_DISCONTINUITY` in the axm-sfn verifier extension.
Document shards and non-embodied spokes are unaffected.

---

## Constants

```python
MAGIC_FAB_FILE = b"SFNF"   # file-level header
MAGIC_FAB_REC  = b"SFNR"   # per-record magic
VERSION        = 1
REC_HEADER_FMT = "<4sBII"
REC_HEADER_LEN = 13
PAYLOAD_LEN    = 256
FILE_HEADER_LEN = 4
FAB_REC_LEN    = REC_HEADER_LEN + PAYLOAD_LEN  # 269
```

These constants are frozen for the v1 format. Spokes implementing a
different physical domain must use distinct magic bytes.

---

## Relationship to axm-embodied

| Field        | axm-embodied       | axm-sfn            |
|--------------|--------------------|--------------------|
| File         | `cam_latents.bin`  | `fab_latents.bin`  |
| File magic   | `AXLF`             | `SFNF`             |
| Record magic | `AXLR`             | `SFNR`             |
| Payload dim  | 256 (camera latent)| 256 (fab telemetry)|
| REQ 5 check  | Genesis kernel     | axm-sfn extension  |

The Genesis kernel does not change. The spoke discriminator is the magic
byte pair, documented here and enforced by the spoke-specific verifier.
