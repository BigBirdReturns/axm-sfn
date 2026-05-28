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
