# axm-sfn

**AXM Embodied Spoke — Sovereign Fabrication Node**

Transforms a standard Klipper/Moonraker 3D printer into a cryptographically
verified fabrication node. Every epoch of a print run is sealed into a
BLAKE3 chain, hardware-bound to the node's TPM, and uploaded as an AXM
journal shard to the NodalFlow routing layer.

Part of the [AXM ecosystem](https://axm.tools).

---

## What It Does

- **1Hz custody clock** — driven by an independent epoch ticker, not Moonraker
  event arrival. Printer silence is recorded, not ignored. Implements AXM REQ 5
  (non-selective recording).
- **TPM attestation** — each epoch packet is signed by a TPM 2.0 RSA-PSS key.
  TPM quotes (PCR measurements) are taken at session start, lifecycle edges,
  and on a configurable interval.
- **BLAKE3 chain** — packets are chained via BLAKE3, producing a tamper-evident
  local record in a SQLite WAL trust buffer that survives network outages.
- **Material-Process Profile evaluation** — the optional `internal/policy` engine
  evaluates each epoch against a versioned MPF, producing a `policy_verdict`
  embedded in the packet chain.
- **AXM journal shards** — segments are uploaded to the NodalFlow routing layer,
  which compiles them into signed AXM Layer 2 journal shards via Forge + Genesis.

---

## Quick Start

```bash
# Build
go build ./cmd/axm-edge/

# Provision TPM keys (run once, requires root or tss group membership)
sudo ./axm-edge provision --config config.example.yaml

# Run (dev mode — uploader logs to stdout, no NodalFlow required)
./axm-edge run --config config.example.yaml
```

TPM hardware is not required for development. If `/dev/tpmrm0` is absent,
the daemon runs in software-only mode: packets are hashed and chained but
not TPM-signed. The trust buffer and epoch loop function normally.

---

## Repo Layout

```
cmd/axm-edge/          — daemon entrypoint
internal/
  config/              — YAML config loader
  moonraker/           — Moonraker WebSocket client + state types
  epoch/               — 1Hz custody clock + packet builder
  telemetry/           — EpochPacket and Segment types
  trustbuffer/         — SQLite WAL trust buffer
  tpm/                 — TPM 2.0 Sign + Quote worker
  uploader/            — BLAKE3 Merkle aggregation + NodalFlow upload
  policy/              — Material-Process Profile evaluator
schema/
  mpf/                 — example MPF JSON profiles
docs/
  STREAM_FORMAT.md     — fab_latents.bin binary format (SFNF/SFNR)
config.example.yaml    — annotated example configuration
```

---

## Architecture

```
Moonraker WebSocket
        │  notify_status_update (event-driven)
        ▼
   State Cache (sync.RWMutex)
        │
        │  1Hz tick (independent of Moonraker)
        ▼
   Epoch Packetizer
        │  ┌─ policy.Engine.Evaluate() → PolicyVerdict
        │  ├─ tpm.Worker.SignPacket()  → TPMSig
        │  └─ computePacketBLAKE3()   → chain link
        ▼
   Trust Buffer (SQLite WAL)           ← survives network outage
        │
        │  on retryInterval
        ▼
   Uploader
        │  ┌─ PacketHashes() → BLAKE3 Merkle root
        │  └─ WriteSegment() + POST /segments
        ▼
   NodalFlow routing layer
        ▼
   Forge → Genesis → AXM journal shard (Layer 2)
```

---

## Three-Layer AXM Integration

| AXM Layer | axm-sfn Equivalent |
|---|---|
| Layer 3 — Hot Buffer | SQLite WAL trust buffer (`trust.db`) |
| Layer 2 — Journal Shards | Compiled at session boundary by Forge + Genesis |
| Layer 1 — Knowledge Shards | Material-Process Profile shards (Track 2, TBD) |

---

## Track Status

**Track 1 — Edge Daemon (complete)**
- [x] Moonraker WebSocket client with reconnect
- [x] 1Hz epoch packetizer (REQ 5 custody clock)
- [x] SQLite WAL trust buffer with provenance fault recording
- [x] TPM 2.0 Sign + Quote worker
- [x] BLAKE3 chain linking
- [x] Segment uploader with Merkle aggregation
- [x] Policy engine skeleton (null profile passes everything)

**Track 2 — Certification Standard (in progress)**
- [ ] MPF schema v1 (JSON Schema + candidates.jsonl pipeline)
- [ ] Cryptographic tolerance definitions
- [ ] NIST challenge artifact integration
- [ ] axm-sfn verifier extension (fab_latents.bin REQ 5 check)
- [ ] Certification README (how nodes get onto an approved vendor list)

---

## Open Questions

- **MPF signing key / trust store:** Currently TBD. Candidates: AXM Foundation
  multi-sig escrow, rotating threshold scheme, or per-integrator delegation.
  Tracked in `docs/TRUST_STORE.md` (forthcoming).
- **NodalFlow transport:** Uploader POSTs to a configurable endpoint.
  Full NodalFlow integration is a Track 2 dependency.

---

## License

AGPL-3.0 — see [LICENSE](LICENSE).

Copyleft by design: modifications must be shared. Network use triggers
source disclosure. This prevents capture, classification, or proprietary
forking by defense primes or integrators.
