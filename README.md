# axm-sfn

**AXM Embodied Spoke — Sovereign Fabrication Node**

Transforms a standard Klipper/Moonraker 3D printer into a cryptographically
verified fabrication node. Every custody tick of a print run is sealed into a
BLAKE3 chain, hardware-bound to the node's TPM, and recorded in an append-only
hot buffer. At session boundary the `axm-sfn` spoke compiles the buffer into a
signed AXM Layer 2 journal shard through the frozen Genesis kernel.

Part of the [AXM ecosystem](https://axm.tools).

This repo has two halves:

- **`cmd/`, `internal/` (Go)** — the `axm-edge` edge daemon. Runs next to
  Klipper on the printer host. Tight 1 Hz custody loop, TPM bindings, low
  footprint. Its job ends at a TPM-attested custody ledger in SQLite.
- **`python/` (Python)** — the `axm-sfn` spoke. Reads the daemon's hot buffer
  at session boundary and compiles it into a verifiable shard via
  `axm-core` → `compile_generic_shard`, exactly like every other AXM spoke
  (INV-26 / INV-28). This is the only path to a sealed shard.

---

## What It Does

- **1Hz custody clock** — driven by an independent custody ticker, not Moonraker
  event arrival. Printer silence is recorded, not ignored. Implements AXM REQ 5
  (non-selective recording).
- **TPM attestation** — each custody packet is signed by a TPM 2.0 RSA-PSS key.
  TPM quotes (PCR measurements) are taken at session start, lifecycle edges,
  and on a configurable interval.
- **BLAKE3 chain** — packets are chained via BLAKE3, producing a tamper-evident
  local record in a SQLite WAL hot buffer that survives network outages.
- **Material-Process Profile evaluation** — the optional `internal/policy` engine
  evaluates each custody tick against a versioned MPF, producing a `decision`
  embedded in the packet chain.
- **AXM journal shards** — at session boundary the `axm-sfn` Python spoke reads
  the hot buffer and compiles it into a signed AXM Layer 2 journal shard via
  `axm-core`'s `compile_generic_shard`. The custody stream is serialized to the
  embodied `cam_latents.bin` (AXLF/AXLR) format so the frozen Genesis verifier
  validates REQ 5 continuity with no spoke-specific verifier.

---

## Quick Start

```bash
# Build
go build ./cmd/axm-edge/

# Provision TPM keys (run once, requires root or tss group membership)
sudo ./axm-edge provision --config config.example.yaml

# Run (dev mode — uploader logs segment digests to stdout)
./axm-edge run --config config.example.yaml
```

Compile a finished session into a shard (Python spoke, requires `axm-core`):

```bash
cd python && pip install -e .
axm sfn compile --db /var/lib/axm-edge/buffer.db --session <session_id> \
  --key sfn-key.bin --out ./shards
```

TPM hardware is not required for development. If `/dev/tpmrm0` is absent,
the daemon runs in software-only mode: packets are hashed and chained but
not TPM-signed. The hot buffer and custody loop function normally.

---

## Repo Layout

```
cmd/axm-edge/          — daemon entrypoint
internal/
  config/              — YAML config loader
  moonraker/           — Moonraker WebSocket client + state types
  custody/             — 1Hz custody clock + packet builder
  telemetry/           — CustodyPacket and Segment types
  hotbuffer/           — SQLite WAL hot buffer
  tpm/                 — TPM 2.0 Sign + Quote worker
  uploader/            — local segment digests + optional HTTP forward
  policy/              — Material-Process Profile evaluator
python/                — axm-sfn spoke (shard compilation via axm-core)
  src/axm_sfn_core/    — spoke constants (AXLF/AXLR) + delegated identity
  src/axm_sfn/         — buffer reader, stream serializer, compiler, CLI
schema/
  mpf/                 — example MPF JSON profiles
docs/
  STREAM_FORMAT.md     — cam_latents.bin binary format (AXLF/AXLR)
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
   Custody Packetizer
        │  ┌─ policy.Evaluator.Evaluate() → Decision
        │  ├─ tpm.Worker.SignPacket()  → TPMSig
        │  └─ computePacketBLAKE3()   → chain link
        ▼
   Hot Buffer (SQLite WAL)           ← survives network outage
        │  ┌─ Uploader: local segment digest (WAL tamper-evidence,
        │  │            optional HTTP forward for monitoring)
        │  └─ NOT the shard seal
        │
        │  ═══ session boundary ═══
        ▼
   axm-sfn spoke (Python)            ← reads buffer.db read-only
        │  ┌─ serialize custody → cam_latents.bin (AXLF/AXLR)
        │  ├─ compile_generic_shard()   (via axm-core, INV-28)
        │  └─ verify_shard()  → self-check
        ▼
   AXM Layer 2 journal shard (ML-DSA-44 signed, kernel-sealed)
```

---

## Three-Layer AXM Integration

| AXM Layer | axm-sfn Equivalent |
|---|---|
| Layer 3 — Hot Buffer | SQLite WAL hot buffer (`buffer.db`) |
| Layer 2 — Journal Shards | Compiled at session boundary by the `axm-sfn` spoke via `compile_generic_shard` |
| Layer 1 — Knowledge Shards | Material-Process Profile shards (Track 2, TBD) |

---

## Track Status

**Track 1 — Edge Daemon (complete)**
- [x] Moonraker WebSocket client with reconnect
- [x] 1Hz custody packetizer (REQ 5 custody clock)
- [x] SQLite WAL hot buffer with provenance fault recording
- [x] TPM 2.0 Sign + Quote worker
- [x] BLAKE3 chain linking
- [x] Segment uploader with Merkle aggregation
- [x] Policy engine skeleton (null profile passes everything)

**Track 1.5 — Python Spoke (implemented, integration-pending)**
- [x] `axm_sfn_core` constants + delegated identity (INV-25 / INV-27)
- [x] Read-only hot-buffer reader (`buffer.db`)
- [x] CustodyPacket → cam_latents.bin (AXLF/AXLR) serializer + `ext/streams@1.parquet`
- [x] Two-pass compile via `compile_generic_shard` + reseal + self-verify (INV-28)
- [x] `axm sfn` CLI registered on the `axm.spokes` entry point (INV-26)
- [ ] **Verified against a live `axm-core` install** — not yet run end-to-end;
      API call shapes need confirmation against the real package

**Track 2 — Certification Standard (in progress)**
- [ ] MPF schema v1 (JSON Schema + candidates.jsonl pipeline)
- [ ] Cryptographic tolerance definitions
- [ ] NIST challenge artifact integration
- [ ] Certification README (how nodes get onto an approved vendor list)

---

## Open Questions

- **MPF signing key / trust store:** Currently TBD. Candidates: AXM Foundation
  multi-sig escrow, rotating threshold scheme, or per-integrator delegation.
  Tracked in `docs/TRUST_STORE.md` (forthcoming).
- **Shard distribution:** the spoke compiles shards to a local directory.
  How sealed shards are published/ingested downstream is a Track 2 dependency.
- **Spoke execution environment:** the Python spoke targets `axm-core@v1.1.0`
  but has not yet been run against a live install; the `compile_generic_shard`
  call shapes are taken from the API spec and need end-to-end confirmation.

---

## License

AGPL-3.0 — see [LICENSE](LICENSE).

Copyleft by design: modifications must be shared. Network use triggers
source disclosure. This prevents capture, classification, or proprietary
forking by defense primes or integrators.
