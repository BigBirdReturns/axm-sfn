"""
Serialize custody packets to the AXLF/AXLR binary stream (cam_latents.bin)
and build ext/streams@1.parquet.

Each custody tick maps to one AXLR record. The 256-byte payload encodes the
packet's cryptographic fingerprint so that any holder of the shard can verify
the BLAKE3 chain link without the Go daemon.

Payload layout (256 bytes, little-endian):
  [0:32]   packet_blake3  — BLAKE3 chain link  (zeros if not yet computed)
  [32:64]  packet_sha256  — SHA-256 of canonical bytes (TPM-signable digest)
  [64]     verdict        — 0=PASS  1=FAIL  0xFF=no active profile
  [65]     tpm_present    — 1 if tpm_sig non-null, else 0
  [66:74]  seq            — uint64 LE (redundant with frame_id for convenience)
  [74:256] reserved       — zeros
"""
import struct
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from axm_sfn_core.protocol import (
    FILE_HEADER_LEN,
    LATENT_DIM,
    LATENT_REC_LEN,
    MAGIC_LATENT_FILE,
    MAGIC_LATENT_REC,
    REC_HEADER_FMT,
    VERSION,
)
from axm_sfn.db import PacketRecord

_CORE_FMT = struct.Struct("<32s32sBBQ")   # 74 bytes; remainder padded to LATENT_DIM
_PAD_LEN  = LATENT_DIM - _CORE_FMT.size  # 182 bytes

STREAMS_SCHEMA = pa.schema([
    ("frame_id",     pa.int32()),
    ("stream",       pa.string()),
    ("file",         pa.string()),
    ("offset",       pa.int64()),
    ("length",       pa.int32()),
    ("status",       pa.string()),
    ("content_hash", pa.string()),
])


def _pack_payload(pkt: PacketRecord) -> bytes:
    b3  = pkt.packet_blake3 or b"\x00" * 32
    sha = pkt.packet_sha256 or b"\x00" * 32
    verdict = (
        0xFF if pkt.verdict_pass is None
        else 0 if pkt.verdict_pass
        else 1
    )
    tpm = 1 if pkt.tpm_sig else 0
    return _CORE_FMT.pack(b3, sha, verdict, tpm, pkt.seq) + b"\x00" * _PAD_LEN


def build_axlf_stream(packets: list[PacketRecord]) -> bytes:
    """Return raw AXLF/AXLR bytes for cam_latents.bin."""
    parts = [MAGIC_LATENT_FILE]
    for pkt in packets:
        payload = _pack_payload(pkt)
        header  = struct.pack(REC_HEADER_FMT, MAGIC_LATENT_REC, VERSION, pkt.seq, len(payload))
        parts.append(header + payload)
    return b"".join(parts)


def build_streams_parquet(packets: list[PacketRecord], out_path: Path) -> None:
    """Write ext/streams@1.parquet — spoke domain extension; genesis ignores ext/."""
    rows = []
    for i, pkt in enumerate(packets):
        offset  = FILE_HEADER_LEN + i * LATENT_REC_LEN
        b3_hex  = pkt.packet_blake3.hex() if pkt.packet_blake3 else ""
        status  = (
            "unverified" if pkt.verdict_pass is None
            else "pass" if pkt.verdict_pass
            else "fail"
        )
        rows.append({
            "frame_id":     pkt.seq,
            "stream":       "custody",
            "file":         "cam_latents.bin",
            "offset":       offset,
            "length":       LATENT_REC_LEN,
            "status":       status,
            "content_hash": b3_hex,
        })

    table = pa.Table.from_pylist(rows, schema=STREAMS_SCHEMA)
    table = table.sort_by([
        ("stream",   "ascending"),
        ("frame_id", "ascending"),
        ("offset",   "ascending"),
    ])
    pq.write_table(table, out_path, compression="snappy")
