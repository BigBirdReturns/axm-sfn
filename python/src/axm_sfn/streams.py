"""
Serialize custody packets to the AXLF/AXLR binary stream (cam_latents.bin)
and build the streams@1 / packets@1 extension rows (canonical JSONL, fed to
the kernel compiler via extra_ext — RFC 0006; no Parquet, no reseal).

Each custody tick maps to one AXLR record. The 256-byte payload encodes the
packet's cryptographic fingerprint so that any holder of the shard can verify
the BLAKE3 chain link without the Go daemon.

Payload layout (256 bytes, little-endian):
  [0:32]    packet_blake3  — BLAKE3 chain link  (zeros if not yet computed)
  [32:64]   packet_sha256  — SHA-256 of canonical bytes (TPM-signable digest)
  [64]      verdict        — 0=PASS  1=FAIL  0xFF=no active profile
  [65]      tpm_present    — 1 if tpm_sig non-null, else 0
  [66:74]   seq            — uint64 LE (redundant with frame_id for convenience)
  [74]      attestation_class — 0=none  1=TPM 2.0
  [75]      sig_alg        — 0=none  1=TPMT_SIGNATURE (RSA-PSS-2048/SHA-256)
  [76:108]  sign_key_fp    — SHA-256 of the signing key's public area
                             (the TPM2B_PUBLIC bytes in ext/tpm-attestation@1);
                             zeros if the key material is unknown
  [108:256] reserved       — zeros

Bytes 74–107 were reserved-as-zeros in the original layout; allocating them
is backward compatible (old readers ignore them, old streams parse as
attestation_class=0). A 2045 verifier reads these to know which algorithm
and key to try before touching ext/tpm-attestation@1.
"""
import struct
from hashlib import sha256
from typing import Optional

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

# Content path (under the shard's content/ dir) that holds the verbatim
# canonical packet bytes indexed by ext/packets@1 (RFC 0006).
PACKETS_CONTENT_FILE = "content/packets.bin"

# Payload identifiers — values are frozen once production shards exist.
ATTESTATION_CLASS_NONE  = 0
ATTESTATION_CLASS_TPM20 = 1
SIG_ALG_NONE                = 0
SIG_ALG_TPMT_RSAPSS_SHA256  = 1   # marshalled TPMT_SIGNATURE, RSA-PSS-2048/SHA-256

_CORE_FMT = struct.Struct("<32s32sBBQBB32s")  # 108 bytes; remainder padded to LATENT_DIM
_PAD_LEN  = LATENT_DIM - _CORE_FMT.size       # 148 bytes


def _pack_payload(pkt: PacketRecord, sign_key_fp: Optional[bytes] = None) -> bytes:
    b3  = pkt.packet_blake3 or b"\x00" * 32
    sha = pkt.packet_sha256 or b"\x00" * 32
    verdict = (
        0xFF if pkt.verdict_pass is None
        else 0 if pkt.verdict_pass
        else 1
    )
    tpm = 1 if pkt.tpm_sig else 0
    att_class = ATTESTATION_CLASS_TPM20 if pkt.tpm_sig else ATTESTATION_CLASS_NONE
    sig_alg   = SIG_ALG_TPMT_RSAPSS_SHA256 if pkt.tpm_sig else SIG_ALG_NONE
    fp        = sign_key_fp if pkt.tpm_sig and sign_key_fp else b"\x00" * 32
    if len(fp) != 32:
        raise ValueError(f"sign_key_fp must be 32 bytes (SHA-256), got {len(fp)}")
    payload = _CORE_FMT.pack(b3, sha, verdict, tpm, pkt.seq, att_class, sig_alg, fp) \
              + b"\x00" * _PAD_LEN
    assert len(payload) == LATENT_DIM, f"payload must be {LATENT_DIM} bytes, got {len(payload)}"
    return payload


def build_axlf_stream(packets: list[PacketRecord], sign_key_fp: Optional[bytes] = None) -> bytes:
    """Return raw AXLF/AXLR bytes for cam_latents.bin.

    sign_key_fp: SHA-256 of the TPM signing key's public area (32 bytes),
    stamped into each TPM-signed record so a spec-only verifier knows which
    key in ext/tpm-attestation@1 covers the packet signatures.
    """
    parts = [MAGIC_LATENT_FILE]
    for pkt in packets:
        payload = _pack_payload(pkt, sign_key_fp)
        header  = struct.pack(REC_HEADER_FMT, MAGIC_LATENT_REC, VERSION, pkt.seq, len(payload))
        parts.append(header + payload)
    return b"".join(parts)


def build_streams_rows(packets: list[PacketRecord]) -> list[dict]:
    """Rows for ext/streams@1.jsonl — AXLR record locators into cam_latents.bin.

    Fed to compile_generic_shard via extra_ext; the kernel writes canonical
    JSONL and seals it. genesis treats ext/ as opaque.
    """
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
    return rows


# ── ext/packets@1 — verbatim canonical packet bytes ───────────────────────────
#
# The archival rule is hash-over-stored-bytes: packet_sha256 (in the AXLR
# payload) MUST equal SHA-256 of the `canonical` column, byte for byte. The
# canonicalization that produced those bytes (Go encoding/json over the
# CustodyPacket struct) is deliberately NOT part of the verification contract —
# a spec-only reimplementer never has to reproduce Go's float formatting.

def build_packets(packets: list[PacketRecord]) -> tuple[list[dict], bytes]:
    """Build the ext/packets@1 index and the verbatim-bytes content blob.

    The exact canonical packet bytes are concatenated into one content leaf
    (content/packets.bin); each row indexes its slice by (offset, length) and
    carries packet_sha256. Returns (rows, blob); ([], b"") when no canonical
    bytes are available. Raises if any stored bytes fail the
    hash-over-stored-bytes rule — a mismatch means the hot buffer is corrupt
    and must never be sealed into a shard.
    """
    rows: list[dict] = []
    blob = bytearray()
    for pkt in packets:
        if pkt.telemetry_raw is None:
            continue
        if pkt.packet_sha256 and sha256(pkt.telemetry_raw).digest() != pkt.packet_sha256:
            raise ValueError(
                f"packet seq={pkt.seq}: stored canonical bytes do not hash to "
                f"packet_sha256 — hot buffer is corrupt, refusing to seal"
            )
        offset = len(blob)
        blob.extend(pkt.telemetry_raw)
        rows.append({
            "seq":           pkt.seq,
            "file":          PACKETS_CONTENT_FILE,
            "offset":        offset,
            "length":        len(pkt.telemetry_raw),
            "packet_sha256": sha256(pkt.telemetry_raw).hexdigest(),
        })
    return rows, bytes(blob)
