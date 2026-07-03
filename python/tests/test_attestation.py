"""
Tests for the attestation-evidence pipeline (ext/attestation@1, ext/packets@1,
AXLR payload attestation fields).

The point of these artifacts is sealed-before-break archival validity: a
verifier holding ONLY the shard must be able to check the TPM evidence and
recompute the BLAKE3 chain with no access to buffer.db or the Go daemon.
test_chain_recompute_from_shard_artifacts exercises exactly that.
"""
import json
import struct
from hashlib import sha256

import pytest

from axm_sfn.attestation import (
    ALG_TPM2B_PUBLIC,
    ALG_TPMT_SIG_RSAPSS,
    ALG_X509_DER,
    build_tpm_attestation,
    key_fingerprint,
    sign_key_fingerprint,
)
from axm_sfn.db import AttestationKey, PacketRecord, QuoteRecord
from axm_sfn.streams import (
    ATTESTATION_CLASS_NONE,
    ATTESTATION_CLASS_TPM20,
    SIG_ALG_NONE,
    SIG_ALG_TPMT_RSAPSS_SHA256,
    _pack_payload,
    build_packets,
)
from axm_sfn_core.protocol import FILE_HEADER_LEN, LATENT_REC_LEN, REC_HEADER_LEN
from tests.conftest import _make_packet, make_packets, make_session

_PAYLOAD_FMT = struct.Struct("<32s32sBBQBB32s")

_FAKE_SIGN_PUB = b"\x01\x3a" + b"sign-pub-tpm2b-public" * 12   # opaque TPM2B_PUBLIC stand-in
_FAKE_AK_PUB   = b"\x01\x3a" + b"ak-pub-tpm2b-public" * 13
_FAKE_EK_CERT  = b"\x30\x82" + b"ek-cert-der" * 20


def _keys():
    return [
        AttestationKey("sign_pub", ALG_TPM2B_PUBLIC, _FAKE_SIGN_PUB, "2025-01-01T00:00:00Z"),
        AttestationKey("ak_pub",   ALG_TPM2B_PUBLIC, _FAKE_AK_PUB,   "2025-01-01T00:00:00Z"),
        AttestationKey("ek_cert",  ALG_X509_DER,     _FAKE_EK_CERT,  "2025-01-01T00:00:00Z"),
    ]


def _parse_payloads(raw: bytes) -> list[tuple]:
    payloads = []
    offset = FILE_HEADER_LEN
    while offset < len(raw):
        payloads.append(_PAYLOAD_FMT.unpack_from(raw, offset + REC_HEADER_LEN))
        offset += LATENT_REC_LEN
    return payloads


# ── AXLR payload attestation fields ──────────────────────────────────────────

def test_payload_attestation_fields_signed():
    fp  = sha256(_FAKE_SIGN_PUB).digest()
    pkt = _make_packet(3, tpm_sig=b"\xaa" * 64)
    payload = _pack_payload(pkt, sign_key_fp=fp)
    _, _, _, tpm, seq, att_class, sig_alg, got_fp = _PAYLOAD_FMT.unpack(payload[:_PAYLOAD_FMT.size])
    assert tpm == 1
    assert att_class == ATTESTATION_CLASS_TPM20
    assert sig_alg == SIG_ALG_TPMT_RSAPSS_SHA256
    assert got_fp == fp


def test_payload_attestation_fields_unsigned():
    """No TPM sig → class/alg/fingerprint all zero, even when a fp is passed."""
    fp  = sha256(_FAKE_SIGN_PUB).digest()
    payload = _pack_payload(_make_packet(3), sign_key_fp=fp)
    _, _, _, tpm, _, att_class, sig_alg, got_fp = _PAYLOAD_FMT.unpack(payload[:_PAYLOAD_FMT.size])
    assert tpm == 0
    assert att_class == ATTESTATION_CLASS_NONE
    assert sig_alg == SIG_ALG_NONE
    assert got_fp == b"\x00" * 32


def test_payload_rejects_bad_fingerprint_length():
    pkt = _make_packet(0, tpm_sig=b"\xaa" * 64)
    with pytest.raises(ValueError, match="32 bytes"):
        _pack_payload(pkt, sign_key_fp=b"\x01" * 16)


# ── ext/packets@1 ────────────────────────────────────────────────────────────

def test_packets_index_hash_over_stored_bytes():
    pkts = make_packets(4)
    rows, blob = build_packets(pkts)
    assert len(rows) == 4
    by_seq = {r["seq"]: r for r in rows}
    for p in pkts:
        r = by_seq[p.seq]
        stored = bytes(blob[r["offset"]:r["offset"] + r["length"]])
        assert sha256(stored).digest() == p.packet_sha256
        assert r["packet_sha256"] == p.packet_sha256.hex()
        assert r["file"] == "content/packets.bin"


def test_packets_index_refuses_corrupt_buffer():
    pkts = make_packets(2)
    pkts[1].telemetry_raw = b'{"tampered": true}'
    with pytest.raises(ValueError, match="corrupt"):
        build_packets(pkts)


def test_packets_index_empty_without_raw_bytes():
    pkts = make_packets(2)
    for p in pkts:
        p.telemetry_raw = None
    rows, blob = build_packets(pkts)
    assert rows == [] and blob == b""


# ── ext/attestation@1 ────────────────────────────────────────────────────────

def _evidence_session():
    pkts = [_make_packet(i, tpm_sig=bytes([0x50 + i]) * 96) for i in range(3)]
    quote = QuoteRecord(
        seq=0,
        pcrs=[10, 11, 12, 15],
        nonce=b"\x07" * 32,
        attest_blob=b"\xffTCG-attest" * 8,
        sig=b"\x51" * 96,
        ak_handle=0x81000002,
        created_at="2025-01-01T00:00:00Z",
    )
    sd = make_session(pkts)
    sd.quotes = [quote]
    sd.attestation_keys = _keys()
    return sd


def test_tpm_attestation_contents():
    sd = _evidence_session()
    rows, blob = build_tpm_attestation(sd)

    def _slice(r):
        return bytes(blob[r["offset"]:r["offset"] + r["length"]])

    by_kind: dict[str, list] = {}
    for r in rows:
        assert r["file"] == "content/tpm-attestation.bin"
        assert r["sha256"] == sha256(_slice(r)).hexdigest()   # index matches stored bytes
        by_kind.setdefault(r["kind"], []).append(r)

    # One packet_sig row per TPM-signed packet; the stored blob is the signature.
    assert len(by_kind["packet_sig"]) == 3
    for r in by_kind["packet_sig"]:
        assert r["field"] == "signature"
        assert r["alg"] == ALG_TPMT_SIG_RSAPSS
        assert r["key_fingerprint"] == sha256(_FAKE_SIGN_PUB).hexdigest()
        assert _slice(r) == sd.packets[r["seq"]].tpm_sig

    # A quote fans out to signature / attest / nonce rows sharing its seq.
    q_by_field = {r["field"]: r for r in by_kind["quote"]}
    assert set(q_by_field) == {"signature", "attest", "nonce"}
    assert all(r["key_fingerprint"] == sha256(_FAKE_AK_PUB).hexdigest() for r in by_kind["quote"])
    assert _slice(q_by_field["attest"]) == sd.quotes[0].attest_blob
    assert _slice(q_by_field["nonce"]) == sd.quotes[0].nonce
    assert json.loads(q_by_field["attest"]["pcrs"]) == [10, 11, 12, 15]

    # Key/cert rows: seq 0, self-fingerprint over the stored bytes.
    for role, kb in [("sign_pub", _FAKE_SIGN_PUB), ("ak_pub", _FAKE_AK_PUB), ("ek_cert", _FAKE_EK_CERT)]:
        (k,) = by_kind[role]
        assert k["seq"] == 0
        assert _slice(k) == kb
        assert k["key_fingerprint"] == key_fingerprint(kb)


def test_tpm_attestation_absent_without_evidence():
    rows, blob = build_tpm_attestation(make_session(make_packets(3)))  # no evidence
    assert rows == [] and blob == b""


def test_sign_key_fingerprint_helper():
    sd = _evidence_session()
    assert sign_key_fingerprint(sd) == sha256(_FAKE_SIGN_PUB).digest()
    sd.attestation_keys = []
    assert sign_key_fingerprint(sd) is None


# ── The archival property: shard-only verification ───────────────────────────

def _go_style_packets(session_id: str, n: int) -> list[PacketRecord]:
    """Packets whose hashes are computed exactly the way the Go daemon does:
    sha256 over the canonical bytes, blake3 chain link over
    0x00 || seq_le || session_id || canonical || tpm_sig || prev.
    """
    import blake3

    pkts = []
    prev = None
    for seq in range(n):
        telemetry = {
            "session_id": session_id,
            "seq": seq,
            "extruder_temp": 210.0 + seq,
            "bed_temp": 60.0,
        }
        canonical = json.dumps(telemetry, separators=(",", ":")).encode()
        sha = sha256(canonical).digest()
        tpm_sig = bytes([0x60 + seq]) * 96

        h = blake3.blake3()
        h.update(b"\x00")
        h.update(struct.pack("<Q", seq))
        h.update(session_id.encode())
        h.update(canonical)
        h.update(tpm_sig)
        if prev is not None:
            h.update(prev)
        b3 = h.digest()

        pkts.append(PacketRecord(
            seq=seq,
            tick_utc=f"2025-01-01T00:00:{seq:02d}Z",
            tick_mono_ns=seq * 1_000_000_000,
            telemetry=telemetry,
            packet_blake3=b3,
            packet_sha256=sha,
            tpm_sig=tpm_sig,
            anomaly_extruder=False,
            anomaly_bed=False,
            anomaly_load_cell=False,
            verdict_pass=True,
            profile_id="test-profile",
            violations=[],
            telemetry_raw=canonical,
        ))
        prev = b3
    return pkts


def test_chain_recompute_from_shard_artifacts(tmp_path):
    """Compile a shard with full TPM evidence, then verify the custody chain
    using ONLY files inside the shard — the sealed-before-break property.
    """
    pytest.importorskip("axm_build", reason="axm-genesis not installed")
    pytest.importorskip("axm_verify", reason="axm-genesis not installed")
    import blake3
    from axm_build.sign import hybrid1_keygen
    from axm_sfn.compile import compile_session
    from axm_verify.logic import verify_shard
    from tests.test_compile import _write_buffer_db

    session_id = "test-session-attest"
    pkts = _go_style_packets(session_id, 5)
    db = tmp_path / "buffer.db"
    _write_buffer_db(
        db, session_id, pkts,
        quotes=[(0, json.dumps([10, 11, 12, 15]), b"\x07" * 32, b"\xffattest" * 8, b"\x51" * 96, 0x81000002)],
        keys=[(k.role, k.alg, k.data) for k in _keys()],
    )

    _pub, secret_key = hybrid1_keygen()
    shard = compile_session(db, session_id, secret_key, tmp_path / "shards")

    # The frozen kernel accepts the shard with all three ext/ tables.
    result = verify_shard(shard, trusted_key_path=shard / "sig" / "publisher.pub")
    assert result["status"] == "PASS", f"verify_shard failed: {result}"

    manifest = json.loads((shard / "manifest.json").read_bytes())
    assert set(manifest["extensions"]) == {"streams@1", "packets@1", "tpm-attestation@1"}

    # ── From here on, use ONLY shard contents ─────────────────────────────────
    def _read_jsonl(p):
        return [json.loads(line) for line in p.read_bytes().splitlines() if line]

    raw = (shard / "content" / "cam_latents.bin").read_bytes()
    payloads = _parse_payloads(raw)

    # packets@1 indexes verbatim bytes in content/packets.bin.
    packets_blob = (shard / "content" / "packets.bin").read_bytes()
    canon = {r["seq"]: packets_blob[r["offset"]:r["offset"] + r["length"]]
             for r in _read_jsonl(shard / "ext" / "packets@1.jsonl")}

    # tpm-attestation@1 indexes blobs in content/tpm-attestation.bin.
    tpm_blob = (shard / "content" / "tpm-attestation.bin").read_bytes()
    att_rows = _read_jsonl(shard / "ext" / "tpm-attestation@1.jsonl")

    def _blob(r):
        return tpm_blob[r["offset"]:r["offset"] + r["length"]]

    sigs = {r["seq"]: _blob(r) for r in att_rows if r["kind"] == "packet_sig"}
    keys = {r["kind"]: _blob(r) for r in att_rows
            if r["kind"] in ("sign_pub", "ak_pub", "ek_cert")}

    prev = None
    for b3_link, sha_digest, verdict, tpm, seq, att_class, sig_alg, fp in payloads:
        # Rule 1 — hash-over-stored-bytes.
        assert sha256(canon[seq]).digest() == sha_digest
        # Rule 2 — payload identifiers point at the sealed key material.
        assert tpm == 1 and att_class == ATTESTATION_CLASS_TPM20
        assert sig_alg == SIG_ALG_TPMT_RSAPSS_SHA256
        assert fp == sha256(keys["sign_pub"]).digest()
        # Rule 3 — full BLAKE3 chain recomputation.
        h = blake3.blake3()
        h.update(b"\x00")
        h.update(struct.pack("<Q", seq))
        h.update(session_id.encode())
        h.update(canon[seq])
        h.update(sigs[seq])
        if prev is not None:
            h.update(prev)
        assert h.digest() == b3_link, f"chain link mismatch at seq={seq}"
        prev = b3_link
