"""
Tests for axm_sfn.streams — AXLF/AXLR serialization.

Checklist items covered:
  §4  test_payload_length
  §9  test_build_axlf_stream_continuity
  §9  test_build_axlf_stream_gap
"""
import struct

import pytest

from axm_sfn.streams import _pack_payload, build_axlf_stream
from axm_sfn_core.protocol import (
    FILE_HEADER_LEN,
    LATENT_DIM,
    LATENT_REC_LEN,
    MAGIC_LATENT_FILE,
    MAGIC_LATENT_REC,
    REC_HEADER_FMT,
    VERSION,
)
from tests.conftest import make_packets


# ── §4 / checklist §9: payload length ────────────────────────────────────────

def test_payload_length():
    """_pack_payload must return exactly LATENT_DIM (256) bytes."""
    pkts = make_packets(1)
    payload = _pack_payload(pkts[0])
    assert len(payload) == LATENT_DIM, f"expected {LATENT_DIM}, got {len(payload)}"


def test_payload_length_no_hashes():
    """Payload is still 256 bytes when packet_blake3 and packet_sha256 are None."""
    from axm_sfn.db import PacketRecord
    pkt = PacketRecord(
        seq=0,
        tick_utc="2025-01-01T00:00:00Z",
        tick_mono_ns=0,
        telemetry={},
        packet_blake3=None,
        packet_sha256=None,
        tpm_sig=None,
        anomaly_extruder=False,
        anomaly_bed=False,
        anomaly_load_cell=False,
        verdict_pass=None,
        profile_id=None,
        violations=[],
    )
    assert len(_pack_payload(pkt)) == LATENT_DIM


# ── §9: stream structure and continuity ──────────────────────────────────────

def _parse_records(raw: bytes) -> list[dict]:
    """Parse AXLF file back into a list of record dicts for assertions."""
    assert raw[:FILE_HEADER_LEN] == MAGIC_LATENT_FILE, "missing AXLF magic"
    header_size = struct.calcsize(REC_HEADER_FMT)
    offset = FILE_HEADER_LEN
    records = []
    while offset < len(raw):
        magic, version, frame_id, payload_len = struct.unpack_from(REC_HEADER_FMT, raw, offset)
        assert magic == MAGIC_LATENT_REC, f"bad record magic at offset {offset}"
        assert version == VERSION
        offset += header_size
        payload = raw[offset : offset + payload_len]
        offset += payload_len
        records.append({"frame_id": frame_id, "payload": payload})
    return records


def test_build_axlf_stream_continuity():
    """10 sequential packets produce a well-formed AXLF stream with no gaps."""
    n = 10
    pkts = make_packets(n)
    raw = build_axlf_stream(pkts)

    records = _parse_records(raw)
    assert len(records) == n

    for i, rec in enumerate(records):
        assert rec["frame_id"] == i, f"frame_id mismatch at position {i}: got {rec['frame_id']}"
        assert len(rec["payload"]) == LATENT_DIM


def test_build_axlf_stream_total_size():
    """Total byte length matches FILE_HEADER_LEN + n * LATENT_REC_LEN."""
    n = 5
    pkts = make_packets(n)
    raw = build_axlf_stream(pkts)
    expected = FILE_HEADER_LEN + n * LATENT_REC_LEN
    assert len(raw) == expected, f"expected {expected} bytes, got {len(raw)}"


def test_build_axlf_stream_frame_ids_match_seq():
    """frame_id in each AXLR record must equal pkt.seq."""
    pkts = make_packets(5)
    raw = build_axlf_stream(pkts)
    records = _parse_records(raw)
    for pkt, rec in zip(pkts, records):
        assert rec["frame_id"] == pkt.seq


def test_build_axlf_stream_gap():
    """
    Dropping a packet creates a gap in frame_id sequence.

    We do NOT import axm_verify here (may not be installed), so we validate
    the gap directly by inspecting the frame_id sequence. When axm_verify IS
    installed, _validate_hot_stream_continuity would emit E_BUFFER_DISCONTINUITY
    on this exact input.
    """
    pkts = make_packets(10)
    pkts_with_gap = pkts[:4] + pkts[5:]   # drop seq=4, gap between 3 and 5

    raw = build_axlf_stream(pkts_with_gap)
    records = _parse_records(raw)

    frame_ids = [r["frame_id"] for r in records]
    # There must be a non-unit step somewhere
    gaps = [frame_ids[i+1] - frame_ids[i] for i in range(len(frame_ids) - 1)]
    assert any(g > 1 for g in gaps), "expected a gap in frame_id sequence but found none"


def test_build_axlf_stream_gap_axm_verify():
    """If axm_verify is installed, E_BUFFER_DISCONTINUITY fires on a gap."""
    pytest.importorskip("axm_verify", reason="axm-core not installed")
    from axm_verify.logic import _validate_hot_stream_continuity

    pkts = make_packets(10)
    pkts_with_gap = pkts[:4] + pkts[5:]
    raw = build_axlf_stream(pkts_with_gap)

    errors = _validate_hot_stream_continuity(raw)
    codes = [e.get("code") for e in errors]
    assert "E_BUFFER_DISCONTINUITY" in codes


def test_build_axlf_stream_continuity_axm_verify():
    """If axm_verify is installed, a clean stream has no E_BUFFER_DISCONTINUITY."""
    pytest.importorskip("axm_verify", reason="axm-core not installed")
    from axm_verify.logic import _validate_hot_stream_continuity

    raw = build_axlf_stream(make_packets(10))
    errors = _validate_hot_stream_continuity(raw)
    disc = [e for e in errors if e.get("code") == "E_BUFFER_DISCONTINUITY"]
    assert disc == [], f"unexpected discontinuity errors: {disc}"
