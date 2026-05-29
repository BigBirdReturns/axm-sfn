"""
Shared fixtures for axm-sfn spoke tests.

All tests run entirely offline — no axm-core, no SQLite daemon, no TPM.
The two tests that call compile_session or verify_shard are skipped when
axm-core is not installed.
"""
import struct
import pytest

from axm_sfn.db import PacketRecord, SessionData, ProvenanceFault
from axm_sfn_core.protocol import LATENT_DIM


def _make_packet(seq: int, *, verdict_pass=True, tpm_sig=None) -> PacketRecord:
    b3  = bytes([seq & 0xFF]) * 32
    sha = bytes([(seq + 1) & 0xFF]) * 32
    return PacketRecord(
        seq=seq,
        tick_utc=f"2025-01-01T00:00:{seq:02d}Z",
        tick_mono_ns=seq * 1_000_000_000,
        telemetry={
            "extruder_temp": 210.0 + seq * 0.1,
            "bed_temp": 60.0,
        },
        packet_blake3=b3,
        packet_sha256=sha,
        tpm_sig=tpm_sig,
        anomaly_extruder=False,
        anomaly_bed=False,
        anomaly_load_cell=False,
        verdict_pass=verdict_pass,
        profile_id="test-profile",
        violations=[],
    )


def make_packets(n: int) -> list[PacketRecord]:
    return [_make_packet(i) for i in range(n)]


def make_session(packets, faults=None) -> SessionData:
    return SessionData(
        session_id="test-session-001",
        printer_id="printer-test",
        node_label="node-test",
        mpf_id=None,
        packets=packets,
        faults=faults or [],
    )
