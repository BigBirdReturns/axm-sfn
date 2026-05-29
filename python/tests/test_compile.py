"""
Tests for axm_sfn.compile — session compilation and candidate extraction.

Checklist items covered:
  §2  test_private_key_length_guard
  §6  test_candidates_evidence_uniqueness
  §9  test_compile_session_end_to_end  (skipped without axm-core)

All tests in this file require axm-core to be installed because compile.py
imports from axm_build at module level. The module-level importorskip skips
the entire file gracefully when axm-core is absent.
"""
import json
import sqlite3
import tempfile
from pathlib import Path

import pytest

# Skip the entire module when axm-core is absent — every function here
# transitively imports from axm_build or axm_verify.
pytest.importorskip("axm_build", reason="axm-core not installed — skip compile tests")
pytest.importorskip("axm_verify", reason="axm-core not installed — skip compile tests")

from axm_build.sign import SUITE_ED25519, SUITE_MLDSA44  # noqa: E402
from axm_sfn.compile import build_candidates, build_journal_text, compile_session  # noqa: E402
from tests.conftest import make_packets, make_session  # noqa: E402


# ── §2: private key length guard ─────────────────────────────────────────────

def test_private_key_length_guard_rejects_wrong_length():
    """compile_session raises ValueError when ML-DSA-44 key is neither 2528 nor 3840 bytes."""
    with tempfile.TemporaryDirectory() as tmp:
        db  = Path(tmp) / "buf.db"
        out = Path(tmp) / "out"
        # 64 bytes — wrong length for ML-DSA-44
        with pytest.raises(ValueError, match="ML-DSA-44 key must be"):
            compile_session(db, "s1", b"\x00" * 64, out, suite=SUITE_MLDSA44)


def test_private_key_length_guard_accepts_sk_only():
    """Guard passes for 2528-byte key; failure comes from missing db, not the guard."""
    with tempfile.TemporaryDirectory() as tmp:
        db  = Path(tmp) / "buf.db"
        out = Path(tmp) / "out"
        with pytest.raises(Exception) as exc_info:
            compile_session(db, "s1", b"\x00" * 2528, out, suite=SUITE_MLDSA44)
        assert "ML-DSA-44 key must be" not in str(exc_info.value)


def test_private_key_length_guard_accepts_sk_pk():
    """Guard passes for 3840-byte key; failure comes from missing db, not the guard."""
    with tempfile.TemporaryDirectory() as tmp:
        db  = Path(tmp) / "buf.db"
        out = Path(tmp) / "out"
        with pytest.raises(Exception) as exc_info:
            compile_session(db, "s1", b"\x00" * 3840, out, suite=SUITE_MLDSA44)
        assert "ML-DSA-44 key must be" not in str(exc_info.value)


def test_private_key_length_guard_ed25519_not_checked():
    """Ed25519 path has no length guard — any length reaches load_session."""
    with tempfile.TemporaryDirectory() as tmp:
        db  = Path(tmp) / "buf.db"
        out = Path(tmp) / "out"
        with pytest.raises(Exception) as exc_info:
            compile_session(db, "s1", b"\x00" * 3840, out, suite=SUITE_ED25519)
        assert "ML-DSA-44 key must be" not in str(exc_info.value)


# ── §6: candidates evidence uniqueness ───────────────────────────────────────

def test_candidates_evidence_uniqueness_clean():
    """build_candidates succeeds when every evidence string appears exactly once."""
    pkts  = make_packets(3)
    sd    = make_session(pkts)
    txt   = build_journal_text(sd)
    cands = build_candidates(sd, txt)
    for c in cands:
        assert txt.count(c["evidence"]) == 1, (
            f"evidence appears {txt.count(c['evidence'])} times: {c['evidence']!r}"
        )


def test_candidates_evidence_uniqueness_raises_on_duplicate():
    """build_candidates raises ValueError before writing when evidence appears twice."""
    pkts = make_packets(3)
    sd   = make_session(pkts)
    txt  = build_journal_text(sd)
    # Force a duplicate occurrence of the session_id evidence line
    duplicated = txt + f"\nsession_id: {sd.session_id}\n"
    with pytest.raises(ValueError, match="exactly once"):
        build_candidates(sd, duplicated)


# ── §9: end-to-end compile + verify ──────────────────────────────────────────

def _write_buffer_db(db_path: Path, session_id: str, packets) -> None:
    """Write a minimal buffer.db that db.load_session can read."""
    con = sqlite3.connect(db_path)
    con.execute("""
        CREATE TABLE packets (
            seq               INTEGER PRIMARY KEY,
            session_id        TEXT NOT NULL,
            telemetry_json    TEXT NOT NULL,
            packet_blake3     TEXT,
            packet_sha256     TEXT,
            tpm_sig           TEXT,
            anomaly_extruder  INTEGER DEFAULT 0,
            anomaly_bed       INTEGER DEFAULT 0,
            anomaly_load_cell INTEGER DEFAULT 0,
            recovered_from_cache INTEGER DEFAULT 0,
            tick_utc          TEXT,
            tick_mono_ns      INTEGER,
            verdict_pass      INTEGER,
            profile_id        TEXT,
            violations_json   TEXT
        )
    """)
    con.execute("""
        CREATE TABLE provenance_faults (
            seq         INTEGER,
            reason      TEXT,
            detected_at TEXT
        )
    """)
    for p in packets:
        con.execute(
            "INSERT INTO packets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                p.seq,
                session_id,
                json.dumps(p.telemetry),
                p.packet_blake3.hex() if p.packet_blake3 else None,
                p.packet_sha256.hex() if p.packet_sha256 else None,
                p.tpm_sig.hex() if p.tpm_sig else None,
                int(p.anomaly_extruder),
                int(p.anomaly_bed),
                int(p.anomaly_load_cell),
                0,
                p.tick_utc,
                p.tick_mono_ns,
                (1 if p.verdict_pass is True else (0 if p.verdict_pass is False else None)),
                p.profile_id,
                json.dumps(p.violations),
            ),
        )
    con.commit()
    con.close()


def test_compile_session_end_to_end(tmp_path):
    """
    Synthetic buffer.db → compile_session → verify_shard must return PASS.

    This is the key integration smoke test: it exercises the full two-pass
    reseal (cam_latents.bin injection, Merkle recompute, re-sign) and confirms
    the frozen kernel accepts the output.
    """
    from axm_build.sign import generate_keypair

    session_id = "test-session-e2e"
    pkts       = make_packets(5)
    db         = tmp_path / "buffer.db"
    _write_buffer_db(db, session_id, pkts)

    sk_pk = generate_keypair(SUITE_MLDSA44)   # sk||pk, 3840 bytes
    out   = tmp_path / "shards"
    shard = compile_session(db, session_id, sk_pk, out, suite=SUITE_MLDSA44)

    from axm_verify.logic import verify_shard
    pub_path = shard / "sig" / "publisher.pub"
    result   = verify_shard(shard, trusted_key_path=pub_path)
    assert result["status"] == "PASS",      f"verify_shard failed: {result}"
    assert result["error_count"] == 0,      f"unexpected errors: {result['errors']}"
