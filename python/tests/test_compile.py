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

# Skip the entire module when the kernel is absent — every function here
# transitively imports from axm_build or axm_verify.
pytest.importorskip("axm_build", reason="axm-genesis not installed — skip compile tests")
pytest.importorskip("axm_verify", reason="axm-genesis not installed — skip compile tests")

from axm_build.sign import HYBRID1_SK_LEN  # noqa: E402
from axm_sfn.compile import build_candidates, build_journal_text, compile_session  # noqa: E402
from tests.conftest import make_packets, make_session  # noqa: E402


# ── §2: private key length guard ─────────────────────────────────────────────

def test_private_key_length_guard_rejects_wrong_length():
    """compile_session raises ValueError when the key is not a 3904-byte hybrid1 blob."""
    with tempfile.TemporaryDirectory() as tmp:
        db  = Path(tmp) / "buf.db"
        out = Path(tmp) / "out"
        with pytest.raises(ValueError, match="3904-byte axm-hybrid1"):
            compile_session(db, "s1", b"\x00" * 64, out)


def test_private_key_length_guard_accepts_correct_length():
    """Guard passes for a 3904-byte key; failure then comes from the missing db."""
    with tempfile.TemporaryDirectory() as tmp:
        db  = Path(tmp) / "buf.db"
        out = Path(tmp) / "out"
        with pytest.raises(Exception) as exc_info:
            compile_session(db, "s1", b"\x00" * HYBRID1_SK_LEN, out)
        assert "3904-byte axm-hybrid1" not in str(exc_info.value)


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

def _write_buffer_db(db_path: Path, session_id: str, packets, quotes=None, keys=None) -> None:
    """Write a minimal buffer.db that db.load_session can read.

    quotes: optional list of (seq, pcrs_json, nonce, attest_blob, sig, ak_handle)
    keys:   optional list of (role, alg, data)
    """
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
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT NOT NULL,
            seq         INTEGER,
            reason      TEXT,
            detected_at TEXT
        )
    """)
    con.execute("""
        CREATE TABLE quotes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT    NOT NULL,
            seq         INTEGER NOT NULL,
            pcrs        TEXT    NOT NULL,
            nonce       BLOB    NOT NULL,
            attest_blob BLOB    NOT NULL,
            sig         BLOB    NOT NULL,
            ak_handle   INTEGER NOT NULL,
            created_at  TEXT    NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE attestation_keys (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            role        TEXT NOT NULL,
            alg         TEXT NOT NULL,
            data        BLOB NOT NULL,
            created_at  TEXT NOT NULL
        )
    """)
    for p in packets:
        telemetry_json = (
            p.telemetry_raw.decode("utf-8") if p.telemetry_raw
            else json.dumps(p.telemetry)
        )
        con.execute(
            "INSERT INTO packets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                p.seq,
                session_id,
                telemetry_json,
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
    for q in quotes or []:
        con.execute(
            "INSERT INTO quotes (session_id, seq, pcrs, nonce, attest_blob, sig, ak_handle, created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (session_id, *q, "2025-01-01T00:00:00Z"),
        )
    for k in keys or []:
        con.execute(
            "INSERT INTO attestation_keys (role, alg, data, created_at) VALUES (?,?,?,?)",
            (*k, "2025-01-01T00:00:00Z"),
        )
    con.commit()
    con.close()


def test_compile_session_end_to_end(tmp_path):
    """
    Synthetic buffer.db → compile_session → verify_shard must return PASS.

    The key integration smoke test: it exercises the ONE-pass compile
    (cam_latents.bin + registered ext tables via extra_content/extra_ext) and
    confirms the frozen kernel accepts the output. No reseal is performed.
    """
    from axm_build.sign import hybrid1_keygen

    session_id = "test-session-e2e"
    pkts       = make_packets(5)
    db         = tmp_path / "buffer.db"
    _write_buffer_db(db, session_id, pkts)

    _pub, secret_key = hybrid1_keygen()       # 3904-byte axm-hybrid1 secret
    out   = tmp_path / "shards"
    shard = compile_session(db, session_id, secret_key, out)

    from axm_verify.logic import verify_shard
    pub_path = shard / "sig" / "publisher.pub"
    result   = verify_shard(shard, trusted_key_path=pub_path)
    assert result["status"] == "PASS",      f"verify_shard failed: {result}"
    assert result["error_count"] == 0,      f"unexpected errors: {result['errors']}"

    # Identity is derived, never stored (spec §9).
    manifest = json.loads((shard / "manifest.json").read_bytes())
    assert "shard_id" not in manifest
    assert manifest["suite"] == "axm-hybrid1"
