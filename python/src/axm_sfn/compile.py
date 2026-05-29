"""
Compile an axm-sfn custody session into an AXM Layer 2 journal shard.

Follows the two-pass reseal pattern from axm-embodied (INV-28):
  Pass 1  compile_generic_shard over custody journal + claims
  Inject  cam_latents.bin  (AXLF/AXLR serialized custody stream)
  Pass 2  recompute Merkle root, re-sign, self-verify
"""
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from axm_build.compiler_generic import CompilerConfig, compile_generic_shard
from axm_build.manifest import dumps_canonical_json
from axm_build.merkle import compute_merkle_root
from axm_build.sign import SUITE_MLDSA44, mldsa44_sign
from axm_verify.logic import verify_shard
from nacl.signing import SigningKey

from axm_sfn.db import PacketRecord, SessionData, load_session
from axm_sfn.streams import build_axlf_stream, build_streams_parquet
from axm_sfn_core.ids import SFN_NAMESPACE

_PUBLISHER_ID   = "@axm_sfn"
_PUBLISHER_NAME = "AXM SFN"


# ── Journal text ──────────────────────────────────────────────────────────────

def _final_verdict(packets: list[PacketRecord]) -> str:
    return "FAIL" if any(p.verdict_pass is False for p in packets) else "PASS"


def build_journal_text(sd: SessionData) -> str:
    """Produce the byte-authoritative custody journal that becomes source.txt."""
    fv         = _final_verdict(sd.packets)
    first_tick = sd.packets[0].tick_utc if sd.packets else "—"
    last_tick  = sd.packets[-1].tick_utc if sd.packets else "—"
    pass_count = sum(1 for p in sd.packets if p.verdict_pass is True)
    fail_count = sum(1 for p in sd.packets if p.verdict_pass is False)

    lines = [
        "AXM SFN Custody Session",
        "=======================",
        f"session_id: {sd.session_id}",
        f"printer_id: {sd.printer_id}",
        f"node_label: {sd.node_label}",
        f"mpf_id: {sd.mpf_id or 'null'}",
        f"session_start: {first_tick}",
        f"session_end: {last_tick}",
        f"packet_count: {len(sd.packets)}",
        f"fault_count: {len(sd.faults)}",
        f"pass_count: {pass_count}",
        f"fail_count: {fail_count}",
        f"final_verdict: {fv}",
        "",
        "Custody Timeline",
        "----------------",
    ]

    for pkt in sd.packets:
        tel     = pkt.telemetry
        verdict = "PASS" if pkt.verdict_pass else ("FAIL" if pkt.verdict_pass is False else "----")
        quoted  = "quoted=true " if pkt.tpm_sig else "quoted=false"
        ext     = f"{tel.get('extruder_temp', 0.0):.3f}°C"
        bed     = f"{tel.get('bed_temp',      0.0):.3f}°C"
        b3      = (pkt.packet_blake3.hex()[:16] + "…") if pkt.packet_blake3 else "pending"
        lines.append(
            f"[seq={pkt.seq:<4d} tick={pkt.tick_utc}] {verdict} "
            f"{quoted} ext={ext} bed={bed} chain={b3}"
        )

    lines += ["", "Provenance Faults", "-----------------"]
    if sd.faults:
        for f in sd.faults:
            lines.append(f"[seq={f.seq}] {f.reason} at={f.detected_at}")
    else:
        lines.append("(none)")

    lines.append("")
    return "\n".join(lines)


# ── Candidates ────────────────────────────────────────────────────────────────

def build_candidates(sd: SessionData, source_text: str) -> list[dict]:
    """
    Build candidates.jsonl entries whose evidence strings each appear exactly
    once in source_text. The header-line format guarantees uniqueness because
    session IDs are unique and key prefixes (e.g. 'packet_count: ') don't
    recur in the timeline body.
    """
    fv         = _final_verdict(sd.packets)
    pass_count = sum(1 for p in sd.packets if p.verdict_pass is True)
    fail_count = sum(1 for p in sd.packets if p.verdict_pass is False)
    sid        = sd.session_id
    pid        = sd.printer_id
    mpf        = sd.mpf_id or "null"

    candidates = []

    def add(subject, predicate, obj, object_type, evidence, tier=2):
        count = source_text.count(evidence)
        if count != 1:
            raise ValueError(
                f"Evidence must appear exactly once in source.txt "
                f"(found {count}): {evidence!r}"
            )
        candidates.append({
            "subject":     subject,
            "predicate":   predicate,
            "object":      str(obj),
            "object_type": object_type,
            "tier":        tier,
            "evidence":    evidence,
        })

    add(pid, "completed_custody_session", sid,              "entity",          f"session_id: {sid}",              tier=1)
    add(sid, "recorded_by_node",          sd.node_label,    "entity",          f"node_label: {sd.node_label}",    tier=1)
    add(sid, "used_mpf",                  mpf,              "entity",          f"mpf_id: {mpf}",                  tier=1)
    add(sid, "packet_count",              len(sd.packets),  "literal:integer", f"packet_count: {len(sd.packets)}")
    add(sid, "fault_count",               len(sd.faults),   "literal:integer", f"fault_count: {len(sd.faults)}")
    add(sid, "pass_count",                pass_count,       "literal:integer", f"pass_count: {pass_count}")
    add(sid, "fail_count",                fail_count,       "literal:integer", f"fail_count: {fail_count}")
    add(sid, "final_verdict",             fv,               "literal:string",  f"final_verdict: {fv}",            tier=1)

    return candidates


# ── Compilation ───────────────────────────────────────────────────────────────

def compile_session(
    db_path: Path,
    session_id: str,
    private_key: bytes,
    out_dir: Path,
    suite: str = SUITE_MLDSA44,
    created_at: Optional[str] = None,
) -> Path:
    """
    Full two-pass compilation of a custody session into an AXM Layer 2 shard.

    private_key:
      ML-DSA-44  sk||pk concatenated = 3840 bytes (passed to CompilerConfig)
      Ed25519    raw seed             =   32 bytes

    Returns the path to the compiled shard directory.
    Raises on any compilation or verification failure.
    """
    if suite == SUITE_MLDSA44 and len(private_key) not in (2528, 3840):
        raise ValueError(
            f"ML-DSA-44 key must be 2528 (sk) or 3840 (sk||pk) bytes, got {len(private_key)}"
        )

    if created_at is None:
        created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ── Load ──────────────────────────────────────────────────────────────────
    sd = load_session(db_path, session_id)

    # ── Source text + candidates ───────────────────────────────────────────────
    source_text = build_journal_text(sd)
    candidates  = build_candidates(sd, source_text)

    work_dir        = out_dir / f"_work_{session_id}"
    shard_dir       = out_dir / f"shard_{session_id}"
    source_path     = work_dir / "source.txt"
    candidates_path = work_dir / "candidates.jsonl"

    work_dir.mkdir(parents=True, exist_ok=True)
    source_path.write_text(source_text, encoding="utf-8")
    with candidates_path.open("w", encoding="utf-8") as fh:
        for c in candidates:
            fh.write(json.dumps(c) + "\n")

    # ── Pass 1: compile generic shard (no binary stream yet) ─────────────────
    cfg = CompilerConfig(
        source_path=source_path,
        candidates_path=candidates_path,
        out_dir=shard_dir,
        private_key=private_key,
        publisher_id=_PUBLISHER_ID,
        publisher_name=_PUBLISHER_NAME,
        namespace=SFN_NAMESPACE,
        created_at=created_at,
        suite=suite,
    )
    if not compile_generic_shard(cfg):
        raise RuntimeError(f"compile_generic_shard returned False for session {session_id!r}")

    # ── Inject cam_latents.bin (AXLF/AXLR custody stream) ────────────────────
    (shard_dir / "content" / "cam_latents.bin").write_bytes(
        build_axlf_stream(sd.packets)
    )

    # ── Write ext/streams@1.parquet ───────────────────────────────────────────
    ext_dir = shard_dir / "ext"
    ext_dir.mkdir(exist_ok=True)
    build_streams_parquet(sd.packets, ext_dir / "streams@1.parquet")

    # ── Pass 2: reseal over all content including cam_latents.bin ────────────
    new_root  = compute_merkle_root(shard_dir, suite=suite)
    manifest  = json.loads((shard_dir / "manifest.json").read_bytes())
    manifest["integrity"]["merkle_root"] = new_root
    manifest["shard_id"] = f"shard_blake3_{new_root}"
    man_bytes = dumps_canonical_json(manifest)
    (shard_dir / "manifest.json").write_bytes(man_bytes)

    # Re-sign with raw sk only (CompilerConfig takes sk||pk; reseal needs sk alone)
    pub_path = shard_dir / "sig" / "publisher.pub"
    if suite == SUITE_MLDSA44:
        sig = mldsa44_sign(private_key[:2528], man_bytes)
    else:
        sig = SigningKey(private_key[:32]).sign(man_bytes).signature
    (shard_dir / "sig" / "manifest.sig").write_bytes(sig)

    # ── Self-verify (mandatory — INV-28) ─────────────────────────────────────
    result = verify_shard(shard_dir, trusted_key_path=pub_path)
    if result["status"] != "PASS":
        raise RuntimeError(
            f"Self-verification failed for session {session_id!r}: "
            f"{result['error_count']} error(s): {result['errors']}"
        )

    shutil.rmtree(work_dir)
    return shard_dir


def main():
    from axm_sfn.cli import sfn_group
    sfn_group(sys.argv[1:])
