"""
Compile an axm-sfn custody session into an AXM Layer 2 journal shard.

One pass, no reseal. The custody journal + claims, the AXLF/AXLR custody
stream (cam_latents.bin), the verbatim canonical packet bytes, and the TPM
trust-chain evidence are all handed to compile_generic_shard at once via
CompilerConfig.extra_content / extra_ext (RFC 0006). The kernel computes the
Merkle root, signs with axm-hybrid1, derives the sh1_ identity (never stored),
and self-verifies — this spoke reimplements none of it. (The earlier two-pass
reseal reimplemented four frozen kernel surfaces; RFC 0006 retires it.)
"""
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from axm_build.compiler_generic import CompilerConfig, compile_generic_shard
from axm_build.sign import HYBRID1_SK_LEN

from axm_sfn.attestation import build_tpm_attestation, sign_key_fingerprint
from axm_sfn.db import PacketRecord, SessionData, load_session
from axm_sfn.streams import build_axlf_stream, build_packets, build_streams_rows
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
    created_at: Optional[str] = None,
) -> Path:
    """
    One-pass compilation of a custody session into an AXM Layer 2 shard.

    private_key: a 3904-byte axm-hybrid1 secret key blob (from `axm sfn keygen`
    or `axm-build keygen`).

    Returns the path to the compiled shard directory.
    Raises on any compilation or verification failure.
    """
    if len(private_key) != HYBRID1_SK_LEN:
        raise ValueError(
            f"private_key must be a {HYBRID1_SK_LEN}-byte axm-hybrid1 secret blob, "
            f"got {len(private_key)} bytes (generate one with `axm sfn keygen`)"
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

    # ── Domain content leaves + registered extension tables (RFC 0006) ────────
    # Everything below is passed to the ONE compile pass; nothing is written
    # into the shard after it is sealed. Binary lives in content/; the ext
    # tables only index it.
    #
    # cam_latents.bin — AXLF/AXLR custody stream, located by streams@1.
    latents_path = work_dir / "cam_latents.bin"
    latents_path.write_bytes(
        build_axlf_stream(sd.packets, sign_key_fp=sign_key_fingerprint(sd))
    )
    extra_content: list[tuple[str, Path]] = [("cam_latents.bin", latents_path)]
    extra_ext: dict[str, list[dict]] = {"streams@1": build_streams_rows(sd.packets)}

    # packets@1 — verbatim canonical packet bytes (hash-over-stored-bytes).
    packet_rows, packets_blob = build_packets(sd.packets)
    if packet_rows:
        packets_path = work_dir / "packets.bin"
        packets_path.write_bytes(packets_blob)
        extra_content.append(("packets.bin", packets_path))
        extra_ext["packets@1"] = packet_rows

    # tpm-attestation@1 — TPM signatures, quotes, and key material; sealing
    # these under the hybrid root keeps the hardware-attestation claim
    # verifiable after buffer.db is pruned.
    tpm_rows, tpm_blob = build_tpm_attestation(sd)
    if tpm_rows:
        tpm_path = work_dir / "tpm-attestation.bin"
        tpm_path.write_bytes(tpm_blob)
        extra_content.append(("tpm-attestation.bin", tpm_path))
        extra_ext["tpm-attestation@1"] = tpm_rows

    # ── Single pass: the kernel seals, signs, derives id, and self-verifies ───
    cfg = CompilerConfig(
        source_path=source_path,
        candidates_path=candidates_path,
        out_dir=shard_dir,
        private_key=private_key,
        publisher_id=_PUBLISHER_ID,
        publisher_name=_PUBLISHER_NAME,
        namespace=SFN_NAMESPACE,
        created_at=created_at,
        extra_content=tuple(extra_content),
        extra_ext=extra_ext,
    )
    if not compile_generic_shard(cfg):
        raise RuntimeError(
            f"compile_generic_shard failed self-verification for session {session_id!r}"
        )

    shutil.rmtree(work_dir)
    return shard_dir


def main():
    from axm_sfn.cli import sfn_group
    sfn_group(sys.argv[1:])
