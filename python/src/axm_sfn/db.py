"""
Read axm-edge custody sessions from the SQLite hot buffer (buffer.db).

The schema is owned by the Go daemon (internal/hotbuffer/buffer.go).
This module is read-only — it never writes to the buffer.
"""
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class PacketRecord:
    seq: int
    tick_utc: str
    tick_mono_ns: int
    telemetry: dict
    packet_blake3: Optional[bytes]   # 32 bytes hex-decoded, None if not yet set
    packet_sha256: Optional[bytes]   # 32 bytes hex-decoded
    tpm_sig: Optional[bytes]
    anomaly_extruder: bool
    anomaly_bed: bool
    anomaly_load_cell: bool
    recovered_from_cache: bool
    verdict_pass: Optional[bool]     # from telemetry decision.pass; None = no profile
    profile_id: Optional[str]
    violations: list[str] = field(default_factory=list)


@dataclass
class ProvenanceFault:
    seq: int
    reason: str
    detected_at: str


@dataclass
class SessionData:
    session_id: str
    packets: list[PacketRecord]
    faults: list[ProvenanceFault]
    printer_id: str = ""
    node_label: str = ""
    mpf_id: str = ""


def _hex_to_bytes(h: Optional[str]) -> Optional[bytes]:
    if h is None:
        return None
    return bytes.fromhex(h)


def load_session(db_path: Path, session_id: str) -> SessionData:
    """Load all packets and faults for a session from the hot buffer.

    Opens the database read-only. Raises ValueError if no packets exist.
    """
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            """
            SELECT seq, tick_utc, tick_mono_ns, telemetry_json,
                   packet_blake3, packet_sha256, tpm_sig,
                   anomaly_extruder, anomaly_bed, anomaly_load_cell,
                   recovered_from_cache
            FROM packets
            WHERE session_id = ?
            ORDER BY seq ASC
            """,
            (session_id,),
        ).fetchall()

        if not rows:
            raise ValueError(f"No packets found for session {session_id!r}")

        packets = []
        printer_id = node_label = mpf_id = ""

        for r in rows:
            tel = json.loads(r["telemetry_json"])
            decision = tel.get("decision") or {}

            if not printer_id:
                printer_id = tel.get("printer_id", "")
            if not node_label:
                node_label = tel.get("node_label", "")
            if not mpf_id and decision.get("profile_id"):
                mpf_id = decision["profile_id"]

            packets.append(PacketRecord(
                seq=r["seq"],
                tick_utc=r["tick_utc"],
                tick_mono_ns=r["tick_mono_ns"],
                telemetry=tel,
                packet_blake3=_hex_to_bytes(r["packet_blake3"]),
                packet_sha256=_hex_to_bytes(r["packet_sha256"]),
                tpm_sig=_hex_to_bytes(r["tpm_sig"]),
                anomaly_extruder=bool(r["anomaly_extruder"]),
                anomaly_bed=bool(r["anomaly_bed"]),
                anomaly_load_cell=bool(r["anomaly_load_cell"]),
                recovered_from_cache=bool(r["recovered_from_cache"]),
                verdict_pass=decision.get("pass"),
                profile_id=decision.get("profile_id"),
                violations=decision.get("violations") or [],
            ))

        fault_rows = con.execute(
            """
            SELECT seq, reason, detected_at
            FROM provenance_faults
            WHERE session_id = ?
            ORDER BY seq ASC
            """,
            (session_id,),
        ).fetchall()

        faults = [
            ProvenanceFault(seq=r["seq"], reason=r["reason"], detected_at=r["detected_at"])
            for r in fault_rows
        ]

        return SessionData(
            session_id=session_id,
            packets=packets,
            faults=faults,
            printer_id=printer_id,
            node_label=node_label,
            mpf_id=mpf_id,
        )
    finally:
        con.close()
