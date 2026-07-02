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
    recovered_from_cache: bool = False
    verdict_pass: Optional[bool] = None   # from telemetry decision.pass; None = no profile
    profile_id: Optional[str] = None
    violations: list[str] = field(default_factory=list)
    # Verbatim canonical packet bytes as stored by the Go daemon (telemetry_json).
    # These are the exact bytes whose SHA-256 is packet_sha256 and which the TPM
    # signature covers. None when reading a synthetic/legacy buffer.
    telemetry_raw: Optional[bytes] = None


@dataclass
class QuoteRecord:
    """One TPM2_Quote from the quotes table (PCR evidence bound to the chain)."""
    seq: int
    pcrs: list[int]
    nonce: bytes
    attest_blob: bytes               # marshalled TPM2B_ATTEST
    sig: bytes                       # marshalled TPMT_SIGNATURE
    ak_handle: int
    created_at: str


@dataclass
class AttestationKey:
    """Node key material from the attestation_keys table.

    role: 'sign_pub' | 'ak_pub' (marshalled TPM2B_PUBLIC) or 'ek_cert' (X.509 DER)
    """
    role: str
    alg: str
    data: bytes
    created_at: str


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
    quotes: list[QuoteRecord] = field(default_factory=list)
    attestation_keys: list[AttestationKey] = field(default_factory=list)


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
                telemetry_raw=r["telemetry_json"].encode("utf-8"),
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
            quotes=_load_quotes(con, session_id),
            attestation_keys=_load_attestation_keys(con),
        )
    finally:
        con.close()


def _load_quotes(con: sqlite3.Connection, session_id: str) -> list[QuoteRecord]:
    """Read TPM quotes for a session. Older buffers may predate the table."""
    try:
        rows = con.execute(
            """
            SELECT seq, pcrs, nonce, attest_blob, sig, ak_handle, created_at
            FROM quotes
            WHERE session_id = ?
            ORDER BY seq ASC, id ASC
            """,
            (session_id,),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    return [
        QuoteRecord(
            seq=r["seq"],
            pcrs=json.loads(r["pcrs"]),
            nonce=bytes(r["nonce"]),
            attest_blob=bytes(r["attest_blob"]),
            sig=bytes(r["sig"]),
            ak_handle=r["ak_handle"],
            created_at=r["created_at"],
        )
        for r in rows
    ]


def _load_attestation_keys(con: sqlite3.Connection) -> list[AttestationKey]:
    """Read node key material (sign key, AK public areas, EK cert chain).

    Keys are node-level, not session-level; all rows are returned. Older
    buffers may predate the table.
    """
    try:
        rows = con.execute(
            """
            SELECT role, alg, data, created_at
            FROM attestation_keys
            ORDER BY role ASC, id ASC
            """
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    return [
        AttestationKey(
            role=r["role"],
            alg=r["alg"],
            data=bytes(r["data"]),
            created_at=r["created_at"],
        )
        for r in rows
    ]
