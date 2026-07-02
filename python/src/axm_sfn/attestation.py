"""
Build ext/attestation@1.parquet — the hardware-attestation evidence artifact.

This is the shard's time capsule for the TPM trust chain. Everything a
verifier needs to check the hardware-attestation claim rides *inside* the
ML-DSA-sealed shard, so the claim stays verifiable after the hot buffer is
pruned and after the TPM's RSA cryptography falls: a future forger able to
break RSA still cannot alter these bytes without breaking the ML-DSA seal,
so signatures sealed before the break remain evidence of what the hardware
attested at seal time (given a seal-time anchor — see the anchoring policy
in axm-genesis docs/DURABILITY.md).

Row kinds (one parquet, discriminated by `kind`, sorted by (kind, seq)):

  packet_sig — one row per TPM-signed packet
      seq              packet sequence number
      alg              "tpm2:rsapss-2048-sha256:tpmt-signature"
      key_fingerprint  hex SHA-256 of the signing key's public-area bytes
      data             marshalled TPMT_SIGNATURE over SHA-256(canonical bytes,
                       see ext/packets@1)

  quote — one row per TPM2_Quote
      seq              packet seq the quote is bound to (via nonce derivation)
      alg              "tpm2:rsapss-2048-sha256:tpmt-signature"
      key_fingerprint  hex SHA-256 of the AK's public-area bytes
      data             marshalled TPMT_SIGNATURE over the attest blob
      attest           marshalled TPM2B_ATTEST (contains PCR digest + nonce)
      nonce            qualifying data: SHA-256(session_nonce || packet_sha256
                       || seq_le || prev_blake3)
      pcrs             JSON array of quoted PCR indices

  sign_pub / ak_pub — key material (seq null)
      alg              "tpm2:tpm2b-public"
      key_fingerprint  hex SHA-256 of `data` (self-fingerprint)
      data             marshalled TPM2B_PUBLIC

  ek_cert — endorsement certificate chain (seq null)
      alg              "x509:der"
      key_fingerprint  hex SHA-256 of `data`
      data             DER-encoded certificate

Fingerprint rule: SHA-256 over the exact bytes stored in the `data` column
of the corresponding key row. No TPM "Name" computation, no re-marshalling —
recomputable from the shard alone with nothing but SHA-256.
"""
import json
from hashlib import sha256
from pathlib import Path
from typing import Optional

import pyarrow as pa
import pyarrow.parquet as pq

from axm_sfn.db import SessionData

ALG_TPMT_SIG_RSAPSS = "tpm2:rsapss-2048-sha256:tpmt-signature"
ALG_TPM2B_PUBLIC    = "tpm2:tpm2b-public"
ALG_X509_DER        = "x509:der"

ROLE_SIGN_PUB = "sign_pub"
ROLE_AK_PUB   = "ak_pub"
ROLE_EK_CERT  = "ek_cert"

_ROLE_ALGS = {
    ROLE_SIGN_PUB: ALG_TPM2B_PUBLIC,
    ROLE_AK_PUB:   ALG_TPM2B_PUBLIC,
    ROLE_EK_CERT:  ALG_X509_DER,
}

ATTESTATION_SCHEMA = pa.schema([
    ("kind",            pa.string()),
    ("seq",             pa.int64()),    # null for key/cert rows
    ("alg",             pa.string()),
    ("key_fingerprint", pa.string()),
    ("data",            pa.binary()),
    ("attest",          pa.binary()),   # quote rows only
    ("nonce",           pa.binary()),   # quote rows only
    ("pcrs",            pa.string()),   # quote rows only, JSON array
])


def key_fingerprint(data: bytes) -> str:
    """Hex SHA-256 over stored public-area/cert bytes — the archival key ID."""
    return sha256(data).hexdigest()


def sign_key_fingerprint(sd: SessionData) -> Optional[bytes]:
    """32-byte fingerprint of the signing key, for the AXLR payload stamp."""
    for k in sd.attestation_keys:
        if k.role == ROLE_SIGN_PUB:
            return sha256(k.data).digest()
    return None


def build_attestation_parquet(sd: SessionData, out_path: Path) -> bool:
    """Write ext/attestation@1.parquet if the session carries any TPM evidence.

    Returns True if the artifact was written. Sessions recorded without a TPM
    (software-only mode) produce no artifact — absence of the extension is the
    honest statement that no hardware evidence exists.
    """
    fps = {k.role: key_fingerprint(k.data) for k in sd.attestation_keys}

    rows = []
    for pkt in sd.packets:
        if not pkt.tpm_sig:
            continue
        rows.append({
            "kind":            "packet_sig",
            "seq":             pkt.seq,
            "alg":             ALG_TPMT_SIG_RSAPSS,
            "key_fingerprint": fps.get(ROLE_SIGN_PUB, ""),
            "data":            pkt.tpm_sig,
            "attest":          None,
            "nonce":           None,
            "pcrs":            None,
        })

    for q in sd.quotes:
        rows.append({
            "kind":            "quote",
            "seq":             q.seq,
            "alg":             ALG_TPMT_SIG_RSAPSS,
            "key_fingerprint": fps.get(ROLE_AK_PUB, ""),
            "data":            q.sig,
            "attest":          q.attest_blob,
            "nonce":           q.nonce,
            "pcrs":            json.dumps(q.pcrs),
        })

    for k in sd.attestation_keys:
        rows.append({
            "kind":            k.role,
            "seq":             None,
            "alg":             k.alg or _ROLE_ALGS.get(k.role, ""),
            "key_fingerprint": key_fingerprint(k.data),
            "data":            k.data,
            "attest":          None,
            "nonce":           None,
            "pcrs":            None,
        })

    if not rows:
        return False

    table = pa.Table.from_pylist(rows, schema=ATTESTATION_SCHEMA)
    table = table.sort_by([("kind", "ascending"), ("seq", "ascending")])
    pq.write_table(table, out_path, compression="snappy")
    return True
