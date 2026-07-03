"""
Build ext/tpm-attestation@1 — the hardware-attestation evidence for a custody
shard (RFC 0006).

This is the shard's time capsule for the TPM trust chain. Everything a verifier
needs to check the hardware-attestation claim rides *inside* the sealed shard,
so the claim stays verifiable after the hot buffer is pruned and after the TPM's
RSA cryptography falls: a future forger able to break RSA still cannot alter
these bytes without breaking the shard's hybrid (axm-hybrid1) seal, so signatures
sealed before the break remain evidence of what the hardware attested at seal
time (given a seal-time anchor — see axm-genesis docs/DURABILITY.md).

The table never inlines binary. Each stored blob (TPMT_SIGNATURE, TPM2B_ATTEST,
quote nonce, TPM2B_PUBLIC key area, DER cert) is concatenated into one content
leaf (content/tpm-attestation.bin) and indexed by (file, offset, length, sha256)
— exactly how streams@1 indexes cam_latents.bin. The kernel seals it in one pass
via CompilerConfig.extra_content/extra_ext; there is no reseal.

Row kinds (one row per stored blob; `field` discriminates a quote's parts):

  packet_sig  — one per TPM-signed packet   (seq=packet seq, field=signature)
      data = marshalled TPMT_SIGNATURE over SHA-256(canonical bytes, see packets@1)
  quote       — one TPM2_Quote → three rows (seq=the bound packet seq)
      field=signature  marshalled TPMT_SIGNATURE over the attest blob
      field=attest     marshalled TPM2B_ATTEST (PCR digest + nonce); pcrs set here
      field=nonce      qualifying data
  sign_pub / ak_pub — key material (seq=0, field=public)
      data = marshalled TPM2B_PUBLIC
  ek_cert     — endorsement certificate (seq=0, field=certificate)
      data = DER-encoded certificate

Fingerprint rule: key_fingerprint = SHA-256 over the exact stored public-area/
cert bytes — no TPM "Name" computation, recomputable from the shard with SHA-256
alone. (Named tpm-attestation@1 to stay distinct from RFC 0005's proof-of-when
attestations@1.)
"""
import json
from hashlib import sha256
from typing import Optional

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

# Content path (under the shard's content/ dir) holding the concatenated TPM
# evidence blobs indexed by ext/tpm-attestation@1.
TPM_ATTESTATION_CONTENT_FILE = "content/tpm-attestation.bin"


def key_fingerprint(data: bytes) -> str:
    """Hex SHA-256 over stored public-area/cert bytes — the archival key ID."""
    return sha256(data).hexdigest()


def sign_key_fingerprint(sd: SessionData) -> Optional[bytes]:
    """32-byte fingerprint of the signing key, for the AXLR payload stamp."""
    for k in sd.attestation_keys:
        if k.role == ROLE_SIGN_PUB:
            return sha256(k.data).digest()
    return None


def build_tpm_attestation(sd: SessionData) -> tuple[list[dict], bytes]:
    """Build ext/tpm-attestation@1 rows and the concatenated evidence blob.

    One row per stored blob, indexing (file, offset, length) + sha256 into
    content/tpm-attestation.bin. Returns (rows, blob); ([], b"") when the
    session carries no TPM evidence — absence of the extension is the honest
    statement that no hardware evidence exists (software-only mode).
    """
    fps = {k.role: key_fingerprint(k.data) for k in sd.attestation_keys}
    rows: list[dict] = []
    blob = bytearray()

    def _put(kind: str, seq: int, field: str, alg: str, key_fp: str,
             data: bytes, pcrs: str = "") -> None:
        offset = len(blob)
        blob.extend(data)
        rows.append({
            "kind":            kind,
            "seq":             seq,
            "field":           field,
            "alg":             alg,
            "key_fingerprint": key_fp,
            "file":            TPM_ATTESTATION_CONTENT_FILE,
            "offset":          offset,
            "length":          len(data),
            "sha256":          sha256(data).hexdigest(),
            "pcrs":            pcrs,
        })

    for pkt in sd.packets:
        if not pkt.tpm_sig:
            continue
        _put("packet_sig", pkt.seq, "signature", ALG_TPMT_SIG_RSAPSS,
             fps.get(ROLE_SIGN_PUB, ""), pkt.tpm_sig)

    for q in sd.quotes:
        akfp = fps.get(ROLE_AK_PUB, "")
        _put("quote", q.seq, "signature", ALG_TPMT_SIG_RSAPSS, akfp, q.sig)
        _put("quote", q.seq, "attest", ALG_TPMT_SIG_RSAPSS, akfp, q.attest_blob,
             pcrs=json.dumps(q.pcrs, separators=(",", ":")))
        _put("quote", q.seq, "nonce", ALG_TPMT_SIG_RSAPSS, akfp, q.nonce)

    for k in sd.attestation_keys:
        field = "certificate" if k.role == ROLE_EK_CERT else "public"
        _put(k.role, 0, field, k.alg or _ROLE_ALGS.get(k.role, ""),
             key_fingerprint(k.data), k.data)

    if not rows:
        return [], b""
    return rows, bytes(blob)
