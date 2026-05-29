"""
AXLF/AXLR binary stream format constants.

Verbatim mirror of axm_embodied_core/protocol.py (INV-25: binary format is
authoritative). axm-sfn uses the identical cam_latents.bin format so the
frozen genesis verifier validates sfn shards with zero spoke-specific changes.

Any change here requires a simultaneous change to axm_embodied_core/protocol.py
and axm_verify/logic.py in a single PR.
"""
import struct

MAGIC_LATENT_FILE = b"AXLF"
MAGIC_LATENT_REC  = b"AXLR"
MAGIC_RESID_REC   = b"AXRR"
VERSION           = 1
REC_HEADER_FMT    = "<4sBII"
REC_HEADER_LEN    = struct.calcsize(REC_HEADER_FMT)  # 13
LATENT_DIM        = 256
FILE_HEADER_LEN   = 4
LATENT_REC_LEN    = REC_HEADER_LEN + LATENT_DIM      # 269
