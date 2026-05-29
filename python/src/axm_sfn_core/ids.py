"""
Spoke-specific identity helpers for axm-sfn.

Genesis identity functions delegate to axm_verify.identity — never
reimplemented here (INV-27).
"""
from axm_verify.identity import (
    recompute_entity_id as entity_id,
    recompute_claim_id  as claim_id,
    canonicalize,
)

__all__ = ["entity_id", "claim_id", "canonicalize", "SFN_NAMESPACE"]

SFN_NAMESPACE = "sfn/custody"
