"""JAC v0.5 implementation seed.

This module provides a small JEP-compatible declared dependency chain
extension implementation aligned with draft-wang-jac-02.

It intentionally does not implement full JEP signing or HJS receipt
validation. It only builds and validates JAC extension structures and
chain fragments.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

JAC_CHAIN_EXT = "https://jac.org/chain"

ALLOWED_BASED_ON_TYPES = {
    "jep-event",
    "hjs-behavior-record",
    "hjs-receipt-manifest",
    "hjs-receipt-bundle",
    "external-digest",
    "declared-break",
    "chain-root",
}

ALLOWED_RELATIONS = {
    "derived-from",
    "delegated-from",
    "verified-by",
    "terminated-by",
    "supersedes",
    "declared-break",
    "chain-root",
    "depends-on",
    "caused-by",
    "context-for",
}


def jcs_seed(obj: Any) -> bytes:
    """JCS-compatible canonicalization for simple seed objects."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_seed(obj)).hexdigest()


@dataclass
class JACChainExtension:
    based_on: Optional[str]
    based_on_type: str
    relation: str
    observed_log_assumption: str = "partial"
    chain_id: Optional[str] = None
    note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        return {k: v for k, v in data.items() if v is not None}


def make_chain_extension(
    based_on: Optional[str],
    based_on_type: str,
    relation: str,
    observed_log_assumption: str = "partial",
    chain_id: Optional[str] = None,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    ext = JACChainExtension(
        based_on=based_on,
        based_on_type=based_on_type,
        relation=relation,
        observed_log_assumption=observed_log_assumption,
        chain_id=chain_id,
        note=note,
    )
    return ext.to_dict()


def attach_jac_chain_extension(
    event: Dict[str, Any],
    chain_ext: Dict[str, Any],
    critical: bool = True,
) -> Dict[str, Any]:
    """Attach JAC chain extension using JEP ext/ext_crit."""
    out = dict(event)
    out.setdefault("ext", {})
    out["ext"][JAC_CHAIN_EXT] = chain_ext
    if critical:
        ext_crit = list(out.get("ext_crit", []))
        if JAC_CHAIN_EXT not in ext_crit:
            ext_crit.append(JAC_CHAIN_EXT)
        out["ext_crit"] = ext_crit
    return out


def make_jep_like_event(
    verb: str,
    who: str,
    what: Any,
    based_on: Optional[str] = None,
    based_on_type: str = "jep-event",
    relation: str = "derived-from",
    observed_log_assumption: str = "partial",
    aud: str = "https://example.org",
    ref: Optional[str] = None,
) -> Dict[str, Any]:
    """Create an unsigned JEP-like event with a JAC chain extension.

    This is a seed/demo helper, not a production JEP signer.
    """
    event = {
        "jep": "1",
        "verb": verb,
        "who": who,
        "when": int(time.time()),
        "what": what,
        "nonce": "00000000-0000-4000-8000-000000000000",
        "aud": aud,
        "ref": ref,
        "sig": "UNSIGNED-DEMO",
    }
    chain_ext = make_chain_extension(
        based_on=based_on,
        based_on_type=based_on_type,
        relation=relation,
        observed_log_assumption=observed_log_assumption,
    )
    return attach_jac_chain_extension(event, chain_ext)


class JACChainValidator:
    """Minimal JAC chain extension validator."""

    def validate_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        errors: List[Dict[str, Any]] = []
        warnings: List[Dict[str, Any]] = []

        ext = event.get("ext", {})
        chain = ext.get(JAC_CHAIN_EXT)

        if not chain:
            errors.append({
                "code": "ERR_JAC_CHAIN_EXTENSION_MISSING",
                "message": "Missing https://jac.org/chain extension.",
            })
            return self._result(False, errors, warnings)

        based_on_type = chain.get("based_on_type")
        relation = chain.get("relation")

        if based_on_type not in ALLOWED_BASED_ON_TYPES:
            errors.append({
                "code": "ERR_JAC_BASED_ON_TYPE_UNSUPPORTED",
                "message": f"Unsupported based_on_type: {based_on_type}",
            })

        if relation not in ALLOWED_RELATIONS:
            errors.append({
                "code": "ERR_JAC_RELATION_UNSUPPORTED",
                "message": f"Unsupported relation: {relation}",
            })

        if relation != "chain-root" and based_on_type != "chain-root" and not chain.get("based_on"):
            errors.append({
                "code": "ERR_JAC_PARENT_MISSING",
                "message": "Non-root JAC chain events require based_on.",
            })

        if JAC_CHAIN_EXT not in event.get("ext_crit", []):
            warnings.append({
                "code": "WARN_JAC_CHAIN_NOT_CRITICAL",
                "message": "JAC chain extension is not listed in ext_crit.",
            })

        return self._result(len(errors) == 0, errors, warnings)

    def validate_fragment(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = [self.validate_event(e) for e in events]
        valid = all(r["valid"] for r in results)
        return {
            "valid": valid,
            "event_count": len(events),
            "results": results,
            "observed_log_assumption": self._infer_observed_log_assumption(events),
        }

    def _infer_observed_log_assumption(self, events: List[Dict[str, Any]]) -> str:
        assumptions = []
        for event in events:
            chain = event.get("ext", {}).get(JAC_CHAIN_EXT, {})
            if "observed_log_assumption" in chain:
                assumptions.append(chain["observed_log_assumption"])
        if "partial" in assumptions:
            return "partial"
        if "complete" in assumptions:
            return "complete"
        return "unspecified"

    def _result(self, valid: bool, errors: List[Dict[str, Any]], warnings: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "valid": valid,
            "profile": "jac-v0.5",
            "extension": JAC_CHAIN_EXT,
            "errors": errors,
            "warnings": warnings,
        }


def export_chain_fragment(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "jac": "0.5",
        "type": "chain-fragment",
        "event_count": len(events),
        "events": events,
        "fragment_hash": digest(events),
    }


def demo() -> Dict[str, Any]:
    root = make_jep_like_event(
        verb="D",
        who="did:example:human-123",
        what={"claim": "delegate", "scope": "summarize-document"},
        based_on=None,
        based_on_type="chain-root",
        relation="chain-root",
    )
    root_hash = digest(root)

    judgment = make_jep_like_event(
        verb="J",
        who="did:example:agent-789",
        what="sha256:" + "a" * 64,
        based_on=root_hash,
        based_on_type="jep-event",
        relation="delegated-from",
    )
    judgment_hash = digest(judgment)

    verification = make_jep_like_event(
        verb="V",
        who="did:example:verifier-123",
        what={"verification_scope": ["syntax", "cryptographic"]},
        based_on=judgment_hash,
        based_on_type="jep-event",
        relation="verified-by",
    )

    fragment = export_chain_fragment([root, judgment, verification])
    fragment["validation"] = JACChainValidator().validate_fragment(fragment["events"])
    return fragment


if __name__ == "__main__":
    print(json.dumps(demo(), indent=2))
