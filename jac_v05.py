"""JAC 0.5 declared-dependency helpers over Core 0.6 event containers.

This module validates JAC declarations, not Core signatures, authority,
external causality, parent availability or complete logging.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, asdict
import hashlib
import json
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional
import uuid

from jsonschema import Draft202012Validator
import rfc8785

JAC_CHAIN_EXT = "https://jac.org/chain"
CANONICALIZATION = "rfc8785"
SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
CHAIN_SCHEMA = json.loads((SCHEMA_DIR / "jac-chain-extension.schema.json").read_text())
CHAIN_VALIDATOR = Draft202012Validator(CHAIN_SCHEMA)
FRAGMENT_VALIDATOR = Draft202012Validator(
    json.loads((SCHEMA_DIR / "jac-chain-fragment.schema.json").read_text())
)
ALLOWED_BASED_ON_TYPES = set(CHAIN_SCHEMA["properties"]["based_on_type"]["enum"])
ALLOWED_RELATIONS = set(CHAIN_SCHEMA["properties"]["relation"]["enum"])


def _json_value(value):
    """Reject Python-only values before a serializer can coerce them."""
    if value is None or type(value) in (str, bool, int, float):
        return
    if isinstance(value, list):
        for item in value:
            _json_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings")
            _json_value(item)
        return
    raise ValueError("Only JSON values are supported")


def jcs_seed(obj: Any) -> bytes:
    """RFC 8785 bytes, including ECMAScript numbers and UTF-16 key ordering."""
    _json_value(obj)
    return rfc8785.dumps(obj)


def digest(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_seed(obj)).hexdigest()


def legacy_digest(obj: Any) -> str:
    """Explicit historical json-sorted-v1 digest; never used for new output."""
    _json_value(obj)
    payload = json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _error(code, message):
    return {"code": code, "message": message}


def _digest_reference(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9-]+:[0-9a-f]+", value):
        return False
    algorithm, hexdigest = value.split(":", 1)
    return len(hexdigest) % 2 == 0 and (algorithm != "sha256" or len(hexdigest) == 64)


def _chain_errors(chain):
    errors = [
        _error("ERR_JAC_EXTENSION_SCHEMA", e.message)
        for e in CHAIN_VALIDATOR.iter_errors(chain)
    ]
    if errors:
        return errors
    kind, relation, parent = (
        chain["based_on_type"],
        chain["relation"],
        chain.get("based_on"),
    )
    for declaration in ("chain-root", "declared-break"):
        if (kind == declaration) != (relation == declaration):
            errors.append(
                _error(
                    "ERR_JAC_DECLARATION_MISMATCH",
                    f"{declaration} type and relation must agree",
                )
            )
    if kind == "chain-root" and parent is not None:
        errors.append(
            _error(
                "ERR_JAC_ROOT_HAS_PARENT",
                "A declared root cannot also declare a parent",
            )
        )
    if kind not in {"chain-root", "declared-break"} and parent is None:
        errors.append(
            _error(
                "ERR_JAC_PARENT_MISSING",
                "Non-root, non-break declarations require based_on",
            )
        )
    if parent is not None and not _digest_reference(parent):
        errors.append(
            _error(
                "ERR_JAC_PARENT_DIGEST_INVALID",
                "based_on must be an algorithm-tagged lowercase hex digest; sha256 requires 64 digits",
            )
        )
    return errors


@dataclass
class JACChainExtension:
    based_on: Optional[str]
    based_on_type: str
    relation: str
    observed_log_assumption: str = "partial"
    chain_id: Optional[str] = None
    note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = {k: v for k, v in asdict(self).items() if v is not None}
        jcs_seed(data)
        errors = _chain_errors(data)
        if errors:
            raise ValueError(json.dumps(errors))
        return data


def make_chain_extension(
    based_on: Optional[str],
    based_on_type: str,
    relation: str,
    observed_log_assumption: str = "partial",
    chain_id: Optional[str] = None,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    return JACChainExtension(
        based_on, based_on_type, relation, observed_log_assumption, chain_id, note
    ).to_dict()


def _container_errors(event):
    if not isinstance(event, dict):
        return [_error("ERR_JAC_EVENT_TYPE", "Event must be an object")]
    if not isinstance(event.get("ext", {}), dict):
        return [_error("ERR_JAC_EXT_TYPE", "ext must be an object")]
    critical = event.get("ext_crit", [])
    if not isinstance(critical, list) or not all(
        isinstance(x, str) and x for x in critical
    ):
        return [
            _error(
                "ERR_JAC_EXT_CRIT_TYPE",
                "ext_crit must be an array of non-empty strings",
            )
        ]
    if len(critical) != len(set(critical)):
        return [_error("ERR_JAC_EXT_CRIT_TYPE", "ext_crit entries must be unique")]
    if any(key not in event.get("ext", {}) for key in critical):
        return [
            _error(
                "ERR_JAC_CRITICAL_EXTENSION_MISSING",
                "Each ext_crit entry must exist in ext",
            )
        ]
    return []


def attach_jac_chain_extension(
    event: Dict[str, Any], chain_ext: Dict[str, Any], critical: bool = True
) -> Dict[str, Any]:
    """Return a copy. Attach before signing; never silently invalidate a signature."""
    jcs_seed(event)
    jcs_seed(chain_ext)
    errors = _container_errors(event) + _chain_errors(chain_ext)
    if errors:
        raise ValueError(json.dumps(errors))
    if type(critical) is not bool:
        raise ValueError("critical must be a boolean")
    if "sig" in event and event["sig"] != "UNSIGNED-DEMO":
        raise ValueError("Attach extensions to an unsigned event, then sign the result")
    if JAC_CHAIN_EXT in event.get("ext", {}):
        raise ValueError(
            "JAC extension already exists; build a new unsigned event to replace it"
        )
    out = deepcopy(event)
    out.setdefault("ext", {})[JAC_CHAIN_EXT] = deepcopy(chain_ext)
    if critical:
        out.setdefault("ext_crit", []).append(JAC_CHAIN_EXT)
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
    """Build an explicitly UNSIGNED-DEMO container; this is not a Core signer."""
    if not isinstance(verb, str) or verb not in {"J", "D", "T", "V"}:
        raise ValueError("Unsupported Core verb")
    if (
        not isinstance(who, str)
        or not who.strip()
        or not isinstance(aud, str)
        or not aud
    ):
        raise ValueError("who and aud must be non-empty strings")
    if not isinstance(what, dict) and not _digest_reference(what):
        raise ValueError("what must be an object or a digest")
    if ref is not None and not _digest_reference(ref):
        raise ValueError("ref must be a digest or null")
    event = {
        "jep": "1",
        "verb": verb,
        "who": who,
        "when": int(time.time()),
        "what": deepcopy(what),
        "nonce": str(uuid.uuid4()),
        "aud": aud,
        "ref": ref,
        "sig": "UNSIGNED-DEMO",
    }
    chain_ext = make_chain_extension(
        based_on, based_on_type, relation, observed_log_assumption
    )
    return attach_jac_chain_extension(event, chain_ext)


class JACChainValidator:
    """Validate declarations only; valid does not mean cryptographically verified."""

    def validate_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        try:
            jcs_seed(event)
        except (ValueError, TypeError, RecursionError) as exc:
            return self._result(False, [_error("ERR_JAC_JSON", str(exc))], [])
        errors = _container_errors(event)
        warnings = []
        if errors:
            return self._result(False, errors, warnings)
        ext = event.get("ext", {})
        if JAC_CHAIN_EXT not in ext:
            errors.append(
                _error(
                    "ERR_JAC_CHAIN_EXTENSION_MISSING",
                    "Missing https://jac.org/chain extension",
                )
            )
        else:
            errors.extend(_chain_errors(ext[JAC_CHAIN_EXT]))
        if JAC_CHAIN_EXT not in event.get("ext_crit", []):
            warnings.append(
                _error(
                    "WARN_JAC_CHAIN_NOT_CRITICAL",
                    "JAC chain extension is not listed in ext_crit",
                )
            )
        return self._result(not errors, errors, warnings)

    def validate_fragment(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not isinstance(events, list) or not events:
            return {
                **self._result(
                    False,
                    [
                        _error(
                            "ERR_JAC_FRAGMENT_INPUT",
                            "A non-empty event array is required",
                        )
                    ],
                    [],
                ),
                "event_count": len(events) if isinstance(events, list) else 0,
                "results": [],
                "observed_log_assumption": "unspecified",
            }
        results = [self.validate_event(event) for event in events]
        valid = all(result["valid"] for result in results)
        return {
            **self._result(
                valid,
                (
                    []
                    if valid
                    else [
                        _error(
                            "ERR_JAC_FRAGMENT_INVALID",
                            "One or more declarations are invalid",
                        )
                    ]
                ),
                [],
            ),
            "event_count": len(events),
            "results": results,
            "observed_log_assumption": (
                self._infer_observed_log_assumption(events) if valid else "unspecified"
            ),
        }

    def _infer_observed_log_assumption(self, events):
        assumptions = [
            event["ext"][JAC_CHAIN_EXT].get("observed_log_assumption", "unspecified")
            for event in events
        ]
        if "partial" in assumptions:
            return "partial"
        return (
            "complete" if all(a == "complete" for a in assumptions) else "unspecified"
        )

    def _result(self, valid, errors, warnings):
        return {
            "valid": valid,
            "profile": "jac-v0.5",
            "extension": JAC_CHAIN_EXT,
            "scopes": ["jac_extension_structure"] if valid else [],
            "core_verified": False,
            "references_verified": False,
            "log_completeness_verified": False,
            "errors": errors,
            "warnings": warnings,
        }


def export_chain_fragment(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    result = JACChainValidator().validate_fragment(events)
    if not result["valid"]:
        raise ValueError(json.dumps(result))
    snapshot = deepcopy(events)
    return {
        "jac": "0.5",
        "type": "chain-fragment",
        "canonicalization": CANONICALIZATION,
        "event_count": len(snapshot),
        "events": snapshot,
        "fragment_hash": digest(snapshot),
    }


def verify_fragment_hash(fragment, *, canonicalization="rfc8785"):
    """Check exported hash binding only; legacy mode must be explicitly requested."""
    try:
        if canonicalization not in {"rfc8785", "json-sorted-v1"}:
            raise ValueError("Unknown canonicalization")
        _json_value(fragment)
        errors = list(FRAGMENT_VALIDATOR.iter_errors(fragment))
        if errors:
            raise ValueError(errors[0].message)
        declared = fragment.get("canonicalization")
        if declared is not None and declared != canonicalization:
            raise ValueError("Declared canonicalization differs from requested mode")
        if type(fragment["event_count"]) is not int or fragment["event_count"] != len(
            fragment["events"]
        ):
            raise ValueError("event_count does not match events")
        if "fragment_hash" not in fragment:
            raise ValueError("fragment_hash is required for hash verification")
        expected = (digest if canonicalization == "rfc8785" else legacy_digest)(
            fragment["events"]
        )
        if fragment["fragment_hash"] != expected:
            raise ValueError("Fragment hash mismatch")
        return {
            "valid": True,
            "scopes": ["fragment_hash_binding"],
            "canonicalization": canonicalization,
            "core_verified": False,
            "references_verified": False,
        }
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        return {
            "valid": False,
            "scopes": [],
            "errors": [_error("ERR_JAC_FRAGMENT_HASH", str(exc))],
        }


def demo() -> Dict[str, Any]:
    root = make_jep_like_event(
        "D",
        "did:example:human-123",
        {
            "claim": "delegate",
            "delegatee": "did:example:agent-789",
            "scope": "summarize-document",
        },
        based_on_type="chain-root",
        relation="chain-root",
    )
    root_hash = digest(root)
    judgment = make_jep_like_event(
        "J",
        "did:example:agent-789",
        "sha256:" + "a" * 64,
        based_on=root_hash,
        relation="delegated-from",
        ref=root_hash,
    )
    judgment_hash = digest(judgment)
    verification = make_jep_like_event(
        "V",
        "did:example:verifier-123",
        {"verification_scope": ["syntax", "cryptographic"]},
        based_on=judgment_hash,
        relation="verified-by",
        ref=judgment_hash,
    )
    fragment = export_chain_fragment([root, judgment, verification])
    fragment["validation"] = JACChainValidator().validate_fragment(fragment["events"])
    return fragment


if __name__ == "__main__":
    print(json.dumps(demo(), indent=2))
