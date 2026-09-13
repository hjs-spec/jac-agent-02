import hashlib
import json
from copy import deepcopy
from pathlib import Path
import subprocess
import sys

import pytest
from jac_v05 import (
    JAC_CHAIN_EXT,
    JACChainValidator,
    attach_jac_chain_extension,
    make_chain_extension,
    make_jep_like_event,
    jcs_seed,
    digest,
    legacy_digest,
    export_chain_fragment,
    verify_fragment_hash,
)


def root(**kwargs):
    return make_jep_like_event(
        "J",
        "did:example:agent",
        {"claim": "root", "number": 1.0},
        based_on_type="chain-root",
        relation="chain-root",
        **kwargs
    )


def test_rfc8785_numbers_and_utf16_sorting():
    obj = {"\ue000": 1.0, "\U0001f600": 1e-7, "a": -0.0}
    expected = '{"a":0,"😀":1e-7,"\ue000":1}'.encode()
    assert jcs_seed(obj) == expected
    assert digest(obj) == "sha256:" + hashlib.sha256(expected).hexdigest()
    assert digest(obj) != legacy_digest(obj)


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), 2**60, {1: "coerced"}, {"bad": "\ud800"}, (1, 2)],
)
def test_invalid_json_cannot_be_hashed(value):
    with pytest.raises((ValueError, TypeError)):
        digest(value)


def test_attach_copies_both_inputs_and_outputs():
    event = {
        "ext": {"https://example.org/data": {"items": [1]}},
        "ext_crit": ["https://example.org/data"],
    }
    chain = make_chain_extension(None, "chain-root", "chain-root")
    original, original_chain = deepcopy(event), deepcopy(chain)
    attached = attach_jac_chain_extension(event, chain)
    assert event == original and chain == original_chain
    attached["ext"]["https://example.org/data"]["items"].append(2)
    attached["ext"][JAC_CHAIN_EXT]["note"] = "new"
    attached["ext_crit"].clear()
    assert event == original and chain == original_chain
    event["ext"]["https://example.org/data"]["items"].append(3)
    assert attached["ext"]["https://example.org/data"]["items"] == [1, 2]


@pytest.mark.parametrize("signature", ["header..signature", "demo", None, []])
def test_attach_rejects_existing_signatures(signature):
    event = {"sig": signature}
    with pytest.raises(ValueError, match="unsigned"):
        attach_jac_chain_extension(
            event, make_chain_extension(None, "chain-root", "chain-root")
        )
    assert event == {"sig": signature}


def test_attach_cannot_overwrite_an_existing_declaration():
    event = root()
    with pytest.raises(ValueError, match="already exists"):
        attach_jac_chain_extension(
            event, make_chain_extension(None, "chain-root", "chain-root")
        )


@pytest.mark.parametrize(
    "event",
    [
        None,
        [],
        "text",
        {"ext": None},
        {"ext": []},
        {"ext": {JAC_CHAIN_EXT: []}},
        {"ext": {JAC_CHAIN_EXT: None}},
        {"ext_crit": "text"},
        {"ext_crit": [1]},
        {"ext_crit": [{}]},
        {"ext_crit": ["missing"]},
    ],
)
def test_bad_containers_fail_without_crashing(event):
    result = JACChainValidator().validate_event(event)
    assert result["valid"] is False
    assert JACChainValidator().validate_fragment([event])["valid"] is False


@pytest.mark.parametrize(
    "changes",
    [
        {"based_on_type": []},
        {"relation": []},
        {"observed_log_assumption": "guaranteed"},
        {"based_on": 123},
        {"based_on": "sha256:bad"},
        {"based_on": "sha256:" + "A" * 64},
        {"chain_id": []},
        {"note": 7},
        {"unknown": True},
    ],
)
def test_extension_schema_and_hash_shapes_are_enforced(changes):
    chain = make_chain_extension("sha256:" + "a" * 64, "jep-event", "derived-from")
    chain.update(changes)
    assert not JACChainValidator().validate_event({"ext": {JAC_CHAIN_EXT: chain}})[
        "valid"
    ]
    with pytest.raises(ValueError):
        attach_jac_chain_extension({}, chain)


def test_declared_break_and_root_rules():
    historical = json.loads(
        (Path(__file__).parent / "examples/jac-declared-break.json").read_text()
    )
    result = JACChainValidator().validate_event(historical)
    assert result["valid"] and result["core_verified"] is False
    assert make_chain_extension(None, "declared-break", "declared-break")
    for parent, kind, relation in [
        (None, "jep-event", "chain-root"),
        (None, "declared-break", "derived-from"),
        ("sha256:" + "a" * 64, "chain-root", "chain-root"),
    ]:
        with pytest.raises(ValueError):
            make_chain_extension(parent, kind, relation)


@pytest.mark.parametrize("events", [None, {}, "text", []])
def test_empty_or_invalid_fragment_is_not_a_valid_chain(events):
    assert not JACChainValidator().validate_fragment(events)["valid"]
    with pytest.raises(ValueError):
        export_chain_fragment(events)


def test_complete_declaration_does_not_become_a_completeness_proof():
    complete = root(observed_log_assumption="complete")
    unspecified = root(observed_log_assumption="unspecified")
    result = JACChainValidator().validate_fragment([complete])
    assert result["observed_log_assumption"] == "complete"
    assert result["log_completeness_verified"] is False
    assert result["references_verified"] is False and result["core_verified"] is False
    assert result["scopes"] == ["jac_extension_structure"]
    assert (
        JACChainValidator().validate_fragment([complete, unspecified])[
            "observed_log_assumption"
        ]
        == "unspecified"
    )


def test_fragment_snapshot_and_hash_binding():
    events = [root()]
    fragment = export_chain_fragment(events)
    events[0]["what"]["claim"] = "changed"
    assert fragment["events"][0]["what"]["claim"] == "root"
    assert verify_fragment_hash(fragment)["valid"]
    fragment["events"][0]["what"]["claim"] = "tampered"
    assert not verify_fragment_hash(fragment)["valid"]


def test_legacy_hash_requires_explicit_selection_and_preserves_bytes():
    events = [root()]
    old = {
        "jac": "0.5",
        "type": "chain-fragment",
        "event_count": 1,
        "events": events,
        "fragment_hash": legacy_digest(events),
    }
    before = deepcopy(old)
    assert not verify_fragment_hash(old)["valid"]
    assert verify_fragment_hash(old, canonicalization="json-sorted-v1")["valid"]
    assert old == before
    new = export_chain_fragment(events)
    assert not verify_fragment_hash(new, canonicalization="json-sorted-v1")["valid"]
    for bad_count in (0, True, "1"):
        assert not verify_fragment_hash(dict(new, event_count=bad_count))["valid"]


def test_demo_has_unique_nonces_and_consistent_parent_hashes():
    output = subprocess.check_output(
        [sys.executable, "jac_v05.py"], cwd=Path(__file__).parent, text=True
    )
    fragment = json.loads(output)
    assert fragment["validation"]["valid"]
    assert verify_fragment_hash(fragment)["valid"]
    events = fragment["events"]
    assert len({event["nonce"] for event in events}) == 3
    assert all(event["sig"] == "UNSIGNED-DEMO" for event in events)
    for parent, child in zip(events, events[1:]):
        assert child["ext"][JAC_CHAIN_EXT]["based_on"] == digest(parent)
        assert child["ref"] == digest(parent)
