from jac_v05 import (
    JAC_CHAIN_EXT,
    make_chain_extension,
    attach_jac_chain_extension,
    make_jep_like_event,
    JACChainValidator,
    export_chain_fragment,
)


def test_chain_extension_shape():
    ext = make_chain_extension(
        based_on="sha256:" + "a" * 64,
        based_on_type="jep-event",
        relation="derived-from",
    )
    assert ext["based_on_type"] == "jep-event"
    assert ext["relation"] == "derived-from"


def test_attach_extension_uses_jep_ext_and_ext_crit():
    event = {"jep": "1", "verb": "J", "sig": "demo"}
    ext = make_chain_extension(None, "chain-root", "chain-root")
    out = attach_jac_chain_extension(event, ext)
    assert JAC_CHAIN_EXT in out["ext"]
    assert JAC_CHAIN_EXT in out["ext_crit"]


def test_validator_accepts_chain_root():
    event = make_jep_like_event(
        verb="D",
        who="did:example:human-123",
        what={"claim": "delegate"},
        based_on=None,
        based_on_type="chain-root",
        relation="chain-root",
    )
    result = JACChainValidator().validate_event(event)
    assert result["valid"] is True


def test_validator_rejects_missing_parent_for_non_root():
    event = make_jep_like_event(
        verb="J",
        who="did:example:agent-789",
        what="sha256:" + "a" * 64,
        based_on=None,
        based_on_type="jep-event",
        relation="derived-from",
    )
    result = JACChainValidator().validate_event(event)
    assert result["valid"] is False
    assert result["errors"][0]["code"] == "ERR_JAC_PARENT_MISSING"


def test_export_chain_fragment():
    event = make_jep_like_event(
        verb="D",
        who="did:example:human-123",
        what={"claim": "delegate"},
        based_on=None,
        based_on_type="chain-root",
        relation="chain-root",
    )
    fragment = export_chain_fragment([event])
    assert fragment["jac"] == "0.5"
    assert fragment["type"] == "chain-fragment"
    assert fragment["event_count"] == 1
    assert fragment["fragment_hash"].startswith("sha256:")
