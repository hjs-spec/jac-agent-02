# JAC v0.5 — JEP/HJS Declared Dependency Chain Implementation Seed

JAC v0.5 is a declared dependency-chain implementation seed developed against JEP v0.6 and HJS v0.5. Those are its historical alignment targets, not a claim that its demo events conform to current JEP Core 0.7.

For current signed events, start with [JEP Core](https://github.com/hjs-spec/jep-core) and the [integration directory](https://github.com/hjs-spec/.github/blob/main/PROJECTS.md#integrate). This repository checks JAC declarations and fragment integrity; it does not replace Core event validation or provide an automatic format bridge.

Historical alignment targets:

- `draft-wang-jac-02`
- `draft-wang-jep-judgment-event-protocol-06`
- `draft-wang-hjs-accountability-05`

JAC adds declared dependency links over JEP events and HJS objects. Core owns
event structure, signatures and validation requirements.

## Chain extension

JAC v0.5 uses the JEP extension framework:

```json
{
  "ext": {
    "https://jac.org/chain": {
      "based_on": "sha256:...",
      "based_on_type": "jep-event",
      "relation": "derived-from"
    }
  },
  "ext_crit": ["https://jac.org/chain"]
}
```

## Included tools

- JAC chain extension builder
- JAC chain validator seed
- JEP-compatible `ext` / `ext_crit` usage
- `based_on`, `based_on_type`, and `relation` fields
- declared chain root support
- declared break support
- observed-log assumption field
- chain fragment export
- schemas
- examples
- tests
- JAC/JEP alignment documentation
- release notes

## Hashing, mutation and validation behavior

- New event and fragment hashes use RFC 8785 (`rfc8785`), including number
  rendering and UTF-16 property ordering. `export_chain_fragment` records
  `canonicalization: "rfc8785"` and copies the supplied events.
- Attach extensions **before signing**. `attach_jac_chain_extension` copies
  both inputs, rejects an existing real `sig`, and refuses to overwrite a JAC
  declaration. To change a signed event, explicitly build and sign a new event;
  its event hash and dependent references change.
- Extension validation applies the checked-in schema, digest shapes, container
  types and root/break consistency. Declared breaks may omit an unavailable
  parent. Empty fragments and malformed input fail without crashing.
- Results report `jac_extension_structure`. `valid` does not mean a signature,
  parent object, authority or complete log was verified. A caller's
  `observed_log_assumption: "complete"` remains a declaration, not evidence.
- `make_jep_like_event` is an unsigned demo helper with a fresh nonce. Its
  `UNSIGNED-DEMO` output must not be submitted as a signed Core event.
- Critical JAC declarations require a consumer with a JAC extension handler.
  A Core-only verifier, including the current baseline API, correctly rejects
  this unknown critical extension. Use `critical=False` only when your
  application explicitly permits the declaration to be ignored; that is not
  JAC verification.

### Historical data

Existing examples and reports retain their original bytes and placeholder
signatures. Hashes previously produced with sorted Python JSON may differ
from RFC 8785 for numbers and Unicode property names. Read old exports with
`verify_fragment_hash(fragment, canonicalization="json-sorted-v1")`; there is
no automatic fallback or rewrite. `legacy_digest` is provided only to reproduce
old references. Hash verification alone does not validate the chain.

`jac_agent_trace.py` remains an explicitly historical prototype with its old
serialization intact. Use `jac_v05.py` for current declarations. The JAC wire
version remains `0.5`; no new protocol version is claimed.

## Quick example

```bash
pip install -r requirements.txt
python jac_v05.py
```

## Run tests

```bash
python -m pytest -q
```

## Public drafts

- JAC: https://datatracker.ietf.org/doc/draft-wang-jac/
- JEP-Core: https://datatracker.ietf.org/doc/draft-wang-jep-judgment-event-protocol/
- HJS: https://datatracker.ietf.org/doc/draft-wang-hjs-accountability/
