# JAC v0.5 — JEP/HJS Declared Dependency Chain Implementation Seed

JAC v0.5 is a JEP v0.6 and HJS v0.5 compatible implementation seed for declared dependency chains.

It aligns with:

- `draft-wang-jac-02`
- `draft-wang-jep-judgment-event-protocol-06`
- `draft-wang-hjs-accountability-05`

## Positioning

JAC is a companion chain-composition layer over JEP and HJS.

```text
JEP = atomic signed judgment events
HJS = accountability receipts, archive/privacy/evidence lifecycle
JAC = declared dependency chains over JEP/HJS objects
```

JAC v0.5 does not redefine JEP-Core:

- event object semantics;
- J/D/T/V verbs;
- event hash semantics;
- detached JWS over JCS;
- key resolution;
- validation modes;
- `ext` / `ext_crit` extension framework;
- failure-code semantics.

## What changed from the earlier implementation

The earlier implementation used top-level `task_based_on` and `extensions` fields.

JAC v0.5 aligns dependency declarations with the JEP extension framework:

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

## Added in v0.5

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

## Status

This is an implementation seed aligned with the core architecture of `draft-wang-jac-02`.

It does not yet claim full production conformance or complete coverage of all optional JAC deployment profiles.

## Quick example

```bash
python jac_v05.py
```

## Run tests

```bash
pip install -r requirements.txt
python -m pytest -q
```

## Public drafts

- JAC: https://datatracker.ietf.org/doc/draft-wang-jac/
- JEP-Core: https://datatracker.ietf.org/doc/draft-wang-jep-judgment-event-protocol/
- HJS: https://datatracker.ietf.org/doc/draft-wang-hjs-accountability/
