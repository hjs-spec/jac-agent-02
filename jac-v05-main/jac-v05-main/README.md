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

## Status

This is an implementation seed aligned with the core architecture of `draft-wang-jac-02`.

It does not yet claim full production conformance or complete coverage of all optional JAC deployment profiles.

## Quick example

```bash
python jac_v05.py
```

## Run tests

```bash
python -m pytest -q tests_jac_v05.py
```

## Public drafts

- JAC: https://datatracker.ietf.org/doc/draft-wang-jac/
- JEP-Core: https://datatracker.ietf.org/doc/draft-wang-jep-judgment-event-protocol/
- HJS: https://datatracker.ietf.org/doc/draft-wang-hjs-accountability/
