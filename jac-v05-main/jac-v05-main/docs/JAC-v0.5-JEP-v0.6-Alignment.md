# JAC v0.5 Alignment with JEP v0.6 and HJS v0.5

This document describes how JAC v0.5 aligns with JEP v0.6 and HJS v0.5.

## Scope

JAC v0.5 is a declared dependency chain companion layer.

It composes JEP events and HJS receipt objects into declared dependency chains, accountability chains, delegation paths, verification paths, and workflow traces.

## Core boundary

JAC v0.5 does not redefine:

- JEP event object;
- J/D/T/V verbs;
- JEP signature semantics;
- JEP event hash semantics;
- JEP validation levels;
- JEP failure codes;
- JEP extension processing;
- HJS receipt semantics;
- HJS evidence lifecycle semantics.

## JAC extension identifier

The primary JAC extension identifier is:

```text
https://jac.org/chain
```

## Extension structure

```json
{
  "ext": {
    "https://jac.org/chain": {
      "based_on": "sha256:...",
      "based_on_type": "jep-event",
      "relation": "derived-from",
      "observed_log_assumption": "partial"
    }
  },
  "ext_crit": ["https://jac.org/chain"]
}
```

## Current v0.5 implementation status

Implemented:

- JEP-compatible JAC chain extension object.
- `based_on`, `based_on_type`, `relation` fields.
- `observed_log_assumption`.
- chain root and declared break examples.
- chain fragment schema.
- chain validation result schema.
- basic chain validator seed.
- examples and tests.

Not yet complete:

- full JEP signature verification integration;
- full HJS receipt validation integration;
- full external evidence validation;
- production-grade graph reconstruction;
- multi-implementation conformance suite;
- complete-log proof profile.

## Boundary statements

A valid JAC chain means that dependency links were declared and structurally validated.

It does not prove:

- factual causality;
- legal liability;
- authorization validity;
- complete log availability;
- regulatory compliance;
- moral responsibility.

## Version relationship

```text
JEP v0.6 = stable event core
HJS v0.5 = receipt / archive / evidence lifecycle companion layer
JAC v0.5 = declared dependency chain companion layer
```
