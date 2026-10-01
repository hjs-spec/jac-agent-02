# JAC v0.5 — Declared Dependency Chains

Build declared dependency links, validate their structure and export chain fragments.
Use `jac_v05.py` for these operations.

Checks cover declarations and fragment hashes. Signatures, referenced objects,
authority and log completeness require separate verification. To create or verify
signed events, start with [JEP Core](https://github.com/hjs-spec/jep-core).

## Try the example

Use Python 3.11 in your development environment:

```bash
git clone https://github.com/hjs-spec/jac-agent-02.git
cd jac-agent-02
python -m pip install -r requirements.txt
python jac_v05.py
```

The command prints a three-event fragment and its declaration-validation results.
The example events are unsigned; they are not signed Core 0.7 events.

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

## Use in your code

| Task | Entry in `jac_v05.py` |
|---|---|
| Attach a declared link before signing | `attach_jac_chain_extension` |
| Check declarations | `JACChainValidator` |
| Export a copied event fragment | `export_chain_fragment` |
| Check a fragment's hash binding | `verify_fragment_hash` |

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
- `make_jep_like_event` is an unsigned demo helper. Its
  `UNSIGNED-DEMO` output must not be submitted as a signed Core event.
- Critical JAC declarations require a consumer with a JAC extension handler.
  A Core-only verifier, including the current baseline API, correctly rejects
  this unknown critical extension. Use `critical=False` only when your
  application explicitly permits the declaration to be ignored; that is not
  JAC verification.

## Run tests

```bash
python -m pytest -q
```

## Public drafts

- JAC: https://datatracker.ietf.org/doc/draft-wang-jac/
- JEP-Core: https://datatracker.ietf.org/doc/draft-wang-jep-judgment-event-protocol/
