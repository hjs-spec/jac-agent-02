# JAC v0.5.0 Release Notes

## Summary

This release upgrades the JAC implementation toward alignment with `draft-wang-jac-02`, JEP v0.6, and HJS v0.5.

## Added

- JAC v0.5 alignment documentation.
- JEP-compatible JAC chain extension.
- `https://jac.org/chain` extension identifier.
- `based_on`, `based_on_type`, and `relation` fields.
- `observed_log_assumption` support.
- declared chain root example.
- declared break example.
- chain fragment export.
- schemas for chain extension, chain fragment, and validation result.
- examples for JEP/HJS/JAC chain usage.
- tests for v0.5 chain behavior.

## Changed

- Dependency declarations are now expressed through JEP `ext` / `ext_crit`.
- Earlier top-level `task_based_on` usage is deprecated.
- Earlier `extensions` usage is replaced by JEP-compatible `ext`.

## Boundary

JAC v0.5 is not an independent event protocol. It does not redefine JEP-Core event format, signatures, hashes, validation modes, or extension processing.

## Status

Implementation seed. Not yet a full production conformance implementation.
