# Governance model

## Authority boundary

Probabilistic or human-assisted interpretation may propose:

- whether a signal is relevant;
- facts and their source associations;
- reasonable inferences;
- structural similarities;
- broader trend language;
- five content drafts.

Those proposals are inputs. They do not own SQLite connections and cannot select the next workflow state.

Deterministic application code owns:

- schema validation;
- evidence hashing and preservation rules;
- URL normalization and duplicate matching;
- prior-state checks;
- the explicit transition map;
- packet file names and atomic generation;
- manifest hashing;
- approval and release gates;
- append-only execution receipts.

## Evidence

When a source file is supplied, the application creates a new candidate-specific directory, opens the destination exclusively, copies bytes, and verifies the SHA-256 hash. There is no evidence update command. A different source must become a different evidence record rather than silently replacing a prior file.

A URL-only ingest is not an archive operation. Its evidence record states that content was not preserved.

## Human approval

Generation ends in `AWAITING_APPROVAL`. Approval records the actor, time, prior state, packet manifest hash, decision, and receipt run ID. A rejection is terminal for that packet in v0.1.0. Release requires `APPROVED` and authorizes downstream publication only locally.

## Receipts

Every accepted or rejected transition attempt creates a receipt. Receipt records contain command, execution identity, identifiers, prior and requested states, resulting state, outcome, reason, hashes when applicable, application version, timestamp, and UUID run ID. Sensitive key names are redacted before serialization. Existing run IDs cannot be appended a second time.

This is an inspectability mechanism, not a cryptographic transparency log. Stronger chaining and signatures are future work.
