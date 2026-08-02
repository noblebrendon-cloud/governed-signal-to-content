# Repository implementation note

This example points only to implemented repository surfaces:

- `src/governed_signal_to_content/state_machine.py` defines the authoritative states and allowed transitions, and records rejected attempts.
- `src/governed_signal_to_content/evidence.py` preserves supplied source bytes with exclusive file creation and SHA-256 verification, or records an honest URL-only reference.
- `src/governed_signal_to_content/deduplication.py` normalizes URLs and compares source identity, normalized URL, and known development identifiers.
- `src/governed_signal_to_content/qualification.py` validates a classification proposal while keeping state-transition authority in application logic.
- `src/governed_signal_to_content/packets.py` writes the fixed packet through a temporary directory, hashes its outputs, and moves it to `AWAITING_APPROVAL`.
- `src/governed_signal_to_content/approvals.py` requires explicit human approval before local release authorization.
- `src/governed_signal_to_content/receipts.py` appends canonical JSON records and refuses duplicate run IDs rather than mutating a prior receipt.
- `src/governed_signal_to_content/database.py` persists state in a user-selected local workspace.
- `schemas/` contains machine-readable record contracts, while `docs/governance-model.md` explains the authority boundary.

The repository implements no autonomous web discovery, bundled language model, social-media posting, GitHub Release creation, or Zenodo integration call.
