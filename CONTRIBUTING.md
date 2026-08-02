# Contributing

Thank you for contributing to Governed Signal-to-Content.

1. Use Python 3.11 or newer.
2. Create a virtual environment and install `python -m pip install -e ".[dev]"`.
3. Keep runtime workspaces and evidence outside tracked directories.
4. Preserve the proposal-versus-authority boundary: adapters may propose; deterministic application logic changes state.
5. Add tests for changes to transitions, schemas, evidence identity, packets, approvals, or receipts.
6. Run `pytest` and both CLI help smoke tests before proposing a change.

Never include credentials, private evidence, runtime databases, or generated local workspace state in a contribution.
