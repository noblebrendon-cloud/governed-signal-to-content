# Adapter contracts

`src/governed_signal_to_content/adapters/` contains two provider-neutral protocols.

## DiscoveryAdapter

`DiscoveryAdapter.discover()` returns proposed `DiscoveredSignal` values with a title and source URL. It has no workspace or database parameter and cannot create authoritative candidates by contract. A caller must pass a proposal through the normal ingest command or application service.

## InterpretationAdapter

`InterpretationAdapter.propose(candidate)` returns an `InterpretationProposal` containing classification and content-input dictionaries. The application validates those dictionaries using strict models. The adapter cannot invoke the state machine.

## Contract rules for future implementations

1. Provider output is untrusted input.
2. Credentials remain in provider-specific runtime configuration and never enter candidates, packets, receipts, or source control.
3. A provider may not write the SQLite database or receipt log.
4. A provider may not select or apply an authoritative state.
5. Evidence acquisition must explicitly report whether bytes were preserved.
6. External publication requires a separate adapter and must still honor human approval and local authorization.
