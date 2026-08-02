# Architecture

Governed Signal-to-Content is a narrow local reference implementation. It separates proposal-producing components from components that own durable state.

```mermaid
flowchart TB
  subgraph Proposal[Proposal layer]
    DA[Discovery adapter]
    IA[Interpretation adapter]
    HD[Human-authored drafts]
  end

  subgraph Authority[Deterministic authority layer]
    EV[Evidence preservation]
    NM[Normalization]
    DD[Duplicate check]
    QL[Qualification validation]
    PG[Atomic packet generator]
    AG[Approval gate]
    SM[Explicit state machine]
  end

  subgraph Persistence[Local persistence]
    DB[(SQLite state)]
    FS[Evidence and packet files]
    JL[Append-only JSONL receipts]
  end

  DA -. proposed signal .-> EV
  IA -. proposed classification and drafts .-> QL
  HD -. drafts .-> PG
  EV --> NM --> DD --> QL --> PG --> AG
  SM --> EV
  SM --> NM
  SM --> DD
  SM --> QL
  SM --> PG
  SM --> AG
  Authority --> DB
  Authority --> FS
  Authority --> JL
```

## Components

- `evidence.py` creates stable IDs, copies supplied source files to new paths, and verifies SHA-256 identity.
- `deduplication.py` performs deterministic URL normalization and duplicate comparison.
- `qualification.py` validates a proposed classification and decides whether its positive decision can be applied from the current state.
- `packets.py` validates draft inputs, writes through a temporary directory, records warnings, and atomically exposes a fixed packet.
- `approvals.py` records a named human decision and gates local release authorization.
- `state_machine.py` is the transition authority. It records both accepted and rejected attempts.
- `database.py` persists candidate, packet, evidence, and approval metadata in SQLite.
- `receipts.py` appends canonical JSON to an immutable-by-contract JSONL log.

Runtime files are never required inside the source tree. A user selects the workspace for every command.
