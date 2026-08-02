# State machine

The application recognizes these authoritative states:

`DISCOVERED`, `EVIDENCE_PRESERVED`, `NORMALIZED`, `DUPLICATE_CHECKED`, `QUALIFIED`, `PACKET_GENERATED`, `AWAITING_APPROVAL`, `APPROVED`, `RELEASED`, `SUPPRESSED`, `REJECTED`, and `FAILED`.

```mermaid
stateDiagram-v2
  [*] --> DISCOVERED
  DISCOVERED --> EVIDENCE_PRESERVED
  EVIDENCE_PRESERVED --> NORMALIZED
  NORMALIZED --> DUPLICATE_CHECKED
  NORMALIZED --> SUPPRESSED
  DUPLICATE_CHECKED --> QUALIFIED
  DUPLICATE_CHECKED --> SUPPRESSED
  QUALIFIED --> PACKET_GENERATED
  PACKET_GENERATED --> AWAITING_APPROVAL
  AWAITING_APPROVAL --> APPROVED
  AWAITING_APPROVAL --> REJECTED
  APPROVED --> RELEASED
  DISCOVERED --> FAILED
  EVIDENCE_PRESERVED --> FAILED
  NORMALIZED --> FAILED
  DUPLICATE_CHECKED --> FAILED
  QUALIFIED --> FAILED
  PACKET_GENERATED --> FAILED
  AWAITING_APPROVAL --> FAILED
  APPROVED --> FAILED
```

`RELEASED`, `SUPPRESSED`, `REJECTED`, and `FAILED` are terminal in version 0.1.0.

An attempted transition is checked against the map before an update. Rejected attempts leave state unchanged and append a receipt with `outcome: rejected`. A classification with `qualification_decision: false` is also recorded as a rejected request to reach `QUALIFIED`; the proposal cannot assign a state.

Packets mirror their candidate's state from `PACKET_GENERATED` forward. Approval, rejection, and release update the packet and linked candidate in one SQLite transaction.
