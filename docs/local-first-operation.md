# Local-first operation

Every command that reads or writes runtime state requires `--workspace PATH`. `gs2c init` creates the following layout:

```text
workspace/
├── evidence/
├── candidates/
├── packets/
├── approvals/
├── receipts/
│   └── run_receipts.jsonl
└── state/
    └── watch_state.sqlite
```

Choose a workspace outside the Git checkout. The repository ignores common workspace names, SQLite databases, evidence directories, virtual environments, environment files, caches, and credential file patterns as defense in depth.

The default implementation needs no API key, paid service, network discovery provider, or language model. URL-only ingestion does not fetch the URL. This makes the core workflow usable offline after installation.

SQLite provides durable local state. JSONL provides a simple append-only receipt stream. Local files retain evidence and generated packet bytes. Version 0.1.0 assumes one local operator and does not claim distributed concurrency safety.

The example Windows task script invokes a configured watch command. It is a template only and never embeds credentials.
