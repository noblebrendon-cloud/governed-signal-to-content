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

SQLite provides durable local state, canonical approval decisions, and canonical
transition events. Native events receive an atomic sequence and SHA-256 predecessor
link; JSONL provides an append-only projection of their exact committed chain identity.
Local files retain evidence and generated packet bytes. Version 0.1.0 assumes one local
operator and does not claim distributed consensus or external history authentication.

## Local principal bootstrap and signing

Authority-sensitive commands require a trusted principal's Ed25519 signature. Generate
the keypair at explicit paths outside both the checkout and governed workspace, then use
the public key for the one-time empty-registry bootstrap:

```powershell
gs2c principal-keygen `
  --private-key E:\gs2c-credentials\reviewer-private.pem `
  --public-key E:\gs2c-credentials\reviewer-public.pem
gs2c principal-bootstrap --workspace E:\gs2c-workspace `
  --principal-id reviewer-1 `
  --public-key E:\gs2c-credentials\reviewer-public.pem
```

SQLite retains only the public key, derived key ID, and verifier fingerprint. The
private key remains under operator filesystem custody and is never copied into SQLite,
the workspace, packets, approvals, events, or receipts. Key theft and host compromise
are not mitigated here. After the first principal is registered, bootstrap closes;
rotation, revocation, and additional-principal administration are not implemented.

Use `prepare-operation` to snapshot the exact current operation into an unsigned
canonical envelope, `sign-operation` to sign it without opening the workspace, and pass
the resulting public signed proof with `--authenticated-operation`. Proofs expire after
five minutes by default and are single-use. `--actor` remains asserted display text only
and cannot substitute for the signed proof.

Every new packet receives canonical scope at generation. Add a `scope` object to the
content-input JSON before `gs2c generate`:

```json
{
  "scope": {
    "scope_version": "1.0",
    "brand_id": "example-brand",
    "channel_id": "linkedin",
    "destination_id": "example-profile"
  }
}
```

The identifiers are lowercase logical IDs, not display labels or credentials. They are
bound into `sources.json`, the packet manifest, the packet receipt, and SQLite at
`PACKET_GENERATED`. Inspect the committed value without mutation using:

```powershell
gs2c packet-scope --workspace E:\gs2c-workspace --packet-id PACKET_ID
```

There is no scope-update command. A changed brand, channel, or destination requires a
new packet identity and fresh approval authority.

For approval, rejection, and release, the CLI parses the signed operation and delegates
to the `TransitionMediator`. It does not choose canonical state, rebuild the signed
decision, or write authority records itself. Packet ID, command, and rejection reason
supplied to compatibility commands constrain the signed request; a conflict is rejected
and cannot replace a signed value.

## Capability-policy bootstrap and grants

Authentication does not grant operational authority. After principal bootstrap, prepare,
sign, and apply the one-time policy-administrator operation:

```powershell
gs2c prepare-policy-operation --workspace E:\gs2c-workspace `
  --operation bootstrap-capability-policy --principal-id reviewer-1 `
  --reason "Initialize local capability administration." `
  --output E:\gs2c-operations\policy-bootstrap.json
gs2c sign-operation --operation-file E:\gs2c-operations\policy-bootstrap.json `
  --private-key E:\gs2c-credentials\reviewer-private.pem `
  --output E:\gs2c-operations\policy-bootstrap-signed.json
gs2c bootstrap-policy-admin --workspace E:\gs2c-workspace --actor "Reviewer" `
  --authenticated-operation E:\gs2c-operations\policy-bootstrap-signed.json
```

Bootstrap grants only `policy.manage_capabilities`. Each operational capability must be
granted explicitly with a fresh signed operation. For example:

```powershell
gs2c prepare-policy-operation --workspace E:\gs2c-workspace `
  --operation grant-capability --principal-id reviewer-1 `
  --subject-principal-id reviewer-1 --capability packet.approve `
  --brand-id example-brand --channel-id linkedin `
  --destination-id example-profile `
  --reason "Permit local packet approvals." `
  --output E:\gs2c-operations\grant-approve.json
gs2c sign-operation --operation-file E:\gs2c-operations\grant-approve.json `
  --private-key E:\gs2c-credentials\reviewer-private.pem `
  --output E:\gs2c-operations\grant-approve-signed.json
gs2c grant-capability --workspace E:\gs2c-workspace --actor "Reviewer" `
  --authenticated-operation E:\gs2c-operations\grant-approve-signed.json
```

Repeat for `packet.reject` and `packet.release` as needed. Inspect effective and revoked
grant rows with `gs2c list-capability-grants --workspace PATH`. Revoke one exact grant by
preparing `revoke-capability --grant-id GRANT_ID`, signing it, and applying it with
`gs2c revoke-capability`. The final effective policy-administrator grant cannot be
revoked. There is no unsigned policy mutation shortcut.

Operational grants always require all three exact scope dimensions. A grant for one
destination cannot authorize another, even when principal, capability, brand, channel,
and states are otherwise identical. `policy.manage_capabilities` is deliberately
unscoped, not a wildcard. Scope is included in the signed policy envelope; the apply
commands accept no unsigned subject, capability, or scope replacement.

Migrating schema 3 creates an empty capability policy and grants nothing. Existing
authenticated principals therefore fail closed for approve, reject, and release until
the explicit bootstrap and grant workflow is completed.

If a JSONL append is interrupted after a transition commits, run:

```powershell
gs2c reconcile-receipts --workspace E:\gs2c-workspace
```

The command appends exact pending payloads from SQLite, tolerates an identical line that
was appended before interruption, and does not rewrite history. This recovers a split
SQLite/filesystem write; it does not create or recalculate an event hash.

Run a read-only full audit with:

```powershell
gs2c verify-integrity --workspace E:\gs2c-workspace
```

The command reports canonical-chain validity, canonical-policy validity, receipt
validity, and projection completeness separately. Missing pending projections are
recoverable incompleteness and do not invalidate SQLite history. A missing receipt
already marked projected, changed receipt, broken event linkage, or inconsistent
grant/revocation relationship exits nonzero.

When schema 2 is upgraded, existing events remain explicitly unsequenced. Migration
records a deterministic activation checkpoint over their immutable stored evidence, and
the first native event links to that checkpoint at sequence 1. This retrospective digest
does not claim those legacy events were chained when originally created, and historical
JSONL lines are never rewritten.

When schema 3 is upgraded to schema 4, existing chain entries, hashes, receipts,
activation state, and head remain unchanged. New nullable authorization columns and
empty policy tables do not retroactively claim that prior events were capability
authorized.

When schema 4 is upgraded through schema 5, nullable scope columns are added without
rewriting any grant, packet, approval, event, chain, canonical receipt, or JSONL byte.
Historical operational grants and packets remain explicitly unscoped and cannot act as
global authority; issue fresh exact grants for newly scoped packets. Existing unscoped
`policy.manage_capabilities` grants remain effective. Schema 5→6 adds empty
external-effect tables and expands only the fixed capability vocabulary; it creates no
binding, credential reference, executor, effect request, claim, result, or inferred
grant. Running migration again preserves the same state and does not rewrite a prior
chain or JSONL byte.

A local SHA-256 chain is tamper-evident, not independently authenticated against an
attacker capable of rewriting and recomputing the entire local evidence store.

`RELEASED` remains local authorization. Slice 7 can derive and exercise an offline
external-effect request but performs no account discovery, OAuth, social-network
connection, or live publication.

## Offline privileged-effect workflow

Grant `effect.manage_bindings` with the existing prepare/sign/grant workflow. It is a
non-packet-scoped management capability and is not part of bootstrap. Prepare and sign a
binding, then apply it without unsigned overrides:

```powershell
gs2c prepare-destination-binding --workspace E:\gs2c-workspace `
  --principal-id reviewer-1 --brand-id example-brand --channel-id linkedin `
  --destination-id example-profile --external-target-ref capture.example-profile `
  --credential-ref cred_capture-local --reason "Bind offline capture." `
  --output E:\gs2c-operations\binding.json
gs2c sign-operation --operation-file E:\gs2c-operations\binding.json `
  --private-key E:\gs2c-credentials\reviewer-private.pem `
  --output E:\gs2c-operations\binding-signed.json
gs2c register-destination-binding --workspace E:\gs2c-workspace --actor "Reviewer" `
  --authenticated-operation E:\gs2c-operations\binding-signed.json
```

Generate a separate executor key pair, register only its public key with
`prepare-effect-executor` → `sign-operation` → `register-effect-executor`, then derive
and claim the effect with `create-external-effect` and `claim-external-effect`. Configure
the executor only through its environment:

```powershell
$env:GS2C_EFFECT_EXECUTOR_ID = "executor_capture-1"
$env:GS2C_EFFECT_EXECUTOR_PRIVATE_KEY_PATH = "E:\executor\identity-private.pem"
$env:GS2C_TEST_CAPTURE_DIRECTORY = "E:\executor\captures"
$env:GS2C_CREDENTIAL_CRED_CAPTURE_LOCAL = "runtime-only-value"
gs2c-effect-executor execute --workspace E:\gs2c-workspace `
  --effect-id EFFECT_ID --dispatch-id DISPATCH_ID `
  --result-output E:\executor\result.json
gs2c record-external-effect-result --workspace E:\gs2c-workspace `
  --signed-result E:\executor\result.json
```

Do not place environment values, private keys, or live credentials in the governed
workspace. `list-destination-bindings` and `list-external-effects` expose only canonical
opaque references and status. A pending JSONL projection does not corrupt or block the
canonical ledger, while chain, policy, external-effect, or projection disagreement makes
`verify-integrity` exit nonzero.

The example Windows task script invokes a configured watch command. It is a template only and never embeds credentials.
