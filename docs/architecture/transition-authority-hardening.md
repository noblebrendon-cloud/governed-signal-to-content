# Transition authority hardening

## Scope and baseline audit

This phase preserves the deterministic workflow and now implements Slices 1 through 6
locally: exact packet artifact binding, atomic canonical transition events, recoverable
JSONL receipt projection, authenticated principals, mediated canonical execution, and a
locally tamper-evident canonical event/receipt chain, and default-deny
principal-by-capability-by-state authorization, and exact brand/channel/destination
scope. `RELEASED` continues to mean
locally authorized for downstream publication. It does not mean externally published.

The untouched baseline audit was performed on 2026-08-22 before implementation:

- branch: `main`;
- HEAD: `43016a5469a6efd82fd12b3e848a572487a79668`, matching the expected public
  baseline;
- worktree: clean and aligned with `origin/main`;
- Python: 3.12.10, within the supported Python 3.11+ range;
- literal initial test invocation: collection failed because the package was not
  installed in the host interpreter;
- isolated development environment result: 17 tests collected and 17 passed.

All reproductions used temporary workspaces. The canonical operational workspace
was not opened or modified.

### Confirmed failure boundaries

1. **Post-approval artifact mutation — confirmed.** A packet was generated and
   approved, `01_linkedin_analysis.md` was changed, and release still succeeded.
   Both packet and candidate reached `RELEASED`. The release path trusted the
   stored manifest and did not recompute hashes from the packet directory. Risk:
   local release authority could apply to bytes the human did not approve.
2. **Approval/state split — confirmed.** Fault injection made SQLite approval
   insertion raise after the state transition. Both packet and candidate remained
   `APPROVED`, while the required approval row was absent. Risk: canonical state
   could claim approval without canonical approval evidence.
3. **State/receipt split — confirmed.** Fault injection made JSONL append raise
   after a candidate transition. The candidate remained in the new state and no
   receipt for that accepted transition was appended. Risk: accepted state could
   exist without the promised transition evidence.

## Slice 1 design

### Canonical authorities

SQLite remains the authority for workflow state. A new SQLite
`transition_events` table is the authority for transition attempts created by
this version and later. The existing `approvals` table remains the authority for
human approval decisions. Human-readable approval JSON and append-only JSONL run
receipts are projections, not independent authority sources.

Historical v0.1.0 JSONL lines remain immutable historical records. Migration does
not rewrite them or claim they were transactionally coupled to their historical
state changes.

### Canonical transition event

One durable event represents one attempted canonical transition. Its event ID is
the existing receipt run UUID, preserving stable run IDs across SQLite and JSONL.
The record contains:

- event ID and command;
- asserted actor identity (not an authenticated principal);
- target type and target ID, plus candidate and packet IDs where applicable;
- prior, requested, and resulting state;
- accepted or rejected outcome and reason;
- the governed packet manifest hash where applicable;
- file hashes and input identifiers;
- timestamp and application version;
- the exact canonical JSON receipt payload; and
- nullable JSONL projection time.

The primary key prevents duplicate event/run IDs. No event hash chain or signature
is introduced in this slice.

### Atomicity invariant

An accepted candidate transition commits its state mutation and canonical event
in one SQLite transaction. An accepted packet transition commits packet state,
paired candidate state, and its canonical event in one transaction.

An approval or rejection decision additionally commits the decision row in that
same transaction. Therefore an approval-event insertion failure, transition-event
insertion failure, state precondition failure, or paired-state failure rolls back
the whole accepted operation.

Release performs artifact verification immediately before the transaction. The
transaction rechecks the `APPROVED` state, paired candidate state, stored packet
manifest, and matching canonical approved decision before committing the release
event and both state mutations. Filesystem bytes and SQLite cannot share an ACID
transaction; this local-first slice therefore binds the bytes observed by the
immediate verification and does not claim to lock the packet directory against a
separate concurrent filesystem writer.

Rejected attempts do not mutate workflow state. Their rejected canonical event is
committed in its own SQLite transaction, then projected to JSONL. If even the
rejected event cannot be persisted, the transition still fails closed and the
persistence error is surfaced rather than inventing evidence.

### Exact packet identity

The governed packet manifest definition remains compatible with v0.1.0: SHA-256
is recomputed for the five required content artifacts plus `sources.json`, and
the canonical JSON hash of that filename-to-hash map is the packet manifest.
Verification also requires the fixed seven-file directory and checks that
`packet_receipt.json` describes the same packet, candidate, artifact hashes, and
manifest. The receipt file is self-descriptive metadata and is not recursively
included in its own manifest. Its direct SHA-256 hash is nevertheless stored on
the canonical approval event and compared again at release, so all seven
materialized files are bound without a recursive manifest.

Immediately before approval, the recomputed manifest must equal the packet row's
stored manifest. Immediately before release, it must equal both the packet row's
stored manifest and the manifest on the canonical approved decision. Any missing,
extra, malformed, or changed governed artifact fails closed. The rejected attempt
is recorded, and packet/candidate state remains unchanged. The application never
silently regenerates or repairs the packet.

### JSONL receipt projection and recovery

SQLite and a filesystem append cannot be one ACID commit. Each transition event
therefore stores the exact canonical receipt JSON before commit and begins with a
null projection timestamp. After commit, the application appends that exact event
payload to the existing JSONL log and marks it projected in SQLite.

If append fails, the canonical event and accepted state remain intact and the
event remains pending. If append succeeds but marking fails, reconciliation finds
the existing identical run ID and marks it projected without appending a duplicate.
If an existing run ID has different JSON, reconciliation fails rather than
rewriting history. A bounded local reconciliation operation appends only missing
canonical payloads; it never rewrites historical receipt lines.

## Dependency order

```text
Slice 1  Artifact binding + atomic canonical transition event [implemented locally]
   ↓
Slice 2  AuthenticatedPrincipal [implemented locally]
   ↓
Slice 3  TransitionRequest + mediated canonical execution [implemented locally]
   ↓
Slice 4  Tamper-evident event/receipt chain [implemented locally]
   ↓
Slice 5  principal × CapabilityPolicy × state authorization [implemented locally]
   ↓
Slice 6  BrandScope × ChannelScope × destination/action scoping [implemented locally]
   ↓
Slice 7  privileged ExternalEffectAdapter boundaries
```

No dependency needs to move ahead of Slice 1. Authentication needs a durable event
and atomic evidence boundary to bind to; otherwise an authenticated identity could
still be separated from the state it supposedly authorized. Mediated canonical
execution must consume authenticated principals rather than free-form actor strings.
Tamper-evident chaining requires stable canonical events to chain. Capability and
scope policy require both authenticated principals and the mediated request
boundary. External-effect adapters come last because they must consume the fully
scoped authorization result while keeping credentials outside agent context.

## Explicit future work

- **PrivilegedExternalEffectExecutor / ExternalEffectAdapter:** credential-isolated
  downstream publication execution, distinct from canonical state mutation.

Human approval remains required throughout. This design adds no autonomous approval,
external publication, publication credential, hosted service, or agent-owned authority.
The private authentication signing key remains under separate operator custody.

## Slice 2 pre-implementation identity audit

The Slice 2 baseline was verified on 2026-08-22 without discarding or rewriting
Slice 1. The branch and HEAD remained `main` at
`43016a5469a6efd82fd12b3e848a572487a79668`; the expected Slice 1 files were
modified/untracked, version remained `0.1.0`, the focused Slice 1 suite passed
13 tests, and the full suite passed 30 tests.

### Current identity path

The current CLI accepts arbitrary `--actor` text. `decide_packet` and
`release_packet` pass it to the state machine, the approval row stores it as
`actor`, and the transition event stores it as `asserted_actor`. No independent
credential, verifier, or proof is involved.

1. **Forged asserted actor — confirmed.** In a disposable workspace,
   `gs2c approve --actor "Brendon"` created an accepted approval whose approval
   row and canonical event both identified `Brendon`. Risk: any caller can claim
   any display identity.
2. **Identity substitution — unprevented.** No authenticated identity artifact
   exists, so there is nothing binding an identity to packet A rather than packet
   B. A future proof that establishes only key possession would retain this flaw.
3. **Replay — unprevented.** There is no proof nonce/operation ID or canonical
   consumption ledger. Current state may accidentally reject a repeated command,
   but that is not replay prevention and would not remain safe if state later
   changed.
4. **State substitution — unprevented.** Actor text carries no binding to
   `AWAITING_APPROVAL → APPROVED` versus `APPROVED → RELEASED`.
5. **Object substitution — unprevented.** Actor text carries no packet,
   candidate, manifest, packet-receipt, approval, or decision identity.
6. **Credential custody — absent.** Slice 1 has no signing credential or trust
   registry. This avoids credential leakage but provides no authentication.

### Slice 2 threat boundary

Slice 2 is responsible for arbitrary actor impersonation; identity, signed
operation, target, state, decision, and object substitution; exact-proof replay;
expired or malformed authentication material; and key/principal mismatch.

It does not claim protection from unrestricted database writers, a compromised
operating-system kernel or process, stolen private signing credentials,
hardware-key compromise, remote federation, OAuth/OIDC, organization-wide PKI,
multi-user administration, capability authorization, OpenClaw credential
propagation, or publication credentials.

### Dependency finding before implementation

Authentication cannot safely remain only a statement that principal P possessed
key K. Preventing substitution and replay requires a minimal signed operation
envelope containing a unique operation ID and the exact operation, target,
candidate, prior/requested state, governed object identity, decision, and relevant
approval identity. This is the authentication payload only. It is not the future
general-purpose `TransitionRequest`: it carries no capability policy, brand,
channel, destination, external-effect parameters, or execution credential.

## Slice 2 authenticated-principal design

### Principal and verifier

Slice 2 uses Ed25519 signatures through the maintained `cryptography` package;
GS2C does not implement signature primitives. A canonical trusted-principal row
contains:

- stable `principal_id`;
- `authentication_scheme = ed25519`;
- deterministic `key_id` derived from the public-key fingerprint;
- raw public verification key encoded as base64;
- SHA-256 public-key/verifier fingerprint; and
- bootstrap timestamp.

Successful verification produces an `AuthenticatedPrincipal` value containing
the principal ID, scheme, key ID, verifier fingerprint, verification status,
operation ID, canonical envelope hash, proof hash, and authentication time. This
is distinct from both the free-form asserted actor and any future capability
authorization decision.

### Trust bootstrap and credential custody

An empty principal registry permits exactly one local bootstrap. Bootstrap reads
an Ed25519 public key and atomically registers its derived fingerprint and key ID.
Once any principal exists, the bootstrap path is closed. Rotation, additional
principals, revocation, delegation, and organizational administration are future
work.

This assumes the local operator controls the empty workspace at bootstrap time.
An attacker who can replace the SQLite database or run first with the same host
authority is outside the Slice 2 threat boundary.

Private signing material is generated or supplied as a separate filesystem file
chosen by the operator. It is never placed in SQLite, packets, approvals, events,
receipts, or the source repository. GS2C stores only public verifier material and
public signature evidence. Filesystem and host credential protection remain the
operator's responsibility.

### Minimal signed operation envelope

The signed envelope is versioned and contains only authentication-critical data:

- unique operation ID;
- principal ID, Ed25519 scheme, and key ID;
- operation (`approve`, `reject`, or `release`);
- packet target ID and linked candidate ID;
- expected prior and requested state;
- packet manifest hash and direct packet-receipt hash;
- exact approval decision and approval ID;
- approval transition-event ID for release when present;
- exact recorded reason; and
- issue and expiry timestamps.

The signature covers UTF-8 bytes of the repository's existing canonical JSON
serialization: sorted keys, no insignificant whitespace, no NaN values, and the
signature field excluded. Pretty-printed files are transport only. Changing any
signed field invalidates the signature or the exact-operation comparison.

The default proof lifetime is five minutes and the verifier rejects future,
expired, non-positive, or overlong validity windows. Freshness limits capture
before first use; canonical single-use consumption handles replay after use.

### Replay ledger

`authenticated_operations` is the canonical consumption ledger. Its primary key
is the signed operation ID and its proof hash is also unique. A consumed row stores
the canonical envelope, public signature, verifier identity, verification time,
adjudication event, and accepted/rejected outcome. It stores no private key.

A cryptographically verified request is consumed when it reaches canonical
adjudication, including a state-, object-, decision-, or artifact-invalid request.
Consumption and the rejected event commit together so the proof cannot become
usable if conditions later change. An exact replay is verified, detected against
the ledger, rejected without another consumption row, and recorded as a separate
rejected transition event referencing the already consumed operation.

Invalid signatures, unknown principals, malformed proofs, and expired proofs are
not consumed because they never authenticate. Where the target is identifiable,
their failed attempt is still recorded without attributing an authenticated
principal.

### Authority-sensitive transition classification

The human decisions `AWAITING_APPROVAL → APPROVED` and
`AWAITING_APPROVAL → REJECTED`, plus local release authority
`APPROVED → RELEASED`, require an authenticated principal. Rejection is included
because it is a terminal human authority decision. Discovery, preservation,
normalization, duplicate checking, qualification, and packet generation remain
deterministic internal workflow operations and do not require human
authentication.

Authentication proves which trusted principal signed the exact operation. It does
not decide whether that principal has a capability for a brand, channel,
destination, or action. State-machine admissibility and Slice 1 artifact checks
remain separate required predicates.

### Atomic adjudication

For an accepted approval or rejection, the consumed authenticated operation,
approval decision, canonical event, packet state, and candidate state commit in
one SQLite transaction. For accepted release, consumption, the release event, and
both state mutations commit together after the Slice 1 artifact and approval
bindings are rechecked inside the transaction.

A verified but rejected operation commits its consumption and rejected event in
one transaction without changing state or creating approval authority. Replay
attempts create only a rejected event because the original consumption already
exists. Authentication failures create a failed-authentication rejected event
when the packet target is known. JSONL remains a recoverable projection after
these SQLite commits.

## Slice 2 implementation and migration

`authentication.py` implements Ed25519 key generation, one-time public-verifier
bootstrap, exact-envelope preparation, detached signing, deterministic verification,
freshness checks, and replay detection through the maintained `cryptography` library.
`approvals.py` keeps asserted actor text separate while requiring verified evidence for
approval, rejection, and release. `state_machine.py` and `database.py` enforce atomic
proof consumption, approval/event persistence, and state mutation.

Schema version 2 adds `trusted_principals` and `authenticated_operations`, nullable
authentication references to `approvals`, and nullable authentication evidence fields
to `transition_events`. Migration is idempotent. Legacy Slice 1 rows retain null
authentication fields, existing receipt JSON is not rewritten, and no historical actor
is promoted to an authenticated principal.

An authentication failure with an identifiable packet produces a rejected canonical
event without state mutation or approval authority. A verified operation that fails
state, object, decision, approval, or artifact checks is consumed with its rejected
event in one transaction. An accepted approval/rejection additionally commits its
approval row and both state mutations; an accepted release commits consumption, event,
and both state mutations. A replay adds only a rejected event referencing the consumed
operation and cannot create a second ledger row.

This establishes proof that a trusted local principal signed one exact adjudicated
operation. It does not establish capability authorization, brand/channel/destination
permission, a mediated privileged executor, a tamper-evident event chain, external
publication credential separation, OpenClaw identity propagation, or protection from a
compromised host/database writer or stolen private key. No external publication adapter
or publication credential exists in GS2C today.

## Slice 3 pre-implementation execution-path audit

The Slice 3 baseline was verified on 2026-08-23 without modifying or reconstructing the
uncommitted Slice 1 and Slice 2 work. The branch remained `main`, HEAD remained
`43016a5469a6efd82fd12b3e848a572487a79668`, application version remained `0.1.0`,
database schema version remained 2, the focused Slice 1 suite passed 13 tests, the
focused Slice 2 suite passed 24 tests, and the full suite passed 54 tests.

### Authority-sensitive call graph before mediation

The intended CLI paths were:

```text
approve/reject CLI
  -> parse SignedOperation
  -> approvals.decide_packet(packet_id, actor, decision, reason, proof)
  -> verify_signed_operation
  -> independently compare/reconstruct request fields
  -> packet/receipt artifact verification
  -> state_machine.transition_packet
  -> database.apply_packet_transition
  -> packet + candidate + approval + event + proof-consumption transaction

release CLI
  -> parse SignedOperation
  -> approvals.release_packet(packet_id, actor, proof)
  -> verify_signed_operation
  -> independently load and compare approval/request fields
  -> packet/receipt artifact verification
  -> state_machine.transition_packet
  -> database.apply_packet_transition
  -> packet + candidate + event + proof-consumption transaction
```

Direct Python callers could also invoke `decide_packet` or `release_packet`, which used
the same intended checks. However, three lower-level application helpers remained
callable with materially weaker contracts:

1. `state_machine.transition_packet` accepted caller-created
   `AuthenticationEvidence(verification_status="verified")` and an arbitrary operation
   consumption dictionary. It did not cryptographically verify either value.
2. `database.apply_packet_transition` accepted caller-created event, approval, and proof
   dictionaries and could perform the same paired mutation transaction.
3. `database.update_packet_and_candidate_state` directly changed both state rows without
   requiring authentication, approval evidence, proof consumption, or a canonical event.

In a disposable workspace, a fabricated verified evidence object plus the literal
signature `not-a-signature` moved a packet and candidate to `APPROVED`, inserted a proof
ledger row, and created no approval row. A second disposable packet was moved to
`APPROVED` through `update_packet_and_candidate_state` with zero new transition events.
This is not a claim that Python can defend itself from arbitrary hostile in-process code;
it confirms that the supported module surface lacked one clear mediated authority path.

### Confirmed mediation failure boundaries

- **Multiple authority paths — confirmed.** Intended approval/release orchestration and
  lower-level state/database mutation helpers could all reach the same state rows.
- **Authentication/execution field drift — structurally confirmed, with existing checks
  preventing the obvious normal-path exploit.** Authentication verified the envelope,
  but approval/release then received packet, operation/decision, and reason again as
  separate caller arguments and used those reconstructed values after equality checks.
- **Mutable verified request — confirmed.** The outer `VerifiedOperation` dataclass was
  frozen, but its nested Pydantic `SignedOperation` and envelope remained mutable.
- **Caller-forged authentication context — confirmed.** The state-machine boundary
  trusted a caller-created verification-status value and consumption dictionary.
- **Direct mutation around mediation — confirmed.** The database state-update helper
  could bypass authentication, replay handling, approval checks, and canonical events.
- **Verification-to-execution drift — no signed field was shown to be silently replaced
  in the intended path, but the intended path depended on repeated comparisons against
  separately supplied arguments.** This is unnecessary drift surface and is removed in
  Slice 3.
- **Duplicate parsing/canonicalization — disproven.** The CLI parsed signed JSON once and
  the verifier canonicalized that validated model. Downstream code did not independently
  parse the transport bytes, although it did reconstruct operation semantics from
  separate arguments.

## Slice 3 mediated-transition design

Slice 3 retains the Slice 2 signed schema rather than introducing a competing request.
`SignedOperation` remains the untrusted transport containing one
`SignedOperationEnvelope` and its public signature. Successful verification converts the
exact envelope fields into a frozen `TransitionRequest`, then combines that request with
the verified principal, verifier identity, envelope hash, proof hash, signature, and
authentication time in a frozen `AuthenticatedTransitionRequest`.

The supported authority flow becomes:

```text
Untrusted caller / CLI adapter
      -> SignedOperationEnvelope + signature
      -> Ed25519 verification and freshness/replay lookup
      -> immutable AuthenticatedTransitionRequest
      -> TransitionMediator
      -> adapter-constraint + current-state + object + artifact + approval checks
      -> deterministic state-machine admissibility
      -> CanonicalTransitionService
      -> one atomic SQLite authority transaction
      -> canonical transition event
      -> recoverable JSONL projection
```

The mediator derives every authority-sensitive execution value from the authenticated
request. CLI packet, command, and rejection-reason inputs are compatibility constraints
only: they can reject a mismatch but never replace a signed value used for execution.
The mediator owns verified-request rejection and consumption semantics, packet and
candidate identity checks, artifact verification, approval binding, and the future
authorization seam. No capability decision exists in this slice.

`CanonicalTransitionService` is the only supported application component that requests
an accepted authority-sensitive database commit. It does not authenticate, authorize a
capability, perform an external effect, or hold any credential. The guarded public
state-machine/database helpers reject authority-sensitive pairs; an internal persistence
primitive remains callable by arbitrary Python code because Python modules are not a
process security boundary.

Accepted approval/rejection still commits operation consumption, approval, canonical
event, packet state, and candidate state together. Accepted release commits consumption,
event, and both state rows together. A verified request rejected by mediation consumes
the proof with its rejected event. Authentication failures are not consumed. Replays add
only a rejected event. JSONL remains a post-commit recoverable projection, and packet
filesystem bytes still cannot participate in the SQLite transaction.

Internal deterministic transitions through `AWAITING_APPROVAL` remain outside human
authentication mediation. `RELEASED` remains local authorization and is not an external
effect. Capability authorization, tamper-evident chaining, and privileged external-effect
execution remain later slices.

## Slice 3 implementation findings

`SignedOperationEnvelope` and `SignedOperation` are now frozen Pydantic models.
Successful verification creates a frozen `TransitionRequest` with the same inherited
field schema and a frozen, slotted `AuthenticatedTransitionRequest` containing the
verified principal and cryptographic provenance. The mediator never accepts an
`authenticated=True` flag or a caller-supplied principal in place of signed transport.
Python immutability prevents casual application mutation; it is not protection against
arbitrary hostile same-process code.

`transition_mediator.py` now contains the supported `TransitionMediator` and
`CanonicalTransitionService`. Both the CLI commands and the compatibility
`decide_packet`/`release_packet` facades call `mediate_signed_transition`. The mediator
uses the authenticated request for operation ID, principal/key, operation, packet,
candidate, prior/requested state, manifest, packet-receipt identity, decision, approval
identity, reason, and signed timestamps. Separate adapter values only constrain the
request and cannot replace its execution fields.

The former direct `update_packet_and_candidate_state` and unused `insert_packet` helpers
were removed. Generic candidate field updates can no longer update state. The public
state-machine packet path and public database packet/candidate transition paths reject
authority-sensitive state pairs. The database's leading-underscore authority commit
primitive is used by `CanonicalTransitionService`; direct SQLite access necessarily
remains possible to arbitrary code in the trusted process and remains outside the stated
boundary.

No schema change was required: schema version 2 already stores the exact authenticated
operation, approval references, canonical event, and atomic consumption relationship.
No historical request is manufactured, and legacy asserted actors remain unauthenticated.

The mediator returns an explicit immutable `TransitionResult` for acceptance. Rejection
retains established exception types for compatibility and attaches the corresponding
rejected `TransitionResult`, including canonical event ID, after the event commits.
Authentication rejection and authenticated mediation rejection remain distinct:
unverified material is not consumed or attributed, while a verified request rejected by
state, object, adapter, artifact, or approval checks is consumed with its rejected event.

### Remaining dependency order

Slice 3 establishes a stable future policy input containing authenticated principal,
action, packet/candidate target, expected/current state, artifact identity, approval
identity, and proof provenance. Scoped capability authorization therefore has the
structural request/mediation boundary it needs.

Tamper-evident event chaining is not a prerequisite for evaluating capability policy at
transition time: a deterministic policy can safely run against the authenticated request
and current canonical state. Chaining would protect later audit evidence from undetected
rewriting; it would not prevent a compromised live process or database writer from
bypassing policy, both of which remain out of scope. No concrete Slice 3 failure requires
moving capability authorization ahead of Slice 4, so the documented order remains:

```text
Slice 4  Tamper-evident canonical event/receipt chain
   ↓
Slice 5  principal × capability × state authorization
   ↓
Slice 6  brand/channel/destination scope
   ↓
Slice 7  privileged external-effect adapters
```

## Slice 4 tamper-evident event and receipt chain

### Baseline and confirmed failure boundary

Slice 4 began on `main` at the unchanged public baseline commit
`43016a5469a6efd82fd12b3e848a572487a79668`, preserving the intentionally uncommitted
Slices 1–3. Application version remained `0.1.0`, database schema began at 2, the focused
Slice 1/2/3 suites passed 13/24/18 tests, and the full pre-Slice-4 suite passed 72 tests.

Before chaining, event UUIDs identified records but did not order them. Timestamps were
used with UUIDs for deterministic display/projection order but were not a database-assigned
causal sequence and could collide. `receipt_projected_at_utc` was the only supported
post-commit mutable event field; it was projection bookkeeping rather than semantic
evidence. Accepted and rejected canonical attempts, including verified rejections,
replays, and identifiable authentication failures, all used `transition_events`.

Disposable copies confirmed that SQLite event mutation, deletion, fabricated insertion,
and timestamp/order changes had no cryptographic failure before Slice 4. JSONL mutation,
canonical/receipt divergence, and a removed receipt also lacked a full audit command.
Projection omission remained importantly different from canonical event omission: the
former was recoverable from SQLite, while the latter removed authority evidence.

### Chain definition

Schema version 3 adds `transition_event_chain_entries` and the singleton
`transition_event_chain_state`. New events use:

```text
chain_version      = "1.0"
chain_origin       = "native"
hash_algorithm     = SHA-256
event_domain       = GS2C_TRANSITION_EVENT_CHAIN_V1
activation_domain  = GS2C_TRANSITION_EVENT_CHAIN_ACTIVATION_V1
```

The database assigns a positive, unique `event_sequence`. Event hashes and predecessor
hashes are lowercase 64-character SHA-256 values. Sequence, event hash, and predecessor
hash are each unique, so two events cannot claim the same causal predecessor. The
canonical serialization is UTF-8 JSON with sorted keys, compact separators, explicit
JSON nulls where represented, no NaN values, and stable stored string/enum/timestamp
representations.

Conceptually, native hashes are:

```text
SHA256(CanonicalJSON({
  domain,
  chain_version,
  chain_origin,
  event_sequence,
  previous_event_hash,
  event: immutable_event_and_receipt_evidence
}))
```

Immutable evidence includes event/operation ID, command, asserted actor, target and
candidate/packet IDs, state values, outcome and reason, governed/artifact hashes,
timestamp, application version, authentication status/principal/verifier/operation and
proof hashes, and the exact receipt object. The receipt's self-referential `event_hash`
field alone is removed while calculating that hash. `receipt_projected_at_utc` and the
mutable current-head fields are excluded, so ordinary reconciliation cannot change an
event hash. Approval/rejection/release receipts also record signed approval ID, decision,
and applicable approval transition-event ID.

### Activation and legacy provenance

Historical events are not assigned retrospective native sequences. Migration computes a
deterministic activation hash over their exact immutable stored columns, excluding only
projection time, in `(occurred_at_utc, event_id)` order. The state row records that
ordering, count, domains, algorithm, and digest. With no historical events, the same
domain-separated empty snapshot is the explicit genesis checkpoint. The first native
event receives sequence 1 and uses the activation hash as its predecessor.

Migration is deterministic and idempotent. It does not modify historical event receipt
JSON, JSONL lines, asserted actors, or authentication fields. The activation digest is a
retrospective checkpoint over what migration observed; it does not prove those events
were chained or unmodified at original creation time.

### Atomic append, concurrency, and event participation

All event-producing transactions use SQLite `BEGIN IMMEDIATE`. They validate the current
state/head/tail, allocate the next sequence, enrich the exact receipt, calculate and
insert the event/chain entry, and advance the singleton head with a compare-and-set in
the same transaction. Accepted authority commits retain their state, approval, and proof
consumption atomicity. Verified rejected requests commit consumption with their chained
event. Replays and identifiable authentication failures join the same chain without
fabricating a consumption or principal. Failures without an identifiable canonical
target continue to create no event.

The immediate writer lock serializes local appenders. Unique sequence, event hash, and
predecessor constraints additionally prevent a duplicate successor or branch. Hash,
event, chain-entry, head, approval, operation-consumption, or state failure rolls back
the whole transaction. Runtime append recomputes and validates the current head/tail; it
does not rescan all prior events. The explicit integrity command performs the full audit.

### Projection and verification

Native `RunReceipt` values contain `chain_version`, `chain_origin`, `event_sequence`,
`previous_event_hash`, and `event_hash` as an all-or-none group. SQLite commits the final
canonical receipt JSON before projection. JSONL copies those exact bytes and never forms
a separate receipt hash chain. Interrupted projection leaves the already chained event
pending; reconciliation emits its existing identity, recognizes an identical append
before a failed mark, and never rewrites old lines.

`gs2c verify-integrity --workspace PATH` opens SQLite read-only and checks the activation
checkpoint, sequence continuity, predecessor relationships, canonical hash
recomputation, head, duplicate/orphan anomalies, exact JSONL payloads, receipt IDs,
missing projected receipts, and pending projection state. A schema-2 database is reported
as not activated rather than silently migrated. Canonical validity, projection validity,
and projection completeness are separate result fields. A legitimate pending projection
exits successfully with `projection_complete: false`; canonical or receipt-integrity
failure exits nonzero. Unbound receipts predating canonical transition events are counted
as legacy records and are never promoted to native evidence.

### Security claim and dependency finding

A local SHA-256 chain now detects accidental or partial mutation, deletion, insertion,
reordering, broken causal linkage, tail/head disagreement, and JSONL projection mismatch
when the affected hashes and local metadata are not coherently replaced. It is not a
signature, non-repudiation mechanism, external timestamp, or external anchor.

> A local SHA-256 chain is tamper-evident, not independently authenticated against an
> attacker capable of rewriting and recomputing the entire local evidence store.

The chain provides a stable evidence foundation for later capability-policy decisions
and effect reconciliation. No newly discovered integrity prerequisite must precede
scoped capability authorization. The next slice remains:

```text
Slice 5  Scoped Principal × Capability × State Authorization
```

## Slice 5 capability authorization

Authentication and authorization are independent predicates. Ed25519 verification
establishes which trusted principal signed one exact request; it does not grant that
principal permission. For packet authority operations, application code derives one
fixed capability and state scope:

| Operation | Required capability | Prior state | Requested state |
| --- | --- | --- | --- |
| approve | `packet.approve` | `AWAITING_APPROVAL` | `APPROVED` |
| reject | `packet.reject` | `AWAITING_APPROVAL` | `REJECTED` |
| release | `packet.release` | `APPROVED` | `RELEASED` |

No wildcard, role, group, inheritance, or caller-selected required capability exists.
An unknown capability or absence of an exact active canonical grant fails closed.
Artifact integrity and state-machine admissibility remain additional independent
requirements; possession of a grant does not override either.

### Canonical grants, revocations, and policy administration

Schema 4 adds immutable `capability_grants`, append-only
`capability_revocations`, and singleton `capability_policy_state`. A grant binds its
subject principal, fixed capability, canonical state pair, granting principal,
authenticated operation, chained policy event, timestamp, and application version.
A revocation names one exact grant and records equivalent revoker, operation, event,
and time evidence. Effective authority is an exact grant for which no revocation row
exists. If multiple exact grants are active, the earliest grant event sequence and
grant ID determine the evidence recorded on the authorized event.

Policy mutation uses the same signed-operation authentication and mediator boundary as
packet transitions. A dedicated one-time bootstrap is allowed only while the trusted
registry contains its original single principal and capability policy has never been
bootstrapped. It atomically grants only `policy.manage_capabilities` to that principal.
Approve, reject, and release grants must be added explicitly afterward. Subsequent
grant and revoke operations require an active `policy.manage_capabilities` grant.
Explicit self-grants are allowed; revoking the final effective policy administrator is
rejected to avoid an irreversible administrative lockout. No hidden recovery bypass
exists.

The Slice 2 trusted-principal bootstrap remains closed. Slice 5 does not add principal
enrollment, rotation, delegation, or remote identity administration.

### Transaction-time authorization and denials

```text
signed request
    ↓
authenticate principal and exact request
    ↓
validate target, current artifacts, and request semantics
    ↓
BEGIN IMMEDIATE → reread state → derive capability → evaluate active exact grant
    ├─ deny → consume proof → chained rejection → unchanged governed state
    └─ allow → revalidate canonical state/approval bindings
                  ↓
              state/policy mutation + chained evidence
```

For an accepted packet transition, SQLite acquires `BEGIN IMMEDIATE`, rereads the
packet/candidate state and required approval evidence, derives the capability, and
evaluates the active grant before committing state, approval, proof consumption,
authorization evidence, event, chain entry, and chain head together. Any earlier
authorization observation is advisory. If revocation commits first, the transition
transaction observes it and instead consumes the proof with a chained denial while
leaving packet, candidate, and approval state unchanged.

Bootstrap, grants, and revocations use the same serialized transaction boundary for
their policy row, authenticated-operation consumption, event, chain entry, and head.
A verified unauthorized proof is consumed, so a later grant cannot make that old proof
usable. A fresh signed operation is required. Invalid signatures remain authentication
failures and never fabricate a principal or authorization decision. Identifiable
replays record that authorization was not reevaluated and do not add a second
consumption row.

### Authorization evidence and chain compatibility

New authenticated events and receipts record authorization status, principal, required
capability, evaluated state scope, exact authorizing grant ID when applicable, and a
machine-readable reason. Policy events additionally bind grant, revocation, subject,
and scope identifiers. These fields are present before the event hash is calculated.

The Slice 4 chain remains version `1.0`. Its hash already commits to the complete
canonical receipt, so new authorization evidence is covered without changing the
historical top-level hash field list. Migration from schema 3 creates empty policy
tables and nullable event columns only: it adds no grants, rewrites no receipts, and
does not change any activation hash, event hash, sequence, predecessor, or head.
Authenticated principals without explicit grants therefore fail closed after migration.

`verify-integrity` reports canonical chain, canonical policy, JSONL projection, and
projection completeness separately. Policy verification checks bootstrap, grant,
revocation, authenticated-operation, event, principal, scope, and authorizing-grant
linkage. A schema-3 database is inspected read-only and reported as policy not activated;
verification does not migrate it.

This slice does not authorize a brand, channel, destination, publication credential, or
external effect. `packet.release` still means only that the canonical local packet may
proceed to a future privileged adapter. The local hash chain remains tamper-evident,
not signed or externally anchored, and complete host/database compromise or signing-key
theft remains outside the guarantee.

## Slice 6 brand, channel, and destination scope

### Scope-model audit and canonical location

The pre-Slice-6 model had no canonical concepts equivalent to a brand, publication
channel, destination account/page/profile/feed, or downstream publication target.
Existing filesystem variables named `destination` described copy paths, not authority.
Adding scope only to grants or requests would therefore leave the governed packet
unbound and permit request/object disagreement.

Schema 5 uses the smallest sufficient representation: a versioned exact `PacketScope`
stored directly on the packet, operational grants, approvals, signed operations, and
authorization evidence:

```text
PacketScope v1.0 = brand_id × channel_id × destination_id
```

Separate scope registries are intentionally absent. Exact normalized identifier
equality supplies every invariant required in this slice; a registry would be necessary
only for governed lifecycle, relationship, or hierarchy rules that do not exist here.
There is consequently no unsigned scope-administration surface.

Scope becomes canonical during packet generation, before the packet reaches
`AWAITING_APPROVAL`. The validated proposal is written to the packet row and to
`sources.json`; because `sources.json` is a governed manifest input, the content and
intended scope jointly determine the packet manifest. `packet_receipt.json` repeats the
same triple and is directly hash-bound by later signed operations. Scope is therefore
part of governed packet identity, not mutable routing metadata.

No supported helper can mutate a packet's scope. A new intended brand, channel, or
destination requires generation of a new packet ID and fresh approval. Direct SQLite
tampering is outside the same-process application boundary but is detected by artifact,
event, approval, chain, and policy verification unless the attacker coherently rewrites
the complete local evidence store.

### Identifier and no-wildcard rules

Scope IDs are stable lowercase logical identifiers of 1–64 characters. Components use
ASCII letters/digits with single `.`, `_`, or `-` separators. Uppercase, whitespace,
paths, URLs, empty/partial triples, wildcard-like words, and credential-shaped words are
rejected. The application stores exactly the validated representation; it does not
case-fold differently at signing or authorization time.

`destination_id` is a logical authority identity only. It never contains or resolves an
access token, API secret, OAuth material, browser cookie, password, private key,
credential path, or session token. Mapping a logical destination to isolated credentials
belongs to the future privileged external-effect adapter.

Operational scope is exact. The model defines no `*`, all/any/default/global value,
null-means-any behavior, prefix match, regex, hierarchy, inheritance, group, or role.
All three dimensions apply to approve, reject, and release. The policy-administration
capability remains explicitly non-applicable to packet scope; its null dimensions are
not wildcard packet authority.

### Confirmed pre-hardening failure boundaries

Before this slice, an active operational grant distinguished only principal, capability,
and state pair. It could not distinguish Brand A from Brand B, channel C1 from C2, or
destination D1 from D2. A signed packet operation had no scope fields, and the packet had
no canonical target against which to compare them. Any later destination metadata would
therefore have been outside both packet identity and approval authority. Existing
Slice-5 operational grants were effectively broad across a dimension the model did not
represent.

The hardening closes each boundary with one invariant:

```text
SignedRequestScope = CanonicalPacketScope = ActiveGrantScope
```

Approval additionally stores that same packet scope. Release requires equality among
the current packet, its approved decision, the signed release, and its selected active
grant. Changing one signed field invalidates Ed25519 verification; changing only stored
packet/approval evidence causes deterministic rejection or integrity failure.

### Scoped grants, requests, and transactional authorization

For packet capabilities, a grant now binds principal, capability, canonical state pair,
brand, channel, and destination. `prepare-policy-operation` requires the full scope for a
new operational grant and places it inside the signed envelope. Grant application accepts
no unsigned subject, capability, or scope override. Revocation derives and signs the
complete binding of its exact immutable target grant. Multiple grants may cover the same
triple; the earliest active grant by policy-event sequence and grant ID remains the
deterministic authorizing evidence.

`prepare-operation` does not ask the operator to repeat scope. It loads and validates the
canonical packet, recomputes its artifact identity, and includes the exact stored triple
in the signed request. The mediator preserves the authenticated fields without allowing
adapter substitution.

The authoritative predicate executes under `BEGIN IMMEDIATE`:

```text
packet proposal
    ↓
canonical packet scope: Brand × Channel × Destination
    ↓
signed operation binds exact scope
    ↓
authenticate principal
    ↓
BEGIN IMMEDIATE
    ↓
reread packet/state/scope and derive required capability
    ↓
evaluate Principal × Capability × State × Brand × Channel × Destination
    ↓
revalidate artifact + approval + deterministic admissibility
    ↓
consume proof + transition/denial + chained scoped evidence
```

The exact request/packet comparison precedes grant selection inside that transaction.
A scope or revocation change observed by the serialized writer causes a consumed chained
denial and no packet/candidate/approval mutation. Stable reasons distinguish missing
scope, request/object disagreement, legacy unscoped grants, and brand, channel, or
destination mismatches. A later grant cannot revive the consumed proof.

### Evidence, migration, and verification

New events and exact committed receipts record authorization scope version, brand,
channel, and destination. Accepted events also name the exact scoped grant. Denied events
record the canonical packet scope actually evaluated and their machine-readable reason.
Authentication failures make no authorization claim; identifiable replays preserve the
signed scope with `not_evaluated` status.

The Slice-4 hash chain remains version/domain `1.0`. Scope is present in the canonical
receipt and mirrored event columns before hashing, so it is covered without changing the
fixed top-level v1 material. Schema-4→5 migration only adds nullable columns and a
scope-aware lookup index. It does not rewrite historical event or receipt JSON, JSONL,
activation state, sequence, predecessor, hash, chain head, policy row, grant, or
revocation. Repeated migration is idempotent.

Historical packets and operational grants remain accurately unscoped. They are never
promoted to a default or global triple and cannot authorize scoped operations; a fresh
scoped packet/grant is required. Historical `policy.manage_capabilities` grants remain
effective because policy administration is inherently unscoped.

Read-only `verify-integrity` reports a schema-4 database as scope not activated and does
not migrate it. On schema 5 it validates complete and syntactically safe scopes, packet
manifest/receipt scope, generation evidence, signed grant and authenticated-operation
bindings, approval equality, authorization event/receipt alignment, exact authorizing
grant order and revocation order, and absence of fabricated historical scope. These
failures remain under `canonical_policy`; chain validity, policy validity, projection
validity, and recoverable projection completeness remain separate outputs.

Slice 6 adds no live platform connection, account discovery, OAuth, credential storage,
or external publication. `RELEASED` remains a local authorization state.

## Slice 7: privileged external-effect adapters

Schema 6 introduces append-only destination bindings, trusted executor public
identities, external-effect requests, dispatch claims, and signed results. The existing
chain remains domain/version `1.0`; every accepted or denied management adjudication,
derived request, claim, and ingested result is another native event. Migration does not
backfill or reinterpret any Slice 1–6 event.

`effect.manage_bindings` is explicit, unscoped management authority and is never
bootstrap-granted. Signed registration envelopes bind all destination or executor fields,
and the transaction re-evaluates the exact active grant under `BEGIN IMMEDIATE` before
consuming the proof. Logical scope is immutable and one-to-one with adapter, external
target reference, and credential reference. The reference is canonical evidence; its
credential value is executor-local and never canonical evidence.

The effect request is a deterministic projection of existing authority, not a second
human authorization. Its domain-separated SHA-256 binds the packet and candidate,
accepted release event/hash/sequence, approval, releasing principal, exact release grant,
full scope, binding, fixed adapter, target and credential references, packet manifest and
receipt hashes, application version, and stable idempotency key. Creation recomputes the
packet before committing the request and event atomically.

Claims serialize writers and assign consecutive attempts. A claim without a signed
result remains unresolved and cannot be blindly retried. Only `FAILED` with confirmed
`effect_may_have_occurred=false` and explicit `retry_permitted=true` permits another
attempt; `SUCCEEDED` and `UNKNOWN` are terminal for automatic retry. This is a local
idempotency protocol, not proof of remote exactly-once behavior.

The separable `gs2c-effect-executor` verifies chain, policy, effect ledger, release
authority, binding, and artifacts read-only, rehashes immediately at invocation, resolves
credentials inside its process, invokes only the fixed no-network `test.capture` adapter,
and signs the outcome with a distinct Ed25519 executor identity. GS2C stores only that
identity's public verifier. Ingestion rejects unsigned, unknown-executor, mismatched, or
duplicate results and commits the verified result/event/head atomically.

Read-only verification reports `canonical_external_effect_valid` independently from
chain, policy, projection validity, and recoverable projection completeness. It validates
all registration, release/grant/approval/binding/request/claim/result links, ordering,
hashes, adapter vocabulary, artifact identity, retry admissibility, and executor
signature evidence. A schema-5 database is reported as not activated and is never
silently migrated by verification.

The executor boundary provides process and configuration separation only. It is not a
sandbox, hardened OS boundary, external anchor, timestamp authority, live provider,
publication credential manager, or defense against complete host/database compromise.
