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
- canonical packet brand/channel/destination scope and its governed identity binding;
- manifest hashing;
- approval and release gates;
- authenticated-principal and exact-operation verification;
- immutable authenticated transition requests and deterministic mediation;
- fixed principal-by-capability-by-state-by-exact-scope authorization for packet actions;
- authenticated, append-only capability grant and revocation policy;
- single-use authenticated-operation consumption;
- atomic SQLite transition events; and
- append-only JSONL receipt projection.

## Evidence

When a source file is supplied, the application creates a new candidate-specific directory, opens the destination exclusively, copies bytes, and verifies the SHA-256 hash. There is no evidence update command. A different source must become a different evidence record rather than silently replacing a prior file.

A URL-only ingest is not an archive operation. Its evidence record states that content was not preserved.

## Human approval and authenticated identity

Generation ends in `AWAITING_APPROVAL`. Immediately before approval, the application
recomputes every governed artifact hash and requires the canonical manifest to equal
the packet row's stored manifest. Approval and rejection require an Ed25519 signature
from the one trusted principal bootstrapped into the empty local registry. The signature
covers a canonical, short-lived exact-operation envelope binding the principal and key,
unique operation ID, operation, packet and candidate, expected states, manifest and
packet-receipt hashes, decision, approval identity, reason, and timestamps.
For new packets it also covers the canonical scope version, brand ID, channel ID, and
destination ID derived from the packet rather than repeated as unsigned authority input.

Authentication alone is insufficient. Approval additionally requires an active
`packet.approve` grant scoped to `AWAITING_APPROVAL → APPROVED`; rejection requires
`packet.reject` for `AWAITING_APPROVAL → REJECTED`; and release requires
`packet.release` for `APPROVED → RELEASED`. Every operational grant must also match the
packet's exact canonical brand/channel/destination triple. Application code derives the
capability and rereads the packet scope, so CLI text or signed-request fields cannot
substitute weaker authority.

The canonical SQLite approval decision records the asserted actor, authenticated
principal and operation references, time, prior state, exact manifest hash, decision,
transition event ID, and exact packet scope in the same transaction that consumes the
operation and changes packet and candidate state. The approval JSON file is a
human-readable projection.

The `actor` value remains operator-supplied display/compatibility text and is recorded as
`asserted_actor`. It is never authentication evidence and need not equal the stable
`authenticated_principal_id`. A rejection is terminal for that packet in v0.1.0 and is
therefore also authority-sensitive.

Release requires `APPROVED`, a canonical approved decision, and equality among the
freshly recomputed packet manifest, stored packet manifest, and approval manifest.
Release requires a distinct signed release operation bound to that exact canonical
approval identity and transition event. An approval proof cannot authenticate release,
and a release proof cannot authenticate approval. The packet, approval, release request,
and release grant scopes must all be equal. Release authorizes downstream publication
only locally and contacts no external platform.

## Canonical packet scope

Schema 5 defines packet scope as one versioned exact triple:

```text
scope_version = 1.0
brand_id × channel_id × destination_id
```

These are stable, lowercase, slug-like logical identifiers. They are case-sensitive
after validation because only the canonical lowercase representation is accepted.
Whitespace, path/URL syntax, wildcard-like components, and credential-shaped components
are rejected. A destination ID names where a future effect would be permitted; it is not
an OAuth token, cookie, password, private key, credential path, or live account lookup.
No registry is needed in this slice because the enforced invariant is exact equality,
not lifecycle, hierarchy, or relationship membership. Adding a registry without a
governed mutation path would create a new authority bypass.

Scope becomes canonical during `QUALIFIED → PACKET_GENERATED`. The validated content
input proposes it, while the deterministic generator writes it to the packet row and
into `sources.json`. Because `sources.json` participates in the packet manifest and the
packet receipt repeats and binds the same scope, changing any dimension changes or
invalidates governed packet identity. There is no supported packet-scope update helper.
A changed intended target requires a newly generated packet identity and fresh review.

Operational grants are exact only. There is no `*`, `all`, `any`, null-means-any,
prefix, hierarchy, regex, role, or inheritance interpretation. `policy.manage_capabilities`
remains explicitly unscoped because it governs policy administration rather than a
packet destination. Legacy schema-4 packets and Slice-5 operational grants retain null
scope as honest historical evidence and fail closed with `SCOPE_REQUIRED` or
`LEGACY_UNSCOPED_GRANT`; migration never broadens them. Legacy policy-administrator
grants remain effective under their original unscoped policy semantics.

## Mediated canonical execution

`SignedOperation` is untrusted transport. After Ed25519, identity, freshness, and replay
verification, application logic creates an immutable `AuthenticatedTransitionRequest`
that preserves every signed semantic field and its proof provenance. The
`TransitionMediator` derives operation, target, states, decision, reason, manifest, and
approval binding from that request. Compatibility CLI arguments may reject a mismatch;
they never replace authenticated execution values.

The mediator owns current-state, paired-object, artifact, approval, request/packet scope,
capability, and deterministic state-map checks. `CanonicalTransitionService` owns the supported packet
authority write route. Its serialized SQLite transaction re-evaluates the exact active
grant and commits the decision evidence with state, approval, proof, event, and chain.
No stale outside-transaction allow or scope observation can authorize a later write.

Inside `BEGIN IMMEDIATE`, the canonical service rereads packet scope, requires it to
equal the signed request, derives the required capability, and selects an active exact
scoped grant. The decision records the actual canonical scope. Brand, then channel,
then destination mismatch reasons are deterministic; a verified denial consumes the
proof and chains the rejection without mutating governed state.

Internal progression from discovery through `AWAITING_APPROVAL` remains deterministic
and does not require human authentication. Capability authorization is default-deny for
approve, reject, and release, and never follows merely from authenticated identity.

## Capability policy

SQLite schema 6 retains direct principal grants and separate revocations. The fixed
vocabulary is `packet.approve`, `packet.reject`, `packet.release`, and
`policy.manage_capabilities`, plus the deliberately separate
`effect.manage_bindings`. Operational grants carry their one canonical state pair and
full packet scope; both management capabilities have null workflow states and no packet
scope. Policy bootstrap never grants effect-management authority. There are no roles,
groups, wildcards, inheritance, or policy language.

An authenticated, single-use bootstrap operation creates only the first
`policy.manage_capabilities` grant. It succeeds once, only for the original sole trusted
principal. Every later grant or revocation must itself be signed by a principal with an
active policy-management grant. Self-grants are permitted in the local single-principal
model, but removal of the final policy administrator is denied. Operational grants are
never inferred from authentication, actor names, prior history, or migration.

Verified authorization denials consume their signed proof and create a chained event
without mutating packet or approval state. Granting authority later does not revive the
old proof. Authentication failure remains distinct and carries no fabricated
authorization attribution.

## Trust and credential boundary

The `trusted_principals` SQLite table stores a stable principal ID, Ed25519 scheme,
derived key ID, public verification key, and verifier fingerprint. Exactly one principal
can be bootstrapped while that registry is empty. This assumes the legitimate local
operator controls the workspace and database at bootstrap time; broad enrollment,
rotation, revocation, delegation, and multi-user administration are deferred.

The private signing key stays at an explicit operator-selected filesystem path outside
the repository and governed workspace. It is not stored in SQLite, packet or approval
files, canonical events, or JSONL receipts. A compromised host, unrestricted database
writer, or stolen private key remains outside this slice's protection.

The same-process boundary is structural rather than cryptographic. Hostile Python code
already executing inside the trusted GS2C process can import internal names or open
SQLite directly. The supported CLI and application facades nevertheless converge on one
mediator and do not accept caller-created authentication booleans or principal objects.

## Receipts

Every accepted or rejected transition attempt creates a canonical SQLite transition
event. Accepted authority-sensitive events commit atomically with authenticated-operation
consumption, state mutation, and any approval decision. Events contain command, asserted
actor, target, identifiers, prior and requested states, resulting state, outcome, reason,
hashes when applicable, application version, timestamp, and UUID event ID. Authenticated
events also carry principal ID, scheme, key ID, verifier fingerprint, operation ID,
envelope hash, proof hash, and verification time. Historical events retain null
authentication fields; migration does not reinterpret asserted actors. The event UUID is
also the stable JSONL receipt run ID.

New packet authorization evidence additionally records scope version, brand, channel,
and destination before chain hashing. Accepted evidence names the exact scoped grant;
denied evidence preserves the canonical scope actually evaluated and a stable reason.
Authentication failures do not fabricate an authorization scope conclusion, while an
identifiable replay records the signed scope with `not_evaluated` provenance.

The append-only JSONL file is an outward projection, not the canonical authority for
new transition events. For each native event, SQLite atomically assigns a unique
monotonic sequence, predecessor SHA-256, event SHA-256, and chain-head update while
committing the event and any state, approval, or proof-consumption changes. The hash uses
versioned, domain-separated canonical JSON and covers immutable event and receipt
evidence. The mutable JSONL projection timestamp and chain-head bookkeeping are excluded.

SQLite stores the exact chain-bearing receipt payload and a nullable projection time. If
an append is interrupted, `gs2c reconcile-receipts --workspace PATH` appends the missing
payload. It recognizes an already appended identical run ID and never rewrites historical
lines or recalculates an event hash. Sensitive key names are redacted before the canonical
event payload is stored.

Schema-2 events are not deceptively backfilled as native chain members. Migration stores
a deterministic activation checkpoint over their immutable evidence in
`(occurred_at_utc, event_id)` order. The first native event is sequence 1 and names that
checkpoint as its predecessor. This records the legacy corpus observed during migration;
it does not prove contemporaneous integrity before activation and does not rewrite legacy
JSONL receipts.

The `authenticated_operations` SQLite ledger makes each verified proof single-use by
unique operation ID and proof hash. A verified request is consumed when canonically
adjudicated, even when state, object, decision, or artifact validation rejects it;
consumption and that rejected event commit together. A replay creates a rejected event
but cannot create a second consumption or mutate state.

`gs2c verify-integrity --workspace PATH` performs a read-only full verification of the
activation checkpoint, sequence continuity, predecessor links, event hashes, chain head,
capability-policy/event linkage, grant/request/packet/approval scope equality, governed
packet scope artifacts, and JSONL correspondence. It reports chain validity,
policy validity, projection validity, and recoverable projection incompleteness
separately.

This remains a local inspectability mechanism, not an independently authenticated
transparency log. A local SHA-256 chain detects partial mutation, deletion, insertion,
reordering, broken linkage, and projection disagreement when the attacker does not also
rewrite all affected hashes and local chain metadata. It is not a digital signature,
external anchor, timestamp authority, or defense against an attacker capable of
recomputing the entire local evidence store. Scoped local authorization establishes only
permission to reach `RELEASED` for the exact governed logical destination; it does not
execute or prove external publication. The Slice 7 boundary below adds only an offline
capture adapter and executor-signed result evidence. Signed/externally anchored history,
hardened credential isolation, live provider adapters, and external publication
credentials remain future work.

## Privileged external effects

Schema 6 stores immutable destination bindings, trusted executor public identities,
derived effect requests, exclusive dispatch claims, and executor-signed results. A
binding maps one exact logical `Brand × Channel × Destination` to fixed adapter
`test.capture`, an opaque external target reference, and an opaque credential reference.
It contains no credential value and cannot be rebound; a different target or credential
requires a new logical destination and binding identity.

Effect intent is derived only after the packet reaches `RELEASED`. Its canonical hash
commits to the accepted release event and sequence, approval, authenticated releasing
principal, exact release grant, scope and binding, packet manifest/receipt hashes,
adapter/target/credential references, and a stable idempotency key. Claims serialize
under `BEGIN IMMEDIATE`. An unresolved claim blocks retry; `SUCCEEDED` and `UNKNOWN`
block retry permanently; only an executor-confirmed `FAILED` result explicitly marked
retry-safe permits the next consecutive attempt.

Executor results use a second Ed25519 identity whose public verifier is registered in
SQLite. The executor private key and resolved credential remain outside the governed
workspace. Result ingestion verifies the signature and every effect, claim, scope,
binding, artifact, adapter, and idempotency field before committing the result and chain
event together. The bundled adapter performs deterministic local capture with no network
access. This establishes process/context separation and locally tamper-evident evidence,
not hardened OS isolation, remote exactly-once delivery, non-repudiation, or safety after
complete host compromise.
