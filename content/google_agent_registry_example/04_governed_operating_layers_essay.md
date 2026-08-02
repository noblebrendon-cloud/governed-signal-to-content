# Governed operating layers for evidence-backed content

The central design question is not whether probabilistic systems can produce useful interpretations. They can. The question is which part of a system should be allowed to change durable, authoritative state. Governed Signal-to-Content answers with a firm boundary: **probabilistic intelligence embedded inside deterministic systems**. A person or model may propose a classification, an inference, or a draft. Deterministic application logic validates those proposals, checks prior state, and decides whether a transition is permitted.

## 1. Documented facts

Google Cloud's Agent Registry documentation provides a bounded primary-source signal for this design discussion. The overview describes a centralized catalog for agents, MCP servers, endpoints, and standalone skills. Its data model distinguishes standalone skills from A2A skills: standalone skills are executable packages governed directly as `Skill` resources, while A2A skills are declarative metadata blocks represented inline in an agent's Agent Card.

The registration documentation says standalone skills are managed as top-level resources and that administrators can apply fine-grained access policies and manage version history using skill revisions. The concepts documentation describes `SkillRevision` as an immutable, versioned snapshot of a skill package. It states that a skill has a default revision and can contain multiple versioned revisions. It also defines a `Publisher` as an entity that creates and registers skills. These statements are limited to the four primary sources recorded with this packet.

## 2. Reasonable inference

Resource identity and revision history can make a reusable capability easier to discover, control, and inspect than instructions that exist only inside an ephemeral conversation. A stable parent identity lets consumers refer to a capability while revisions change. A policy boundary can limit use. A publisher identity provides context about origin. These are reasonable architectural inferences from the documented resource model; they are not assertions about undocumented internal controls or operating outcomes.

That distinction matters. Evidence-backed analysis should not silently convert interpretation into fact. The packet therefore stores sources separately and labels the reasoning layer. A reader can disagree with the inference without having to dispute what the documentation actually says.

## 3. Direct structural similarity

The direct similarity to Governed Signal-to-Content is intentionally narrow. Both approaches value durable operational identity, controlled reuse, revision history, lifecycle governance, and capabilities treated as managed resources. These are design principles, not a claim of product or architectural equivalence. Google Cloud Agent Registry is not equivalent to Clarity Systems Group's architecture, and this repository does not reproduce or emulate the registry.

Governed Signal-to-Content applies those principles to an evidence-to-publication-candidate workflow. An external signal receives a stable candidate identity. When local source bytes are supplied, the application preserves them under an exclusive path, records the original filename and byte size, and verifies a SHA-256 digest. When only a URL is supplied, the evidence record says `content_preserved: false`; it does not pretend that remote content was archived.

The candidate then passes deterministic normalization and duplicate checks. URL normalization, source identity, and known development identifiers are compared before qualification. A proposed classification must keep documented facts, reasonable inferences, direct similarities, and broader industry trends in separate fields. Even a valid classification file cannot change state by itself. The application verifies its decision and current state before moving a candidate to `QUALIFIED`.

Packet generation is another controlled boundary. The generator accepts validated content inputs, writes a fixed seven-file directory through a temporary path, hashes the artifacts, and records target-length warnings. A slightly short or long draft does not disappear or fail silently. The finished packet moves to `AWAITING_APPROVAL`, not to a published state.

Approval binds a named human actor to the packet manifest hash. Release is permitted only from `APPROVED`. In version 0.1.0, `RELEASED` means locally authorized for downstream publication. The command does not contact a social network, content platform, package index, GitHub Release endpoint, or archival service.

## 4. Broader industry trend

A broader industry trend is emerging around agent infrastructure: capabilities are shifting from transient text toward managed resources. Registries, reusable skills, explicit interfaces, versioned packages, and policy gates all reflect pressure for systems that can retain identity and control after the originating model context has vanished. This observation extends beyond the Google sources and is explicitly labeled as a trend rather than a documented Google fact.

The governance requirements grow as the operating boundary widens. Reusable content work needs more than capability registration. It needs source identity so an external signal can be recognized later; evidence lineage so claims remain connected to sources; approval authority so responsibility is explicit; persistent local workflow state so work survives process restarts; publication authorization so preparation is not confused with posting; multi-brand control surfaces so downstream context can be governed; and command receipts so accepted and rejected actions remain inspectable.

Those extensions describe this repository's scope. They do not imply that Google lacks or supplies the same functions. The comparison stays at the level of shared governance principles while the implementation boundaries remain distinct.

## Layered responsibility

The system's operating layers are small on purpose. Adapter contracts reserve space for future discovery and interpretation providers. Those providers can propose signals, classifications, and drafts, but they do not receive database authority. Pydantic models and JSON Schemas validate records at boundaries. SQLite persists authoritative candidate and packet state in a user-selected workspace. An explicit transition map rejects shortcuts such as `DISCOVERED` to `APPROVED` or `QUALIFIED` to `RELEASED`.

Append-only JSONL receipts record every accepted or rejected transition attempt. Canonical JSON serialization makes manifest hashing stable. Packet files and preserved evidence are created without overwriting an existing path. Together, these mechanisms make the workflow inspectable without pretending that software alone guarantees truth.

The result is a modest reference implementation of disciplined preparation. Probabilistic reasoning contributes where ambiguity is unavoidable. Deterministic code controls consequential state. Humans remain responsible at the approval boundary. Evidence and receipts keep the chain visible. Publication stays outside the system.
