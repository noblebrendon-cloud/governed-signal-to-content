# Google Agent Registry operational case

> This directory is a sanitized public export. Canonical runtime evidence, SQLite state, approval records, and append-only receipts remain in the configured local governed workspace and were not moved or rewritten.

## Purpose

This is the first real use of Governed Signal-to-Content against the Google Cloud Agent Registry standalone-skill development that originally motivated the repository. It tests the system as an operating workflow rather than treating the tracked example packet as proof of execution.

The run used four existing Google Cloud primary-source URLs. The overview page was downloaded and byte-preserved during ingestion; the other three pages were verified as resolving and retained as honest URL references. See [source-manifest.json](source-manifest.json).

## Causal sequence

```text
External signal
→ source evidence
→ normalized candidate
→ duplicate check
→ structured qualification
→ five-artifact packet
→ human approval
→ local release authorization
→ public communication (manual external boundary; not performed by the CLI)
```

Candidate `cand_3034defafdde4051afdecb4976cd0864` produced packet `pkt_64e811082405471ea8369a9bd4c4b430`. Eight accepted transition receipts moved the candidate and packet to `RELEASED`. In this application, `RELEASED` means locally authorized for downstream publication; it does not mean posted online.

## Qualification boundary

The [classification](classification.json) separates documented facts, reasonable inferences, direct similarities, broader industry trends, primary sources, and structural-overlap dimensions. The positive qualification proposal was accepted only after deterministic application logic confirmed the candidate's prior state.

The comparison does not claim architectural equivalence. Direct similarity is limited to capabilities treated as managed resources, durable operational identity, revision history, controlled reuse, and lifecycle governance. Governed Signal-to-Content additionally governs source identity, evidence lineage, duplicate suppression, deterministic workflow state, approval authority, publication authorization, persistent local state, and append-only receipts.

## What the system handled

- Created one stable candidate and one evidence record.
- Preserved 106,166 source bytes and verified SHA-256 identity `4be73b25abda8181e10f2ea0497e4bd2acf7c77ef24a009c20613b5a2b295e71`.
- Normalized the source URL and candidate record.
- Checked source identity, normalized URL, and development identifiers for duplicates.
- Validated the structured classification before applying `QUALIFIED`.
- Atomically generated the fixed seven-file packet with all five content artifacts.
- Hashed packet outputs and produced manifest `72d03c60193f9fa72b63f83ab068bd0c393583f3392bcf03a850a3746ee168d0`.
- Recorded two non-blocking target-length warnings.
- Enforced named human approval before local release authorization.
- Appended a receipt for every accepted transition attempt.

## What remained manual

- Discovering the external signal and selecting the bounded case.
- Retrieving the central primary-source page and checking the four source URLs.
- Drafting and fact-checking the classification JSON.
- Preparing the five content drafts in the content-input JSON.
- Capturing generated candidate, packet, and run IDs from CLI output and the receipt log.
- Exporting and sanitizing public summaries without altering canonical records.
- Posting to LinkedIn, Facebook, Substack, or another public platform.
- Capturing a public LinkedIn URL after manual publication.
- Enabling Zenodo and recording the verified DOI for the earlier `v0.1.0` repository release.

## Outcome

| Output or state | Observed outcome |
|---|---|
| Five packet artifacts | Generated |
| Exact packet manifest | Approved by Brendon R. Coleman |
| Packet | Locally authorized as `RELEASED` |
| External publication by `gs2c` | Not performed |
| LinkedIn analysis | Manual publication reported; public URL not captured, so public verification remains pending |
| Facebook post | Approved and locally authorized draft; no publication evidence captured |
| Long-form/Substack essay | Approved and locally authorized draft; not claimed as published |
| Mermaid diagram and repository note | Approved packet artifacts; no standalone publication claimed |

See [publication-status.md](publication-status.md) for the non-collapsed publication states.

## Evidence index

- [workflow-summary.json](workflow-summary.json) — sanitized run summary and initialization evidence.
- [receipt-index.json](receipt-index.json) — sanitized receipt fields plus hashes of the original canonical JSONL lines.
- [packet/](packet/) — byte-for-byte exported copies of the canonical generated packet.
- [friction-log.md](friction-log.md) — observed manual work and bounded responses.

The packet receipt records `AWAITING_APPROVAL` because it is a generation-time artifact. Later approval and release authorization are evidenced by the receipt index and workflow summary; the packet receipt was not retroactively edited.

## Reproducibility boundary

The repository can reproduce governed preparation, deterministic state checks, evidence identity, packet hashing, approval gating, and execution receipts. It cannot reproduce or prove third-party platform posting without external publication evidence. Public-platform posting remains outside the CLI and requires separate manual authorization and URL capture.
