# ADR-0002. Trust and binding come from the reader

**Status:** accepted. **Date:** 2026-10-17.

## Context

A review store can be published by anyone, so anyone can file a record that claims
to be a review by a well-known auditor. The question this tool answers is "who that
**I** trust reviewed these bytes". Only the reader's trust config can answer it.

## Decision

- The reader passes a warrant trust config (SPEC §12) that binds reviewer ids to keys.
- The reader's warrant (0.11.0 or later) verifies the review store at settlement
  grade with `--require-bound` (warrant WRT-018). A record whose own actor did not
  sign with a key bound to that actor is an `ERR`.
- Records with an `ERR` are **set aside one by one**, not fatal to the whole store.
  A review store is shared and appended to by many hands, and one bad record must not
  silence every good one. The number set aside for an artifact is shown next to its
  verdict.
- An `ERR` about the store as a whole (subject `settlement` or `store`: an unusable
  trust config, say), or a verifier that produces no report, refuses the run.

## Normative

- **WVET-T1.** A check MUST require a trust config supplied by the reader; reviewers are bound to keys only through it.
- **WVET-T2.** The reader's warrant MUST verify the review store at settlement grade with the required-binding option; a record it reports with an `ERR` MUST NOT count, a store-level `ERR` or a missing report MUST refuse the run, and warnings MUST NOT change a verdict.

## Considered

- **Refuse the whole store on any `ERR`** (as warrant-pdf does for a contract). A
  contract is one document, while a review store is a commons. Refusing it whole hands
  a veto to whoever appends one broken record.

## Consequences

- A reviewer missing from the reader's trust config counts as nobody. That is the
  point, and it means each reader curates whom they trust, as with cargo-crev's web of
  trust but without transitive trust.

## Counter-vectors

`test_without_reader_trust_refuses`, `test_review_signed_with_another_key_is_set_aside`,
`test_reviewer_unknown_to_the_reader_is_set_aside`, `test_unavailable_verifier_refuses`,
`test_broken_trust_config_refuses`.
