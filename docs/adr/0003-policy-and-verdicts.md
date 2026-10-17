# ADR-0003. Policy and verdicts

**Status:** accepted. **Date:** 2026-10-17.

## Context

Reviewers apply different standards. "Safe to run in CI" is not "safe to ship to
customers". cargo-vet names such standards *criteria*. A reader also decides how many
independent reviewers are enough, and whose rejection is final.

## Decision

- A review files `under` a **criteria blob**,
  `{"profile":"warrant-vet/0","criteria":"<name>"}`. The reader's policy names one
  criteria, and only reviews filed under exactly that blob count.
- `policy.json`:
  `{"warrant_vet":"0","criteria":"safe-to-deploy","min_accepts":1,"reviewers":[...]}`.
  `reviewers` is optional; without it, every reviewer the trust config binds counts.
- **Verdict per registry artifact:**
  - `REJECTED` if any counted reviewer has an active `reject`; one veto suffices;
  - otherwise `ADMITTED` if at least `min_accepts` **distinct** counted reviewers have
    an active `accept`;
  - otherwise `UNREVIEWED`.
- A reviewer withdraws its own review with a `supersede` whose `prior` names that
  review. A `supersede` by anyone else withdraws nothing.
- `check` exits 0 only if every artifact is `ADMITTED` or `LOCAL`.

## Normative

- **WVET-P1.** Only `accept` and `reject` records whose subject is the artifact's descriptor and whose `under` contains the policy's criteria blob MUST count.
- **WVET-P2.** An active `reject` by a counted reviewer MUST make the artifact `REJECTED`, whatever the accepts.
- **WVET-P3.** An artifact MUST be `ADMITTED` only when at least `min_accepts` distinct counted reviewers have an active `accept`; when `reviewers` is given, only those reviewers count.
- **WVET-P4.** A review MUST stop counting when its own actor files a `supersede` naming it, and only then.
- **WVET-P5.** `check` MUST exit 0 only when every lockfile entry is `ADMITTED` or `LOCAL`, and MUST refuse a policy with unknown members, an empty criteria, or `min_accepts` below 1.

## Considered

- **Majority vote between accepts and rejects.** A reject usually reports a concrete
  finding. Outvoting a finding is not a review process, so a single veto stands until
  its author withdraws it.
- **Transitive trust** (a trusted reviewer's trusted reviewers). It is out of scope
  for `warrant-vet/0`. The reader's trust config is the whole set.

## Consequences

- A malicious reviewer the reader trusts can veto anything. That reviewer's key is
  the reader's own choice, and removing it from `trust.json` ends the veto.
- Withdrawal is by the reviewer only. A reject that turns out to be wrong stays until
  its author supersedes it, or the reader stops counting that reviewer.

## Counter-vectors

`test_demo_verdicts`, `test_reject_vetoes_accepts`, `test_withdrawn_review_does_not_count`,
`test_withdrawal_by_another_actor_withdraws_nothing`, `test_other_criteria_does_not_count`,
`test_min_accepts_counts_distinct_reviewers`, `test_reviewer_allowlist`, `test_policy_refuses_malformed`,
`test_exit_zero_only_when_all_admitted`.
