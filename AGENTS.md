# Working in warrant-vet

- **Every change goes through a pull request.** No direct commits to `main`.
- **A normative change starts in an ADR.** Edit the ADR's Normative section, run
  `python3 tools/contracts.py spec`, and add a decision to the statement's contract.
  The decision says why, the new `statement_sha256`, and the previous one. Never
  edit SPEC.md by hand, and never rewrite a contract's history.
- **A counterexample is recorded, not hidden.** When a test, a mutant or a review
  shows a statement was wrong or unwitnessed, write the counter-vector test, fix the
  code or the statement, and record the counterexample (`witness`, `observed`,
  `expected`) in the contract's decision. All of this lands in one PR, and CI stays
  green: red is evidence in the record, not a red build.
- **Every rule has its own witness and its own mutant.** A mutant that only kills
  tests of *other* statements (`OFF_TARGET`) means the rule has no witness of its
  own. Add one.
- **Never re-implement warrant.** Canonical form, WarrantIDs, signatures, key
  state and trust come from the reader's `warrant` command.
  and compare. The comparison document says what is and is not borrowed.
- Run `sh scripts/local-ci.sh` before pushing (`MUTATE=0` for a fast pass).
- Files are in English. The demo keys are public test keys and demo reviews say so; never add real keys or present a demo review as an audit.
