# warrant-vet

Admit dependencies by signed reviews of their exact bytes, under **your** trust.

A review is an ordinary [warrant](https://github.com/s0fractal/warrant) record: an
`accept` or `reject` whose subject is a descriptor of one artifact (ecosystem, name,
version and the digest your lockfile already pins), filed under a named standard
such as `safe-to-deploy`. `warrant-vet check` reads your lockfile, verifies a review
store with your warrant and your trust config, and gives every dependency one
verdict.

**Status:** `warrant-vet/0`, a working prototype. Cargo and npm lockfiles. Demo
reviews only; no real audits are published here.

## Try it

```sh
pip install warrant-verify==0.11.0     # your verifier; warrant-vet calls it
python3 -m warrant_vet check demo/Cargo.lock --store demo/reviews \
        --trust demo/trust.json --policy demo/policy.json
```

```
REJECTED   cargo regex 1.13.1   rejected by bob@demo.test
UNREVIEWED cargo libc 0.2.189
UNREVIEWED cargo serde 1.0.229
UNPINNED   cargo patched-lib 0.3.0  source 'git+…' carries no checksum
ADMITTED   cargo aho-corasick 1.1.5  accepted by alice@demo.test
ADMITTED   cargo itoa 1.0.18  accepted by alice@demo.test
ADMITTED   cargo memchr 2.8.3  accepted by alice@demo.test, bob@demo.test
LOCAL      cargo demo-app 0.1.0  workspace member: no registry artifact

REJECTED 1, UNREVIEWED 2, UNPINNED 1, ADMITTED 3, LOCAL 1
```

The lockfile entries are real (crates.io checksums, from sokol-core's lockfile). The
reviews are **demo reviews by test actors**, and each says so in its reason. serde
is unreviewed because alice withdrew her review.

Filing a review:

```sh
python3 -m warrant_vet review Cargo.lock memchr 2.8.3 --store reviews \
        --criteria safe-to-deploy --actor you@example --key you.key \
        --reason "read the diff since 2.8.2"          # add --reject for a finding
```

## What a verdict means

- **ADMITTED**: at least `min_accepts` distinct reviewers, each bound to a key in
  *your* trust config, filed an `accept` of exactly this descriptor under your
  policy's criteria. None of them withdrew it, and no counted reviewer has a standing
  `reject`.
- **REJECTED**: a counted reviewer has a standing `reject`. One veto is enough.
- **UNREVIEWED**: not enough accepts. This includes reviews of other bytes under the
  same name and version (a substituted artifact), reviews by people you do not trust,
  and reviews signed with someone else's key.
- **UNPINNED**: the lockfile has no content digest for it (a git dependency, or a
  registry entry without a checksum).
- **LOCAL**: your own workspace.

`check` exits 0 only when everything is ADMITTED or LOCAL.

## What it protects against, and what it does not

**It catches:**
- a substituted artifact (a mirror, a custom build, a re-published version);
- a compromised maintainer account publishing a new version, which stays
  unreviewed until someone you trust reviews it;
- a forged review signed with another key (warrant's `--require-bound`).

**It does not catch:**
- malicious code your trusted reviewer missed: a review shows who approved, not
  that the code is clean;
- `build.rs` or postinstall scripts fetching things at build time, which the
  lockfile digest does not cover;
- a compromised warrant on your machine. Pin it.

## Related work

**[cargo-crev](https://github.com/crev-dev/cargo-crev)** has signed package reviews
and a web of trust, and is the closest prior art.
**[cargo-vet](https://github.com/mozilla/cargo-vet)** introduced named *criteria*
and imports of audits from others' files. Its audits are not signed.
**Sigstore / SLSA / in-toto** attest who *built* or *published* an artifact, not
who reviewed it.

warrant-vet differs in:
- one record format across ecosystems;
- content-addressed records with settlement semantics (reject, supersede);
- policies whose threshold is a count of distinct trusted reviewers;
- reasons that can be re-run (`ski@v1`);
- three independent verifier implementations held to one conformance pack.

## How it is built

The same discipline as [warrant-pdf](https://github.com/s0fractal/warrant-pdf):
- [SPEC.md](SPEC.md) is generated from the [ADRs](docs/adr/).
- Each normative statement has a [contract](contracts/): its witness tests,
  mutants and history, including the counterexamples that changed it.
- [tests/test_counter_vectors.py](tests/test_counter_vectors.py) holds one attack
  per test.
- A mutant counts as killed only when a witness of its own statement fails.

```sh
sh scripts/local-ci.sh     # demo reproduces, contracts, tests, mutants
```

License: MIT.
