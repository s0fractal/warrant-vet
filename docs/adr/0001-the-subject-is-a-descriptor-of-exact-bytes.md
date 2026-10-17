# ADR-0001. The subject is a descriptor of exact bytes

**Status:** accepted. **Date:** 2026-10-17.

## Context

A review means something only about the bytes that were reviewed. Package managers
already pin those bytes in their lockfiles. Cargo records the SHA-256 of each `.crate`
(`checksum`); npm records an SRI digest (`integrity`). A review of "serde 1.0.229"
without the digest would survive a registry that serves different bytes under the
same name and version.

## Decision

A **descriptor** is a JSON object with exactly the members `profile`
(`warrant-vet/0`), `ecosystem`, `name`, `version` and `digest`:
- `digest` is `sha256:<hex>` for Cargo;
- for npm it is the lockfile's `integrity` string as written.

Its canonical bytes (sorted keys, compact) are added to the review store as a blob.
The SHA-256 of those bytes is the `subject.hash` every review of that artifact signs.
One signature therefore binds the ecosystem, name, version and digest together.

The descriptor is built from the lockfile alone, with no download. Entries that
cannot be described are classified, not guessed:
- a workspace member, or an npm `link`, is `LOCAL`;
- a git or path dependency, or a registry entry without a digest, is `UNPINNED`.

## Normative

- **WVET-D1.** A review's subject MUST be the SHA-256 of the canonical descriptor `{"profile","ecosystem","name","version","digest"}` whose members are ASCII strings; a review of any other descriptor, including the same name and version with another digest, MUST NOT count for an artifact.
- **WVET-D2.** A descriptor MUST be built from the lockfile's own digest: a registry entry without a digest and a git or path dependency MUST be reported `UNPINNED`, a workspace member `LOCAL`, and a name or version that is not ASCII MUST refuse the lockfile.

## Considered

- **Hash the downloaded artifact ourselves.** That needs network access and trust in
  the download path. The lockfile digest is what the package manager will enforce at
  install, so reviewing that digest closes the loop without a second fetch.
- **The digest alone as the subject.** The same bytes under two names (a re-publish,
  a fork) would share reviews. Binding name and version too keeps a review about one
  published artifact.

## Consequences

- A git dependency cannot be admitted. Its source string names a commit, but
  `Cargo.lock` carries no content digest for it. Supporting it needs a separate
  descriptor kind (a commit plus a tree hash).
- npm digests are compared as strings. The same tarball described with `sha1-` in one
  lockfile and `sha512-` in another gives two descriptors, so it needs two reviews.

## Counter-vectors

`test_subject_hash_is_pinned`, `test_review_of_another_version_does_not_count`,
`test_changed_checksum_unreviews`, `test_git_dependency_is_unpinned`,
`test_workspace_member_is_local`, `test_non_ascii_name_refuses`,
`test_npm_lockfile_entries`.
