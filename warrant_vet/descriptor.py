"""Artifact descriptors, built from a lockfile and nothing else (ADR-0001).

A descriptor names exactly one artifact by the digest the package manager
already pins: Cargo's `checksum` (SHA-256 of the .crate) or npm's `integrity`.
Its canonical bytes are a warrant blob; their SHA-256 is the `subject.hash` a
review signs. So one signature binds ecosystem, name, version and bytes."""
import hashlib
import json
import re
import tomllib

PROFILE = "warrant-vet/0"
SHA256_HEX = re.compile(r"[0-9a-f]{64}")
NPM_INTEGRITY = re.compile(r"sha(256|384|512)-[A-Za-z0-9+/]+={0,2}")


class LockfileError(Exception):
    pass


def encode(obj):
    """Canonical bytes. Every member is an ASCII string, where RFC 8785 and
    sorted-key compact JSON coincide; non-ASCII is refused, not encoded."""
    for k, v in obj.items():
        if not (isinstance(k, str) and isinstance(v, str) and k.isascii() and v.isascii()):
            raise LockfileError(f"descriptor member {k!r} is not an ASCII string")
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("ascii")


def descriptor(ecosystem, name, version, digest):
    """Refuses at construction, so a lockfile with a look-alike (non-ASCII) name is
    rejected when it is read, not later when a hash is needed."""
    d = {"profile": PROFILE, "ecosystem": ecosystem, "name": name, "version": version, "digest": digest}
    encode(d)
    return d


def subject_hash(desc):
    return hashlib.sha256(encode(desc)).hexdigest()


def criteria_blob(criteria):
    """The blob a review files `under`: which standard the reviewer applied."""
    return encode({"profile": PROFILE, "criteria": criteria})


class Entry:
    """One lockfile line: a descriptor, or why there is none."""

    def __init__(self, ecosystem, name, version, desc=None, status=None, why=""):
        self.ecosystem, self.name, self.version = ecosystem, name, version
        self.desc, self.status, self.why = desc, status, why

    @property
    def key(self):
        return (self.ecosystem, self.name, self.version, self.desc and self.desc["digest"])


def read_cargo_lock(raw):
    try:
        doc = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise LockfileError(f"Cargo.lock: {e}")
    out = []
    for p in doc.get("package", []):
        name, version, source = p.get("name"), p.get("version"), p.get("source")
        if not (isinstance(name, str) and isinstance(version, str)):
            raise LockfileError("Cargo.lock: a package without name/version")
        if source is None:
            out.append(Entry("cargo", name, version, status="LOCAL", why="workspace member: no registry artifact"))
        elif not isinstance(source, str) or not source.startswith("registry+"):
            out.append(Entry("cargo", name, version, status="UNPINNED", why=f"source {source!r} carries no checksum"))
        elif not (isinstance(p.get("checksum"), str) and SHA256_HEX.fullmatch(p["checksum"])):
            out.append(Entry("cargo", name, version, status="UNPINNED", why="registry package without a sha256 checksum"))
        else:
            out.append(Entry("cargo", name, version, descriptor("cargo", name, version, "sha256:" + p["checksum"])))
    return out


def read_package_lock(raw):
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise LockfileError(f"package-lock.json: {e}")
    if not isinstance(doc, dict) or doc.get("lockfileVersion") not in (2, 3) or not isinstance(doc.get("packages"), dict):
        raise LockfileError("package-lock.json: lockfileVersion 2 or 3 with `packages` is required")
    out = []
    for path, p in doc["packages"].items():
        if path == "" or not isinstance(p, dict):
            continue
        name = p.get("name") or path.rsplit("node_modules/", 1)[-1]
        version = p.get("version")
        if p.get("link"):
            out.append(Entry("npm", name, str(version), status="LOCAL", why="linked workspace package"))
        elif not isinstance(version, str):
            raise LockfileError(f"package-lock.json: {path} has no version")
        elif not (isinstance(p.get("integrity"), str) and NPM_INTEGRITY.fullmatch(p["integrity"])):
            out.append(Entry("npm", name, version, status="UNPINNED", why="no integrity digest"))
        else:
            out.append(Entry("npm", name, version, descriptor("npm", name, version, p["integrity"])))
    return out


def read_lockfile(path, raw):
    name = str(path).rsplit("/", 1)[-1]
    if name == "Cargo.lock":
        entries = read_cargo_lock(raw)
    elif name == "package-lock.json":
        entries = read_package_lock(raw)
    else:
        raise LockfileError(f"{name}: supported lockfiles are Cargo.lock and package-lock.json")
    for e in entries:
        if not (isinstance(e.name, str) and e.name.isascii() and isinstance(e.version, str) and e.version.isascii()):
            raise LockfileError(f"{e.name!r} {e.version!r}: names and versions must be ASCII")
    seen, unique = set(), []
    for e in entries:
        if e.key not in seen:
            seen.add(e.key)
            unique.append(e)
    return unique
