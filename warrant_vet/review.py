"""File a review: an `accept` or `reject` of one artifact, through the warrant CLI."""
import tempfile
from pathlib import Path

from . import wcli
from .descriptor import criteria_blob, encode


def file_review(cmd, store, desc, criteria, decision, actor, key, reason, ts):
    """Returns the WarrantID. The descriptor and criteria blobs go into the store,
    so a reader can see exactly what was reviewed and against which standard."""
    if decision not in ("accept", "reject"):
        raise ValueError("decision must be accept or reject")
    if not Path(store, "records").is_dir():
        wcli.checked(cmd, ["--store", str(store), "init"])
    with tempfile.TemporaryDirectory() as tmp:
        d, c = Path(tmp, "descriptor.json"), Path(tmp, "criteria.json")
        d.write_bytes(encode(desc))
        c.write_bytes(criteria_blob(criteria))
        for p in (d, c):
            wcli.checked(cmd, ["--store", str(store), "blob", "add", str(p)])
        note = f"{desc['ecosystem']} {desc['name']} {desc['version']}"[:200]
        out = wcli.checked(cmd, ["--store", str(store), decision, "--subject", str(d), "--under", str(c),
                                 "--note", note, "--reason", reason, "--actor", actor,
                                 "--key", str(key), "--ts", str(ts)])
    return out.strip().splitlines()[-1]


def withdraw(cmd, store, wid, actor, key, reason, ts):
    """A reviewer withdraws its own review: a `supersede` naming it."""
    out = wcli.checked(cmd, ["--store", str(store), "supersede", wid, "--reason", reason,
                             "--actor", actor, "--key", str(key), "--ts", str(ts)])
    return out.strip().splitlines()[-1]
