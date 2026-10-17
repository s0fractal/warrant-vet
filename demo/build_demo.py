"""Build demo/reviews/, demo/trust.json and demo/policy.json reproducibly.

DEMO REVIEWS, NOT AUDITS. alice@demo.test and bob@demo.test are test actors whose
keys are SHA-256 of public labels; every review here says so in its reason. The
point is to show the verdicts, not to vouch for any crate.

    python3 demo/build_demo.py            # (re)write the demo files
    python3 demo/build_demo.py --check    # fail if the committed files differ
"""
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from warrant_vet import wcli  # noqa: E402
from warrant_vet.descriptor import read_lockfile  # noqa: E402
from warrant_vet.review import file_review, withdraw  # noqa: E402

TS = 1792195200  # 2026-10-17T00:00:00Z
LOCK = ROOT / "demo" / "Cargo.lock"
REVIEWERS = {"alice@demo.test": "warrant-vet demo test key: alice",
             "bob@demo.test": "warrant-vet demo test key: bob"}
NOTE = "DEMO review, not an actual audit: "
# (actor, crate, decision, reason)
PLAN = [
    ("alice@demo.test", "memchr", "accept", "read the diff since the last reviewed version"),
    ("bob@demo.test", "memchr", "accept", "ran the test suite against our usage"),
    ("alice@demo.test", "aho-corasick", "accept", "no unsafe outside the vetted SIMD paths"),
    ("alice@demo.test", "itoa", "accept", "small, no build script"),
    ("bob@demo.test", "regex", "reject", "pretend finding, to show a veto"),
    ("alice@demo.test", "serde", "accept", "accepted, then withdrawn below"),
]


def keyfiles(tmp):
    out = {}
    for actor, label in REVIEWERS.items():
        p = Path(tmp) / f"{actor}.key"
        p.write_text(hashlib.sha256(label.encode()).hexdigest() + "\n")
        out[actor] = p
    return out


def build(cmd="warrant"):
    entries = {e.name: e for e in read_lockfile(LOCK, LOCK.read_bytes())}
    tmp = Path(tempfile.mkdtemp())
    try:
        keys = keyfiles(tmp)
        store = tmp / "reviews"
        wids = {}
        for i, (actor, crate, decision, reason) in enumerate(PLAN):
            wids[(actor, crate)] = file_review(cmd, store, entries[crate].desc, "safe-to-deploy", decision,
                                               actor, keys[actor], NOTE + reason, TS + i)
        withdraw(cmd, store, wids[("alice@demo.test", "serde")], "alice@demo.test", keys["alice@demo.test"],
                 NOTE + "withdrawn: reviewed the wrong feature set", TS + len(PLAN))
        for actor, key in keys.items():
            wcli.checked(cmd, ["trust", "add", "--actor", actor, "--key", str(key), "--config", "trust.json"], cwd=tmp)
        files = {"trust.json": json.dumps(json.loads((tmp / "trust.json").read_text()), indent=2, sort_keys=True) + "\n",
                 "policy.json": json.dumps({"warrant_vet": "0", "criteria": "safe-to-deploy", "min_accepts": 1},
                                           indent=2, sort_keys=True) + "\n"}
        tree = {str(p.relative_to(store)): p.read_bytes() for p in sorted(store.rglob("*")) if p.is_file()}
    finally:
        shutil.rmtree(tmp)
    return tree, files


def main():
    tree, files = build()
    demo = ROOT / "demo"
    current = {str(p.relative_to(demo / "reviews")): p.read_bytes()
               for p in sorted((demo / "reviews").rglob("*")) if p.is_file()} if (demo / "reviews").exists() else {}
    if "--check" in sys.argv:
        stale = current != tree or any(not (demo / n).is_file() or (demo / n).read_text() != t for n, t in files.items())
        if stale:
            sys.exit("stale demo files; run python3 demo/build_demo.py")
        print(f"demo reproduces: {len(tree)} store files, {', '.join(files)}")
        return
    if (demo / "reviews").exists():
        shutil.rmtree(demo / "reviews")
    for rel, data in tree.items():
        (demo / "reviews" / rel).parent.mkdir(parents=True, exist_ok=True)
        (demo / "reviews" / rel).write_bytes(data)
    for n, t in files.items():
        (demo / n).write_text(t)
    print(f"wrote demo/reviews ({len(tree)} files), {', '.join(files)}")


if __name__ == "__main__":
    main()
