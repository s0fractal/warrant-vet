"""warrant-vet: admit dependencies by signed reviews of their exact bytes.

  python3 -m warrant_vet check LOCKFILE --store REVIEWS --trust TRUST.json --policy POLICY.json [--json]
  python3 -m warrant_vet review LOCKFILE NAME VERSION --store REVIEWS --criteria C
                                  --actor ID --key KEY --reason TEXT [--reject] [--ts N]
  python3 -m warrant_vet describe LOCKFILE NAME VERSION     # the descriptor and its subject hash

check exits 0 when every registry dependency is ADMITTED, 1 otherwise, 2 when refused.
"""
import argparse
import json
import sys
import time
from pathlib import Path

from .descriptor import LockfileError, encode, read_lockfile, subject_hash
from .review import file_review
from .vet import Refusal, vet

ORDER = {"REJECTED": 0, "UNREVIEWED": 1, "UNPINNED": 2, "ADMITTED": 3, "LOCAL": 4}


def find(entries, name, version):
    hits = [e for e in entries if e.name == name and e.version == version]
    if len(hits) != 1 or hits[0].desc is None:
        sys.exit(f"{name} {version}: {'not in the lockfile' if not hits else 'no registry digest to review'}")
    return hits[0]


def main(argv=None):
    ap = argparse.ArgumentParser(prog="warrant_vet", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--warrant", default="warrant", help="the reader's warrant verifier (>= 0.11.0)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("lockfile")
    c.add_argument("--store", required=True)
    c.add_argument("--trust", required=True)
    c.add_argument("--policy", required=True)
    c.add_argument("--json", action="store_true")
    r = sub.add_parser("review")
    for a in ("lockfile", "name", "version"):
        r.add_argument(a)
    for a in ("--store", "--criteria", "--actor", "--key", "--reason"):
        r.add_argument(a, required=True)
    r.add_argument("--reject", action="store_true")
    r.add_argument("--ts", type=int)
    d = sub.add_parser("describe")
    for a in ("lockfile", "name", "version"):
        d.add_argument(a)
    args = ap.parse_args(argv)
    try:
        entries = read_lockfile(args.lockfile, Path(args.lockfile).read_bytes())
    except (OSError, LockfileError) as e:
        print(f"REFUSED LOCKFILE: {e}")
        return 2
    if args.cmd == "describe":
        e = find(entries, args.name, args.version)
        print(encode(e.desc).decode())
        print("subject", subject_hash(e.desc))
        return 0
    if args.cmd == "review":
        e = find(entries, args.name, args.version)
        wid = file_review(args.warrant, args.store, e.desc, args.criteria, "reject" if args.reject else "accept",
                          args.actor, args.key, args.reason, args.ts if args.ts is not None else int(time.time()))
        print(wid)
        return 0
    try:
        verdicts = vet(entries, args.store, args.trust, args.policy, args.warrant)
    except Refusal as e:
        print(f"REFUSED {e.code}: {e.detail}")
        return 2
    verdicts.sort(key=lambda v: (ORDER[v.status], v.entry.ecosystem, v.entry.name, v.entry.version))
    if args.json:
        print(json.dumps([{"ecosystem": v.entry.ecosystem, "name": v.entry.name, "version": v.entry.version,
                           "status": v.status, "accepts": v.accepts, "rejects": v.rejects,
                           "set_aside": v.set_aside, "why": v.entry.why} for v in verdicts], indent=2))
    else:
        for v in verdicts:
            who = (f"accepted by {', '.join(v.accepts)}" if v.accepts else "") + \
                  (f" rejected by {', '.join(v.rejects)}" if v.rejects else "")
            extra = f"  [{v.set_aside} record(s) set aside: warrant ERR]" if v.set_aside else ""
            print(f"{v.status:10} {v.entry.ecosystem:5} {v.entry.name} {v.entry.version}  {who or v.entry.why}{extra}")
        counts = {}
        for v in verdicts:
            counts[v.status] = counts.get(v.status, 0) + 1
        print("\n" + ", ".join(f"{k} {counts[k]}" for k in sorted(counts, key=ORDER.get)))
    return 0 if all(v.status in ("ADMITTED", "LOCAL") for v in verdicts) else 1


if __name__ == "__main__":
    sys.exit(main())
