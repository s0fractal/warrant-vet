"""Verdicts for a lockfile, from a review store, under the reader's policy and trust.

Order: the reader's trust and policy (ADR-0002, ADR-0003) -> the reader's warrant
verifies the store at settlement grade with --require-bound -> records with an
ERR are set aside, record by record -> each lockfile entry gets one verdict."""
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from . import wcli
from .descriptor import criteria_blob, subject_hash

POLICY_FIELDS = {"warrant_vet", "criteria", "min_accepts", "reviewers"}


class Refusal(Exception):
    def __init__(self, code, detail):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


@dataclass
class Verdict:
    entry: object
    status: str                      # ADMITTED REJECTED UNREVIEWED UNPINNED LOCAL
    accepts: list = field(default_factory=list)
    rejects: list = field(default_factory=list)
    set_aside: int = 0               # records about this artifact that warrant found in error


def read_policy(path):
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise Refusal("POLICY", f"{path}: {e}")
    if not isinstance(doc, dict) or not set(doc) <= POLICY_FIELDS or doc.get("warrant_vet") != "0":
        raise Refusal("POLICY", f"fields must be within {sorted(POLICY_FIELDS)}, warrant_vet \"0\"")
    if not (isinstance(doc.get("criteria"), str) and doc["criteria"]):
        raise Refusal("POLICY", "criteria must be a nonempty string")
    m = doc.get("min_accepts", 1)
    if not (isinstance(m, int) and not isinstance(m, bool) and m >= 1):
        raise Refusal("POLICY", "min_accepts must be an integer >= 1")
    r = doc.get("reviewers")
    if r is not None and not (isinstance(r, list) and r and all(isinstance(x, str) and x for x in r)):
        raise Refusal("POLICY", "reviewers, when present, must be a nonempty list of actor ids")
    return {"criteria": doc["criteria"], "min_accepts": m, "reviewers": set(r) if r else None}


def load_store(store):
    records = {}
    for p in sorted(Path(store, "records").glob("*.json")):
        try:
            records[p.stem] = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            records[p.stem] = None    # warrant reports it; it is set aside below
    return records


def vet(entries, store, trust_config, policy_path, cmd="warrant"):
    if trust_config is None or not Path(trust_config).is_file():
        raise Refusal("NO_TRUST_CONFIG", "a reader trust config is required; reviews cannot supply one")
    policy = read_policy(policy_path)
    if not Path(store, "records").is_dir():
        raise Refusal("NO_STORE", f"{store} is not a warrant store")
    try:
        code, report = wcli.verify_store(cmd, store, trust_config)
    except (wcli.WarrantError, OSError) as e:
        raise Refusal("WARRANT", f"the reader's verifier produced no report: {e}")
    store_level = [f for f in report["findings"] if f["level"] == "ERR" and f["subject"] in ("settlement", "store")]
    if store_level:
        raise Refusal("WARRANT", f"{store_level[0]['message']}")
    in_error = {f["subject"] for f in report["findings"] if f["level"] == "ERR"}

    criteria_hash = hashlib.sha256(criteria_blob(policy["criteria"])).hexdigest()
    records = load_store(store)
    valid = {w: r for w, r in records.items() if r is not None and w not in in_error}
    # A reviewer withdraws its own review with a `supersede` that names it in `prior`.
    withdrawn = {p for r in valid.values() if r["body"]["decision"] == "supersede"
                 for p in r["body"]["prior"]
                 if p in valid and valid[p]["body"]["actor"]["id"] == r["body"]["actor"]["id"]}
    by_subject, errors_by_subject = {}, {}
    for w, r in valid.items():
        b = r["body"]
        if b["decision"] in ("accept", "reject") and criteria_hash in b["under"] and w not in withdrawn:
            by_subject.setdefault(b["subject"]["hash"], []).append(b)
    for w in in_error:
        r = records.get(w)
        if isinstance(r, dict) and isinstance(r.get("body"), dict) and isinstance(r["body"].get("subject"), dict):
            h = r["body"]["subject"].get("hash")
            errors_by_subject[h] = errors_by_subject.get(h, 0) + 1

    allowed = policy["reviewers"]
    out = []
    for e in entries:
        if e.desc is None:
            out.append(Verdict(e, e.status))
            continue
        h = subject_hash(e.desc)
        reviews = [b for b in by_subject.get(h, []) if allowed is None or b["actor"]["id"] in allowed]
        accepts = sorted({b["actor"]["id"] for b in reviews if b["decision"] == "accept"})
        rejects = sorted({b["actor"]["id"] for b in reviews if b["decision"] == "reject"})
        if rejects:
            status = "REJECTED"
        elif len(accepts) >= policy["min_accepts"]:
            status = "ADMITTED"
        else:
            status = "UNREVIEWED"
        out.append(Verdict(e, status, accepts, rejects, errors_by_subject.get(h, 0)))
    return out
