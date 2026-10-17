"""Counter-vectors: each test is one attack or accident and the verdict it must give.
`witness:` lines bind a test to the normative statement it witnesses."""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "demo"))
import build_demo  # noqa: E402
from warrant_vet import wcli  # noqa: E402
from warrant_vet.descriptor import LockfileError, read_lockfile, subject_hash  # noqa: E402
from warrant_vet.review import file_review, withdraw  # noqa: E402
from warrant_vet.vet import Refusal, vet  # noqa: E402

CMD = "warrant"
LOCK = ROOT / "demo" / "Cargo.lock"
ENTRIES = read_lockfile(LOCK, LOCK.read_bytes())
BY_NAME = {e.name: e for e in ENTRIES}
ALICE, BOB = list(build_demo.REVIEWERS)


def status(verdicts):
    return {v.entry.name: v.status for v in verdicts}


class Scenario:
    """A fresh review store, the demo reviewers' keys, a trust config and a policy."""

    def __init__(self, policy=None, trusted=(ALICE, BOB)):
        self.tmp = Path(tempfile.mkdtemp())
        self.keys = build_demo.keyfiles(self.tmp)
        self.mallory = self.tmp / "mallory.key"
        self.mallory.write_text(hashlib.sha256(b"mallory").hexdigest() + "\n")
        self.keys["carol@demo.test"] = self.tmp / "carol.key"
        self.keys["carol@demo.test"].write_text(hashlib.sha256(b"carol").hexdigest() + "\n")
        self.store = self.tmp / "reviews"
        self.ts = build_demo.TS
        for actor in trusted:
            wcli.checked(CMD, ["trust", "add", "--actor", actor, "--key", str(self.keys[actor]),
                               "--config", "trust.json"], cwd=self.tmp)
        self.trust = self.tmp / "trust.json"
        self.policy = self.tmp / "policy.json"
        self.policy.write_text(json.dumps(policy or {"warrant_vet": "0", "criteria": "safe-to-deploy"}))

    def review(self, actor, crate, decision="accept", criteria="safe-to-deploy", key=None, desc=None):
        self.ts += 1
        return file_review(CMD, self.store, desc or BY_NAME[crate].desc, criteria, decision, actor,
                           key or self.keys[actor], "test review", self.ts)

    def withdraw(self, actor, wid):
        self.ts += 1
        return withdraw(CMD, self.store, wid, actor, self.keys[actor], "withdrawn", self.ts)

    def vet(self, entries=ENTRIES):
        return vet(entries, self.store, self.trust, self.policy, CMD)

    def cleanup(self):
        shutil.rmtree(self.tmp)


class CounterVectors(unittest.TestCase):

    def scenario(self, **kw):
        s = Scenario(**kw)
        self.addCleanup(s.cleanup)
        return s

    def refused(self, code, fn):
        with self.assertRaises(Refusal) as cm:
            fn()
        self.assertEqual(cm.exception.code, code, cm.exception.detail)

    # --- the demo -----------------------------------------------------------

    def test_demo_verdicts(self):
        """witness: WVET-P2
        witness: WVET-P3
        witness: WVET-P4"""
        v = vet(ENTRIES, ROOT / "demo" / "reviews", ROOT / "demo" / "trust.json", ROOT / "demo" / "policy.json", CMD)
        self.assertEqual(status(v), {"aho-corasick": "ADMITTED", "itoa": "ADMITTED", "memchr": "ADMITTED",
                                     "regex": "REJECTED", "serde": "UNREVIEWED", "libc": "UNREVIEWED",
                                     "patched-lib": "UNPINNED", "demo-app": "LOCAL"})

    def test_demo_rebuilds_byte_for_byte(self):
        """The committed demo store, trust config and policy reproduce exactly."""
        r = subprocess.run([sys.executable, str(ROOT / "demo" / "build_demo.py"), "--check"],
                           capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)

    # --- descriptors (ADR-0001) ----------------------------------------------

    def test_subject_hash_is_pinned(self):
        """Canonical bytes, so any implementation reproduces this hash for memchr 2.8.3.
        witness: WVET-D1"""
        self.assertEqual(subject_hash(BY_NAME["memchr"].desc),
                         hashlib.sha256(b'{"digest":"sha256:cf8baf1c55e62ffcace7a9f06f4bd9cd3f0c4beb022d3b367256b91b87513d98",'
                                        b'"ecosystem":"cargo","name":"memchr","profile":"warrant-vet/0",'
                                        b'"version":"2.8.3"}').hexdigest())

    def test_review_of_another_version_does_not_count(self):
        """witness: WVET-D1"""
        s = self.scenario()
        other = dict(BY_NAME["memchr"].desc, version="2.8.2")
        s.review(ALICE, "memchr", desc=other)
        self.assertEqual(status(s.vet())["memchr"], "UNREVIEWED")

    def test_changed_checksum_unreviews(self):
        """The registry (or a mirror) serves other bytes under the same name and version.
        witness: WVET-D1"""
        s = self.scenario()
        s.review(ALICE, "memchr")
        self.assertEqual(status(s.vet())["memchr"], "ADMITTED")
        tampered = LOCK.read_text().replace("cf8baf1c55e62ffc", "cf8baf1c55e62ff0")
        entries = read_lockfile("Cargo.lock", tampered.encode())
        self.assertEqual(status(s.vet(entries))["memchr"], "UNREVIEWED")

    def test_git_dependency_is_unpinned(self):
        """witness: WVET-D2"""
        self.assertEqual(BY_NAME["patched-lib"].status, "UNPINNED")
        self.assertIsNone(BY_NAME["patched-lib"].desc)

    def test_workspace_member_is_local(self):
        """witness: WVET-D2"""
        self.assertEqual(BY_NAME["demo-app"].status, "LOCAL")

    def test_registry_entry_without_checksum_is_unpinned(self):
        """witness: WVET-D2"""
        raw = LOCK.read_text().replace(
            'checksum = "8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682"\n', "")
        e = {x.name: x for x in read_lockfile("Cargo.lock", raw.encode())}
        self.assertEqual(e["itoa"].status, "UNPINNED")

    def test_non_ascii_name_refuses(self):
        """A look-alike name (Cyrillic 'а') must not quietly become another descriptor.
        witness: WVET-D2"""
        for old, new in (('name = "libc"', 'name = "libс"'), ('name = "demo-app"', 'name = "demо-app"')):
            raw = LOCK.read_text().replace(old, new)     # a registry entry, then a workspace member
            with self.assertRaises(LockfileError):
                read_lockfile("Cargo.lock", raw.encode())

    def test_npm_lockfile_entries(self):
        """witness: WVET-D2"""
        lock = {"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/left-pad": {"version": "1.3.0", "integrity": "sha512-" + "A" * 86 + "=="},
            "node_modules/a/node_modules/b": {"version": "2.0.0"},
            "node_modules/ws-pkg": {"link": True, "version": "0.0.1"}}}
        e = {x.name: x for x in read_lockfile("package-lock.json", json.dumps(lock).encode())}
        self.assertEqual(e["left-pad"].desc["digest"], "sha512-" + "A" * 86 + "==")
        self.assertEqual(e["b"].status, "UNPINNED")
        self.assertEqual(e["ws-pkg"].status, "LOCAL")

    # --- trust (ADR-0002) ----------------------------------------------------

    def test_without_reader_trust_refuses(self):
        """witness: WVET-T1"""
        s = self.scenario()
        self.refused("NO_TRUST_CONFIG", lambda: vet(ENTRIES, s.store, None, s.policy, CMD))

    def test_review_signed_with_another_key_is_set_aside(self):
        """Mallory files an accept as alice@demo.test with her own key.
        witness: WVET-T2"""
        s = self.scenario()
        s.review(ALICE, "memchr", key=s.mallory)
        v = {x.entry.name: x for x in s.vet()}
        self.assertEqual(v["memchr"].status, "UNREVIEWED")
        self.assertEqual(v["memchr"].set_aside, 1)

    def test_reviewer_unknown_to_the_reader_is_set_aside(self):
        """carol's key is real, but this reader never bound it.
        witness: WVET-T2"""
        s = self.scenario()
        s.review("carol@demo.test", "memchr")
        self.assertEqual(status(s.vet())["memchr"], "UNREVIEWED")

    def test_one_bad_record_does_not_silence_the_store(self):
        """A forged review of memchr does not stop alice's real review of itoa counting.
        witness: WVET-T2"""
        s = self.scenario()
        s.review(ALICE, "memchr", key=s.mallory)
        s.review(ALICE, "itoa")
        self.assertEqual(status(s.vet())["itoa"], "ADMITTED")

    def test_unavailable_verifier_refuses(self):
        """witness: WVET-T2"""
        s = self.scenario()
        s.review(ALICE, "memchr")
        self.refused("WARRANT", lambda: vet(ENTRIES, s.store, s.trust, s.policy, "/nonexistent/warrant"))

    def test_broken_trust_config_refuses(self):
        """An unparseable trust config is a store-level ERR, not 'nobody trusted'.
        witness: WVET-T2"""
        s = self.scenario()
        s.review(ALICE, "memchr")
        s.trust.write_text("{not json")
        self.refused("WARRANT", s.vet)

    # --- policy (ADR-0003) ---------------------------------------------------

    def test_other_criteria_does_not_count(self):
        """witness: WVET-P1"""
        s = self.scenario()
        s.review(ALICE, "memchr", criteria="safe-to-run")
        self.assertEqual(status(s.vet())["memchr"], "UNREVIEWED")

    def test_reject_vetoes_accepts(self):
        """witness: WVET-P2"""
        s = self.scenario()
        s.review(ALICE, "memchr")
        s.review(BOB, "memchr")
        s.review(BOB, "memchr", decision="reject")
        self.assertEqual(status(s.vet())["memchr"], "REJECTED")

    def test_withdrawn_review_does_not_count(self):
        """witness: WVET-P4"""
        s = self.scenario()
        s.withdraw(ALICE, s.review(ALICE, "memchr"))
        self.assertEqual(status(s.vet())["memchr"], "UNREVIEWED")

    def test_withdrawal_by_another_actor_withdraws_nothing(self):
        """bob cannot retract alice's review (nor her veto).
        witness: WVET-P4"""
        s = self.scenario()
        s.withdraw(BOB, s.review(ALICE, "memchr"))
        s.withdraw(BOB, s.review(ALICE, "itoa", decision="reject"))
        st = status(s.vet())
        self.assertEqual((st["memchr"], st["itoa"]), ("ADMITTED", "REJECTED"))

    def test_min_accepts_counts_distinct_reviewers(self):
        """Two accepts by the same reviewer are one.
        witness: WVET-P3"""
        s = self.scenario(policy={"warrant_vet": "0", "criteria": "safe-to-deploy", "min_accepts": 2})
        s.review(ALICE, "memchr")
        s.review(BOB, "memchr")
        s.review(ALICE, "itoa")
        s.review(ALICE, "itoa")
        st = status(s.vet())
        self.assertEqual((st["memchr"], st["itoa"]), ("ADMITTED", "UNREVIEWED"))

    def test_reviewer_allowlist(self):
        """witness: WVET-P3"""
        s = self.scenario(policy={"warrant_vet": "0", "criteria": "safe-to-deploy", "reviewers": [BOB]})
        s.review(ALICE, "itoa")
        s.review(BOB, "memchr")
        st = status(s.vet())
        self.assertEqual((st["memchr"], st["itoa"]), ("ADMITTED", "UNREVIEWED"))

    def test_policy_refuses_malformed(self):
        """witness: WVET-P5"""
        for bad in ({"warrant_vet": "0", "criteria": ""},
                    {"warrant_vet": "0", "criteria": "x", "min_accepts": 0},
                    {"warrant_vet": "0", "criteria": "x", "typo": 1},
                    {"warrant_vet": "1", "criteria": "x"}):
            s = self.scenario(policy=bad)
            self.refused("POLICY", s.vet)

    def test_exit_zero_only_when_all_admitted(self):
        """witness: WVET-P5"""
        s = self.scenario()
        for crate in ("aho-corasick", "itoa", "libc", "memchr", "regex", "serde"):
            s.review(ALICE, crate)
        cli = [sys.executable, "-m", "warrant_vet", "check", "--store", str(s.store),
               "--trust", str(s.trust), "--policy", str(s.policy)]
        r = subprocess.run(cli[:4] + [str(LOCK)] + cli[4:], cwd=ROOT, capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 1, r.stdout)          # patched-lib is UNPINNED
        no_git = LOCK.read_text().split('[[package]]\nname = "patched-lib"')[0].rstrip() + "\n" + \
            LOCK.read_text().split('[[package]]\nname = "regex"')[1].join(['[[package]]\nname = "regex"', ""])
        lock2 = s.tmp / "Cargo.lock"
        lock2.write_text(no_git)
        r = subprocess.run(cli[:4] + [str(lock2)] + cli[4:], cwd=ROOT, capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stdout)


if __name__ == "__main__":
    unittest.main()
