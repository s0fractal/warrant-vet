"""The reader's warrant verifier, called as a separate program.

warrant-pdf never re-implements warrant: canonical form, WarrantIDs, signatures,
key state and trust all come from the `warrant` command the reader chose
(ADR-0003). This module only runs it and parses what it prints.
"""
import json
import subprocess
from pathlib import Path


class WarrantError(Exception):
    pass


def run(cmd, args, cwd=None):
    proc = subprocess.run([cmd, *args], capture_output=True, text=True, cwd=cwd)
    return proc.returncode, proc.stdout, proc.stderr


def checked(cmd, args, cwd=None):
    code, out, err = run(cmd, args, cwd)
    if code != 0:
        raise WarrantError(f"{cmd} {' '.join(args)} failed ({code}): {err.strip() or out.strip()}")
    return out


def warrant_id(cmd, body, workdir):
    path = Path(workdir) / "body.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return json.loads(checked(cmd, ["canon", str(path)]))["warrant_id"]


def verify_store(cmd, store, trust_config):
    """Settlement grade under the reader's trust config, requiring each record's own
    actor to be bound (warrant >= 0.11.0, WRT-018)."""
    code, out, err = run(cmd, ["--store", str(store), "verify", "--settlement",
                               "--trust-config", str(trust_config), "--require-bound", "--json"])
    try:
        report = json.loads(out)
    except json.JSONDecodeError:
        raise WarrantError(f"warrant verify printed no report ({code}): {err.strip()}")
    if report.get("report") != "warrant.verify-report@v0":
        raise WarrantError("unexpected report profile")
    return code, report
