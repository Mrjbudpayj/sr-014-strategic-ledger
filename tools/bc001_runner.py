#!/usr/bin/env python3
"""BC-001 execution harness.

The fixture and oracle are read-only inputs. The harness invokes an external
target adapter, captures its raw process stream, and compares the observed
decision to the frozen oracle.

No result is written into the fixture or oracle.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        value = json.load(fh)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def write_bytes(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def classify(exit_code: int, stdout: bytes, decision: dict[str, Any] | None,
             oracle: dict[str, Any]) -> str:
    if decision is None:
        if exit_code != 0:
            return "ENVIRONMENT MISMATCH"
        return "HALT / UNRESOLVED"

    observed_allowed = decision.get("transition_allowed")
    expected_allowed = oracle.get("expected_transition_allowed")

    if observed_allowed is None:
        return "HALT / UNRESOLVED"

    if observed_allowed is expected_allowed:
        return "PASS — WITHIN BC-001 SCOPE"

    return "FAIL — BOUNDARY COLLAPSE"


def main() -> int:
    parser = argparse.ArgumentParser(description="Execute BC-001 against an external target adapter.")
    parser.add_argument("--fixture", default="spec/bc-001-assertion-verified/fixture.json", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--target",
        nargs="+",
        required=True,
        help="External target-adapter command. It must accept the fixture path as its final argument.",
    )
    args = parser.parse_args()

    fixture_path = args.fixture.resolve()
    fixture = read_json(fixture_path)
    oracle = fixture["oracle"]

    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)

    # Preserve the exact fixture bytes supplied to the run without altering the source.
    fixture_bytes = fixture_path.read_bytes()
    write_bytes(out / "fixture.json", fixture_bytes)

    command = list(args.target) + [str(fixture_path)]
    command_text = shlex.join(command)
    (out / "command.txt").write_text(command_text + "\n", encoding="utf-8")

    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError as exc:
        (out / "exit_code.txt").write_text("ENVIRONMENT_MISMATCH\n", encoding="utf-8")
        write_bytes(out / "stdout.bin", b"")
        write_bytes(out / "stderr.bin", str(exc).encode("utf-8"))
        (out / "oracle-comparison.json").write_text(
            json.dumps(
                {
                    "fixture_id": fixture["fixture_id"],
                    "disposition": "ENVIRONMENT MISMATCH",
                    "reason": "target adapter executable unavailable",
                    "oracle": oracle,
                },
                sort_keys=True,
                separators=(",", ":"),
            ) + "\n",
            encoding="utf-8",
        )
        return 3

    write_bytes(out / "stdout.bin", completed.stdout)
    write_bytes(out / "stderr.bin", completed.stderr)
    (out / "exit_code.txt").write_text(str(completed.returncode) + "\n", encoding="utf-8")

    decision: dict[str, Any] | None = None
    try:
        parsed = json.loads(completed.stdout.decode("utf-8"))
        if isinstance(parsed, dict):
            decision = parsed
    except (UnicodeDecodeError, json.JSONDecodeError):
        decision = None

    if decision is not None:
        (out / "decision.json").write_text(
            json.dumps(decision, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    disposition = classify(completed.returncode, completed.stdout, decision, oracle)

    comparison = {
        "fixture_id": fixture["fixture_id"],
        "oracle": oracle,
        "observed": {
            "exit_code": completed.returncode,
            "decision": decision,
        },
        "disposition": disposition,
    }
    (out / "oracle-comparison.json").write_text(
        json.dumps(comparison, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    # Human-readable disposition is emitted to stdout for the raw console stream.
    print(disposition)

    # PASS is the only successful test result. Other dispositions remain evidence
    # and are deliberately not rewritten as PASS.
    return 0 if disposition == "PASS — WITHIN BC-001 SCOPE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
