#!/usr/bin/env python3
"""Independent verifier for A11-CLI-EXECUTION-RECEIPT.v1.

This verifier treats receipt fields as claims. Verification-critical values
are recomputed from retained raw evidence supplied outside the receipt.

It intentionally does not execute the target CLI and does not mutate the
target artifact. A successful verification is evidence about the supplied
receipt/evidence bundle only; it is not an authority transition.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


RECEIPT_FORMAT = "A11-CLI-EXECUTION-RECEIPT.v1"
C14N_FORMAT = "A11-CLI-EXECUTION-RECEIPT-C14N.v1"


class VerificationError(Exception):
    pass


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise VerificationError(f"cannot read JSON evidence: {path}: {exc}") from exc


def canonicalize_receipt(receipt: dict[str, Any]) -> bytes:
    payload = json.loads(json.dumps(receipt))
    identity = payload.get("receipt_identity")
    if not isinstance(identity, dict):
        raise VerificationError("receipt_identity missing or not an object")
    identity.pop("receipt_sha256", None)

    def reject_non_integer_numbers(value: Any, path: str = "$") -> None:
        if isinstance(value, float):
            raise VerificationError(
                f"non-integer JSON number is forbidden by C14N.v1: {path}"
            )
        if isinstance(value, dict):
            for key, item in value.items():
                reject_non_integer_numbers(item, f"{path}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                reject_non_integer_numbers(item, f"{path}[{index}]")

    reject_non_integer_numbers(payload)

    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        .encode("utf-8")
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def compare_digest(label: str, recorded: Any, raw: bytes) -> None:
    recomputed = sha256_bytes(raw)
    require(recorded == recomputed, f"MISMATCH: {label}: recorded={recorded!r} recomputed={recomputed!r}")


def verify_receipt(receipt_path: Path, evidence_dir: Path) -> dict[str, Any]:
    receipt = read_json(receipt_path)
    require(isinstance(receipt, dict), "receipt root must be an object")
    require(receipt.get("receipt_format") == RECEIPT_FORMAT, "receipt_format mismatch")

    identity = receipt.get("receipt_identity", {})
    require(identity.get("canonicalization") == C14N_FORMAT, "canonicalization profile mismatch")

    canonical = canonicalize_receipt(receipt)
    recomputed_receipt_digest = sha256_bytes(canonical)
    compare_digest(
        "receipt_identity.receipt_sha256",
        identity.get("receipt_sha256"),
        canonical,
    )

    process = receipt["process"]
    stdout = (evidence_dir / "stdout.bin").read_bytes()
    stderr = (evidence_dir / "stderr.bin").read_bytes()

    compare_digest("process.stdout.sha256", process["stdout"]["sha256"], stdout)
    compare_digest("process.stderr.sha256", process["stderr"]["sha256"], stderr)
    require(process["stdout"]["byte_count"] == len(stdout), "MISMATCH: stdout.byte_count")
    require(process["stderr"]["byte_count"] == len(stderr), "MISMATCH: stderr.byte_count")

    process_evidence = evidence_dir / "process.json"
    require(process_evidence.exists(), "UNVERIFIABLE: process.json is required")
    observed_process = read_json(process_evidence)
    require(
        observed_process.get("exit_code") == process["exit_code"],
        "MISMATCH: process.exit_code",
    )

    before = receipt["filesystem"]["before"]
    after = receipt["filesystem"]["after"]

    def verify_snapshot(name: str, snapshot: dict[str, Any]) -> bytes | None:
        raw_path = evidence_dir / f"{name}.bin"
        exists = bool(snapshot["exists"])
        if not exists:
            require(not raw_path.exists(), f"MISMATCH: unexpected raw bytes for absent {name}")
            require(snapshot["byte_count"] == 0, f"MISMATCH: {name}.byte_count")
            require(snapshot["sha256"] is None, f"MISMATCH: {name}.sha256")
            return None

        require(raw_path.exists(), f"UNVERIFIABLE: missing {name}.bin")
        raw = raw_path.read_bytes()
        require(snapshot["byte_count"] == len(raw), f"MISMATCH: {name}.byte_count")
        compare_digest(f"filesystem.{name}.sha256", snapshot["sha256"], raw)
        return raw

    before_raw = verify_snapshot("before", before)
    after_raw = verify_snapshot("after", after)

    output = receipt["output"]
    output_path = evidence_dir / "output.bin"
    if output["observed_sha256"] is not None:
        require(output_path.exists(), "UNVERIFIABLE: missing output.bin")
        output_raw = output_path.read_bytes()
        compare_digest("output.observed_sha256", output["observed_sha256"], output_raw)
        require(output["byte_count"] == len(output_raw), "MISMATCH: output.byte_count")
        if output["expected_sha256"] is not None:
            require(
                output["expected_sha256"] == sha256_bytes(output_raw),
                "MISMATCH: output.expected_sha256",
            )
    else:
        require(not output_path.exists(), "MISMATCH: output.bin exists but observed_sha256 is null")

    results: list[dict[str, Any]] = []

    def predicate(pid: str, observed: Any, expected: Any, passed: bool) -> None:
        results.append({
            "predicate_id": pid,
            "observed": observed,
            "expected": expected,
            "result": "PASS" if passed else "FAIL",
        })
        require(passed, f"REJECTED: predicate {pid} failed")

    if before["exists"]:
        require(after["exists"], "REJECTED: existing target disappeared on rejection check")
        predicate(
            "A11.CLI.REJECTION_NON_MUTATION.v1",
            {
                "exit_code": process["exit_code"],
                "stdout_byte_count": len(stdout),
                "before_sha256": sha256_bytes(before_raw or b""),
                "after_sha256": sha256_bytes(after_raw or b""),
            },
            {
                "exit_code": 2,
                "stdout_byte_count": 0,
                "before_sha256_equals_after": True,
            },
            (
                process["exit_code"] == 2
                and len(stdout) == 0
                and before_raw is not None
                and after_raw is not None
                and sha256_bytes(before_raw) == sha256_bytes(after_raw)
            ),
        )
    else:
        predicate(
            "A11.CLI.REJECTION_NON_CREATION.v1",
            {
                "exit_code": process["exit_code"],
                "stdout_byte_count": len(stdout),
                "before_exists": before["exists"],
                "after_exists": after["exists"],
            },
            {
                "exit_code": 2,
                "stdout_byte_count": 0,
                "before_exists": False,
                "after_exists": False,
            },
            process["exit_code"] == 2 and len(stdout) == 0 and not after["exists"],
        )

    if process["exit_code"] == 2:
        predicate(
            "A11.CLI.STDOUT_EMPTY_ON_REJECTION.v1",
            {"exit_code": process["exit_code"], "stdout_byte_count": len(stdout)},
            {"exit_code": 2, "stdout_byte_count": 0},
            len(stdout) == 0,
        )

    recorded_predicates = {
        item["predicate_id"]: item for item in receipt.get("predicates", [])
    }
    for result in results:
        recorded = recorded_predicates.get(result["predicate_id"])
        require(recorded is not None, f"MISMATCH: missing recorded predicate {result['predicate_id']}")
        require(
            recorded["result"] == result["result"],
            f"MISMATCH: recorded predicate result {result['predicate_id']}",
        )

    return {
        "result": "PASS",
        "receipt_sha256": recomputed_receipt_digest,
        "predicates": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args()

    try:
        result = verify_receipt(args.receipt, args.evidence_dir)
    except VerificationError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"UNVERIFIABLE: {exc}", file=sys.stderr)
        return 3

    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
