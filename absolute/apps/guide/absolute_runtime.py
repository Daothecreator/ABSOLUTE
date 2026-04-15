#!/usr/bin/env python3
"""ABSOLUTE Runtime MVP: working event validation, capability policy checks and secure command execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = REPO_ROOT / "absolute/core/event-bus/absolute-event.schema.json"
CAPS_PATH = REPO_ROOT / "absolute/core/policy-engine/capabilities.json"


class ValidationError(Exception):
    pass


class EventValidator:
    def __init__(self, schema_path: Path = SCHEMA_PATH):
        self.schema = json.loads(schema_path.read_text())
        self.required = set(self.schema["required"])
        self.allowed_platforms = set(self.schema["properties"]["platform"]["enum"])
        self.allowed_event_types = set(self.schema["properties"]["event_type"]["enum"])
        self.allowed_effects = set(self.schema["properties"]["policy_decision"]["properties"]["effect"]["enum"])

    def validate(self, event: dict[str, Any]) -> None:
        missing = self.required - set(event)
        if missing:
            raise ValidationError(f"Missing required fields: {sorted(missing)}")

        if event["platform"] not in self.allowed_platforms:
            raise ValidationError(f"Unsupported platform: {event['platform']}")
        if event["event_type"] not in self.allowed_event_types:
            raise ValidationError(f"Unsupported event_type: {event['event_type']}")

        self._validate_process(event["process"])
        self._validate_policy(event["policy_decision"])
        self._validate_evidence(event["evidence"])

    def canonical_hash(self, event: dict[str, Any]) -> str:
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def _validate_process(process: dict[str, Any]) -> None:
        for f in ["pid", "ppid", "image", "lineage"]:
            if f not in process:
                raise ValidationError(f"process.{f} is required")
        if not isinstance(process["pid"], int) or process["pid"] < 1:
            raise ValidationError("process.pid must be integer >= 1")
        if not isinstance(process["lineage"], list):
            raise ValidationError("process.lineage must be a list")

    def _validate_policy(self, policy: dict[str, Any]) -> None:
        for f in ["effect", "policy_id", "reason"]:
            if f not in policy:
                raise ValidationError(f"policy_decision.{f} is required")
        if policy["effect"] not in self.allowed_effects:
            raise ValidationError(f"Invalid policy effect: {policy['effect']}")

    @staticmethod
    def _validate_evidence(evidence: dict[str, Any]) -> None:
        for f in ["collector", "inputs", "hash"]:
            if f not in evidence:
                raise ValidationError(f"evidence.{f} is required")
        if not re.fullmatch(r"[a-f0-9]{64}", evidence["hash"]):
            raise ValidationError("evidence.hash must be 64-char lowercase hex SHA-256")


@dataclass
class Rule:
    effect: str
    capability: str
    scope_prefix: str


class CapabilityPolicyEngine:
    def __init__(self, caps_path: Path = CAPS_PATH):
        capabilities = json.loads(caps_path.read_text())["capabilities"]
        self.known_caps = {item["name"] for item in capabilities}

    def load_rules(self, rules_path: Path) -> list[Rule]:
        data = json.loads(rules_path.read_text())
        rules: list[Rule] = []
        for row in data.get("rules", []):
            rules.append(Rule(effect=row["effect"], capability=row["capability"], scope_prefix=row["scope_prefix"]))
        return rules

    def evaluate(self, rules: list[Rule], capability: str, scope: str) -> tuple[bool, str]:
        if capability not in self.known_caps:
            return False, f"Unknown capability: {capability}"

        decision = None
        matched = []
        for rule in rules:
            if rule.capability != capability:
                continue
            if scope.startswith(rule.scope_prefix):
                matched.append(rule)

        # deny takes precedence over allow
        for rule in matched:
            if rule.effect == "deny":
                decision = (False, f"Denied by rule scope_prefix={rule.scope_prefix}")
                break

        if decision is None:
            for rule in matched:
                if rule.effect == "allow":
                    decision = (True, f"Allowed by rule scope_prefix={rule.scope_prefix}")
                    break

        if decision is None:
            return False, "No matching allow rule"
        return decision


class CommandRunner:
    ALLOWED = {
        "show-date": ["date", "-u"],
        "hash-file": ["sha256sum"],
        "show-disk": ["df", "-h"],
        "list-dir": ["ls", "-la"],
    }

    @staticmethod
    def run(command_id: str, args: list[str], timeout_sec: int = 10) -> dict[str, Any]:
        if command_id not in CommandRunner.ALLOWED:
            raise ValidationError(f"Command not allowed: {command_id}")

        for arg in args:
            if arg.startswith("-"):
                raise ValidationError("Custom flags are not allowed; use positional args only")

        cmd = CommandRunner.ALLOWED[command_id] + args
        started = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec, check=False)
        elapsed_ms = int((time.time() - started) * 1000)

        return {
            "command": cmd,
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "elapsed_ms": elapsed_ms,
        }


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        prev_hash = "0" * 64
        if self.path.exists() and self.path.stat().st_size > 0:
            last = self.path.read_text().strip().splitlines()[-1]
            prev_hash = json.loads(last)["chain_hash"]

        payload = json.dumps(record, sort_keys=True, separators=(",", ":"))
        chain_hash = hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()
        envelope = {"record": record, "prev_hash": prev_hash, "chain_hash": chain_hash}

        with self.path.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(envelope, ensure_ascii=False) + "\n")

        return envelope


def cmd_validate_event(args: argparse.Namespace) -> int:
    event = json.loads(Path(args.event).read_text())
    validator = EventValidator()
    validator.validate(event)
    print(json.dumps({"ok": True, "event_hash": validator.canonical_hash(event)}, ensure_ascii=False))
    return 0


def cmd_check_access(args: argparse.Namespace) -> int:
    engine = CapabilityPolicyEngine()
    rules = engine.load_rules(Path(args.rules))
    allowed, reason = engine.evaluate(rules, args.capability, args.scope)
    out = {"allowed": allowed, "reason": reason, "capability": args.capability, "scope": args.scope}
    print(json.dumps(out, ensure_ascii=False))
    return 0 if allowed else 2


def cmd_run_command(args: argparse.Namespace) -> int:
    result = CommandRunner.run(args.command_id, args.args, timeout_sec=args.timeout)
    print(json.dumps(result, ensure_ascii=False))
    return result["exit_code"]


def cmd_append_audit(args: argparse.Namespace) -> int:
    record = json.loads(Path(args.record).read_text())
    log = AuditLog(Path(args.log))
    envelope = log.append(record)
    print(json.dumps(envelope, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ABSOLUTE Runtime MVP")
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser("validate-event", help="Validate unified event JSON")
    p_validate.add_argument("--event", required=True)
    p_validate.set_defaults(func=cmd_validate_event)

    p_access = sub.add_parser("check-access", help="Evaluate capability policy rules")
    p_access.add_argument("--rules", required=True)
    p_access.add_argument("--capability", required=True)
    p_access.add_argument("--scope", required=True)
    p_access.set_defaults(func=cmd_check_access)

    p_run = sub.add_parser("run-command", help="Run whitelisted command in safe mode")
    p_run.add_argument("--command-id", required=True)
    p_run.add_argument("--timeout", type=int, default=10)
    p_run.add_argument("args", nargs="*")
    p_run.set_defaults(func=cmd_run_command)

    p_audit = sub.add_parser("append-audit", help="Append hash-chained audit record")
    p_audit.add_argument("--record", required=True)
    p_audit.add_argument("--log", default=str(REPO_ROOT / "absolute/runtime/audit.log"))
    p_audit.set_defaults(func=cmd_append_audit)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ValidationError, json.JSONDecodeError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
