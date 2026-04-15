import json
import tempfile
import unittest
from pathlib import Path

from absolute.apps.guide.absolute_runtime import (
    AuditLog,
    CapabilityPolicyEngine,
    CommandRunner,
    EventValidator,
)


class RuntimeTests(unittest.TestCase):
    def test_event_validation_and_hash(self):
        validator = EventValidator()
        event = json.loads(Path("absolute/apps/guide/event.example.json").read_text())
        validator.validate(event)
        digest = validator.canonical_hash(event)
        self.assertEqual(len(digest), 64)

    def test_policy_engine_allow_and_deny(self):
        engine = CapabilityPolicyEngine()
        rules = engine.load_rules(Path("absolute/apps/guide/policies.example.json"))

        allowed, _ = engine.evaluate(rules, "filesystem:read", "path:/workspace/ABSOLUTE/README.md")
        self.assertTrue(allowed)

        denied, _ = engine.evaluate(rules, "filesystem:read", "path:/etc/passwd")
        self.assertFalse(denied)

    def test_command_runner_executes_whitelisted_command(self):
        result = CommandRunner.run("show-date", [])
        self.assertIn("exit_code", result)
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(result["stdout"])

    def test_audit_log_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.log"
            log = AuditLog(path)
            one = log.append({"n": 1})
            two = log.append({"n": 2})
            self.assertEqual(two["prev_hash"], one["chain_hash"])


if __name__ == "__main__":
    unittest.main()
