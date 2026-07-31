import json
import tempfile
import unittest
from pathlib import Path

from absolute.apps.guide.absolute_runtime import (
    AuditLog,
    CapabilityPolicyEngine,
    CommandRunner,
    EventValidator,
    PrivacySafeSearch,
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

    def test_audit_log_chain_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.log"
            log = AuditLog(path)
            one = log.append({"n": 1})
            two = log.append({"n": 2})
            self.assertEqual(two["prev_hash"], one["chain_hash"])
            verify = log.verify()
            self.assertTrue(verify["ok"])
            self.assertEqual(verify["records"], 2)

    def test_privacy_safe_search_blocks_pii(self):
        search = PrivacySafeSearch(Path("absolute/apps/guide/search-index.example.json"))
        result = search.search("найди email john.doe@example.com", limit=3)
        self.assertTrue(result["blocked"])
        self.assertTrue(result["safe_alternatives"])

    def test_privacy_safe_search_fallback_non_empty(self):
        search = PrivacySafeSearch(Path("absolute/apps/guide/search-index.example.json"))
        result = search.search("квантовый кит в пустыне", limit=2)
        self.assertFalse(result["blocked"])
        self.assertEqual(result["mode"], "fallback")
        self.assertEqual(len(result["results"]), 2)


if __name__ == "__main__":
    unittest.main()
