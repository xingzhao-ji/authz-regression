import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from authz_regression.demo import demo_server, sample_policy


ROOT = Path(__file__).resolve().parents[1]


def cli(*args, env=None):
    return subprocess.run([sys.executable, "-m", "authz_regression", *args], cwd=ROOT,
                          env=env, capture_output=True, text=True, encoding="utf-8", timeout=15)


class CLITests(unittest.TestCase):
    def test_safe_demo_generates_real_json_and_markdown_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            md_path = Path(directory) / "report.md"
            result = cli("demo", "--adapter", "annotations", "--json", str(json_path), "--markdown", str(md_path))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json_path.exists(), "JSON report was not written")
            report = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"], {"passed": 11, "failed": 0})
            self.assertEqual(result.stdout, md_path.read_text(encoding="utf-8"))
            self.assertIn("11 passed, 0 failed", result.stdout)

    def test_report_pipe_is_utf8_even_with_legacy_process_encoding(self):
        for encoding in ("ascii", "cp1252"):
            with self.subTest(encoding=encoding), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "report.md"
                result = subprocess.run(
                    [sys.executable, "-m", "authz_regression", "demo", "--markdown", str(path)],
                    cwd=ROOT, env={**os.environ, "PYTHONIOENCODING": encoding, "PYTHONUTF8": "0"},
                    capture_output=True, timeout=15,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, path.read_bytes())
                self.assertIn("**PASS** — 10 passed", result.stdout.decode("utf-8"))

    def test_buggy_demo_returns_nonzero_with_semantic_evidence(self):
        result = cli("demo", "--mode", "buggy")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("state_changed", result.stdout)
        self.assertIn("assertion_failed", result.stdout)
        self.assertIn("5 passed, 5 failed", result.stdout)

    def test_run_reads_policy_and_env_credentials_against_real_http(self):
        with demo_server() as fixture, tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(sample_policy("reservations", fixture.url)))
            result = cli("run", str(path), env={**os.environ, **fixture.environ})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("10 passed, 0 failed", result.stdout)
            for secret in fixture.environ.values():
                self.assertNotIn(secret, result.stdout + result.stderr)

    def test_malformed_policy_error_does_not_echo_sensitive_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text('{"version": "sensitive-policy-secret", "version": 1}')
            result = cli("run", str(path))
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("sensitive-policy-secret", result.stdout + result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_unpaired_unicode_surrogate_is_a_policy_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            data = sample_policy("reservations", "http://127.0.0.1:1")
            data["resources"]["own"] = "\ud800"
            path.write_text(json.dumps(data), encoding="utf-8")
            result = cli("validate", str(path))
            self.assertEqual(result.returncode, 2)
            self.assertIn("Policy error:", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertNotIn("UnicodeEncodeError", result.stderr)

    def test_validation_does_not_require_tokens_or_send_http(self):
        result = cli("validate", "authz_regression/policies/reservations.json", env={"PATH": os.environ.get("PATH", "")})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Valid policy", result.stdout)

    def test_report_paths_cannot_overwrite_the_input_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            before = json.dumps(sample_policy("reservations", "http://127.0.0.1:1"))
            path.write_text(before)
            result = cli("run", str(path), "--json", str(path))
            self.assertEqual(result.returncode, 2)
            self.assertEqual(path.read_text(), before)


if __name__ == "__main__":
    unittest.main()
