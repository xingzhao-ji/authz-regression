"""Tests use an actual HTTP server; no mocked HTTP transport."""

import copy
import json
import threading
import time
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from authz_regression.engine import PolicyError, render_markdown, run_policy, validate_policy


@contextmanager
def server():
    state = {"value": "original", "calls": [], "headers": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            state["calls"].append(self.path)
            state["headers"].append(self.headers.get("Authorization"))
            if self.path == "/slow":
                time.sleep(0.15)
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/state")
                self.end_headers()
                return
            status = 403 if self.path == "/leak" else 200
            data = {
                "value": state["value"],
                "items": [{"tenant": "A"}, {"tenant": "B"}],
                "echo": self.headers.get("Authorization"),
                "private": "response-only-secret",
            }
            body = json.dumps(data).encode()
            if self.path == "/huge":
                body = b"x" * 1100000
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                if self.path == "/trickle":
                    for byte in body:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(0.01)
                    return
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_POST(self):
            state["calls"].append(self.path)
            state["value"] = "changed"
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}", state
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


def policy(base_url="http://127.0.0.1:1"):
    return {
        "version": 1,
        "name": "test-contract",
        "base_url": base_url,
        "actors": {"owner": {"headers": {"Authorization": {"env": "TEST_TOKEN", "prefix": "Bearer "}}}},
        "resources": {"record": "one"},
        "cases": [{"id": "owner-read", "actor": "owner", "method": "GET", "path": "/state", "status": 200,
                   "assertions": [{"pointer": "/value", "op": "equals", "value": "original"}]}],
    }


class PolicyTests(unittest.TestCase):
    def test_malformed_contracts_are_rejected_before_network(self):
        changes = [
            ("base_url", "http://127.0.0.1:1/private"),
            ("base_url", "http://secret:password@127.0.0.1"),
            ("base_url", "http://127.0.0.1:0"),
            ("base_url", "file:///tmp/file"),
            ("timeout_seconds", 0),
            ("timeout_seconds", 31),
            ("version", True),
            ("unexpected", "typo"),
            ("cases", []),
            ("actors", {"owner": {"headers": {"Host": {"env": "HOST"}}}}),
        ]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                data = policy()
                data[key] = value
                with self.assertRaises(PolicyError):
                    validate_policy(data)

    def test_paths_and_assertions_cannot_escape_or_silently_do_nothing(self):
        for path in ("https://example.com", "//example.com", "/../state", "/%2e%2e/state", "/a\\b", "/{unknown}"):
            with self.subTest(path=path):
                data = policy()
                data["cases"][0]["path"] = path
                with self.assertRaises(PolicyError):
                    validate_policy(data)
        data = policy()
        data["cases"][0]["assertions"][0]["op"] = "equalz"
        with self.assertRaises(PolicyError):
            validate_policy(data)

    def test_non_loopback_requires_exact_cli_allowlist(self):
        with self.assertRaises(PolicyError):
            run_policy(policy("https://example.com"), environ={"TEST_TOKEN": "secret"})

    def test_resource_expansion_has_a_final_path_bound(self):
        data = policy()
        data["resources"] = {"long": "x" * 256}
        data["cases"][0]["path"] = "/" + "/".join(["{long}"] * 10)
        with self.assertRaises(PolicyError):
            validate_policy(data)

    def test_denied_writes_require_a_state_probe(self):
        data = policy()
        data["cases"][0].update(method="POST", status=403, assertions=[])
        with self.assertRaises(PolicyError):
            validate_policy(data)

    def test_all_env_references_are_resolved_before_requests(self):
        with server() as (url, state):
            data = policy(url)
            data["actors"]["other"] = {"headers": {"Authorization": {"env": "MISSING"}}}
            with self.assertRaises(PolicyError):
                run_policy(data, environ={"TEST_TOKEN": "secret"})
            self.assertEqual(state["calls"], [])


class HTTPTests(unittest.TestCase):
    def test_real_auth_header_and_semantic_assertion(self):
        with server() as (url, state):
            report = run_policy(policy(url), environ={"TEST_TOKEN": "bearer-secret"})
            self.assertEqual(report["summary"], {"passed": 1, "failed": 0})
            self.assertEqual(state["headers"], ["Bearer bearer-secret"])

    def test_expected_403_still_fails_when_private_data_leaks(self):
        with server() as (url, _):
            data = policy(url)
            data["cases"][0].update(path="/leak", status=403, assertions=[{"pointer": "/private", "op": "absent"}])
            report = run_policy(data, environ={"TEST_TOKEN": "secret"})
            self.assertFalse(report["passed"])
            self.assertEqual(report["cases"][0]["checks"][0]["passed"], True)
            self.assertIn("assertion_failed", [c["code"] for c in report["cases"][0]["checks"]])

    def test_list_scope_detected_without_status_failure(self):
        with server() as (url, _):
            data = policy(url)
            data["cases"][0]["assertions"] = [{"pointer": "/items/*/tenant", "op": "all_equals", "value": "A"}]
            report = run_policy(data, environ={"TEST_TOKEN": "secret"})
            self.assertFalse(report["passed"])

    def test_denied_mutation_checks_before_and_after_state(self):
        with server() as (url, state):
            data = policy(url)
            data["cases"][0].update(method="POST", path="/mutate", status=403, assertions=[],
                                    unchanged={"actor": "owner", "path": "/state", "pointer": "/value", "status": 200})
            report = run_policy(data, environ={"TEST_TOKEN": "secret"})
            self.assertFalse(report["passed"])
            self.assertEqual(state["calls"], ["/state", "/mutate", "/state"])
            self.assertIn("state_changed", [c["code"] for c in report["cases"][0]["checks"]])

    def test_reports_do_not_contain_tokens_headers_or_bodies(self):
        with server() as (url, _):
            data = policy(url)
            data["cases"][0]["assertions"] = [{"pointer": "/echo", "op": "equals", "value": "wrong"}]
            report = run_policy(data, environ={"TEST_TOKEN": "bearer-secret"})
            output = json.dumps(report) + render_markdown(report)
            self.assertNotIn("bearer-secret", output)
            self.assertNotIn("response-only-secret", output)
            self.assertNotIn("Authorization", output)
            self.assertIn("FAIL", output)

    def test_redirects_are_never_followed(self):
        with server() as (url, state):
            data = policy(url)
            data["cases"][0].update(path="/redirect", status=200, assertions=[])
            report = run_policy(data, environ={"TEST_TOKEN": "secret"})
            self.assertFalse(report["passed"])
            self.assertEqual(state["calls"], ["/redirect"])

    def test_timeout_and_response_size_fail_closed(self):
        for path, code in (("/slow", "timeout"), ("/huge", "response_too_large")):
            with self.subTest(path=path), server() as (url, _):
                data = policy(url)
                data["timeout_seconds"] = 0.03
                data["cases"][0]["path"] = path
                report = run_policy(data, environ={"TEST_TOKEN": "secret"})
                self.assertFalse(report["passed"])
                self.assertEqual(report["cases"][0]["checks"][0]["code"], code)

    def test_trickled_body_cannot_extend_the_request_deadline(self):
        with server() as (url, _):
            data = policy(url)
            data["timeout_seconds"] = 0.04
            data["cases"][0]["path"] = "/trickle"
            started = time.monotonic()
            report = run_policy(data, environ={"TEST_TOKEN": "secret"})
            self.assertLess(time.monotonic() - started, 0.3)
            self.assertFalse(report["passed"])
            self.assertEqual(report["cases"][0]["checks"][0]["code"], "timeout")

    def test_unavailable_state_baseline_prevents_the_write(self):
        with server() as (url, state):
            data = policy(url)
            data["cases"][0].update(method="POST", path="/mutate", status=403, assertions=[],
                                    unchanged={"actor": "owner", "path": "/leak", "pointer": "/value", "status": 200})
            report = run_policy(data, environ={"TEST_TOKEN": "secret"})
            self.assertFalse(report["passed"])
            self.assertEqual(state["calls"], ["/leak"])
            self.assertEqual(state["value"], "original")

    def test_reports_are_deterministic_across_identical_runs(self):
        with server() as (url, _):
            first = run_policy(policy(url), environ={"TEST_TOKEN": "secret"})
            second = run_policy(copy.deepcopy(policy(url)), environ={"TEST_TOKEN": "secret"})
            self.assertEqual(first, second)
            self.assertEqual(render_markdown(first), render_markdown(second))


if __name__ == "__main__":
    unittest.main()
