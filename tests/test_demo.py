import unittest

from authz_regression.demo import demo_server, sample_policy
from authz_regression.engine import run_policy


class DemoTests(unittest.TestCase):
    def test_safe_reservation_and_annotation_contracts_pass(self):
        for adapter, total in (("reservations", 10), ("annotations", 11)):
            with self.subTest(adapter=adapter), demo_server() as fixture:
                report = run_policy(sample_policy(adapter, fixture.url), environ=fixture.environ)
                self.assertEqual(report["summary"], {"passed": total, "failed": 0})

    def test_buggy_contract_fails_exact_seeded_cases_despite_correct_http_status(self):
        expected = {"cross-tenant-read", "tenant-list", "cross-tenant-write", "peer-write-denied", "admin-cross-tenant-write"}
        for adapter in ("reservations", "annotations"):
            with self.subTest(adapter=adapter), demo_server(bugs={"read-leak", "list-leak", "denied-write"}) as fixture:
                report = run_policy(sample_policy(adapter, fixture.url), environ=fixture.environ)
                failures = {row["id"] for row in report["cases"] if not row["passed"]}
                self.assertEqual(failures, expected)
                for row in report["cases"]:
                    for check in row["checks"]:
                        if check["code"] == "status":
                            self.assertTrue(check["passed"], row["id"])

    def test_each_bug_is_independently_detectable(self):
        for bug, expected in (("read-leak", {"cross-tenant-read"}), ("list-leak", {"tenant-list"}),
                              ("denied-write", {"cross-tenant-write", "peer-write-denied", "admin-cross-tenant-write"})):
            with self.subTest(bug=bug), demo_server(bugs={bug}) as fixture:
                report = run_policy(sample_policy("reservations", fixture.url), environ=fixture.environ)
                self.assertEqual({row["id"] for row in report["cases"] if not row["passed"]}, expected)


if __name__ == "__main__":
    unittest.main()
