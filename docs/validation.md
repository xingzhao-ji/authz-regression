# Validation notes

Local interpreter: Python 3.12.14 on Linux. No external target API was contacted; integration tests use loopback servers on ephemeral ports and synthetic credentials.

Initial local suite: **25 tests passed**, including parameterized safe/buggy adapter runs. The built wheel was installed into a fresh virtual environment with `--no-index --no-deps`; running its installed entrypoint from `/tmp` passed all 10 reservation cases and all 11 annotation cases. This also checks that the policies are present in the wheel rather than accidentally loading them from the checkout.

The core's first test run observed 26 failed assertions against the initial no-op implementation. The demo API's first run observed seven failing adapter/defect subcases against a 404-only server. The CLI's initial six tests failed against its no-op entrypoint. These were followed by implementation and complete passing runs.

A further four failing regression checks identified missing final path bounds, port-zero normalization, missing required probes for denied writes, and a trickled-body timeout bug. The last exposed `http.client` detaching its connection socket on HTTP/1.0 while the response still reads through a file wrapper. Keeping the connected socket allows the deadline to interrupt that read. All four then passed.

Commands used for verification and packaging:

```sh
python3 -m unittest discover -v
python3 -m authz_regression demo
python3 -m authz_regression demo --adapter annotations
python3 -m authz_regression demo --mode buggy --json docs/sample-buggy-report.json --markdown docs/sample-buggy-report.md
python3 -m pip wheel . --no-build-isolation --no-deps --wheel-dir dist
```

The buggy demo's exit status 1 is expected and demonstrates detection. No performance, comprehensive security, production adoption or hosted-service availability claim is made.

## Review corrections

The initial hosted CI run passed Linux/Python 3.12 and 3.13 but failed Windows/Python 3.12 and 3.13 on comparison of captured stdout against a UTF-8 report file. Both child-pipe output and test readers had inherited locale-dependent encodings. New regressions reproduced an ASCII output crash and cp1252/UTF-8 byte mismatch locally, then passed after configuring CLI streams/files as UTF-8/LF and test capture/readers explicitly as UTF-8. Windows CI must be rerun on the corrected commit; the local legacy-encoding simulation is not a claim of a Windows pass.

Two review findings also have failing-before/passing-after regressions: unpaired-surrogate fixture identifiers now produce a clean policy error/exit 2 before URL quoting, and short actor tokens no longer rewrite fixed report reason codes/methods/operators. Redaction applies to user-controlled labels and still omits request/response data. The revised full suite contains **28 tests**, including subcases for ASCII/cp1252 pipes and overlapping short token strings.
