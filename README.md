# authz-regression

**A 403 response can still leak a record. It can also arrive after a write.**

Run permission contracts against an HTTP API and check three things: response status, returned data scope, and whether a denied operation changed state. The report deliberately omits request paths, headers, response bodies and compared values.

Python 3.12+. No application or test dependencies. This is a small contract runner with a real, disposable HTTP demonstration API—not an automatic vulnerability scanner.

## Try it

From a checkout, one command starts a local server, creates synthetic actors and fixtures, exercises the reservation API, and shuts everything down:

```sh
python3 -m authz_regression demo
```

The safe API passes all 10 reservation cases. Inject the three known permission defects:

```sh
python3 -m authz_regression demo --mode buggy
```

That command intentionally exits **1**: five cases fail even though **every HTTP status is correct**. The failed cases are a cross-tenant read, an unfiltered list, and three denied writes that change state.

```text
FAIL — 5 passed, 5 failed.

cross-tenant-read          403   FAIL   assertion_failed #1
tenant-list               200   FAIL   assertion_failed #1, assertion_failed #2
cross-tenant-write         403   FAIL   state_changed
peer-write-denied          403   FAIL   state_changed
admin-cross-tenant-write   403   FAIL   state_changed
```

The excerpt is from the real [sample report](docs/sample-buggy-report.md), with the complete [machine-readable JSON](docs/sample-buggy-report.json).

The second adapter uses nested document/annotation routes, PATCH requests and document-parent checks:

```sh
python3 -m authz_regression demo --adapter annotations
python3 -m authz_regression demo --adapter annotations --mode buggy
```

Safe annotations pass 11 cases; the buggy API fails the same five permission invariants. Both examples use real loopback HTTP, fresh random synthetic bearer credentials and isolated in-memory data. These are example API contracts, not integrations with an existing production service.

## Test

```sh
python3 -m unittest discover -v
```

The suite covers both safe/buggy APIs, individually injected defects, real authorization headers, a 403 data leak, successful cross-tenant list leakage, denied-write snapshots, unusable baseline refusal, secret omission, redirect refusal, oversized responses, trickled-body deadlines, malformed contracts, and CLI exit codes/report files. The CI definition also tests package installation on Linux and Windows with Python 3.12/3.13; local results are recorded in [validation notes](docs/validation.md).

## Use your own contract

Start from a packaged example:

- [Reservation permissions](authz_regression/policies/reservations.json): tenant-wide reads, owner cancellation, tenant-admin cancellation, cross-tenant denial.
- [Annotation permissions](authz_regression/policies/annotations.json): document-scoped reads, owner/admin edits, parent-resource mismatch, cross-tenant denial.

The `resources` map contains fixture identifiers, not instructions to create or discover resources. Provision disposable fixture records in your own test environment, map actor tokens through environment variables, and adapt paths/assertions to that API.

```sh
python3 -m authz_regression validate authz_regression/policies/reservations.json
python3 -m authz_regression run my-contract.json --json reports/run.json --markdown reports/run.md
```

`validate` performs no network requests and requires no credentials. `run` validates the entire policy and resolves **all** environment references before sending the first request. Reports are deterministic for identical observed outcomes: no timestamps, durations, generated ports, bodies or credential header values. CLI output and report files use **UTF-8 with LF newlines**, including when output is piped on Windows.

Only literal loopback addresses and `localhost` are allowed by default. An external test environment requires an exact origin opt-in:

```sh
python3 -m authz_regression run my-contract.json \
  --base-url https://staging.example.test \
  --allow-origin https://staging.example.test
```

This runs only the explicit contract paths on that origin. It does not crawl, discover endpoints or follow redirects. Proxy environment variables are ignored. Use disposable test environments you are authorized to exercise: legitimate success cases and deliberately faulty servers can change data.

## A denied-write case

```json
{
  "id": "cross-tenant-cancel",
  "actor": "a-owner",
  "method": "POST",
  "path": "/reservations/{other}/cancel",
  "status": 403,
  "assertions": [{"pointer": "/resource", "op": "absent"}],
  "unchanged": {
    "actor": "b-owner",
    "path": "/reservations/{other}",
    "pointer": "/resource",
    "status": 200
  }
}
```

For this illustrative API, the runner reads the resource as its authorized owner, issues the denied request as the other tenant, and reads it again. A missing/unreadable baseline blocks the mutation. The after-probe still runs if the target request fails or times out, subject to the overall run budget. `POST`, `PUT`, `PATCH` and `DELETE` cases expecting 401/403/404 must include an `unchanged` probe.

Actor headers reference environment values; literal credentials are not part of the schema:

```json
"a-owner": {
  "headers": {
    "Authorization": {"env": "STAGING_OWNER_TOKEN", "prefix": "Bearer "}
  }
}
```

See the [contract reference](docs/contracts.md) for all fields, assertions and limits.

## Install the command

Running from a checkout needs only Python. To install the `authz-regression` entrypoint in a virtual environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
authz-regression demo
```

On Windows, activate with `.venv\Scripts\Activate.ps1`. There are no runtime dependencies; build tooling is pinned in `pyproject.toml` and `requirements-build.txt`. No package has been published to PyPI.

Exit codes: **0** contract passes or validation succeeds; **1** one or more HTTP/semantic/state checks fail; **2** invalid policy, scope, credentials or local I/O; **130** interrupted.

## Persistent local fixture server

`demo` is the shortest path. For a server in a separate terminal, set `DEMO_A_OWNER`, `DEMO_A_PEER`, `DEMO_A_ADMIN`, and `DEMO_B_OWNER` to four distinct synthetic values in both terminals, then run:

```sh
python3 -m authz_regression serve --port 8765
```

In the second terminal, run a packaged policy with `run`. Restart the server between contract runs to reset fixture state; authorized mutations increment versions. The server is always bound to `127.0.0.1`. `--mode buggy` intentionally enables the three teaching defects. It is a fixture API, with no persistent storage or production deployment role.

## Limits and design choices

- Assertions cover only what the contract names. A green report is evidence about those cases, not a complete authorization or security assessment.
- Requests run sequentially. Concurrent races, asynchronous side effects after the after-probe, eventual consistency, OAuth token refresh, WebSockets and browser sessions are outside this version.
- A state probe checks a single JSON subtree with exact comparison. Choose a stable, authoritative subtree. There is no automatic database rollback or cleanup of target fixtures.
- Responses are buffered up to 1 MiB; request bodies up to 64 KiB. Per-request network deadlines include headers and bodies, including slow trickles; OS DNS resolution for explicitly allowed hostnames is not interruptible by Python's socket timeout. The default loopback demo performs no DNS lookup.
- TLS certificate verification uses Python's default trust settings. Remote HTTP can be explicitly allowed, but use HTTPS for real credentials. Redirects always fail, even to the same origin.
- Reports omit bodies and values entirely rather than guessing which fields are sensitive. Known actor token strings are also removed from user-supplied report labels. Fixed schema names, reason codes, methods and operators remain stable even if a short token coincidentally matches one of them. The original policy and target application logs remain your responsibility.
- This implementation was developed with AI assistance. The included defect injections and executable tests make its claimed behavior reviewable.
