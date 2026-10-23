# Contract reference (version 1)

A policy is one JSON object. Unknown fields, duplicate object keys, invalid identifiers, unpaired Unicode surrogates and unrecognized assertions are errors before network activity. The complete examples are in `authz_regression/policies/`.

| Top-level field | Meaning |
| --- | --- |
| `version` | Integer `1`. |
| `name` | Stable report identifier. |
| `base_url` | HTTP(S) origin only, such as `http://127.0.0.1:8765`. No URL credentials, base path, query or fragment. |
| `actors` | 1–32 actor objects with a `headers` map. Anonymous actors use an empty map. |
| `resources` | Up to 64 fixture aliases with string identifiers. `{alias}` in a request path is URL-encoded as one value. No discovery or fixture creation. |
| `cases` | 1–256 sequential cases, with unique `id` fields. |
| `timeout_seconds` | Optional number, greater than zero and at most 30; default 3 per request. |
| `max_duration_seconds` | Optional number, greater than zero and at most 3600; default 60 for the run. Cases after exhaustion fail with `run_limit`. |

Names and case/actor/resource identifiers start with an ASCII letter or digit and use up to 80 ASCII letters, digits, underscores, periods or hyphens. JSON nesting is bounded at 20 levels; policies and responses are bounded at 1 MiB. No dynamic expressions, scripts, regular expressions or plugins execute from a policy.

Each actor header has `{"env": "VARIABLE_NAME", "prefix": "Bearer "}`. `prefix` is optional. Missing/empty variables, control characters, duplicate case-insensitive header names and reserved transport headers fail preflight. Credential values are never copied to reports. Known credential strings are additionally removed from policy-controlled report labels; fixed public schema names/enums are preserved even if a token happens to have the same spelling.

## Cases

Required fields: `id`, `actor`, `method`, `path`, `status`, `assertions`. Optional fields: `body` (JSON), `unchanged` (probe).

Methods are GET, HEAD, POST, PUT, PATCH, DELETE. Paths must start with a single `/` and cannot switch origins, contain fragments or traverse directories. Query strings are allowed and omitted from reports. The expanded path limit is 2048 characters. JSON `body` is allowed only on mutation methods and is limited to 64 KiB.

`status` is one exact expected HTTP status. Every redirect is a failure, irrespective of that expectation. An empty `assertions` list checks status alone; use content assertions to check disclosure and tenant boundaries. Denied mutation cases expecting 401/403/404 require a state probe.

## JSON assertions

An assertion has `pointer`, `op` and, except for `present`/`absent`, `value`. Pointers follow JSON Pointer's `/` segments and `~0`/`~1` escapes. The empty pointer selects the entire response. A `*` segment expands an array and is permitted with `all_equals`, `present` and `absent` only. Literal object keys named `*` are not addressable unambiguously in this version.

| Operator | Behavior |
| --- | --- |
| `equals` | Exact JSON value comparison at one location. Object key order is ignored; types remain significant. |
| `not_equals` | Existing value must differ. A missing field fails. |
| `present` | At least one selected value exists, and all selected locations exist. JSON `null` is present. |
| `absent` | Every selected location is missing. JSON `null` is not absent. |
| `length` | String, array or object length equals a nonnegative integer. |
| `contains` | Array includes the exact JSON value. |
| `not_contains` | Existing array does not include the exact JSON value. |
| `all_equals` | Every selected value equals the expected value; an empty selection or any missing field fails. |

Example list scope checks:

```json
[
  {"pointer": "/items", "op": "length", "value": 2},
  {"pointer": "/items/*/tenant", "op": "all_equals", "value": "A"}
]
```

Checking a nonempty collection also prevents a server from satisfying tenant filtering by returning no records. If an empty result is the expected contract, use a `length: 0` assertion without `all_equals`.

## State invariants

`unchanged` requires `actor`, `path`, `pointer`, and a successful `status` in 200–299. The probe is always GET and selects exactly one JSON subtree; wildcard probes are forbidden. Choose an actor authorized to observe the actual record being mutated. No separate probe origin can be supplied.

The runner performs a before-probe, the target request, and an after-probe. A failed before-probe stops the target request. A failed after-probe fails the case, because preservation could not be established. Successful probes are compared without including their values or hashes in the report. Concurrent writers can cause a failure; this runner does not isolate a target database or perform rollback.

## Reports and execution scope

JSON reports have `schema_version`, `suite`, `passed`, `summary` and ordered `cases`. Each case includes its id, actor label, method, observed status, boolean outcome and checks. Checks report fixed reason codes, status integers and assertion indexes/operators; they contain no values, paths, response excerpts or exception text. Schema version is independently versioned from the policy.

Markdown is derived from this report. CLI streams and output files use UTF-8 with LF newlines, independent of the platform's locale/default pipe encoding. When capturing output in Python, specify `encoding="utf-8"`; read report files with `encoding="utf-8"`. Reports are atomically replaced individually; writing two output files is not a multi-file transaction. The CLI refuses output paths that overwrite the input policy or collide with each other.

The allowlist is an exact `(scheme, hostname, port)` match supplied via `--allow-origin`; it cannot be embedded in the policy to grant itself permission. It does not accept wildcards or redirects. `localhost` is pinned to IPv4 loopback; other default-allowed targets must be literal loopback addresses. Explicitly allowed DNS hostnames use OS resolution at connection time, so allowlisting expresses operator intent, not a defense against a compromised DNS service. Proxy environment variables are ignored.
