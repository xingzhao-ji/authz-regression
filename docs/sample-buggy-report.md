# reservation-permissions

**FAIL** — 5 passed, 5 failed.

| Case | Actor | Method | HTTP | Result | Evidence |
| --- | --- | --- | --- | --- | --- |
| anonymous-denied | anonymous | GET | 401 | PASS | All checks passed |
| owner-read | a-owner | GET | 200 | PASS | All checks passed |
| same-tenant-read | a-peer | GET | 200 | PASS | All checks passed |
| cross-tenant-read | a-owner | GET | 403 | FAIL | assertion_failed #1 |
| tenant-list | a-owner | GET | 200 | FAIL | assertion_failed #1, assertion_failed #2 |
| owner-cancel | a-owner | POST | 200 | PASS | All checks passed |
| admin-same-tenant-cancel | a-admin | POST | 200 | PASS | All checks passed |
| cross-tenant-write | a-owner | POST | 403 | FAIL | state_changed |
| peer-write-denied | a-peer | POST | 403 | FAIL | state_changed |
| admin-cross-tenant-write | a-admin | POST | 403 | FAIL | state_changed |

Headers, paths, response bodies and compared values are omitted. No timing or wall-clock fields are included.
