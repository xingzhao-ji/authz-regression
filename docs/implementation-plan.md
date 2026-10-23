# Implementation plan

1. Validate a bounded JSON contract before sending any request. Use explicit actor environment references, relative paths, status and JSON assertions, and before/after state probes.
2. Implement sequential HTTP execution with exact-origin allowlisting, redirect refusal, bounded response reads, timeout handling and reports that omit headers, bodies and compared values.
3. Provide a real local demonstration API with two domains and independently selectable read/list/mutation authorization defects. Supply reservation and annotation contracts.
4. Test safe and faulty behavior through actual loopback HTTP, including a forbidden status that still leaks or mutates state. Verify malformed policies, missing secrets, bounded requests and deterministic output.
5. Package the CLI, one-command demos, CI, documentation and a reproducible sample report. Run the entire suite before committing.
