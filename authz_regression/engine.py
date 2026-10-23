"""Bounded, sequential HTTP permission checks with no response data in reports."""

import copy
import http.client
import ipaddress
import json
import math
import os
import re
import socket
import threading
import time
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

MAX_BYTES = 1_048_576
MAX_BODY_BYTES = 65_536
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
ENV = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}
MISSING = object()


class PolicyError(ValueError):
    """Invalid policy or execution scope; messages never contain policy values."""


def _require(condition, message):
    if not condition:
        raise PolicyError(message)


def _object(value, required, optional=()):
    _require(isinstance(value, dict), "Expected an object.")
    _require(set(required) <= value.keys() <= set(required) | set(optional), "Missing or unknown policy fields.")


def _identifier(value):
    _require(isinstance(value, str) and ID.fullmatch(value), "Invalid identifier.")


def _bounded_json(value):
    stack = [(value, 0)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        _require(count <= 50_000 and depth <= 20, "JSON structure exceeds limits.")
        if isinstance(item, dict):
            _require(all(isinstance(k, str) for k in item), "JSON keys must be strings.")
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, depth + 1) for v in item)
        elif isinstance(item, float):
            _require(math.isfinite(item), "Non-finite numbers are not supported.")
        else:
            _require(item is None or isinstance(item, (str, int, bool)), "Unsupported JSON value.")
    try:
        _require(len(json.dumps(value, ensure_ascii=True).encode()) <= MAX_BYTES, "JSON input exceeds one MiB.")
    except (ValueError, OverflowError, RecursionError):
        raise PolicyError("Invalid JSON structure.") from None


def _parse_json(raw):
    def duplicate_safe(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, "Duplicate JSON object keys.")
            result[key] = value
        return result

    try:
        result = json.loads(raw, object_pairs_hook=duplicate_safe)
        _bounded_json(result)
        return result
    except (UnicodeError, ValueError, RecursionError):
        raise PolicyError("Invalid or oversized JSON.") from None


def load_policy(path):
    """Read at most one MiB; reject duplicate keys and unknown schema fields."""
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
    except OSError:
        raise PolicyError("Cannot read policy file.") from None
    _require(len(raw) <= MAX_BYTES, "Policy exceeds one MiB.")
    return validate_policy(_parse_json(raw))


def _origin(value):
    _require(isinstance(value, str) and len(value) <= 2048, "Invalid base URL.")
    _require(not any(c.isspace() or ord(c) < 32 for c in value), "Invalid base URL.")
    try:
        parsed = urlsplit(value)
        _require(parsed.scheme in ("http", "https") and parsed.hostname, "Use an HTTP(S) origin.")
        _require(parsed.username is None and parsed.password is None, "URL credentials are forbidden.")
        _require(parsed.path in ("", "/") and not parsed.query and not parsed.fragment, "Base URL must be an origin only.")
        host = parsed.hostname.lower()
        _require(re.fullmatch(r"[a-z0-9.:-]+", host) is not None, "Invalid origin hostname.")
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        _require(1 <= port <= 65535, "Invalid origin port.")
    except ValueError:
        raise PolicyError("Invalid base URL.") from None
    return parsed.scheme, host, port


def _is_loopback(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _path(value, resources):
    _require(isinstance(value, str) and 1 <= len(value) <= 2048, "Invalid request path.")
    _require(value.startswith("/") and not value.startswith("//"), "Paths must be origin-relative.")
    _require(not any(ord(c) < 33 or ord(c) > 126 for c in value), "Use percent-encoded ASCII request paths.")
    _require("#" not in value and "\\" not in value, "Invalid request path.")
    for name in re.findall(r"\{([^{}]+)\}", value):
        _require(name in resources, "Unknown resource placeholder.")
        value = value.replace("{" + name + "}", quote(resources[name], safe=""))
    _require("{" not in value and "}" not in value, "Malformed resource placeholder.")
    _require(len(value) <= 2048, "Expanded request path exceeds limits.")
    decoded = value
    for _ in range(3):
        decoded = unquote(decoded)
    _require(not decoded.startswith("//") and "\\" not in decoded, "Invalid decoded request path.")
    _require(not any(ord(c) < 32 for c in decoded), "Control characters are forbidden.")
    _require(not any(part in (".", "..") for part in decoded.split("?", 1)[0].split("/")), "Path traversal is forbidden.")
    return value


def _pointer(value):
    _require(isinstance(value, str) and len(value) <= 512, "Invalid JSON pointer.")
    _require(value == "" or value.startswith("/"), "JSON pointers must be empty or start with slash.")
    _require(re.search(r"~(?![01])", value) is None and len(value.split("/")) <= 32, "Invalid JSON pointer escape or depth.")


def validate_policy(document):
    _bounded_json(document)
    _object(document, ("version", "name", "base_url", "actors", "resources", "cases"), ("timeout_seconds", "max_duration_seconds"))
    _require(type(document["version"]) is int and document["version"] == 1, "Unsupported policy version.")
    _identifier(document["name"])
    _origin(document["base_url"])
    for key, default, maximum in (("timeout_seconds", 3, 30), ("max_duration_seconds", 60, 3600)):
        number = document.get(key, default)
        _require(type(number) in (int, float) and 0 < number <= maximum, "Timeout or duration is out of bounds.")
    actors, resources, cases = document["actors"], document["resources"], document["cases"]
    _require(isinstance(actors, dict) and 1 <= len(actors) <= 32, "Use 1 to 32 actors.")
    for name, actor in actors.items():
        _identifier(name)
        _object(actor, ("headers",))
        headers = actor["headers"]
        _require(isinstance(headers, dict) and len(headers) <= 16, "Invalid actor headers.")
        seen = set()
        for header, ref in headers.items():
            _require(isinstance(header, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,63}", header), "Invalid header name.")
            lower = header.lower()
            _require(lower not in seen and lower not in {"host", "content-length", "transfer-encoding", "connection", "content-type", "accept-encoding"}, "Reserved or duplicate header.")
            seen.add(lower)
            _object(ref, ("env",), ("prefix",))
            _require(isinstance(ref["env"], str) and ENV.fullmatch(ref["env"]), "Invalid environment reference.")
            prefix = ref.get("prefix", "")
            _require(isinstance(prefix, str) and len(prefix) <= 64 and all(32 <= ord(c) <= 126 for c in prefix), "Invalid header prefix.")
    _require(isinstance(resources, dict) and len(resources) <= 64, "Invalid resource fixtures.")
    for name, value in resources.items():
        _identifier(name)
        _require(isinstance(value, str) and 1 <= len(value) <= 256, "Resource fixture must be a bounded string.")
    _require(isinstance(cases, list) and 1 <= len(cases) <= 256, "Use 1 to 256 cases.")
    ids = set()
    for case in cases:
        _object(case, ("id", "actor", "method", "path", "status", "assertions"), ("body", "unchanged"))
        _identifier(case["id"])
        _require(case["id"] not in ids, "Duplicate case identifier.")
        ids.add(case["id"])
        _require(isinstance(case["actor"], str) and case["actor"] in actors, "Unknown case actor.")
        _require(isinstance(case["method"], str) and case["method"] in METHODS, "Unsupported HTTP method.")
        _path(case["path"], resources)
        _require(type(case["status"]) is int and 100 <= case["status"] <= 599, "Invalid expected HTTP status.")
        if case["method"] in {"POST", "PUT", "PATCH", "DELETE"} and case["status"] in {401, 403, 404}:
            _require("unchanged" in case, "Denied mutations require an unchanged state probe.")
        if "body" in case:
            _require(case["method"] not in ("GET", "HEAD"), "GET and HEAD cannot have a request body.")
            _require(len(json.dumps(case["body"]).encode()) <= MAX_BODY_BYTES, "Request body exceeds 64 KiB.")
        assertions = case["assertions"]
        _require(isinstance(assertions, list) and len(assertions) <= 32, "Too many assertions.")
        for assertion in assertions:
            _object(assertion, ("pointer", "op"), ("value",))
            _pointer(assertion["pointer"])
            op = assertion["op"]
            _require(isinstance(op, str) and op in {"equals", "not_equals", "present", "absent", "length", "contains", "not_contains", "all_equals"}, "Unknown assertion operator.")
            _require(("value" in assertion) == (op not in ("present", "absent")), "Assertion value is missing or unexpected.")
            if op == "length":
                _require(type(assertion["value"]) is int and assertion["value"] >= 0, "Length assertion requires a nonnegative integer.")
            if "*" in assertion["pointer"].split("/"):
                _require(op in {"all_equals", "present", "absent"}, "Use all_equals for wildcard pointers.")
        if "unchanged" in case:
            probe = case["unchanged"]
            _object(probe, ("actor", "path", "pointer", "status"))
            _require(isinstance(probe["actor"], str) and probe["actor"] in actors, "Unknown probe actor.")
            _path(probe["path"], resources)
            _pointer(probe["pointer"])
            _require("*" not in probe["pointer"].split("/"), "State probes require a single JSON value.")
            _require(type(probe["status"]) is int and 200 <= probe["status"] <= 299, "State probes require a successful HTTP status.")
    return copy.deepcopy(document)


def _resolve_headers(actors, environ):
    result, secrets = {}, []
    for name, actor in actors.items():
        result[name] = {}
        for header, ref in actor["headers"].items():
            value = environ.get(ref["env"])
            _require(isinstance(value, str) and 1 <= len(value) <= 8192, "Missing, empty or oversized actor environment value.")
            _require(all(32 <= ord(c) <= 126 for c in value), "Actor header values must be printable ASCII.")
            result[name][header] = ref.get("prefix", "") + value
            secrets.extend((value, result[name][header]))
    return result, secrets


def _request(origin, path, method, headers, body, timeout):
    scheme, host, port = origin
    # Literal loopback also avoids localhost DNS overrides and ignores proxy env vars.
    host = "127.0.0.1" if host == "localhost" else host
    cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    connection = cls(host, port, timeout=timeout)
    deadline = time.monotonic() + timeout
    expired = threading.Event()
    timer = None
    active_socket = None

    def interrupt():
        expired.set()
        # HTTP/1.0 may detach connection.sock while the response still owns
        # a file wrapper. Keep the connected socket to interrupt a slow body.
        sock = active_socket
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    try:
        connection.connect()
        active_socket = connection.sock
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, None, "timeout"
        timer = threading.Timer(remaining, interrupt)
        timer.daemon = True
        timer.start()
        request_headers = {"Accept": "application/json", **headers}
        payload = None
        if body is not MISSING:
            payload = json.dumps(body, separators=(",", ":")).encode()
            request_headers["Content-Type"] = "application/json"
        connection.request(method, path, body=payload, headers=request_headers)
        response = connection.getresponse()
        data = response.read(MAX_BYTES + 1)
        if expired.is_set():
            return None, None, "timeout"
        if len(data) > MAX_BYTES:
            return response.status, None, "response_too_large"
        if 300 <= response.status < 400:
            return response.status, None, "redirect_refused"
        return response.status, data, None
    except (socket.timeout, TimeoutError):
        return None, None, "timeout"
    except (OSError, http.client.HTTPException, ValueError):
        return None, None, "timeout" if expired.is_set() else "network_error"
    finally:
        if timer is not None:
            timer.cancel()
        connection.close()


def _select(document, pointer):
    values = [document]
    for part in pointer.split("/")[1:]:
        part = part.replace("~1", "/").replace("~0", "~")
        next_values = []
        for value in values:
            if part == "*" and isinstance(value, list):
                next_values.extend(value)
            elif isinstance(value, dict):
                next_values.append(value.get(part, MISSING))
            elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", part):
                index = int(part)
                next_values.append(value[index] if index < len(value) else MISSING)
            else:
                next_values.append(MISSING)
        values = next_values
    return values


def _equal(left, right):
    # JSON bools are distinct from numbers (unlike Python's True == 1).
    return json.dumps(left, sort_keys=True, separators=(",", ":")) == json.dumps(right, sort_keys=True, separators=(",", ":"))


def _assert(document, assertion):
    values = _select(document, assertion["pointer"])
    op, expected = assertion["op"], assertion.get("value")
    if op == "absent":
        return all(value is MISSING for value in values)
    if not values or any(value is MISSING for value in values):
        return False
    if op == "present":
        return True
    if op == "all_equals":
        return all(_equal(value, expected) for value in values)
    if len(values) != 1:
        return False
    value = values[0]
    if op in ("equals", "not_equals"):
        equal = _equal(value, expected)
        return equal if op == "equals" else not equal
    if op == "length":
        return isinstance(value, (list, dict, str)) and len(value) == expected
    if not isinstance(value, list):
        return False
    contains = any(_equal(item, expected) for item in value)
    return contains if op == "contains" else not contains


def _check(code, passed, **extra):
    return {"code": code, "passed": bool(passed), **extra}


def _redact(value, secrets):
    if isinstance(value, str):
        for secret in sorted(set(secrets), key=len, reverse=True):
            value = value.replace(secret, "[REDACTED]")
        return value
    if isinstance(value, list):
        return [_redact(item, secrets) for item in value]
    if isinstance(value, dict):
        return {key: _redact(item, secrets) for key, item in value.items()}
    return value


def run_policy(document, *, environ=None, allow_origins=()):
    policy = validate_policy(document)
    origin = _origin(policy["base_url"])
    allowed = {_origin(value) for value in allow_origins}
    _require(_is_loopback(origin[1]) or origin in allowed, "Non-loopback targets require an explicit exact --allow-origin.")
    headers, secrets = _resolve_headers(policy["actors"], os.environ if environ is None else environ)
    deadline = time.monotonic() + policy.get("max_duration_seconds", 60)
    results = []

    def request(actor, path, method="GET", body=MISSING):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, None, "run_limit"
        return _request(origin, _path(path, policy["resources"]), method, headers[actor], body,
                        min(policy.get("timeout_seconds", 3), remaining))

    def probe(probe_config):
        status, raw, error = request(probe_config["actor"], probe_config["path"])
        if error or status != probe_config["status"]:
            return MISSING, error or "probe_status"
        try:
            values = _select(_parse_json(raw), probe_config["pointer"])
        except PolicyError:
            return MISSING, "probe_invalid_json"
        if len(values) != 1 or values[0] is MISSING:
            return MISSING, "probe_missing_value"
        return values[0], None

    for case in policy["cases"]:
        checks = []
        row = {"id": case["id"], "actor": case["actor"], "method": case["method"], "status": None, "checks": checks}
        results.append(row)
        before = MISSING
        if "unchanged" in case:
            before, error = probe(case["unchanged"])
            if error:
                checks.append(_check("preflight_" + error, False))
                row["passed"] = False
                continue  # An unusable baseline must never permit a mutation.
        status, raw, error = request(case["actor"], case["path"], case["method"], case.get("body", MISSING))
        row["status"] = status
        if error:
            checks.append(_check(error, False))
        else:
            checks.append(_check("status", status == case["status"], expected=case["status"], actual=status))
            if case["assertions"]:
                try:
                    parsed = _parse_json(raw)
                except PolicyError:
                    checks.append(_check("invalid_json", False))
                else:
                    for index, assertion in enumerate(case["assertions"], 1):
                        passed = _assert(parsed, assertion)
                        checks.append(_check("assertion_passed" if passed else "assertion_failed", passed, index=index, op=assertion["op"]))
        if "unchanged" in case:
            after, error = probe(case["unchanged"])
            if error:
                checks.append(_check("postflight_" + error, False))
            else:
                same = _equal(before, after)
                checks.append(_check("state_unchanged" if same else "state_changed", same))
        row["passed"] = all(check["passed"] for check in checks)
    passed_count = sum(row["passed"] for row in results)
    report = {"schema_version": 1, "suite": policy["name"], "passed": passed_count == len(results),
              "summary": {"passed": passed_count, "failed": len(results) - passed_count}, "cases": results}
    return _redact(report, secrets)


def render_markdown(report):
    lines = [f"# {report['suite']}", "", f"**{'PASS' if report['passed'] else 'FAIL'}** — {report['summary']['passed']} passed, {report['summary']['failed']} failed.", "",
             "| Case | Actor | Method | HTTP | Result | Evidence |", "| --- | --- | --- | --- | --- | --- |"]
    for row in report["cases"]:
        evidence = ", ".join(check["code"] + (f" #{check['index']}" if "index" in check else "")
                             for check in row["checks"] if not check["passed"])
        lines.append(f"| {row['id']} | {row['actor']} | {row['method']} | {row['status'] or '—'} | {'PASS' if row['passed'] else 'FAIL'} | {evidence or 'All checks passed'} |")
    lines.extend(["", "Headers, paths, response bodies and compared values are omitted. No timing or wall-clock fields are included.", ""])
    return "\n".join(lines)
