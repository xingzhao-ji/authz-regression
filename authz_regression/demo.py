"""Synthetic local fixture APIs for exercising permission contracts."""

from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
import json
import secrets
import threading
from urllib.parse import urlsplit

from .engine import PolicyError

BUGS = frozenset({"read-leak", "list-leak", "denied-write"})
ACTORS = {
    "DEMO_A_OWNER": {"id": "alice", "tenant": "A", "role": "member"},
    "DEMO_A_PEER": {"id": "avery", "tenant": "A", "role": "member"},
    "DEMO_A_ADMIN": {"id": "alex", "tenant": "A", "role": "admin"},
    "DEMO_B_OWNER": {"id": "blair", "tenant": "B", "role": "member"},
}


@dataclass
class Fixture:
    url: str
    environ: dict


def sample_policy(adapter, base_url):
    if adapter not in ("reservations", "annotations"):
        raise PolicyError("Unknown demo adapter.")
    path = files("authz_regression").joinpath("policies", adapter + ".json")
    policy = json.loads(path.read_text(encoding="utf-8"))
    policy["base_url"] = base_url
    return policy


@contextmanager
def demo_server(*, bugs=(), environ=None, port=0):
    """Start a disposable API on IPv4 loopback, reset seeded data at each start."""
    bugs = frozenset(bugs)
    if not bugs <= BUGS:
        raise PolicyError("Unknown demo defect.")
    tokens = {key: secrets.token_urlsafe(24) for key in ACTORS} if environ is None else {
        key: environ.get(key) for key in ACTORS
    }
    if any(not isinstance(value, str) or not value or len(value) > 8192 or
           any(ord(c) < 32 or ord(c) > 126 for c in value) for value in tokens.values()):
        raise PolicyError("Demo server requires all four DEMO actor environment values.")
    if len(set(tokens.values())) != len(tokens):
        raise PolicyError("Demo actor environment values must be distinct.")
    identities = {"Bearer " + value: ACTORS[key] for key, value in tokens.items()}
    reservations = {
        "r-a": {"id": "r-a", "tenant": "A", "owner": "alice", "room": "Lab 1", "state": "active", "version": 0},
        "r-peer": {"id": "r-peer", "tenant": "A", "owner": "avery", "room": "Lab 2", "state": "active", "version": 0},
        "r-b": {"id": "r-b", "tenant": "B", "owner": "blair", "room": "Lab 3", "state": "active", "version": 0},
    }
    annotations = {
        "a-a": {"id": "a-a", "document": "d-a", "tenant": "A", "owner": "alice", "text": "A synthetic note", "version": 0},
        "a-peer": {"id": "a-peer", "document": "d-a", "tenant": "A", "owner": "avery", "text": "A peer note", "version": 0},
        "a-b": {"id": "a-b", "document": "d-b", "tenant": "B", "owner": "blair", "text": "B synthetic note", "version": 0},
    }
    documents = {"d-a": "A", "d-b": "B"}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "AuthzDemo/0.1"

        def setup(self):
            super().setup()
            self.connection.settimeout(3)

        def log_message(self, *args):
            # Access logging would expose request paths or credentials in fixtures.
            pass

        def reply(self, status, value):
            body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def body(self):
            if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) > 1:
                raise ValueError
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= 65536:
                raise ValueError
            if not length:
                return {}
            data = self.rfile.read(length)
            if len(data) != length:
                raise ValueError
            value = json.loads(data)
            if not isinstance(value, dict):
                raise ValueError
            return value

        def handle_api(self):
            actor = identities.get(self.headers.get("Authorization"))
            if actor is None:
                self.reply(401, {"error": "unauthenticated"})
                return
            try:
                payload = self.body() if self.command in ("PATCH", "POST") else {}
            except (ValueError, UnicodeError, RecursionError, OSError):
                self.reply(400, {"error": "invalid_request"})
                return
            parts = urlsplit(self.path).path.strip("/").split("/")
            with lock:
                if parts == ["reservations"] and self.command == "GET":
                    items = list(reservations.values())
                    if "list-leak" not in bugs:
                        items = [item for item in items if item["tenant"] == actor["tenant"]]
                    self.reply(200, {"items": items})
                    return
                if len(parts) in (2, 3) and parts[0] == "reservations":
                    record = reservations.get(parts[1])
                    read = len(parts) == 2 and self.command == "GET"
                    write = len(parts) == 3 and parts[2] == "cancel" and self.command == "POST"
                    domain = "reservations"
                elif len(parts) in (3, 4) and parts[0] == "documents" and parts[2] == "annotations":
                    document = parts[1]
                    if document not in documents:
                        self.reply(404, {"error": "not_found"})
                        return
                    if len(parts) == 3 and self.command == "GET":
                        if documents[document] != actor["tenant"]:
                            self.reply(403, {"error": "forbidden"})
                            return
                        items = list(annotations.values())
                        if "list-leak" not in bugs:
                            items = [item for item in items if item["document"] == document and item["tenant"] == actor["tenant"]]
                        self.reply(200, {"items": items})
                        return
                    record = annotations.get(parts[3]) if len(parts) == 4 else None
                    if record and record["document"] != document:
                        record = None
                    read, write = self.command == "GET", self.command == "PATCH"
                    domain = "annotations"
                else:
                    record, read, write, domain = None, False, False, None
                if record is None:
                    self.reply(404, {"error": "not_found"})
                    return
                if not read and not write:
                    self.reply(405, {"error": "method_not_allowed"})
                    return
                same_tenant = record["tenant"] == actor["tenant"]
                allowed = same_tenant and (read or record["owner"] == actor["id"] or actor["role"] == "admin")
                if write:
                    if domain == "annotations" and (set(payload) != {"text"} or not isinstance(payload["text"], str) or not 1 <= len(payload["text"]) <= 4096):
                        self.reply(400, {"error": "invalid_request"})
                        return
                    if allowed or "denied-write" in bugs:
                        if domain == "reservations":
                            record["state"] = "cancelled"
                        else:
                            record["text"] = payload["text"]
                        record["version"] += 1
                if not allowed:
                    response = {"error": "forbidden"}
                    if read and "read-leak" in bugs:
                        response["resource"] = record
                    self.reply(403, response)
                    return
                self.reply(200, {"resource": record})

        do_GET = handle_api
        do_POST = handle_api
        do_PATCH = handle_api
        do_PUT = handle_api
        do_DELETE = handle_api

    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield Fixture(f"http://127.0.0.1:{httpd.server_port}", tokens)
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()
