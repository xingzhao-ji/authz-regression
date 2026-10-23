"""Command-line entrypoint."""

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import threading

from . import __version__
from .demo import BUGS, demo_server, sample_policy
from .engine import PolicyError, load_policy, render_markdown, run_policy


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # A mistyped argument may itself contain sensitive text.
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid arguments; use --help for supported options.\n")


def _parser():
    parser = Parser(prog="authz-regression", description="Exercise an explicitly configured HTTP permission contract.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
    run = commands.add_parser("run", help="Run a JSON contract against its explicitly configured origin")
    run.add_argument("policy")
    run.add_argument("--base-url", help="Override the contract's origin")
    run.add_argument("--allow-origin", action="append", default=[], help="Explicitly allow this exact non-loopback origin; repeatable")
    validate = commands.add_parser("validate", help="Validate the JSON schema without network or credentials")
    validate.add_argument("policy")
    demo = commands.add_parser("demo", help="Start an ephemeral local API, run its contract, then stop it")
    demo.add_argument("--adapter", choices=("reservations", "annotations"), default="reservations")
    demo.add_argument("--mode", choices=("safe", "buggy"), default="safe")
    serve = commands.add_parser("serve", help="Serve the synthetic API on loopback; requires four DEMO actor env vars")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--mode", choices=("safe", "buggy"), default="safe")
    for command in (run, demo):
        command.add_argument("--json", dest="json_path", help="Write a machine-readable report")
        command.add_argument("--markdown", dest="markdown_path", help="Write the terminal report as Markdown")
    return parser


def _output_paths(args):
    paths = [Path(value).resolve() for value in (args.json_path, args.markdown_path) if value]
    if len(paths) != len(set(paths)):
        raise PolicyError("Report outputs must be different files.")
    if args.command == "run" and Path(args.policy).resolve() in paths:
        raise PolicyError("Report output cannot overwrite the input policy.")


def _write(path, text):
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=destination.parent,
                                         prefix=".authz-report-", delete=False) as output:
            temporary = output.name
            output.write(text)
        os.replace(temporary, destination)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def main(argv=None):
    # Pipes use locale-dependent defaults on Windows. Reports use one explicit
    # encoding/newline contract whether written to a file or standard output.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="strict", newline="\n")
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate":
            load_policy(args.policy)
            print("Valid policy. No network requests sent.")
            return 0
        if args.command == "serve":
            if not 1 <= args.port <= 65535:
                raise PolicyError("Port must be between 1 and 65535.")
            with demo_server(bugs=BUGS if args.mode == "buggy" else (), environ=os.environ, port=args.port) as fixture:
                print(f"Synthetic {args.mode} API listening at {fixture.url}. Press Ctrl-C to stop.", flush=True)
                threading.Event().wait()
            return 0
        _output_paths(args)
        if args.command == "demo":
            with demo_server(bugs=BUGS if args.mode == "buggy" else ()) as fixture:
                report = run_policy(sample_policy(args.adapter, fixture.url), environ=fixture.environ)
        else:
            policy = load_policy(args.policy)
            if args.base_url:
                policy["base_url"] = args.base_url
            report = run_policy(policy, allow_origins=args.allow_origin)
        markdown = render_markdown(report)
        if args.json_path:
            _write(args.json_path, json.dumps(report, indent=2, sort_keys=True) + "\n")
        if args.markdown_path:
            _write(args.markdown_path, markdown)
        print(markdown, end="")
        return 0 if report["passed"] else 1
    except PolicyError as error:
        print(f"Policy error: {error}", file=sys.stderr)
        return 2
    except OSError:
        print("I/O error: unable to bind the demo or write a report.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
