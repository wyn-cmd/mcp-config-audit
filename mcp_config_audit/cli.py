# Command line interface for mcp-config-audit.

import argparse
import json
import os
import sys

from .config import extract_servers, load_config
from .findings import SEVERITY_ORDER, at_least, sort_findings
from .report import render_json, render_text
from .rules import audit_servers

KNOWN_NAMES = ("mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_servers.json", "servers.json")

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache", "dist", "build"}


def discover(paths):
    found = []
    for path in paths:
        if not os.path.isdir(path):
            found.append(path)
            continue
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in sorted(files):
                if name in KNOWN_NAMES or name.endswith(".mcp.json"):
                    found.append(os.path.join(root, name))
    return found


def audit_path(path):
    document = load_config(path)
    servers = extract_servers(document)
    return sort_findings(audit_servers(servers, {"path": path}))


def build_parser():
    parser = argparse.ArgumentParser(
        prog="mcp-config-audit",
        description="Audit MCP server configuration files for risky settings.",
    )
    parser.add_argument("paths", nargs="*", default=["."], help="config files or directories to scan")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    parser.add_argument("--min-severity", choices=sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get), default="low", help="lowest severity that still fails the run")
    parser.add_argument("--quiet", action="store_true", help="print nothing unless a finding reaches the threshold")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    targets = discover(args.paths)
    
    if not targets:
        print("no MCP config files found", file=sys.stderr)
        return 0

    exit_code = 0
    results = []
    
    for path in targets:
        try:
            findings = audit_path(path)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            exit_code = 2
            continue
            
        results.append((path, findings))
        if at_least(findings, args.min_severity):
            exit_code = 1

    if args.json:
        payload = [json.loads(render_json(findings, path)) for path, findings in results]
        print(json.dumps(payload, indent=2))
    elif not args.quiet:
        rendered = [render_text(findings, path) for path, findings in results]
        print("\n\n".join(rendered))
        
    return exit_code