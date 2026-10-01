# Tests for config loading and shape detection.

import json
import os
import tempfile
import unittest

from mcp_config_audit.config import command_and_args, extract_servers, load_config, server_url


class ConfigShapeTests(unittest.TestCase):
    def test_claude_desktop_shape(self):
        document = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "server-fs@1.0.0"]}}}
        servers = extract_servers(document)
        self.assertEqual(list(servers), ["fs"])

    def test_vscode_shape(self):
        document = {"servers": {"remote": {"url": "https://example.com/mcp"}}}
        self.assertIn("remote", extract_servers(document))

    def test_nested_shape(self):
        document = {"mcp": {"servers": {"db": {"command": "uvx", "args": ["db-server==2.1"]}}}}
        self.assertIn("db", extract_servers(document))

    def test_entries_without_command_or_url_are_ignored(self):
        document = {"note": "hello", "inputs": [1, 2, 3]}
        self.assertEqual(extract_servers(document), {})

    def test_command_line_folded_into_command_field(self):
        spec = {"command": "npx -y some-server@1.2.3"}
        command, args = command_and_args(spec)
        self.assertEqual(command, "npx")
        self.assertEqual(args, ["-y", "some-server@1.2.3"])

    def test_args_as_string(self):
        spec = {"command": "node", "args": "--port 8080"}
        self.assertEqual(command_and_args(spec), ("node", ["--port", "8080"]))

    def test_url_key_variants(self):
        self.assertEqual(server_url({"serverUrl": "https://a.example/mcp"}), "https://a.example/mcp")
        self.assertEqual(server_url({"command": "npx"}), "")

    def test_load_config_reports_bad_json(self):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        handle.write("{not json")
        handle.close()
        try:
            with self.assertRaises(ValueError) as caught:
                load_config(handle.name)
            self.assertIn("invalid JSON", str(caught.exception))
        finally:
            os.unlink(handle.name)

    def test_load_config_round_trip(self):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"mcpServers": {}}, handle)
        handle.close()
        try:
            self.assertEqual(load_config(handle.name), {"mcpServers": {}})
        finally:
            os.unlink(handle.name)


if __name__ == "__main__":
    unittest.main()
