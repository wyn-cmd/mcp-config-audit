# Tests for config loading and shape detection.

import json
import os
import tempfile
import unittest

from mcp_config_audit.config import command_and_args, extract_servers, load_config, server_url


class ConfigShapeTests(unittest.TestCase):
    def _create_temp_config(self, content, is_json=True):
        # Helper to create a temporary file and ensure it gets cleaned up after the test.
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        if is_json:
            json.dump(content, handle)
        else:
            handle.write(content)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

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
        path = self._create_temp_config("{not json", is_json=False)
        with self.assertRaises(ValueError) as caught:
            load_config(path)
        self.assertIn("invalid JSON", str(caught.exception))

    def test_load_config_round_trip(self):
        data = {"mcpServers": {}}
        path = self._create_temp_config(data)
        self.assertEqual(load_config(path), data)


if __name__ == "__main__":
    unittest.main()