# Reading MCP server configuration files into one normalised shape.

import json

# Clients disagree on the name of the server table, so try each in turn.
SERVER_TABLE_KEYS = ("mcpServers", "mcp_servers", "servers")


def load_config(path):
    # Read a JSON config from disk, raising ValueError with something readable.
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise ValueError("cannot read %s: %s" % (path, exc.strerror))
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "invalid JSON in %s at line %d column %d: %s"
            % (path, exc.lineno, exc.colno, exc.msg)
        )
    return document


def _table_to_servers(table):
    return {name: spec for name, spec in table.items() if isinstance(spec, dict)}


def extract_servers(document):
    # Return an ordered mapping of server name to server spec for any known shape.
    if not isinstance(document, dict):
        return {}
    for key in SERVER_TABLE_KEYS:
        table = document.get(key)
        if isinstance(table, dict):
            return _table_to_servers(table)
    # Some clients wrap the table one level deeper, for example under "mcp".
    for wrapper in ("mcp", "mcpServers"):
        nested = document.get(wrapper)
        if isinstance(nested, dict):
            for key in SERVER_TABLE_KEYS:
                table = nested.get(key)
                if isinstance(table, dict):
                    return _table_to_servers(table)
    # Last resort: treat every entry that carries a command or url as a server.
    servers = {}
    for name, spec in document.items():
        if isinstance(spec, dict) and ("command" in spec or "url" in spec):
            servers[name] = spec
    return servers


def command_and_args(spec):
    # Split a server spec into the executable and its argument list.
    command = spec.get("command")
    if not isinstance(command, str):
        return "", []
    raw_args = spec.get("args")
    if isinstance(raw_args, list):
        args = [str(item) for item in raw_args]
    elif isinstance(raw_args, str):
        args = raw_args.split()
    else:
        args = []
    parts = command.split()
    # Some configs put the whole command line in "command" and leave args empty.
    if not args and len(parts) > 1:
        return parts[0], parts[1:]
    return (parts[0] if parts else ""), args


def server_url(spec):
    for key in ("url", "serverUrl", "endpoint", "baseUrl"):
        value = spec.get(key)
        if isinstance(value, str) and value:
            return value
    return ""
