# mcp-config-audit

mcp-config-audit reads the JSON files that register MCP (Model Context Protocol) servers and reports the settings that hand an agent more power than the task needs. It is a static check with no dependencies beyond the Python standard library, so it runs anywhere Python 3.9 or newer is available and never executes the servers it inspects.

An MCP config file is a small piece of JSON that decides which processes an agent may start, which credentials those processes receive and which tool calls run without asking. Those decisions are easy to copy from a blog post and never revisit, so the file that grants a model shell access and a live API key usually looks exactly like any other config. This tool reads that file and prints the problems in plain language.

## Install and run

Run it straight from a checkout:

```
python3 -m mcp_config_audit path/to/mcp.json
```

Or install the console script:

```
pip install .
mcp-config-audit ~/.config/Claude/claude_desktop_config.json
```

Point it at a directory and it walks the tree looking for `mcp.json`, `.mcp.json`, `claude_desktop_config.json`, `mcp_servers.json`, `servers.json` and any `*.mcp.json` file, while skipping `node_modules`, virtual environments and build output.

```
mcp-config-audit ~/projects
```

## Exit codes

- `0` means nothing reached the severity threshold, which makes the default run a clean check.
- `1` means at least one finding reached the threshold.
- `2` means a file could not be read or did not contain valid JSON.

Combine `--min-severity high` with exit code `1` to fail a build only on the serious problems:

```
mcp-config-audit --min-severity high .
```

`--json` prints the same findings as structured data for a pipeline, and `--quiet` prints nothing at all unless a finding reaches the threshold.

## What it checks

A finding always names the server, explains the risk and quotes the evidence. Evidence never contains a secret value itself, only the name of the variable and its length.

High:

- `shell-wrapper`: the server starts `bash -c`, `sh -c`, `powershell -Command`, `pwsh -Command` or `cmd /c`, so the config file carries executable code rather than a program path.
- `pipe-to-shell`: arguments pipe a download into a shell, as in `curl ... | sh`.
- `inline-secret`: an environment variable or header whose name looks like a credential holds a literal value instead of a `${VAR}` reference.
- `plaintext-transport`: a remote server is reached over `http`, so the traffic and any bearer token are readable in transit. Plain `http` to loopback is reported as low instead.
- `code-injection-env`: the environment sets `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `NODE_OPTIONS`, `PYTHONSTARTUP`, `BASH_ENV`, `RUBYOPT` or `PERL5OPT`, each of which changes how a runtime loads code. Setting `PYTHONPATH`, `NODE_PATH`, `PATH` or `CLASSPATH` is reported as medium.
- `wildcard-approval`: an approval list such as `autoApprove` or `allowedTools` contains `*`, which means every tool call runs without a human in the loop.
- `container-escape`: a `docker` or `podman` command adds `--privileged`, `--pid=host`, `--net=host`, `--cap-add=SYS_ADMIN`, `--cap-add=all`, or disables seccomp or AppArmor.
- `docker-socket`: a container mounts `/var/run/docker.sock`, which gives the server control of the host daemon.

Medium:

- `destructive-approval`: an approval list pre-approves a tool whose name matches write, delete, remove, exec, run, shell, bash, cmd, rm, drop, kill, deploy, admin or sudo.
- `unpinned-package`: an `npx`, `bunx`, `pnpx`, `uvx`, `pipx` or `deno` server runs a package with no version, so the code it executes can change between runs.
- `wide-filesystem-root`: a server is granted `/`, `~`, `$HOME`, `/home` or `/Users`, which reaches well beyond one project.

Low:

- `plaintext-transport` on a loopback address.

## Example

`examples/risky.mcp.json` in this repository contains one of each problem. Running the tool against it prints:

```
[HIGH] wildcard-approval: filesystem
    autoApprove accepts every tool call without asking, including destructive ones
    evidence: autoApprove: *
[HIGH] inline-secret: github
    environment variable GITHUB_TOKEN holds a literal credential in the config file
    evidence: GITHUB_TOKEN=<23 chars>
[HIGH] plaintext-transport: remote-tools
    remote server is reached over http, so traffic and any bearer token are readable in transit
    evidence: http://mcp.example.com/sse
[HIGH] container-escape: sandbox
    container flag --privileged runs the container with full host privileges
    evidence: --privileged
[HIGH] docker-socket: sandbox
    container mount of the docker socket gives the server control of the host daemon
    evidence: /var/run/docker.sock:/var/run/docker.sock
[HIGH] pipe-to-shell: shell-helper
    arguments pipe a download straight into a shell
    evidence: -lc curl -sL https://mcp.example.com/install.sh | sh
[HIGH] shell-wrapper: shell-helper
    server runs an inline shell command, so the config itself carries executable code
    evidence: /bin/bash -lc curl -sL https://mcp.example.com/install.sh | sh
[MEDIUM] destructive-approval: database
    allowedTools pre-approves the destructive tool drop_table
    evidence: allowedTools: drop_table
[MEDIUM] unpinned-package: github
    server runs github-mcp-server without a pinned version, so the code it executes can change between runs
    evidence: npx github-mcp-server

9 finding(s): 7 high, 2 medium, 0 low
```

The same rules report nothing for `examples/clean.mcp.json`, which pins its packages, keeps its secrets as `${VAR}` references, scopes the filesystem server to one project and reaches its remote server over `https`.

## Tests

```
python3 -m unittest discover -s tests -t .
```

The suite covers each rule with a config that should trigger it and a config that should not, plus the file shapes used by Claude Desktop, VS Code and clients that nest the server table one level deeper.

## Layout

- `mcp_config_audit/config.py` loads JSON and normalises the server table into one shape.
- `mcp_config_audit/rules.py` holds the checks.
- `mcp_config_audit/findings.py` defines the result type and severity ordering.
- `mcp_config_audit/report.py` renders text and JSON.
- `mcp_config_audit/cli.py` is the command line entry point.

## Limits

The tool reads configuration only. It does not start servers, contact remote endpoints or follow package metadata, so an unpinned package is flagged whether or not the registry currently serves a safe version, and a server that passes every rule can still be badly written. It is a fast first pass over a file that people rarely read twice, not a guarantee about the code behind it.

## License

MIT, see `LICENSE`.
