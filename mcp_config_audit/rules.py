# Rules that flag risky settings in MCP server definitions.

import os
import re
from urllib.parse import urlparse

from .config import command_and_args, server_url
from .findings import Finding

# Commands that only exist to wrap a shell string, so their arguments run as code.
SHELL_COMMANDS = {"bash", "sh", "dash", "zsh", "ksh", "ash"}
SHELL_FLAGS = {"-c", "-lc", "-ic", "-cl"}
POWERSHELL_COMMANDS = {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}
POWERSHELL_FLAGS = {"-c", "-command", "-encodedcommand", "-enc"}
CMD_COMMANDS = {"cmd", "cmd.exe"}

# Package runners that fetch code at start time, which makes pinning matter.
RUNNER_COMMANDS = {"npx", "bunx", "pnpx", "uvx", "pipx", "deno"}
RUNNER_SKIP_FLAGS = {"-y", "--yes", "-q", "--quiet", "-p", "--package", "--from", "run", "dlx", "exec", "-s", "--silent"}

# Environment variable names that normally hold a credential.
SECRET_KEY_PATTERN = re.compile(r"(token|secret|api[_-]?key|password|passwd|credential|private[_-]?key|access[_-]?key)", re.I)

# Values that point at a secret store instead of holding the secret itself.
REFERENCE_PATTERN = re.compile(r"^(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|env:|op://|vault:|secret:|keyring:|<[^>]+>|\{\{[^}]*\}\}|changeme|your[_-]?[a-z]*[_-]?(key|token|secret))$", re.I)

# Environment variables that change how a runtime loads or executes code.
CODE_INJECTION_ENV = {"LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "NODE_OPTIONS", "PYTHONSTARTUP", "BASH_ENV", "RUBYOPT", "PERL5OPT"}
PATH_OVERRIDE_ENV = {"PATH", "PYTHONPATH", "NODE_PATH", "CLASSPATH"}

# Container flags that hand a server more of the host than it needs.
DOCKER_ESCAPES = {
    "--privileged": "runs the container with full host privileges",
    "--pid=host": "shares the host process namespace",
    "--net=host": "shares the host network namespace",
    "--network=host": "shares the host network namespace",
    "--cap-add=SYS_ADMIN": "adds SYS_ADMIN, which is close to root on the host",
    "--cap-add=all": "adds every capability",
    "--security-opt=seccomp=unconfined": "disables the seccomp filter",
    "--security-opt=apparmor=unconfined": "disables the AppArmor profile",
}
DOCKER_SOCKET = "/var/run/docker.sock"

# Filesystem paths that place the server above any single project.
WIDE_ROOTS = {"/": "high", "~": "high", "$HOME": "high", "/home": "medium", "/Users": "medium"}
ROOT_FLAGS = {"--root", "--roots", "--directory", "--dir", "--path", "--workspace", "-w", "--folder"}

# Approval list entries that remove the human from the loop on destructive calls.
APPROVAL_KEYS = ("autoApprove", "auto_approve", "allowedTools", "allowed_tools", "alwaysAllow", "always_allow", "trustedTools", "permissions")
DESTRUCTIVE_PATTERN = re.compile(r"(^|[_\-.])(write|delete|remove|exec|execute|run|shell|bash|cmd|rm|drop|kill|deploy|admin|sudo)", re.I)


def _basename(command):
    return os.path.basename(str(command or "").strip().strip('"'))


def rule_shell_wrapper(server, spec, _context):
    findings = []
    command, args = command_and_args(spec)
    base = _basename(command)
    lowered = [a.lower() for a in args]
    if base in SHELL_COMMANDS and any(a in SHELL_FLAGS for a in lowered):
        findings.append(Finding("shell-wrapper", "high", server, "server runs an inline shell command, so the config itself carries executable code", " ".join([command] + args[:4])))
    elif base in POWERSHELL_COMMANDS and any(a in POWERSHELL_FLAGS for a in lowered):
        findings.append(Finding("shell-wrapper", "high", server, "server runs an inline PowerShell command", " ".join([command] + args[:4])))
    elif base in CMD_COMMANDS and any(a == "/c" for a in lowered):
        findings.append(Finding("shell-wrapper", "high", server, "server runs an inline cmd.exe command", " ".join([command] + args[:4])))
    joined = " ".join(args)
    if re.search(r"\|\s*(ba|z|k)?sh\b", joined):
        findings.append(Finding("pipe-to-shell", "high", server, "arguments pipe a download straight into a shell", joined[:120]))
    return findings


def rule_inline_secret(server, spec, _context):
    findings = []
    env = spec.get("env")
    if isinstance(env, dict):
        for key, value in env.items():
            if not isinstance(value, str) or not value.strip():
                continue
            if not SECRET_KEY_PATTERN.search(str(key)):
                continue
            if REFERENCE_PATTERN.match(value.strip()):
                continue
            findings.append(Finding("inline-secret", "high", server, "environment variable %s holds a literal credential in the config file" % key, "%s=<%d chars>" % (key, len(value.strip()))))
    headers = spec.get("headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            if isinstance(value, str) and SECRET_KEY_PATTERN.search(str(key)) and not REFERENCE_PATTERN.match(value.strip()):
                findings.append(Finding("inline-secret", "high", server, "header %s holds a literal credential in the config file" % key, "%s=<%d chars>" % (key, len(value.strip()))))
    return findings


def rule_insecure_remote(server, spec, _context):
    findings = []
    url = server_url(spec)
    if not url:
        return findings
    parsed = urlparse(url)
    if parsed.scheme == "http":
        host = (parsed.hostname or "").lower()
        local = host in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or host.endswith(".local")
        if local:
            findings.append(Finding("plaintext-transport", "low", server, "local server is reached over http", url))
        else:
            findings.append(Finding("plaintext-transport", "high", server, "remote server is reached over http, so traffic and any bearer token are readable in transit", url))
    return findings


def _has_npm_version(package):
    # Scoped names start with @, so the version separator is the next one.
    body = package[1:] if package.startswith("@") else package
    return "@" in body


def rule_unpinned_package(server, spec, _context):
    findings = []
    command, args = command_and_args(spec)
    base = _basename(command)
    if base not in RUNNER_COMMANDS:
        return findings
    package = ""
    for arg in args:
        if arg in RUNNER_SKIP_FLAGS or arg.startswith("-"):
            continue
        package = arg
        break
    if not package:
        return findings
    if base in ("uvx", "pipx", "deno"):
        pinned = "==" in package or "@" in package
    else:
        pinned = _has_npm_version(package)
    if not pinned:
        findings.append(Finding("unpinned-package", "medium", server, "server runs %s without a pinned version, so the code it executes can change between runs" % package, "%s %s" % (command, package)))
    return findings


def rule_destructive_approval(server, spec, _context):
    findings = []
    for key in APPROVAL_KEYS:
        value = spec.get(key)
        if value is None:
            continue
        raw = value if isinstance(value, list) else [value]
        entries = [str(e) for e in raw]
        if any(e.strip() == "*" for e in entries):
            findings.append(Finding("wildcard-approval", "high", server, "%s accepts every tool call without asking, including destructive ones" % key, "%s: *" % key))
        for entry in entries:
            if entry.strip() != "*" and DESTRUCTIVE_PATTERN.search(entry):
                findings.append(Finding("destructive-approval", "medium", server, "%s pre-approves the destructive tool %s" % (key, entry), "%s: %s" % (key, entry)))
    return findings


def rule_risky_env(server, spec, _context):
    findings = []
    env = spec.get("env")
    if not isinstance(env, dict):
        return findings
    for key, value in env.items():
        name = str(key)
        if not isinstance(value, str) or not value.strip():
            continue
        if name in CODE_INJECTION_ENV:
            findings.append(Finding("code-injection-env", "high", server, "%s changes how the runtime loads or executes code" % name, "%s=<%d chars>" % (name, len(value.strip()))))
        elif name in PATH_OVERRIDE_ENV:
            findings.append(Finding("path-override-env", "medium", server, "%s overrides where the server looks for executables or modules" % name, "%s=<%d chars>" % (name, len(value.strip()))))
    return findings


def rule_container_escape(server, spec, _context):
    findings = []
    command, args = command_and_args(spec)
    if _basename(command) not in ("docker", "podman"):
        return findings
    for flag, reason in DOCKER_ESCAPES.items():
        if any(arg == flag or arg.startswith(flag + "=") for arg in args):
            findings.append(Finding("container-escape", "high", server, "container flag %s %s" % (flag, reason), flag))
    index = 0
    while index < len(args):
        arg = args[index]
        # A -v flag and its value are one item, so consume both together.
        if arg in ("-v", "--volume") and index + 1 < len(args):
            value = args[index + 1]
            if DOCKER_SOCKET in value:
                findings.append(Finding("docker-socket", "high", server, "container mount of the docker socket gives the server control of the host daemon", value))
            index += 2
            continue
        if DOCKER_SOCKET in arg:
            findings.append(Finding("docker-socket", "high", server, "container mount of the docker socket gives the server control of the host daemon", arg))
        index += 1
    return findings


def rule_wide_filesystem_root(server, spec, _context):
    findings = []
    _command, args = command_and_args(spec)
    candidates = []
    for index, arg in enumerate(args):
        if arg in ROOT_FLAGS and index + 1 < len(args):
            candidates.append((arg, args[index + 1]))
        elif arg.startswith("--") and "=" in arg and arg.split("=", 1)[0] in ROOT_FLAGS:
            candidates.append((arg.split("=", 1)[0], arg.split("=", 1)[1]))
        elif arg in ("-v", "--volume") and index + 1 < len(args):
            candidates.append(("-v", args[index + 1]))
    for flag, value in candidates:
        mount = value.split(":")[0] if flag == "-v" else value
        severity = WIDE_ROOTS.get(mount)
        if severity:
            findings.append(Finding("wide-filesystem-root", severity, server, "server is granted %s, which reaches well beyond one project" % mount, "%s %s" % (flag, value)))
    return findings


# Every rule in the order they are reported within one server.
RULES = (
    rule_shell_wrapper,
    rule_inline_secret,
    rule_insecure_remote,
    rule_risky_env,
    rule_destructive_approval,
    rule_container_escape,
    rule_wide_filesystem_root,
    rule_unpinned_package,
)


def audit_servers(servers, context=None):
    # Run every rule over every server and return the findings, worst first.
    context = context or {}
    findings = []
    for name in sorted(servers):
        spec = servers[name]
        if not isinstance(spec, dict):
            continue
        for rule in RULES:
            findings.extend(rule(name, spec, context))
    return findings
