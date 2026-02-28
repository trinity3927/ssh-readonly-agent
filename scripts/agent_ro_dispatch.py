#!/usr/bin/env python3
"""Restricted SSH dispatcher for the agent_ro user."""

import json
import os
import select
import shlex
import shutil
import subprocess
import sys
import syslog
import time
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

POLICY_PATH = os.environ.get("AGENT_RO_POLICY_FILE", "/etc/agent-ro/policy.json")
DEFAULT_ALLOWED_COMMANDS = ["find", "rg", "cat", "ls", "stat", "git", "grep"]
DEFAULT_MAX_CMD_SECONDS = 20
DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024
ALLOWED_GIT_SUBCOMMANDS = {"log", "show"}
BAD_FIND_TOKENS = {
    "-delete",
    "-exec",
    "-execdir",
    "-ok",
    "-okdir",
    "-files0-from",
    "-fprint",
    "-fprint0",
    "-fprintf",
    "-fls",
}
RG_LONG_WITH_VALUE = {
    "--after-context",
    "--before-context",
    "--color",
    "--colors",
    "--context",
    "--crlf",
    "--dfa-size-limit",
    "--encoding",
    "--engine",
    "--file",
    "--glob",
    "--glob-case-insensitive",
    "--iglob",
    "--ignore-file",
    "--max-columns",
    "--max-columns-preview",
    "--max-count",
    "--max-depth",
    "--max-filesize",
    "--mmap",
    "--path-separator",
    "--pre",
    "--pre-glob",
    "--regex-size-limit",
    "--regexp",
    "--replace",
    "--sort",
    "--sortr",
    "--threads",
    "--trim",
    "--type",
    "--type-add",
    "--type-clear",
    "--type-not",
}
RG_SHORT_WITH_VALUE = {"-A", "-B", "-C", "-e", "-f", "-g", "-j", "-M", "-m", "-t", "-T"}
GREP_LONG_WITH_VALUE = {
    "--binary-files",
    "--color",
    "--colour",
    "--context",
    "--directories",
    "--exclude",
    "--exclude-dir",
    "--exclude-from",
    "--file",
    "--include",
    "--label",
    "--line-buffered",
    "--max-count",
    "--null-data",
    "--regexp",
}
GREP_SHORT_WITH_VALUE = {"-A", "-B", "-C", "-e", "-f", "-m"}


class PolicyError(Exception):
    pass


def deny(message: str, cmdline: str = "", exit_code: int = 126) -> None:
    audit("deny", message, cmdline=cmdline, level=syslog.LOG_WARNING)
    print(f"DENY: {message}", file=sys.stderr)
    sys.exit(exit_code)


def is_truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() not in {"0", "false", "no", "off", ""}


def canonicalize_root(path: str) -> str:
    if not path:
        raise PolicyError("empty allowed root")
    expanded = os.path.expanduser(path)
    if not os.path.isabs(expanded):
        raise PolicyError(f"allowed root must be absolute: {path}")
    return os.path.realpath(expanded)


def load_policy() -> Dict[str, object]:
    data: Dict[str, object] = {}
    try:
        with open(POLICY_PATH, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
        if isinstance(raw, dict):
            data = raw
    except FileNotFoundError:
        raise PolicyError(f"missing policy file: {POLICY_PATH}")
    except (json.JSONDecodeError, OSError) as exc:
        raise PolicyError(f"unable to read policy: {exc}")

    commands = data.get("allowed_commands", DEFAULT_ALLOWED_COMMANDS)
    if not isinstance(commands, list):
        raise PolicyError("allowed_commands must be a list")
    allowed_commands = [str(c) for c in commands if str(c)]
    if not allowed_commands:
        raise PolicyError("allowed_commands cannot be empty")

    roots_raw = data.get("allowed_roots")
    if not isinstance(roots_raw, list) or not roots_raw:
        raise PolicyError("allowed_roots must be a non-empty list")
    roots: List[str] = []
    seen = set()
    for root in roots_raw:
        canonical = canonicalize_root(str(root))
        if canonical not in seen:
            seen.add(canonical)
            roots.append(canonical)

    max_seconds_raw = data.get("max_cmd_seconds", DEFAULT_MAX_CMD_SECONDS)
    max_bytes_raw = data.get("max_output_bytes", DEFAULT_MAX_OUTPUT_BYTES)
    try:
        max_seconds = int(max_seconds_raw)
        max_bytes = int(max_bytes_raw)
    except (TypeError, ValueError):
        raise PolicyError("max_cmd_seconds and max_output_bytes must be integers")
    if max_seconds <= 0 or max_bytes <= 0:
        raise PolicyError("max_cmd_seconds and max_output_bytes must be > 0")

    return {
        "allowed_commands": allowed_commands,
        "allowed_roots": roots,
        "max_cmd_seconds": max_seconds,
        "max_output_bytes": max_bytes,
        "logging": is_truthy(data.get("logging", True)),
    }


POLICY: Dict[str, object] = {}


def peer_identity() -> str:
    ssh_conn = os.environ.get("SSH_CONNECTION", "").strip()
    if not ssh_conn:
        return "unknown-peer"
    parts = ssh_conn.split()
    if len(parts) >= 2:
        return f"{parts[0]}:{parts[1]}"
    return ssh_conn


def audit(event: str, message: str, *, cmdline: str = "", level: int = syslog.LOG_INFO) -> None:
    if POLICY and not bool(POLICY.get("logging", True)):
        return
    user = os.environ.get("USER", "unknown-user")
    peer = peer_identity()
    safe_cmd = cmdline.replace("\n", " ").strip()
    safe_msg = message.replace("\n", " ").strip()
    entry = f"agent_ro_dispatch event={event} user={user} peer={peer} msg={safe_msg}"
    if safe_cmd:
        entry += f" cmd={safe_cmd}"
    syslog.syslog(syslog.LOG_AUTHPRIV | level, entry)


def resolve_user_path(path_token: str) -> str:
    if path_token == "-":
        raise PolicyError("stdin token '-' is not allowed")
    expanded = os.path.expanduser(path_token)
    absolute = expanded if os.path.isabs(expanded) else os.path.abspath(expanded)
    return os.path.realpath(absolute)


def path_allowed(path_token: str, allowed_roots: Sequence[str]) -> bool:
    resolved = resolve_user_path(path_token)
    for root in allowed_roots:
        try:
            if os.path.commonpath([resolved, root]) == root:
                return True
        except ValueError:
            continue
    return False


def validate_paths(paths: Iterable[str], allowed_roots: Sequence[str], kind: str) -> None:
    path_list = list(paths)
    if not path_list:
        raise PolicyError(f"{kind} requires at least one path argument")
    for token in path_list:
        if not path_allowed(token, allowed_roots):
            raise PolicyError(f"path outside allowed roots: {token}")


def parse_find_args(args: Sequence[str], allowed_roots: Sequence[str]) -> None:
    paths: List[str] = []
    expression_started = False
    for token in args:
        if token in BAD_FIND_TOKENS or token.startswith("-files0-from="):
            raise PolicyError(f"find option not allowed: {token}")
        if not expression_started and not token.startswith("-") and token not in {"!", "(", ")", ","}:
            paths.append(token)
            continue
        expression_started = True
    validate_paths(paths, allowed_roots, "find")


def parse_cat_args(args: Sequence[str], allowed_roots: Sequence[str]) -> None:
    paths: List[str] = []
    parse_opts = True
    for token in args:
        if parse_opts and token == "--":
            parse_opts = False
            continue
        if parse_opts and token.startswith("-"):
            continue
        parse_opts = False
        paths.append(token)
    validate_paths(paths, allowed_roots, "cat")


def parse_ls_args(args: Sequence[str], allowed_roots: Sequence[str]) -> List[str]:
    paths: List[str] = []
    parse_opts = True
    normalized_args = list(args)
    for token in args:
        if parse_opts and token == "--":
            parse_opts = False
            continue
        if parse_opts and token.startswith("-"):
            continue
        paths.append(token)
    if not paths:
        if not allowed_roots:
            raise PolicyError("ls requires at least one allowed root")
        default_target = allowed_roots[0]
        normalized_args.append(default_target)
        paths = [default_target]
    validate_paths(paths, allowed_roots, "ls")
    return normalized_args


def parse_stat_args(args: Sequence[str], allowed_roots: Sequence[str]) -> None:
    paths: List[str] = []
    parse_opts = True
    consume_next = False
    for token in args:
        if consume_next:
            consume_next = False
            continue
        if parse_opts and token == "--":
            parse_opts = False
            continue
        if parse_opts and token in {"-c", "--format", "--printf"}:
            consume_next = True
            continue
        if parse_opts and (token.startswith("--format=") or token.startswith("--printf=")):
            continue
        if parse_opts and token.startswith("-"):
            continue
        paths.append(token)
    validate_paths(paths, allowed_roots, "stat")


def parse_search_args(
    args: Sequence[str],
    *,
    command: str,
    allowed_roots: Sequence[str],
    long_with_value: Sequence[str],
    short_with_value: Sequence[str],
) -> None:
    positionals: List[str] = []
    has_recursive = False
    has_explicit_pattern = False
    option_paths: List[str] = []
    long_with_value_set = set(long_with_value)
    short_with_value_set = set(short_with_value)
    long_path_options = {
        "rg": {"--file", "--ignore-file"},
        "grep": {"--file", "--exclude-from"},
    }.get(command, set())
    forbidden_long_options = {"--pre", "--pre-glob"} if command == "rg" else set()
    i = 0
    while i < len(args):
        token = args[i]
        if token == "--":
            positionals.extend(args[i + 1 :])
            break
        if token.startswith("--"):
            option_name, has_inline = token.split("=", 1)[0], "=" in token
            inline_value = token.split("=", 1)[1] if has_inline else ""
            if option_name in forbidden_long_options:
                raise PolicyError(f"{command} option not allowed: {option_name}")
            if option_name in {"--regexp", "--file"}:
                has_explicit_pattern = True
            if command == "grep":
                if token in {"--recursive", "--dereference-recursive"}:
                    has_recursive = True
                elif token.startswith("--directories="):
                    directory_mode = token.split("=", 1)[1].strip().lower()
                    if directory_mode == "recurse":
                        has_recursive = True
                elif token == "--directories" and i + 1 < len(args):
                    directory_mode = args[i + 1].strip().lower()
                    if directory_mode == "recurse":
                        has_recursive = True
            if option_name in long_with_value_set:
                if has_inline:
                    option_value = inline_value
                else:
                    if i + 1 >= len(args):
                        raise PolicyError(f"{command} option missing value: {option_name}")
                    option_value = args[i + 1]
                    i += 1
                if option_name in long_path_options:
                    option_paths.append(option_value)
                i += 1
                continue
            i += 1
            continue
        if token.startswith("-") and token != "-":
            if command == "grep":
                if "r" in token[1:] or "R" in token[1:]:
                    has_recursive = True
                if "e" in token[1:] or "f" in token[1:]:
                    has_explicit_pattern = True
            if command == "rg" and ("e" in token[1:] or "f" in token[1:]):
                has_explicit_pattern = True
            short_flags = token[1:]
            j = 0
            while j < len(short_flags):
                short_opt = "-" + short_flags[j]
                if short_opt in short_with_value_set:
                    if j + 1 < len(short_flags):
                        option_value = short_flags[j + 1 :]
                    else:
                        if i + 1 >= len(args):
                            raise PolicyError(f"{command} option missing value: {short_opt}")
                        option_value = args[i + 1]
                        i += 1
                    if short_opt == "-f":
                        option_paths.append(option_value)
                    break
                j += 1
            i += 1
            continue
        positionals.append(token)
        i += 1

    if command == "grep" and not has_recursive:
        raise PolicyError("grep allowed only with recursive options (-R/-r/--recursive)")

    if has_explicit_pattern:
        paths = positionals
    else:
        if len(positionals) < 2:
            raise PolicyError(f"{command} requires PATTERN and at least one PATH")
        paths = positionals[1:]
    validate_paths(paths, allowed_roots, command)
    if option_paths:
        validate_paths(option_paths, allowed_roots, f"{command} option")


def parse_git_args(args: List[str], allowed_roots: Sequence[str]) -> None:
    i = 0
    c_paths: List[str] = []
    while i < len(args):
        token = args[i]
        if token == "-C":
            if i + 1 >= len(args):
                raise PolicyError("git option missing value: -C")
            c_paths.append(args[i + 1])
            i += 2
            continue
        if token.startswith("-"):
            raise PolicyError(f"git option not allowed: {token}")
        break

    if i >= len(args):
        raise PolicyError("git subcommand required")

    subcommand = args[i]
    if subcommand not in ALLOWED_GIT_SUBCOMMANDS:
        raise PolicyError("only 'git log' and 'git show' are allowed")
    if not c_paths:
        raise PolicyError("git requires -C <repo-path> inside allowed roots")
    validate_paths(c_paths, allowed_roots, "git -C")

    for token in args[i + 1 :]:
        if token in {"--ext-diff", "--exec-path", "--output"} or token.startswith("--output="):
            raise PolicyError(f"git option not allowed: {token}")

    args.insert(i, "--no-pager")


def validate_command(argv: List[str], allowed_roots: Sequence[str]) -> None:
    command = argv[0]
    args = argv[1:]
    if command == "find":
        parse_find_args(args, allowed_roots)
    elif command == "cat":
        parse_cat_args(args, allowed_roots)
    elif command == "ls":
        argv[1:] = parse_ls_args(args, allowed_roots)
    elif command == "stat":
        parse_stat_args(args, allowed_roots)
    elif command == "rg":
        parse_search_args(
            args,
            command="rg",
            allowed_roots=allowed_roots,
            long_with_value=RG_LONG_WITH_VALUE,
            short_with_value=RG_SHORT_WITH_VALUE,
        )
    elif command == "grep":
        parse_search_args(
            args,
            command="grep",
            allowed_roots=allowed_roots,
            long_with_value=GREP_LONG_WITH_VALUE,
            short_with_value=GREP_SHORT_WITH_VALUE,
        )
    elif command == "git":
        parse_git_args(args, allowed_roots)


def stream_command(
    argv: List[str],
    executable: str,
    *,
    timeout_seconds: int,
    output_cap_bytes: int,
) -> int:
    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": os.environ.get("LANG", "C"),
        "LC_ALL": os.environ.get("LC_ALL", "C"),
        "LC_CTYPE": os.environ.get("LC_CTYPE", "C"),
        "TERM": os.environ.get("TERM", "dumb"),
    }
    if argv[0] == "git":
        env["GIT_PAGER"] = "cat"
        env["PAGER"] = "cat"
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_CONFIG_GLOBAL"] = "/dev/null"

    process = subprocess.Popen(
        [executable] + argv[1:],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    assert process.stdout is not None
    assert process.stderr is not None

    open_streams = [process.stdout, process.stderr]
    deadline = time.monotonic() + timeout_seconds
    emitted = 0

    while open_streams:
        now = time.monotonic()
        if now >= deadline:
            process.kill()
            process.wait(timeout=2)
            deny(f"command timed out after {timeout_seconds}s")
        wait_for = min(0.5, max(0.05, deadline - now))
        readable, _, _ = select.select(open_streams, [], [], wait_for)
        for stream in readable:
            chunk = stream.read1(65536)
            if not chunk:
                open_streams.remove(stream)
                continue
            emitted += len(chunk)
            target = sys.stdout.buffer if stream is process.stdout else sys.stderr.buffer
            target.write(chunk)
            target.flush()
            if emitted > output_cap_bytes:
                process.kill()
                process.wait(timeout=2)
                deny(f"output exceeded policy limit ({output_cap_bytes} bytes)")

    return process.wait()


def main() -> None:
    global POLICY
    try:
        POLICY = load_policy()
    except PolicyError as exc:
        deny(str(exc))

    cmdline = os.environ.get("SSH_ORIGINAL_COMMAND", "").strip()
    if not cmdline:
        deny("interactive shell disabled; run a remote command")

    try:
        argv = shlex.split(cmdline, posix=True)
    except ValueError as exc:
        deny(f"parse error: {exc}", cmdline=cmdline)
    if not argv:
        deny("empty command", cmdline=cmdline)

    command = argv[0]
    allowed_commands = set(POLICY["allowed_commands"])
    if command not in allowed_commands:
        deny("command not allowed", cmdline=cmdline)

    binary = shutil.which(command)
    if not binary:
        if command == "rg":
            deny("rg not installed; use grep -R fallback", cmdline=cmdline)
        deny(f"{command} not available", cmdline=cmdline)

    try:
        validate_command(argv, POLICY["allowed_roots"])
    except PolicyError as exc:
        deny(str(exc), cmdline=cmdline)

    audit("allow", "command accepted by policy", cmdline=cmdline)
    rc = stream_command(
        argv,
        binary,
        timeout_seconds=int(POLICY["max_cmd_seconds"]),
        output_cap_bytes=int(POLICY["max_output_bytes"]),
    )
    if rc == 0:
        audit("complete", "command completed", cmdline=cmdline)
    else:
        audit("complete", f"command exited rc={rc}", cmdline=cmdline, level=syslog.LOG_NOTICE)
    sys.exit(rc)


if __name__ == "__main__":
    main()
