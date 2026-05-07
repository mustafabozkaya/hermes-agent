"""hermes credbroker — manage the credential broker subprocess.

Subcommands::

    hermes credbroker start              # spawn the broker (idempotent)
    hermes credbroker stop               # terminate the running broker
    hermes credbroker status             # is it running? how many creds?
    hermes credbroker set NAME [VALUE]   # write a credential
    hermes credbroker get NAME           # print a credential value
    hermes credbroker list               # list stored credential names
    hermes credbroker delete NAME        # remove a credential

Credentials live in an encrypted vault at
``<hermes_home>/credentials/vault.enc`` and are never readable by the
agent's terminal tool — the broker process owns the vault; clients speak
to it via a Unix socket.
"""

from __future__ import annotations

import getpass
import json
import sys

from hermes_constants import display_hermes_home
from tools import credbroker


def credbroker_command(args) -> None:
    sub = getattr(args, "credbroker_action", None)
    if not sub:
        print("Usage: hermes credbroker {start|stop|status|set|get|list|delete}")
        print("Run 'hermes credbroker --help' for details.")
        return

    if sub == "start":
        _cmd_start(args)
    elif sub == "stop":
        _cmd_stop(args)
    elif sub == "status":
        _cmd_status(args)
    elif sub == "set":
        _cmd_set(args)
    elif sub == "get":
        _cmd_get(args)
    elif sub in ("list", "ls"):
        _cmd_list(args)
    elif sub in ("delete", "rm", "remove"):
        _cmd_delete(args)
    else:
        print(f"Unknown credbroker subcommand: {sub}")


def _cmd_start(args) -> None:
    if credbroker.is_running():
        print(f"credbroker already running (pid={credbroker._read_pidfile()})")
        return
    try:
        pid = credbroker.start_detached()
    except RuntimeError as e:
        print(f"Failed to start credbroker: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"credbroker started (pid={pid}).")
    print(f"Socket:  {credbroker.socket_path()}")
    print(f"Vault:   {credbroker.vault_path()}")


def _cmd_stop(args) -> None:
    if not credbroker.is_running():
        print("credbroker is not running.")
        return
    stopped = credbroker.stop()
    if stopped:
        print("credbroker stopped.")
    else:
        print("credbroker was not reachable; cleaned up stale state.")


def _cmd_status(args) -> None:
    running = credbroker.is_running()
    pid = credbroker._read_pidfile()
    print(f"Status:   {'running' if running else 'stopped'}")
    if pid:
        print(f"PID:      {pid}")
    print(f"Socket:   {credbroker.socket_path()}")
    print(f"Vault:    {credbroker.vault_path()}")
    print(f"Key file: {credbroker.key_path()}")
    if running:
        names = credbroker.list_names()
        print(f"Creds:    {len(names)} stored")


def _cmd_set(args) -> None:
    name = args.name.strip()
    if not name:
        print("Error: name is required")
        return
    value = args.value
    if value is None:
        try:
            value = getpass.getpass(f"Value for {name!r} (will not echo): ")
        except (EOFError, KeyboardInterrupt):
            print()
            return
    if not credbroker.is_running():
        print("credbroker is not running — start it first with 'hermes credbroker start'.")
        sys.exit(2)
    try:
        credbroker.set_(name, value)
    except credbroker.CredbrokerError as e:
        print(f"Failed: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Stored {name!r}.")


def _cmd_get(args) -> None:
    if not credbroker.is_running():
        print("credbroker is not running.", file=sys.stderr)
        sys.exit(2)
    value = credbroker.get(args.name)
    if value is None:
        print(f"No credential named {args.name!r}.", file=sys.stderr)
        sys.exit(1)
    # Print without a trailing newline so it can be captured cleanly.
    sys.stdout.write(value)
    sys.stdout.flush()


def _cmd_list(args) -> None:
    if not credbroker.is_running():
        print("credbroker is not running.", file=sys.stderr)
        sys.exit(2)
    names = credbroker.list_names()
    if not names:
        print("No credentials stored.")
        return
    for name in names:
        print(name)


def _cmd_delete(args) -> None:
    if not credbroker.is_running():
        print("credbroker is not running.", file=sys.stderr)
        sys.exit(2)
    try:
        existed = credbroker.delete(args.name)
    except credbroker.CredbrokerError as e:
        print(f"Failed: {e}", file=sys.stderr)
        sys.exit(1)
    if existed:
        print(f"Removed {args.name!r}.")
    else:
        print(f"No credential named {args.name!r}.")
