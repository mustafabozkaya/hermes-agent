"""Credential broker subprocess — owns the credential store so the agent
cannot read it via terminal.

**What this is:** the bootstrap of credential isolation.  A standalone
process holds a vault at ``~/.hermes/credentials/vault.enc`` protected by
a per-install key at ``~/.hermes/credentials/broker.key``.  Other parts
of Hermes request credentials via a Unix domain socket (line-JSON
protocol) rather than reading env vars / files the agent can see.

**What this is NOT (yet):** a full Vellum-CES equivalent.  The deeper
integration work — having every provider adapter fetch tokens from the
broker on demand, sandbox-level mount exclusions, egress proxy, manifest-
driven secure commands — is deferred.  What ships here is the subprocess
+ IPC + vault format, plus the CLI to manage it.  This is defense in
depth on top of an already-reasonable threat model, not a complete
reimagining of the credential story.

Protocol (newline-delimited JSON over a Unix socket)::

    ->  {"op": "get", "name": "OPENAI_API_KEY"}
    <-  {"ok": true, "value": "sk-..."}

    ->  {"op": "list"}
    <-  {"ok": true, "names": ["OPENAI_API_KEY", "..."]}

    ->  {"op": "set", "name": "FOO", "value": "bar"}
    <-  {"ok": true}

    ->  {"op": "delete", "name": "FOO"}
    <-  {"ok": true}

All errors:  ``{"ok": false, "error": "reason"}``.

The socket path is fixed at ``<hermes_home>/credbroker.sock`` so clients
don't need configuration.  Peer authentication relies on filesystem
permissions: the socket is ``0600`` and lives inside the user's
``~/.hermes/`` tree.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import signal
import socket
import socketserver
import stat
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


SOCKET_NAME = "credbroker.sock"
VAULT_DIRNAME = "credentials"
VAULT_FILENAME = "vault.enc"
KEY_FILENAME = "broker.key"
PIDFILE_NAME = "credbroker.pid"


def _get_home() -> Path:
    from hermes_constants import get_hermes_home
    return get_hermes_home()


def socket_path() -> Path:
    return _get_home() / SOCKET_NAME


def vault_dir() -> Path:
    return _get_home() / VAULT_DIRNAME


def vault_path() -> Path:
    return vault_dir() / VAULT_FILENAME


def key_path() -> Path:
    return vault_dir() / KEY_FILENAME


def pidfile_path() -> Path:
    return _get_home() / PIDFILE_NAME


# ---------------------------------------------------------------------------
# Encryption — Fernet if available, plaintext+warning otherwise.
# ---------------------------------------------------------------------------


def _load_or_create_key() -> bytes:
    """Read the broker key, creating one if missing.

    Key file is 0600 so only the owner can read it.  Without ``cryptography``
    installed, a random 32-byte key is still generated — we just can't use
    Fernet, so the vault is stored as plaintext JSON with file-level
    permissions as the only protection.  A warning is logged so this
    doesn't go unnoticed.
    """
    vault_dir().mkdir(parents=True, exist_ok=True)
    kp = key_path()
    if kp.exists():
        return kp.read_bytes()
    try:
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
    except ImportError:
        logger.warning(
            "credbroker: 'cryptography' not installed — vault will be stored as "
            "plaintext JSON with 0600 perms.  Install cryptography for at-rest "
            "encryption."
        )
        key = secrets.token_urlsafe(32).encode("utf-8")
    kp.write_bytes(key)
    os.chmod(kp, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    return key


def _encrypt(key: bytes, payload: bytes) -> bytes:
    try:
        from cryptography.fernet import Fernet
        return Fernet(key).encrypt(payload)
    except ImportError:
        return payload


def _decrypt(key: bytes, blob: bytes) -> bytes:
    try:
        from cryptography.fernet import Fernet, InvalidToken
        try:
            return Fernet(key).decrypt(blob)
        except InvalidToken as e:
            raise ValueError("vault decryption failed — key/vault mismatch") from e
    except ImportError:
        return blob


# ---------------------------------------------------------------------------
# Vault I/O — safe against partial writes via tmp-file + atomic replace.
# ---------------------------------------------------------------------------


def _vault_load(key: bytes) -> Dict[str, str]:
    vp = vault_path()
    if not vp.exists():
        return {}
    raw = vp.read_bytes()
    if not raw.strip():
        return {}
    decrypted = _decrypt(key, raw)
    try:
        data = json.loads(decrypted.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"vault is corrupt: {e}") from e
    if not isinstance(data, dict):
        raise ValueError("vault does not contain a JSON object")
    return {str(k): str(v) for k, v in data.items()}


def _vault_save(key: bytes, data: Dict[str, str]) -> None:
    vault_dir().mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")
    blob = _encrypt(key, payload)
    vp = vault_path()
    tmp = vp.with_suffix(".tmp")
    tmp.write_bytes(blob)
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
    os.replace(tmp, vp)
    os.chmod(vp, stat.S_IRUSR | stat.S_IWUSR)


# ---------------------------------------------------------------------------
# IPC handler — newline-delimited JSON per request.
# ---------------------------------------------------------------------------


class _Handler(socketserver.BaseRequestHandler):
    """One-shot request handler.  Reads one JSON line, dispatches, writes
    one JSON line back.
    """

    server: "_BrokerServer"  # populated by socketserver

    def handle(self) -> None:
        conn: socket.socket = self.request
        try:
            conn.settimeout(5.0)
            data = b""
            while b"\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 1 << 16:  # cap request size at 64 KiB
                    self._send(conn, {"ok": False, "error": "request too large"})
                    return
            line = data.split(b"\n", 1)[0]
            try:
                req = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                self._send(conn, {"ok": False, "error": f"invalid JSON: {e}"})
                return
            if not isinstance(req, dict):
                self._send(conn, {"ok": False, "error": "request must be a JSON object"})
                return
            response = self.server.dispatch(req)
            self._send(conn, response)
        except Exception as e:
            logger.exception("credbroker handler error: %s", e)
            try:
                self._send(conn, {"ok": False, "error": f"internal error: {e}"})
            except Exception:
                pass

    @staticmethod
    def _send(conn: socket.socket, payload: Dict[str, Any]) -> None:
        conn.sendall(json.dumps(payload).encode("utf-8") + b"\n")


class _BrokerServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """Threaded Unix-socket server with in-memory vault cached under a lock."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, sock_path: str):
        super().__init__(sock_path, _Handler)
        os.chmod(sock_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        self._key = _load_or_create_key()
        self._lock = threading.Lock()
        self._vault = _vault_load(self._key)

    def dispatch(self, req: Dict[str, Any]) -> Dict[str, Any]:
        op = str(req.get("op") or "").lower()
        if op == "get":
            name = str(req.get("name") or "")
            with self._lock:
                if name not in self._vault:
                    return {"ok": False, "error": f"no credential named {name!r}"}
                return {"ok": True, "value": self._vault[name]}
        if op == "list":
            with self._lock:
                return {"ok": True, "names": sorted(self._vault.keys())}
        if op == "set":
            name = str(req.get("name") or "")
            value = str(req.get("value") or "")
            if not name:
                return {"ok": False, "error": "name is required"}
            with self._lock:
                self._vault[name] = value
                _vault_save(self._key, self._vault)
            return {"ok": True}
        if op == "delete":
            name = str(req.get("name") or "")
            with self._lock:
                existed = self._vault.pop(name, None) is not None
                if existed:
                    _vault_save(self._key, self._vault)
            return {"ok": True, "existed": existed}
        if op == "ping":
            return {"ok": True, "pong": True, "version": 1}
        return {"ok": False, "error": f"unknown op: {op!r}"}


# ---------------------------------------------------------------------------
# Lifecycle — start / stop / status
# ---------------------------------------------------------------------------


def is_running() -> bool:
    """Probe the broker via the ``ping`` op. Returns False on any error."""
    resp = _request({"op": "ping"}, timeout=1.0, raise_on_error=False)
    return bool(resp and resp.get("ok"))


def _write_pidfile(pid: int) -> None:
    pf = pidfile_path()
    pf.write_text(str(pid), encoding="utf-8")
    try:
        os.chmod(pf, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _read_pidfile() -> Optional[int]:
    pf = pidfile_path()
    if not pf.exists():
        return None
    try:
        return int(pf.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return None


def _cleanup_socket() -> None:
    sp = socket_path()
    if sp.exists():
        try:
            sp.unlink()
        except OSError:
            pass


def serve_forever() -> None:
    """Run the broker in the foreground.

    Binds the Unix socket, writes the pidfile, and blocks until SIGTERM /
    SIGINT.  Intended to be called from a spawned subprocess — see
    ``start_detached()``.
    """
    _cleanup_socket()
    sp = str(socket_path())
    _get_home().mkdir(parents=True, exist_ok=True)
    server = _BrokerServer(sp)
    _write_pidfile(os.getpid())

    stop_event = threading.Event()

    def _stop(signum, frame):
        stop_event.set()
        try:
            server.shutdown()
        except Exception:
            pass

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    logger.info("credbroker: listening on %s (pid=%d)", sp, os.getpid())
    try:
        server.serve_forever()
    finally:
        _cleanup_socket()
        pf = pidfile_path()
        if pf.exists():
            try:
                pf.unlink()
            except OSError:
                pass


def start_detached() -> int:
    """Spawn ``python -m tools.credbroker`` as a detached subprocess.

    Returns the child pid.  If a broker is already running (pidfile + live
    socket), returns the existing pid instead.
    """
    if is_running():
        existing = _read_pidfile()
        if existing:
            return existing
    # Clean up stale pidfile/socket from a crashed previous instance.
    _cleanup_socket()
    pf = pidfile_path()
    if pf.exists():
        try:
            pf.unlink()
        except OSError:
            pass

    import subprocess
    proc = subprocess.Popen(
        [sys.executable, "-m", "tools.credbroker"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    # Wait up to 5s for the socket + pong.
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if is_running():
            return proc.pid
        time.sleep(0.1)
    raise RuntimeError("credbroker failed to come up within 5 seconds")


def stop() -> bool:
    """Shut down the running broker, if any.  Returns True if we sent SIGTERM."""
    pid = _read_pidfile()
    if pid is None:
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        _cleanup_socket()
        pf = pidfile_path()
        if pf.exists():
            try:
                pf.unlink()
            except OSError:
                pass
        return False
    # Brief wait so CLI commands see it gone.
    for _ in range(20):
        if not is_running():
            break
        time.sleep(0.1)
    return True


# ---------------------------------------------------------------------------
# Client — used by the CLI and by higher-level code that wants a credential.
# ---------------------------------------------------------------------------


class CredbrokerError(Exception):
    """Raised when an IPC request to the broker fails."""


def _request(
    payload: Dict[str, Any],
    *,
    timeout: float = 3.0,
    raise_on_error: bool = True,
) -> Optional[Dict[str, Any]]:
    sp = str(socket_path())
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(sp)
            s.sendall(json.dumps(payload).encode("utf-8") + b"\n")
            data = b""
            while b"\n" not in data:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 1 << 16:
                    break
            line = data.split(b"\n", 1)[0]
            return json.loads(line.decode("utf-8"))
    except (FileNotFoundError, ConnectionRefusedError) as e:
        if raise_on_error:
            raise CredbrokerError("credbroker is not running") from e
        return None
    except (OSError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as e:
        if raise_on_error:
            raise CredbrokerError(f"broker IPC failed: {e}") from e
        return None


def get(name: str) -> Optional[str]:
    """Return the credential value, or ``None`` if unknown / broker down."""
    resp = _request({"op": "get", "name": name}, raise_on_error=False)
    if resp is None or not resp.get("ok"):
        return None
    value = resp.get("value")
    return str(value) if value is not None else None


def list_names() -> list[str]:
    resp = _request({"op": "list"}, raise_on_error=False)
    if resp is None or not resp.get("ok"):
        return []
    names = resp.get("names") or []
    return [str(n) for n in names]


def set_(name: str, value: str) -> None:
    resp = _request({"op": "set", "name": name, "value": value})
    if not resp or not resp.get("ok"):
        raise CredbrokerError(f"set failed: {resp}")


def delete(name: str) -> bool:
    resp = _request({"op": "delete", "name": name})
    if not resp or not resp.get("ok"):
        raise CredbrokerError(f"delete failed: {resp}")
    return bool(resp.get("existed", False))


# ---------------------------------------------------------------------------
# CLI: ``python -m tools.credbroker`` → serve
# ---------------------------------------------------------------------------


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    serve_forever()
