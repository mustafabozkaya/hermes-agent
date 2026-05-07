"""Tests for tools/credbroker.py — vault round-trip, IPC protocol, lifecycle.

We test against a real running broker subprocess (spawned in a tmp home dir)
for the integration surface, plus direct function tests for the vault I/O
path and error handling.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import time

import pytest

from tools import credbroker


@pytest.fixture
def broker_home(tmp_path, monkeypatch):
    """Isolated HERMES_HOME so each test gets a fresh vault + socket path."""
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    import importlib
    import hermes_constants

    importlib.reload(hermes_constants)
    return home


@pytest.fixture
def running_broker(broker_home):
    """Start a broker subprocess for the test, tear it down afterward."""
    pid = credbroker.start_detached()
    assert credbroker.is_running()
    try:
        yield pid
    finally:
        if credbroker.is_running():
            credbroker.stop()
        # Belt and suspenders for sockets/pids left behind.
        sp = credbroker.socket_path()
        if sp.exists():
            try:
                sp.unlink()
            except OSError:
                pass


class TestVaultIO:
    def test_load_missing_vault_returns_empty(self, broker_home):
        key = credbroker._load_or_create_key()
        assert credbroker._vault_load(key) == {}

    def test_round_trip_preserves_values(self, broker_home):
        key = credbroker._load_or_create_key()
        data = {"OPENAI_API_KEY": "sk-abc123", "ANTHROPIC_API_KEY": "ant-xyz"}
        credbroker._vault_save(key, data)
        assert credbroker._vault_load(key) == data

    def test_wrong_key_cannot_decrypt(self, broker_home):
        key1 = credbroker._load_or_create_key()
        credbroker._vault_save(key1, {"A": "1"})
        # Overwrite the key with a different one.
        import secrets
        credbroker.key_path().write_bytes(secrets.token_urlsafe(32).encode())
        key2 = credbroker._load_or_create_key()
        # Fernet case: decrypt raises a ValueError translated from InvalidToken.
        # Plaintext fallback case: still succeeds.  Accept either.
        try:
            from cryptography.fernet import Fernet  # noqa: F401
            fernet_available = True
        except ImportError:
            fernet_available = False
        if fernet_available:
            with pytest.raises(ValueError):
                credbroker._vault_load(key2)
        else:
            assert credbroker._vault_load(key2) == {"A": "1"}

    def test_key_file_permissions_are_0600(self, broker_home):
        credbroker._load_or_create_key()
        mode = stat.S_IMODE(credbroker.key_path().stat().st_mode)
        assert mode == 0o600

    def test_vault_file_permissions_are_0600(self, broker_home):
        key = credbroker._load_or_create_key()
        credbroker._vault_save(key, {"X": "1"})
        mode = stat.S_IMODE(credbroker.vault_path().stat().st_mode)
        assert mode == 0o600


class TestBrokerLifecycle:
    def test_is_running_false_when_no_broker(self, broker_home):
        assert credbroker.is_running() is False

    def test_start_then_status_then_stop(self, broker_home):
        pid = credbroker.start_detached()
        try:
            assert credbroker.is_running()
            assert isinstance(pid, int) and pid > 0
            # Pidfile and socket must exist.
            assert credbroker.pidfile_path().exists()
            assert credbroker.socket_path().exists()
            # Socket is 0600.
            mode = stat.S_IMODE(credbroker.socket_path().stat().st_mode)
            assert mode == 0o600
        finally:
            credbroker.stop()

        # After stop, is_running() should settle to False.
        deadline = time.time() + 3.0
        while time.time() < deadline and credbroker.is_running():
            time.sleep(0.05)
        assert credbroker.is_running() is False

    def test_start_is_idempotent(self, broker_home):
        pid1 = credbroker.start_detached()
        try:
            pid2 = credbroker.start_detached()
            # Same broker — no second subprocess spawned.
            assert pid1 == pid2
        finally:
            credbroker.stop()


class TestIpcProtocol:
    def test_set_get_delete_round_trip(self, running_broker):
        credbroker.set_("TEST_KEY", "hello-world")
        assert credbroker.get("TEST_KEY") == "hello-world"
        assert credbroker.delete("TEST_KEY") is True
        assert credbroker.get("TEST_KEY") is None

    def test_list_names_returns_sorted(self, running_broker):
        credbroker.set_("ZEBRA", "z")
        credbroker.set_("ALPHA", "a")
        credbroker.set_("MIKE", "m")
        names = credbroker.list_names()
        assert names == sorted(names)
        assert "ZEBRA" in names and "ALPHA" in names and "MIKE" in names

    def test_get_missing_returns_none(self, running_broker):
        assert credbroker.get("NEVER_EXISTED") is None

    def test_delete_missing_returns_false(self, running_broker):
        # False not raised — the protocol confirms "existed: false".
        assert credbroker.delete("NO_SUCH_KEY") is False

    def test_invalid_json_is_rejected_cleanly(self, running_broker):
        """Raw invalid payload must not crash the broker."""
        sp = str(credbroker.socket_path())
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect(sp)
            s.sendall(b"not valid json\n")
            data = b""
            while b"\n" not in data:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            resp = json.loads(data.split(b"\n", 1)[0])
        assert resp["ok"] is False
        assert "invalid JSON" in resp["error"]

        # Broker is still alive and accepting more requests.
        assert credbroker.get("whatever") is None

    def test_unknown_op_returns_error_without_crashing(self, running_broker):
        resp = credbroker._request({"op": "explode"})
        assert resp["ok"] is False
        assert "unknown op" in resp["error"]
        # Broker still alive.
        assert credbroker.is_running()

    def test_values_persist_across_broker_restart(self, broker_home):
        """Credentials survive stop/start — vault is on disk."""
        credbroker.start_detached()
        try:
            credbroker.set_("PERSIST_ME", "persistent-value")
        finally:
            credbroker.stop()
        # Wait for full teardown before restarting.
        deadline = time.time() + 3.0
        while time.time() < deadline and credbroker.is_running():
            time.sleep(0.05)

        credbroker.start_detached()
        try:
            assert credbroker.get("PERSIST_ME") == "persistent-value"
        finally:
            credbroker.stop()


class TestClientErrors:
    def test_client_raises_when_broker_down(self, broker_home):
        with pytest.raises(credbroker.CredbrokerError):
            credbroker.set_("ANY", "thing")

    def test_get_returns_none_when_broker_down_for_soft_callers(self, broker_home):
        """Helpers like get() / list_names() are soft on connection errors so
        they can be probed without a try/except everywhere."""
        assert credbroker.get("ANY") is None
        assert credbroker.list_names() == []
        assert credbroker.is_running() is False
