---
title: Credential Broker (experimental)
description: Standalone subprocess that owns an encrypted credential vault — the agent's terminal can't read it.
---

# Credential Broker

The credential broker is a **standalone subprocess** that owns an encrypted credential vault at `~/.hermes/credentials/vault.enc`. Credentials stored here are **not readable by the agent's terminal tool**: clients speak to the broker via a Unix socket; only the broker process ever sees the plaintext vault.

Inspired by Vellum Assistant's Credential Execution Service (CES), scoped down to a tractable first cut.

> **Experimental.** This PR ships the subprocess + IPC + vault format, plus the CLI to manage it. Provider-adapter integration — having every provider fetch its token from the broker instead of reading an env var — is deferred to follow-up work. For now, credentials in the broker are opt-in: use `hermes credbroker get NAME` to retrieve them explicitly.

## Why

Hermes already uses per-process env vars for credentials, which is fine until the agent gets a terminal. Any `cat ~/.hermes/.env` inside the agent's shell happily prints every secret. The broker closes that hole by moving the vault into a **different process** — the agent's terminal can't `cat` a file it can't see.

Threat model this addresses:
- Prompt-injected `cat ~/.hermes/.env` / `env | grep -i key`
- Accidentally-committed .env files (vault is binary and encrypted)
- A compromised skill reading env vars at import time

Threat model this does NOT fully address:
- A rooted user account (the key and vault both live under `~/.hermes`)
- A malicious process running as the same user
- A compromised provider adapter that uses credentials legitimately then exfiltrates them

The broker is defense-in-depth, not a capability sandbox.

## Architecture

```
┌─────────────────────────┐           Unix socket             ┌───────────────────────┐
│  hermes cli / agent     │  ─────────────────────────────>   │  credbroker           │
│  (no vault access)      │  {"op":"get","name":"..."}        │  (reads vault.enc)    │
│                         │  <──────────────────────────────  │  ~/.hermes/...        │
└─────────────────────────┘           {"ok":true,...}         └───────────────────────┘
                                                                 vault.enc   (0600)
                                                                 broker.key  (0600)
                                                                 credbroker.sock (0600)
```

- **Socket:** `~/.hermes/credbroker.sock`, `0600`.
- **Vault:** `~/.hermes/credentials/vault.enc`, encrypted with Fernet if `cryptography` is available (it is, transitively).
- **Key:** `~/.hermes/credentials/broker.key`, `0600`. Generated once per install.
- **Protocol:** newline-delimited JSON over the socket. One request per connection.

## CLI

```bash
hermes credbroker start               # spawn the broker (idempotent)
hermes credbroker stop                # terminate it
hermes credbroker status              # running? how many creds?

hermes credbroker set NAME            # prompts for value (no echo)
hermes credbroker set NAME value      # inline value (careful with shell history)
hermes credbroker get NAME            # prints to stdout, no trailing newline
hermes credbroker list                # one name per line
hermes credbroker delete NAME
```

## Protocol

Clients send a single-line JSON request and receive a single-line JSON response:

```
->  {"op": "get", "name": "OPENAI_API_KEY"}
<-  {"ok": true, "value": "sk-..."}

->  {"op": "list"}
<-  {"ok": true, "names": ["OPENAI_API_KEY", "..."]}

->  {"op": "set", "name": "FOO", "value": "bar"}
<-  {"ok": true}

->  {"op": "delete", "name": "FOO"}
<-  {"ok": true, "existed": true}

->  {"op": "ping"}
<-  {"ok": true, "pong": true, "version": 1}
```

Any error shape: `{"ok": false, "error": "reason"}`.

## Python client

```python
from tools import credbroker

if credbroker.is_running():
    token = credbroker.get("OPENAI_API_KEY")
    ...
```

- `credbroker.get(name)` / `credbroker.list_names()` are soft — they return `None` / `[]` if the broker is down.
- `credbroker.set_(name, value)` / `credbroker.delete(name)` raise `CredbrokerError` on failure.

## Roadmap (deferred)

- **Provider adapter integration** — `hermes_cli/auth.py` learning to prefer broker creds over env vars, so switching a credential to the vault is a one-line user action.
- **Mount exclusion** — auto-mount Hermes config dirs read-only with `credentials/` omitted, so even tools with `~/.hermes/` access can't see the vault.
- **Audit log** — every broker `get` records a timestamped entry.
- **Egress proxy** — a managed HTTP proxy that injects credentials into outbound requests, so the agent never touches the secret directly.

Each of these is a separate, scoped-down PR. The subprocess + IPC shipped here is the load-bearing part — everything else layers on top.
