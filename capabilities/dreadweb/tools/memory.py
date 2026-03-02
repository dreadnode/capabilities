#!/usr/bin/env python3
"""Persistent key-value memory for the agent session.

Allows the agent to save, retrieve, and manage structured notes across
tool calls — useful for tracking discovered endpoints, credentials,
gadget inventories, attack chains, and testing hypotheses.

Protocol: reads JSON from stdin, writes JSON to stdout.
"""

import json
import os
import sys
from pathlib import Path

STATE_FILE = Path(os.environ.get("MEMORY_STATE_PATH", "/tmp/dreadweb_memory.json"))


def load_memory() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {}


def save_memory_state(memory: dict) -> None:
    STATE_FILE.write_text(json.dumps(memory, indent=2))


def save_memory(params: dict) -> dict:
    key = params["key"]
    value = params["value"]
    memory = load_memory()
    memory[key] = value
    save_memory_state(memory)
    return {"result": f"Saved to memory key: '{key}'"}


def retrieve_memory(params: dict) -> dict:
    key = params["key"]
    memory = load_memory()
    if key not in memory:
        available = ", ".join(memory.keys()) if memory else "none"
        return {"error": f"Key '{key}' not found. Available keys: {available}"}
    return {"result": memory[key]}


def list_memory_keys(_params: dict) -> dict:
    memory = load_memory()
    if not memory:
        return {"result": "Memory is empty."}
    lines = [f"Memory keys ({len(memory)}):"]
    for key, value in memory.items():
        preview = value[:80] + "..." if len(value) > 80 else value
        lines.append(f"  - {key}: {preview}")
    return {"result": "\n".join(lines)}


def clear_memory(params: dict) -> dict:
    key = params.get("key")
    memory = load_memory()

    if key is None:
        memory.clear()
        save_memory_state(memory)
        return {"result": "All memory cleared."}

    if key not in memory:
        return {"error": f"Key '{key}' not found in memory."}

    del memory[key]
    save_memory_state(memory)
    return {"result": f"Cleared memory key: '{key}'"}


METHODS = {
    "save_memory": save_memory,
    "retrieve_memory": retrieve_memory,
    "list_memory_keys": list_memory_keys,
    "clear_memory": clear_memory,
}


def main():
    raw = sys.stdin.read()
    request = json.loads(raw)
    method = request.get("method", request.get("name", ""))
    params = request.get("parameters", {})

    handler = METHODS.get(method)
    if not handler:
        print(json.dumps({"error": f"Unknown method: {method}"}))
        sys.exit(1)

    try:
        result = handler(params)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
