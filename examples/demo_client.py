#!/usr/bin/env python3
"""Minimal MCP stdio client that walks through a SacredArts session.

Usage:  python3 examples/demo_client.py [path/to/sacredarts]
(stdlib only; prints the human-readable text of every tool result)
"""
import json
import queue
import subprocess
import sys
import threading

BIN = sys.argv[1] if len(sys.argv) > 1 else "target/release/sacredarts"

proc = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, text=True)
lines: "queue.Queue[str]" = queue.Queue()
threading.Thread(target=lambda: [lines.put(l) for l in proc.stdout], daemon=True).start()
next_id = 0


def send(msg):
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()


def rpc(method, params):
    global next_id
    next_id += 1
    send({"jsonrpc": "2.0", "id": next_id, "method": method, "params": params})
    while True:
        m = json.loads(lines.get(timeout=120))
        if m.get("id") == next_id:
            return m


def tool(tool_name, **args):
    res = rpc("tools/call", {"name": tool_name, "arguments": args})["result"]
    print(f"\n>>> {tool_name} {json.dumps(args, ensure_ascii=False)}")
    print(res["content"][0]["text"])
    return res.get("structuredContent") or {}


rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "sacredarts-demo", "version": "0"}})
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

sid = tool("sandbox_create", guide_level=1)["session_id"]
fd = tool("syscall_invoke", session_id=sid, name="openat",
          args={"path": "/workspace/hello.txt", "flags": ["O_CREAT", "O_WRONLY"], "mode": "0644"})["return_value"]
tool("syscall_invoke", session_id=sid, name="write", args={"fd": fd, "data": "Hello"})
tool("syscall_invoke", session_id=sid, name="close", args={"fd": fd})
tool("session_set_guide", session_id=sid, guide_level=2, trace_mode="all")
fd = tool("syscall_invoke", session_id=sid, name="openat", args={"path": "hello.txt"})["return_value"]
tool("syscall_invoke", session_id=sid, name="read", args={"fd": fd, "count": 64})
tool("sandbox_inspect", session_id=sid)
tool("policy_set", session_id=sid, deny=["mkdirat"], errno="EPERM")
tool("syscall_invoke", session_id=sid, name="mkdirat", args={"path": "test", "mode": "0755"})
tool("policy_set", session_id=sid, deny=[])
tool("session_set_guide", session_id=sid, guide_level=1)
tool("syscall_invoke", session_id=sid, name="mkdirat", args={"path": "test", "mode": "0755"})
tool("trace_get", session_id=sid, limit=12)
tool("sandbox_destroy", session_id=sid)

proc.stdin.close()
proc.wait(timeout=60)
