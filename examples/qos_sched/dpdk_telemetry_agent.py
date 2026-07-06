"""
benchmarks/dpdk_telemetry_agent.py

Deployed and executed on the DUT via dut.run() / dut.run_application().
Polls the DPDK telemetry Unix socket and serves JSONL records over a TCP
socket so the bench server can collect them without an SSH tunnel.

Protocol (plain TCP):
  - Client connects on AGENT_PORT
  - Agent streams one JSON record per line, newline-terminated, until the
    client disconnects or the agent is killed
  - Each record:
      {"timestamp": <float>, "samples": {"/ethdev/stats": {...}, ...}}
    or on error:
      {"timestamp": <float>, "error": "<msg>"}
"""

from __future__ import annotations

import json
import os
import socket
import sys
import time

# ---------------------------------------------------------------------------
# Configuration — overridable via env vars so the bench server can tune them
# without editing this file
# ---------------------------------------------------------------------------
DPDK_SOCKET  = os.environ.get("DPDK_TELEMETRY_SOCKET", "/var/run/dpdk/rte/dpdk_telemetry.v2")
AGENT_HOST   = os.environ.get("DPDK_AGENT_HOST", "0.0.0.0")
AGENT_PORT   = int(os.environ.get("DPDK_AGENT_PORT", "7779"))
INTERVAL     = float(os.environ.get("DPDK_AGENT_INTERVAL", "0.01"))
COMMANDS     = os.environ.get(
    "DPDK_AGENT_COMMANDS", "/qos/pending_stats,0"
).split(",")


# ---------------------------------------------------------------------------
# DPDK telemetry helpers
# ---------------------------------------------------------------------------

def _query_dpdk(command: str) -> dict:
    """Open a fresh SEQPACKET connection, query one command, return parsed JSON."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as s:
        s.connect(DPDK_SOCKET)
        s.recv(1024)  # drain version banner
        s.sendall(command.encode())  # plain command string, no JSON envelope
        return json.loads(s.recv(16 * 1024).decode())


def _poll() -> dict:
    record: dict = {"timestamp": time.time_ns()}
    samples: dict = {}
    for cmd in COMMANDS:
        cmd = cmd.strip()
        try:
            samples[cmd] = _query_dpdk(cmd)
        except Exception as exc:
            samples[cmd] = {"error": str(exc)}
    record["samples"] = samples
    return record


# ---------------------------------------------------------------------------
# TCP server — one client at a time, streams records until disconnected
# ---------------------------------------------------------------------------

def serve(client: socket.socket) -> None:
    """Stream telemetry records to a connected client."""
    with client:
        addr = client.getpeername()
        print(f"[agent] client connected: {addr}", flush=True)
        try:
            while True:
                t0 = time.monotonic()

                try:
                    record = _poll()
                except Exception as exc:
                    record = {"timestamp": time.time_ns(), "error": str(exc)}

                line = (json.dumps(record) + "\n").encode()
                try:
                    client.sendall(line)
                except (BrokenPipeError, ConnectionResetError):
                    break  # client disconnected cleanly

                elapsed = time.monotonic() - t0
                time.sleep(max(0.0, INTERVAL - elapsed))

        except Exception as exc:
            print(f"[agent] error serving {addr}: {exc}", flush=True)

        print(f"[agent] client disconnected: {addr}", flush=True)


def main() -> None:
    print(
        f"[agent] starting — dpdk_socket={DPDK_SOCKET} "
        f"port={AGENT_PORT} interval={INTERVAL}s "
        f"commands={COMMANDS}",
        flush=True,
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((AGENT_HOST, AGENT_PORT))
        srv.listen(1)
        print(f"[agent] listening on {AGENT_HOST}:{AGENT_PORT}", flush=True)

        # Single-client, sequential — one benchmark run at a time
        while True:
            client, _ = srv.accept()
            serve(client)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[agent] stopped", flush=True)
        sys.exit(0)

