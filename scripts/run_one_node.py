#!/usr/bin/env python3
"""
run_one_node.py
---------------

Entry point for single-process/single-node, used for local multi-process parallel experiments.

Usage:
    python -u scripts/run_one_node.py \
        <n> <t> <k> <layers> <total_cm> <send_id> <start_ts>

Environment Variables:
  PROTOCOL  Values: admpc (default) / fluid / hbmpc, determines which *_run module to call

Argument Descriptions (all integers):
  n         Number of nodes per layer
  t         Threshold of tolerated malicious nodes
  k         Degree of the polynomial (usually k = t)
  layers    Number of circuit layers
  total_cm  Total number of multiplication gates
  send_id   Global node index, range 0..(n*layers-1)
  start_ts  Unix timestamp (seconds); will sleep until start_ts if current time < start_ts
"""
from __future__ import annotations
import sys
import time
import asyncio
from types import SimpleNamespace
import os
import importlib



def main() -> None:
    if len(sys.argv) != 8:
        print(
            f"Usage: {sys.argv[0]} n t k layers total_cm send_id start_ts",
            file=sys.stderr,
        )
        sys.exit(1)

    n, t, k, layers, total_cm, send_id, start_ts = map(int, sys.argv[1:])

    # -------- Select protocol module --------
    protocol = os.environ.get("PROTOCOL", "admpc").lower()
    proto_map = {
        "admpc": "scripts.admpc_dynamic_run",
        "fluid1": "scripts.fluid_mpc_run_1",
        "fluid2": "scripts.fluid_mpc_run",
        "hbmpc": "scripts.honeybadgermpc_run",
        "hbmpc_attack": "scripts.hbmpc_attack_run",
    }
    if protocol not in proto_map:
        print(f"[run_one_node] Unknown PROTOCOL='{protocol}'. Choose from {list(proto_map)}", file=sys.stderr)
        sys.exit(2)

    # --- Clear CLI args first to avoid being parsed by the imported module ---
    sys.argv = [sys.argv[0]]

    proto_mod = importlib.import_module(proto_map[protocol])

    # ========== Important addition ==========
    # Protocol module can expose NEED_LAYER_SPLIT = False to indicate
    # "the same n nodes handle all layers" (e.g., HoneyBadger)
    need_layer_split = getattr(proto_mod, "NEED_LAYER_SPLIT", True)
    total_layers_for_nodes = layers if need_layer_split else 1

    peers = [
        SimpleNamespace(ip="127.0.0.1", port=20000 + i) for i in range(n * total_layers_for_nodes)
    ]
    my_id = send_id % n

    # Synchronize to global start_ts
    now = time.time()
    if start_ts > now:
        time.sleep(start_ts - now)

    asyncio.run(
        proto_mod._run(
            peers,
            n,
            t,
            k,
            my_id,
            start_ts,
            layers,
            send_id,
            total_cm,
        )
    )


if __name__ == "__main__":
    main()