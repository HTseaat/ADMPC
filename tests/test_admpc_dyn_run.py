#!/usr/bin/env python3
"""
test_admpc_dyn_run.py

Standalone local simulation entry for ADMPC-Dynamic.

Example usage:
    python3 test_admpc_dyn_run.py          # Use default parameters
    python3 test_admpc_dyn_run.py --n 5    # 5 nodes per layer
    python3 test_admpc_dyn_run.py --layers 3 --t 1 --cm 200 --k 2 --delay 2
"""

import asyncio
import time
import argparse
from types import SimpleNamespace

# 导入真正的 _run 协程
import scripts.admpc_dynamic_run as adrun
import scripts.fluid_mpc_run as fuildrun
import scripts.honeybadgermpc_run as hbmpcrun


async def run_dynamic(n: int, t: int, k: int, layers: int, total_cm: int, delay: int):
    """
    Launch n*layers ADMPC node coroutines locally and wait for completion.
    Parameters:
      n        – Number of nodes per layer
      t        – Fault tolerance threshold
      k        – Polynomial degree
      layers   – Number of circuit layers
      total_cm – Total number of multiplication gates
      delay    – Delay (seconds) for synchronizing coroutine startup
    """
    # Construct the list of peers: SimpleNamespace(ip, port)
    base_port = 20000
    peers = [
        SimpleNamespace(ip="127.0.0.1", port=base_port + i)
        for i in range(n * layers)
    ]

    # Unified start time
    start_time = time.time() + delay

    # Launch all _run() tasks corresponding to each send_id in parallel
    tasks = []
    for send_id in range(n * layers):
        my_id = send_id % n
        # tasks.append(asyncio.create_task(
        #     adrun._run(
        #         peers,
        #         n,
        #         t,
        #         k,
        #         my_id,
        #         start_time,
        #         layers,
        #         send_id,
        #         total_cm,
        #     )
        # ))

        # tasks.append(asyncio.create_task(
        #     fuildrun._run(
        #         peers,
        #         n,
        #         t,
        #         k,
        #         my_id,
        #         start_time,
        #         layers,
        #         send_id,
        #         total_cm,
        #     )
        # ))

        tasks.append(asyncio.create_task(
            hbmpcrun._run(
                peers,
                n,
                t,
                k,
                my_id,
                start_time,
                layers,
                send_id,
                total_cm,
            )
        ))

    # Wait for all tasks to complete
    await asyncio.gather(*tasks)


def main():
    parser = argparse.ArgumentParser(description="Local ADMPC-Dynamic test runner")
    parser.add_argument("--n",      type=int, default=4, help="nodes per layer")
    parser.add_argument("--t",      type=int, default=1, help="fault threshold")
    parser.add_argument("--k",      type=int, default=1, help="polynomial degree")
    parser.add_argument("--layers", type=int, default=2, help="number of layers")
    parser.add_argument("--cm",     type=int, default=100, help="total multiplication gates")
    parser.add_argument("--delay",  type=int, default=1, help="start delay (seconds)")

    args = parser.parse_args()

    # Directly run the asynchronous entry point
    asyncio.run(
        run_dynamic(
            n=args.n,
            t=args.t,
            k=args.k,
            layers=args.layers,
            total_cm=args.cm,
            delay=args.delay,
        )
    )


if __name__ == "__main__":
    main()