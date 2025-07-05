#!/usr/bin/env python3
"""
Local simulator for ADMPC-Dynamic
---------------------------------

Launch n × layers nodes in a local environment,
reuse the `_run` logic from `adkg/scripts/admpc_dynamic_run.py`,
no need for JSON configuration or SSH, just run `python3 tests/test_admpc_dynamic.py`.

Command-line arguments:
  --n       Number of nodes per layer (default: 4)
  --t       Fault-tolerance threshold (default: 1)
  --layers  Number of layers (default: 2)
  --cm      Total multiplication gates (default: 100)
  --k       Polynomial degree k (default: 1)
  --delay   Delay in seconds before synchronized start (default: 1)
"""
import asyncio
import time
import argparse
import logging

# 直接调用官方脚本里的协程
import scripts.admpc_dynamic_run as admpc_run
from test_admpc_dyn_run import run_dynamic

async def local_sim(
    n: int = 4,
    t: int = 1,
    layers: int = 2,
    total_cm: int = 100,
    k: int = 1,
    delay: int = 1,
):
    """
    Launch n×layers `_run()` coroutines and wait for all to complete
    """
    # Placeholder strings; ProcessProgramRunner only distinguishes by index
    peers = [f"peer-{i}" for i in range(n * layers)]

    # Give each node a moment to synchronize startup
    start_time = time.time() + delay

    tasks = []
    for send_id in range(n * layers):
        my_id = send_id % n  # 层内编号

        task = asyncio.create_task(
            admpc_run._run(
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
        )
        tasks.append(task)

    await asyncio.gather(*tasks)


def main():
    parser = argparse.ArgumentParser(description="Local ADMPC-Dynamic test runner")
    parser.add_argument("--n", type=int, default=4, help="nodes per layer")
    parser.add_argument("--t", type=int, default=1, help="fault threshold")
    parser.add_argument("--layers", type=int, default=2, help="number of layers")
    parser.add_argument("--cm", type=int, default=100, help="total multiplication gates")
    parser.add_argument("--k", type=int, default=1, help="polynomial degree")
    parser.add_argument("--delay", type=int, default=1, help="start delay (seconds)")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    asyncio.run(run_dynamic(n=4, t=1, k=1, layers=1, total_cm=200, delay=1))


if __name__ == "__main__":
    main()