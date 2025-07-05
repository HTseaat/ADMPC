"""
hbMPC tutorial 1. Running sample MPC programs in the testing simulator
"""
import asyncio
from adkg.mpc import TaskProgramRunner
from adkg.progs.mixins.dataflow import Share
from adkg.preprocessing import (
    PreProcessedElements as FakePreProcessedElements,
)
from adkg.utils.typecheck import TypeCheck
from adkg.progs.mixins.share_arithmetic import (
    MixinConstants,
    BeaverMultiply,
    BeaverMultiplyArrays,
)

from adkg.poly_commit_hybrid import PolyCommitHybrid
from pytest import mark
from random import randint
from adkg.polynomial import polynomials_over
from adkg.utils.misc import print_exception_callback
import asyncio
import math

import numpy as np
from adkg.aprep import APREP
import time

from adkg.trans import Trans
from adkg.rand import Rand

from pypairing import ZR, G1, blsmultiexp as multiexp, dotprod

config = {
    MixinConstants.MultiplyShareArray: BeaverMultiplyArrays(),
    MixinConstants.MultiplyShare: BeaverMultiply(),
}

def get_avss_params(n, t):
    g, h = G1.rand(b'g'), G1.rand(b'h')
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random()
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys

async def gather_outputs(acss_list):
    return await asyncio.gather(
        *[acss.output_queue.get() for acss in acss_list if acss is not None]
    )

def gen_vector(t, n, ZR):


    vm = np.array([[ZR(i+1)**j for j in range(n)] for i in range(n-t)])
    # print(f"vm: {vm}")
    # print(f"vm.tolist(): {vm.tolist()}")

    return (vm.tolist())

async def prog(ctx):
    print(f"my id: {ctx.myid} ctx.N: {ctx.N}")
    t = ctx.t
    deg = t
    n = ctx.N
    sc = math.ceil(deg/t) + 1
    myid = ctx.myid

    g, h, public_keys, private_key = ctx.g, ctx.h, ctx.public_keys, ctx.private_key
    pc = PolyCommitHybrid(g, h, ZR, multiexp)

    # w is the number of random values to generate
    w = 100
    
    if w > n - t: 
        rounds = math.ceil(w / (n - t))
    else: 
        rounds = 1
    print(f"rounds: {rounds}, w: {w}")
    
    dkg_tasks = ctx.avss_tasks
    dkg_list = ctx.acss_list

    curve_params = (ZR, G1, multiexp, dotprod)
    mat = gen_vector(t, n, ZR)
    
    dkg = Rand(public_keys, private_key, g, h, n, t, deg, myid, ctx.send, ctx.recv, pc, curve_params, mat)
    dkg_list[myid] = dkg
    dkg_tasks[myid] = asyncio.create_task(dkg.run_rand(w, rounds))
    

async def tutorial_1():
    # Create a test network of 4 nodes (no sockets, just asyncio tasks)
    n, t = 16, 5
    pp = FakePreProcessedElements()
    pp.generate_zeros(100, n, t)
    pp.generate_triples(100, n, t)
    pp.generate_bits(100, n, t)
    program_runner = TaskProgramRunner(n, t, config)
    program_runner.add(prog)
    results = await program_runner.join()
    return results


def main():
    # Run the tutorials
    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tutorial_1())
    # loop.run_until_complete(tutorial_2())


if __name__ == "__main__":
    main()
    print("Tutorial 1 ran successfully")
