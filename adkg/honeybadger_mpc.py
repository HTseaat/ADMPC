from adkg.polynomial import polynomials_over, EvalPoint
from adkg.utils.poly_misc import interpolate_g1_at_x
from adkg.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib, time
from math import ceil
import logging
from adkg.utils.bitmap import Bitmap
from adkg.acss import ACSS, ACSS_Foll, ACSS_Pre
from adkg.router import SimpleRouter

from adkg.broadcast.tylerba import tylerba
from adkg.broadcast.optqrbc import optqrbc

from adkg.preprocessing import PreProcessedElements

from adkg.mpc import TaskProgramRunner
from adkg.robust_rec import robust_reconstruct_admpc, Robust_Rec
from adkg.trans import Trans, Trans_Pre, Trans_Foll
from adkg.rand import Rand, Rand_Pre, Rand_Foll
from adkg.aprep import APREP, APREP_Pre, APREP_Foll
import math

from adkg.utils.serilization import Serial
from adkg.field import GF, GFElement
from adkg.ntl import vandermonde_batch_evaluate
from adkg.elliptic_curve import Subgroup
from adkg.progs.mixins.dataflow import Share
from adkg.robust_reconstruction import robust_reconstruct_admpc, robust_rec_admpc

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)

class ADMPCMsgType:
    ACSS = "A"
    RBC = "R"
    ABA = "B"
    PREKEY = "P"
    KEY = "K"
    GENRAND = "GR"
    ROBUSTREC = "RR"
    TRANS = "TR"
    APREP = "AP"
    

class ADMPC:
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrices, total_cm, layers):
        self.public_keys, self.private_key, self.g, self.h = (public_keys, private_key, g, h)
        self.n, self.t, self.deg, self.my_id = (n, t, deg, my_id)
        self.send, self.recv, self.pc = (send, recv, pc)
        self.ZR, self.G1, self.multiexp, self.dotprod = curve_params
        self.curve_params = curve_params
        self.poly = polynomials_over(self.ZR)
        self.poly.clear_cache() #FIXME: Not sure why we need this.
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)
        self.matrix = matrices
        self.total_cm = total_cm
        self.layers = layers

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send
        self.output_queue = asyncio.Queue()

        rectag = ADMPCMsgType.ROBUSTREC
        recsend, recrecv = self.get_send(rectag), self.subscribe_recv(rectag)
        curve_params = (self.ZR, self.G1, self.multiexp, self.dotprod)
        self.rec = Robust_Rec(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, recsend, recrecv, self.pc, curve_params)




        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )
            
    def kill(self):
        try:
            self.subscribe_recv_task.cancel()
            for task in self.acss_tasks:
                task.cancel()
            self.acss.kill()
            self.acss_task.cancel()
        except Exception:
            logging.info("HBMPC task finished")
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def robust_rec_step(self, rec_shares, index):         

        rec_values = await self.rec.batch_robust_rec(index, rec_shares)

        return rec_values
    
    async def rec_step(self, rec_shares, index):                
        
        self.rec_tasks = [None] * self.n
        for i in range(self.n):
            if i == self.my_id:
                self.rec_tasks[i] = asyncio.create_task(self.rec.run_robust_rec(index, values=rec_shares))
            else:
                self.rec_tasks[i] = asyncio.create_task(self.rec.run_robust_rec(index, dealer_id=i))

        outputs = []
        rbc_number = []
        while True:
            rec_id, dealer_id, rbc_msg = await self.rec.output_queue.get()
            if rec_id != index:
                continue
            outputs.append(rbc_msg)
            rbc_number.append(dealer_id)
            if len(outputs) == self.n - 1: 

                sr = Serial(self.G1)

                # First, deserialize the entire rbc_list
                deserialized_rbc_list = [sr.deserialize_fs(item) for item in outputs]


                # Initialize the rbc_shares 2D list
                rbc_shares = [[None for _ in range(len(outputs))] for _ in range(len(deserialized_rbc_list[0]))]

                # Populate the rbc_shares 2D list
                for i in range(len(deserialized_rbc_list[0])):
                    for node in range(len(deserialized_rbc_list)):
                        rbc_shares[i][node] = int(deserialized_rbc_list[node][i])



                GFEG1 = GF(Subgroup.BLS12_381)

                point = EvalPoint(GFEG1, self.n, use_omega_powers=False)
                key_proposal = rbc_number
                poly, err = [None] * len(rbc_shares), [None] * len(rbc_shares)
                rec_values = []
                for i in range(len(rbc_shares)): 
                    poly[i], err[i] = await robust_rec_admpc(rbc_shares[i], key_proposal, GFEG1, self.t, point, self.t)
                    constant = int(poly[i].coeffs[0])
                    rec_values.append(self.ZR(constant))
                te = int(poly[0].coeffs[0])
                tes = self.ZR(te)
                err_list = [list(err[i]) for i in range(len(err))]

                for i in range(len(err_list)): 
                    if len(err_list[i]) == 0: 
                        continue
                    else: 
                        for j in range(len(err_list[i])): 
                            key_proposal.pop(err_list[i][j])

                return (key_proposal, rec_values)

                
            if len(outputs) == self.n:
                return 
        
   
    
    async def mult(self, mult_values, mult_triples, layer): 
        gamma_list, epsilon_list = [None] * len(mult_values), [None] * len(mult_values)
        
        if layer == 200: 
            batch_rec_list = []

            byzantine_nodes = [1]
            for i in range(len(mult_values)): 
                if self.my_id in byzantine_nodes: 
                    gamma_list[i] = self.ZR(0)
                    epsilon_list[i] = self.ZR(0)
                    batch_rec_list.append(gamma_list[i])
                    batch_rec_list.append(epsilon_list[i])
                else: 
                    gamma_list[i] = mult_values[i][0] - mult_triples[layer*self.cm+i][0]
                    epsilon_list[i] = mult_values[i][1] - mult_triples[layer*self.cm+i][1]
                    batch_rec_list.append(gamma_list[i])
                    batch_rec_list.append(epsilon_list[i])

            rec_task = asyncio.create_task(self.rec_step(batch_rec_list, layer))
            (mks, rec_values) = await rec_task
            num = 0
            rec_gamma_list, rec_epsilon_list = [], []
            for i in range(len(mult_values)):
                rec_gamma_list.append(rec_values[num])
                rec_epsilon_list.append(rec_values[num+1])
                num += 2
            mult_outputs = [None] * len(mult_values)
            for i in range(len(mult_values)):
                mult_outputs[i] = mult_triples[i][2] + rec_gamma_list[i] * mult_triples[i][1] + rec_epsilon_list[i] * mult_triples[i][0] + rec_gamma_list[i] * rec_epsilon_list[i]

        else: 
            batch_rec_list = []
            for i in range(len(mult_values)): 
                gamma_list[i] = mult_values[i][0] - mult_triples[layer*self.cm+i][0]
                epsilon_list[i] = mult_values[i][1] - mult_triples[layer*self.cm+i][1]
                batch_rec_list.append(gamma_list[i])
                batch_rec_list.append(epsilon_list[i])

            rec_task = asyncio.create_task(self.rec_step(batch_rec_list, layer))
            (mks, rec_values) = await rec_task
            num = 0
            rec_gamma_list, rec_epsilon_list = [], []
            for i in range(len(mult_values)):
                rec_gamma_list.append(rec_values[num])
                rec_epsilon_list.append(rec_values[num+1])
                num += 2
            mult_outputs = [None] * len(mult_values)
            for i in range(len(mult_values)):
                mult_outputs[i] = mult_triples[i][2] + rec_gamma_list[i] * mult_triples[i][1] + rec_epsilon_list[i] * mult_triples[i][0] + rec_gamma_list[i] * rec_epsilon_list[i]


        return mult_outputs

    
    async def run_computation(self, inputs, gate_tape, mult_triples, layer):
        print(f"len inputs: {len(inputs)} len gate_tape: {len(gate_tape)} len mult: {len(mult_triples)}")

        
        self.gates_num = len(gate_tape)
        # 这里根据当前层门的数量对输入进行划分
        gate_input_values = [[self.ZR(0) for _ in range(2)] for _ in range(self.gates_num)]
        for i in range(self.gates_num): 
            for j in range(2): 
                gate_input_values[i][j] = inputs[j]
        # 输出存在这里
        gate_output_values = [None] * self.gates_num
        # 这两个用来记录当前层的乘法门位置和数量，用来做当前层乘法门的批处理
        batch_mult_gates, mult_pos = [], []
        triple_num = 0
        for i in range(self.gates_num): 
            # 这是加法
            if gate_tape[i] == 0: 
                gate_output_values[i] = gate_input_values[i][0] + gate_input_values[i][1]
            # 这是乘法
            else: 
                batch_mult_gates.append(gate_input_values[i])
                mult_pos.append(i)
                # gate_output_values[i] = await self.mult(gate_input_values[i], mult_triples[triple_num])
                # triple_num += 1

        batch_mult_outputs = await self.mult(batch_mult_gates, mult_triples, layer)
        for i in range(len(mult_pos)): 
            gate_output_values[mult_pos[i]] = batch_mult_outputs[i]

        # self.output_queue.put_nowait(gate_output_values)
        return gate_output_values
    
   
    async def run_admpc(self, start_time):
        layers = self.layers
        self.cm = int(self.total_cm / layers)
        cm = self.cm
        w = 2 * cm
        print(f"cm: {cm} layers: {layers}")

        if self.my_id != 200:
            step3_start_time = time.time()
            apreptag = ADMPCMsgType.APREP
            aprepsend, apreprecv = self.get_send(apreptag), self.subscribe_recv(apreptag)
            aprep = APREP(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, aprepsend, apreprecv, self.pc, self.curve_params, self.matrix)
            new_mult_triples = await aprep.run_aprep(self.total_cm)
            step3_time = time.time() - step3_start_time

            print(f"prepare mult_triples time: {step3_time}")
            
            intput_num = 2 * w

            if intput_num > self.n - self.t: 
                rounds = math.ceil(intput_num / (self.n - self.t))
            else: 
                rounds = 1

            step2_start_time = time.time()
            randtag = ADMPCMsgType.GENRAND
            randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
            rand = Rand(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, randsend, randrecv, self.pc, self.curve_params, self.matrix)
            new_shares = await rand.run_rand(intput_num, rounds)
            step2_time = time.time() - step2_start_time
            print(f"prepare new shares time: {step2_time}")

            # execution stage
            gate_tape = []
            for i in range(cm): 
                gate_tape.append(1)
            for i in range(w - cm): 
                gate_tape.append(0)
            
            for i in range(layers): 
                layer_time = time.time()
                gate_outputs = await self.run_computation(new_shares, gate_tape, new_mult_triples, i)
                layer_time = time.time() - layer_time
                print(f"layer ID: {i} layer_time: {layer_time}")

            # invoke robust_rec to reconstruct the output
            rec_task = asyncio.create_task(self.rec_step(gate_outputs, 20))
            (mks, output_values) = await rec_task


            admpc_time = time.time() - start_time
            print(f"honeybadgermpc_time: {admpc_time}")


from pypairing import ZR, G1, blsmultiexp as multiexp, dotprod
from adkg.router import SimpleRouter
from adkg.poly_commit_hybrid import PolyCommitHybrid
import numpy as np

def get_avss_params(n):
    g, h = G1.rand(b'g'), G1.rand(b'h')
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.random()
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys

def gen_vector(t, n, ZR):
    vm = np.array([[ZR(i+1)**j for j in range(n)] for i in range(n-t)])
    # print(f"vm: {vm}")
    print(f"vm.tolist(): {vm.tolist()}")

    return (vm.tolist())


class ADMPC_Multi_Layer_Control():
    def __init__(self, n=None, t= None, deg=None, layer_num=None, total_cm=None, pks=None):
        self.n = n
        self.t = t
        self.deg = deg
        self.layer_num = layer_num
        self.total_cm = total_cm
        self.control_signal = asyncio.Event()
        self.pks_all = [[None] * self.n for _ in range(self.layer_num)]
        if pks is not None: 
            for layerID in range(self.layer_num): 
                self.pks_all[layerID] = pks[self.n*layerID:self.n*layerID+self.n]

    async def add(self):

        self.pks_all = [[None] * self.n for _ in range(self.layer_num)]      
        self.admpc_lists = [[None] * self.n for _ in range(self.layer_num)]
        self.admpc_tasks = [[None] * self.n for _ in range(self.layer_num)]

        router = SimpleRouter(self.n * self.layer_num)

        curve_params = (ZR, G1, multiexp, dotprod)

        start_time = time.time()

        g, h, pks, sks = get_avss_params(self.n * self.layer_num)
        pc = PolyCommitHybrid(g, h, ZR, multiexp)
        mat = gen_vector(self.t, self.n, ZR)

        for layerID in range(self.layer_num):
            self.pks_all[layerID] = pks[self.n*layerID:self.n*layerID+self.n]
            
            for i in range(self.n):
                admpc = ADMPC_Dynamic(self.pks_all[layerID], sks[self.n * layerID + i], 
                                      g, h, self.n, self.t, self.deg, i, 
                                      router.sends[self.n * layerID + i], router.recvs[self.n * layerID + i], 
                                      pc, curve_params, mat, layerID, admpc_control_instance=self)
                self.admpc_lists[layerID][i] = admpc
                self.admpc_tasks[layerID][i] = asyncio.create_task(admpc.run_admpc(start_time))
            
        for layerID in range(self.layer_num):
            await asyncio.gather(*(self.admpc_tasks[layerID]))

    


class ADMPC_Dynamic(ADMPC):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrices, total_cm, layerID = None, admpc_control_instance=None):
        self.admpc_control_instance = admpc_control_instance if admpc_control_instance is not None else ADMPC_Multi_Layer_Control(n=n, t=t, deg=deg, layer_num=int(len(public_keys)/n), total_cm=total_cm, pks=public_keys)
        self.layer_ID = layerID
        self.sc = ceil((deg+1)/(t+1)) + 1
        self.Signal = asyncio.Event()
        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrices)
