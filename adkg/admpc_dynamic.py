from adkg.polynomial import polynomials_over
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


from adkg.mpc import TaskProgramRunner
from adkg.robust_rec import robust_reconstruct_admpc, Robust_Rec
from adkg.trans import Trans, Trans_Pre, Trans_Foll
from adkg.rand import Rand, Rand_Pre, Rand_Foll
from adkg.aprep import APREP, APREP_Pre, APREP_Foll
import math

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
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrices):
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
            logging.info("ADMPC task finished")
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def robust_rec_step(self, rec_shares, index):         

        # self.rectasks = [None] * len(rec_shares)
        # for i in range(len(rec_shares)): 
        #     self.rectasks[i] = asyncio.create_task(self.rec.run_robust_rec(i, rec_shares[i]))
        # rec_values = await asyncio.gather(*self.rectasks)
        # print(f"my id: {self.my_id} rec_values: {rec_values}")

        # return rec_values
        rec_values = await self.rec.batch_run_robust_rec(index, rec_shares)

        # # rec_signal.set()
        return rec_values
    
    async def mult(self, mult_values, mult_triples): 
        gamma_list, epsilon_list = [None] * len(mult_values), [None] * len(mult_values)
        
        batch_rec_list = []
        for i in range(len(mult_values)): 
            gamma_list[i] = mult_values[i][0] - mult_triples[i][0]
            epsilon_list[i] = mult_values[i][1] - mult_triples[i][1]
            batch_rec_list.append(gamma_list[i])
            batch_rec_list.append(epsilon_list[i])
        # gamma = mult_values[0] - mult_triples[0]
        # epsilon = mult_values[1] - mult_triples[1]

        # batch_rec_list = []
        # batch_rec_list.append(gamma_list)
        # batch_rec_list.append(epsilon_list)

        # robust_rec_signal = asyncio.Event()
        # rec_gamma = await self.robust_rec_step(gamma, 0)
        
        # await robust_rec_signal.wait()
        # robust_rec_signal.clear()
        # rec_epsilon = await self.robust_rec_step(epsilon, 1)
        # await robust_rec_signal.wait()
        # robust_rec_signal.clear()

        rec_values = await self.robust_rec_step(batch_rec_list, 0)
        num = 0
        rec_gamma_list, rec_epsilon_list = [], []
        for i in range(len(mult_values)):
            rec_gamma_list.append(rec_values[num])
            rec_epsilon_list.append(rec_values[num+1])
            num += 2
        mult_outputs = [None] * len(mult_values)
        for i in range(len(mult_values)):
            mult_outputs[i] = mult_triples[i][2] + rec_gamma_list[i] * mult_triples[i][1] + rec_epsilon_list[i] * mult_triples[i][0] + rec_gamma_list[i] * rec_epsilon_list[i]

        # rec_gamma, rec_epsilon = await asyncio.gather(self.robust_rec_step(gamma, 0), self.robust_rec_step(epsilon, 1))  

        # mult_output = mult_triples[2] + rec_gamma * mult_triples[1] + rec_epsilon * mult_triples[0] + rec_gamma * rec_epsilon
        return mult_outputs

    
    async def run_computation(self, inputs, gate_tape, mult_triples):
        self.gates_num = int(len(inputs)/2)
        # 这里根据当前层门的数量对输入进行划分
        gate_input_values = [[self.ZR(0) for _ in range(2)] for _ in range(self.gates_num)]
        for i in range(self.gates_num): 
            for j in range(2): 
                gate_input_values[i][j] = inputs[i*2+j]
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
        batch_mult_outputs = await self.mult(batch_mult_gates, mult_triples)
        for i in range(len(mult_pos)): 
            gate_output_values[mult_pos[i]] = batch_mult_outputs[i]

        # self.output_queue.put_nowait(gate_output_values)
        return gate_output_values
    
    async def run_admpc(self, start_time):

        tape_num = 4
        inputs = []
        gate_tape = []
        mult_triples = []
        rand_values = []
        for i in range(tape_num): 
            inputs.append(self.ZR(2*(self.my_id+1)+3))
            inputs.append(self.ZR(3*(self.my_id+1)+2))
            gate_tape.append(1)
            mult_triples.append([self.ZR((self.my_id+1)+5), self.ZR(3*(self.my_id+1)+2), self.ZR(2*(self.my_id+1)+10)])
            rand_values.append(self.ZR(2*(self.my_id+1)+5))



        # 这里是 execution stage 的 step 1，执行当前层的计算

        step1_start_time = time.time()
        gate_outputs = await self.run_computation(inputs, gate_tape, mult_triples)
        step1_time = time.time() - step1_start_time
        print(f"step 1 output: {gate_outputs}")

        # 这里是 execution stage 的 step 2，调用 rand 协议为下一层生成随机数
        # w 是需要生成的随机数的数量
        w = 100

        if w > self.n - self.t: 
            rounds = math.ceil(w / (self.n - self.t))
        else: 
            rounds = 1

        step2_start_time = time.time()
        randtag = ADMPCMsgType.GENRAND
        randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
        rand = Rand(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, randsend, randrecv, self.pc, self.curve_params, self.matrix)
        rand_shares = await rand.run_rand(w, rounds)
        step2_time = time.time() - step2_start_time
        print(f"step 2 output: {rand_shares}")
        # print(f"rand_shares: {rand_shares}")

        # 这里是 execution stage 的 step 3，调用 Aprep 协议为下一层生成乘法三元组
        cm = 2

        step3_start_time = time.time()
        apreptag = ADMPCMsgType.APREP
        aprepsend, apreprecv = self.get_send(apreptag), self.subscribe_recv(apreptag)
        aprep = APREP_Pre(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, aprepsend, apreprecv, self.pc, self.curve_params, self.matrix)
        new_mult_triples = await aprep.run_aprep(cm)
        step3_time = time.time() - step3_start_time
        print(f"step 3 output: {new_mult_triples}")
        print(f"time: {step3_time}")

        # 这里是 execution stage 的 step 4，调用 Trans 协议将当前层的电路输出传输到下一层
        step4_start_time = time.time()
        transtag = ADMPCMsgType.TRANS
        transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)
        trans = Trans(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, transsend, transrecv, self.pc, self.curve_params)
        new_shares = await trans.run_trans(gate_outputs, rand_values)
        step4_time = time.time() - step4_start_time
        print(f"step 4 output: {new_shares}")
        print(f"time: {step4_time}")

        admpc_time = time.time() - start_time
        logging.info(f"admpc finished! n: {self.n} Node {self.my_id}, tape_num: {tape_num} step1_time: {step1_time}, w: {w} step2_time: {step2_time}, cm: {cm} step3_time: {step3_time}, step4_time: {step4_time} time: {admpc_time}")


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
    print(f"vm.tolist(): {vm.tolist()}")

    return (vm.tolist())


# Manage all MPC instances
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
        """Generate layer_num * n MPC instances (stored in self.admpc_lists, corresponding run_admpc tasks stored in admpc_tasks)"""
        # Initialize public key groups (including all MPC instance public keys)
        self.pks_all = [[None] * self.n for _ in range(self.layer_num)]      # Storage format: pks_all = [[all public keys for layer 1], [all public keys for layer 2], ..., [public keys for last layer]]
        # Initialize admpc_lists (store all MPC instances)
        self.admpc_lists = [[None] * self.n for _ in range(self.layer_num)]
        self.admpc_tasks = [[None] * self.n for _ in range(self.layer_num)]

        router = SimpleRouter(self.n * self.layer_num)

        curve_params = (ZR, G1, multiexp, dotprod)

        start_time = time.time()

        g, h, pks, sks = get_avss_params(self.n * self.layer_num)
        pc = PolyCommitHybrid(g, h, ZR, multiexp)
        mat = gen_vector(self.t, self.n, ZR)

        # Generate all MPC instances
        for layerID in range(self.layer_num):
            # Generate MPC instances for each layer
            self.pks_all[layerID] = pks[self.n*layerID:self.n*layerID+self.n]
            
            # Generate each MPC instance in the layer with layerID
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

    async def robust_rec_step(self, rec_shares, index):         

        member_list = []
        for i in range(self.n): 
            member_list.append(self.n * (self.layer_ID) + i)
        rec_values = await self.rec.batch_run_robust_rec(index, rec_shares, member_list)

        return rec_values
    
    async def mult(self, mult_values, mult_triples): 
        gamma_list, epsilon_list = [None] * len(mult_values), [None] * len(mult_values)
        
        batch_rec_list = []
        for i in range(len(mult_values)): 
            gamma_list[i] = mult_values[i][0] - mult_triples[i][0]
            epsilon_list[i] = mult_values[i][1] - mult_triples[i][1]
            batch_rec_list.append(gamma_list[i])
            batch_rec_list.append(epsilon_list[i])

        rec_values = await self.robust_rec_step(batch_rec_list, 0)
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

    
    async def run_computation(self, inputs, gate_tape, mult_triples):
        self.gates_num = len(gate_tape)
        gate_input_values = [[self.ZR(0) for _ in range(2)] for _ in range(self.gates_num)]
        for i in range(self.gates_num): 
            for j in range(2): 
                gate_input_values[i][j] = inputs[i*2+j]
        gate_output_values = [None] * self.gates_num
        batch_mult_gates, mult_pos = [], []
        triple_num = 0
        for i in range(self.gates_num): 
            if gate_tape[i] == 0: 
                gate_output_values[i] = gate_input_values[i][0] + gate_input_values[i][1]
            else: 
                batch_mult_gates.append(gate_input_values[i])
                mult_pos.append(i)

        batch_mult_outputs = await self.mult(batch_mult_gates, mult_triples)
        for i in range(len(mult_pos)): 
            gate_output_values[mult_pos[i]] = batch_mult_outputs[i]

        print(f"layer ID: {self.layer_ID} run_computation finished")
        return gate_output_values


    
    
    async def run_admpc(self, start_time):
        acss_start_time = time.time()
        self.public_keys = self.public_keys[self.n*self.layer_ID:self.n*self.layer_ID+self.n]
        
        # cm indicates the number of multiplication gates per layer, evenly distributed across working layers
        if self.admpc_control_instance.layer_num > 2:
            cm = int(self.admpc_control_instance.total_cm / (self.admpc_control_instance.layer_num - 2))
        else:
            cm = self.admpc_control_instance.total_cm
        print(f"run_admpc layer_ID: {self.layer_ID}, cm: {cm}, total_cm: {self.admpc_control_instance.total_cm}")
        
        # w indicates the circuit width of each layer
        w = cm * 2
        # len_values represents the number of values that need to be passed to the next layer
        len_values = w

        # Calculate the time for each layer
        layer_time = time.time()

        # We assume that when layer_ID = 0, clients provide inputs to servers
        if self.layer_ID == 0:
            # The number of client input values should be equal to 2 * w
            inputs_num = int((2*w)/self.n) + 1
            print(f"inputs_num: {inputs_num}, n: {self.n}, w: {w}")
            clients_inputs = []
            for i in range(inputs_num):
                clients_inputs.append(self.ZR.rand())

            # The public keys passed here should be those of the next layer
            acss_pre_time = time.time()
            pks_next_layer = self.admpc_control_instance.pks_all[self.layer_ID + 1]       # Public key group for the next layer

            acsstag = ADMPCMsgType.ACSS + str(self.layer_ID+1) + str(self.my_id)
            acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

            self.acss = ACSS_Pre(pks_next_layer, 
                                self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                mpc_instance=self
                            )
            self.acss_tasks = [None] * self.n
            self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, values=clients_inputs))
            await self.acss_tasks[self.my_id]
            acss_pre_time = time.time() - acss_pre_time
            print(f"layer ID: {self.layer_ID} acss_pre_time: {acss_pre_time}")

            # clients step 2: invoke Rand protocol to send random values to the next layer
            rand_pre_time = time.time()
            r_num = 2 * w + 1
            if r_num > self.n - self.t: 
                rounds = math.ceil(r_num / (self.n - self.t))
            else: 
                rounds = 1

            randtag = ADMPCMsgType.GENRAND + str(self.layer_ID+1)
            randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)

            rand_pre = Rand_Pre(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                randsend, randrecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)
            rand_pre_task = asyncio.create_task(rand_pre.run_rand(r_num, rounds))
            await rand_pre_task
            rand_pre_time = time.time() - rand_pre_time
            print(f"layer ID: {self.layer_ID} rand_pre_time: {rand_pre_time}")

            # clients step 3: invoke Aprep protocol to send multiplication triples to the next layer
            aprep_pre_time = time.time()
            apreptag = ADMPCMsgType.APREP + str(self.layer_ID+1)
            aprepsend, apreprecv = self.get_send(apreptag), self.subscribe_recv(apreptag)

            aprep_pre = APREP_Pre(self.public_keys, self.private_key, 
                          self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                          aprepsend, apreprecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)
            aprep_pre_task = asyncio.create_task(aprep_pre.run_aprep(cm))
            await aprep_pre_task
            aprep_pre_time = time.time() - aprep_pre_time
            print(f"layer ID: {self.layer_ID} aprep_pre_time: {aprep_pre_time}")


        elif self.layer_ID == 1: 
            # Before executing this layer, servers need to: 1. receive inputs from the previous layer (note special handling for layer=1); 2. receive random values from the previous layer; 3. receive multiplication triples from the previous layer
            # Step 1: receive outputs from the previous layer (special handling for layer=1)
            recv_input_time = time.time()
            self.acss_tasks = [None] * self.n
            for dealer_id in range(self.n): 
                # Here ADMPCMsgType.ACSS is reused, which may conflict with the following trans protocol
                acsstag = ADMPCMsgType.ACSS + str(self.layer_ID) + str(dealer_id)
                acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

                # At this point, the current layer's public/private keys are used
                self.acss = ACSS_Foll(self.public_keys, self.private_key, 
                                    self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                    acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                    mpc_instance=self
                                )
                inputs_num = int((2 * w) / self.n) + 1
                self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, dealer_id, inputs_num))


            results = await asyncio.gather(*self.acss_tasks)
            dealer_to_shares = {
                entry[0]: entry[2]['msg']
                for entry in results
            }

            dealers, shares = zip(*dealer_to_shares.items())
            dealers = list(dealers)
            shares  = list(shares)

            new_shares = [item for share_list in shares for sublist in share_list for item in sublist]

            recv_input_time = time.time() - recv_input_time
            print(f"layer ID: {self.layer_ID} recv_input_time: {recv_input_time}")

            
            # Step 2: receive random values from the previous layer
            rand_foll_time = time.time()
            randtag = ADMPCMsgType.GENRAND + str(self.layer_ID)
            randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
            rand_foll = Rand_Foll(self.public_keys, self.private_key, 
                                  self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                  randsend, randrecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)
            r_num = 2 * w + 1 
            if r_num > self.n - self.t: 
                rounds = math.ceil(r_num / (self.n - self.t))
            else: 
                rounds = 1
            rand_shares = await rand_foll.run_rand(r_num, rounds)
            rand_foll_time = time.time() - rand_foll_time
            print(f"layer ID: {self.layer_ID} rand_foll_time: {rand_foll_time}")
            
            # Step 3: receive multiplication triples from the previous layer
            aprep_foll_time = time.time()
            apreptag = ADMPCMsgType.APREP + str(self.layer_ID)
            aprepsend, apreprecv = self.get_send(apreptag), self.subscribe_recv(apreptag)

            aprep_foll = APREP_Foll(self.public_keys, self.private_key, 
                          self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                          aprepsend, apreprecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)

            new_mult_triples = await aprep_foll.run_aprep(cm)
            aprep_foll_time = time.time() - aprep_foll_time
            print(f"layer ID: {self.layer_ID} aprep_foll_time: {aprep_foll_time}")

            # Execution stage step 1: perform computation of the current layer
            exec_time = time.time()
            gate_tape = []
            for i in range(cm): 
                gate_tape.append(1)
            for i in range(w-cm):
                gate_tape.append(0)
            gate_outputs = await self.run_computation(new_shares, gate_tape, new_mult_triples)
            exec_time = time.time() - exec_time
            print(f"layer ID: {self.layer_ID} exec_time: {exec_time}")

            if self.layer_ID + 1 < len(self.admpc_control_instance.pks_all):
                # This indicates that the next layer will output results to the clients
                if self.layer_ID + 1 == len(self.admpc_control_instance.pks_all) - 1: 
                    # Execution stage step 4: call the Trans protocol to transmit this layer’s circuit output to the next layer
                    trans_pre_time = time.time()
                    transtag = ADMPCMsgType.TRANS + str(self.layer_ID+1)
                    transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)

                    trans_pre = Trans_Pre(self.public_keys, self.private_key, 
                                    self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                    transsend, transrecv, self.pc, self.curve_params, mpc_instance=self)
                    trans_pre_task = asyncio.create_task(trans_pre.run_trans(gate_outputs, rand_shares))
                    
                    self.admpc_control_instance.control_signal.set()
                    trans_pre_time = time.time() - trans_pre_time
                    print(f"layer ID: {self.layer_ID} trans_pre_time: {trans_pre_time}")
                else: 
                    rand_pre_time = time.time()
                    r_num = 2 * w + 1 
                    if r_num > self.n - self.t: 
                        rounds = math.ceil(r_num / (self.n - self.t))
                    else: 
                        rounds = 1

                    randtag = ADMPCMsgType.GENRAND + str(self.layer_ID+1)
                    randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)

                    rand_pre = Rand_Pre(self.public_keys, self.private_key, 
                                        self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                        randsend, randrecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)
                    rand_pre_task = asyncio.create_task(rand_pre.run_rand(r_num, rounds))
                    rand_pre_time = time.time() - rand_pre_time
                    print(f"layer ID: {self.layer_ID} rand_pre_time: {rand_pre_time}")

                    aprep_pre_time = time.time()
                    apreptag = ADMPCMsgType.APREP + str(self.layer_ID+1)
                    aprepsend, apreprecv = self.get_send(apreptag), self.subscribe_recv(apreptag)

                    aprep_pre = APREP_Pre(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                aprepsend, apreprecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)
                    aprep_pre_task = asyncio.create_task(aprep_pre.run_aprep(cm))
                    aprep_pre_time = time.time() - aprep_pre_time
                    print(f"layer ID: {self.layer_ID} aprep_pre_time: {aprep_pre_time}")

                    # Execution stage step 4: call the Trans protocol to transmit this layer’s circuit output to the next layer
                    trans_pre_time = time.time()
                    transtag = ADMPCMsgType.TRANS + str(self.layer_ID+1)
                    transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)

                    trans_pre = Trans_Pre(self.public_keys, self.private_key, 
                                    self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                    transsend, transrecv, self.pc, self.curve_params, mpc_instance=self)
                    trans_pre_task = asyncio.create_task(trans_pre.run_trans(gate_outputs, rand_shares))
                    
                    self.admpc_control_instance.control_signal.set()
                    trans_pre_time = time.time() - trans_pre_time
                    print(f"layer ID: {self.layer_ID} trans_pre_time: {trans_pre_time}")

            else: 
                print("over")
        else:            
            # This indicates clients receive outputs from servers and reconstruct the results
            if self.layer_ID + 1 == len(self.admpc_control_instance.pks_all):
                # First, clients call the Trans protocol to receive shares
                trans_foll_time = time.time()
                transtag = ADMPCMsgType.TRANS + str(self.layer_ID)
                transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)

                trans_foll = Trans_Foll(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                transsend, transrecv, self.pc, self.curve_params, mpc_instance=self)

                new_shares = await trans_foll.run_trans(len_values)
                trans_foll_time = time.time() - trans_foll_time
                print(f"layer ID: {self.layer_ID} trans_foll_time: {trans_foll_time}")

                rec_values = await self.robust_rec_step(new_shares, 0)
            else: 
            
                # Before computation, servers need to: 1. receive inputs from the previous layer (handle layer=1 carefully); 2. receive random values; 3. receive multiplication triples
                # Step 1: receive outputs from the previous layer
                trans_foll_time = time.time()
                transtag = ADMPCMsgType.TRANS + str(self.layer_ID)
                transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)

                trans_foll = Trans_Foll(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                transsend, transrecv, self.pc, self.curve_params, mpc_instance=self)

                new_shares = await trans_foll.run_trans(len_values)
                trans_foll_time = time.time() - trans_foll_time
                print(f"layer ID: {self.layer_ID} trans_foll_time: {trans_foll_time}")
                  
                # Step 2: receive random values from the previous layer
                rand_foll_time = time.time()
                randtag = ADMPCMsgType.GENRAND + str(self.layer_ID)
                randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
                rand_foll = Rand_Foll(self.public_keys, self.private_key, 
                                    self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                    randsend, randrecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)

                r_num = 2 * w + 1 
                if r_num > self.n - self.t: 
                    rounds = math.ceil(r_num / (self.n - self.t))
                else: 
                    rounds = 1
                rand_shares = await rand_foll.run_rand(r_num, rounds)
                rand_foll_time = time.time() - rand_foll_time
                print(f"layer ID: {self.layer_ID} rand_foll_time: {rand_foll_time}")
                

                # Step 3: receive multiplication triples from the previous layer
                aprep_foll_time = time.time()
                apreptag = ADMPCMsgType.APREP + str(self.layer_ID)
                aprepsend, apreprecv = self.get_send(apreptag), self.subscribe_recv(apreptag)

                aprep_foll = APREP_Foll(self.public_keys, self.private_key, 
                            self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                            aprepsend, apreprecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)

                new_mult_triples = await aprep_foll.run_aprep(cm)
                aprep_foll_time = time.time() - aprep_foll_time
                print(f"layer ID: {self.layer_ID} aprep_foll_time: {aprep_foll_time}")


                # Execution stage step 1: perform computation of the current layer
                exec_time = time.time()
                gate_tape = []
                for i in range(cm): 
                    gate_tape.append(1)
                for i in range(w-cm):
                    gate_tape.append(0)
                gate_inputs = new_shares + new_shares
                gate_outputs = await self.run_computation(gate_inputs, gate_tape, new_mult_triples)
                exec_time = time.time() - exec_time
                print(f"layer ID: {self.layer_ID} exec_time: {exec_time}")


                if self.layer_ID + 1 == len(self.admpc_control_instance.pks_all) - 1: 
                    # Execution stage step 4: call Trans protocol to send circuit outputs to the next layer
                    trans_pre_time = time.time()
                    transtag = ADMPCMsgType.TRANS + str(self.layer_ID+1)
                    transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)

                    trans_pre = Trans_Pre(self.public_keys, self.private_key, 
                                    self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                    transsend, transrecv, self.pc, self.curve_params, mpc_instance=self)
                    trans_pre_task = asyncio.create_task(trans_pre.run_trans(gate_outputs, rand_shares))
                    
                    self.admpc_control_instance.control_signal.set()
                    trans_pre_time = time.time() - trans_pre_time
                    print(f"layer ID: {self.layer_ID} trans_pre_time: {trans_pre_time}")
                else: 

                    rand_pre_time = time.time()
                    r_num = 2 * w + 1 
                    if r_num > self.n - self.t: 
                        rounds = math.ceil(r_num / (self.n - self.t))
                    else: 
                        rounds = 1

                    randtag = ADMPCMsgType.GENRAND + str(self.layer_ID+1)
                    randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)

                    rand_pre = Rand_Pre(self.public_keys, self.private_key, 
                                        self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                        randsend, randrecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)
                    rand_pre_task = asyncio.create_task(rand_pre.run_rand(r_num, rounds))
                    rand_pre_time = time.time() - rand_pre_time
                    print(f"layer ID: {self.layer_ID} rand_pre_time: {rand_pre_time}")


                    aprep_pre_time = time.time()
                    apreptag = ADMPCMsgType.APREP + str(self.layer_ID+1)
                    aprepsend, apreprecv = self.get_send(apreptag), self.subscribe_recv(apreptag)

                    aprep_pre = APREP_Pre(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                aprepsend, apreprecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)
                    aprep_pre_task = asyncio.create_task(aprep_pre.run_aprep(cm))
                    aprep_pre_time = time.time() - aprep_pre_time
                    print(f"layer ID: {self.layer_ID} aprep_pre_time: {aprep_pre_time}")

                    # Execution stage step 4: call Trans protocol to send circuit outputs to the next layer
                    trans_pre_time = time.time()
                    transtag = ADMPCMsgType.TRANS + str(self.layer_ID+1)
                    transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)

                    trans_pre = Trans_Pre(self.public_keys, self.private_key, 
                                    self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                    transsend, transrecv, self.pc, self.curve_params, mpc_instance=self)
                    trans_pre_task = asyncio.create_task(trans_pre.run_trans(gate_outputs, rand_shares))
                        
                    self.admpc_control_instance.control_signal.set()
                    trans_pre_time = time.time() - trans_pre_time
                    print(f"layer ID: {self.layer_ID} trans_pre_time: {trans_pre_time}")
                        
        layer_time = time.time() - layer_time
        print(f"layer ID: {self.layer_ID} layer_time: {layer_time}")
        
        