from adkg.polynomial import polynomials_over, EvalPoint
from adkg.utils.poly_misc import interpolate_g1_at_x
from adkg.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib, time
from math import ceil
import logging
from adkg.utils.bitmap import Bitmap
from adkg.acss import ACSS, ACSS_Foll, ACSS_Pre, ACSS_Fluid_Pre, ACSS_Fluid_Foll
from adkg.router import SimpleRouter

from adkg.broadcast.tylerba import tylerba
from adkg.broadcast.optqrbc import optqrbc, optqrbc_dynamic

from adkg.preprocessing import PreProcessedElements

from adkg.mpc import TaskProgramRunner
from adkg.robust_rec import robust_reconstruct_admpc, Robust_Rec
from adkg.trans import Trans, Trans_Pre, Trans_Foll, Trans_Fluid_Foll, Trans_Fluid_Pre
from adkg.rand import Rand, Rand_Pre, Rand_Foll, Rand_Fluid_Pre, Rand_Fluid_Foll
from adkg.aprep import APREP, APREP_Pre, APREP_Foll
import math

from adkg.utils.serilization import Serial
from adkg.field import GF, GFElement
from adkg.elliptic_curve import Subgroup

import random
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
            logging.info("Fluid MPC task finished")
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    

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


# 管理所有的MPC实例
class ADMPC_Multi_Layer_Control():
    def __init__(self, n=None, t= None, deg=None, layer_num=None, total_cm=None, pks=None):
        # 初始化
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
        """生成 layer_num * n 个mpc instances(存在self.admpc_lists中,具体的run_admpc存在admpc_tasks中)"""
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
        # self.public_keys = public_keys[n*layerID:n*layerID+n]
        self.sc = ceil((deg+1)/(t+1)) + 1
        self.Signal = asyncio.Event()
        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrices)


    async def commonsubset(self, rbc_out, rbc_signal, rbc_values, coin_keys, aba_in, aba_out):
        assert len(rbc_out) == self.n
        assert len(aba_in) == self.n
        assert len(aba_out) == self.n

        aba_inputted = [False]*self.n
        aba_values = [0]*self.n

        async def _recv_rbc(j):
            # rbc_values[j] = await rbc_out[j]
            rbcl = await rbc_out[j].get()
            # print(f"rbcl: {rbcl}")
            rbcb = Bitmap(self.n, rbcl)
            # print(f"rbcb: {rbcb}")
            rbc_values[j] = []
            # for i in range(self.n): 
            #     print(f"{self.my_id} receives {i} {rbcb.get_bit(i)}")
            for i in range(self.n):
                if rbcb.get_bit(i):
                    rbc_values[j].append(i)
            # print(f"rbc_values[{j}]: {rbc_values[j]}")        
            
            if not aba_inputted[j]:
                aba_inputted[j] = True
                aba_in[j](1)
            
            subset = True
            # while True:
            #     acss_signal.clear()
            #     for k in rbc_values[j]:
            #         if k not in acss_outputs.keys():
            #             subset = False
            #     if subset:
            #         coin_keys[j]((acss_outputs, rbc_values[j]))
            #         return
            #     await acss_signal.wait()

        r_threads = [asyncio.create_task(_recv_rbc(j)) for j in range(self.n)]

        async def _recv_aba(j):
            aba_values[j] = await aba_out[j]()  # May block

            if sum(aba_values) >= 1:
                # Provide 0 to all other aba
                for k in range(self.n):
                    if not aba_inputted[k]:
                        aba_inputted[k] = True
                        aba_in[k](0)
        
        await asyncio.gather(*[asyncio.create_task(_recv_aba(j)) for j in range(self.n)])
        # assert sum(aba_values) >= self.n - self.t  # Must have at least N-f committed
        assert sum(aba_values) >= 1  # Must have at least N-f committed

        # Wait for the corresponding broadcasts
        for j in range(self.n):
            if aba_values[j]:
                await r_threads[j]
                assert rbc_values[j] is not None
            else:
                r_threads[j].cancel()
                rbc_values[j] = None

        rbc_signal.set()
    
    async def agreement(self, key_proposal):
        
        aba_inputs = [asyncio.Queue() for _ in range(self.n)]
        aba_outputs = [asyncio.Queue() for _ in range(self.n)]
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        
        coin_keys = [asyncio.Queue() for _ in range(self.n)]

        member_list = []
        for i in range(self.n): 
            member_list.append(self.n * (self.layer_ID) + i)

        async def predicate(_key_proposal):
            kp = Bitmap(self.n, _key_proposal)
            kpl = []
            for ii in range(self.n):
                if kp.get_bit(ii):
                    kpl.append(ii)
            # print(f"kpl: {kpl}")
            # print(f"de_masked_value: {de_masked_value}")
            if len(kpl) <= self.t:
                return False
            
            
            return True

        async def _setup(j):
            
            # starting RBC
            rbctag = ADMPCMsgType.RBC + str(j) # (R, msg)
            # rbctag = TRANSMsgType.RBC + str(j)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id: 
                # print(f"key_proposal: {key_proposal}")
                riv = Bitmap(self.n)
                for k in key_proposal: 
                    riv.set_bit(k)
                rbc_input = bytes(riv.array)

            # rbc_outputs[j] = 
            asyncio.create_task(
                optqrbc_dynamic(
                    rbctag,
                    self.my_id,
                    self.n,
                    self.t,
                    j,
                    predicate,
                    rbc_input,
                    rbc_outputs[j].put_nowait,
                    rbcsend,
                    rbcrecv,
                    member_list
                )
            )

            abatag = ADMPCMsgType.ABA + str(j) # (B, msg)
            # abatag = TRANSMsgType.ABA + str(j)
            # abatag = j # (B, msg)
            abasend, abarecv =  self.get_send(abatag), self.subscribe_recv(abatag)

            def bcast(o):
                for i in range(len(member_list)):
                    abasend(member_list[i], o)
                
            aba_task = asyncio.create_task(
                tylerba(
                    abatag,
                    self.my_id,
                    self.n,
                    self.t,
                    coin_keys[j].get,
                    aba_inputs[j].get,
                    aba_outputs[j].put_nowait,
                    bcast,
                    abarecv,
                )
            )
            return aba_task

        work_tasks = await asyncio.gather(*[_setup(j) for j in range(self.n)])
        
        rbc_signal = asyncio.Event()
        rbc_values = [None for i in range(self.n)]

        return (
            self.commonsubset(
                rbc_outputs,
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.new_subset(
                rbc_values,
                rbc_signal,
                
            ),
            work_tasks,
        )

    async def new_subset(self, rbc_values, rbc_signal):
        await rbc_signal.wait()
        rbc_signal.clear()


        self.mks = set() # master key set
        for ks in  rbc_values:
            if ks is not None:
                self.mks = self.mks.union(set(list(ks)))
                if len(self.mks) >= self.n-self.t:
                    break

        mks_list = sorted(self.mks)
        

        return mks_list
    
    
    async def run_admpc(self, start_time):
        acss_start_time = time.time()
        self.public_keys = self.public_keys[self.n*self.layer_ID:self.n*self.layer_ID+self.n]
        cm = int(self.admpc_control_instance.total_cm/(self.admpc_control_instance.layer_num-4))
        w = cm * 2

        input_num = w * 2
        print(f"cm: {cm} total_cm: {self.admpc_control_instance.total_cm}")

        layer_time = time.time()

        # Assume that when layer_ID = 0, clients provide inputs to servers
        if self.layer_ID == 0:

            # The number of client input values should be equal to 2 * w
            inputs_num = int((2*(w))/self.n) + 1
            clients_inputs = []
            for i in range(inputs_num):
                clients_inputs.append(self.ZR.rand())
            
            acss_pre_time = time.time()
            pks_next_layer = self.admpc_control_instance.pks_all[self.layer_ID + 1]       

            
            acsstag = ADMPCMsgType.ACSS + str(self.layer_ID+1) + str(self.my_id)
            acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

            self.acss = ACSS_Fluid_Pre(pks_next_layer, 
                                self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                mpc_instance=self
                            )
            self.acss_tasks = [None] * self.n
                    
            self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, values=clients_inputs))
            await self.acss_tasks[self.my_id]
            acss_pre_time = time.time() - acss_pre_time
            print(f"layer ID: {self.layer_ID} acss_pre_time: {acss_pre_time}")

            # Clients step 2: invoke Rand protocol to transmit random values to the next layer
            rand_pre_time = time.time()
            mac_keys = w + 2
            if mac_keys > self.n - self.t: 
                rounds = math.ceil(mac_keys / (self.n - self.t))
            else: 
                rounds = 1

            randtag = ADMPCMsgType.GENRAND + str(self.layer_ID+1)
            randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)

            rand_pre = Rand_Fluid_Pre(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                randsend, randrecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)
            rand_pre_task = asyncio.create_task(rand_pre.run_rand(mac_keys, rounds))
            await rand_pre_task
            rand_pre_time = time.time() - rand_pre_time
            print(f"layer ID: {self.layer_ID} rand_pre_time: {rand_pre_time}")


        elif self.layer_ID == 1: 
            recv_input_time = time.time()
            self.acss_tasks = [None] * self.n
            # for dealer_id in range(self.n - 1, -1, -1): 
            for dealer_id in range(self.n): 
                
                acsstag = ADMPCMsgType.ACSS + str(self.layer_ID) + str(dealer_id)
                acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

                
                self.acss = ACSS_Fluid_Foll(self.public_keys, self.private_key, 
                                    self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                    acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                    mpc_instance=self
                                )
                
                inputs_num = int((2 * w) / self.n) + 1
                
                self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, dealer_id, inputs_num))
                
            done, pending = await asyncio.wait(self.acss_tasks, return_when=asyncio.ALL_COMPLETED)
    
            results = [task.result() for task in done]
            dealer, _, shares, commitments = zip(*results)
                
            # MVBA
            fluid_mvba_time = time.time()
            key_proposal = []
            key_proposal = random.sample(dealer, self.n - self.t)  
            create_acs_task = asyncio.create_task(self.agreement(key_proposal))

            acs, key_task, work_tasks = await create_acs_task
            await acs
            subset = await key_task
            await asyncio.gather(*work_tasks)
            fluid_mvba_time = time.time() - fluid_mvba_time
            print(f"fluid_mvba_time: {fluid_mvba_time} layer ID: {self.layer_ID} my id: {self.my_id} common_subset: {subset}")
            
            new_shares = []
            for i in range(len(dealer)): 
                for j in range(len(shares[i]['msg'])): 
                    new_shares.append(shares[i]['msg'][j])
            recv_input_time = time.time() - recv_input_time
            print(f"layer ID: {self.layer_ID} recv_input_time: {recv_input_time}")
            


            rand_foll_time = time.time()
            randtag = ADMPCMsgType.GENRAND + str(self.layer_ID)
            randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
            rand_foll = Rand_Fluid_Foll(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                                randsend, randrecv, self.pc, self.curve_params, self.matrix, mpc_instance=self)

            mac_keys = w + 2
            if mac_keys > self.n - self.t: 
                rounds = math.ceil(mac_keys / (self.n - self.t))
            else: 
                rounds = 1
            rand_shares = await rand_foll.run_rand(mac_keys, rounds)
            rand_foll_time = time.time() - rand_foll_time
            print(f"layer ID: {self.layer_ID} rand_foll_time: {rand_foll_time} len rand_shares: {len(rand_shares)} ")
            
            
            input_shares = [None] * input_num
            masked_shares = [None] * input_num
            for i in range(input_num):
                masked_shares[i] = new_shares[0] * rand_shares[0]
                input_shares[i] = new_shares[0]

            if self.layer_ID + 1 < len(self.admpc_control_instance.pks_all):

                trans_values = input_shares + masked_shares + rand_shares
                acss_pre_time = time.time()
                pks_next_layer = self.admpc_control_instance.pks_all[self.layer_ID + 1]       

                
                acsstag = ADMPCMsgType.ACSS + str(self.layer_ID+1) + str(self.my_id)
                acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

                self.acss = ACSS_Fluid_Pre(pks_next_layer, 
                                    self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                    acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                    mpc_instance=self
                                )
                self.acss_tasks = [None] * self.n
                                     
                
                self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, values=trans_values))

                await self.acss_tasks[self.my_id]
                
                acss_pre_time = time.time() - acss_pre_time
                print(f"layer ID: {self.layer_ID} acss_pre_time: {acss_pre_time}")

            else: 
                print("over")
        elif self.layer_ID == 2: 
            recv_input_time = time.time()
            self.acss_tasks = [None] * self.n
            for dealer_id in range(self.n): 
                
                acsstag = ADMPCMsgType.ACSS + str(self.layer_ID) + str(dealer_id)
                acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

                
                self.acss = ACSS_Fluid_Foll(self.public_keys, self.private_key, 
                                    self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                    acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                    mpc_instance=self
                                )
                
                # At this layer (layer = 2), the received shares consist of: original inputs + r-multiplied masked_values + random values (w+2)
                rounds = input_num * 2 + w + 2
                self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, dealer_id, rounds))


            done, pending = await asyncio.wait(self.acss_tasks, return_when=asyncio.ALL_COMPLETED)
    
                                                   
    
            results = [task.result() for task in done]
            dealer, _, shares, commitments = zip(*results)


            # mvba
            fluid_mvba_time = time.time()
            key_proposal = []
            # for i in range(self.n - self.t): key_proposal.append(dealer[i])
            key_proposal = random.sample(dealer, self.n - self.t)  # 从dealer随机选择n-t个不重复的元素
            create_acs_task = asyncio.create_task(self.agreement(key_proposal))

            acs, key_task, work_tasks = await create_acs_task
            await acs
            subset = await key_task
            await asyncio.gather(*work_tasks)
            fluid_mvba_time = time.time() - fluid_mvba_time
            print(f"fluid_mvba_time: {fluid_mvba_time} layer ID: {self.layer_ID} my id: {self.my_id} common_subset: {subset}")
            
            new_shares = []
            for i in range(len(dealer)): 
                for j in range(len(shares[i]['msg'])): 
                    new_shares.append(shares[i]['msg'][j])
            recv_input_time = time.time() - recv_input_time


            print(f"layer ID: {self.layer_ID} recv_input_time: {recv_input_time}")

            inter_shares = [[None for i in range(self.n)] for j in range(rounds)]
            for i in range(rounds):
                for j in range(self.n):
                    inter_shares[i][j] = new_shares[i*self.n+j]

            sc_shares = [] 
            for i in range(len(inter_shares)): 
                sc_shares.append([])
                for j in range(len(inter_shares[0])): 
                    sc_shares[i].append([j+1, inter_shares[i][j]])            
            
            rec_shares = [None] * len(inter_shares)
            for i in range(len(inter_shares)): 
                rec_shares[i] = self.poly.interpolate_at(sc_shares[i], 0)


            # execution stage a*b, ra*b, \alpha*\beta, \alpha*c, \alpha*rc
            input_shares = rec_shares[:input_num]
            masked_shares = rec_shares[input_num:2*input_num]
            rand_shares = rec_shares[2*input_num:]
            output_shares = [None] * w
            output_masked_shares = [None] * w
            current_rand_shares = [None] * w
            rand_last_layer_outputs = [None] * w
            rand_last_layer_masked_outputs = [None] * w
            for i in range(w):
                output_shares[i] = input_shares[0] * input_shares[1]    # a*b
                output_masked_shares[i] = input_shares[0] * masked_shares[0]    # ra*b
                current_rand_shares[i] = rand_shares[1] * rand_shares[2]    # \alpha*\beta
                rand_last_layer_outputs[i] = rand_shares[2] * input_shares[0]   # \alpha*c
                rand_last_layer_masked_outputs[i] = rand_shares[2] * masked_shares[0]   # \alpha*rc

           
            trans_values = output_shares + output_masked_shares + current_rand_shares + rand_last_layer_outputs + rand_last_layer_masked_outputs + rand_shares
            
            acss_pre_time = time.time()
            pks_next_layer = self.admpc_control_instance.pks_all[self.layer_ID + 1]       

            
            acsstag = ADMPCMsgType.ACSS + str(self.layer_ID+1) + str(self.my_id)
            acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

            self.acss = ACSS_Fluid_Pre(pks_next_layer, 
                                self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                mpc_instance=self
                            )
            self.acss_tasks = [None] * self.n
                 
            test_value = [trans_values[0]]
            
            self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, values=trans_values))
            await self.acss_tasks[self.my_id]
            acss_pre_time = time.time() - acss_pre_time
            print(f"layer ID: {self.layer_ID} acss_pre_time: {acss_pre_time}")
                
            

        
        else:
            if self.layer_ID + 1 == len(self.admpc_control_instance.pks_all):
                recv_input_time = time.time()
                self.acss_tasks = [None] * self.n
                for dealer_id in range(self.n): 
                    
                    acsstag = ADMPCMsgType.ACSS + str(self.layer_ID) + str(dealer_id)
                    acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

                    
                    self.acss = ACSS_Fluid_Foll(self.public_keys, self.private_key, 
                                        self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                        acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                        mpc_instance=self
                                    )
                    
                    rounds = w + 3
                    self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, dealer_id, rounds))


                done, pending = await asyncio.wait(self.acss_tasks, return_when=asyncio.ALL_COMPLETED)
    
                
                results = [task.result() for task in done]
                dealer, _, shares, commitments = zip(*results)

                 # mvba
                fluid_mvba_time = time.time()
                key_proposal = []
                # for i in range(self.n - self.t): key_proposal.append(dealer[i])
                key_proposal = random.sample(dealer, self.n - self.t)  # 从dealer随机选择n-t个不重复的元素
                create_acs_task = asyncio.create_task(self.agreement(key_proposal))

                acs, key_task, work_tasks = await create_acs_task
                await acs
                subset = await key_task
                await asyncio.gather(*work_tasks)
                fluid_mvba_time = time.time() - fluid_mvba_time
                print(f"fluid_mvba_time: {fluid_mvba_time} layer ID: {self.layer_ID} my id: {self.my_id} common_subset: {subset}") 
                
                new_shares = []
                for i in range(len(dealer)): 
                    for j in range(len(shares[i]['msg'])): 
                        new_shares.append(shares[i]['msg'][j])
                recv_input_time = time.time() - recv_input_time
                
                
                print(f"layer ID: {self.layer_ID} recv_input_time: {recv_input_time}")

                inter_shares = [[None for i in range(self.n)] for j in range(rounds)]
                for i in range(rounds):
                    for j in range(self.n):
                        inter_shares[i][j] = new_shares[i*self.n+j]

                sc_shares = [] 
                for i in range(len(inter_shares)): 
                    sc_shares.append([])
                    for j in range(len(inter_shares[0])): 
                        sc_shares[i].append([j+1, inter_shares[i][j]])            
                
                rec_shares = [None] * len(inter_shares)
                for i in range(len(inter_shares)): 
                    rec_shares[i] = self.poly.interpolate_at(sc_shares[i], 0)


            
            else: 
                recv_input_time = time.time()
                self.acss_tasks = [None] * self.n
                for dealer_id in range(self.n): 
                    
                    acsstag = ADMPCMsgType.ACSS + str(self.layer_ID) + str(dealer_id)
                    acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

                    
                    self.acss = ACSS_Fluid_Foll(self.public_keys, self.private_key, 
                                        self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                        acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                        mpc_instance=self
                                    )
                    
                    if self.layer_ID == 3:
                        rounds = 6 * w + 2
                   
                    else: 
                        rounds = 6 * w + 4
                    self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, dealer_id, rounds))


                    
                done, pending = await asyncio.wait(self.acss_tasks, return_when=asyncio.ALL_COMPLETED)
    
                
                results = [task.result() for task in done]
                dealer, _, shares, commitments = zip(*results)
                    
                # MVBA
                fluid_mvba_time = time.time()
                key_proposal = []
                # for i in range(self.n - self.t): key_proposal.append(dealer[i])
                key_proposal = random.sample(dealer, self.n - self.t)  # 从dealer随机选择n-t个不重复的元素
                create_acs_task = asyncio.create_task(self.agreement(key_proposal))

                acs, key_task, work_tasks = await create_acs_task
                await acs
                subset = await key_task
                await asyncio.gather(*work_tasks)
                fluid_mvba_time = time.time() - fluid_mvba_time
                print(f"fluid_mvba_time: {fluid_mvba_time} layer ID: {self.layer_ID} my id: {self.my_id} common_subset: {subset}")

                new_shares = []
                for i in range(len(dealer)): 
                    for j in range(len(shares[i]['msg'])): 
                        new_shares.append(shares[i]['msg'][j])
                recv_input_time = time.time() - recv_input_time

                print(f"layer ID: {self.layer_ID} recv_input_time: {recv_input_time}")

                inter_shares = [[None for i in range(self.n)] for j in range(rounds)]
                for i in range(rounds):
                    for j in range(self.n):
                        inter_shares[i][j] = new_shares[i*self.n+j]

                sc_shares = [] 
                for i in range(len(inter_shares)): 
                    sc_shares.append([])
                    for j in range(len(inter_shares[0])): 
                        sc_shares[i].append([j+1, inter_shares[i][j]])            
                
                rec_shares = [None] * len(inter_shares)
                for i in range(len(inter_shares)): 
                    rec_shares[i] = self.poly.interpolate_at(sc_shares[i], 0)


                if self.layer_ID < len(self.admpc_control_instance.pks_all) - 1:
                    len_rec_shares = len(rec_shares)
                    
                    if self.layer_ID + 1 == len(self.admpc_control_instance.pks_all) - 1: 

                        z = rec_shares[:w]

                        trans_shares = z + [rec_shares[0]] + [rec_shares[0]] + [rec_shares[0]]

                        acss_pre_time = time.time()
                        pks_next_layer = self.admpc_control_instance.pks_all[self.layer_ID + 1]       

                        
                        acsstag = ADMPCMsgType.ACSS + str(self.layer_ID+1) + str(self.my_id)
                        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

                        self.acss = ACSS_Fluid_Pre(pks_next_layer, 
                                            self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                            acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                            mpc_instance=self
                                        )
                        self.acss_tasks = [None] * self.n
                             
                        self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, values=trans_shares))
                        await self.acss_tasks[self.my_id]
                        acss_pre_time = time.time() - acss_pre_time
                        print(f"layer ID: {self.layer_ID} acss_pre_time: {acss_pre_time}")
                        
                    
                    else: 

                        # execution stage a*b, ra*b, \alpha*\beta, \alpha*c, \alpha*rc
                        input_shares = rec_shares[:w]
                        masked_shares = rec_shares[w:2*w]


                        rand_shares = rec_shares[:w+2]
                        u = rec_shares[0]
                        v = rec_shares[1]

                        output_shares = [None] * w
                        output_masked_shares = [None] * w
                        current_rand_shares = [None] * w
                        rand_last_layer_outputs = [None] * w
                        rand_last_layer_masked_outputs = [None] * w

                        for i in range(w):
                            output_shares[i] = input_shares[0] * input_shares[1]    # a*b
                            output_masked_shares[i] = input_shares[0] * masked_shares[0]    # ra*b
                            current_rand_shares[i] = rand_shares[1] * rand_shares[2]    # \alpha*\beta
                            rand_last_layer_outputs[i] = rand_shares[2] * input_shares[0]   # \alpha*c
                            rand_last_layer_masked_outputs[i] = rand_shares[2] * masked_shares[0]   # \alpha*rc
                        
                        trans_values = output_shares + output_masked_shares + current_rand_shares + rand_last_layer_outputs + rand_last_layer_masked_outputs + rand_shares + [u] + [v]
                        acss_pre_time = time.time()
                        pks_next_layer = self.admpc_control_instance.pks_all[self.layer_ID + 1]       

                        
                        acsstag = ADMPCMsgType.ACSS + str(self.layer_ID+1) + str(self.my_id)
                        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

                        self.acss = ACSS_Fluid_Pre(pks_next_layer, 
                                            self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                            acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                            mpc_instance=self
                                        )
                        self.acss_tasks = [None] * self.n
                             
                        
                        self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, values=trans_values))
                        await self.acss_tasks[self.my_id]
                        acss_pre_time = time.time() - acss_pre_time
                        print(f"layer ID: {self.layer_ID} acss_pre_time: {acss_pre_time}")
                        
                        

        layer_time = time.time() - layer_time
        print(f"layer ID: {self.layer_ID} layer_time: {layer_time}")
    
        