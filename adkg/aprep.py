from adkg.polynomial import polynomials_over, EvalPoint
from adkg.utils.poly_misc import interpolate_g1_at_x
from adkg.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib, time
from math import ceil
import logging
from adkg.utils.bitmap import Bitmap
from adkg.acss import ACSS, ACSS_Pre, ACSS_Foll

from adkg.broadcast.tylerba import tylerba
from adkg.broadcast.optqrbc import optqrbc, optqrbc_dynamic

from adkg.preprocessing import PreProcessedElements

from adkg.mpc import TaskProgramRunner
from adkg.utils.serilization import Serial
from adkg.rand import Rand, Rand_Pre, Rand_Foll
from adkg.robust_rec import Robust_Rec
import math

from adkg.field import GF, GFElement
from adkg.ntl import vandermonde_batch_evaluate
from adkg.elliptic_curve import Subgroup
from adkg.progs.mixins.dataflow import Share
from adkg.robust_reconstruction import robust_reconstruct_admpc, robust_rec_admpc

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)

class APREPMsgType:
    ACSS = "AP.A"
    RBC = "AP.R"
    ABA = "AP.B"
    PREKEY = "AP.P"
    KEY = "AP.K"
    MASK = "AP.M"
    GENRAND = "AP.GR"
    ROBUSTREC = "AP.RR"
    APREP = "AP.AP"
    
class APREP:
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix):
        self.public_keys, self.private_key, self.g, self.h = (public_keys, private_key, g, h)
        self.n, self.t, self.deg, self.my_id = (n, t, deg, my_id)
        self.sc = ceil((deg+1)/(t+1)) + 1
        self.send, self.recv, self.pc = (send, recv, pc)
        self.ZR, self.G1, self.multiexp, self.dotprod = curve_params
        self.matrix = matrix
        # print(f"type(self.ZR): {type(self.ZR)}")
        self.poly = polynomials_over(self.ZR)
        self.poly.clear_cache() #FIXME: Not sure why we need this.
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send
        self.output_queue = asyncio.Queue()

        rectag = APREPMsgType.ROBUSTREC
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
            logging.info("APREP task finished")
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def acss_step(self, outputs, aprep_values, acss_signal):
        
        acsstag = APREPMsgType.ACSS
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        self.acss = ACSS(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, acsssend, acssrecv, self.pc, self.ZR, self.G1
                         )
        self.acss_tasks = [None] * self.n
        
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss_aprep(0, values=aprep_values))
            else:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss_aprep(0, dealer_id=i))

        while True:
            (dealer, _, shares, commitments) = await self.acss.output_queue.get()
            outputs[dealer] = {'shares':shares, 'commits':commitments}
            
            if len(outputs) >= self.n - self.t:
                # print("Player " + str(self.my_id) + " Got shares from: " + str([output for output in outputs]))
                acss_signal.set()

            if len(outputs) == self.n:
                return    

    async def commonsubset(self, rbc_out, mult_triples_shares, rec_tau, cm, rbc_signal, rbc_values, coin_keys, aba_in, aba_out):
        assert len(rbc_out) == self.n
        assert len(aba_in) == self.n
        assert len(aba_out) == self.n

        aba_inputted = [False]*self.n
        aba_values = [0]*self.n

        async def _recv_rbc(j):
            rbcl = await rbc_out[j].get()
            rbcb = Bitmap(self.n, rbcl)
            rbc_values[j] = []
          
            for i in range(self.n):
                if rbcb.get_bit(i):
                    rbc_values[j].append(i)
            # print(f"rbc_values[{j}]: {rbc_values[j]}")        
            
            if not aba_inputted[j]:
                aba_inputted[j] = True
                aba_in[j](1)
            
            subset = True
            while True:
                
                if subset:
                    coin_keys[j]((mult_triples_shares, rbc_values[j]))
                    return

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
    
    async def agreement(self, key_proposal, mult_triples_shares, rec_tau, cm):
        aba_inputs = [asyncio.Queue() for _ in range(self.n)]
        aba_outputs = [asyncio.Queue() for _ in range(self.n)]
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        
        coin_keys = [asyncio.Queue() for _ in range(self.n)]

        async def predicate(_key_proposal):
            kp = Bitmap(self.n, _key_proposal)
            kpl = []
            for ii in range(self.n):
                if kp.get_bit(ii):
                    kpl.append(ii)
            if len(kpl) <= self.t:
                return False
            while True:
                subset = True
                for kk in kpl:
                    for i in range(cm): 
                        if rec_tau[kk][i] != self.ZR(0): 
                            print(f"false")
                            subset = False
                    
                if subset:
                    return True
                

        async def _setup(j):
            
            # starting RBC
            rbctag =APREPMsgType.RBC + str(j) # (R, msg)
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
                optqrbc(
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
                )
            )

            abatag = APREPMsgType.ABA + str(j) # (B, msg)
            # abatag = j # (B, msg)
            abasend, abarecv =  self.get_send(abatag), self.subscribe_recv(abatag)

            def bcast(o):
                for i in range(self.n):
                    abasend(i, o)
                
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
                mult_triples_shares,
                rec_tau,
                cm,
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.new_triples(
                mult_triples_shares,
                cm,
                rbc_values,
                rbc_signal,
            ),
            work_tasks,
        )

    async def new_triples(self, mult_triples_shares, cm, rbc_values, rbc_signal):
        await rbc_signal.wait()
        rbc_signal.clear()


        self.mks = set() # master key set
        for ks in  rbc_values:
            if ks is not None:
                self.mks = self.mks.union(set(list(ks)))
                if len(self.mks) >= self.n-self.t:
                    break
        T_list = sorted(self.mks)

        # step 13
        u = [[self.ZR(0) for _ in range(2*self.t+1)] for _ in range(cm)]
        v = [[self.ZR(0) for _ in range(2*self.t+1)] for _ in range(cm)]
        w = [[self.ZR(0) for _ in range(2*self.t+1)] for _ in range(cm)]
        for i in range(cm): 
            for j in range(self.t+1): 
                index = T_list[j]
                u[i][j] = mult_triples_shares[index][i][0]
                v[i][j] = mult_triples_shares[index][i][1]
                w[i][j] = mult_triples_shares[index][i][2]
        
        u_poly, v_poly, w_poly = [], [], []
        for i in range(cm):
            u_poly.append([])
            v_poly.append([])
            # w_poly.append([])
            for j in range(self.t+1): 
                u_poly[i].append([T_list[j]+1, u[i][j]])
                v_poly[i].append([T_list[j]+1, v[i][j]])
            
        # step 14
        for i in range(cm):
            for j in range(self.t+1, 2*self.t+1): 
                index = T_list[j] + 1
                u[i][j] = self.poly.interpolate_at(u_poly[i], index)
                v[i][j] = self.poly.interpolate_at(v_poly[i], index)

        # step 15
        d = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]
        e = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]  
        for i in range(cm):
            for j in range(self.t): 
                index1 = j + self.t + 1
                index2 = T_list[index1]
                d[i][j] = u[i][index1] - mult_triples_shares[index2][i][0]
                e[i][j] = v[i][index1] - mult_triples_shares[index2][i][1]
            

        # step 16
        d_list, e_list = [], []
        for i in range(cm): 
            d_list += d[i]
            e_list += e[i]
        rec_list = d_list + e_list
        # robust_rec = await self.robust_rec_step(rec_list, 3)
        rec_task3 = asyncio.create_task(self.rec_step(rec_list, 3))
        (mks, robust_rec) = await rec_task3
        # robust_rec_d = await self.robust_rec_step(d_list, robust_rec_sig)
  
        # robust_rec_e = await self.robust_rec_step(e_list, robust_rec_sig)
        robust_rec_d = robust_rec[:int(len(robust_rec)/2)]
        robust_rec_e = robust_rec[int(len(robust_rec)/2):]
        
        rec_d = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]
        rec_e = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]
        for i in range(cm):
            for j in range(self.t): 
                rec_d[i][j] = robust_rec_d[i*self.t+j]
                rec_e[i][j] = robust_rec_e[i*self.t+j]

        # step 17    
        for i in range(cm):
            for j in range(self.t): 
                index1 = j + self.t + 1
                index2 = T_list[index1]
                w[i][index1] = rec_d[i][j] * rec_e[i][j] + rec_d[i][j] * mult_triples_shares[index2][i][1] + rec_e[i][j] * mult_triples_shares[index2][i][0] + mult_triples_shares[index2][i][2]

        # step 18
        for i in range(cm):
            w_poly.append([])
            for j in range(2*self.t+1): 
                w_poly[i].append([T_list[j]+1, w[i][j]])
        u_point, v_point, w_point = [None] * cm, [None] * cm, [None] * cm
        for i in range(cm):
            point = 3 * self.t + 2
            u_point[i] = self.poly.interpolate_at(u_poly[i], point)
            v_point[i] = self.poly.interpolate_at(v_poly[i], point)
            w_point[i] = self.poly.interpolate_at(w_poly[i], point)

        aprep_triples = []
        for i in range(cm): 
            aprep_triples.append([])
            aprep_triples[i].append(u_point[i])
            aprep_triples[i].append(v_point[i])
            aprep_triples[i].append(w_point[i])
            

        
        return aprep_triples
    
    
    async def gen_rand_step(self, rand_num, rand_outputs, rand_signal):
        
        if rand_num > self.n - self.t: 
            rounds = math.ceil(rand_num / (self. n - self.t))
        else: 
            rounds = 1
        randtag = APREPMsgType.GENRAND
        randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
        curve_params = (self.ZR, self.G1, self.multiexp, self.dotprod)
        self.rand = Rand(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, randsend, randrecv, self.pc, curve_params, self.matrix)
        self.rand_task = asyncio.create_task(self.rand.run_rand(rand_num, rounds))

        while True: 
            # rand_outputs = await self.rand.output_queue.get()
            rand_outputs = await self.rand_task

            if len(rand_outputs) == rand_num: 
                # print(f"my id: {self.my_id} rand_outputs: {rand_outputs}")
                rand_signal.set()
                return rand_outputs
            
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

            if len(outputs) == self.n:


                sr = Serial(self.G1)

                deserialized_rbc_list = [sr.deserialize_fs(item) for item in outputs]

                rbc_shares = [[None for _ in range(len(outputs))] for _ in range(len(deserialized_rbc_list[0]))]

                for i in range(len(deserialized_rbc_list[0])):
                    for node in range(len(deserialized_rbc_list)):
                        rbc_shares[i][node] = deserialized_rbc_list[node][i]



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
                # print(f"my id: {self.my_id} key_proposal: {key_proposal}")

                return (key_proposal, rec_values)

                

            if len(outputs) == self.n:
                return 
        
   
    async def run_aprep(self, cm):
        run_aprep_start_time = time.time()
        gen_rand_outputs = []
        gen_rand_signal = asyncio.Event()

        # invoke Protocol Rand to generate random shares
        gen_rand_outputs = await self.gen_rand_step(self.n*cm, gen_rand_outputs, gen_rand_signal)
        

        acss_outputs = {}
        acss_signal = asyncio.Event()

        # Each participant generates the multiplication triples needed for the next epoch
        mult_triples = [[self.ZR.rand() for _ in range(3)] for _ in range(cm)]
        chec_triples = [[self.ZR.rand() for _ in range(3)] for _ in range(cm)]
        # rand_values = [None] * cm
        for i in range(cm): 
            mult_triples[i][2] = mult_triples[i][0] * mult_triples[i][1]
            chec_triples[i][2] = chec_triples[i][0] * chec_triples[i][1]

        aprep_values = (mult_triples, chec_triples, cm)      

        self.acss_task = asyncio.create_task(self.acss_step(acss_outputs, aprep_values, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()

        await gen_rand_signal.wait()
        gen_rand_signal.clear()

        # invoke Protocol Robust-Rec 
        # robust_rec_outputs = []
        rec_task = asyncio.create_task(self.rec_step(gen_rand_outputs, 0))
        (mks, robust_rec_outputs) = await rec_task
        mks_list = sorted(mks)


        mult_triples_shares = {}
        chec_triples_shares = {}
        rands = {}



        for node in mks_list:
            if node in acss_outputs:
                output = acss_outputs[node]

                mult_triples_shares[node] = [[self.ZR(0)] * 3 for _ in range(cm)]
                chec_triples_shares[node] = [[self.ZR(0)] * 3 for _ in range(cm)]
                rands[node] = [self.ZR(0)] * cm

                msg_flat = output['shares']['msg'][0]        # 6*cm

                for i in range(cm):
                    mult_start = 3 * i
                    chec_start = 3 * (cm + i)

                    mult_triples_shares[node][i] = msg_flat[mult_start:mult_start + 3]
                    chec_triples_shares[node][i] = msg_flat[chec_start:chec_start + 3]

                    rands[node][i] = robust_rec_outputs[node * cm + i]


            else:
                print(f"Warning: Node {node} is not present in acss_outputs")




        rho = {node: [0] * cm for node in mult_triples_shares}
        sigma = {node: [0] * cm for node in mult_triples_shares}

        for node, outputs in mult_triples_shares.items():
            for i in range(cm):
                rho[node][i] = rands[node][i] * mult_triples_shares[node][i][0] - chec_triples_shares[node][i][0]
                sigma[node][i] = mult_triples_shares[node][i][1] - chec_triples_shares[node][i][1]

        rho_list = []
        sigma_list = []
        for node in mult_triples_shares:
            rho_list += rho[node]
            sigma_list += sigma[node]

        # invoke Robust-Rec to rec rho and sigma
        aprep_rec_start_time = time.time()
        rec_list = rho_list + sigma_list

        # execute Robust-Rec
        rec_task1 = asyncio.create_task(self.rec_step(rec_list, 1))
        (mks, robust_rec) = await rec_task1
        mks_list = sorted(mks)
        

        robust_rec_rho = robust_rec[:int(len(robust_rec)/2)]
        robust_rec_sigma = robust_rec[int(len(robust_rec)/2):]

        rec_rho   = {node: [self.ZR(0)] * cm for node in mult_triples_shares}
        rec_sigma = {node: [self.ZR(0)] * cm for node in mult_triples_shares}
        tau       = {node: [self.ZR(0)] * cm for node in mult_triples_shares}

        for node, outputs in mult_triples_shares.items():
            if node in mks_list: 
                for i in range(cm):
                    index = mks_list.index(node)
                    rec_rho[node][i] = robust_rec_rho[index * cm + i]
                    rec_sigma[node][i] = robust_rec_sigma[index * cm + i]


        for node, outputs in mult_triples_shares.items():
            for i in range(cm):
                tau[node][i] = (rands[node][i] * mult_triples_shares[node][i][2] - chec_triples_shares[node][i][2] -
                                rec_sigma[node][i] * chec_triples_shares[node][i][0] - rec_rho[node][i] * chec_triples_shares[node][i][1] -
                                rec_rho[node][i] * rec_sigma[node][i])
                
        tau_list = []
        for node in mult_triples_shares:
            tau_list += tau[node]

        rec_task2 = asyncio.create_task(self.rec_step(tau_list, 2))
        (mks, robust_rec_tau) = await rec_task2
        mks_list = sorted(mks)

        rec_tau = {node: [0] * cm for node in mult_triples_shares}
        for node, outputs in mult_triples_shares.items():
            if node in mks_list: 
                for i in range(cm):
                    index = mks_list.index(node)
                    rec_tau[node][i] = robust_rec_tau[index * cm + i]

                    
        key_proposal = []
        for node, values in rec_tau.items():
            add_node = True  
            for value in values:
                if value != self.ZR(0):
                    add_node = False  
                    break
            if add_node:
                key_proposal.append(node)

        

        # MVBA
        create_acs_task = asyncio.create_task(self.agreement(key_proposal, mult_triples_shares, rec_tau, cm))
        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        await asyncio.gather(*work_tasks)
        # mks, sk, pk = output
        new_mult_triples = output

        duration = time.time() - run_aprep_start_time
        print(f"my id: {self.my_id} APREP protocol total time: {duration:.4f} seconds")

        # self.output_queue.put_nowait(new_mult_triples)
        return new_mult_triples
        
class APREP_Pre(APREP):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix, mpc_instance):
        
        self.mpc_instance = mpc_instance

        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix)
            
    def kill(self):
        try:
            self.subscribe_recv_task.cancel()
            for task in self.acss_tasks:
                task.cancel()
            self.acss.kill()
            self.acss_task.cancel()
        except Exception:
            logging.info("APREP task finished")
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def acss_step(self, aprep_values):

        
        admpc_control_instance = self.mpc_instance.admpc_control_instance
        layerID = self.mpc_instance.layer_ID
        pks_next_layer = admpc_control_instance.pks_all[layerID + 1]       

        
        acsstag = APREPMsgType.ACSS + str(layerID) + str(self.my_id)
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        self.acss = ACSS_Pre(pks_next_layer,
                             self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                             acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                             mpc_instance=self.mpc_instance
                         )
        self.acss_tasks = [None] * self.n
        self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss_aprep(0, values=aprep_values))

    
    async def gen_rand_step(self, rand_num):
        if rand_num > self.n - self.t: 
            rounds = math.ceil(rand_num / (self. n - self.t))
        else: 
            rounds = 1
        randtag = APREPMsgType.GENRAND
        randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
        curve_params = (self.ZR, self.G1, self.multiexp, self.dotprod)
        self.rand = Rand_Pre(self.public_keys, self.private_key, 
                             self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                             randsend, randrecv, self.pc, curve_params, self.matrix, 
                             mpc_instance=self.mpc_instance)
        self.rand_task = asyncio.create_task(self.rand.run_rand(rand_num, rounds))
   
    async def run_aprep(self, cm):

        gen_rand_task = asyncio.create_task(self.gen_rand_step(self.n*cm))
        
        mult_triples = [[self.ZR.rand() for _ in range(3)] for _ in range(cm)]
        chec_triples = [[self.ZR.rand() for _ in range(3)] for _ in range(cm)]
        for i in range(cm): 
            mult_triples[i][2] = mult_triples[i][0] * mult_triples[i][1]
            chec_triples[i][2] = chec_triples[i][0] * chec_triples[i][1]

        aprep_values = (mult_triples, chec_triples, cm)      
        self.acss_task = asyncio.create_task(self.acss_step(aprep_values))
        await self.acss_task

        
    
class APREP_Foll(APREP):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix, mpc_instance):
        
        self.mpc_instance = mpc_instance

        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix)

    def kill(self):
        try:
            self.subscribe_recv_task.cancel()
            for task in self.acss_tasks:
                task.cancel()
            self.acss.kill()
            self.acss_task.cancel()
        except Exception:
            logging.info("APREP task finished")
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def acss_step(self, cm):
        self.acss_tasks = [None] * self.n
        for dealer_id in range(self.n): 
            
            acsstag = APREPMsgType.ACSS + str(self.mpc_instance.layer_ID - 1) + str(dealer_id)
            acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

            self.acss = ACSS_Foll(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                mpc_instance=self.mpc_instance
                            )
            self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss_aprep(0, dealer_id, cm))
        
        results = await asyncio.gather(*self.acss_tasks)
        dealer, _, shares, commitments = zip(*results)
        
        outputs = {}
        for i in range(len(dealer)): 
            outputs[i] = {'shares':shares[i], 'commits':commitments[i]}

        return outputs
          

    async def commonsubset(self, rbc_out, mult_triples_shares, rec_tau, cm, rbc_signal, rbc_values, coin_keys, aba_in, aba_out):
        assert len(rbc_out) == self.n
        assert len(aba_in) == self.n
        assert len(aba_out) == self.n

        aba_inputted = [False]*self.n
        aba_values = [0]*self.n

        async def _recv_rbc(j):
            rbcl = await rbc_out[j].get()
            rbcb = Bitmap(self.n, rbcl)
            rbc_values[j] = []
          
            for i in range(self.n):
                if rbcb.get_bit(i):
                    rbc_values[j].append(i)
            # print(f"rbc_values[{j}]: {rbc_values[j]}")        
            
            if not aba_inputted[j]:
                aba_inputted[j] = True
                aba_in[j](1)
            
            subset = True
            while True:
                
                if subset:
                    coin_keys[j]((mult_triples_shares, rbc_values[j]))
                    return

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
    
    async def agreement(self, key_proposal, mult_triples_shares, rec_tau, cm):
        aba_inputs = [asyncio.Queue() for _ in range(self.n)]
        aba_outputs = [asyncio.Queue() for _ in range(self.n)]
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        
        coin_keys = [asyncio.Queue() for _ in range(self.n)]

        async def predicate(_key_proposal):
            kp = Bitmap(self.n, _key_proposal)
            kpl = []
            for ii in range(self.n):
                if kp.get_bit(ii):
                    kpl.append(ii)
            if len(kpl) <= self.t:
                return False
        
            while True:
                subset = True
                for kk in kpl:
                    for i in range(cm): 
                        if rec_tau[kk][i] != self.ZR(0): 
                            subset = False
                    
                if subset:
                    return True
                

        async def _setup(j):
            
            # starting RBC
            rbctag =APREPMsgType.RBC + str(j) # (R, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id: 
                riv = Bitmap(self.n)
                for k in key_proposal: 
                    riv.set_bit(k)
                rbc_input = bytes(riv.array)

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
                    self.member_list
                )
            )

            abatag = APREPMsgType.ABA + str(j) # (B, msg)
            abasend, abarecv =  self.get_send(abatag), self.subscribe_recv(abatag)

            def bcast(o):
                for i in range(len(self.member_list)):
                    abasend(self.member_list[i], o)
                
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
                mult_triples_shares,
                rec_tau,
                cm,
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.new_triples(
                mult_triples_shares,
                cm,
                rbc_values,
                rbc_signal,
            ),
            work_tasks,
        )

    async def new_triples(self, mult_triples_shares, cm, rbc_values, rbc_signal):
        await rbc_signal.wait()
        rbc_signal.clear()


        self.mks = set() # master key set
        for ks in  rbc_values:
            if ks is not None:
                self.mks = self.mks.union(set(list(ks)))
                if len(self.mks) >= self.n-self.t:
                    break
        T_list = list(self.mks)
        # This corresponds to Step 3 of the protocol: extract randomized triples from the triples provided by each participant
        # We interpolate new triples (u, v, w) based on the agreed subset T_list
        u = [[self.ZR(0) for _ in range(2*self.t+1)] for _ in range(cm)]
        v = [[self.ZR(0) for _ in range(2*self.t+1)] for _ in range(cm)]
        w = [[self.ZR(0) for _ in range(2*self.t+1)] for _ in range(cm)]
        # 这里 u v w 的行代表 cm ,列代表不同节点的三元组中的元素
        for i in range(cm): 
            for j in range(self.t+1): 
                index = T_list[j]
                u[i][j] = mult_triples_shares[index][i][0]
                v[i][j] = mult_triples_shares[index][i][1]
                w[i][j] = mult_triples_shares[index][i][2]
        
        u_poly, v_poly, w_poly = [], [], []
        for i in range(cm):
            u_poly.append([])
            v_poly.append([])

            for j in range(self.t+1): 
                u_poly[i].append([T_list[j]+1, u[i][j]])
                v_poly[i].append([T_list[j]+1, v[i][j]])

            
        # step 14
        for i in range(cm):
            for j in range(self.t+1, 2*self.t+1): 
                index = T_list[j] + 1
                u[i][j] = self.poly.interpolate_at(u_poly[i], index)
                v[i][j] = self.poly.interpolate_at(v_poly[i], index)

        # step 15
        d = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]
        e = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]  
        for i in range(cm):
            for j in range(self.t): 
                index1 = j + self.t + 1
                index2 = T_list[index1]
                d[i][j] = u[i][index1] - mult_triples_shares[index2][i][0]
                e[i][j] = v[i][index1] - mult_triples_shares[index2][i][1]
            

        # step 16
        d_list, e_list = [], []
        for i in range(cm): 
            d_list += d[i]
            e_list += e[i]
        rec_list = d_list + e_list
        robust_rec = await self.robust_rec_step(rec_list, 3)

  
        robust_rec_d = robust_rec[:int(len(robust_rec)/2)]
        robust_rec_e = robust_rec[int(len(robust_rec)/2):]
        
        rec_d = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]
        rec_e = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]
        for i in range(cm):
            for j in range(self.t): 
                rec_d[i][j] = robust_rec_d[i*self.t+j]
                rec_e[i][j] = robust_rec_e[i*self.t+j]

        # step 17    
        for i in range(cm):
            for j in range(self.t): 
                index1 = j + self.t + 1
                index2 = T_list[index1]
                w[i][index1] = rec_d[i][j] * rec_e[i][j] + rec_d[i][j] * mult_triples_shares[index2][i][1] + rec_e[i][j] * mult_triples_shares[index2][i][0] + mult_triples_shares[index2][i][2]

        # step 18
        for i in range(cm):
            w_poly.append([])
            for j in range(2*self.t+1): 
                w_poly[i].append([T_list[j]+1, w[i][j]])
        u_point, v_point, w_point = [None] * cm, [None] * cm, [None] * cm
        for i in range(cm):
            point = 3 * self.t + 2
            u_point[i] = self.poly.interpolate_at(u_poly[i], point)
            v_point[i] = self.poly.interpolate_at(v_poly[i], point)
            w_point[i] = self.poly.interpolate_at(w_poly[i], point)

        aprep_triples = []
        for i in range(cm): 
            aprep_triples.append([])
            aprep_triples[i].append(u_point[i])
            aprep_triples[i].append(v_point[i])
            aprep_triples[i].append(w_point[i])
        
        return aprep_triples
    
    
    async def gen_rand_step(self, rand_num, rand_outputs):
        
        if rand_num > self.n - self.t: 
            rounds = math.ceil(rand_num / (self. n - self.t))
        else: 
            rounds = 1

        randtag = APREPMsgType.GENRAND
        randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
        curve_params = (self.ZR, self.G1, self.multiexp, self.dotprod)
        self.rand_foll = Rand_Foll(self.public_keys, self.private_key, 
                              self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                              randsend, randrecv, self.pc, curve_params, self.matrix, 
                              mpc_instance=self.mpc_instance)
        self.rand_task = asyncio.create_task(self.rand_foll.run_rand(rand_num, rounds))
        rand_outputs = await self.rand_task
        return rand_outputs

        
    async def robust_rec_step(self, rec_shares, index):                      
        rec_values = await self.rec.batch_run_robust_rec(index, rec_shares, self.member_list)

        return rec_values
        
    
    async def run_aprep(self, cm):
        print(f"aprep_foll run_aprep cm: {cm}")
        gen_rand_outputs = []

        # Invoke Protocol Rand to generate random shares
        gen_rand_outputs = await self.gen_rand_step(self.n*cm, gen_rand_outputs)


        self.acss_task = asyncio.create_task(self.acss_step(cm))
        acss_outputs = await self.acss_task

        # invoke Protocol Robust-Rec 
        self.member_list = []
        for i in range(self.n): 
            self.member_list.append(self.n * (self.mpc_instance.layer_ID) + i)
        robust_rec_outputs = await self.robust_rec_step(gen_rand_outputs, 0)
        

        # In this step, we need to use chec_triples to verify whether the triple in mult_triples satisfies c = a * b
        # Here 'msg' represents the phis set and 'rand' represents the phis_hat set. phis[0] contains the mult_triples, and phis[1] contains the chec_triples
        # acss_outputs[n] indicates that node n provided the corresponding triple
        mult_triples_shares = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        chec_triples_shares = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        rands = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        for node in range(len(acss_outputs)): 
            output = acss_outputs[node]
            mult_triples_shares[node] = [[self.ZR(0)] * 3 for _ in range(cm)]
            chec_triples_shares[node] = [[self.ZR(0)] * 3 for _ in range(cm)]
            rands[node] = [self.ZR(0)] * cm

            msg_flat = output['shares']['msg'][0]        

            # extracting the triples from the flat message
            for i in range(cm):
                mult_start = 3 * i
                chec_start = 3 * (cm + i)

                mult_triples_shares[node][i] = msg_flat[mult_start:mult_start + 3]
                chec_triples_shares[node][i] = msg_flat[chec_start:chec_start + 3]

                rands[node][i] = robust_rec_outputs[node * cm + i]

        # This step begins the use of check triples to validate multiplication triples
        rho = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        sigma = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        for node in range(len(acss_outputs)): 
            for i in range(cm): 
                rho[node][i] = rands[node][i] * mult_triples_shares[node][i][0] - chec_triples_shares[node][i][0]
                sigma[node][i] = mult_triples_shares[node][i][1] - chec_triples_shares[node][i][1]

        rho_list = []
        sigma_list = []
        for i in range(len(acss_outputs)): 
            rho_list += rho[i]
            sigma_list += sigma[i]
        # invoke Robust-Rec to reconstruct rho and sigma
        aprep_rec_start_time = time.time()
        rec_list = rho_list + sigma_list
        robust_rec = await self.robust_rec_step(rec_list, 1)


        robust_rec_rho = robust_rec[:int(len(robust_rec)/2)]
        robust_rec_sigma = robust_rec[int(len(robust_rec)/2):]
        rec_rho = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        rec_sigma = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        for node in range(len(acss_outputs)): 
            for i in range(cm): 
                rec_rho[node][i] = robust_rec_rho[node*cm+i]
                rec_sigma[node][i] = robust_rec_sigma[node*cm+i]
        
        # compute \tau and invoke protocol Robust-Rec to rec \tau and check if \tau is zero
        tau = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        for node in range(len(acss_outputs)): 
            for i in range(cm): 
                tau[node][i] = rands[node][i] * mult_triples_shares[node][i][2] - chec_triples_shares[node][i][2] - rec_sigma[node][i] * chec_triples_shares[node][i][0] - rec_rho[node][i] * chec_triples_shares[node][i][1] - rec_rho[node][i] * rec_sigma[node][i]

        tau_list = []
        for i in range(len(acss_outputs)): 
            tau_list += tau[i]
        robust_rec_tau = await self.robust_rec_step(tau_list, 2)
        

        rec_tau = [[0 for _ in range(cm)] for _ in range(len(acss_outputs))]
        for node in range(len(acss_outputs)): 
            for i in range(cm): 
                rec_tau[node][i] = robust_rec_tau[node*cm+i]


        # check if rec_tau is zero
        key_proposal = []
        for node in range(len(acss_outputs)): 
            for i in range(cm): 
                if rec_tau[node][i] != self.ZR(0):
                    break
            key_proposal.append(node)
        

        # MVBA
        create_acs_task = asyncio.create_task(self.agreement(key_proposal, mult_triples_shares, rec_tau, cm))
        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        await asyncio.gather(*work_tasks)
        new_mult_triples = output

        return new_mult_triples