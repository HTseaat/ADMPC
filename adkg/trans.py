from adkg.polynomial import polynomials_over, EvalPoint
from adkg.utils.poly_misc import interpolate_g1_at_x
from adkg.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib, time
from math import ceil
import logging
from adkg.utils.bitmap import Bitmap
from adkg.acss import ACSS, ACSS_Pre, ACSS_Foll, ACSS_Fluid_Pre, ACSS_Fluid_Foll

from adkg.broadcast.tylerba import tylerba
from adkg.broadcast.optqrbc import optqrbc, optqrbc_dynamic

from adkg.preprocessing import PreProcessedElements

from adkg.mpc import TaskProgramRunner
from adkg.utils.serilization import Serial
from adkg.robust_rec import Robust_Rec
from adkg.field import GF, GFElement
from adkg.robust_reconstruction import robust_reconstruct_admpc
from adkg.elliptic_curve import Subgroup
from itertools import combinations

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)

class TRANSMsgType:
    ACSS = "TR.A"
    RBC = "TR.R"
    ABA = "TR.B"
    PREKEY = "TR.P"
    KEY = "TR.K"
    MASK = "TR.M"
    GENRAND = "TR.GR"
    ROBUSTREC = "TR.RR"
    TRANS = "TR.TR"
    APREP = "TR.AP"

class Trans:
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params):
        self.public_keys, self.private_key, self.g, self.h = (public_keys, private_key, g, h)
        self.n, self.t, self.deg, self.my_id = (n, t, deg, my_id)
        self.sc = ceil((deg+1)/(t+1)) + 1
        self.send, self.recv, self.pc = (send, recv, pc)
        self.ZR, self.G1, self.multiexp, self.dotprod = curve_params
        self.poly = polynomials_over(self.ZR)
        self.poly.clear_cache() #FIXME: Not sure why we need this.
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send
        self.output_queue = asyncio.Queue()

        rectag = TRANSMsgType.ROBUSTREC
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
            logging.info("TRANS task finished")
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def acss_step_log(self, outputs, trans_values, acss_signal):
        acsstag = TRANSMsgType.ACSS
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        self.acss = ACSS(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, acsssend, acssrecv, self.pc, self.ZR, self.G1
                         
                         )
        self.acss_tasks = [None] * self.n
        # n-parallel ACSS
        len_values = len(trans_values[0])
        print(f"my id: {self.my_id} len_values: {len_values}")
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss_trans_log(0, len_values, values=trans_values))
            else:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss_trans_log(0, len_values, dealer_id=i))

        while True:
            (dealer, _, shares, commitments, omega, gamma, masked) = await self.acss.output_queue.get()
            outputs[dealer] = {'shares':shares, 'commits':commitments, 'omega':omega, 'gamma':gamma, 'masked':masked}
            # print("outputs: ", outputs[dealer])
            if len(outputs) >= self.n - self.t:
                # print("Player " + str(self.my_id) + " Got shares from: " + str([output for output in outputs]))
                acss_signal.set()

            if len(outputs) == self.n:
                return   

    async def acss_step(self, outputs, trans_values, acss_signal):
        acsstag = TRANSMsgType.ACSS
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        self.acss = ACSS(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, acsssend, acssrecv, self.pc, self.ZR, self.G1
                         , self.rbcl_list
                         )
        self.acss_tasks = [None] * self.n
        # n-parallel ACSS
        len_values = len(trans_values[0])
        print(f"my id: {self.my_id} len_values: {len_values}")
        for i in range(self.n):
            if i == self.my_id:
                # self.acss_tasks[i] = asyncio.create_task(self.acss.avss_trans(0, len_values, values=trans_values))
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss_trans_log(0, len_values, values=trans_values))
            else:
                # self.acss_tasks[i] = asyncio.create_task(self.acss.avss_trans(0, len_values, dealer_id=i))
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss_trans_log(0, len_values, dealer_id=i))

        while True:
            (dealer, _, shares, commitments) = await self.acss.output_queue.get()
            outputs[dealer] = {'shares':shares, 'commits':commitments}
            # print("outputs: ", outputs[dealer])
            if len(outputs) >= self.n - self.t:
                # print("Player " + str(self.my_id) + " Got shares from: " + str([output for output in outputs]))
                acss_signal.set()

            if len(outputs) == self.n:
                return    

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
    
    async def agreement(self, key_proposal, de_masked_value, acss_outputs, acss_signal):
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

            GFEG1 = GF(Subgroup.BLS12_381)
            point = EvalPoint(GFEG1, self.n, use_omega_powers=False)
            poly, err = await robust_reconstruct_admpc(de_masked_value, key_proposal, GFEG1, self.t, point, self.t)
            err_list = list(err)
            if any(err_list):
                return False

            return True

        async def _setup(j):
            
            # starting RBC
            rbctag = TRANSMsgType.RBC + str(j) # (R, msg)
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

            abatag = TRANSMsgType.ABA + str(j) # (B, msg)
            # abatag = TRANSMsgType.ABA + str(j)
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
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.new_share(
                rbc_values,
                rbc_signal,
                acss_outputs,
                acss_signal, 
            ),
            work_tasks,
        )

    async def new_share(self, rbc_values, rbc_signal, acss_outputs, acss_signal):
        await rbc_signal.wait()
        rbc_signal.clear()

        # print(f"rbc_values: {rbc_values}")
        self.mks = set() # master key set
        for ks in  rbc_values:
            if ks is not None:
                self.mks = self.mks.union(set(list(ks)))
                if len(self.mks) >= self.n-self.t:
                    break
        
        # Waiting for all ACSS to terminate
        for k in self.mks:
            if k not in acss_outputs:
                await acss_signal.wait()
                acss_signal.clear()

        mks_list = list(self.mks)
        # print(f"my id: {self.my_id} acss_outputs: {acss_outputs}")
        secrets_num = len(acss_outputs[mks_list[0]]['shares']['msg'][0])
        secrets = [[self.ZR(0) for _ in range(self.n)] for _ in range(secrets_num)]

        for i in range(secrets_num): 
            for node in range(self.n): 
                if node in self.mks: 
                    secrets[i][node] = acss_outputs[node]['shares']['msg'][0][i]

   

        sc_shares = []
        for i in range(secrets_num): 
            sc_shares.append([])
            for j in self.mks:
                sc_shares[i].append([j+1, secrets[i][j]])

        # print(f"my id: {self.my_id} sc_shares: {sc_shares}")

        res = []
        for i in range(secrets_num):
            res.append(self.poly.interpolate_at(sc_shares[i], 0))


        return res

    # ------------------------------------------------------------------
    # Utility: reconstruct auxiliary values (omega, gamma, masked)
    #          from any subset of ≥ t+1 ACSS outputs in self.mks
    # ------------------------------------------------------------------
    def _lagrange_coeffs_at_zero(self, idxs):
        """
        Compute Lagrange coefficients λ_i for X=0 over given indices.
        idxs: iterable of node indices (0‑based).  X_i = i+1.
        Returns dict {i: λ_i ∈ 𝔽_p}.
        """
        coeffs = {}
        for i in idxs:
            lam = self.ZR(1)
            xi = self.ZR(i + 1)
            for j in idxs:
                if i == j:
                    continue
                xj = self.ZR(j + 1)
                # lam *= (-xj) * (xi - xj).inverse()
                # Use exponent −1 to get multiplicative inverse in the field
                lam *= (-xj) * (xi - xj) ** -1
            coeffs[i] = lam
        return coeffs
    
    def reconstruct_aux(self, acss_outputs):
        """
        Reconstruct g^r  (from omega), g_0^{s_0}·h^{r_1} (from gamma),
        and the scalar masked value from the ACSS outputs held
        by the nodes in self.mks.

        Returns (omega_0, gamma_0, masked_0)

        * omega_0, gamma_0 are G1 elements
        * masked_0 is a field element (self.ZR)
        """
        if len(self.mks) < self.t + 1:
            raise ValueError("Need at least t+1 shares to interpolate")

        idxs = list(self.mks)[: self.t + 1]  # take any t+1 indices
        lambdas = self._lagrange_coeffs_at_zero(idxs)

        # Interpolate in‑exponent for omega and gamma
                # Interpolate in-exponent for omega, gamma, and g_s (Pedersen agg)
        omega_0 = self.G1.identity()
        gamma_0 = self.G1.identity()
        g_s0    = self.G1.identity()

        for i in idxs:
            lam_i   = lambdas[i]

            # omega / gamma
            omega_i = acss_outputs[i]["omega"][0]
            gamma_i = acss_outputs[i]["gamma"][0]
            omega_0 *= omega_i ** int(lam_i)
            gamma_0 *= gamma_i ** int(lam_i)

            # aggregate this node's commit_peds then interpolate
            commit_peds_i = acss_outputs[i]["commits"][0]     # tuple第0项
            g_s_i = self.G1.identity()
            for ped in commit_peds_i:
                g_s_i *= ped
            g_s0 *= g_s_i ** int(lam_i)

        # ---- masked（域元素）普通插值 ----
        masked_0 = self.ZR(0)
        for i in idxs:
            lam_i = lambdas[i]
            masked_i = self.ZR(acss_outputs[i]["masked"][0])
            masked_0 += masked_i * lam_i

        # ------------------------------------------------------------------
        # Equality check:  g_0^{masked_0} · omega_0  ==  g_s0 · gamma_0
        # g_0 取自 hbPolyCommitg 随机基列表中的第 0 位
        # ------------------------------------------------------------------
        gs = self.G1.hash_many(b"hbPolyCommitg", self.t + 1)
        g0 = gs[0]

        left  = (g0 ** masked_0) * omega_0
        right = g_s0 * gamma_0
        print(f"type masked_0: {type(masked_0)}, type omega_0: {type(omega_0)}")

        return left == right
    
    def reconstruct_omega(self, acss_outputs):

        if len(self.mks) < self.t + 1:
            raise ValueError("Need at least t+1 shares to interpolate")

        idxs = list(self.mks)[: self.t + 1]  # take any t+1 indices
        print(f"my id: {self.my_id} idxs: {idxs}")
        lambdas = self._lagrange_coeffs_at_zero(idxs)
        print(f"my id: {self.my_id} lambdas: {lambdas}")    

        # Interpolate in‑exponent for omega and gamma
                # Interpolate in-exponent for omega, gamma, and g_s (Pedersen agg)
        omega_0 = self.G1.identity()

        elems  = [acss_outputs[i]["omega"][0] for i in idxs]
        coeffs = [lambdas[i]                for i in idxs]

        coeffs = [int(c) for c in coeffs]

        omega_0 = self.multiexp(elems, coeffs)


        left  = omega_0
        right = acss_outputs[0]['w']

        rxy = right[0]

        return left == rxy

    def rec_omega(self, acss_outputs):
        """
        Find a subset idxs of size t+1 from self.mks such that
            multiexp([ω_i for i in idxs], [λ_i]) == w_j
        for some node j in the subset. Return the subset if found, otherwise raise.
        """
        if len(self.mks) < 2 * self.t + 1:
            raise ValueError(f"Need at least 2t+1={2*self.t+1} nodes in mks, got {len(self.mks)}")

        # Enumerate all subsets of size t+1 from self.mks
        for idxs in combinations(sorted(self.mks), self.t + 1):

            # Compute Lagrange coefficients at zero for the chosen indices
            lambdas = self._lagrange_coeffs_at_zero(idxs)

            # Perform multi-exponentiation to interpolate ω
            elems  = [acss_outputs[i]["omega"][0] for i in idxs]
            coeffs = [int(lambdas[i])            for i in idxs]
            omega_0 = self.multiexp(elems, coeffs)

        # Use the first node in the subset as reference and compare reconstructed ω to its w
            ref = idxs[0]
            w_ref = acss_outputs[ref]["w"][0]


            if omega_0 == w_ref:
                return list(idxs)

        # If no subset matches, raise an error
        raise RuntimeError("No size-(t+1) subset in mks satisfies ω == w")

    

    async def rbc_masked_step(self, rbc_masked_input): 


        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        
        async def predicate(_m):
            return True


        async def _setup(j):            
            # starting RBC
            rbctag =TRANSMsgType.MASK + str(j) # (M, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id: 
                rbc_input = rbc_masked_input
                # print(f"{self.my_id} rbc_input: {rbc_input}")

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

        await asyncio.gather(*[_setup(j) for j in range(self.n)])

        self.rbcl_list = await asyncio.gather(*(rbc_outputs[j].get() for j in range(self.n)))    
    
    async def run_trans(self, values, rand_values):
        self.len_values = len(values)
        # 这里模拟的是 step 1
        rand_values_hat = [None] * len(values)
        values_hat = [None] * len(values)
        for i in range(len(values)): 
            values_hat[i] = self.ZR.rand()
            rand_values_hat[i] = self.ZR.rand()

        # 这里是协议 step 2 和 3
        masked_values, masked_values_hat = [None] * len(values), [None] * len(values)
        c = [None] * len(values)
        for i in range(len(values)): 
            masked_values[i] = values[i] + rand_values[i]
            masked_values_hat[i] = values_hat[i] + rand_values_hat[i]
            c[i] = self.pc.commit_trans(rand_values[i], rand_values_hat[i])
        

        sr = Serial(self.G1)
        serialized_masked_values = sr.serialize_fs(masked_values)
        serialized_masked_values_hat = sr.serialize_fs(masked_values_hat)
        serialized_c = sr.serialize_gs(c)
        rbc_masked_input = serialized_masked_values + serialized_masked_values_hat + serialized_c
        await asyncio.create_task(self.rbc_masked_step(bytes(rbc_masked_input)))

        acss_outputs = {}
        acss_signal = asyncio.Event()
        trans_values = (values, values_hat)
        test = asyncio.create_task(self.acss_step(acss_outputs, trans_values, acss_signal))
        await test
        # await self.acss_step(acss_outputs, trans_values, acss_signal)
        await acss_signal.wait()
        acss_signal.clear()
        # print("acss_outputs: ", acss_outputs)
        
        LT = list(acss_outputs.keys())

        de_masked_values = [[self.ZR(0) for _ in range(self.n)] for _ in range(len(values))]
        for i in range(len(values)): 
            for j in range(self.n): 
                if j in LT: 
                    de_masked_values[i][j] = int(sr.deserialize_f(self.rbcl_list[j][32*i:32*(i+1)]))

        GFEG1 = GF(Subgroup.BLS12_381)
        point = EvalPoint(GFEG1, self.n, use_omega_powers=False)
        poly, err = [None] * len(values), [None] * len(values)
        for i in range(len(values)): 
            poly[i], err[i] = await robust_reconstruct_admpc(de_masked_values[i], LT, GFEG1, self.t, point, self.t)
            # err_list[i] = list(err[i])
            # GT[i] = [j for j in range(self.n) if j not in err_list[i]]

        err_list = [list(err[i]) for i in range(len(err))]

        for i in range(len(err_list)): 
            if len(err_list[i]) == 0: 
                continue
            else: 
                for j in range(len(err_list[i])): 
                    LT.pop(err_list[i][j])
        GT = LT


        
        
        create_acs_task = asyncio.create_task(self.agreement(GT, de_masked_values, acss_outputs, acss_signal))

        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        await asyncio.gather(*work_tasks)

        
        new_shares = output
        
       
        return new_shares

    async def run_trans_log(self, values, rand_values):
        run_trans_start = time.time()
        self.len_values = len(values)

        acss_outputs = {}
        acss_signal = asyncio.Event()
        trans_values = (values, rand_values)
        test = asyncio.create_task(self.acss_step_log(acss_outputs, trans_values, acss_signal))
        await test
        
        await acss_signal.wait()
        acss_signal.clear()
        
        LT = list(acss_outputs.keys())
        # print(f"LT: {LT}")
        sr = Serial(self.G1)

        de_masked_values = [self.ZR(0) for _ in range(self.n)]
        for j in LT:
            de_masked_values[j] = self.ZR(acss_outputs[j]['masked'][0])

        print(f"de_masked_values: {de_masked_values}")

        GFEG1 = GF(Subgroup.BLS12_381)
        point = EvalPoint(GFEG1, self.n, use_omega_powers=False)

        poly, err = await robust_reconstruct_admpc(de_masked_values, LT, GFEG1, self.t, point, self.t)
        err_list = list(err)
        print(f"err_list: {err_list}")

        for i in range(len(err_list)): 
            if len(err_list[i]) == 0: 
                continue
            else: 
                for j in range(len(err_list[i])): 
                    LT.pop(err_list[i][j])
        GT = LT


        
        create_acs_task = asyncio.create_task(self.agreement(GT, de_masked_values, acss_outputs, acss_signal))

        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        await asyncio.gather(*work_tasks)

        new_shares = output

        duration = time.time() - run_trans_start
        print(f"my id: {self.my_id} TRANS duration: {duration:.2f} seconds")

        # self.output_queue.put_nowait(new_shares)
        return new_shares
        
class Trans_Pre(Trans):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, mpc_instance):
        
        self.mpc_instance = mpc_instance

        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params)
    
    def kill(self):
        try:
            self.subscribe_recv_task.cancel()
            for task in self.acss_tasks:
                task.cancel()
            self.acss.kill()
            self.acss_task.cancel()
        except Exception:
            logging.info("TRANS task finished")
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def acss_step_log(self, trans_values):
        
        admpc_control_instance = self.mpc_instance.admpc_control_instance
        layerID = self.mpc_instance.layer_ID
        pks_next_layer = admpc_control_instance.pks_all[layerID + 1]       

        
        acsstag = TRANSMsgType.ACSS + str(layerID) + str(self.my_id)
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

        self.acss = ACSS_Pre(pks_next_layer, 
                             self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                             acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                             mpc_instance=self.mpc_instance
                         )
        self.acss_tasks = [None] * self.n
        # n-parallel ACSS
        len_values = len(trans_values[0])
        print(f"my id: {self.my_id} len_values: {len_values}")
        self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss_trans_log(0, len_values, values=trans_values))
        
    
    async def acss_step(self, trans_values):
        
        admpc_control_instance = self.mpc_instance.admpc_control_instance
        layerID = self.mpc_instance.layer_ID
        pks_next_layer = admpc_control_instance.pks_all[layerID + 1]       

        
        acsstag = TRANSMsgType.ACSS + str(layerID) + str(self.my_id)
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

        self.acss = ACSS_Pre(pks_next_layer, 
                             self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                             acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                             mpc_instance=self.mpc_instance
                         )
        self.acss_tasks = [None] * self.n


        len_values = len(trans_values[0])

        self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss_trans(0, values=trans_values))


    async def rbc_masked_step_pre(self, rbc_masked_input): 
        rbc_outputs = asyncio.Queue()

        member_list = [(self.mpc_instance.layer_ID) * self.n + self.my_id]
        for i in range(self.n): 
            member_list.append(self.n * (self.mpc_instance.layer_ID + 1) + i)
        
        async def predicate(_m):
            return True

        rbctag =TRANSMsgType.MASK + str(self.my_id) # (M, msg)
        rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

        rbc_input = rbc_masked_input
        asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id,
                self.n+1,
                self.t,
                self.my_id,
                predicate,
                rbc_input,
                rbc_outputs.put_nowait,
                rbcsend,
                rbcrecv,
                member_list
            )
        )
    
    async def run_trans_log(self, values, rand_values):
        self.len_values = len(values)

        acss_outputs = {}
        acss_signal = asyncio.Event()
        # trans_values = (values, values_hat)
        trans_values = (values, rand_values)
        self.acss_task = asyncio.create_task(self.acss_step_log(acss_outputs, trans_values, acss_signal))
        

    async def run_trans(self, values, rand_values, w_list):     
        self.len_values = len(values)

        trans_values = (values, rand_values, w_list)
        self.acss_task = asyncio.create_task(self.acss_step(trans_values))


class Trans_Foll(Trans):        
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, mpc_instance):
        
        self.mpc_instance = mpc_instance

        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params)
    
    def kill(self):
        try:
            self.subscribe_recv_task.cancel()
            for task in self.acss_tasks:
                task.cancel()
            self.acss.kill()
            self.acss_task.cancel()
        except Exception:
            logging.info("TRANS task finished")
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def acss_step(self, len_values):
        rounds = 1
        self.acss_tasks = [None] * self.n
        for dealer_id in range(self.n): 
            
            acsstag = TRANSMsgType.ACSS + str(self.mpc_instance.layer_ID - 1) + str(dealer_id)
            acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

            
            self.acss = ACSS_Foll(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                mpc_instance=self.mpc_instance
                            )

            self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss_trans(0, dealer_id, len_values))


        results = await asyncio.gather(*self.acss_tasks)

        dealer, _, shares, commitments, omega, mask, hat_mask, w = zip(*results)


        outputs = {}
        for i in range(len(dealer)):
            outputs[i] = {
                'shares':  shares[i],
                'commits': commitments[i],
                'omega':   omega[i],
                'mask':   mask[i],
                'hat_mask':  hat_mask[i],
                'w': w[i]
            }
        return outputs
    
       

    async def commonsubset(self, rbc_out, rbc_signal, rbc_values, coin_keys, aba_in, aba_out):
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
            
            if not aba_inputted[j]:
                aba_inputted[j] = True
                aba_in[j](1)
            
            subset = True
            

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
    
    async def agreement(self, key_proposal, de_masked_value, acss_outputs, acss_signal):
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
            # print(f"kpl: {kpl}")
            # print(f"de_masked_value: {de_masked_value}")
            if len(kpl) <= self.t:
                return False
            
            GFEG1 = GF(Subgroup.BLS12_381)
            point = EvalPoint(GFEG1, self.n, use_omega_powers=False)
            poly, err = await robust_reconstruct_admpc(de_masked_value, key_proposal, GFEG1, self.t, point, self.t)
            err_list = list(err)
            if any(err_list):
                return False     
        
            return True

        async def _setup(j):
            
            # starting RBC
            rbctag = TRANSMsgType.RBC + str(j) # (R, msg)
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
                    self.member_list
                )
            )

            abatag = TRANSMsgType.ABA + str(j) # (B, msg)


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
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.new_share(
                rbc_values,
                rbc_signal,
                acss_outputs,
                acss_signal, 
            ),
            work_tasks,
        )

    async def new_share(self, rbc_values, rbc_signal, acss_outputs, acss_signal):
        await rbc_signal.wait()
        rbc_signal.clear()

        self.mks = set() # master key set
        for ks in  rbc_values:
            if ks is not None:
                self.mks = self.mks.union(set(list(ks)))
                if len(self.mks) >= self.n-self.t:
                    break

        # Waiting for all ACSS to terminate
        for k in self.mks:
            if k not in acss_outputs:
                await acss_signal.wait()
                acss_signal.clear()

        mks_list = list(self.mks)
        secrets_num = len(acss_outputs[mks_list[0]]['shares']['msg'][0])
        secrets = [[self.ZR(0) for _ in range(self.n)] for _ in range(secrets_num)]

        for i in range(secrets_num): 
            for node in range(self.n): 
                if node in self.mks: 
                    secrets[i][node] = acss_outputs[node]['shares']['msg'][0][i]
                    
        valid_list = self.rec_omega(acss_outputs)


        sc_shares = []
        for i in range(secrets_num): 
            sc_shares.append([])
            for j in valid_list:
                sc_shares[i].append([j+1, secrets[i][j]])


        res = []
        for i in range(secrets_num):
            res.append(self.poly.interpolate_at(sc_shares[i], 0))


        return res
    
    async def run_trans(self, len_values):
        self.member_list = []
        for i in range(self.n): 
            self.member_list.append(self.n * (self.mpc_instance.layer_ID) + i)
        
        acss_signal = asyncio.Event()
        self.acss_task = asyncio.create_task(self.acss_step(len_values))
        acss_outputs = await self.acss_task
        
        LT = list(acss_outputs.keys())

        sr = Serial(self.G1)
        de_masked_values = [self.ZR(0) for _ in range(self.n)]
        for j in LT:
            de_masked_values[j] = self.ZR(acss_outputs[j]['mask'][0])


        GFEG1 = GF(Subgroup.BLS12_381)
        point = EvalPoint(GFEG1, self.n, use_omega_powers=False)
        poly, err = [None] * len_values, [None] * len_values
        poly, err = await robust_reconstruct_admpc(de_masked_values, LT, GFEG1, self.t, point, self.t)
        err_list = list(err)

  
        # for i in range(len(err_list)): 
        #     if len(err_list[i]) == 0: 
        #         continue
        #     else: 
        #         for j in range(len(err_list[i])): 
        #             LT.pop(err_list[i][j])
        # GT = LT

        filtered = [j for j in LT if all(j not in errs for errs in err_list)]


        if filtered:
            ref_w = acss_outputs[filtered[0]]['w']
            GT = [j for j in filtered if acss_outputs[j]['w'] == ref_w]
        else:
            GT = []


        # MVBA
        create_acs_task = asyncio.create_task(self.agreement(GT, de_masked_values, acss_outputs, acss_signal))

        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        await asyncio.gather(*work_tasks)
        new_shares = output


        return new_shares



class Trans_Fluid_Pre(Trans):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, mpc_instance):
        
        self.mpc_instance = mpc_instance

        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params)
    
    def kill(self):
        try:
            self.subscribe_recv_task.cancel()
            for task in self.acss_tasks:
                task.cancel()
            self.acss.kill()
            self.acss_task.cancel()
        except Exception:
            logging.info("TRANS task finished")
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def acss_step(self, trans_values):
        
        admpc_control_instance = self.mpc_instance.admpc_control_instance
        layerID = self.mpc_instance.layer_ID
        pks_next_layer = admpc_control_instance.pks_all[layerID + 1]       

        
        acsstag = TRANSMsgType.ACSS + str(layerID) + str(self.my_id)
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

        self.acss = ACSS_Fluid_Pre(pks_next_layer, 
                             self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                             acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                             mpc_instance=self.mpc_instance
                         )
        self.acss_tasks = [None] * self.n
        # self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, values=trans_values))
        self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss_trans(0, values=trans_values))

    async def rbc_masked_step_pre(self, rbc_masked_input): 
        rbc_outputs = asyncio.Queue()

        member_list = [(self.mpc_instance.layer_ID) * self.n + self.my_id]
        for i in range(self.n): 
            member_list.append(self.n * (self.mpc_instance.layer_ID + 1) + i)
        
        async def predicate(_m):
            return True

        rbctag =TRANSMsgType.MASK + str(self.my_id) # (M, msg)
        rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

        rbc_input = rbc_masked_input
        asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id,
                self.n+1,
                self.t,
                self.my_id,
                predicate,
                rbc_input,
                rbc_outputs.put_nowait,
                rbcsend,
                rbcrecv,
                member_list
            )
        )
    
    async def run_trans(self, values):     

        

        sr = Serial(self.G1)
        serialized_values = sr.serialize_fs(values)
        rbc_masked_task = asyncio.create_task(self.rbc_masked_step_pre(bytes(serialized_values)))

        

class Trans_Fluid_Foll(Trans):        
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, mpc_instance):
        
        self.mpc_instance = mpc_instance

        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params)
    
    def kill(self):
        try:
            self.subscribe_recv_task.cancel()
            for task in self.acss_tasks:
                task.cancel()
            self.acss.kill()
            self.acss_task.cancel()
        except Exception:
            logging.info("TRANS task finished")
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def acss_step(self, len_values):
        rounds = 1
        self.acss_tasks = [None] * self.n
        for dealer_id in range(self.n): 
            
            acsstag = TRANSMsgType.ACSS + str(self.mpc_instance.layer_ID - 1) + str(dealer_id)
            acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

            
            self.acss = ACSS_Foll(self.public_keys, self.private_key, 
                                self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                                acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                                mpc_instance=self.mpc_instance, rbc_values=self.rbcl_list
                            )
            # self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, dealer_id, rounds))
            self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss_trans(0, dealer_id, len_values))



        results = await asyncio.gather(*self.acss_tasks)
        dealer, _, shares, commitments = zip(*results)
        
        outputs = {}
        for i in range(len(dealer)): 
            outputs[i] = {'shares':shares[i], 'commits':commitments[i]}
        return outputs
    
       

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
    
    async def agreement(self, key_proposal, de_masked_value, acss_outputs, acss_signal):
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
            
            GFEG1 = GF(Subgroup.BLS12_381)
            point = EvalPoint(GFEG1, self.n, use_omega_powers=False)
            poly, err = [None] * len(de_masked_value), [None] * len(de_masked_value)
            for i in range(len(de_masked_value)): 
                poly[i], err[i] = await robust_reconstruct_admpc(de_masked_value[i], key_proposal, GFEG1, self.t, point, self.t)
            err_list = [list(err[i]) for i in range(len(err))]
            for i in range(len(err_list)): 
                if len(err_list[i]) != 0: 
                    return False         
        
            return True

        async def _setup(j):
            
            # starting RBC
            rbctag = TRANSMsgType.RBC + str(j) # (R, msg)
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
                    self.member_list
                )
            )

            abatag = TRANSMsgType.ABA + str(j) # (B, msg)
            # abatag = TRANSMsgType.ABA + str(j)
            # abatag = j # (B, msg)
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
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.new_share(
                rbc_values,
                rbc_signal,
                acss_outputs,
                acss_signal, 
            ),
            work_tasks,
        )

    async def new_share(self, rbc_values, rbc_signal, acss_outputs, acss_signal):
        await rbc_signal.wait()
        rbc_signal.clear()


        self.mks = set() # master key set
        for ks in  rbc_values:
            if ks is not None:
                self.mks = self.mks.union(set(list(ks)))
                if len(self.mks) >= self.n-self.t:
                    break
        
        # Waiting for all ACSS to terminate
        for k in self.mks:
            if k not in acss_outputs:
                await acss_signal.wait()
                acss_signal.clear()


        mks_list = list(self.mks)
        secrets_num = len(acss_outputs[mks_list[0]]['shares']['msg'])
        secrets = [[self.ZR(0) for _ in range(self.n)] for _ in range(secrets_num)]
        # secrets = [self.ZR(0)] * self.n 

        for i in range(secrets_num): 
            for node in range(self.n): 
                if node in self.mks: 
                    secrets[i][node] = acss_outputs[node]['shares']['msg'][i]
        


        sc_shares = []
        for i in range(secrets_num): 
            sc_shares.append([])
            for j in self.mks:
                sc_shares[i].append([j+1, secrets[i][j]])

        res = []
        for i in range(secrets_num):
            res.append(self.poly.interpolate_at(sc_shares[i], 0))
        # res = self.poly.interpolate_at(sc_shares, 0)
        # print(f"my id: {self.my_id} res: {res}")

        return res

    # async def masked_values(): 

    
    async def rbc_masked_step_foll(self): 
        rbc_tasks = [None] * self.n
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]

        async def predicate(_m):
            return True

        for dealer_id in range(self.n): 

            rbctag =TRANSMsgType.MASK + str(dealer_id) # (M, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)
            rbc_input = None

            member_list = [(self.mpc_instance.layer_ID - 1) * self.n + dealer_id]
            for j in range(self.n): 
                member_list.append(self.n * (self.mpc_instance.layer_ID) + j)

            if self.my_id < dealer_id: 
                rbc_tasks[dealer_id] = asyncio.create_task(
                optqrbc_dynamic(
                    rbctag,
                    self.my_id,
                    self.n+1,
                    self.t,
                    dealer_id,
                    predicate,
                    rbc_input,
                    rbc_outputs[dealer_id].put_nowait,
                    rbcsend,
                    rbcrecv,
                    member_list
                ))
            else: 
                rbc_tasks[dealer_id] = asyncio.create_task(
                optqrbc_dynamic(
                    rbctag,
                    self.my_id+1,
                    self.n+1,
                    self.t,
                    dealer_id,
                    predicate,
                    rbc_input,
                    rbc_outputs[dealer_id].put_nowait,
                    rbcsend,
                    rbcrecv,
                    member_list
                ))

        # await asyncio.gather(*[rbc_tasks(j) for j in range(self.n)])
        await asyncio.gather(*rbc_tasks)

        trans_await_rbcl_list = time.time()
        self.rbcl_list = await asyncio.gather(*(rbc_outputs[j].get() for j in range(self.n)))
        trans_await_rbcl_list = time.time() - trans_await_rbcl_list
        # print(f"trans_await_rbcl_list: {trans_await_rbcl_list}")
    
    async def run_trans(self, len_values):
        self.member_list = []
        for i in range(self.n): 
            self.member_list.append(self.n * (self.mpc_instance.layer_ID) + i)


        trans_rbc_time = time.time()
        rbc_tasks = [None] * self.n
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]

        async def predicate(_m):
            return True

        async def _setup(dealer_id):


            rbctag =TRANSMsgType.MASK + str(dealer_id) # (M, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)
            rbc_input = None

            member_list = [(self.mpc_instance.layer_ID - 1) * self.n + dealer_id]
            for j in range(self.n): 
                member_list.append(self.n * (self.mpc_instance.layer_ID) + j)

            if self.my_id < dealer_id: 
                rbc_tasks[dealer_id] = asyncio.create_task(
                optqrbc_dynamic(
                    rbctag,
                    self.my_id,
                    self.n+1,
                    self.t,
                    dealer_id,
                    predicate,
                    rbc_input,
                    rbc_outputs[dealer_id].put_nowait,
                    rbcsend,
                    rbcrecv,
                    member_list
                ))
            else: 
                rbc_tasks[dealer_id] = asyncio.create_task(
                optqrbc_dynamic(
                    rbctag,
                    self.my_id+1,
                    self.n+1,
                    self.t,
                    dealer_id,
                    predicate,
                    rbc_input,
                    rbc_outputs[dealer_id].put_nowait,
                    rbcsend,
                    rbcrecv,
                    member_list
                ))

        trans_await_gather_rbc_time = time.time()
        await asyncio.gather(*[_setup(dealer_id) for dealer_id in range(self.n)])
        trans_await_gather_rbc_time = time.time() - trans_await_gather_rbc_time
        print(f"trans_await_gather_rbc_time: {trans_await_gather_rbc_time}")

        trans_await_rbcl_list = time.time()
        self.rbcl_list = await asyncio.gather(*(rbc_outputs[j].get() for j in range(self.n)))
        trans_await_rbcl_list = time.time() - trans_await_rbcl_list
        print(f"trans_await_rbcl_list: {trans_await_rbcl_list}")
        trans_rbc_time = time.time() - trans_rbc_time
        print(f"trans_rbc_time: {trans_rbc_time}")
        

        sr = Serial(self.G1)
        de_masked_values = [[self.ZR(0) for _ in range(self.n)] for _ in range(len_values)]
        for i in range(len_values): 
            for j in range(self.n): 
                de_masked_values[i][j] = int(sr.deserialize_f(self.rbcl_list[j][32*i:32*(i+1)]))

        

        return de_masked_values

  