from adkg.polynomial import polynomials_over
from adkg.utils.poly_misc import interpolate_g1_at_x
from adkg.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib, time, math
import logging
from adkg.utils.serilization import Serial
from adkg.utils.bitmap import Bitmap
from adkg.acss_ht import ACSS_HT

from adkg.broadcast.tylerba import tylerba
from adkg.broadcast.optqrbc import optqrbc

class ADKGMsgType:
    ACSS = "A"
    RBC = "R"
    ABA = "B"
    PREKEY = "P"
    KEY = "K"
    
class CP:
    def __init__(self, g, h, ZR):
        self.g  = g
        self.h = h
        self.ZR = ZR

    def dleq_derive_chal(self, x, y, a1, a2):
        commit = str(x)+str(y)+str(a1)+str(a2)
        try:
            commit = commit.encode()
        except AttributeError:
            pass 
        # TODO: Convert the hash output to a field element.
        hs =  hashlib.sha256(commit).digest() 
        return self.ZR.hash(hs)

    def dleq_verify(self, x, y, chal, res):
        a1 = (x**chal)*(self.g**res)
        a2 = (y**chal)*(self.h**res)
        eLocal = self.dleq_derive_chal(x, a1, y, a2)
        if eLocal == chal:
            return True
        return False

    def dleq_prove(self, alpha, x, y):
        w = self.ZR.random()
        a1 = self.g**w
        a2 = self.h**w
        e = self.dleq_derive_chal(x, a1, y, a2)
        return  e, w - e*alpha # return (challenge, response)

class ADKG:
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, ZR, G1):
        self.public_keys, self.private_key, self.g, self.h = (public_keys, private_key, g, h)
        self.n, self.t, self.deg, self.my_id = (n, t, deg, my_id)
        self.sc = math.ceil(deg/t) + 1
        self.send, self.recv, self.pc, self.ZR, self.G1 = (send, recv, pc, ZR, G1)
        self.poly = polynomials_over(self.ZR)
        self.poly.clear_cache() #FIXME: Not sure why we need this.
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send
        self.output_queue = asyncio.Queue()


        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )
            
    def kill(self):
        self.benchmark_logger.info("ADKG kill called")
        self.subscribe_recv_task.cancel()
        self.benchmark_logger.info("ADKG Recv task canceled called")
        for task in self.acss_tasks:
            task.cancel()
        self.benchmark_logger.info("ADKG ACSS tasks canceled")
        self.acss.kill()
        self.benchmark_logger.info("ADKG ACSS killed")
        self.acss_task.cancel()
        self.benchmark_logger.info("ADKG ACSS task killed")
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def acss_step(self, outputs, values, acss_signal):
        acsstag = ADKGMsgType.ACSS
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        self.acss = ACSS_HT(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, acsssend, acssrecv, self.pc)
        self.acss_tasks = [None] * self.n
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, values=values))
            else:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, dealer_id=i))

        while True:
            (dealer, _, shares, commitments) = await self.acss.output_queue.get()
            outputs[dealer] = {'shares':shares, 'commits':commitments}
            if len(outputs) >= self.n - self.t:
                # print("Player " + str(self.my_id) + " Got shares from: " + str([output for output in outputs]))
                acss_signal.set()

            if len(outputs) == self.n:
                return    

    async def commonsubset(self, rbc_out, acss_outputs, acss_signal, rbc_signal, rbc_values, coin_keys, aba_in, aba_out):
        assert len(rbc_out) == self.n
        assert len(aba_in) == self.n
        assert len(aba_out) == self.n

        aba_inputted = [False]*self.n
        aba_values = [0]*self.n

        async def _recv_rbc(j):
            # rbc_values[j] = await rbc_out[j]
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
            while True:
                acss_signal.clear()
                for k in rbc_values[j]:
                    if k not in acss_outputs.keys():
                        subset = False
                if subset:
                    coin_keys[j]((acss_outputs, rbc_values[j]))
                    return
                await acss_signal.wait()

        r_threads = [asyncio.create_task(_recv_rbc(j)) for j in range(self.n)]

        async def _recv_aba(j):
            aba_values[j] = await aba_out[j]()  # May block
            # print pid, j, 'ENTERING CRITICAL'
            # if sum(aba_values) >= self.n - self.t:
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

    async def agreement(self, key_proposal, acss_outputs, acss_signal):
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
                    if kk not in acss_outputs.keys():
                        subset = False
                if subset:
                    acss_signal.clear()    
                    return True
                acss_signal.clear()
                await acss_signal.wait()

        async def _setup(j):
            
            # starting RBC
            rbctag =ADKGMsgType.RBC + str(j) # (R, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id: 
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

            abatag = ADKGMsgType.ABA + str(j) # (B, msg)
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
        pre_key_signal  = asyncio.Event()
        pre_key_values = {'share':None, 'my_r_exp':None, 'r_exps': [None for _ in range(self.n)]}

        return (
            self.commonsubset(
                rbc_outputs,
                acss_outputs,
                acss_signal,
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.pre_key(
                acss_outputs,
                acss_signal,
                rbc_values,
                rbc_signal,
                pre_key_values, 
                pre_key_signal,
            ),
            self.derive_key(
                rbc_values,
                pre_key_values, 
                pre_key_signal,
            ),
            work_tasks,
        )

    async def pre_key(self, acss_outputs, acss_signal, rbc_values, rbc_signal, pre_key_values, pre_key_signal):
        await rbc_signal.wait()
        rbc_signal.clear()
        
        mks = set() # master key set
        for ks in  rbc_values:
            if ks is not None:
                mks = mks.union(set(list(ks)))
        
        # Waiting for all ACSS to terminate
        for k in mks:
            if k not in acss_outputs:
                await acss_signal.wait()
                acss_signal.clear()

        # share of the master secret
        z_0 = self.ZR(0)
        for node in mks:
            z_0 = z_0 + acss_outputs[node]['shares']['msg'][0]

        secrets = [[self.ZR(0)]*self.n for _ in range(self.sc-1)]
        randomness = [[self.ZR(0)]*self.n for _ in range(self.sc-1)]
        for idx in range(self.sc-1):
            for node in mks:
                secrets[idx][node] = acss_outputs[node]['shares']['msg'][idx+1]
                randomness[idx][node] = acss_outputs[node]['shares']['msg'][idx]
        
        matrix = [[self.ZR(i+1)**j for j in range(self.n)] for i in range(self.t+1)]

        z_shares = {0:z_0}
        r_shares = {0:self.ZR(0)}

        def dot(a, b):
            res = self.ZR(0)
            for i in range(len(a)):
                res = res + a[i]*b[i]
            return res

        for i in range(self.t+1):
            z_shares[i+1] = dot(matrix[i], secrets[0])
            r_shares[i+1] = dot(matrix[i], randomness[0])
        for i in range(self.t+1, self.deg):
            z_shares[i+1] = dot(matrix[i-(self.t+1)], secrets[1])
            r_shares[i+1] = dot(matrix[i-(self.t+1)], randomness[1])
        
        for i in range(self.deg, self.n):
            z_shares[i+1] = self.poly.interpolate_at( list(z_shares.items()), i+1)
            r_shares[i+1] = self.poly.interpolate_at(list(r_shares.items()), i+1)
        
        r_exps = [self.h**r_shares[i+1] for i in range(self.n)]

        
        # Sending PREKEY messages
        keytag = ADKGMsgType.PREKEY
        send, recv = self.get_send(keytag), self.subscribe_recv(keytag)

        for i in range(self.n):
            send(i, (z_shares[i+1], r_exps))
        
        
        sk_shares = []
        r_exp_shares = []
        while True:
            # TODO(@sourav) FIXME!! Important to add validation checks
            (sender, msg) = await recv()
            sk_share, sender_r_exp = msg
            sk_shares.append([sender+1, sk_share])
            r_exp_shares.append([sender+1, sender_r_exp[sender]])
            pre_key_values['r_exps'][sender] = sender_r_exp
            if len(sk_shares) == self.t+1:
                pre_key_values['share'] =  self.poly.interpolate_at(sk_shares, 0)
                pre_key_values['my_r_exp'] = interpolate_g1_at_x(r_exp_shares, 0, self.G1, self.ZR)
                pre_key_signal.set()
            
            if len(sk_shares) == self.n:
                return
        

    async def derive_key(self, rbc_values, pre_key_values, pre_key_signal):
        # Waiting for the ABA to terminate
        await pre_key_signal.wait()
        pre_key_signal.clear()

        secret = pre_key_values['share']
        x = self.g**secret
        y = self.h**secret
        cp = CP(self.g, self.h, self.ZR)
        chal, res = cp.dleq_prove(secret, x, y)
        r_exps_row = [None]*self.n

        keytag = ADKGMsgType.KEY
        send, recv = self.get_send(keytag), self.subscribe_recv(keytag)

        sr = Serial(self.G1)
        yb, chalb, resb = sr.serialize_g(y), sr.serialize_f(chal), sr.serialize_f(res)
        for i in range(self.n):
            send(i, (yb, chalb, resb, r_exps_row))

        pk_shares = []
        while True:
            (sender, msg) = await recv()
            yb, chalb, resb, r_exp_sender_row = msg
            y, chal, res =  sr.deserialize_g(yb), sr.deserialize_f(chalb), sr.deserialize_f(resb)
            
            # TODO(@sourav): FIXME!! IMPORTANT to add this verification
            # if cp.dleq_verify(agg_x[sender], y, chal, res):
            pk_shares.append([sender+1, y])
            if len(pk_shares) > self.deg:
                break
        pk =  interpolate_g1_at_x(pk_shares, 0, self.G1, self.ZR)

        mks = set() # master key set only for testing purposes
        for ks in  rbc_values:
            if ks is not None:
                mks = mks.union(set(list(ks)))
        
        return (mks, secret, pk)

    async def run_adkg(self, start_time):
        acss_outputs = {}
        acss_signal = asyncio.Event()

        acss_start_time = time.time()
        values =[self.ZR.rand() for _ in range(self.sc)]
        self.acss_task = asyncio.create_task(self.acss_step(acss_outputs, values, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()
        acss_time = time.time() - acss_start_time
        logging.info(f"ACSS time: {(acss_time)}")
        key_proposal = list(acss_outputs.keys())
        create_acs_task = asyncio.create_task(self.agreement(key_proposal, acss_outputs, acss_signal))
        acs, pre_key_task, key_task, work_tasks = await create_acs_task
        await acs
        await pre_key_task
        output = await key_task
        adkg_time = time.time()-start_time
        self.benchmark_logger.info("ADKG time2: %f", adkg_time)
        logging.info(f"ADKG time: {(adkg_time)}")
        await asyncio.gather(*work_tasks)
        mks, sk, pk = output
        self.output_queue.put_nowait((values[0], mks, sk, pk))