import asyncio
from collections import defaultdict
# from pickle import dumps, loads
import re, time, math
from adkg.polynomial import polynomials_over
from adkg.symmetric_crypto import SymmetricCrypto
from adkg.utils.misc import wrap_send, subscribe_recv
from adkg.broadcast.optqrbc import optqrbc, optqrbc_dynamic
from adkg.utils.serilization import Serial
from adkg.poly_commit_log import PolyCommitLog
import zlib, pickle, copy, hashlib
# from pickle import dumps, loads

# adkg/acss.py  ── import 区域
from concurrent.futures import ThreadPoolExecutor
import os
# Thread‑pool shared by all ACSS instances — one worker per CPU core
_VERIFY_POOL = ThreadPoolExecutor(max_workers=os.cpu_count())

from pypairing import ZR, G1, blsmultiexp as multiexp, dotprod
from pypairing.pypairing import deserialize_many_g1, serialize_many_g1, polycommit_commit, polycommit_commit_batch, polycommit_prove_double_batch_inner_product_opt, polycommit_verify_double_batch_inner_product_one_known_but_differenter, polycommit_commit_transfer_batch, polycommit_prove_sigma, polycommit_verify_sigma



import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

# Uncomment this when you want logs from this file.
# logger.setLevel(logging.DEBUG)


class HbAVSSMessageType:
    OK = 1
    IMPLICATE = 2
    RECOVERY = 4
    RECOVERY1 = 5
    RECOVERY2 = 6
    KDIBROADCAST = 7

class ACSS:
    #@profile
    def __init__(
            self, public_keys, private_key, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1
            , rbc_values=None
    ):  # (# noqa: E501)
        self.public_keys, self.private_key = public_keys, private_key
        self.n, self.t, self.deg, self.my_id = n, t, deg, my_id
        self.g, self.h = g, h 
        self.sr = Serial(G1)
        self.sc = sc 
        self.poly_commit = pc

        self.gs = G1.hash_many(b"hbPolyCommitg", t+1)
        self.u = G1.hash(b"hbPolyCommitu")
        crs = [self.gs, self.h, self.u]
        self.poly_commit_log = PolyCommitLog(crs=crs, degree_max=deg)
        # self.poly_commit_log = PolyCommitLog(crs=None, degree_max=deg)

        
        if rbc_values is not None: 
            self.rbc_values = rbc_values
        
        self.multiexp = multiexp

        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )

        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send

        self.acss_status = defaultdict(lambda: True)
        self.field = field
        self.poly = polynomials_over(self.field)
        self.poly.clear_cache()
        self.output_queue = asyncio.Queue()
        self.tagvars = {}
        self.tasks = []
        self.data = {}

    def __enter__(self):
        return self

    #def __exit__(self, typ, value, traceback):
    def kill(self):
        # self.benchmark_logger.info("ACSS kill called")
        self.subscribe_recv_task.cancel()
        # self.benchmark_logger.info("ACSS recv task cancelled")
        for task in self.tasks:
            task.cancel()
        # self.benchmark_logger.info("ACSS self.tasks cancelled")
        for key in self.tagvars:
            for task in self.tagvars[key]['tasks']:
                task.cancel()
        # self.benchmark_logger.info("ACSS self tagvars canceled")

    
    #@profile
    async def _handle_implication(self, tag, j, idx, j_sk):
        """
        Handle the implication of AVSS.
        Return True if the implication is valid, False otherwise.
        """
        commitments =  self.tagvars[tag]['commitments']
        # discard if PKj ! = g^SKj
        if self.public_keys[j] != self.g**j_sk:
            return False
        # decrypt and verify
        implicate_msg = None #FIXME: IMPORTANT!!
        j_shared_key = (self.tagvars[tag]['ephemeral_public_key'])**j_sk

        # Same as the batch size
        secret_count = len(commitments)

        try:
            j_shares, j_witnesses = SymmetricCrypto.decrypt(
                j_shared_key.__getstate__(), implicate_msg
            )
        except Exception as e:  # TODO specific exception
            logger.warn("Implicate confirmed, bad encryption:", e)
            return True
        return not self.poly_commit.batch_verify_eval(
            commitments[idx], j + 1, j_shares, j_witnesses, self.t
        )

    def _init_recovery_vars(self, tag):
        self.kdi_broadcast_sent = False
        self.saved_shares = [None] * self.n
        self.saved_shared_actual_length = 0
        self.interpolated = False

    # this function should eventually multicast OK, set self.tagvars[tag]['all_shares_valid'] to True, and set self.tagvars[tag]['shares']
    #@profile
    async def _handle_share_recovery(self, tag, sender=None, avss_msg=[""]):
        send, recv, multicast = self.tagvars[tag]['io']
        if not self.tagvars[tag]['in_share_recovery']:
            return
        if self.tagvars[tag]['all_shares_valid'] and not self.kdi_broadcast_sent:
            logger.debug("[%d] sent_kdi_broadcast", self.my_id)
            kdi = self.tagvars[tag]['shared_key']
            multicast((HbAVSSMessageType.KDIBROADCAST, kdi))
            self.kdi_broadcast_sent = True
        if self.tagvars[tag]['all_shares_valid']:
            return

        if avss_msg[0] == HbAVSSMessageType.KDIBROADCAST:
            logger.debug("[%d] received_kdi_broadcast from sender %d", self.my_id, sender)
            
            # FIXME: IMPORTANT!! read the message from rbc output
            # retrieved_msg = await avid.retrieve(tag, sender)
            retrieved_msg = None
            try:
                j_shares, j_witnesses = SymmetricCrypto.decrypt(
                    avss_msg[1].__getstate__(), retrieved_msg
                )
            except Exception as e:  # TODO: Add specific exception
                logger.debug("Implicate confirmed, bad encryption:", e)
            commitments = self.tagvars[tag]['commitments']
            if (self.poly_commit.batch_verify_eval(commitments,
                                                   sender + 1, j_shares, j_witnesses, self.t)):
                if not self.saved_shares[sender]:
                    self.saved_shared_actual_length += 1
                    self.saved_shares[sender] = j_shares

        # if t+1 in the saved_set, interpolate and sell all OK
        if self.saved_shared_actual_length >= self.t + 1 and not self.interpolated:
            logger.debug("[%d] interpolating", self.my_id)
            # Batch size
            shares = []
            secret_count = len(self.tagvars[tag]['commitments'])
            for i in range(secret_count):
                phi_coords = [
                    (j + 1, self.saved_shares[j][i]) for j in range(self.n) if self.saved_shares[j] is not None
                ]
                shares.append(self.poly.interpolate_at(phi_coords, self.my_id + 1))
            self.tagvars[tag]['all_shares_valid'] = True
            self.tagvars[tag]['shares'] = shares
            self.tagvars[tag]['in_share_recovery'] = False
            self.interpolated = True
            multicast((HbAVSSMessageType.OK, ""))

        # ------------------------------------------------------------------
    # Helpers to off‑load decode + verify to the thread pool
    # ------------------------------------------------------------------
    def _decode_and_verify_log_sync(self, dealer_id: int, m_bytes: bytes, rand_num: int) -> bool:
        """Sync helper used by run_in_executor for LOG variant."""
        dispersal_msg, commits, shared, ephkey = self.decode_proposal_log(m_bytes, rand_num)

        ok = self.verify_proposal_log(dealer_id, dispersal_msg, commits, shared, ephkey, rand_num)
        return ok

    def _decode_and_verify_bundle_log_sync(self, dealer_id: int, m_bytes: bytes, rand_num: int) -> bool:
        """Sync helper used by run_in_executor for LOG variant."""
        dispersal_msg, commits, shared, ephkey, proof_tuple, W_list = self.decode_proposal_bundle_log(m_bytes, rand_num)

        ok = self.verify_proposal_bundle_log(dealer_id, dispersal_msg, commits, shared, ephkey, rand_num, proof_tuple, W_list)
        return ok

    def _decode_and_verify_trans_log_sync(self, dealer_id: int, m_bytes: bytes, len_values: int) -> bool:
        """Sync helper used by run_in_executor for TRANS‑LOG variant."""
        decode_time = time.time()
        disp, commit_peds, commit_tests, omega, mask, hat_mask, w, shared, ephkey = self.decode_proposal_trans_log(
            m_bytes, len_values
        )
        decode_time = time.time() - decode_time
        verify_time = time.time()
        ok = self.verify_proposal_trans_log(
            dealer_id, disp, commit_peds, commit_tests, omega, mask, hat_mask, w, shared, ephkey, len_values
        )
        verify_time = time.time() - verify_time
        return ok
    
    

    def decode_proposal_log(self, proposal: bytes, poly_num: int):
        """
        Layout (new):
            commitments (poly_num × g_size)
          + shared
          + ciphertext_block (n equal fragments)
          + eph_public_key
        Returns
        -------
        (ctx_bytes, commits, shared, ephkey)
        """
        g_size = self.sr.g_size
        f_size = self.sr.f_size

        # ---- 1) commitments -------------------------------------------------
        com_size = g_size * poly_num
        t0 = time.time()
        # commits_all = self.sr.deserialize_gs(proposal[0:com_size])
        t0 = time.time() - t0

        # Use the Rust‑side fast deserializer (Vec<PyG1>) instead of Python fallback
        deserialize_many_g1_time = time.time()
        commits_all = deserialize_many_g1(bytes(proposal[0:com_size]))

        der_time = time.time()
        # ---- 2) shared ------------------------------------------------------
        idx = com_size

        # roothash
        rlen = int.from_bytes(proposal[idx:idx + 2], "big"); idx += 2
        roothash = proposal[idx:idx + rlen]; idx += rlen

        # t, mu
        t_mu = self.sr.deserialize_fs(proposal[idx:idx + 2 * f_size])
        t, mu = int(t_mu[0]), t_mu[1]
        idx += 2 * f_size

        # S
        S = self.sr.deserialize_g(proposal[idx:idx + g_size]); idx += g_size

        # Use the Rust‑side fast deserializer (Vec<PyG1>) instead of Python fallback
        Ds = deserialize_many_g1(bytes(proposal[idx: idx + poly_num * g_size]))
        idx += poly_num * g_size

        shared = [roothash, t, S, Ds, mu]

        # ---- 3) ciphertext block -------------------------------------------
        ephkey_size = g_size
        ciphertext_block = proposal[idx:-ephkey_size]

        per_cipher_len = len(ciphertext_block) // self.n
        ctx_start = per_cipher_len * self.my_id
        ctx_end = ctx_start + per_cipher_len
        ctx_bytes = ciphertext_block[ctx_start:ctx_end]

        # ---- 4) dealer’s ephemeral public key -------------------------------
        ephkey = self.sr.deserialize_g(proposal[-ephkey_size:])

        return ctx_bytes, commits_all, shared, ephkey

    def decode_proposal_bundle_log(self, proposal: bytes, poly_num: int):
        """
        Layout (new):
            commitments (poly_num × g_size)
          + shared
          + ciphertext_block (n equal fragments)
          + eph_public_key
        Returns
        -------
        (ctx_bytes, commits, shared, ephkey)
        """
        g_size = self.sr.g_size
        f_size = self.sr.f_size

        # ---- 1) commitments -------------------------------------------------
        com_size = g_size * poly_num
        t0 = time.time()
        # commits_all = self.sr.deserialize_gs(proposal[0:com_size])
        t0 = time.time() - t0

        # Use the Rust‑side fast deserializer (Vec<PyG1>) instead of Python fallback
        deserialize_many_g1_time = time.time()
        commits_all = deserialize_many_g1(bytes(proposal[0:com_size]))

        der_time = time.time()
        # ---- 2) shared ------------------------------------------------------
        idx = com_size

        # roothash
        rlen = int.from_bytes(proposal[idx:idx + 2], "big"); idx += 2
        roothash = proposal[idx:idx + rlen]; idx += rlen

        # t, mu
        t_mu = self.sr.deserialize_fs(proposal[idx:idx + 2 * f_size])
        t, mu = int(t_mu[0]), t_mu[1]
        idx += 2 * f_size

        # S
        S = self.sr.deserialize_g(proposal[idx:idx + g_size]); idx += g_size

        # Use the Rust‑side fast deserializer (Vec<PyG1>) instead of Python fallback
        Ds = deserialize_many_g1(bytes(proposal[idx: idx + poly_num * g_size]))
        idx += poly_num * g_size

        shared = [roothash, t, S, Ds, mu]

        # ---- 2.5) Sigma proof -----------------------------------------------
        # number of proof elements per list (half of Ds)
        mid = len(Ds) // 2
        t_plus_1 = len(self.gs)

        # T1, T2, T3, W: mid G1
        T1_list = self.sr.deserialize_gs(proposal[idx: idx + mid * g_size])
        idx += mid * g_size
        T2_list = self.sr.deserialize_gs(proposal[idx: idx + mid * g_size])
        idx += mid * g_size
        T3_list = self.sr.deserialize_gs(proposal[idx: idx + mid * g_size])
        idx += mid * g_size
        W_list  = self.sr.deserialize_gs(proposal[idx: idx + mid * g_size])
        idx += mid * g_size
        # z_r_list: mid  Fr
        z_r_list = self.sr.deserialize_fs(proposal[idx: idx + mid * f_size])
        idx += mid * f_size
        # z_coeffs: mid × (t+1)
        zc_list = []
        for _ in range(mid):
            row = self.sr.deserialize_fs(proposal[idx: idx + (t_plus_1) * f_size])
            idx += (t_plus_1) * f_size
            zc_list.append(row)
        # z_hatcoeffs: mid × (t+1)
        zh_list = []
        for _ in range(mid):
            row = self.sr.deserialize_fs(proposal[idx: idx + (t_plus_1) * f_size])
            idx += (t_plus_1) * f_size
            zh_list.append(row)
        # e: single Fr
        e_list = self.sr.deserialize_fs(proposal[idx: idx + f_size])
        e = e_list[0]
        idx += f_size

        # ---- 3) ciphertext block -------------------------------------------
        ephkey_size = g_size
        ciphertext_block = proposal[idx:-ephkey_size]

        per_cipher_len = len(ciphertext_block) // self.n
        ctx_start = per_cipher_len * self.my_id
        ctx_end = ctx_start + per_cipher_len
        ctx_bytes = ciphertext_block[ctx_start:ctx_end]

        # ---- 4) dealer’s ephemeral public key -------------------------------
        ephkey = self.sr.deserialize_g(proposal[-ephkey_size:])

        proof_tuple = (
            T1_list,
            T2_list,
            T3_list,
            z_r_list,
            zc_list,
            zh_list,
            e
        )
        # 返回 ctx_bytes, 承诺, shared, ephkey, proof_tuple, W_list
        return ctx_bytes, commits_all, shared, ephkey, proof_tuple, W_list

    def decode_proposal_trans_log(self, proposal, com_num):
        
        g_size = self.sr.g_size
        # deserializing commitments
        com_size = g_size * com_num * 2
        t0 = time.time()
        # commits_all = self.sr.deserialize_gs(proposal[0:com_size])
        t0 = time.time() - t0

        # Use the Rust‑side fast deserializer (Vec<PyG1>) instead of Python fallback
        deserialize_many_g1_time = time.time()
        commits_all = deserialize_many_g1(bytes(proposal[0:com_size]))

        der_time = time.time()

        # Split out Pedersen and polynomial commitments
        commit_peds = commits_all[0::2]
        commit_tests = commits_all[1::2]

        # --- Parse the appended proof elements: omega, gamma, masked ---
        f_size = self.sr.f_size


        offset = com_size

        # omega_agg
        omega = self.sr.deserialize_g(proposal[offset: offset + g_size])
        offset += g_size

        # mask_agg
        mask_agg = self.sr.deserialize_fs(proposal[offset: offset + f_size])[0]
        offset += f_size

        # hat_mask_agg
        hat_mask_agg = self.sr.deserialize_fs(proposal[offset: offset + f_size])[0]
        offset += f_size

        # w_agg
        w_agg = self.sr.deserialize_g(proposal[offset: offset + g_size])
        offset += g_size


        # idx = com_size + 2 * g_size + f_size
        idx = offset

        # roothash
        rlen = int.from_bytes(proposal[idx:idx + 2], "big"); idx += 2
        roothash = proposal[idx:idx + rlen]; idx += rlen

        # t, mu
        t_mu = self.sr.deserialize_fs(proposal[idx:idx + 2 * f_size])
        t, mu = int(t_mu[0]), t_mu[1]
        idx += 2 * f_size

        # S
        S = self.sr.deserialize_g(proposal[idx:idx + g_size]); idx += g_size

        # Ds

        t1 = time.time()
        # Ds = self.sr.deserialize_gs(proposal[idx: idx + com_num * g_size])
        t1 = time.time() - t1

        # Use the Rust‑side fast deserializer (Vec<PyG1>) instead of Python fallback
        deserialize_many_g1_time = time.time()
        Ds = deserialize_many_g1(bytes(proposal[idx: idx + com_num * g_size]))
        idx += com_num * g_size

        shared = [roothash, t, S, Ds, mu]

        # --- Ciphertexts block (one ciphertext per node) ---
        # All ciphertexts are stored consecutively after the commitments and proof elements,
        # and before the final `ephemeral_public_key` (whose size is `self.sr.g_size`).
        ephkey_size = self.sr.g_size
        # ciphertexts start after commitments and proof elements
        ciphertext_block_start = idx
        ciphertext_block = proposal[ciphertext_block_start:-ephkey_size]

        # Each node's ciphertext is the same length (payload + AEAD overhead).
        # We infer that length by dividing the block equally.
        per_cipher_len = len(ciphertext_block) // self.n
        if len(ciphertext_block) % self.n != 0:
            raise ValueError("Ciphertext block length not divisible by n; "
                             "check serialization logic.")

        ctx_start = per_cipher_len * self.my_id
        ctx_end = ctx_start + per_cipher_len
        ctx_bytes = ciphertext_block[ctx_start:ctx_end]

        # deserializing the ephemeral public key
        ephkey = self.sr.deserialize_g(proposal[ciphertext_block_start + len(ciphertext_block):])


        return (ctx_bytes, commit_peds, commit_tests, omega, mask_agg, hat_mask_agg, w_agg, shared, ephkey)
    
    def decode_proposal(self, proposal):
        g_size = self.sr.g_size
        c_size = 32

        # deserializing commitments
        com_size = g_size*(self.t+1)*(self.rand_num)
        commits_all = self.sr.deserialize_gs(proposal[0:com_size])
        commits = [commits_all[i*(self.t+1):(i+1)*(self.t+1)] for i in range(self.rand_num)]

        # deserializing ciphertexts
        # IMPORTANT: Here 32 additional bytes are used in the ciphertext for padding
        ctx_size = (c_size*2*self.rand_num+c_size)*self.n
        my_ctx_start = com_size + (c_size*2*self.rand_num+c_size)*self.my_id
        my_ctx_end = my_ctx_start + (c_size*2*self.rand_num+c_size)
        ctx_bytes = proposal[my_ctx_start:my_ctx_end]

        # deserializing the ephemeral public key
        ephkey = self.sr.deserialize_g(proposal[com_size+ctx_size:])
        
        return (ctx_bytes, commits, ephkey)
    
    def decode_proposal_trans(self, proposal):
        g_size = self.sr.g_size
        c_size = 32

        # deserializing commitments
        com_size = g_size*(self.t+1)*(self.len_values)
        commits_all = self.sr.deserialize_gs(proposal[0:com_size])
        commits = [commits_all[i*(self.t+1):(i+1)*(self.t+1)] for i in range(self.len_values)]

        # deserializing ciphertexts
        # IMPORTANT: Here 32 additional bytes are used in the ciphertext for padding
        ctx_size = (c_size*2*self.len_values+c_size)*self.n
        my_ctx_start = com_size + (c_size*2*self.len_values+c_size)*self.my_id
        my_ctx_end = my_ctx_start + (c_size*2*self.len_values+c_size)
        ctx_bytes = proposal[my_ctx_start:my_ctx_end]

        # deserializing the ephemeral public key
        ephkey = self.sr.deserialize_g(proposal[com_size+ctx_size:])
        
        return (ctx_bytes, commits, ephkey)

   
    def decode_proposal_aprep(self, proposal):
        g_size = self.sr.g_size
        c_size = 32

        # deserializing commitments
        com_size = g_size*(self.t+1)*(self.cm)*(3+3)
        # print(f"id: {self.my_id} proposal: {proposal[0:com_size]}")
        commits_all = self.sr.deserialize_gs(proposal[0:com_size])
        # print(f"commits_all: {commits_all}")
        mult_triples_commits = [[] for _ in range(self.cm)]
        chec_triples_commits = [[] for _ in range(self.cm)]
        rand_values_commits = []
        num = 0
        for i in range(self.cm): 
            mult_triples_commits[i] = []
            chec_triples_commits[i] = []
            for j in range(3): 
                mult_triples_commits[i].append(commits_all[num*(self.t+1):(num+1)*(self.t+1)])
                num += 1
            for j in range(3): 
                chec_triples_commits[i].append(commits_all[num*(self.t+1):(num+1)*(self.t+1)])
                num += 1
            # rand_values_commits.append(commits_all[num*(self.t+1):(num+1)*(self.t+1)])
            # num += 1

        commits = (mult_triples_commits, chec_triples_commits)

        ctx_size = (c_size*2*self.cm*(3+3)+c_size)*self.n
        my_ctx_start = com_size + (c_size*2*self.cm*(3+3)+c_size)*self.my_id
        my_ctx_end = my_ctx_start + c_size*2*self.cm*(3+3) + c_size
        ctx_bytes = proposal[my_ctx_start:my_ctx_end]

        ephkey = self.sr.deserialize_g(proposal[com_size+ctx_size:])
        
        return (ctx_bytes, commits, ephkey)

    def verify_proposal_bundle_log(self, dealer_id, dispersal_msg, commits, shared, ephkey, poly_num, proof_tuple, W_list):
        """
        Decrypt, parse <phis | witness>, then batch-verify with `shared`.
        """
        start_time = time.time()
        # the current node does not have a private key, so it cannot verify
        if self.private_key is None:
            return True

        mid = len(commits) // 2
        C_list    = commits[:mid]
        Chat_list = commits[mid:]
        verify_sigma_ok = polycommit_verify_sigma(
            C_list,
            Chat_list,
            W_list,
            proof_tuple,
            self.poly_commit_log.gs,
            self.poly_commit_log.h
        )
        if not verify_sigma_ok:
            self.acss_status[dealer_id] = False
            return False

        decrypt_time = time.time()
        shared_key = ephkey ** self.private_key
        try:
            plaintext = SymmetricCrypto.decrypt(shared_key.__getstate__(), dispersal_msg)
        except ValueError as e:
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            self.acss_status[dealer_id] = False
            return False
        decrypt_time = time.time() - decrypt_time

        # --- split phis / witness ------------------------------------------
        f_size = self.sr.f_size
        phis_bytes_len = poly_num * f_size
        phis_time = time.time()
        phis = self.sr.deserialize_fs(plaintext[:phis_bytes_len])
        phis_time = time.time() - phis_time
        witness_blob = plaintext[phis_bytes_len:]
        wit_time = time.time()
        witness = self.deserialize_witness(witness_blob, poly_num)
        wit_time = time.time() - wit_time

        
        if dealer_id > 2 * self.t:
            self.acss_status[dealer_id] = True
            self.data[dealer_id] = [commits, phis, witness, ephkey, shared_key, W_list]
            return True
        

        i = self.my_id + 1
        verify_time = time.time()
        ok = self.poly_commit_log.batch_verify_eval_rs(
            commits, i, phis, shared, witness, self.t
        )
        verify_time = time.time() - verify_time

        self.acss_status[dealer_id] = ok
        if ok:
            self.data[dealer_id] = [commits, phis, witness, ephkey, shared_key, W_list]
        return ok

    def verify_proposal_log(self, dealer_id, dispersal_msg, commits, shared, ephkey, poly_num):
        """
        Decrypt, parse <phis | witness>, then batch-verify with `shared`.
        """
        start_time = time.time()
        # the current node does not have a private key, so it cannot verify
        if self.private_key is None:
            return True

        decrypt_time = time.time()
        shared_key = ephkey ** self.private_key
        try:
            plaintext = SymmetricCrypto.decrypt(shared_key.__getstate__(), dispersal_msg)
        except ValueError as e:
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            self.acss_status[dealer_id] = False
            return False
        decrypt_time = time.time() - decrypt_time

        # --- split phis / witness ------------------------------------------
        f_size = self.sr.f_size
        phis_bytes_len = poly_num * f_size
        phis_time = time.time()
        phis = self.sr.deserialize_fs(plaintext[:phis_bytes_len])
        phis_time = time.time() - phis_time
        witness_blob = plaintext[phis_bytes_len:]
        wit_time = time.time()
        witness = self.deserialize_witness(witness_blob, poly_num)
        wit_time = time.time() - wit_time

        
        if dealer_id > 2 * self.t:
            self.acss_status[dealer_id] = True
            self.data[dealer_id] = [commits, phis, witness, ephkey, shared_key]
            return True
        

        i = self.my_id + 1
        verify_time = time.time()
        ok = self.poly_commit_log.batch_verify_eval_rs(
            commits, i, phis, shared, witness, self.t
        )
        verify_time = time.time() - verify_time

        self.acss_status[dealer_id] = ok
        if ok:
            self.data[dealer_id] = [commits, phis, witness, ephkey, shared_key]
        return ok

    def verify_proposal_trans_log(self, dealer_id, dispersal_msg, commit_peds, commit_tests, omega, mask, hat_mask, w, shared, ephkey, poly_num):


        if self.private_key is None:
            return True

        shared_key = ephkey ** self.private_key

        try:
            sharesb = SymmetricCrypto.decrypt(shared_key.__getstate__(), dispersal_msg)
        except ValueError as e:
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            self.acss_status[dealer_id] = False
            return False

        f_size = self.sr.f_size
        phis_length_bytes = poly_num * f_size
        phisb = sharesb[:phis_length_bytes]
        phis = self.sr.deserialize_fs(phisb)

        witnessb = sharesb[phis_length_bytes:]
        witness = self.deserialize_witness(witnessb, poly_num)  

        
        if dealer_id > 2 * self.t:
            self.acss_status[dealer_id] = True
            self.data[dealer_id] = [commit_peds, commit_tests, phis, witness, omega, mask, hat_mask, w, ephkey, shared_key]
            return True

        i = self.my_id + 1
        final_commitments = [commit_peds[k] * commit_tests[k] for k in range(len(commit_tests))]
        verify_time = time.time()
        verified = self.poly_commit_log.batch_verify_eval_rs(final_commitments, i, phis, shared, witness, self.t)
        verify_time = time.time() - verify_time

        if not verified:
            self.acss_status[dealer_id] = False
            return False
        
        # Verify aggregated consistency proof (Algorithm 6)
        g_s_agg = G1.identity()
        for ped in commit_peds:
            g_s_agg *= ped
        if not self.verify_consis_bundle(g_s_agg, mask, hat_mask, omega):
            print(f"my id: {self.my_id} verify_consis failed")
            self.acss_status[dealer_id] = False
            return False

        self.acss_status[dealer_id] = True
        self.data[dealer_id] = [commit_peds, commit_tests, phis, witness, omega, mask, hat_mask, w, ephkey, shared_key]
        return True

    
    def verify_proposal(self, dealer_id, dispersal_msg, commits, ephkey):


        if self.private_key == None:
            return True

        
        shared_key = ephkey**self.private_key
        
        try:
            sharesb = SymmetricCrypto.decrypt(shared_key.__getstate__(), dispersal_msg)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            self.acss_status[dealer_id] = False
            return False
        
        shares = self.sr.deserialize_fs(sharesb)

        
        
        phis, phis_hat = shares[:self.rand_num], shares[self.rand_num:]
        
        # check the feldman commitment of the first secret
        for i in range(self.rand_num):
            
            if not self.poly_commit.verify_eval(commits[i], self.my_id + 1, phis[i], phis_hat[i]): 
                self.acss_status[dealer_id] = False
                return False
        
        
        self.acss_status[dealer_id] = True
        self.data[dealer_id] = [commits, phis, phis_hat, ephkey, shared_key]
        return True

    def verify_proposal_trans(self, dealer_id, dispersal_msg, commits, ephkey):

        
        if self.private_key == None:
            return True

        

        shared_key = ephkey**self.private_key


        try:
            sharesb = SymmetricCrypto.decrypt(shared_key.__getstate__(), dispersal_msg)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            self.acss_status[dealer_id] = False
            return False

        shares = self.sr.deserialize_fs(sharesb)
        phis, phis_hat = shares[:self.len_values], shares[self.len_values:]
        # check the feldman commitment of the first secret
        
        for i in range(self.len_values):
            if not self.poly_commit.verify_eval(commits[i], self.my_id + 1, phis[i], phis_hat[i]): 
                self.acss_status[dealer_id] = False
                return False
            

        
        g_size = self.sr.g_size
        f_size = self.sr.f_size
        serialized_masked_values = self.rbc_values[dealer_id][:f_size*self.len_values]
        serialized_masked_values_hat = self.rbc_values[dealer_id][f_size*self.len_values:2*f_size*self.len_values]
        serialized_c = self.rbc_values[dealer_id][2*f_size*self.len_values:(2*f_size+g_size)*self.len_values]

        de_masked_values = self.sr.deserialize_fs(serialized_masked_values)
        de_masked_values_hat = self.sr.deserialize_fs(serialized_masked_values_hat)
        de_c = self.sr.deserialize_gs(serialized_c)

       
        for i in range(self.len_values): 
            if self.multiexp([self.g, self.h], [de_masked_values[i], de_masked_values_hat[i]]) != de_c[i] * commits[i][0]: 
                self.acss_status[dealer_id] = False
                return False
        
        
        self.acss_status[dealer_id] = True
        self.data[dealer_id] = [commits, phis, phis_hat, ephkey, shared_key]
        return True
    
    def verify_proposal_aprep(self, dealer_id, dispersal_msg, commits, ephkey):

        
        if self.private_key == None:
            return True

        shared_key = ephkey**self.private_key

        mult_triples_commits, chec_triples_commits = commits

       

        try:
            sharesb = SymmetricCrypto.decrypt(shared_key.__getstate__(), dispersal_msg)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            self.acss_status[dealer_id] = False
            return False

        shares = self.sr.deserialize_fs(sharesb)

        phi_mult_triples_si_list = shares[:self.cm*3]
        phi_mult_triples_hat_si_list = shares[self.cm*3:self.cm*3*2]
        phi_chec_triples_si_list = shares[self.cm*3*2:self.cm*3*3]
        phi_chec_triples_hat_si_list = shares[self.cm*3*3:self.cm*3*4]
        # phi_rand_values_si = shares[self.cm*3*4:self.cm*3*4+self.cm]
        # phi_rand_values_hat_si = shares[self.cm*3*4+self.cm:self.cm*3*4+self.cm*2]

        phi_mult_triples_si = [[] for _ in range(self.cm)]
        phi_mult_triples_hat_si = [[] for _ in range(self.cm)]
        phi_chec_triples_si = [[] for _ in range(self.cm)]
        phi_chec_triples_hat_si = [[] for _ in range(self.cm)]

        num = 0
        for i in range(self.cm): 
            phi_mult_triples_si[i] = phi_mult_triples_si_list[num:num+3]
            phi_mult_triples_hat_si[i] = phi_mult_triples_hat_si_list[num:num+3]
            phi_chec_triples_si[i] = phi_chec_triples_si_list[num:num+3]
            phi_chec_triples_hat_si[i] = phi_chec_triples_hat_si_list[num:num+3]

            num += 3
        

        for i in range(self.cm): 
            for j in range(3): 
                if not self.poly_commit.verify_eval(mult_triples_commits[i][j], self.my_id + 1, phi_mult_triples_si[i][j], phi_mult_triples_hat_si[i][j]): 
                    self.acss_status[dealer_id] = False
                    return False
                if not self.poly_commit.verify_eval(chec_triples_commits[i][j], self.my_id + 1, phi_chec_triples_si[i][j], phi_chec_triples_hat_si[i][j]): 
                    self.acss_status[dealer_id] = False
                    return False

            
        
        self.acss_status[dealer_id] = True
        phis = (phi_mult_triples_si, phi_chec_triples_si)
        phis_hat = (phi_mult_triples_hat_si, phi_chec_triples_hat_si)
        self.data[dealer_id] = [commits, phis, phis_hat, ephkey, shared_key]
        return True
    
    #@profile    
    async def _process_avss_msg_trans_log(self, avss_id, dealer_id, rbc_msg):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self._init_recovery_vars(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['in_share_recovery'] = False
        
        ok_set = set()
        implicate_set = set()
        output = False

        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs_trans_log(tag, dealer_id)

        if self.tagvars[tag]['all_shares_valid']:
            shares = {'msg': self.tagvars[tag]['shares']}
            commitments = self.tagvars[tag]['commitments']
            omega = self.tagvars[tag]['omega']
            gamma = self.tagvars[tag]['gamma']
            masked = self.tagvars[tag]['masked']
            self.output_queue.put_nowait((dealer_id, avss_id, shares, commitments, omega, gamma, masked))
            output = True
            logger.debug("[%d] Output", self.my_id)
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            logger.debug("Implicate Sent [%d]", dealer_id)
            self.tagvars[tag]['in_share_recovery'] = True

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("Handling Implicate Message [%d]", dealer_id)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        logger.debug("Handle implication called [%d]", dealer_id)
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break

    async def _process_avss_msg_bundle_log(self, avss_id, dealer_id, rbc_msg):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self._init_recovery_vars(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['in_share_recovery'] = False
        # dispersal_msg, commits, ephkey = self.decode_proposal(rbc_msg)
        # dispersal_msg, commits, ephkey = self.decode_proposal(rbc_msg)
        
        ok_set = set()
        implicate_set = set()
        output = False

        # self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs(tag, dealer_id)
        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs_bundle_log(tag, dealer_id)

        if self.tagvars[tag]['all_shares_valid']:
            
            shares = {'msg': self.tagvars[tag]['shares']}
            commitments = self.tagvars[tag]['commitments']
            w_list = self.tagvars[tag]['W_list']
            self.output_queue.put_nowait((dealer_id, avss_id, shares, commitments, w_list))
            output = True
            logger.debug("[%d] Output", self.my_id)
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            logger.debug("Implicate Sent [%d]", dealer_id)
            self.tagvars[tag]['in_share_recovery'] = True

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("Handling Implicate Message [%d]", dealer_id)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        logger.debug("Handle implication called [%d]", dealer_id)
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break
    
    #@profile    
    async def _process_avss_msg_log(self, avss_id, dealer_id, rbc_msg):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self._init_recovery_vars(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['in_share_recovery'] = False
        # dispersal_msg, commits, ephkey = self.decode_proposal(rbc_msg)
        # dispersal_msg, commits, ephkey = self.decode_proposal(rbc_msg)
        
        ok_set = set()
        implicate_set = set()
        output = False

        # self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs(tag, dealer_id)
        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs_log(tag, dealer_id)

        if self.tagvars[tag]['all_shares_valid']:
            
            shares = {'msg': self.tagvars[tag]['shares']}
            commitments = self.tagvars[tag]['commitments']
            self.output_queue.put_nowait((dealer_id, avss_id, shares, commitments))
            output = True
            logger.debug("[%d] Output", self.my_id)
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            logger.debug("Implicate Sent [%d]", dealer_id)
            self.tagvars[tag]['in_share_recovery'] = True

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("Handling Implicate Message [%d]", dealer_id)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        logger.debug("Handle implication called [%d]", dealer_id)
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break
    
    #@profile    
    async def _process_avss_msg(self, avss_id, dealer_id, rbc_msg):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self._init_recovery_vars(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['in_share_recovery'] = False
        # dispersal_msg, commits, ephkey = self.decode_proposal(rbc_msg)
        # dispersal_msg, commits, ephkey = self.decode_proposal(rbc_msg)
        
        ok_set = set()
        implicate_set = set()
        output = False

        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs(tag, dealer_id)
        # self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs_log(tag, dealer_id)

        if self.tagvars[tag]['all_shares_valid']:
            
            shares = {'msg': self.tagvars[tag]['shares'][0], 'rand':self.tagvars[tag]['shares'][1]}
            commitments = self.tagvars[tag]['commitments']
            self.output_queue.put_nowait((dealer_id, avss_id, shares, commitments))
            output = True
            logger.debug("[%d] Output", self.my_id)
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            logger.debug("Implicate Sent [%d]", dealer_id)
            self.tagvars[tag]['in_share_recovery'] = True

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("Handling Implicate Message [%d]", dealer_id)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        logger.debug("Handle implication called [%d]", dealer_id)
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break
    
    

    async def _process_avss_msg_trans(self, avss_id, dealer_id, rbc_msg):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self._init_recovery_vars(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['in_share_recovery'] = False
        # dispersal_msg, commits, ephkey = self.decode_proposal(rbc_msg)
        # dispersal_msg, commits, ephkey = self.decode_proposal(rbc_msg)
        
        ok_set = set()
        implicate_set = set()
        output = False

        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs_trans(tag, dealer_id)

        if self.tagvars[tag]['all_shares_valid']:
            
            shares = {'msg': self.tagvars[tag]['shares'][0], 'rand':self.tagvars[tag]['shares'][1]}
            commitments = self.tagvars[tag]['commitments']
            self.output_queue.put_nowait((dealer_id, avss_id, shares, commitments))
            output = True
            logger.debug("[%d] Output", self.my_id)
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            logger.debug("Implicate Sent [%d]", dealer_id)
            self.tagvars[tag]['in_share_recovery'] = True

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("Handling Implicate Message [%d]", dealer_id)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        logger.debug("Handle implication called [%d]", dealer_id)
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break

    
    async def _process_avss_msg_aprep(self, avss_id, dealer_id, rbc_msg):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self._init_recovery_vars(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['in_share_recovery'] = False
        # dispersal_msg, commits, ephkey = self.decode_proposal(rbc_msg)
        # dispersal_msg, commits, ephkey = self.decode_proposal(rbc_msg)
        
        ok_set = set()
        implicate_set = set()
        output = False

        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs_aprep(tag, dealer_id)

        # print(f"self.tagvars[tag]['shares'][0]: {self.tagvars[tag]['shares'][0]}")

        if self.tagvars[tag]['all_shares_valid']:
            
            shares = {'msg': self.tagvars[tag]['shares'][0], 'rand':self.tagvars[tag]['shares'][1]}
            commitments = self.tagvars[tag]['commitments']
            self.output_queue.put_nowait((dealer_id, avss_id, shares, commitments))
            output = True
            logger.debug("[%d] Output", self.my_id)
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            logger.debug("Implicate Sent [%d]", dealer_id)
            self.tagvars[tag]['in_share_recovery'] = True

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("Handling Implicate Message [%d]", dealer_id)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        logger.debug("Handle implication called [%d]", dealer_id)
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break
    
    #@profile
    def _get_dealer_msg_fluid(self, values, n):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        """
        while len(values) % (batch_size) != 0:
            values.append(0)
        """

        self.rand_num = len(values)

        # 这里 phi 和 phi_hat 都是根据 sc 来的
        phi = [None]*self.rand_num
        phi_hat = [None]*self.rand_num
        commitments = [None]*self.rand_num

        for k in range(self.rand_num):
            phi[k] = self.poly.random(self.t, values[k])
            phi_hat[k] = self.poly.random(self.t, self.field.rand())
            commitments[k] = self.poly_commit.commit(phi[k], phi_hat[k])

        ephemeral_secret_key = self.field.rand()
        ephemeral_public_key = self.g**ephemeral_secret_key
        dispersal_msg_list = bytearray()
        for i in range(n):
            shared_key = self.public_keys[i]**ephemeral_secret_key
            phis_i = [phi[k](i + 1) for k in range(self.rand_num)]
            phis_hat_i = [phi_hat[k](i + 1) for k in range(self.rand_num)]
            ciphertext = SymmetricCrypto.encrypt(shared_key.__getstate__(), self.sr.serialize_fs(phis_i+ phis_hat_i))
            dispersal_msg_list.extend(ciphertext)


        g_commits = []
        for k in range(self.rand_num):
            g_commits = g_commits + commitments[k]

        datab = self.sr.serialize_gs(g_commits) # Serializing commitments

        datab.extend(dispersal_msg_list)


        datab.extend(self.sr.serialize_g(ephemeral_public_key))

        return bytes(datab)
    
    #@profile
    def _get_dealer_msg(self, values, n):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        """
        while len(values) % (batch_size) != 0:
            values.append(0)
        """

        self.rand_num = len(values)

        phi_test = [None] * self.rand_num
        r_shared = self.field.rand()
        commitments_test = [None] * self.rand_num
        for k in range(self.rand_num):
            phi_test[k] = self.poly.random(self.t, values[k])

        batch_coeffs = [phi.coeffs for phi in phi_test]
        batch_comms = polycommit_commit_batch(
            batch_coeffs,
            r_shared,
            self.poly_commit_log.gs,
            self.poly_commit_log.h
        )

        shared_te2, witnesses_te2 = self.poly_commit_log.double_batch_create_witness_rs(phi_test, r_shared, n)
        
        ephemeral_secret_key = self.field.rand()
        ephemeral_public_key = self.g ** ephemeral_secret_key
        dispersal_msg_list = bytearray()


        for i in range(n):
            shared_key = self.public_keys[i] ** ephemeral_secret_key
            phis_i = [phi_test[k](i + 1) for k in range(self.rand_num)]

            wits_te2_i = witnesses_te2[i]

            payload_te2 = self.sr.serialize_fs(phis_i) + self.serialize_witness(wits_te2_i)


            ciphertext = SymmetricCrypto.encrypt(
                shared_key.__getstate__(),
                payload_te2
            )
            dispersal_msg_list.extend(ciphertext)
            

        all_commits_list = []
        for k in range(self.rand_num):
            all_commits_list.append(batch_comms[k])
        
        datab = self.sr.serialize_gs(all_commits_list)

        serialized_shared_te2 = self.serialize_shared(shared_te2)
        datab.extend(serialized_shared_te2)

        datab.extend(dispersal_msg_list)

        
        datab.extend(self.sr.serialize_g(ephemeral_public_key))

        return bytes(datab)
    
    def _get_dealer_msg_bundle(self, values, n):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        """
        while len(values) % (batch_size) != 0:
            values.append(0)
        """

        self.rand_num = len(values)

        phi_test = [None] * self.rand_num
        r_shared = self.field.rand()
        commitments_test = [None] * self.rand_num
        for k in range(self.rand_num):
            phi_test[k] = self.poly.random(self.t, values[k])

        batch_coeffs = [phi.coeffs for phi in phi_test]
        batch_comms = polycommit_commit_batch(
            batch_coeffs,
            r_shared,
            self.poly_commit_log.gs,
            self.poly_commit_log.h
        )

        shared_te2, witnesses_te2 = self.poly_commit_log.double_batch_create_witness_rs(phi_test, r_shared, n)

        mid = len(batch_coeffs) // 2
        coeffs_list = batch_coeffs[:mid]
        hat_coeffs_list = batch_coeffs[mid:]
        # proof：T1_list, T2_list, T3_list, z_r_list, z_coeffs, z_hatcoeffs, e 
        T1_list, T2_list, T3_list, W_list, z_r_list, z_coeffs, z_hatcoeffs, e = polycommit_prove_sigma(
            coeffs_list,
            hat_coeffs_list,
            r_shared,
            self.poly_commit_log.gs,
            self.poly_commit_log.h
        )
        
        ephemeral_secret_key = self.field.rand()
        ephemeral_public_key = self.g ** ephemeral_secret_key
        dispersal_msg_list = bytearray()


        for i in range(n):
            shared_key = self.public_keys[i] ** ephemeral_secret_key
            phis_i = [phi_test[k](i + 1) for k in range(self.rand_num)]

            wits_te2_i = witnesses_te2[i]

            payload_te2 = self.sr.serialize_fs(phis_i) + self.serialize_witness(wits_te2_i)


            ciphertext = SymmetricCrypto.encrypt(
                shared_key.__getstate__(),
                payload_te2
            )
            dispersal_msg_list.extend(ciphertext)
            

        all_commits_list = []
        for k in range(self.rand_num):
            all_commits_list.append(batch_comms[k])
        
        datab = self.sr.serialize_gs(all_commits_list)

        serialized_shared_te2 = self.serialize_shared(shared_te2)
        datab.extend(serialized_shared_te2)

        # ser Sigma 
        # T1, T2, T3, W：G1 
        datab.extend(self.sr.serialize_gs(T1_list))
        datab.extend(self.sr.serialize_gs(T2_list))
        datab.extend(self.sr.serialize_gs(T3_list))
        datab.extend(self.sr.serialize_gs(W_list))
        # z_r_list：Fr 
        datab.extend(self.sr.serialize_fs(z_r_list))
        # z_coeffs 和 z_hatcoeffs：
        for row in z_coeffs:
            datab.extend(self.sr.serialize_fs(row))
        for row in z_hatcoeffs:
            datab.extend(self.sr.serialize_fs(row))
        # e：single Fr
        datab.extend(self.sr.serialize_fs([e]))

        datab.extend(dispersal_msg_list)

        
        datab.extend(self.sr.serialize_g(ephemeral_public_key))

        return bytes(datab)
    
    def serialize_shared(self, shared):
        """
        shared = [roothash, t, S, Ds, mu]
        """
        roothash, t, S, Ds, mu = shared
        out = bytearray()

        # ① roothash
        out.extend(len(roothash).to_bytes(2, "big"))
        out.extend(roothash)

        # ② t 和 mu —— field elements
        out.extend(self.sr.serialize_fs([ZR(t), mu]))

        # ③ S
        out.extend(self.sr.serialize_g(S))

        # ④ Ds
        out.extend(self.sr.serialize_gs(Ds))

        return out


    def deserialize_shared(self, data):
        idx = 0

        # ① roothash
        rlen = int.from_bytes(data[idx:idx+2], "big"); idx += 2
        roothash = data[idx:idx+rlen]; idx += rlen

        # ② t, mu
        t_mu = self.sr.deserialize_fs(data[idx:idx + 2*self.sr.f_size])
        t, mu = int(t_mu[0]), t_mu[1]
        idx += 2*self.sr.f_size

        # ③ S
        S = self.sr.deserialize_g(data[idx:idx+self.sr.g_size]); idx += self.sr.g_size

        # ④ Ds
        dlen = int.from_bytes(data[idx:idx+2], "big"); idx += 2
        Ds = self.sr.deserialize_gs(data[idx:idx+dlen*self.sr.g_size]); idx += dlen*self.sr.g_size

        return [roothash, t, S, Ds, mu]

    def serialize_witness(self, wit):
        """
        wit = [branch, T, t_hats, tail_iproof]
        """
        branch, T, t_hats, iproof = wit
        out = bytearray()

        # ① branch (pickle)
        # bb = pickle.dumps(branch)
        # out.extend(len(bb).to_bytes(4, "big"))
        # out.extend(bb)
        out.extend(pickle.dumps(branch))

        # ② T
        out.extend(self.sr.serialize_g(T))

        # ③ t_hat 
        # out.extend(len(t_hats).to_bytes(2, "big"))
        out.extend(self.sr.serialize_fs(t_hats))

        # ④ tail proof
        # tb = pickle.dumps(iproof)
        # out.extend(len(tb).to_bytes(4, "big"))
        # out.extend(tb)
        out.extend(pickle.dumps(iproof))
        # print(f"pickle.dumps(iproof) size: {len(pickle.dumps(iproof))} bytes")

        return out


    def deserialize_witness(self, data, poly_num):
        """
        Reverses `serialize_witness` without relying on length prefixes.

        Layout written by `serialize_witness`:
            [pickle(branch)] +
            [G1 T (g_size bytes)] +
            [t_hats (rand_num · f_size bytes)] +
            [pickle(iproof)]
        """
        import io, pickle

        bio = io.BytesIO(data)

        # ① branch  —— read with pickle.load and record how many bytes were consumed
        branch_time = time.time()
        branch = pickle.load(bio)
        idx = bio.tell()
        branch_time = time.time() - branch_time

        # ② T       —— fixed g_size bytes
        T = self.sr.deserialize_g(data[idx: idx + self.sr.g_size])
        idx += self.sr.g_size

        # ③ t_hats  —— exactly self.rand_num field elements
        # hats_len = getattr(self, "rand_num", None)
        thats_time = time.time()
        hats_len = poly_num
        if hats_len is None:
            raise ValueError("rand_num not set; cannot parse t_hats without length prefix")
        t_hats = self.sr.deserialize_fs(
            data[idx: idx + hats_len * self.sr.f_size]
        )
        idx += hats_len * self.sr.f_size
        thats_time = time.time() - thats_time

        # ④ tail iproof —— remaining bytes as pickle
        iproof_time = time.time()
        iproof = pickle.loads(data[idx:])
        iproof_time = time.time() - iproof_time

        return [branch, T, t_hats, iproof]

    def serialize_witness_ori(self, wit):
        roothash, branch, t, S, T, Ds, mu, t_hats, iproof = wit

        data = bytearray()

        # Merkle root
        data.extend(len(roothash).to_bytes(2, "big"))
        data.extend(roothash)

        # Merkle branch
        data.extend(pickle.dumps(branch))


        data.extend(self.sr.serialize_fs([ZR(t), mu]))
        data.extend(self.sr.serialize_g(S))
        data.extend(self.sr.serialize_g(T))
        data.extend(self.sr.serialize_gs(Ds))
        data.extend(self.sr.serialize_fs(t_hats))

        # inner-product proof
        data.extend(pickle.dumps(iproof))
        return data
    
    # ------------------------------------------------------------------
    # consistency proof helper
    # ------------------------------------------------------------------
    def _prove_consis(self, phi_const, q1, r_k_li, q3):
        """
        Implements Algorithm 6 (AD-MPC paper).

        Parameters
        ----------
        phi_const : field element
            φ_k_i(0) — constant term of the polynomial.
        q1, r_k_li, q3 : field elements
            Respectively q_{k i,1},  [r_k]_l^i,  q_{k i,3} –
            all drawn from trans_random_values.

        Returns
        -------
        (omega, gamma, masked_value)
            omega  = h^{q1 + q3}
            gamma  = g_0^{[r_k]_l^i} · h^{q3}
            masked = φ_k_i(0) + [r_k]_l^i
        """
        g0 = self.gs[0]          # g_0 in hbPolyCommit
        omega = self.h ** (q1 + q3)
        gamma = (g0 ** r_k_li) * (self.h ** q3)
        masked = phi_const + r_k_li
        return omega, gamma, masked

    def prove_consis_bundle(self, phi_const, q1, r_k_li, q3):
        g0 = self.gs[0]          # g_0 in hbPolyCommit
        omega = (g0 ** r_k_li) * (self.h ** q3)
        mask = phi_const + r_k_li
        hat_mask = q1 + q3
        return mask, hat_mask, omega

    def verify_consis_bundle(self, g_s, mask, hat_mask, omega):
        g0 = self.gs[0]
        # Left-hand side
        lhs = (g0 ** mask) * (self.h ** hat_mask)
        # Right-hand side
        rhs = g_s * omega
        return lhs == rhs

    # ------------------------------------------------------------------
    # VerifyConsis — verifier side consistency proof
    # ------------------------------------------------------------------
    def _verify_consis(self, g_s, omega, gamma, masked):
        """
        Verifies the consistency proof (ω, γ, masked) for a single polynomial.

        Parameters
        ----------
        g_s : G1
            Commitment to the constant term: g_0^{φ(0)} · h^{q1}
        omega : G1
            ω = h^{q1 + q3}
        gamma : G1
            γ = g_0^{[r_k]_l^i} · h^{q3}
        masked : field element
            φ(0) + [r_k]_l^i  (the masked constant term)

        Returns
        -------
        bool
            True iff the proof is valid, False otherwise.
        """
        g0 = self.gs[0]
        # Left-hand side: g_s · γ  =  g_0^{φ(0)+[r_k]_l^i} · h^{q1+q3}
        lhs = g_s * gamma
        # Right-hand side: g_0^{masked} · ω
        rhs = (g0 ** masked) * omega
        return lhs == rhs

    def _get_dealer_msg_trans_log(self, values, n):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        """
        while len(values) % (batch_size) != 0:
            values.append(0)
        """
        trans_values, trans_random_values, w_list = values

        phi_test = [None] * len(trans_values)
        r_shared = self.field.rand()
        commit_pedersen_test = [None] * len(trans_values)
        commitments_test = [None] * len(trans_values)
        r_individual = trans_random_values.pop(0)
        mask_list, hat_mask_list, omega_list = [], [], []
        for k in range(len(trans_values)):
            phi_test[k] = self.poly.random(self.t, trans_values[k])

            # -------- ProveConsis (Alg-6 line 104) --------
            mask_k, hat_mask_k, omega_k = self.prove_consis_bundle(
                phi_test[k].coeffs[0],   # φ0
                r_individual,                   # q1
                trans_random_values.pop(0),                  # [r_k]_l^i
                trans_random_values.pop(0)                    # q3
            )
            mask_list.append(mask_k)
            hat_mask_list.append(hat_mask_k)
            omega_list.append(omega_k)
        

        coeffs_list = [phi.coeffs for phi in phi_test]
        commit_pedersen_test, commitments_test = polycommit_commit_transfer_batch(
            coeffs_list,
            r_individual,
            r_shared,
            self.poly_commit_log.gs,
            self.poly_commit_log.h
        )


        # g_s_agg = commit_pedersen_test[0] * G1.identity()
        omega_agg = omega_list[0] * G1.identity()

        for k in range(1, len(commit_pedersen_test)):
            # g_s_agg = g_s_agg * commit_pedersen_test[k]
            omega_agg = omega_agg * omega_list[k]

        mask_agg = ZR(0)
        hat_mask_agg = ZR(0)
        for v in mask_list:
            mask_agg += v
        for v in hat_mask_list:
            hat_mask_agg += v
        flat_w_list = [elm
               for outer in w_list       
               for mid in outer           
               for elm in mid]     
        w_agg = flat_w_list[0] * G1.identity()
        for w in flat_w_list[1:]:
            w_agg = w_agg * w

        shared_test, witnesses_test = self.poly_commit_log.double_batch_create_witness_rs(phi_test, r_individual+r_shared, n)

        
        ephemeral_secret_key = self.field.rand()
        ephemeral_public_key = self.g ** ephemeral_secret_key
        dispersal_msg_list = bytearray()


        for i in range(n):
            shared_key = self.public_keys[i] ** ephemeral_secret_key
            phis_i = [phi_test[k](i + 1) for k in range(len(trans_values))]
            wits_i = witnesses_test[i]

            payload = self.sr.serialize_fs(phis_i) + self.serialize_witness(wits_i)
            
            ciphertext = SymmetricCrypto.encrypt(
                shared_key.__getstate__(),
                payload
            )
            dispersal_msg_list.extend(ciphertext)

        all_commits_list = []
        for k in range(len(trans_values)):
            all_commits_list.append(commit_pedersen_test[k])
            all_commits_list.append(commitments_test[k])
        
        datab = self.sr.serialize_gs(all_commits_list)

       

        # Append aggregated consistency proof elements
        datab.extend(self.sr.serialize_g(omega_agg))
        datab.extend(self.sr.serialize_fs([mask_agg]))
        datab.extend(self.sr.serialize_fs([hat_mask_agg]))

        datab.extend(self.sr.serialize_g(w_agg))

        serialized_shared = self.serialize_shared(shared_test)
        datab.extend(serialized_shared)

        datab.extend(dispersal_msg_list)

        datab.extend(self.sr.serialize_g(ephemeral_public_key))

        return bytes(datab)

    def _get_dealer_msg_trans(self, values, n):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        """
        while len(values) % (batch_size) != 0:
            values.append(0)
        """
        trans_values, trans_values_hat = values

        phi = [None] * len(trans_values)
        phi_hat = [None] * len(trans_values)
        commitments = [None] * len(trans_values)

        for k in range(len(trans_values)):
            
            phi[k] = self.poly.random(self.t, trans_values[k])
            
            phi_hat[k] = self.poly.random(self.t, trans_values_hat[k])
            
            commitments[k] = self.poly_commit.commit(phi[k], phi_hat[k])


        ephemeral_secret_key = self.field.rand()
        ephemeral_public_key = self.g**ephemeral_secret_key
        dispersal_msg_list = bytearray()
        for i in range(n):
            shared_key = self.public_keys[i]**ephemeral_secret_key
            phis_i = [phi[k](i + 1) for k in range(len(trans_values))]
            phis_hat_i = [phi_hat[k](i + 1) for k in range(len(trans_values))]
            ciphertext = SymmetricCrypto.encrypt(shared_key.__getstate__(), self.sr.serialize_fs(phis_i+ phis_hat_i))
            dispersal_msg_list.extend(ciphertext)

        g_commits = []
        for k in range(len(trans_values)):
            g_commits = g_commits + commitments[k]
        datab = self.sr.serialize_gs(g_commits) # Serializing commitments
        # print(f"dispersal_msg_list: {dispersal_msg_list}")
        datab.extend(dispersal_msg_list)
        datab.extend(self.sr.serialize_g(ephemeral_public_key))

        return bytes(datab)
    
    def _get_dealer_msg_aprep(self, values, n):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        """
        while len(values) % (batch_size) != 0:
            values.append(0)
        """
        mult_triples, chec_triples, self.cm = values

        phi_mult_triples_test = [[None for _ in range(3)] for _ in range(self.cm)]
        phi_chec_triples_test = [[None for _ in range(3)] for _ in range(self.cm)]  
        commit_mult_triples_test = [[None for _ in range(3)] for _ in range(self.cm)]
        commit_chec_triples_test = [[None for _ in range(3)] for _ in range(self.cm)]
        commit_mult_triples_te2 = [[None for _ in range(3)] for _ in range(self.cm)]
        commit_chec_triples_te2 = [[None for _ in range(3)] for _ in range(self.cm)]
        r_shared = self.field.rand()

        
        for i in range(self.cm):
            for j in range(3): 
                phi_mult_triples_test[i][j] = self.poly.random(self.t, mult_triples[i][j])
                phi_chec_triples_test[i][j] = self.poly.random(self.t, chec_triples[i][j])

        # 2) 扁平化并行承诺
        phis_triples_together = [phi for row in phi_mult_triples_test for phi in row] \
                 + [phi for row in phi_chec_triples_test for phi in row]
        coeffs_list = [phi.coeffs for phi in phis_triples_together]
        commits_triples_together = polycommit_commit_batch(
            coeffs_list,
            r_shared,
            self.poly_commit_log.gs,
            self.poly_commit_log.h
        )


        import time
        start_time = time.time()
        shared_test, witnesses_test = self.poly_commit_log.double_batch_create_witness_rs(phis_triples_together, r_shared, n)

        
        ephemeral_secret_key = self.field.rand()
        ephemeral_public_key = self.g ** ephemeral_secret_key
        dispersal_msg_list = bytearray()


        for i in range(n):
            shared_key = self.public_keys[i] ** ephemeral_secret_key
            phis_i = [phis_triples_together[k](i + 1) for k in range(len(phis_triples_together))]
            wits_i = witnesses_test[i]

            payload = self.sr.serialize_fs(phis_i) + self.serialize_witness(wits_i)
            # print(f"payload: {payload}")
            ciphertext = SymmetricCrypto.encrypt(
                shared_key.__getstate__(),
                payload
            )
            dispersal_msg_list.extend(ciphertext)

        all_commits_list = []
        for k in range(len(commits_triples_together)):
            all_commits_list.append(commits_triples_together[k])

        t0 = time.time()
        datab = self.sr.serialize_gs(all_commits_list)
        t0 = time.time() - t0


        serialized_shared = self.serialize_shared(shared_test)
        datab.extend(serialized_shared)

        datab.extend(dispersal_msg_list)

        datab.extend(self.sr.serialize_g(ephemeral_public_key))
        
        return bytes(datab)
    
    #@profile
    def _handle_dealer_msgs_trans_log(self, tag, dealer_id):

        commit_peds, commit_tests, phis, witness, omega, mask, hat_mask, w, ephkey, shared_key = self.data[dealer_id]

        self.tagvars[tag]['shared_key'] = shared_key
        self.tagvars[tag]['commitments'] = (commit_peds, commit_tests)
        self.tagvars[tag]['ephemeral_public_key'] = ephkey
        
        # shares = self.sr.deserialize_fs(sharesb)
        if self.acss_status[dealer_id]: 
            self.tagvars[tag]['shares'] =  [phis]
            self.tagvars[tag]['omega'] =  [omega]
            self.tagvars[tag]['mask'] =  [mask]
            self.tagvars[tag]['hat_mask'] =  [hat_mask]
            self.tagvars[tag]['w'] = [w]
            self.tagvars[tag]['witnesses'] = [witness]
            return True
        return False

    #@profile
    def _handle_dealer_msgs_bundle_log(self, tag, dealer_id):
        commits, phis, witness, ephkey, shared_key, W_list = self.data[dealer_id]

        self.tagvars[tag]['shared_key'] = shared_key
        self.tagvars[tag]['commitments'] = commits
        self.tagvars[tag]['ephemeral_public_key'] = ephkey
        
        if self.acss_status[dealer_id]: 
            self.tagvars[tag]['shares'] =  [phis]
            self.tagvars[tag]['witnesses'] = [witness]
            self.tagvars[tag]['w_list'] = [W_list]
            return True
        return False
    
    #@profile
    def _handle_dealer_msgs_log(self, tag, dealer_id):
        commits, phis, witness, ephkey, shared_key = self.data[dealer_id]

        self.tagvars[tag]['shared_key'] = shared_key
        self.tagvars[tag]['commitments'] = commits
        self.tagvars[tag]['ephemeral_public_key'] = ephkey
        
        if self.acss_status[dealer_id]: 
            self.tagvars[tag]['shares'] =  [phis]
            self.tagvars[tag]['witnesses'] = [witness]
            return True
        return False
    
    #@profile
    def _handle_dealer_msgs(self, tag, dealer_id):

        commits, phis, phis_hat, ephkey, shared_key = self.data[dealer_id]
        self.tagvars[tag]['shared_key'] = shared_key
        self.tagvars[tag]['commitments'] = commits
        self.tagvars[tag]['ephemeral_public_key'] = ephkey
        
        # shares = self.sr.deserialize_fs(sharesb)
        if self.acss_status[dealer_id]: 
            
            self.tagvars[tag]['shares'] =  [phis, phis_hat]
            self.tagvars[tag]['witnesses'] = [None]
            return True
        return False
    
    def _handle_dealer_msgs_trans(self, tag, dealer_id):
        commits, phis, phis_hat, ephkey, shared_key = self.data[dealer_id]
        self.tagvars[tag]['shared_key'] = shared_key
        self.tagvars[tag]['commitments'] = commits
        self.tagvars[tag]['ephemeral_public_key'] = ephkey
        
        # shares = self.sr.deserialize_fs(sharesb)
        if self.acss_status[dealer_id]: 

            self.tagvars[tag]['shares'] =  [phis, phis_hat]
            self.tagvars[tag]['witnesses'] = [None]
            return True
        return False
    
    def _handle_dealer_msgs_aprep(self, tag, dealer_id):
        commits, phis, phis_hat, ephkey, shared_key = self.data[dealer_id]
        self.tagvars[tag]['shared_key'] = shared_key
        self.tagvars[tag]['commitments'] = commits
        self.tagvars[tag]['ephemeral_public_key'] = ephkey
        
        # shares = self.sr.deserialize_fs(sharesb)
        if self.acss_status[dealer_id]: 

            self.tagvars[tag]['shares'] =  [phis, phis_hat]
            self.tagvars[tag]['witnesses'] = [None]
            return True
        return False

    #@profile
    async def avss(self, avss_id, values=None, dealer_id=None):
        """
        An acss with share recovery
        """
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        broadcast_msg = None
        if self.my_id == dealer_id:
            
            broadcast_msg = self._get_dealer_msg(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):

            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                _VERIFY_POOL,
                self._decode_and_verify_log_sync,
                dealer_id,
                _m,
                self.rand_num,
            )
        
        output = asyncio.Queue()
        asyncio.create_task(
        optqrbc(
            rbctag,
            self.my_id,
            self.n,
            self.t,
            dealer_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
        ))
        rbc_msg = await output.get()


        await self._process_avss_msg_log(avss_id, dealer_id, rbc_msg)
        
        for task in self.tagvars[acsstag]['tasks']:
            task.cancel()
        self.tagvars[acsstag] = {}
        del self.tagvars[acsstag]

    #@profile
    async def avss_bundle(self, avss_id, values=None, dealer_id=None):
        """
        An acss with share recovery
        """
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        broadcast_msg = None
        if self.my_id == dealer_id:
            
            broadcast_msg = self._get_dealer_msg_bundle(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):

            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                _VERIFY_POOL,
                self._decode_and_verify_bundle_log_sync,
                dealer_id,
                _m,
                self.rand_num,
            )
        
        output = asyncio.Queue()
        asyncio.create_task(
        optqrbc(
            rbctag,
            self.my_id,
            self.n,
            self.t,
            dealer_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
        ))
        rbc_msg = await output.get()


        await self._process_avss_msg_bundle_log(avss_id, dealer_id, rbc_msg)
        
        for task in self.tagvars[acsstag]['tasks']:
            task.cancel()
        self.tagvars[acsstag] = {}
        del self.tagvars[acsstag]

    async def avss_trans_log(self, avss_id, len_values, values=None, dealer_id=None):
        """
        An acss with share recovery
        """
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        self.len_values = len_values
        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        broadcast_msg = None
        if self.my_id == dealer_id:
            
            # broadcast_msg = self._get_dealer_msg_trans(values, n)
            broadcast_msg = self._get_dealer_msg_trans_log(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            # dispersal_msg, commit_peds, commit_tests, omega, gamma, masked, shared, ephkey = self.decode_proposal_trans_log(_m, self.len_values)
            # # print(f"protocol trans my id: {self.my_id} dealer id: {dealer_id}")
            # return self.verify_proposal_trans_log(dealer_id, dispersal_msg, commit_peds, commit_tests, omega, gamma, masked, shared, ephkey, self.len_values)
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                _VERIFY_POOL,
                self._decode_and_verify_trans_log_sync,
                dealer_id,
                _m,
                self.len_values,
            )
        
        output = asyncio.Queue()
        asyncio.create_task(
        optqrbc(
            rbctag,
            self.my_id,
            self.n,
            self.t,
            dealer_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
        ))
        rbc_msg = await output.get()


        await self._process_avss_msg_trans_log(avss_id, dealer_id, rbc_msg)
        
        for task in self.tagvars[acsstag]['tasks']:
            task.cancel()
        self.tagvars[acsstag] = {}
        del self.tagvars[acsstag]
   
    async def avss_trans(self, avss_id, len_values, values=None, dealer_id=None):
        """
        An acss with share recovery
        """
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        self.len_values = len_values
        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        broadcast_msg = None
        if self.my_id == dealer_id:
            
            # broadcast_msg = self._get_dealer_msg_trans(values, n)
            broadcast_msg = self._get_dealer_msg_trans(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            dispersal_msg, commits, ephkey = self.decode_proposal_trans(_m)
            # print(f"protocol trans my id: {self.my_id} dealer id: {dealer_id}")
            return self.verify_proposal_trans(dealer_id, dispersal_msg, commits, ephkey)
        
        output = asyncio.Queue()
        asyncio.create_task(
        optqrbc(
            rbctag,
            self.my_id,
            self.n,
            self.t,
            dealer_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
        ))
        rbc_msg = await output.get()

        # avss processing
        # logger.debug("starting acss")
        await self._process_avss_msg_trans(avss_id, dealer_id, rbc_msg)
        
        for task in self.tagvars[acsstag]['tasks']:
            task.cancel()
        self.tagvars[acsstag] = {}
        del self.tagvars[acsstag]

    async def avss_aprep(self, avss_id, values=None, dealer_id=None):
        """
        An acss with share recovery
        """
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        broadcast_msg = None
        if self.my_id == dealer_id:
            
            broadcast_msg = self._get_dealer_msg_aprep(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):


            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                _VERIFY_POOL,
                self._decode_and_verify_log_sync,
                dealer_id,
                _m,
                6 * self.cm,
            )
        
        output = asyncio.Queue()
        asyncio.create_task(
        optqrbc(
            rbctag,
            self.my_id,
            self.n,
            self.t,
            dealer_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
        ))
        rbc_msg = await output.get()

        # await self._process_avss_msg_aprep(avss_id, dealer_id, rbc_msg)
        await self._process_avss_msg_log(avss_id, dealer_id, rbc_msg)
        
        for task in self.tagvars[acsstag]['tasks']:
            task.cancel()
        self.tagvars[acsstag] = {}
        del self.tagvars[acsstag]

class ACSS_Pre(ACSS):
    def __init__(self, public_keys, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1, mpc_instance, private_key=None, rbc_values=None):
        
        self.mpc_instance = mpc_instance

        super().__init__(public_keys, private_key, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1, rbc_values)

    async def avss_aprep(self, avss_id, values=None, dealer_id=None):
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-AVSS"

        broadcast_msg = None
        if self.my_id == dealer_id:
            
            broadcast_msg = self._get_dealer_msg_aprep(values, n)


        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)

        async def predicate(_m):
            dispersal_msg, commits, shared, ephkey = self.decode_proposal_log(_m, 6*self.cm)
            
            return self.verify_proposal_log(dealer_id, dispersal_msg, commits, shared, ephkey, 6*self.cm)
        
        output = asyncio.Queue()

        my_mpc_instance = self.mpc_instance
        admpc_control_instance = self.mpc_instance.admpc_control_instance

        member_list = [(self.mpc_instance.layer_ID) * self.n + self.my_id]
        for i in range(self.n): 
            member_list.append(n * (self.mpc_instance.layer_ID + 1) + i)
        asyncio.create_task(
        optqrbc_dynamic(
            rbctag,
            self.my_id,
            self.n+1,
            self.t,
            self.my_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
            member_list
        ))
    
    async def avss_trans(self, avss_id, values=None, dealer_id=None):
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        self.len_values = len(values[0])
        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-RBC"

        broadcast_msg = None
        if self.my_id == dealer_id:
            
            broadcast_msg = self._get_dealer_msg_trans_log(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            dispersal_msg, commit_peds, commit_tests, omega, mask, hat_mask, w, shared, ephkey = self.decode_proposal_trans_log(_m, self.len_values)
            return self.verify_proposal_trans_log(dealer_id, dispersal_msg, commit_peds, commit_tests, omega, mask, hat_mask, w, shared, ephkey, self.len_values)
        
        output = asyncio.Queue()

        my_mpc_instance = self.mpc_instance
        admpc_control_instance = self.mpc_instance.admpc_control_instance

        member_list = [(self.mpc_instance.layer_ID) * self.n + self.my_id]
        for i in range(self.n): 
            member_list.append(n * (self.mpc_instance.layer_ID + 1) + i)
        asyncio.create_task(
        optqrbc_dynamic(
            rbctag,
            self.my_id,
            self.n+1,
            self.t,
            self.my_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
            member_list
        ))

    async def avss_bundle(self, avss_id, values=None, dealer_id=None):
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-AVSS"

        broadcast_msg = None
        if self.my_id == dealer_id:
            
            broadcast_msg = self._get_dealer_msg_bundle(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            dispersal_msg, commits, shared, ephkey, proof_tuple, W_list = self.decode_proposal_bundle_log(_m, self.rand_num)

            return self.verify_proposal_bundle_log(dealer_id, dispersal_msg, commits, shared, ephkey, self.rand_num, proof_tuple, W_list)
        
        output = asyncio.Queue()

        my_mpc_instance = self.mpc_instance
        admpc_control_instance = self.mpc_instance.admpc_control_instance

        member_list = [(self.mpc_instance.layer_ID) * self.n + self.my_id]
        for i in range(self.n): 
            member_list.append(n * (self.mpc_instance.layer_ID + 1) + i)
        asyncio.create_task(
        optqrbc_dynamic(
            rbctag,
            self.my_id,
            self.n+1,
            self.t,
            self.my_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
            member_list
        ))
    
    
    async def avss(self, avss_id, values=None, dealer_id=None):
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-AVSS"

        broadcast_msg = None
        if self.my_id == dealer_id:
            
            broadcast_msg = self._get_dealer_msg(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            dispersal_msg, commits, shared, ephkey = self.decode_proposal_log(_m, self.rand_num)
            return self.verify_proposal_log(dealer_id, dispersal_msg, commits, shared, ephkey, self.rand_num)
        
        output = asyncio.Queue()

        my_mpc_instance = self.mpc_instance
        admpc_control_instance = self.mpc_instance.admpc_control_instance

        member_list = [(self.mpc_instance.layer_ID) * self.n + self.my_id]
        for i in range(self.n): 
            member_list.append(n * (self.mpc_instance.layer_ID + 1) + i)
        asyncio.create_task(
        optqrbc_dynamic(
            rbctag,
            self.my_id,
            self.n+1,
            self.t,
            self.my_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
            member_list
        ))



class ACSS_Foll(ACSS):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1, mpc_instance, rbc_values=None):
        self.mpc_instance = mpc_instance
        if rbc_values is not None: 
            self.rbc_values = rbc_values

        
        super().__init__(public_keys, private_key, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1, rbc_values)

    async def _process_avss_msg_bundle(self, avss_id, dealer_id, rbc_msg):
        tag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self._init_recovery_vars(tag)

        multi_list = []
        for i in range(self.n): 
            multi_list.append(i + (self.mpc_instance.layer_ID) * self.n)

        def multicast(msg):
            for i in range(self.n):
                send(multi_list[i], msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['in_share_recovery'] = False
                
        ok_set = set()
        implicate_set = set()
        output = False

        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs_bundle_log(tag, dealer_id)


        if self.tagvars[tag]['all_shares_valid']:

            shares = {'msg': self.tagvars[tag]['shares']}
            commitments = self.tagvars[tag]['commitments']
            w_list = self.tagvars[tag]['w_list']
            self.output_queue.put_nowait((dealer_id, avss_id, shares, commitments, w_list))
            output = True
            logger.debug("[%d] Output", self.my_id)
            multicast((HbAVSSMessageType.OK, ""))
            return (dealer_id, avss_id, shares, commitments, w_list)
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            logger.debug("Implicate Sent [%d]", dealer_id)
            self.tagvars[tag]['in_share_recovery'] = True
        

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("Handling Implicate Message [%d]", dealer_id)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        logger.debug("Handle implication called [%d]", dealer_id)
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break
    
    async def _process_avss_msg_dynamic(self, avss_id, dealer_id, rbc_msg):
        tag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self._init_recovery_vars(tag)

        multi_list = []
        for i in range(self.n): 
            multi_list.append(i + (self.mpc_instance.layer_ID) * self.n)

        def multicast(msg):
            for i in range(self.n):
                send(multi_list[i], msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['in_share_recovery'] = False
                
        ok_set = set()
        implicate_set = set()
        output = False

        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs_log(tag, dealer_id)


        if self.tagvars[tag]['all_shares_valid']:

            shares = {'msg': self.tagvars[tag]['shares']}
            commitments = self.tagvars[tag]['commitments']
            self.output_queue.put_nowait((dealer_id, avss_id, shares, commitments))
            output = True
            logger.debug("[%d] Output", self.my_id)
            multicast((HbAVSSMessageType.OK, ""))
            return (dealer_id, avss_id, shares, commitments)
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            logger.debug("Implicate Sent [%d]", dealer_id)
            self.tagvars[tag]['in_share_recovery'] = True
        

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("Handling Implicate Message [%d]", dealer_id)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        logger.debug("Handle implication called [%d]", dealer_id)
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break
    
    
    async def avss_aprep(self, avss_id, dealer_id, cm):
        self.cm = cm
        if dealer_id is None:
            dealer_id = self.my_id

        
        admpc_control_instance = self.mpc_instance.admpc_control_instance
        my_mpc_instance = self.mpc_instance

        async def predicate(_m):

            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                _VERIFY_POOL,
                self._decode_and_verify_log_sync,
                dealer_id,
                _m,
                6 * self.cm,
            )


        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        output = asyncio.Queue()
        broadcast_msg = None
        
        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        
        
        

        member_list = [(self.mpc_instance.layer_ID - 1) * self.n + dealer_id]
        for i in range(self.n): 
            member_list.append(self.n * (self.mpc_instance.layer_ID) + i)
        if self.my_id < dealer_id: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))
        else: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id+1,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))

        # signal = admpc_control_instance.admpc_lists[my_mpc_instance.layer_ID - 1][dealer_id].Signal

        rbc_msg = await output.get()

        # avss processing
        (dealer, _, shares, commitments) = await self._process_avss_msg_dynamic(avss_id, dealer_id, rbc_msg)
        return (dealer, _, shares, commitments)
    
    async def _process_avss_msg_dynamic_trans(self, avss_id, dealer_id, rbc_msg):
        tag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self._init_recovery_vars(tag)

        multi_list = []
        for i in range(self.n): 
            multi_list.append(i + (self.mpc_instance.layer_ID) * self.n)

        def multicast(msg):
            for i in range(self.n):
                send(multi_list[i], msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['in_share_recovery'] = False
                
        ok_set = set()
        implicate_set = set()
        output = False

        # self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs(tag, dealer_id)
        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs_trans_log(tag, dealer_id)

        if self.tagvars[tag]['all_shares_valid']:
            
            shares = {'msg': self.tagvars[tag]['shares']}
            commitments = self.tagvars[tag]['commitments']
            omega = self.tagvars[tag]['omega']
            mask = self.tagvars[tag]['mask']
            hat_mask = self.tagvars[tag]['hat_mask']
            w = self.tagvars[tag]['w']
            self.output_queue.put_nowait((dealer_id, avss_id, shares, commitments, omega, mask, hat_mask, w))
            output = True
            logger.debug("[%d] Output", self.my_id)
            multicast((HbAVSSMessageType.OK, ""))
            return (dealer_id, avss_id, shares, commitments, omega, mask, hat_mask, w)

        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            logger.debug("Implicate Sent [%d]", dealer_id)
            self.tagvars[tag]['in_share_recovery'] = True
        

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("Handling Implicate Message [%d]", dealer_id)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        logger.debug("Handle implication called [%d]", dealer_id)
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break
    
    async def avss_trans(self, avss_id, dealer_id, len_values):
        self.len_values = len_values

        
        admpc_control_instance = self.mpc_instance.admpc_control_instance
        my_mpc_instance = self.mpc_instance

        async def predicate(_m):


            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                _VERIFY_POOL,
                self._decode_and_verify_trans_log_sync,
                dealer_id,
                _m,
                self.len_values,
            )

        
        
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        output = asyncio.Queue()
        broadcast_msg = None
        
        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        
        
        

        member_list = [(self.mpc_instance.layer_ID - 1) * self.n + dealer_id]
        for i in range(self.n): 
            member_list.append(self.n * (self.mpc_instance.layer_ID) + i)
        if self.my_id < dealer_id: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))
        else: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id+1,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))

        rbc_msg = await output.get()

        # avss processing
        (dealer, _, shares, commitments, omega, mask, hat_mask, w) = await self._process_avss_msg_dynamic_trans(avss_id, dealer_id, rbc_msg)
        return (dealer, _, shares, commitments, omega, mask, hat_mask, w)
    
    async def avss_bundle(self, avss_id, dealer_id, rounds):
        if dealer_id is None:
            dealer_id = self.my_id

        admpc_control_instance = self.mpc_instance.admpc_control_instance
        my_mpc_instance = self.mpc_instance

        self.rand_num = rounds
        async def predicate(_m):
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                _VERIFY_POOL,
                self._decode_and_verify_bundle_log_sync,
                dealer_id,
                _m,
                self.rand_num,
            )

        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        output = asyncio.Queue()
        broadcast_msg = None
        
        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)


        member_list = [(self.mpc_instance.layer_ID - 1) * self.n + dealer_id]
        for i in range(self.n): 
            member_list.append(self.n * (self.mpc_instance.layer_ID) + i)
        if self.my_id < dealer_id: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))
        else: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id+1,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))

        acss_rbc_time = time.time()
        rbc_msg = await output.get()
        acss_rbc_time = time.time() - acss_rbc_time

        # avss processing
        acss_process_time = time.time()
        (dealer, _, shares, commitments, w_list) = await self._process_avss_msg_bundle(avss_id, dealer_id, rbc_msg)
        acss_process_time = time.time() - acss_process_time
        return (dealer, _, shares, commitments, w_list)
    
    async def avss(self, avss_id, dealer_id, rounds):
        if dealer_id is None:
            dealer_id = self.my_id

        admpc_control_instance = self.mpc_instance.admpc_control_instance
        my_mpc_instance = self.mpc_instance

        self.rand_num = rounds
        async def predicate(_m):
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                _VERIFY_POOL,
                self._decode_and_verify_log_sync,
                dealer_id,
                _m,
                self.rand_num,
            )

        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        output = asyncio.Queue()
        broadcast_msg = None
        
        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)


        member_list = [(self.mpc_instance.layer_ID - 1) * self.n + dealer_id]
        for i in range(self.n): 
            member_list.append(self.n * (self.mpc_instance.layer_ID) + i)
        if self.my_id < dealer_id: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))
        else: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id+1,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))

        acss_rbc_time = time.time()
        rbc_msg = await output.get()
        acss_rbc_time = time.time() - acss_rbc_time

        # avss processing
        acss_process_time = time.time()
        (dealer, _, shares, commitments) = await self._process_avss_msg_dynamic(avss_id, dealer_id, rbc_msg)
        acss_process_time = time.time() - acss_process_time
        return (dealer, _, shares, commitments)




class ACSS_Fluid_Pre(ACSS):
    def __init__(self, public_keys, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1, mpc_instance, private_key=None, rbc_values=None):
        
        # 增加了一个属性self.rand_instance，用来指向 Rand 实例
        self.mpc_instance = mpc_instance

        
        super().__init__(public_keys, private_key, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1, rbc_values)

    async def avss(self, avss_id, values=None, dealer_id=None):
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID + 1}-B-AVSS"

        broadcast_msg = None
        if self.my_id == dealer_id:
            
            broadcast_msg = self._get_dealer_msg_fluid(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            return True
        
        output = asyncio.Queue()

        
        my_mpc_instance = self.mpc_instance
        admpc_control_instance = self.mpc_instance.admpc_control_instance

        member_list = [(self.mpc_instance.layer_ID) * self.n + self.my_id]
        for i in range(self.n): 
            member_list.append(n * (self.mpc_instance.layer_ID + 1) + i)
        asyncio.create_task(
        optqrbc_dynamic(
            rbctag,
            self.my_id,
            self.n+1,
            self.t,
            self.my_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
            member_list
        ))

class ACSS_Fluid_Foll(ACSS):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1, mpc_instance, rbc_values=None):
        self.mpc_instance = mpc_instance
        if rbc_values is not None: 
            self.rbc_values = rbc_values

        
        super().__init__(public_keys, private_key, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1, rbc_values)

    async def _process_avss_msg_dynamic(self, avss_id, dealer_id, rbc_msg):
        tag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self._init_recovery_vars(tag)

        multi_list = []
        for i in range(self.n): 
            multi_list.append(i + (self.mpc_instance.layer_ID) * self.n)

        def multicast(msg):
            for i in range(self.n):
                send(multi_list[i], msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['in_share_recovery'] = False
                
        ok_set = set()
        implicate_set = set()
        output = False
        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs(tag, dealer_id)


        if self.tagvars[tag]['all_shares_valid']:
            shares = {'msg': self.tagvars[tag]['shares'][0], 'rand':self.tagvars[tag]['shares'][1]}

            commitments = self.tagvars[tag]['commitments']
            self.output_queue.put_nowait((dealer_id, avss_id, shares, commitments))
            output = True
            logger.debug("[%d] Output", self.my_id)
            multicast((HbAVSSMessageType.OK, ""))
            return (dealer_id, avss_id, shares, commitments)
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            logger.debug("Implicate Sent [%d]", dealer_id)
            self.tagvars[tag]['in_share_recovery'] = True
        

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("Handling Implicate Message [%d]", dealer_id)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        logger.debug("Handle implication called [%d]", dealer_id)
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break

    async def avss(self, avss_id, dealer_id, rounds):
        if dealer_id is None:
            dealer_id = self.my_id

        
        admpc_control_instance = self.mpc_instance.admpc_control_instance
        my_mpc_instance = self.mpc_instance

        self.rand_num = rounds
        async def predicate(_m):
            
            dispersal_msg, commits, ephkey = self.decode_proposal(_m)

            shared_key = ephkey**self.private_key

            try:
                
                sharesb = SymmetricCrypto.decrypt(shared_key.__getstate__(), dispersal_msg)
            except ValueError as e:
                logger.warn(f"Implicate due to failure in decrypting: {e}")
                self.acss_status[dealer_id] = False
                return False
        
            try:
                sharesb = SymmetricCrypto.decrypt(shared_key.__getstate__(), dispersal_msg)
            except ValueError as e:  # TODO: more specific exception
                logger.warn(f"Implicate due to failure in decrypting: {e}")
                self.acss_status[dealer_id] = False
                return False
            
            shares = self.sr.deserialize_fs(sharesb)          
            
            phis, phis_hat = shares[:self.rand_num], shares[self.rand_num:]
           
            
            self.acss_status[dealer_id] = True
            self.data[dealer_id] = [commits, phis, phis_hat, ephkey, shared_key]
            # self.data[dealer_id] = [commits, phis, witness, ephkey, shared_key]
            return True

        rbctag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-{self.mpc_instance.layer_ID}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        output = asyncio.Queue()
        broadcast_msg = None
        
        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        
        member_list = [(self.mpc_instance.layer_ID - 1) * self.n + dealer_id]
        for i in range(self.n): 
            member_list.append(self.n * (self.mpc_instance.layer_ID) + i)
        if self.my_id < dealer_id: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))
        else: 
            asyncio.create_task(
            optqrbc_dynamic(
                rbctag,
                self.my_id+1,
                self.n+1,
                self.t,
                dealer_id,
                predicate,
                broadcast_msg,
                output.put_nowait,
                send,
                recv,
                member_list
            ))

        acss_rbc_time = time.time()
        rbc_msg = await output.get()
        acss_rbc_time = time.time() - acss_rbc_time

        # avss processing
        acss_process_time = time.time()
        (dealer, _, shares, commitments) = await self._process_avss_msg_dynamic(avss_id, dealer_id, rbc_msg)
        acss_process_time = time.time() - acss_process_time
        return (dealer, _, shares, commitments)


 