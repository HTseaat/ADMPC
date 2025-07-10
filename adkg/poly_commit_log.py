# from honeybadgermpc.betterpairing import ZR, G1
from pypairing import ZR, G1
from adkg.hbproofs import (
    prove_inner_product_one_known,
    verify_inner_product_one_known,
    prove_batch_inner_product_one_known,
    verify_batch_inner_product_one_known,
    prove_double_batch_inner_product_one_known,
    prove_double_batch_inner_product_one_known_but_different,
    prove_double_batch_inner_product_one_known_but_differenter,
    verify_double_batch_inner_product_one_known,
    verify_double_batch_inner_product_one_known_but_differenter,
    MerkleTree,
)
import pickle
import time
from pypairing.pypairing import polycommit_compute_comms_t_hats, polycommit_prove_inner_product_one_known_precomp, polycommit_prove_double_batch_inner_product_one_known_ori, polycommit_verify_double_batch_inner_product_one_known, polycommit_prove_double_batch_inner_product_opt, polycommit_verify_double_batch_inner_product_one_known_but_differenter



class PolyCommitLog:
    def __init__(self, crs=None, degree_max=33):
        if crs is None:
            n = degree_max + 1
            self.gs = G1.hash_many(b"honeybadgerg", n)
            self.h = G1.hash(b"honeybadgerh")
            self.u = G1.hash(b"honeybadgeru")
        else:
            assert len(crs) == 3
            [self.gs, self.h, self.u] = crs
        self.y_vecs = []

    def commit(self, phi, r):
        c = G1.identity()
        for i in range(len(phi.coeffs)):
            c *= self.gs[i] ** phi.coeffs[i]
        c *= self.h ** r
        return c
    
    def commit_transfer(self, phi, r1, r2):
        c = G1.identity()
        for i in range(1, len(phi.coeffs)):  # 从索引 1 开始，跳过常数项
            c *= self.gs[i] ** phi.coeffs[i]
        c *= self.h ** r2
        g_s = (self.gs[0] ** phi.coeffs[0]) * (self.h ** r1)  # g_0^s*h^r1，其中s是多项式的常数项
        return g_s, c

    def create_witness(self, phi, r, i):
        t = len(phi.coeffs) - 1
        y_vec = [ZR(i) ** j for j in range(t + 1)]
        s_vec = [ZR.random() for _ in range(t + 1)]
        sy_prod = ZR(0)
        S = G1.identity()
        for j in range(t + 1):
            S *= self.gs[j] ** s_vec[j]
            sy_prod += s_vec[j] * y_vec[j]
        T = self.gs[0] ** sy_prod
        rho = ZR.random()
        S *= self.h ** rho
        # Fiat Shamir
        challenge = ZR.hash(pickle.dumps([self.gs, self.h, self.u, S, T]))
        d_vec = [phi.coeffs[j] + s_vec[j] * challenge for j in range(t + 1)]
        D = G1.identity()
        for j in range(t + 1):
            D *= self.gs[j] ** d_vec[j]
        mu = r + rho * challenge
        comm, t_hat, iproof = prove_inner_product_one_known(
            d_vec, y_vec, crs=[self.gs, self.u]
        )
        return [S, T, D, mu, t_hat, iproof]

    # Create witnesses for points 1 to n. n defaults to 3*degree+1 if unset.
    def batch_create_witness(self, phi, r, n=None):
        t = len(phi.coeffs) - 1
        if n is None:
            n = 3 * t + 1
        if len(self.y_vecs) < n:
            i = len(self.y_vecs)
            while i < n:
                self.y_vecs.append([ZR(i + 1) ** j for j in range(t + 1)])
                i += 1
        s_vec = [ZR.random() for _ in range(t + 1)]
        sy_prods = [ZR(0) for _ in range(n)]
        S = G1.identity()
        T_vec = [None] * n
        witnesses = [[] for _ in range(n)]
        for i in range(t + 1):
            S *= self.gs[i] ** s_vec[i]
        for j in range(n):
            for i in range(t + 1):
                sy_prods[j] += s_vec[i] * self.y_vecs[j][i]
            T_vec[j] = self.gs[0] ** sy_prods[j]
        rho = ZR.random()
        S *= self.h ** rho
        # Fiat Shamir
        tree = MerkleTree()
        for j in range(n):
            tree.append(pickle.dumps(T_vec[j]))
        roothash = tree.get_root_hash()
        for j in range(n):
            branch = tree.get_branch(j)
            witnesses[j].append(roothash)
            witnesses[j].append(branch)
        challenge = ZR.hash(pickle.dumps([roothash, self.gs, self.h, self.u, S]))
        d_vec = [phi.coeffs[j] + s_vec[j] * challenge for j in range(t + 1)]
        D = G1.identity()
        for j in range(t + 1):
            D *= self.gs[j] ** d_vec[j]
        mu = r + rho * challenge
        comm, t_hats, iproofs = prove_batch_inner_product_one_known(
            d_vec, self.y_vecs, crs=[self.gs, self.u]
        )
        for j in range(len(witnesses)):
            witnesses[j] += [S, T_vec[j], D, mu, t_hats[j], iproofs[j]]
        return witnesses

    def double_batch_create_witness_ori(self, phis, r, n=None):
        t = len(phis[0].coeffs) - 1
        numpolys = len(phis)
        if n is None:
            n = 3 * t + 1
        numverifiers = n
        if len(self.y_vecs) < numverifiers:
            i = len(self.y_vecs)
            while i < numverifiers:
                self.y_vecs.append([ZR(i + 1) ** j for j in range(t + 1)])
                i += 1
        # length t
        s_vec = [ZR.random() for _ in range(t + 1)]
        sy_prods = [ZR(0) for _ in range(numverifiers)]
        S = G1.identity()
        T_vec = [None] * numverifiers
        witnesses = [[] for _ in range(numverifiers)]
        for i in range(t + 1):
            S *= self.gs[i].pow(s_vec[i])
        for j in range(numverifiers):
            for i in range(t + 1):
                sy_prods[j] += s_vec[i] * self.y_vecs[j][i]
            T_vec[j] = self.gs[0].pow(sy_prods[j])
        rho = ZR.random()
        S *= self.h ** rho
        # Fiat Shamir
        tree = MerkleTree()
        for j in range(numverifiers):
            tree.append(pickle.dumps(T_vec[j]))
        roothash = tree.get_root_hash()
        for j in range(numverifiers):
            branch = tree.get_branch(j)
            witnesses[j].append(roothash)
            witnesses[j].append(branch)
        challenge = ZR.hash(pickle.dumps([roothash, self.gs, self.h, self.u, S]))
        d_vecs = []
        for i in range(len(phis)):
            d_vecs.append([phis[i].coeffs[j] + s_vec[j] * challenge for j in range(t + 1)])
        Ds = [G1.identity() for _ in range(len(phis))]
        _ = [[Ds[i].__imul__(self.gs[j].pow(d_vecs[i][j])) for j in range(t + 1)] for i in range(len(phis))]
        mu = r + rho * challenge
        comms, t_hats, iproofs = prove_double_batch_inner_product_one_known_but_differenter(
            d_vecs, self.y_vecs, crs=[self.gs, self.u]
        )
        for j in range(numverifiers):
            witnesses[j] += [t, S, T_vec[j], Ds, mu, t_hats[j], iproofs[j]]
        return witnesses

    # @profile
    def double_batch_create_witness(self, phis, r, n=None):
        t = len(phis[0].coeffs) - 1
        numpolys = len(phis)
        if n is None:
            n = 3 * t + 1
        numverifiers = n

        # # evaluation point for verifier j is ZR(j)
        # y_vecs_cur = [[ZR(j) ** i for i in range(t + 1)]
        #               for j in range(numverifiers)]
        if len(self.y_vecs) < numverifiers:
            i = len(self.y_vecs)
            while i < numverifiers:
                self.y_vecs.append([ZR(i + 1) ** j for j in range(t + 1)])
                i += 1

        # ------------- 生成随机向量 s，公共承诺 S -------------
        s_vec = [ZR.random() for _ in range(t + 1)]
        sy_prods = [ZR(0) for _ in range(numverifiers)]
        S = G1.identity()
        for i in range(t + 1):
            S *= self.gs[i].pow(s_vec[i])

        # ------------- 逐验证者的 T 向量 (与 y_vec 相关) -------------
        T_vec = [None] * numverifiers
        for j in range(numverifiers):
            for i in range(t + 1):
                sy_prods[j] += s_vec[i] * self.y_vecs[j][i]
            T_vec[j] = self.gs[0].pow(sy_prods[j])

        # ------------- Merkle 根与分支 -------------
        tree = MerkleTree()
        for j in range(numverifiers):
            tree.append(pickle.dumps(T_vec[j]))
        roothash = tree.get_root_hash()
        branches = [tree.get_branch(j) for j in range(numverifiers)]

        # ------------- Fiat–Shamir Challenge -------------
        rho = ZR.random()
        S *= self.h ** rho
        challenge = ZR.hash(pickle.dumps([roothash, self.gs, self.h, self.u, S]))

        # ------------- d_vec, D_s, μ -------------
        d_vecs = [[phis[p].coeffs[i] + s_vec[i] * challenge for i in range(t + 1)]
                  for p in range(numpolys)]
        Ds = [G1.identity() for _ in range(len(phis))]
        _ = [[Ds[i].__imul__(self.gs[j].pow(d_vecs[i][j])) for j in range(t + 1)] for i in range(len(phis))]
        mu = r + rho * challenge

        # ------------- 双批量内积证明 -------------
        # Measure time for direct implementation
        start_time_batch1 = time.time()
        comms, t_hats, iproofs = prove_double_batch_inner_product_one_known_but_differenter(
            d_vecs, self.y_vecs, crs=[self.gs, self.u]
        )
        elapsed_batch1 = time.time() - start_time_batch1

        core_proof, tail_proof = iproofs[0]

        decoded_tail_proof = []
        for entry in tail_proof:
            root_bytes = entry[0]
            branch_tuple = entry[1]
            branch_list, idx = branch_tuple
            # Convert each to a Python list of ints
            decoded_root = list(root_bytes)
            decoded_branches = [list(b) for b in branch_list]
            decoded_tail_proof.append((decoded_root, decoded_branches, idx))
        # print(f"decoded_tail_proof: {decoded_tail_proof}")


        start_time_verify_direct = time.time()
        ok_direct = verify_double_batch_inner_product_one_known_but_differenter(
            Ds, t_hats[0], self.y_vecs[0], core_proof, tail_proof, crs=[self.gs, self.u]
        )
        elapsed_verify_direct = time.time() - start_time_verify_direct

        # Measure time for polycommit implementation
        start_time_batch2 = time.time()
        comms_te, t_hats_te, iproofs_te = polycommit_prove_double_batch_inner_product_one_known_ori(
            d_vecs,                 # Vec[Vec[ZR]]
            self.y_vecs,            # Vec[Vec[ZR]]
            self.gs,                # g 基
            self.u,                 # u
        )
        elapsed_batch2 = time.time() - start_time_batch2

        start_time_batch3 = time.time()
        comms_te3, t_hats_te3, iproofs_te3 = polycommit_prove_double_batch_inner_product_opt(
            d_vecs,                 # Vec[Vec[ZR]]
            self.y_vecs,            # Vec[Vec[ZR]]
            self.gs,                # g 基
            self.u,                 # u
        )
        start_time_batch3 = time.time() - start_time_batch3

        print(f"Direct prove execution time: {elapsed_batch1:.6f}s, polycommit execution time: {elapsed_batch2:.6f}s, opt execution time: {start_time_batch3:.6f}s")

        core_iproof_te_0, tail_iproof_te_0 = iproofs_te[0]


        core_iproof_te3_0, tail_iproof_te3_0 = iproofs_te3[0]


        core_iproof_te, tail_iproof_te = iproofs_te3[0]
        start_time_verify = time.time()
        ok = polycommit_verify_double_batch_inner_product_one_known_but_differenter(
                Ds, t_hats_te3[0], self.y_vecs[0],
                core_iproof_te3_0, tail_iproof_te3_0,
                crs=[self.gs, self.u]
        )
        elapsed_verify = time.time() - start_time_verify

        
        # --- Unified print ---
        print(f"verify_double_batch_inner_product_one_known_but_differenter ok: {ok_direct}, execution time: {elapsed_verify_direct:.6f}s")
        print(f"polycommit_verify_double_batch_inner_product_one_known ok: {ok}, execution time: {elapsed_verify:.6f}s")

        comms_test, t_hats_test = polycommit_compute_comms_t_hats(d_vecs, self.y_vecs, self.gs)
        # Compare commitments and t_hats results
        comms_equal = all(comms_test[i] == comms[i] for i in range(len(comms)))
        t_hats_equal = all(
            all(t_hats_test[i][j] == t_hats[i][j] for j in range(len(t_hats[i])))
            for i in range(len(t_hats_test))
        )
        print(f"comms equal: {comms_equal}, t_hats equal: {t_hats_equal}")

        te1, te2, te3 = polycommit_prove_inner_product_one_known_precomp(
            d_vecs[0], self.y_vecs[0], comms_test[0], t_hats_test[0][0], crs=[self.gs, self.u]
        )


        # ------- 广播一次即可的公共部分 -------
        shared = [roothash,          # Merkle 根
                t,                 # degree
                S,                 # 承诺 S
                Ds,                # 长度 = B 的 D_s
                mu]       

        # ------- 每个验证者独占的私有部分 -------
        witnesses = []
        for j in range(numverifiers):
            witnesses.append(
                [branches[j],        # Merkle path
                T_vec[j],           # 该行 T
                t_hats[j],          # 该行长度 B 的 ˆt 向量
                iproofs[j]]    # 该行的 treeparts
            )

        return shared, witnesses
    
    def double_batch_create_witness_rs(self, phis, r, n=None):
        t = len(phis[0].coeffs) - 1
        numpolys = len(phis)
        if n is None:
            n = 3 * t + 1
        numverifiers = n

        # # evaluation point for verifier j is ZR(j)
        # y_vecs_cur = [[ZR(j) ** i for i in range(t + 1)]
        #               for j in range(numverifiers)]
        if len(self.y_vecs) < numverifiers:
            i = len(self.y_vecs)
            while i < numverifiers:
                self.y_vecs.append([ZR(i + 1) ** j for j in range(t + 1)])
                i += 1

        # ------------- 生成随机向量 s，公共承诺 S -------------
        s_vec = [ZR.random() for _ in range(t + 1)]
        sy_prods = [ZR(0) for _ in range(numverifiers)]
        S = G1.identity()
        for i in range(t + 1):
            S *= self.gs[i].pow(s_vec[i])

        # ------------- 逐验证者的 T 向量 (与 y_vec 相关) -------------
        T_vec = [None] * numverifiers
        for j in range(numverifiers):
            for i in range(t + 1):
                sy_prods[j] += s_vec[i] * self.y_vecs[j][i]
            T_vec[j] = self.gs[0].pow(sy_prods[j])

        # ------------- Merkle 根与分支 -------------
        tree = MerkleTree()
        for j in range(numverifiers):
            tree.append(pickle.dumps(T_vec[j]))
        roothash = tree.get_root_hash()
        branches = [tree.get_branch(j) for j in range(numverifiers)]

        # ------------- Fiat–Shamir Challenge -------------
        rho = ZR.random()
        S *= self.h ** rho
        challenge = ZR.hash(pickle.dumps([roothash, self.gs, self.h, self.u, S]))

        # ------------- d_vec, D_s, μ -------------
        d_vecs = [[phis[p].coeffs[i] + s_vec[i] * challenge for i in range(t + 1)]
                  for p in range(numpolys)]
        Ds = [G1.identity() for _ in range(len(phis))]
        _ = [[Ds[i].__imul__(self.gs[j].pow(d_vecs[i][j])) for j in range(t + 1)] for i in range(len(phis))]
        mu = r + rho * challenge

        # ------------- 双批量内积证明 -------------
        # Measure time for polycommit implementation
        start_time_batch3 = time.time()
        comms, t_hats, iproofs = polycommit_prove_double_batch_inner_product_opt(
            d_vecs,                 # Vec[Vec[ZR]]
            self.y_vecs,            # Vec[Vec[ZR]]
            self.gs,                # g 基
            self.u,                 # u
        )
        start_time_batch3 = time.time() - start_time_batch3   

        # ------- 广播一次即可的公共部分 -------
        shared = [roothash,          # Merkle 根
                t,                 # degree
                S,                 # 承诺 S
                Ds,                # 长度 = B 的 D_s
                mu]       

        # ------- 每个验证者独占的私有部分 -------
        witnesses = []
        for j in range(numverifiers):
            witnesses.append(
                [branches[j],        # Merkle path
                T_vec[j],           # 该行 T
                t_hats[j],          # 该行长度 B 的 ˆt 向量
                iproofs[j]]    # 该行的 treeparts
            )

        return shared, witnesses

    def verify_eval(self, c, i, phi_at_i, witness):
        t = witness[-1][0] - 1
        y_vec = [ZR(i) ** j for j in range(t + 1)]
        if len(witness) == 6:
            [S, T, D, mu, t_hat, iproof] = witness
            challenge = ZR.hash(pickle.dumps([self.gs, self.h, self.u, S, T]))
        else:
            [roothash, branch, S, T, D, mu, t_hat, iproof] = witness
            if not MerkleTree.verify_membership(pickle.dumps(T), branch, roothash):
                return False
            challenge = ZR.hash(pickle.dumps([roothash, self.gs, self.h, self.u, S]))
        ret = self.gs[0] ** t_hat == self.gs[0] ** phi_at_i * T ** challenge
        ret &= D * self.h ** mu == S ** challenge * c
        if len(iproof[-1]) > 3:
            ret &= verify_batch_inner_product_one_known(
                D, t_hat, y_vec, iproof, crs=[self.gs, self.u]
            )
        else:
            ret &= verify_inner_product_one_known(
                D, t_hat, y_vec, iproof, crs=[self.gs, self.u]
            )
        return ret

    # Degree specification enables degree enforcement (will return false if polynomial is not of specified degree)
    def batch_verify_eval_ori(self, cs, i, phis_at_i, witness, degree=None):
        [roothash, branch, t, S, T, Ds, mu, t_hats, proof] = witness
        if degree is not None:
            t = degree
        iproof, treeparts = proof
        if not MerkleTree.verify_membership(pickle.dumps(T), branch, roothash):
            return False
        # TODO: Should include cs
        challenge = ZR.hash(pickle.dumps([roothash, self.gs, self.h, self.u, S]))
        y_vec = [ZR(i) ** j for j in range(t + 1)]
        ret = True
        for j in range(len(Ds)):
            ret &= self.gs[0] ** t_hats[j] == self.gs[0] ** phis_at_i[j] * T ** challenge
            ret &= Ds[j] * self.h ** mu == S ** challenge * cs[j]
        ret &= verify_double_batch_inner_product_one_known_but_differenter(
            Ds, t_hats, y_vec, iproof, treeparts, crs=[self.gs, self.u]
        )
        return ret

    # Legacy interface for backward compatibility
    def batch_verify_eval(self, cs, i, phis_at_i, shared, witness, degree=None):
        [roothash, t, S, Ds, mu] = shared
        [branch, T, t_hats, iproof] = witness    # t_hats 是长度 = B 的 list

        core_iproof, tail_iproof = iproof

        if degree is not None:
            t = degree

        # Merkle 认证
        if not MerkleTree.verify_membership(pickle.dumps(T), branch, roothash):
            return False

        challenge = ZR.hash(pickle.dumps([roothash, self.gs, self.h, self.u, S]))
        y_vec = [ZR(i) ** j for j in range(t + 1)]

        # Feldman-style 校验
        for j in range(len(Ds)):
            if self.gs[0] ** t_hats[j] != self.gs[0] ** phis_at_i[j] * T ** challenge:
                return False
            if Ds[j] * self.h ** mu != S ** challenge * cs[j]:
                return False

        # 内积证明
        ok = verify_double_batch_inner_product_one_known_but_differenter(
            Ds, t_hats, y_vec, core_iproof, tail_iproof, crs=[self.gs, self.u]
        )
        return ok
    
    # Legacy interface for backward compatibility
    def batch_verify_eval_rs(self, cs, i, phis_at_i, shared, witness, degree=None):
        [roothash, t, S, Ds, mu] = shared
        [branch, T, t_hats, iproof] = witness    # t_hats 是长度 = B 的 list

        core_iproof, tail_iproof = iproof

        if degree is not None:
            t = degree

        y_vec = [ZR(i) ** j for j in range(t + 1)]

        ok = polycommit_verify_double_batch_inner_product_one_known_but_differenter(
                Ds, t_hats, y_vec,
                core_iproof, tail_iproof,
                crs=[self.gs, self.u]
        )
        return ok

    def preprocess_prover(self, level=8):
        self.u.preprocess(level)
        # 0 to length-1
        for i in range(len(self.gs) - 1):
            self.y_vecs.append([ZR(i + 1) ** j for j in range(len(self.gs))])

    def preprocess_verifier(self, level=8):
        self.u.preprocess(level)
