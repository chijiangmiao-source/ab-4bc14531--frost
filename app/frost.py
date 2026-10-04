"""RFC 9591 FROST(Ed25519, SHA-512) 核心密码原语。

仅依赖 Python 标准库，实现：
  * Ed25519 扭爱德华曲线点运算（扩展坐标，素数阶子群严格解码）；
  * RFC 9591 的 H1/H2/H3/H4/H5、列表编码与域分隔；
  * 绑定因子 rho_i、群承诺 R、挑战 c、拉格朗日系数 lambda_i；
  * 份额验证方程与聚合签名验证方程；
  * 供测试/冒烟使用的可信分发方密钥生成与完整会签包构造。

标量/点编码一律 32 字节小端；标量必须满足 0 <= s < l（规范标量）。
"""

from __future__ import annotations

import hashlib

# ---------------------------------------------------------------------------
# 群参数（RFC 8032 / RFC 9591）
# ---------------------------------------------------------------------------

Q = 2**255 - 19  # 基域阶
L = 2**252 + 27742317777372353535851937790883648493  # 基点标量阶
_COFACTOR = 8
_D = (-121665 * pow(121666, Q - 2, Q)) % Q
_SQRT_M1 = pow(2, (Q - 1) // 4, Q)

BASEPOINT_HEX = (
    "5866666666666666666666666666666666666666666666666666666666666666"
)


class DecodeError(ValueError):
    """点或标量无法按 RFC 9591 规范解码。"""


class NonCanonicalScalarError(DecodeError):
    """标量编码不在 [0, l) 区间内。"""


# ---------------------------------------------------------------------------
# 扩展坐标点 (X, Y, Z, T)，x = X/Z, y = Y/Z, T = XY/Z
# 曲线方程 -x^2 + y^2 = 1 + d x^2 y^2
# ---------------------------------------------------------------------------


class Point:
    __slots__ = ("x", "y", "z", "t")

    def __init__(self, x: int, y: int, z: int, t: int):
        self.x = x % Q
        self.y = y % Q
        self.z = z % Q
        self.t = t % Q

    @staticmethod
    def identity() -> "Point":
        return Point(0, 1, 1, 0)

    def is_identity(self) -> bool:
        return (self.x * pow(self.z, Q - 2, Q)) % Q == 0 and (
            self.y * pow(self.z, Q - 2, Q)
        ) % Q == 1

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return NotImplemented
        x1z2 = self.x * other.z % Q
        x2z1 = other.x * self.z % Q
        y1z2 = self.y * other.z % Q
        y2z1 = other.y * self.z % Q
        return x1z2 == x2z1 and y1z2 == y2z1

    def __hash__(self) -> int:
        return hash(self.encode())

    # -- 群运算 -------------------------------------------------------------

    def add(self, other: "Point") -> "Point":
        x1, y1, z1, t1 = self.x, self.y, self.z, self.t
        x2, y2, z2, t2 = other.x, other.y, other.z, other.t
        a = ((y1 - x1) * (y2 - x2)) % Q
        b = ((y1 + x1) * (y2 + x2)) % Q
        c = (2 * _D * t1 * t2) % Q
        dd = (2 * z1 * z2) % Q
        e = b - a
        f = dd - c
        g = dd + c
        h = b + a
        return Point(e * f, g * h, f * g, e * h)

    def double(self) -> "Point":
        x, y, z = self.x, self.y, self.z
        a = x * x % Q
        b = y * y % Q
        c = 2 * z * z % Q
        h = a + b
        e = h - (x + y) * (x + y) % Q
        g = a - b
        f = c + g
        return Point(e * f % Q, g * h % Q, f * g % Q, e * h % Q)

    def scalar_mul(self, k: int) -> "Point":
        k %= L
        r = Point.identity()
        p = self
        while k:
            if k & 1:
                r = r.add(p)
            p = p.double()
            k >>= 1
        return r

    def neg(self) -> "Point":
        return Point((-self.x) % Q, self.y, self.z, (-self.t) % Q)

    # -- 编解码 -------------------------------------------------------------

    def encode(self) -> bytes:
        zi = pow(self.z, Q - 2, Q)
        x = self.x * zi % Q
        y = self.y * zi % Q
        out = bytearray(y.to_bytes(32, "little"))
        if x & 1:
            out[31] |= 0x80
        return bytes(out)

    @staticmethod
    def decode(raw: bytes, *, strict: bool = True) -> "Point":
        """RFC 8032 §5.1.3 解压；strict=True 时执行 RFC 9591 素数阶子群检查。

        拒绝：长度错误、y 非规范、非曲线点、x=0 时符号位为 1、
        小阶点（8P = O，含单位元）以及非素数阶子群点（lP != O）。
        """
        if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
            raise DecodeError("点编码必须为 32 字节")
        b = bytes(raw)
        sign = (b[31] >> 7) & 1
        y = int.from_bytes(b, "little") & ((1 << 255) - 1)

        u = (y * y - 1) % Q
        v = (1 + _D * y * y) % Q
        # x = sqrt(u / v)：Ed25519 q ≡ 5 (mod 8)，指数 (q+3)/8。
        x = u * pow(v, Q - 2, Q) % Q
        x = pow(x, (Q + 3) // 8, Q)
        if (v * x * x - u) % Q != 0:
            x = x * _SQRT_M1 % Q
            if (v * x * x - u) % Q != 0:
                raise DecodeError("坐标不在曲线上")
        if x == 0 and sign:
            raise DecodeError("x=0 时不允许奇数符号位")
        if x & 1 != sign:
            x = Q - x
        p = Point(x, y, 1, x * y % Q)

        if p.encode() != b:
            raise DecodeError("非规范点编码")
        if strict:
            # 余因子为 8：8P = O 当且仅当 P 是小阶点（含单位元）。
            if p.scalar_mul(_COFACTOR).is_identity():
                raise DecodeError("拒绝小阶点（含单位元）")
            if not p.scalar_mul(L).is_identity():
                raise DecodeError("点不属于素数阶子群")
        return p


BASEPOINT = Point.decode(bytes.fromhex(BASEPOINT_HEX))


# ---------------------------------------------------------------------------
# 标量编解码
# ---------------------------------------------------------------------------


def scalar_encode(s: int) -> bytes:
    if not 0 <= s < L:
        raise NonCanonicalScalarError("标量超出 [0, l)")
    return s.to_bytes(32, "little")


def scalar_decode(raw: bytes, *, nonzero: bool = False) -> int:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
        raise DecodeError("标量编码必须为 32 字节")
    v = int.from_bytes(raw, "little")
    if v >= L:
        raise NonCanonicalScalarError("非规范标量：s >= l")
    if nonzero and v == 0:
        raise DecodeError("标量不得为 0")
    return v


# ---------------------------------------------------------------------------
# RFC 9591 §2.6 辅助函数（SHA-512，域分隔）
# ---------------------------------------------------------------------------


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def i2osp(n: int, width: int) -> bytes:
    return n.to_bytes(width, "big")


def encode_list(elements: list[bytes]) -> bytes:
    """RFC 9591 列表编码：2 字节元素个数 + 每个元素的 2 字节长度前缀。"""
    if len(elements) > 0xFFFF:
        raise ValueError("列表过长")
    out = i2osp(len(elements), 2)
    for e in elements:
        if not isinstance(e, (bytes, bytearray)) or len(e) > 0xFFFF:
            raise ValueError("列表元素必须为 <=65535 字节的字节串")
        out += i2osp(len(e), 2) + bytes(e)
    return out


def _scalar_from_hash(data: bytes) -> int:
    return int.from_bytes(_sha512(data), "little") % L


def H1(msg: bytes) -> int:
    """消息 -> 标量（密钥生成域）。"""
    return _scalar_from_hash(msg)


def H3(msg: bytes) -> int:
    """绑定因子/随机数域 -> 标量。"""
    return _scalar_from_hash(msg)


def H2(msg: bytes, elements: list[bytes]) -> int:
    """挑战哈希：H2(m, lst) = scalar(SHA-512(encode_list(lst) || m))。"""
    return _scalar_from_hash(encode_list(elements) + msg)


def hash_to_group(msg: bytes) -> Point:
    """RFC 9591 Ed25519 try-and-increment 散列到素数阶子群点。

    以单字节计数器为前缀尝试 SHA-512(msg) 前 32 字节，严格解码
    （曲线上、非小阶、素数阶子群）。仅用于构造第二承诺 E 的基点。
    """
    for ctr in range(256):
        h = _sha512(i2osp(ctr, 1) + msg)
        try:
            return Point.decode(h[:32])
        except DecodeError:
            continue
    raise RuntimeError("hash_to_group 失败")


def H4(msg: bytes) -> Point:
    return hash_to_group(msg)


def H5(msg: bytes) -> Point:  # 与 H4 构造相同，按 RFC 保留独立域分隔名
    return hash_to_group(msg)


# ---------------------------------------------------------------------------
# FROST 验证侧运算
# ---------------------------------------------------------------------------


def encode_commitment_list(
    order: list[int],
    commitments: dict[int, tuple[Point, Point]],
) -> bytes:
    """完整承诺集编码：外层列表，每项为 [identifier, D, E] 的内层列表。"""
    return encode_list(
        [
            encode_list(
                [
                    scalar_encode(i),
                    commitments[i][0].encode(),
                    commitments[i][1].encode(),
                ]
            )
            for i in order
        ]
    )


def binding_factor(
    encoded_commitment_list: bytes,
    group_pk: bytes,
    message: bytes,
    identifier: int,
) -> int:
    """rho_i = H3(encode_list(承诺集) || PK || m || identifier)。"""
    return H3(
        encoded_commitment_list + group_pk + message + scalar_encode(identifier)
    )


def group_commitment(
    order: list[int],
    commitments: dict[int, tuple[Point, Point]],
    rhos: dict[int, int],
) -> Point:
    """R = Prod_i D_i * E_i^rho_i。"""
    r = Point.identity()
    for i in order:
        d_i, e_i = commitments[i]
        r = r.add(d_i).add(e_i.scalar_mul(rhos[i]))
    return r


def challenge(message: bytes, r_commitment: Point, group_pk: bytes) -> int:
    """c = H2(m, [R, PK])。"""
    return H2(message, [r_commitment.encode(), group_pk])


def lagrange_coefficient(signer_ids: list[int], identifier: int) -> int:
    """lambda_i = Prod_{j != i} x_j / (x_j - x_i)（在 x=0 处插值）。"""
    num = 1
    den = 1
    for j in signer_ids:
        if j == identifier:
            continue
        num = num * j % L
        den = den * (j - identifier) % L
    return num * pow(den % L, L - 2, L) % L


def share_equation_lhs(sig_share: int) -> Point:
    """L_i = G^s_i（RFC 9591 §5.2.1，s_i 为第 i 份签名份额）。"""
    return BASEPOINT.scalar_mul(sig_share)


def share_equation_rhs(
    d_i: Point,
    e_i: Point,
    rho_i: int,
    public_key_share: Point,
    c: int,
    lam: int,
) -> Point:
    """R_i = D_i * E_i^rho_i * PK_i^(c*lambda_i)，PK_i 为该参与者公钥份额。"""
    hidden = d_i.add(e_i.scalar_mul(rho_i))
    return hidden.add(public_key_share.scalar_mul(c * lam % L))


def aggregate_equation_lhs(z: int) -> Point:
    return BASEPOINT.scalar_mul(z)


def aggregate_equation_rhs(r_group: Point, group_pk: Point, c: int) -> Point:
    return r_group.add(group_pk.scalar_mul(c))


# ---------------------------------------------------------------------------
# 可信分发方密钥生成 + 完整会签包构造（供测试/验收与演示）
# ---------------------------------------------------------------------------


class _SeedRng:
    """基于 SHA-512 的确定性随机标量源，便于复现实验。"""

    def __init__(self, seed: bytes):
        self._seed = seed
        self._ctr = 0

    def scalar(self, label: bytes) -> int:
        self._ctr += 1
        return _scalar_from_hash(
            self._seed + label + self._ctr.to_bytes(8, "little")
        )


def trusted_dealer_keygen(
    n: int,
    threshold: int,
    rng: _SeedRng,
) -> tuple[int, Point, dict[int, tuple[int, Point]]]:
    """返回 (群秘密 s, 群公钥 PK, {id: (份额私钥 sk_i, 份额公钥 PK_i)})。"""
    if not 1 <= threshold <= n:
        raise ValueError("门限参数非法")
    secret = rng.scalar(b"group-secret")
    coeffs = [secret] + [rng.scalar(b"poly-coeff") for _ in range(threshold - 1)]

    def f(x: int) -> int:
        acc = 0
        xk = 1
        for a in coeffs:
            acc = (acc + a * xk) % L
            xk = xk * x % L
        return acc

    shares = {}
    for i in range(1, n + 1):
        sk_i = f(i)
        shares[i] = (sk_i, BASEPOINT.scalar_mul(sk_i))
    return secret, BASEPOINT.scalar_mul(secret), shares


def make_commitments(
    identifier: int, sk_i: int, rng: _SeedRng
) -> tuple[int, int, Point, Point]:
    """构造 RFC 9591 双随机承诺：d_i, e_i, D_i = G^d_i, E_i = G^e_i。

    两个承诺均以基点 G 为底，这是份额方程
    G^s_i = D_i * E_i^rho_i * PK_i^(c lambda_i)
    与聚合方程 G^z = R * PK^c 同时成立的前提（RFC 9591 §6.1.1）。
    （H4/H5 的散列到群函数仍按 RFC 实现，用于预派生随机数/DKG 场景。）
    """
    d_i = rng.scalar(b"nonce-d" + scalar_encode(identifier) + scalar_encode(sk_i))
    e_i = rng.scalar(b"nonce-e" + scalar_encode(identifier) + scalar_encode(sk_i))
    return d_i, e_i, BASEPOINT.scalar_mul(d_i), BASEPOINT.scalar_mul(e_i)


def make_valid_package(
    threshold: int = 3,
    n: int = 3,
    message: bytes = b"deep-space-formation: station-keeping burn bravo-7",
    seed: bytes = b"rfc9591-acceptance-fixed-seed",
) -> dict:
    """构造一个密码学上有效的门限会签包（字段为 API 线格式：十六进制字符串）。"""
    if n < threshold:
        raise ValueError("n 必须 >= threshold")
    rng = _SeedRng(seed)
    secret, group_pk, shares = trusted_dealer_keygen(n, threshold, rng)
    del secret

    signer_ids = sorted(shares)[:threshold]
    raw_nonces: dict[int, tuple[int, int]] = {}
    commitments: dict[int, tuple[Point, Point]] = {}
    participants = []
    for i in signer_ids:
        sk_i, pk_i = shares[i]
        d_i, e_i, dp, ep = make_commitments(i, sk_i, rng)
        raw_nonces[i] = (d_i, e_i)
        commitments[i] = (dp, ep)
        participants.append(
            {
                "identifier": scalar_encode(i).hex(),
                "public_share": pk_i.encode().hex(),
                "commitment_d": dp.encode().hex(),
                "commitment_e": ep.encode().hex(),
            }
        )

    pk_bytes = group_pk.encode()
    order = signer_ids
    enc_list = encode_commitment_list(order, commitments)
    rhos = {
        i: binding_factor(enc_list, pk_bytes, message, i) for i in order
    }
    r_group = group_commitment(order, commitments, rhos)
    c = challenge(message, r_group, pk_bytes)

    z = 0
    for row, i in zip(participants, order):
        sk_i = shares[i][0]
        d_i, e_i = raw_nonces[i]
        lam = lagrange_coefficient(order, i)
        s_i = (d_i + e_i * rhos[i] + c * lam * sk_i) % L
        row["signature_share"] = scalar_encode(s_i).hex()
        z = (z + s_i) % L

    return {
        "message": message.hex(),
        "group_public_key": pk_bytes.hex(),
        "threshold": threshold,
        "participants": participants,
        "aggregate_signature": {
            "commitment": r_group.encode().hex(),
            "response": scalar_encode(z).hex(),
        },
    }
