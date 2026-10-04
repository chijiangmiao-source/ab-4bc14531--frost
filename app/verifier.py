"""会签包验证器：结构校验 -> 逐份额方程 -> 聚合签名核对。

验证严格遵循 RFC 9591：
  * 所有标量必须规范（0 <= s < l），所有点必须可解码且属于素数阶子群；
  * 参与者标识唯一且在 1..l-1；参与者数量必须恰好等于阈值且不超过 8；
  * 绑定因子由原始消息、群公钥与“完整承诺集”共同计算（抗拼接）；
  * 先逐份验证（定位首个失败份额并给出方程残差），再核对聚合签名；
  * 聚合响应必须等于各份额之和，且满足 G^z = R * PK^c。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import frost


MAX_PARTICIPANTS = 8
MIN_THRESHOLD = 1
MAX_THRESHOLD = 0xFFFF


class VerificationError(ValueError):
    """会签包结构或内容不满足验证前提（在密码方程之前拒绝）。"""


@dataclass
class ShareResult:
    index: int                      # 稳定顺序中的位置（0 起）
    identifier: int
    ok: bool
    lagrange: str
    binding_factor: str
    residual_hex: str               # L_i - R_i 规范化点编码（全零表示相等）
    lhs_hex: str
    rhs_hex: str
    detail: str = ""


@dataclass
class VerificationResult:
    accepted: bool
    reasons: list[str] = field(default_factory=list)
    stable_order: list[int] = field(default_factory=list)
    group_commitment_hex: str = ""
    challenge_hex: str = ""
    shares: list[ShareResult] = field(default_factory=list)
    aggregate_residual_hex: str = ""
    aggregate_lhs_hex: str = ""
    aggregate_rhs_hex: str = ""
    aggregate_ok: bool = False
    response_sum_ok: bool = False
    first_failed_identifier: int | None = None

    def to_dict(self) -> dict:
        return {
            "accepted": self.accepted,
            "reasons": self.reasons,
            "stable_order": [_hex(frost.scalar_encode(i)) for i in self.stable_order],
            "group_commitment": self.group_commitment_hex,
            "challenge": self.challenge_hex,
            "participants": [
                {
                    "index": s.index,
                    "identifier": _hex(frost.scalar_encode(s.identifier)),
                    "accepted": s.ok,
                    "lagrange_coefficient": s.lagrange,
                    "binding_factor": s.binding_factor,
                    "residual": s.residual_hex,
                    "lhs": s.lhs_hex,
                    "rhs": s.rhs_hex,
                    "detail": s.detail,
                }
                for s in self.shares
            ],
            "aggregate": {
                "accepted": self.aggregate_ok,
                "response_matches_sum_of_shares": self.response_sum_ok,
                "residual": self.aggregate_residual_hex,
                "lhs": self.aggregate_lhs_hex,
                "rhs": self.aggregate_rhs_hex,
            },
            "first_failed_identifier": (
                _hex(frost.scalar_encode(self.first_failed_identifier))
                if self.first_failed_identifier is not None
                else None
            ),
        }


def _hex(b: bytes) -> str:
    return b.hex()


def _as_bytes(value, field_name: str) -> bytes:
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError as exc:
            raise VerificationError(f"{field_name} 不是合法十六进制") from exc
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise VerificationError(f"{field_name} 必须为十六进制字符串或字节串")


def _decode_participants(raw) -> tuple[list[int], dict[int, dict]]:
    if not isinstance(raw, list):
        raise VerificationError("participants 必须为列表")
    if not raw:
        raise VerificationError("参与者列表为空")
    if len(raw) > MAX_PARTICIPANTS:
        raise VerificationError(
            f"参与者数量 {len(raw)} 超过上限 {MAX_PARTICIPANTS}"
        )

    seen: set[int] = set()
    decoded: list[tuple[int, dict]] = []
    for pos, row in enumerate(raw):
        if not isinstance(row, dict):
            raise VerificationError(f"参与者 #{pos} 不是对象")
        label = f"参与者 #{pos}"
        id_raw = _as_bytes(row.get("identifier"), f"{label}.identifier")
        identifier = frost.scalar_decode(id_raw, nonzero=True)
        if identifier in seen:
            raise VerificationError(f"重复参与者标识：{_hex(id_raw)}")
        seen.add(identifier)

        fields = {}
        for name in ("public_share", "commitment_d", "commitment_e", "signature_share"):
            fields[name] = _as_bytes(row.get(name), f"{label}.{name}")
        decoded.append((identifier, fields))

    decoded.sort(key=lambda item: item[0])
    order = [i for i, _ in decoded]
    table = {i: f for i, f in decoded}
    return order, table


def _residual(lhs: "frost.Point", rhs: "frost.Point") -> str:
    """方程残差：LHS * RHS^{-1} 的点编码；与单位元编码相等即方程成立。

    我们不以一个点“是否为单位元”作为唯一判据（其编码并非全零字节），
    而是直接比较 LHS 与 RHS 的编码；残差用 LHS-RHS 点呈现给审计员，
    并额外给出 identity_hex 以便页面直观判断。
    """
    return lhs.add(rhs.neg()).encode().hex()


def verify_package(pkg: dict) -> VerificationResult:
    """对会签包执行完整验证；任何结构缺陷都抛出 VerificationError。"""
    if not isinstance(pkg, dict):
        raise VerificationError("会签包必须为 JSON 对象")

    threshold = pkg.get("threshold")
    if not isinstance(threshold, int) or isinstance(threshold, bool):
        raise VerificationError("threshold 必须为整数")
    if not MIN_THRESHOLD <= threshold <= MAX_THRESHOLD:
        raise VerificationError("threshold 超出允许范围")

    message = _as_bytes(pkg.get("message", b""), "message")
    pk_bytes = _as_bytes(pkg.get("group_public_key"), "group_public_key")

    agg = pkg.get("aggregate_signature")
    if not isinstance(agg, dict):
        raise VerificationError("aggregate_signature 必须为对象")
    r_claimed_raw = _as_bytes(agg.get("commitment"), "aggregate_signature.commitment")
    z_raw = _as_bytes(agg.get("response"), "aggregate_signature.response")

    order, table = _decode_participants(pkg.get("participants"))
    if len(order) != threshold:
        raise VerificationError(
            f"阈值不符：threshold={threshold}，但实际签名者数量={len(order)}"
        )

    # 点与标量解码（任何不可解码点/非规范标量在此拒绝）。
    try:
        group_pk = frost.Point.decode(pk_bytes)
    except frost.DecodeError as exc:
        raise VerificationError(f"群公钥不可解码：{exc}") from exc

    commitments: dict[int, tuple[frost.Point, frost.Point]] = {}
    sig_shares: dict[int, int] = {}
    pk_shares: dict[int, frost.Point] = {}
    for i in order:
        row = table[i]
        try:
            d_i = frost.Point.decode(row["commitment_d"])
            e_i = frost.Point.decode(row["commitment_e"])
            pk_i = frost.Point.decode(row["public_share"])
        except frost.DecodeError as exc:
            raise VerificationError(
                f"参与者 {_hex(frost.scalar_encode(i))} 的点不可解码：{exc}"
            ) from exc
        try:
            s_i = frost.scalar_decode(row["signature_share"])
        except frost.DecodeError as exc:
            raise VerificationError(
                f"参与者 {_hex(frost.scalar_encode(i))} 的签名份额为非规范标量：{exc}"
            ) from exc
        commitments[i] = (d_i, e_i)
        pk_shares[i] = pk_i
        sig_shares[i] = s_i

    try:
        r_claimed = frost.Point.decode(r_claimed_raw)
    except frost.DecodeError as exc:
        raise VerificationError(f"聚合承诺不可解码：{exc}") from exc
    try:
        z = frost.scalar_decode(z_raw)
    except frost.DecodeError as exc:
        raise VerificationError(f"聚合响应为非规范标量：{exc}") from exc

    # 完整承诺集 -> 绑定因子 -> 群承诺 -> 挑战（域分隔由 H3/H2 保证）。
    enc_list = frost.encode_commitment_list(order, commitments)
    rhos = {
        i: frost.binding_factor(enc_list, pk_bytes, message, i) for i in order
    }
    r_group = frost.group_commitment(order, commitments, rhos)
    c = frost.challenge(message, r_group, pk_bytes)

    result = VerificationResult(
        accepted=False,
        stable_order=order,
        group_commitment_hex=r_group.encode().hex(),
        challenge_hex=frost.scalar_encode(c).hex(),
    )

    if r_group.encode() != r_claimed_raw:
        result.reasons.append(
            "聚合承诺与完整承诺集派生的群承诺 R 不一致（疑似承诺拼接）"
        )

    # 逐份额验证。
    first_failed: int | None = None
    for pos, i in enumerate(order):
        lam = frost.lagrange_coefficient(order, i)
        d_i, e_i = commitments[i]
        lhs = frost.share_equation_lhs(sig_shares[i])
        rhs = frost.share_equation_rhs(d_i, e_i, rhos[i], pk_shares[i], c, lam)
        ok = lhs.encode() == rhs.encode()
        share_result = ShareResult(
            index=pos,
            identifier=i,
            ok=ok,
            lagrange=frost.scalar_encode(lam).hex(),
            binding_factor=frost.scalar_encode(rhos[i]).hex(),
            residual_hex=lhs.add(rhs.neg()).encode().hex(),
            lhs_hex=lhs.encode().hex(),
            rhs_hex=rhs.encode().hex(),
            detail="" if ok else "份额验证方程 G^s_i = D_i E_i^rho_i PK_i^(c lambda_i) 不成立",
        )
        result.shares.append(share_result)
        if not ok and first_failed is None:
            first_failed = i

    if first_failed is not None:
        result.first_failed_identifier = first_failed
        result.reasons.append(
            "首个失败份额：参与者标识 "
            + _hex(frost.scalar_encode(first_failed))
            + "（见 participants 中残差）"
        )

    # 聚合响应必须是份额之和（防聚合器重写/拼接响应）。
    z_sum = sum(sig_shares.values()) % frost.L
    result.response_sum_ok = z_sum == z
    if not result.response_sum_ok:
        result.reasons.append(
            "聚合响应 z 不等于各签名份额之和（疑似响应拼接/重写）"
        )

    # 聚合签名核对：G^z = R * PK^c。
    agg_lhs = frost.aggregate_equation_lhs(z)
    agg_rhs = frost.aggregate_equation_rhs(r_group, group_pk, c)
    result.aggregate_lhs_hex = agg_lhs.encode().hex()
    result.aggregate_rhs_hex = agg_rhs.encode().hex()
    result.aggregate_residual_hex = agg_lhs.add(agg_rhs.neg()).encode().hex()
    result.aggregate_ok = agg_lhs.encode() == agg_rhs.encode()
    if not result.aggregate_ok:
        result.reasons.append("聚合签名方程 G^z = R * PK^c 不成立")

    all_shares_ok = all(s.ok for s in result.shares)
    result.accepted = (
        all_shares_ok
        and result.aggregate_ok
        and result.response_sum_ok
        and r_group.encode() == r_claimed_raw
    )
    if result.accepted:
        result.reasons.append(
            "全部份额验证通过，聚合签名与完整承诺集、原始消息、群公钥绑定一致"
        )
    return result
