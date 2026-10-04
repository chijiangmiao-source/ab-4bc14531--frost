"""RFC 9591 密码规则代码测试（标准库 unittest）。"""

from __future__ import annotations

import copy
import hashlib
import unittest

from app import frost
from app.frost import (
    BASEPOINT,
    L,
    Q,
    Point,
    make_valid_package,
)
from app.store import (
    AuditIdError,
    ConflictError,
    EvidenceStore,
    canonical_digest,
)
from app.verifier import VerificationError, verify_package


def _hex_scalar(i: int) -> str:
    return frost.scalar_encode(i % L).hex()


class PointTests(unittest.TestCase):
    def test_basepoint_vector(self):
        self.assertEqual(
            BASEPOINT.encode().hex(),
            "5866666666666666666666666666666666666666666666666666666666666666",
        )

    def test_decode_rejects_non_curve_and_identity(self):
        with self.assertRaises(frost.DecodeError):
            Point.decode(b"\xff" * 32)
        # 单位元（全零编码）是小阶点，必须拒绝。
        with self.assertRaises(frost.DecodeError):
            Point.decode(b"\x00" * 32)

    def test_known_low_order_points_rejected(self):
        # RFC 8032 经典小阶点（y=1, x 符号位=1 -> 编码 0x01..0x80）。
        lo = bytes([1] + [0] * 30 + [0x80])
        with self.assertRaises(frost.DecodeError):
            Point.decode(lo)

    def test_encode_roundtrip_and_recompression_flag(self):
        for k in (1, 2, 3, 7, L - 1):
            p = BASEPOINT.scalar_mul(k)
            raw = p.encode()
            self.assertEqual(Point.decode(raw), p)
        # 两个符号位选择对应互逆点，各自都能还原；非法拒绝由曲线/子群检查覆盖。
        raw = bytearray(BASEPOINT.scalar_mul(12345).encode())
        raw[31] ^= 0x80
        self.assertEqual(Point.decode(bytes(raw)), Point.decode(BASEPOINT.scalar_mul(12345).encode()).neg())

    def test_group_law_affine_crosscheck(self):
        """用独立的仿射坐标加法交叉验证扩展坐标实现。"""

        def aff(p: Point):
            zi = pow(p.z, Q - 2, Q)
            return p.x * zi % Q, p.y * zi % Q

        def aff_add(p: Point, q: Point) -> Point:
            x1, y1 = aff(p)
            x2, y2 = aff(q)
            d = frost._D
            den = d * x1 * x2 * y1 * y2 % Q
            x3 = ((x1 * y2 + x2 * y1) * pow(1 + den, Q - 2, Q)) % Q
            y3 = (y1 * y2 + x1 * x2) * pow(1 - den, Q - 2, Q) % Q
            return Point(x3, y3, 1, x3 * y3 % Q)

        for a, b in ((1, 2), (3, 5), (100, L - 100)):
            p, q = BASEPOINT.scalar_mul(a), BASEPOINT.scalar_mul(b)
            self.assertEqual(p.add(q), aff_add(p, q))
            if a + b == L:
                self.assertTrue(p.add(q).is_identity())

    def test_basepoint_has_prime_order(self):
        self.assertTrue(BASEPOINT.scalar_mul(L).is_identity())
        self.assertFalse(BASEPOINT.scalar_mul(L - 1).is_identity())


class ScalarTests(unittest.TestCase):
    def test_canonical_bounds(self):
        self.assertEqual(frost.scalar_decode((0).to_bytes(32, "little")), 0)
        self.assertEqual(
            frost.scalar_decode((L - 1).to_bytes(32, "little")), L - 1
        )
        with self.assertRaises(frost.NonCanonicalScalarError):
            frost.scalar_decode(L.to_bytes(32, "little"))
        with self.assertRaises(frost.NonCanonicalScalarError):
            frost.scalar_decode((2**256 - 1).to_bytes(32, "little"))
        with self.assertRaises(frost.DecodeError):
            frost.scalar_decode(b"\x00" * 31)
        with self.assertRaises(frost.DecodeError):
            frost.scalar_decode((0).to_bytes(32, "little"), nonzero=True)


class HashEncodingTests(unittest.TestCase):
    def test_encode_list_structure(self):
        enc = frost.encode_list([b"\x01\x02", b"\x03"])
        self.assertEqual(enc, b"\x00\x02" + b"\x00\x02\x01\x02" + b"\x00\x01\x03")

    def test_h2_domain_separation(self):
        """H2 必须对消息、列表顺序、列表内容敏感。"""
        base = frost.H2(b"m", [b"a", b"b"])
        self.assertNotEqual(base, frost.H2(b"n", [b"a", b"b"]))
        self.assertNotEqual(base, frost.H2(b"m", [b"b", b"a"]))
        self.assertNotEqual(base, frost.H2(b"m", [b"a", b"c"]))
        expect = int.from_bytes(
            hashlib.sha512(
                frost.encode_list([b"a", b"b"]) + b"m"
            ).digest(),
            "little",
        ) % L
        self.assertEqual(base, expect)

    def test_binding_factor_binds_full_commitment_set(self):
        pkg = make_valid_package()
        order = [1, 2, 3]
        commits = {}
        for row, i in zip(pkg["participants"], order):
            commits[i] = (
                Point.decode(bytes.fromhex(row["commitment_d"])),
                Point.decode(bytes.fromhex(row["commitment_e"])),
            )
        enc = frost.encode_commitment_list(order, commits)
        pk = bytes.fromhex(pkg["group_public_key"])
        msg = bytes.fromhex(pkg["message"])
        rho1 = frost.binding_factor(enc, pk, msg, 1)
        # 交换/更换任意承诺都会改变所有绑定因子。
        enc2 = frost.encode_commitment_list(
            order, {**commits, 2: (commits[2][1], commits[2][0])}
        )
        self.assertNotEqual(rho1, frost.binding_factor(enc2, pk, msg, 1))
        # 消息/公钥变化同样改变绑定因子。
        self.assertNotEqual(rho1, frost.binding_factor(enc, pk, b"x", 1))
        self.assertNotEqual(rho1, frost.binding_factor(enc, b"\x00" * 32, msg, 1))


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.pkg = make_valid_package()

    def test_valid_package_accepted(self):
        r = verify_package(self.pkg)
        self.assertTrue(r.accepted)
        self.assertTrue(r.aggregate_ok)
        self.assertTrue(r.response_sum_ok)
        self.assertEqual([s.ok for s in r.shares], [True, True, True])
        self.assertEqual(r.stable_order, [1, 2, 3])

    def test_stable_order_is_identifier_sorted(self):
        """打乱输入顺序后，结论中的稳定顺序仍按标识升序。"""
        pkg = copy.deepcopy(self.pkg)
        pkg["participants"] = [
            pkg["participants"][2],
            pkg["participants"][0],
            pkg["participants"][1],
        ]
        r = verify_package(pkg)
        self.assertTrue(r.accepted)
        self.assertEqual(r.stable_order, [1, 2, 3])
        self.assertEqual([s.identifier for s in r.shares], [1, 2, 3])

    def test_each_tampered_share_is_localized(self):
        for pos in range(3):
            bad = copy.deepcopy(self.pkg)
            s = int(bad["participants"][pos]["signature_share"], 16)
            bad["participants"][pos]["signature_share"] = _hex_scalar(s + 1)
            r = verify_package(bad)
            self.assertFalse(r.accepted)
            self.assertEqual(r.first_failed_identifier, pos + 1)
            fails = [x.identifier for x in r.shares if not x.ok]
            self.assertEqual(fails, [pos + 1])
            fr = next(x for x in r.shares if not x.ok)
            self.assertNotEqual(fr.lhs_hex, fr.rhs_hex)

    def test_message_change_conflicts_with_everything(self):
        bad = copy.deepcopy(self.pkg)
        bad["message"] = b"retarget burn order".hex()
        r = verify_package(bad)
        self.assertFalse(r.accepted)
        self.assertFalse(r.aggregate_ok)
        self.assertFalse(all(s.ok for s in r.shares))

    def test_commitment_splice_rejected_and_localized(self):
        donor = make_valid_package(seed=b"donor-seed-98765")
        bad = copy.deepcopy(self.pkg)
        bad["participants"][1]["commitment_e"] = donor["participants"][0]["commitment_e"]
        r = verify_package(bad)
        self.assertFalse(r.accepted)
        # 绑定因子绑定“完整承诺集”：替换任一份承诺会改变全部 rho_i，
        # 因而所有份额方程同时失败，首个失败为稳定顺序中的第 1 名。
        self.assertEqual(r.first_failed_identifier, 1)
        self.assertFalse(any(s.ok for s in r.shares))
        # 群承诺 R 亦不再匹配聚合承诺。
        self.assertIn("群承诺", "；".join(r.reasons))

    def test_aggregate_response_splice_detected(self):
        bad = copy.deepcopy(self.pkg)
        z = int(bad["aggregate_signature"]["response"], 16)
        bad["aggregate_signature"]["response"] = _hex_scalar(z + 1)
        r = verify_package(bad)
        self.assertFalse(r.accepted)
        self.assertFalse(r.response_sum_ok)
        self.assertFalse(r.aggregate_ok)

    def test_structural_rejections(self):
        cases = {
            "duplicate identifier": lambda b: b["participants"][1].__setitem__(
                "identifier", b["participants"][0]["identifier"]
            ),
            "threshold mismatch": lambda b: b.__setitem__("threshold", 2),
            "noncanonical scalar": lambda b: b["participants"][0].__setitem__(
                "signature_share", L.to_bytes(32, "little").hex()
            ),
            "undecodable point": lambda b: b["participants"][0].__setitem__(
                "commitment_d", "ff" * 32
            ),
            "bad hex": lambda b: b["participants"][0].__setitem__(
                "public_share", "zz"
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                bad = copy.deepcopy(self.pkg)
                mutate(bad)
                with self.assertRaises(VerificationError):
                    verify_package(bad)

    def test_more_than_eight_participants_rejected(self):
        pkg = copy.deepcopy(self.pkg)
        rows = pkg["participants"]
        while len(rows) < 9:
            rows.append(copy.deepcopy(rows[0]))
        with self.assertRaises(VerificationError):
            verify_package(pkg)

    def test_threshold_one_and_eight_supported(self):
        pkg = make_valid_package(threshold=1, n=1)
        self.assertTrue(verify_package(pkg).accepted)
        pkg8 = make_valid_package(threshold=8, n=8)
        self.assertTrue(verify_package(pkg8).accepted)


class EvidenceStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = EvidenceStore()  # 内存库
        self.pkg = make_valid_package()

    def test_freeze_then_replay_returns_same_conclusion(self):
        a = self.store.submit("AUDIT/001", self.pkg)
        self.assertFalse(a.reused)
        b = self.store.submit("AUDIT/001", copy.deepcopy(self.pkg))
        self.assertTrue(b.reused)
        self.assertEqual(
            a.record["result"]["challenge"], b.record["result"]["challenge"]
        )
        self.assertEqual(a.record["created_at"], b.record["created_at"])

    def test_conflict_never_overwrites(self):
        self.store.submit("AUDIT/002", self.pkg)
        changed = copy.deepcopy(self.pkg)
        changed["message"] = b"abort burn".hex()
        with self.assertRaises(ConflictError) as ctx:
            self.store.submit("AUDIT/002", changed)
        self.assertIn("message", ctx.exception.changed["top_level"])
        rec = self.store.get("AUDIT/002")
        self.assertEqual(rec["content_hash"], canonical_digest(self.pkg))
        self.assertTrue(rec["result"]["accepted"])
        self.assertEqual(len(rec["conflicts"]), 1)

    def test_commitment_change_is_conflict_and_localized_in_diff(self):
        self.store.submit("AUDIT/003", self.pkg)
        changed = copy.deepcopy(self.pkg)
        changed["participants"][0]["commitment_d"] = changed["participants"][1]["commitment_d"]
        with self.assertRaises(ConflictError) as ctx:
            self.store.submit("AUDIT/003", changed)
        self.assertIn(
            "commitment_d", ctx.exception.changed["participants"]["01" + "00" * 31]
        )

    def test_bad_audit_id(self):
        for bad in ("", "a", "../escape", "a b", "中文"):
            with self.assertRaises(AuditIdError):
                EvidenceStore().submit(bad, self.pkg)

    def test_structurally_invalid_package_freezes_rejection(self):
        bad = copy.deepcopy(self.pkg)
        bad["threshold"] = 99
        rec = self.store.submit("AUDIT/004", bad)
        self.assertFalse(rec.record["result"]["accepted"])
        self.assertTrue(rec.record["structural_error"])
        again = self.store.submit("AUDIT/004", bad)
        self.assertTrue(again.reused)


class EvidenceStorePersistenceTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path

        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "evidence.json")
        self.pkg = make_valid_package()

    def tearDown(self):
        self.tmp.cleanup()

    def test_freeze_survives_reopen_and_conflict_still_blocked(self):
        store = EvidenceStore(self.path)
        store.submit("AUDIT/PERSIST/1", self.pkg)
        # 重新打开证据库（模拟服务重启）：既有冻结结论原样可读。
        reopened = EvidenceStore(self.path)
        rec = reopened.get("AUDIT/PERSIST/1")
        self.assertIsNotNone(rec)
        self.assertTrue(rec["result"]["accepted"])
        # 重启后相同载荷仍是复用既有结论。
        again = reopened.submit("AUDIT/PERSIST/1", copy.deepcopy(self.pkg))
        self.assertTrue(again.reused)
        # 重启后内容变化依然冲突且不覆盖。
        changed = copy.deepcopy(self.pkg)
        changed["aggregate_signature"]["response"] = (0).to_bytes(32, "little").hex()
        with self.assertRaises(ConflictError):
            reopened.submit("AUDIT/PERSIST/1", changed)
        rec2 = EvidenceStore(self.path).get("AUDIT/PERSIST/1")
        self.assertTrue(rec2["result"]["accepted"])
        self.assertEqual(len(rec2["conflicts"]), 1)


class HashToGroupTests(unittest.TestCase):
    def test_h4_returns_prime_order_point_and_is_domain_separated(self):
        p1 = frost.H4(b"pre-nonce-input-1")
        p2 = frost.H4(b"pre-nonce-input-2")
        self.assertTrue(p1.scalar_mul(L).is_identity())
        self.assertFalse(p1.scalar_mul(8).is_identity())
        self.assertNotEqual(p1, p2)
        self.assertEqual(frost.H4(b"pre-nonce-input-1"), p1)


if __name__ == "__main__":
    unittest.main()
