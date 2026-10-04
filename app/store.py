"""稳定审计标识与冻结证据库。

规则：
  * 同一 audit_id 重传“完全相同”的会签包 -> 返回既有冻结结论（不重算、不覆盖）；
  * 同一 audit_id 内容（消息、承诺或任何字段）变化 -> ConflictError，
    原始证据原样保留，冲突仅被记录但绝不覆盖；
  * 证据落盘为 JSON（原子替换），进程重启后冻结结论依然有效。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone

from .verifier import VerificationError, verify_package

_AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{2,127}$")


class AuditIdError(ValueError):
    """审计标识不合法。"""


class ConflictError(Exception):
    """相同审计标识承载了不同内容；原始冻结证据不得覆盖。"""

    def __init__(self, existing: dict, current_hash: str, changed: dict):
        self.existing = existing
        self.current_hash = current_hash
        self.changed = changed
        super().__init__(
            f"审计标识 {existing['audit_id']} 内容冲突：原始证据保持冻结，拒绝覆盖"
        )


def validate_audit_id(audit_id: str) -> str:
    if not isinstance(audit_id, str):
        raise AuditIdError("audit_id 必须为字符串")
    audit_id = audit_id.strip()
    if not _AUDIT_ID_RE.match(audit_id):
        raise AuditIdError(
            "audit_id 须为 3-128 位字母/数字及 . _ : / - 字符，且以字母数字开头"
        )
    return audit_id


def canonical_digest(pkg: dict) -> str:
    """对会签包做规范 JSON 序列化后的 SHA-256（用于内容同一性判定）。"""
    blob = json.dumps(
        pkg, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _diff_packages(a: dict, b: dict) -> dict:
    """给出顶层字段与逐参与者（按标识索引）的变化清单。"""
    changed_top: list[str] = []
    scalar_fields = ("message", "group_public_key", "threshold")
    for f in scalar_fields:
        if a.get(f) != b.get(f):
            changed_top.append(f)
    if a.get("aggregate_signature") != b.get("aggregate_signature"):
        changed_top.append("aggregate_signature")

    def index(rows):
        out = {}
        for pos, row in enumerate(rows or []):
            key = row.get("identifier", f"#{pos}")
            out[key] = row
        return out

    pa, pb = index(a.get("participants")), index(b.get("participants"))
    changed_participants: dict[str, list[str]] = {}
    for key in sorted(set(pa) | set(pb)):
        if key not in pa:
            changed_participants[str(key)] = ["<新增参与者>"]
            continue
        if key not in pb:
            changed_participants[str(key)] = ["<参与者缺失>"]
            continue
        fields = [
            f
            for f in (
                "public_share",
                "commitment_d",
                "commitment_e",
                "signature_share",
            )
            if pa[key].get(f) != pb[key].get(f)
        ]
        if fields:
            changed_participants[str(key)] = fields
    return {
        "top_level": changed_top,
        "participants": changed_participants,
    }


@dataclass
class FrozenRecord:
    record: dict
    reused: bool


class EvidenceStore:
    def __init__(self, path: str | None = None):
        self._lock = threading.Lock()
        self.path = path
        self._records: dict[str, dict] = {}
        if path:
            self._load()

    def _load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict) and isinstance(data.get("records"), dict):
                self._records = data["records"]
        except FileNotFoundError:
            pass
        except (json.JSONDecodeError, OSError):
            # 证据库损坏时不得静默吞掉：另存损坏文件后从空库启动。
            bak = self.path + ".corrupt"
            try:
                os.replace(self.path, bak)
            except OSError:
                pass
            self._records = {}

    def _persist_locked(self) -> None:
        if not self.path:
            return
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        payload = {"version": 1, "records": self._records}
        fd, tmp = tempfile.mkstemp(prefix=".evidence-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def get(self, audit_id: str) -> dict | None:
        with self._lock:
            rec = self._records.get(audit_id)
            return json.loads(json.dumps(rec)) if rec else None

    def all_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._records)

    def submit(self, audit_id: str, pkg: dict, *, content_hash: str | None = None) -> FrozenRecord:
        """提交会签包；结构非法同样冻结为“拒绝”结论。"""
        audit_id = validate_audit_id(audit_id)
        digest = content_hash or canonical_digest(pkg)

        with self._lock:
            existing = self._records.get(audit_id)
            if existing is not None:
                if existing["content_hash"] == digest:
                    return FrozenRecord(record=json.loads(json.dumps(existing)), reused=True)
                changed = _diff_packages(existing["package"], pkg)
                conflict = {
                    "at": datetime.now(timezone.utc).isoformat(),
                    "incoming_hash": digest,
                    "changed": changed,
                }
                existing.setdefault("conflicts", []).append(conflict)
                self._persist_locked()
                raise ConflictError(
                    json.loads(json.dumps(existing)), digest, changed
                )

            try:
                result = verify_package(pkg).to_dict()
                structural_error = None
            except VerificationError as exc:
                result = {"accepted": False, "structural_rejection": True}
                structural_error = str(exc)

            record = {
                "audit_id": audit_id,
                "content_hash": digest,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "structural_error": structural_error,
                "result": result,
                "package": pkg,
                "conflicts": [],
            }
            self._records[audit_id] = record
            self._persist_locked()
            return FrozenRecord(record=json.loads(json.dumps(record)), reused=False)
