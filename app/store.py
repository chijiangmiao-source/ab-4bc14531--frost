"""Append-only frozen evidence store.

The first packet seen for an audit identifier freezes its conclusion.

* byte-identical retransmission (same canonical JSON digest) -> the
  existing frozen conclusion is returned untouched;
* same audit_id but any content difference -> CONFLICT, the request is
  rejected and the original evidence is never overwritten.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone

from .verifier import canonical_packet_bytes, packet_digest


class EvidenceStore:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if not os.path.exists(path):
            self._write({})

    def _read(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def _write(self, data: dict) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2,
                      sort_keys=True)
        os.replace(tmp, self.path)

    @staticmethod
    def _fingerprint(result: dict) -> str:
        """Stable hash of the verification conclusion itself."""
        return hashlib.sha256(
            canonical_packet_bytes(result)).hexdigest()

    def submit(self, packet: dict, result: dict) -> dict:
        """Freeze or reconcile. Returns an envelope dict."""
        audit_id = result.get("audit_id") or packet.get("audit_id") or ""
        digest = packet_digest(packet)
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            data = self._read()
            existing = data.get(audit_id)
            if existing is None:
                record = {
                    "audit_id": audit_id,
                    "status": "frozen",
                    "frozen_at": now,
                    "packet_digest": digest,
                    "conclusion_fingerprint": self._fingerprint(result),
                    "verdict": result["verdict"],
                    "result": result,
                    "conflicts": [],
                }
                data[audit_id] = record
                self._write(data)
                return {"frozen_state": "new", "record": record}

            if existing["packet_digest"] == digest:
                return {"frozen_state": "identical_retransmit",
                        "record": existing}

            conflict = {
                "detected_at": now,
                "incoming_packet_digest": digest,
                "frozen_packet_digest": existing["packet_digest"],
                "note": "same audit identifier with different content; "
                        "original frozen evidence retained",
            }
            existing.setdefault("conflicts", []).append(conflict)
            data[audit_id] = existing
            self._write(data)
            return {"frozen_state": "conflict", "record": existing,
                    "conflict": conflict}

    def get(self, audit_id: str):
        with self._lock:
            return self._read().get(audit_id)

    def list(self):
        with self._lock:
            data = self._read()
        return [
            {
                "audit_id": k,
                "frozen_at": v.get("frozen_at"),
                "verdict": v.get("verdict"),
                "packet_digest": v.get("packet_digest"),
                "conflict_count": len(v.get("conflicts", [])),
            }
            for k, v in sorted(data.items())
        ]
