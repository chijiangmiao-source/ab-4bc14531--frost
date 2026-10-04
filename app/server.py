"""核验台 HTTP 服务（标准库实现，无第三方依赖）。

路由：
  GET  /healthz                      健康响应
  POST /api/v1/countersign/verify    提交会签包（验证并冻结证据）
  GET  /api/v1/evidence/<audit_id>   读取既有冻结结论
  GET  /api/v1/evidence              证据列表
  GET  /                             核验台页面
  GET  /static/app.js, /static/style.css

监听地址由环境变量 HOST / PORT 配置（默认 0.0.0.0:8080）。
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote, urlparse

from . import __version__
from .store import (
    AuditIdError,
    ConflictError,
    EvidenceStore,
    canonical_digest,
    validate_audit_id,
)
from .verifier import VerificationError
from .frost import make_valid_package

_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
_MAX_BODY = 1 << 22  # 4 MiB


def _normalize_package(body: dict) -> dict:
    """允许页面直接提交文本消息：message_text 以 UTF-8 编码为消息字节。"""
    pkg = body.get("package")
    if not isinstance(pkg, dict):
        raise VerificationError("请求体缺少 package 对象")
    if "message" not in pkg and isinstance(pkg.get("message_text"), str):
        raw = pkg.pop("message_text").encode("utf-8")
        pkg["message"] = raw.hex()
    return pkg


class Handler(BaseHTTPRequestHandler):
    server_version = f"FrostCounterSignDesk/{__version__}"
    store: EvidenceStore = None  # 由工厂注入

    # -- 工具 ----------------------------------------------------------------

    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_static(self, filename: str, ctype: str) -> None:
        path = os.path.join(_STATIC_DIR, filename)
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            self._send_json(404, {"error": "not found"})
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args) -> None:
        if os.environ.get("FROST_DESK_QUIET"):
            return
        super().log_message(fmt, *args)

    # -- GET -----------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if path == "/healthz":
            self._send_json(
                200,
                {
                    "status": "ok",
                    "service": "frost-countersign-desk",
                    "version": __version__,
                },
            )
            return
        if path == "/":
            self._send_static("index.html", "text/html; charset=utf-8")
            return
        if path == "/static/app.js":
            self._send_static("app.js", "application/javascript; charset=utf-8")
            return
        if path == "/static/style.css":
            self._send_static("style.css", "text/css; charset=utf-8")
            return
        if path == "/api/v1/evidence":
            ids = self.store.all_ids()
            self._send_json(200, {"audit_ids": ids, "count": len(ids)})
            return
        if path == "/api/v1/sample-package":
            pkg = make_valid_package()
            self._send_json(200, {"package": pkg})
            return
        prefix = "/api/v1/evidence/"
        if path.startswith(prefix):
            audit_id = path[len(prefix):]
            record = self.store.get(audit_id)
            if record is None:
                self._send_json(404, {"error": "审计标识不存在", "audit_id": audit_id})
            else:
                self._send_json(200, {"record": record})
            return
        self._send_json(404, {"error": "未知路径", "path": path})

    # -- POST ----------------------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if unquote(parsed.path) != "/api/v1/countersign/verify":
            self._send_json(404, {"error": "未知路径"})
            return

        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > _MAX_BODY:
            self._send_json(413, {"error": "请求体为空或超过 4MiB"})
            return
        try:
            raw = self.rfile.read(length)
            body = json.loads(raw.decode("utf-8"))
            if not isinstance(body, dict):
                raise ValueError
        except (ValueError, UnicodeDecodeError):
            self._send_json(400, {"error": "请求体必须为 UTF-8 JSON 对象"})
            return

        try:
            audit_id = validate_audit_id(body.get("audit_id", ""))
            pkg = _normalize_package(body)
            digest = canonical_digest(pkg)
        except (AuditIdError, VerificationError) as exc:
            self._send_json(400, {"error": str(exc)})
            return

        try:
            frozen = self.store.submit(audit_id, pkg, content_hash=digest)
        except ConflictError as exc:
            self.send_response(409)
            payload = {
                "error": str(exc),
                "conflict": True,
                "changed": exc.changed,
                "incoming_hash": exc.current_hash,
                "existing": {
                    "audit_id": exc.existing["audit_id"],
                    "content_hash": exc.existing["content_hash"],
                    "created_at": exc.existing["created_at"],
                    "result": exc.existing["result"],
                },
            }
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            return

        record = frozen.record
        self._send_json(
            200,
            {
                "frozen": True,
                "reused_existing_conclusion": frozen.reused,
                "audit_id": audit_id,
                "content_hash": digest,
                "created_at": record["created_at"],
                "conflicts": record.get("conflicts", []),
                "result": record["result"],
                "structural_error": record.get("structural_error"),
            },
        )


def build_server(host: str, port: int, store: EvidenceStore) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"store": store})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    return httpd


def serve(host: str | None = None, port: int | None = None) -> None:
    host = host or os.environ.get("HOST", "0.0.0.0")
    port = int(port if port is not None else os.environ.get("PORT", "8080"))
    db_path = os.environ.get(
        "EVIDENCE_DB", os.path.join(os.getcwd(), "data", "evidence.json")
    )
    store = EvidenceStore(db_path)
    httpd = build_server(host, port, store)
    print(f"FROST countersign verification desk on http://{host}:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    serve()
