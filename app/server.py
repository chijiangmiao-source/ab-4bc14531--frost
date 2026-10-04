"""HTTP API + console for the offline countersigning verifier.

Standard-library only, so the container image needs no packages.

Endpoints
---------
GET  /healthz                       liveness probe
GET  /                              verification console (static page)
GET  /static/*                      console assets
POST /api/verify                    verify a packet and freeze the result
GET  /api/evidence                  list frozen conclusions
GET  /api/evidence/{audit_id}       fetch a frozen conclusion
GET  /api/demo-package              mint a valid fixture packet
GET  /api/demo-package?tamper=KIND  mint a tampered fixture packet
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import verifier  # noqa: E402
from app.store import EvidenceStore  # noqa: E402

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "web")
MAX_BODY_BYTES = 1 << 20

STORE = EvidenceStore(os.environ.get(
    "EVIDENCE_STORE_PATH",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "data", "evidence.json")))

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "FrostVerify/1.0"

    def log_message(self, fmt, *args):  # concise structured logs
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send_json(self, status: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_static(self, rel_path: str):
        rel_path = rel_path.lstrip("/")
        target = os.path.normpath(os.path.join(WEB_DIR, rel_path))
        if not target.startswith(WEB_DIR + os.sep) and target != WEB_DIR:
            self.send_error(403)
            return
        if os.path.isdir(target) or rel_path == "":
            target = os.path.join(WEB_DIR, "index.html")
        if not os.path.isfile(target):
            self.send_error(404)
            return
        ext = os.path.splitext(target)[1]
        with open(target, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Type",
                         CONTENT_TYPES.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/healthz":
            self._send_json(200, {"status": "ok",
                                  "service": "frost-countersign-verifier",
                                  "ciphersuite": "FROST-ED25519-SHA512-v1"})
            return
        if path == "/api/evidence":
            self._send_json(200, {"evidence": STORE.list()})
            return
        if path.startswith("/api/evidence/"):
            audit_id = path.split("/", 3)[3]
            record = STORE.get(audit_id)
            if record is None:
                self._send_json(404, {"error": "no frozen evidence",
                                      "audit_id": audit_id})
            else:
                self._send_json(200, record)
            return
        if path == "/api/demo-package":
            self._demo_package(parse_qs(parsed.query))
            return
        if path.startswith("/api/"):
            self._send_json(404, {"error": "unknown API route", "path": path})
            return
        self._send_static(path)

    def _demo_package(self, query):
        from .fixtures import make_countersign_package, tamper
        msg = (query.get("message", ["MANEUVER-ORDER: delta-7 go"])[0]
               ).encode("utf-8")
        audit_id = query.get("audit_id", ["AUDIT-DEMO-0001"])[0]
        seed = query.get("seed", ["fixture-seed-alpha"])[0].encode()
        packet = make_countersign_package(
            msg, threshold=2, identifiers=(1, 3),
            rng_seed=seed, audit_id=audit_id)
        tamper_kind = query.get("tamper", [""])[0]
        if tamper_kind:
            try:
                index = int(query.get("index", ["1"])[0])
                packet = tamper(packet, kind=tamper_kind, index=index)
            except (ValueError, KeyError) as exc:
                self._send_json(400, {"error": str(exc)})
                return
        self._send_json(200, packet)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/verify":
            self._send_json(404, {"error": "unknown API route",
                                  "path": parsed.path})
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            self._send_json(400, {"error": "empty request body"})
            return
        if length > MAX_BODY_BYTES:
            self._send_json(413, {"error": "packet too large"})
            return
        raw = self.rfile.read(length)
        try:
            packet = json.loads(raw.decode("utf-8"))
            if not isinstance(packet, dict):
                raise ValueError("top-level JSON value must be an object")
        except (ValueError, UnicodeDecodeError) as exc:
            self._send_json(400, {"error": f"invalid JSON packet: {exc}"})
            return

        try:
            result = verifier.verify_packet(packet)
            envelope = STORE.submit(packet, result)
        except Exception as exc:  # never leak a traceback as a 200
            traceback.print_exc()
            self._send_json(500, {"error": "internal verification error",
                                  "detail": str(exc)})
            return

        frozen_state = envelope["frozen_state"]
        record = envelope["record"]
        status = 200
        if frozen_state == "conflict":
            status = 409
        response = {
            "frozen_state": frozen_state,
            "packet_digest": record["packet_digest"],
            "frozen_at": record["frozen_at"],
            "frozen_verdict": record["verdict"],
            "conclusion_fingerprint": record["conclusion_fingerprint"],
            "result": record["result"] if frozen_state != "new" else result,
        }
        if frozen_state == "identical_retransmit":
            response["note"] = ("identical retransmission: returning the "
                                "existing frozen conclusion")
        if frozen_state == "conflict":
            response["conflict"] = envelope["conflict"]
            response["note"] = ("content changed under the same audit "
                                "identifier; original evidence preserved")
        self._send_json(status, response)


def main():
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"frost countersigning verifier listening on {host}:{port}",
          flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
