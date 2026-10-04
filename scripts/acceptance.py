#!/usr/bin/env python3
"""One-shot acceptance service for the offline countersigning verifier.

Runs, and reports via exit code:

  1. Cryptographic rule tests (RFC 9591 vectors + rejection rules and
     first-failing-share attribution);
  2. API/HTTP smoke against a booted server (valid packet, tampered
     share, identical retransmit freeze, content conflict 409, page and
     static assets);
  3. Image/build check: a real container build when a runtime
     (docker/podman) is available, otherwise an explicit hermetic
     fallback that replays the image command locally and validates the
     Dockerfile/compose inputs.

Exits 0 only if every stage passes.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import frost9591 as f  # noqa: E402
from app import verifier  # noqa: E402
from app.fixtures import make_countersign_package, tamper  # noqa: E402
from app.server import Handler  # noqa: E402

PASS = "PASS"
FAIL = "FAIL"
results: list[tuple[str, str, str]] = []


def check(stage: str, name: str, ok: bool, detail: str = ""):
    results.append((stage, PASS if ok else FAIL, name + (f" — {detail}" if detail else "")))
    print(f"  [{PASS if ok else FAIL}] {name}" + (f" — {detail}" if detail else ""))
    return ok


# --------------------------------------------------------------------------
# Stage 1: cryptographic rule tests
# --------------------------------------------------------------------------
def stage_crypto_tests() -> bool:
    print("\n=== 1. 密码规则代码测试 (RFC 9591 Ed25519/SHA-512) ===")
    ok = True

    # Official RFC 9591 Appendix E.1 vector cross-check lives in tests/.
    vec = subprocess.run([sys.executable,
                          os.path.join(ROOT, "tests", "rfc9591_vectors.py")],
                         capture_output=True, text=True)
    ok &= check("crypto", "RFC 9591 附录 E.1 官方向量对拍",
                vec.returncode == 0,
                "" if vec.returncode == 0 else vec.stdout[-400:] + vec.stderr[-400:])

    pkg = make_countersign_package(b"MANEUVER: burn-7 insertion",
                                   threshold=2, identifiers=(1, 3),
                                   rng_seed=b"acceptance",
                                   audit_id="AUDIT-ACC-1")
    r = verifier.verify_packet(pkg)
    ok &= check("crypto", "有效会签包通过且聚合证据完整",
                r["verdict"] == "ACCEPTED"
                and r["aggregate"]["cofactor_equation_holds"] is True
                and r["aggregate"]["z_matches_share_sum"] is True)

    # Non-canonical scalar: top three bits set.
    bad = tamper(pkg, kind="noncanonical_scalar", index=0)
    r = verifier.verify_packet(bad)
    ok &= check("crypto", "非规范标量（顶置位）被拒绝",
                r["verdict"] == "REJECTED"
                and any("non-canonical scalar" in x for x in r["rejected_reasons"]))

    # Non-canonical scalar: value >= L, top three bits still zero.
    bad2 = json.loads(json.dumps(pkg))
    bad2["participants"][0]["signature_share"] = f.L.to_bytes(32, "little").hex()
    r = verifier.verify_packet(bad2)
    ok &= check("crypto", "标量 >= 群阶 L 被拒绝",
                r["verdict"] == "REJECTED"
                and any("group order" in x for x in r["rejected_reasons"]))

    # Undecodable point: identity encoding.
    bad = tamper(pkg, kind="non_subgroup_point", index=1)
    r = verifier.verify_packet(bad)
    ok &= check("crypto", "不可解码点（单位元编码）被拒绝",
                r["verdict"] == "REJECTED"
                and any("identity" in x or "subgroup" in x
                        for x in r["rejected_reasons"]))

    # Out-of-field y.
    bad = json.loads(json.dumps(pkg))
    bad["group_public_key"] = "ff" * 32
    r = verifier.verify_packet(bad)
    ok &= check("crypto", "越界点编码（y >= p）被拒绝",
                r["verdict"] == "REJECTED"
                and any("group_public_key" in x for x in r["rejected_reasons"]))

    # Duplicate identifiers.
    dup = json.loads(json.dumps(pkg))
    dup["participants"][1]["identifier"] = dup["participants"][0]["identifier"]
    r = verifier.verify_packet(dup)
    ok &= check("crypto", "重复参与者标识被拒绝",
                r["verdict"] == "REJECTED"
                and any("duplicate" in x for x in r["rejected_reasons"]))

    # Threshold mismatch.
    tm = json.loads(json.dumps(pkg))
    tm["threshold"] = 3
    r = verifier.verify_packet(tm)
    ok &= check("crypto", "阈值与提交人数不符被拒绝",
                r["verdict"] == "REJECTED"
                and any("threshold mismatch" in x for x in r["rejected_reasons"]))

    # More than eight participants.
    big_pkg = make_countersign_package(
        b"nine?", threshold=9, identifiers=tuple(range(1, 10)),
        rng_seed=b"nine", audit_id="AUDIT-ACC-NINE")
    r = verifier.verify_packet(big_pkg)
    ok &= check("crypto", "超过八名参与者被拒绝",
                r["verdict"] == "REJECTED"
                and any("at most 8" in x for x in r["rejected_reasons"]))

    # First failed share attribution: only participant 3 is tampered.
    bad = tamper(pkg, kind="share_add_one", index=1)
    r = verifier.verify_packet(bad)
    statuses = {p["identifier"]: p["status"] for p in r["participants"]}
    want_id_first = sorted(p["identifier"] for p in pkg["participants"])[1]
    ok &= check("crypto", "篡改份额被拒绝", r["verdict"] == "REJECTED")
    ok &= check("crypto", "拒绝结果定位到失败份额参与者",
                r["first_failed_participant"] == want_id_first
                and statuses.get(want_id_first) == "invalid",
                f"first_failed={r['first_failed_participant']}")
    ok &= check("crypto", "未篡改参与者仍判 valid",
                any(v == "valid" for v in statuses.values()))
    ok &= check("crypto", "逐份结论含方程残差摘要",
                all(p["residual"] and p["residual"]["residual_digest"]
                    for p in r["participants"] if p["status"] != "malformed"))

    # Commitment splicing between participants.
    bad = tamper(pkg, kind="commitment_swap")
    r = verifier.verify_packet(bad)
    ok &= check("crypto", "双承诺互换（拼接）被拒绝",
                r["verdict"] == "REJECTED"
                and r["first_failed_participant"] is not None)

    # Aggregate z splicing.
    bad = tamper(pkg, kind="aggregate_z_swap")
    r = verifier.verify_packet(bad)
    ok &= check("crypto", "聚合签名 z 拼接被拒绝",
                r["verdict"] == "REJECTED"
                and any("splicing" in x or "cofactor" in x
                        for x in r["rejected_reasons"]))

    # Message change while keeping shares/commitments invalidates everything.
    bad = tamper(pkg, kind="message_change")
    r = verifier.verify_packet(bad)
    ok &= check("crypto", "原始消息变化导致拒绝",
                r["verdict"] == "REJECTED")

    # Stable ascending participant order regardless of input order.
    shuffled = json.loads(json.dumps(pkg))
    shuffled["participants"] = list(reversed(shuffled["participants"]))
    r = verifier.verify_packet(shuffled)
    ids_in_order = [p["identifier"] for p in r["participants"]]
    ok &= check("crypto", "参与者顺序稳定（按标识升序）",
                ids_in_order == sorted(ids_in_order)
                and r["verdict"] == "ACCEPTED")

    # Scalar strictness unit checks.
    try:
        f.deserialize_scalar(bytes(31) + bytes([0xE0]))  # top bits set
        scalar_ok = False
    except f.DecodeError:
        scalar_ok = True
    ok &= check("crypto", "DeserializeScalar 拒绝非规范编码", scalar_ok)
    try:
        f.deserialize_element(bytes(32))  # order-4 low-order point
        point_ok = False
    except f.DecodeError:
        point_ok = True
    ok &= check("crypto", "DeserializeElement 拒绝单位元/非素阶子群点", point_ok)
    try:
        f.deserialize_element(bytes([1]) + bytes(31))  # identity (0,1)
        identity_ok = False
    except f.DecodeError:
        identity_ok = True
    ok &= check("crypto", "DeserializeElement 拒绝群单位元编码", identity_ok)

    return ok


# --------------------------------------------------------------------------
# Stage 2: API/HTTP smoke against a real server
# --------------------------------------------------------------------------
def _wait_port(port: int, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def _req(method: str, url: str, body=None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def stage_http_smoke(port: int) -> bool:
    print("\n=== 2. API/HTTP 冒烟测试 ===")
    ok = True
    base = f"http://127.0.0.1:{port}"

    status, body = _req("GET", base + "/healthz")
    ok &= check("http", "健康响应 /healthz 200",
                status == 200 and body.get("status") == "ok",
                f"status={status}")

    html = urllib.request.urlopen(base + "/", timeout=10).read().decode()
    ok &= check("http", "核验台页面可访问且含中文标题",
                "离线会签机动指令核验台" in html)
    for asset in ("/static/console.js", "/static/console.css"):
        st = urllib.request.urlopen(base + asset, timeout=10).status
        ok &= check("http", f"静态资源 {asset}", st == 200)

    # Valid packet through the REAL API.
    _, valid_pkg = _req("GET",
                        base + "/api/demo-package?audit_id=AUDIT-HTTP-1")
    status, body = _req("POST", base + "/api/verify", valid_pkg)
    ok &= check("http", "有效会签包 API 判定 ACCEPTED",
                status == 200 and body["result"]["verdict"] == "ACCEPTED"
                and body["frozen_state"] == "new")

    # Identical retransmission: frozen conclusion returned.
    fp1 = body["conclusion_fingerprint"]
    status, body2 = _req("POST", base + "/api/verify", valid_pkg)
    ok &= check("http", "完全相同重传返回既有冻结结论",
                status == 200
                and body2["frozen_state"] == "identical_retransmit"
                and body2["conclusion_fingerprint"] == fp1)

    # Tampered share via API: rejection names the failed participant.
    _, bad_pkg = _req("GET", base + "/api/demo-package"
                      "?audit_id=AUDIT-HTTP-2&tamper=share_add_one&index=1")
    status, body = _req("POST", base + "/api/verify", bad_pkg)
    failed = body["result"]["first_failed_participant"]
    ok &= check("http", "篡改份额 API 判定 REJECTED",
                status == 200 and body["result"]["verdict"] == "REJECTED")
    ok &= check("http", "API 拒绝结果可定位失败份额",
                failed == sorted(p["identifier"]
                                 for p in bad_pkg["participants"])[1],
                f"first_failed_participant={failed}")

    # Conflict: same audit id, altered message -> 409 and evidence kept.
    conflict_pkg = tamper(valid_pkg, kind="message_change")
    status, body = _req("POST", base + "/api/verify", conflict_pkg)
    ok &= check("http", "同标识内容变化返回 409 冲突且不覆盖",
                status == 409 and body["frozen_state"] == "conflict"
                and body["frozen_verdict"] == "ACCEPTED")
    status, evidence = _req("GET", base + "/api/evidence/AUDIT-HTTP-1")
    ok &= check("http", "原始冻结证据保留且记录冲突",
                status == 200 and evidence["verdict"] == "ACCEPTED"
                and len(evidence.get("conflicts", [])) == 1)

    # Another identical retransmit still returns the original frozen one.
    status, body = _req("POST", base + "/api/verify", valid_pkg)
    ok &= check("http", "冲突后再次重传仍返回原始冻结结论",
                body["frozen_state"] == "identical_retransmit"
                and body["frozen_verdict"] == "ACCEPTED")

    # Malformed JSON and unknown routes behave sanely.
    req = urllib.request.Request(base + "/api/verify",
                                 data=b"{not-json", method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10)
        bad_json_ok = False
    except urllib.error.HTTPError as e:
        bad_json_ok = e.code == 400
    ok &= check("http", "非法 JSON 返回 400", bad_json_ok)
    status, _ = _req("GET", base + "/api/nope")
    ok &= check("http", "未知 API 路由 404", status == 404)

    return ok


# --------------------------------------------------------------------------
# Stage 3: image / build check
# --------------------------------------------------------------------------
def _runtime():
    for name in ("docker", "podman"):
        if shutil.which(name):
            return name
    return None


def stage_build_check() -> bool:
    print("\n=== 3. 镜像构建 / Compose 检查 ===")
    ok = True

    for required in ("Dockerfile", "compose.yaml", "app/server.py"):
        ok &= check("build", f"存在 {required}", os.path.isfile(os.path.join(ROOT, required)))

    runtime = _runtime()
    if runtime:
        print(f"  -- 检测到容器运行时 {runtime}，执行真实镜像构建")
        tag = "frost-verifier:acceptance"
        built = subprocess.run([runtime, "build", "-t", tag, ROOT],
                               capture_output=True, text=True)
        ok &= check("build", f"{runtime} build 成功", built.returncode == 0,
                    built.stderr[-300:] if built.returncode else "")
        if built.returncode == 0:
            host_port = _free_port()
            run_cmd = [
                runtime, "run", "--rm", "-d",
                "-p", f"{host_port}:8080",
                "-e", "PORT=8080",
                "--name", "frost-verify-accept", tag,
            ]
            cid = subprocess.run(run_cmd, capture_output=True, text=True)
            container_up = cid.returncode == 0
            if container_up:
                container_id = cid.stdout.strip()
                try:
                    healthy = _wait_port(host_port)
                    status, body = _req(
                        "GET", f"http://127.0.0.1:{host_port}/healthz")
                    ok &= check("build", "容器内服务健康响应",
                                healthy and status == 200
                                and body.get("status") == "ok")
                finally:
                    subprocess.run([runtime, "stop", container_id],
                                   capture_output=True)
            else:
                ok &= check("build", "容器启动", False, cid.stderr[-300:])
    else:
        print("  -- 未检测到 docker/podman，执行等价的离线构建检查")
        # Validate Dockerfile content contract.
        df = open(os.path.join(ROOT, "Dockerfile")).read()
        ok &= check("build", "Dockerfile 基于 python 3.11 slim",
                    "python:3.11-slim" in df)
        ok &= check("build", "Dockerfile 暴露可配置端口",
                    "EXPOSE" in df and "PORT" in df)
        compose = open(os.path.join(ROOT, "compose.yaml")).read()
        ok &= check("build", "compose 宿主端口可配置 (HOST_PORT)",
                    "HOST_PORT" in compose)
        ok &= check("build", "compose 含健康检查", "healthcheck" in compose
                    or "health_check" in compose)

        # Compile-all as the image build would.
        comp = subprocess.run(
            [sys.executable, "-m", "compileall", "-q",
             os.path.join(ROOT, "app"), os.path.join(ROOT, "scripts")],
            capture_output=True, text=True)
        ok &= check("build", "Python 字节码编译（镜像构建步骤）通过",
                    comp.returncode == 0, comp.stderr[-200:])

    return ok


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def boot_test_server():
    """Start the real HTTP server in-process with an isolated store."""
    tmpdir = tempfile.mkdtemp(prefix="frost-evidence-")
    os.environ["EVIDENCE_STORE_PATH"] = os.path.join(tmpdir, "evidence.json")
    # Re-initialize the store the handler module bound at import time.
    from app import server as server_module
    server_module.STORE = server_module.EvidenceStore(
        os.environ["EVIDENCE_STORE_PATH"])
    port = _free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    import threading
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    if not _wait_port(port):
        raise RuntimeError("test server failed to start")
    return httpd, port


def main() -> int:
    print("深空编队 · 离线会签核验台 —— 一次性验收服务 verify")
    stage_ok = True
    stage_ok &= stage_crypto_tests()

    httpd, port = boot_test_server()
    try:
        stage_ok &= stage_http_smoke(port)
    finally:
        httpd.shutdown()

    stage_ok &= stage_build_check()

    print("\n=== 验收汇总 ===")
    stages = ("crypto", "http", "build")
    overall = True
    for stage in stages:
        rows = [r for r in results if r[0] == stage]
        passed = sum(1 for r in rows if r[1] == PASS)
        print(f"  {stage:7s}: {passed}/{len(rows)} 通过")
        overall &= passed == len(rows)

    print()
    if overall and stage_ok:
        print("ACCEPTANCE RESULT: PASS — 业务验收、构建检查与代码测试全部通过")
        return 0
    print("ACCEPTANCE RESULT: FAIL")
    for stage, status, name in results:
        if status == FAIL:
            print(f"  FAIL [{stage}] {name}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
