"""端到端冒烟验收：在临时端口启动真实 HTTP 服务，经真实接口验证。

覆盖：
  * 健康响应、页面与静态资源；
  * 有效会签包被接受、证据冻结；
  * 完全相同重传返回既有冻结结论（reused_existing_conclusion）；
  * 消息/内容变化以 409 冲突返回且原始证据不被覆盖；
  * 篡改签名份额被拒绝且 first_failed_identifier 精确指向失败份额，
    并返回逐参与者方程残差与聚合证据；
  * 结构非法（9 名参与者）返回 400；
  * 证据读取接口可用。
"""

from __future__ import annotations

import copy
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


class CheckFailed(AssertionError):
    pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _request(method: str, url: str, payload: dict | None = None, timeout: int = 10):
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            return resp.status, ctype, body
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", ""), exc.read()


def _wait_healthy(base: str, proc: subprocess.Popen, seconds: float = 15.0) -> None:
    deadline = time.time() + seconds
    last = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise CheckFailed(f"服务进程提前退出，退出码 {proc.returncode}；最后错误：{last}")
        try:
            status, _, body = _request("GET", base + "/healthz", timeout=2)
            if status == 200:
                j = json.loads(body)
                if j.get("status") == "ok":
                    return
        except Exception as exc:  # noqa: BLE001 - 启动轮询
            last = repr(exc)
        time.sleep(0.25)
    raise CheckFailed(f"健康检查在 {seconds}s 内未就绪：{last}")


def _post_verify(base, audit_id, pkg):
    return _request(
        "POST",
        base + "/api/v1/countersign/verify",
        {"audit_id": audit_id, "package": pkg},
    )


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise CheckFailed(msg)


def run() -> tuple[bool, list[str]]:
    log: list[str] = []
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    tmpdir = tempfile.mkdtemp(prefix="frost-smoke-")
    db = os.path.join(tmpdir, "evidence.json")
    env = {
        **os.environ,
        "HOST": "127.0.0.1",
        "PORT": str(port),
        "EVIDENCE_DB": db,
        "FROST_DESK_QUIET": "1",
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "app.server"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_healthy(base, proc)
        log.append(f"健康响应 OK（GET /healthz -> 200，端口 {port} 可配置）")

        # 页面与静态资源。
        status, ctype, body = _request("GET", base + "/")
        _assert(status == 200 and "离线机动指令会签核验台".encode() in body, "核验台页面异常")
        _assert(b"/static/app.js" in body, "页面未引用真实前端脚本")
        log.append("核验台页面 OK（经真实服务渲染）")
        for path, needle in (
            ("/static/app.js", b"/api/v1/countersign/verify"),
            ("/static/style.css", b".badge"),
        ):
            status, _, body = _request("GET", base + path)
            _assert(status == 200 and needle in body, f"静态资源 {path} 异常")
        log.append("静态资源 app.js / style.css OK")

        # 样例会签包来自服务端密码模块（真实接口）。
        status, _, body = _request("GET", base + "/api/v1/sample-package")
        _assert(status == 200, "样例会签包接口异常")
        valid_pkg = json.loads(body)["package"]
        log.append("样例会签包接口 OK")

        # 1) 有效会签包被接受并冻结。
        audit_ok = "SMOKE/2026/VALID-001"
        status, _, body = _post_verify(base, audit_ok, valid_pkg)
        _assert(status == 200, f"有效包提交失败：{body[:200]!r}")
        r1 = json.loads(body)
        _assert(r1["result"]["accepted"] is True, "有效包未被接受")
        _assert(r1["frozen"] is True, "结论未冻结")
        _assert(
            [p["accepted"] for p in r1["result"]["participants"]] == [True] * 3,
            "逐份额结论应全部通过",
        )
        _assert(r1["result"]["aggregate"]["accepted"] is True, "聚合证据应成立")
        _assert(
            r1["result"]["aggregate"]["response_matches_sum_of_shares"] is True,
            "z 应等于份额之和",
        )
        _assert(
            [p["identifier"] for p in r1["result"]["participants"]]
            == sorted(p["identifier"] for p in r1["result"]["participants"]),
            "参与者顺序必须稳定（标识升序）",
        )
        log.append(
            "有效会签：3/3 份额通过，G^z=R·PK^c 成立，稳定顺序与聚合证据齐全"
        )

        # 2) 完全相同重传 -> 既有冻结结论。
        status, _, body = _post_verify(base, audit_ok, copy.deepcopy(valid_pkg))
        _assert(status == 200, f"重传失败：{body[:200]!r}")
        r2 = json.loads(body)
        _assert(r2["reused_existing_conclusion"] is True, "重传应复用冻结结论")
        _assert(
            r2["created_at"] == r1["created_at"]
            and r2["content_hash"] == r1["content_hash"],
            "冻结时间/内容哈希必须保持不变",
        )
        log.append("相同 audit_id + 相同载荷重传：返回既有冻结结论（未重算）")

        # 3) 消息变化 -> 409 冲突，原始证据保留。
        changed_msg = copy.deepcopy(valid_pkg)
        changed_msg["message"] = b"EMERGENCY: unscheduled delta-v".hex()
        status, _, body = _post_verify(base, audit_ok, changed_msg)
        _assert(status == 409, f"消息变化应冲突 409，实际 {status}")
        conflict = json.loads(body)
        _assert(conflict["conflict"] is True, "冲突标记缺失")
        _assert("message" in conflict["changed"]["top_level"], "未定位到 message 变化")
        _assert(
            conflict["existing"]["result"]["accepted"] is True,
            "原始接受结论必须保留",
        )
        log.append("消息变化：409 冲突，明确指出 message 变化，原始证据未覆盖")

        # 4) 冲突后再重传原包，仍是冻结的接受结论。
        status, _, body = _post_verify(base, audit_ok, copy.deepcopy(valid_pkg))
        r3 = json.loads(body)
        _assert(
            status == 200
            and r3["reused_existing_conclusion"]
            and r3["result"]["accepted"],
            "冲突登记后原包重传仍须返回原始接受结论",
        )
        _assert(len(r3["conflicts"]) == 1, "冲突应被登记在原始证据上")
        log.append("冲突登记后原包重传：冻结结论不变，冲突计数=1")

        # 5) 篡改第 2 名参与者的签名份额 -> 拒绝并精确定位。
        bad_pkg = copy.deepcopy(valid_pkg)
        target = bad_pkg["participants"][1]
        target_id = target["identifier"]
        s = int(target["signature_share"], 16)
        from app.frost import L

        target["signature_share"] = ((s + 1) % L).to_bytes(32, "little").hex()
        status, _, body = _post_verify(base, "SMOKE/2026/TAMPER-SHARE", bad_pkg)
        _assert(status == 200, f"篡改份额应返回 200+拒绝结论，实际 {status} {body[:150]!r}")
        r4 = json.loads(body)
        res = r4["result"]
        _assert(res["accepted"] is False, "篡改份额必须拒绝")
        _assert(
            res["first_failed_identifier"] == target_id,
            f"首个失败份额应定位到 {target_id}，实际 {res['first_failed_identifier']}",
        )
        failed = [p for p in res["participants"] if not p["accepted"]]
        _assert(len(failed) == 1 and failed[0]["identifier"] == target_id, "失败份额定位错误")
        _assert(failed[0]["residual"] and failed[0]["residual"] != failed[0]["rhs"], "残差摘要缺失")
        _assert("residual" in res["aggregate"], "聚合残差缺失")
        log.append(
            f"篡改份额：拒绝，首个失败份额精确锁定 {target_id}，返回方程残差与聚合证据"
        )

        # 6) 承诺拼接 -> 拒绝。
        splice = copy.deepcopy(valid_pkg)
        donor_status, _, donor_body = _request("GET", base + "/api/v1/sample-package")
        donor = json.loads(donor_body)["package"]
        splice["participants"][0]["commitment_d"] = donor["participants"][1]["commitment_d"]
        status, _, body = _post_verify(base, "SMOKE/2026/SPLICE", splice)
        r5 = json.loads(body)
        _assert(status == 200 and r5["result"]["accepted"] is False, "承诺拼接必须拒绝")
        log.append("跨会签承诺拼接：拒绝（绑定因子由完整承诺集计算）")

        # 7) 结构非法（9 名参与者）-> 200 冻结的结构拒绝结论。
        too_many = copy.deepcopy(valid_pkg)
        while len(too_many["participants"]) < 9:
            too_many["participants"].append(copy.deepcopy(too_many["participants"][0]))
        status, _, body = _post_verify(base, "SMOKE/2026/NINE", too_many)
        j9 = json.loads(body)
        _assert(
            status == 200
            and j9["result"].get("structural_rejection") is True
            and "参与者数量 9 超过上限 8" in (j9.get("structural_error") or ""),
            "9 名参与者应冻结为结构拒绝",
        )
        log.append("9 名参与者（>8）：结构拒绝结论已冻结并附原因")

        # 7b) 请求本身非法（audit_id 不合法）-> 400。
        status, _, body = _post_verify(base, "bad id with space", valid_pkg)
        _assert(status == 400, f"非法 audit_id 应 400，实际 {status}")
        log.append("非法审计标识：HTTP 400 拒绝")

        # 8) 证据读取接口。
        status, _, body = _request("GET", base + "/api/v1/evidence")
        listing = json.loads(body)
        _assert(audit_ok in listing["audit_ids"], "证据列表缺少冻结标识")
        status, _, body = _request(
            "GET", base + "/api/v1/evidence/" + urllib.request.quote(audit_ok, safe="")
        )
        _assert(status == 200, "证据详情接口异常")
        record = json.loads(body)["record"]
        _assert(record["audit_id"] == audit_ok and record["result"]["accepted"], "冻结证据内容不符")
        log.append("证据接口 OK：列表与冻结详情可读，重启持久化由单测覆盖")

        return True, log
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    ok, lines = run()
    for line in lines:
        print("  -", line)
    print("SMOKE", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)
