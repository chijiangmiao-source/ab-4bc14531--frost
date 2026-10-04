# 深空编队 · 离线会签机动指令核验台

基于 [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591) **FROST(Ed25519, SHA-512)**
ciphersuite 的离线双随机承诺阈值会签核验服务。聚合器提交会签包后，核验台独立
重算绑定因子、挑战与群承诺，先逐份验证签名份额、再核对聚合签名，并把结论按
稳定审计标识冻结为证据；审查员通过浏览器页面查看稳定参与者顺序、逐份结论与
聚合证据。

## 它防范什么

聚合器（或注入者）若把**不同参与者的份额、不同承诺或不同消息的片段**拼接成
"表面有效"的签名，以下检查会逐项暴露：

| 攻击面 | 核验手段 |
| --- | --- |
| 份额所属关系 / message-binding | 每份份额满足 `[z_i]B = comm_share_i + [c·λ_i]PK_i`，其中 `c` 由**原始消息**与**完整承诺集**经 H2 计算 |
| 承诺拼接 | 提交的 R 必须等于从完整双随机承诺集重算的群承诺 `Σ(H_i + [ρ_i]E_i)` |
| 份额/聚合拼接 | 提交的 z 必须等于所有已提交签名份额之和 `Σz_i` |
| 杂凑/低阶点 | 严格 RFC 8032 解码 + `[L]P = I` 素阶子群校验 |
| 拼包重放 | 同审计标识内容变化 => HTTP 409 冲突，原始证据永不覆盖 |

## 密码学口径（RFC 9591 §6.1）

* 群：edwards25519，`Ne = Ns = 32`，余因子 8；标量 32 字节小端，最高 3 位必须为零且 `< L`。
* `H1 = SHA-512(contextString‖"rho"‖m) mod L` — 绑定因子
* `H2 = SHA-512(m) mod L` — 挑战（为兼容 RFC 8032 省略域分隔）
* `H4 = SHA-512(contextString‖"msg"‖m)`，`H5 = SHA-512(contextString‖"com"‖m)`
* 绑定因子输入：`PK ‖ H4(msg) ‖ H5(承诺集编码) ‖ id`
* 挑战输入：`R ‖ PK ‖ msg`
* 聚合核对方程（强制余因子方程）：`[8]zB = [8]R + [8]cPK`

`contextString = "FROST-ED25519-SHA512-v1"`。实现经 **RFC 9591 附录 E.1 官方向量对拍**
（t=2/n=3，P1+P3，消息 "test"），绑定因子、群承诺、两份份额、聚合 z 与方程全部一致。

## 会签包格式

```json
{
  "audit_id": "AUDIT-...",
  "message": "MANEUVER-ORDER: ...",
  "message_hex": "可选；与 message 同时提交时必须一致",
  "group_public_key": "<32B hex>",
  "threshold": 2,
  "participants": [
    {"identifier": "<32B LE scalar hex>",
     "public_key_share": "<32B point hex>",
     "hiding_commitment": "<32B point hex>",
     "binding_commitment": "<32B point hex>",
     "signature_share" : "<32B LE scalar hex>"}
  ],
  "aggregate_signature": {"R": "<32B hex>", "z": "<32B hex>"}
}
```

参与者至多 8 名，数量必须等于阈值，标识不得重复。

## 运行

```bash
# 直接运行（仅需 Python 3.11+，无第三方依赖）
python3 -m app.server                       # 默认 0.0.0.0:8080
PORT=9090 HOST=127.0.0.1 python3 -m app.server

# Docker Compose（宿主端口可配置）
HOST_PORT=9090 docker compose up --build -d
curl http://localhost:9090/healthz
```

页面入口 `GET /`；示例包可经 `GET /api/demo-package`（加 `&tamper=share_add_one`
可取篡改样例）获取。

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET  | `/healthz` | 健康响应 |
| GET  | `/` | 核验台页面 |
| POST | `/api/verify` | 核验会签包并冻结结论 |
| GET  | `/api/evidence` | 已冻结结论列表 |
| GET  | `/api/evidence/{audit_id}` | 取某审计标识的冻结结论（含冲突记录） |
| GET  | `/api/demo-package` | 生成有效/篡改示例包 |

### 冻结语义

* **首次**：核验后以 `audit_id` 冻结，记录包摘要与结论指纹；
* **完全相同重传**：返回 `frozen_state=identical_retransmit` 与既有结论，证据不变；
* **同标识内容变化**（消息、承诺、任何字段不同）：返回 **409 conflict**，
  冲突记入原记录，**原始证据永不被覆盖**，后续仍只返回原始冻结结论。

## 拒绝规则（均返回 REJECTED 并给出参与者定位与方程残差摘要）

非规范标量、不可解码点/非素阶子群点、重复标识、阈值不符、超 8 人、
首个失败份额（`first_failed_participant`，按标识升序评估）、承诺拼接、
z 拼接、消息变化、聚合余因子方程不成立。

## 一次性验收服务 `verify`

```bash
./verify
```

执行后退出，以退出码报告三阶段结果（0 = 全部通过）：

1. **密码规则代码测试** —— 官方向量对拍 + 上述全部拒绝规则 + 失败份额定位；
2. **API/HTTP 冒烟** —— 启动真实服务，对有效包、篡改份额、相同重传冻结、
   内容冲突 409、页面与静态资源、错误 JSON、404 进行端到端检查；
3. **镜像/构建检查** —— 有 docker/podman 时真实构建镜像并起容器验健康；
   无运行时执行等价离线检查（Dockerfile/compose 契约 + 字节码编译）。

## 目录

```
app/frost9591.py   edwards25519 + RFC 9591 哈希族与验证原语（纯标准库）
app/verifier.py    结构规则、逐份验证、聚合核对与残差证据
app/fixtures.py    仅供测试/演示的造包与篡改工具（产品不持有秘密份额）
app/store.py       仅追加冻结证据库（JSON）
app/server.py      HTTP API + 页面服务（标准库）
web/               核验台页面
tests/             RFC 9591 官方向量对拍
scripts/verify     一次性验收入口
```
