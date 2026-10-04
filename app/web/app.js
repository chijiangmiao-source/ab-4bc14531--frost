/* 核验台前端：所有字段均经真实 /api/v1 接口提交与渲染，无任何桩数据。 */
"use strict";

const $ = (id) => document.getElementById(id);

function hexFields() {
  return ["public_share", "commitment_d", "commitment_e", "signature_share"];
}

function addParticipant(data = {}) {
  const box = $("participants");
  const idx = box.children.length;
  const card = document.createElement("div");
  card.className = "participant";
  card.dataset.idx = String(idx);
  card.innerHTML = `
    <div class="phead">
      <strong>参与者 ${idx + 1}</strong>
      <button type="button" class="del">移除</button>
    </div>
    <div class="grid">
      <label>标识 identifier（32B 小端标量）
        <input class="mono f-identifier" spellcheck="false" />
      </label>
      <label>公钥份额 public_share（点）
        <input class="mono f-public_share" spellcheck="false" />
      </label>
      <label>双随机承诺 D
        <input class="mono f-commitment_d" spellcheck="false" />
      </label>
      <label>双随机承诺 E
        <input class="mono f-commitment_e" spellcheck="false" />
      </label>
      <label class="span2">签名份额 signature_share（标量）
        <input class="mono f-signature_share" spellcheck="false" />
      </label>
    </div>`;
  card.querySelector(".del").addEventListener("click", () => {
    card.remove();
    renumber();
  });
  box.appendChild(card);
  for (const f of ["identifier", ...hexFields()]) {
    const inp = card.querySelector(`.f-${f}`);
    inp.value = data[f] ? String(data[f]) : "";
  }
}

function renumber() {
  [...$("participants").children].forEach((c, i) => {
    c.querySelector("strong").textContent = `参与者 ${i + 1}`;
  });
}

function fillPackage(pkg) {
  $("threshold").value = pkg.threshold;
  $("group_pk").value = pkg.group_public_key;
  $("message").value = bytesToText(pkg.message);
  $("participants").innerHTML = "";
  for (const p of pkg.participants) addParticipant(p);
  $("agg_commitment").value = pkg.aggregate_signature.commitment;
  $("agg_response").value = pkg.aggregate_signature.response;
}

function bytesToText(hex) {
  try {
    const bytes = new Uint8Array(hex.match(/../g).map((h) => parseInt(h, 16)));
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (_e) {
    return "";
  }
}

function collectPackage() {
  const participants = [...$("participants").children].map((card) => {
    const row = {};
    for (const f of ["identifier", ...hexFields()]) {
      row[f] = card.querySelector(`.f-${f}`).value.trim().toLowerCase();
    }
    return row;
  });
  return {
    message_text: $("message").value,
    threshold: Number($("threshold").value),
    group_public_key: $("group_pk").value.trim().toLowerCase(),
    participants,
    aggregate_signature: {
      commitment: $("agg_commitment").value.trim().toLowerCase(),
      response: $("agg_response").value.trim().toLowerCase(),
    },
  };
}

function flash(kind, html) {
  const panel = $("result_panel");
  panel.hidden = false;
  let el = panel.querySelector(".flash");
  if (!el) {
    el = document.createElement("div");
    el.className = "flash";
    panel.prepend(el);
  }
  el.className = `flash ${kind}`;
  el.innerHTML = html;
}

function short(h, n = 22) {
  return h && h.length > n * 2 ? h.slice(0, n) + "…" + h.slice(-10) : h || "—";
}

function renderResult(data) {
  const r = data.result;
  const panel = $("result_panel");
  panel.hidden = false;
  const existingFlash = panel.querySelector(".flash");
  if (existingFlash) existingFlash.remove();

  const verdict = $("verdict");
  if (r.structural_rejection) {
    verdict.innerHTML = `<span class="badge bad">拒绝（结构/编码不合规）</span>`;
  } else if (r.accepted) {
    verdict.innerHTML = `<span class="badge ok">接受 · 会签有效</span>`;
  } else {
    verdict.innerHTML = `<span class="badge bad">拒绝 · 密码方程失败</span>`;
  }

  const reused = data.reused_existing_conclusion
    ? `<span class="badge warn">既有冻结结论（相同载荷重传，未重算）</span>`
    : `<span class="badge ok">新结论已冻结</span>`;

  const conflictNote = (data.conflicts && data.conflicts.length)
    ? `<div class="flash conflict">该审计标识曾发生 <b>${data.conflicts.length}</b> 次内容冲突提交，原始证据始终保留未被覆盖。</div>`
    : "";

  $("meta").innerHTML = `
    <div class="kv"><span>审计标识</span><span>${data.audit_id}</span></div>
    <div class="kv"><span>载荷 SHA-256</span><span class="hex">${data.content_hash}</span></div>
    <div class="kv"><span>结论状态</span><span>${reused}</span></div>
    <div class="kv"><span>冻结时间 (UTC)</span><span>${data.created_at}</span></div>
    ${data.structural_error ? `<div class="kv"><span>结构拒绝原因</span><span>${data.structural_error}</span></div>` : ""}
    ${conflictNote}`;

  const tbody = $("shares_table").querySelector("tbody");
  tbody.innerHTML = "";
  if (r.participants) {
    for (const s of r.participants) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${s.index + 1}</td>
        <td class="hex">${s.identifier}</td>
        <td>${s.accepted
          ? '<span class="badge ok">通过</span>'
          : '<span class="badge bad">失败</span>'}</td>
        <td class="hex">${short(s.binding_factor)}</td>
        <td class="hex">${short(s.lagrange_coefficient)}</td>
        <td class="hex">${s.residual}</td>
        <td>${s.detail || "G<sup>sᵢ</sup> = Dᵢ·Eᵢ<sup>ρᵢ</sup>·PKᵢ<sup>cλᵢ</sup> 成立"}</td>`;
      if (!s.accepted) tr.style.background = "rgba(255,107,107,.07)";
      tbody.appendChild(tr);
    }
  }

  if (r.aggregate) {
    const a = r.aggregate;
    const order = (r.stable_order || []).map((x) => x.slice(0, 8) + "…").join(" → ");
    $("aggregate").innerHTML = `
      <div class="kv"><span>稳定顺序（标识升序）</span><span class="hex">${order || "—"}</span></div>
      <div class="kv"><span>群承诺 R（由完整承诺集派生）</span><span class="hex">${r.group_commitment || "—"}</span></div>
      <div class="kv"><span>挑战 c = H2(m,[R,PK])</span><span class="hex">${short(r.challenge)}</span></div>
      <div class="kv"><span>z = Σ sᵢ 校验</span><span>${a.response_matches_sum_of_shares
        ? '<span class="badge ok">一致</span>'
        : '<span class="badge bad">不一致（拼接）</span>'}</span></div>
      <div class="kv"><span>G<sup>z</sup> = R·PK<sup>c</sup></span><span>${a.accepted
        ? '<span class="badge ok">成立</span>'
        : '<span class="badge bad">不成立</span>'}</span></div>
      <div class="kv"><span>聚合残差 LHS−RHS</span><span class="hex">${a.residual}</span></div>`;
  } else {
    $("aggregate").innerHTML = `<p class="hint">结构拒绝，未进入聚合核对。</p>`;
  }

  const reasons = (r.reasons || []).map((x) => `• ${x}`).join("\n");
  const firstFail = r.first_failed_identifier
    ? `首个失败份额标识：${r.first_failed_identifier}`
    : "首个失败份额：无";
  $("raw_json").textContent =
    JSON.stringify(r, null, 2) + `\n\n拒绝定位：${firstFail}\n${reasons}`;
}

async function submit() {
  const body = { audit_id: $("audit_id").value.trim(), package: collectPackage() };
  try {
    const resp = await fetch("/api/v1/countersign/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    if (resp.status === 409) {
      $("result_panel").hidden = false;
      flash(
        "conflict",
        `<b>内容冲突，拒绝覆盖原始证据。</b> ${data.error}<br>` +
          `变化字段：<span class="hex">${JSON.stringify(data.changed)}</span><br>` +
          `原始载荷哈希：<span class="hex">${data.existing.content_hash}</span>，` +
          `新载荷哈希：<span class="hex">${data.incoming_hash}</span>`
      );
      return;
    }
    if (!resp.ok) {
      flash("err", `<b>请求被拒绝：</b> ${data.error || resp.status}`);
      return;
    }
    renderResult(data);
  } catch (e) {
    flash("err", `<b>请求失败：</b> ${e.message}`);
  }
}

async function checkHealth() {
  try {
    const r = await fetch("/healthz");
    const j = await r.json();
    const el = $("health");
    el.textContent = `● ${j.status} · v${j.version}`;
    el.className = "health ok";
  } catch (_e) {
    const el = $("health");
    el.textContent = "● 服务不可用";
    el.className = "health bad";
  }
}

$("add_btn").addEventListener("click", () => addParticipant());
$("clear_btn").addEventListener("click", () => {
  $("participants").innerHTML = "";
});
$("sample_btn").addEventListener("click", async () => {
  const r = await fetch("/api/v1/sample-package");
  const j = await r.json();
  fillPackage(j.package);
});
$("submit_btn").addEventListener("click", submit);

addParticipant();
checkHealth();
