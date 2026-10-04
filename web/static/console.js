"use strict";

const HEX_RE = /^[0-9a-fA-F]{64}$/;

let rowSeq = 0;

function el(tag, attrs = {}, text) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "hidden") { if (v) node.hidden = true; }
    else node.setAttribute(k, v);
  }
  if (text !== undefined) node.textContent = text;
  return node;
}

function shortHex(s) {
  if (!s) return "—";
  return s.length > 20 ? `${s.slice(0, 20)}…` : s;
}

function newRow(p) {
  const seq = ++rowSeq;
  const row = el("div", {class: "row", "data-seq": seq});
  row.appendChild(el("div", {class: "idx"}, String(seq)));
  const fields = el("div", {class: "fields"});
  const defs = [
    ["identifier", "参与者标识"],
    ["public_key_share", "公钥份额 PK_i"],
    ["hiding_commitment", "隐藏承诺 H_i"],
    ["binding_commitment", "绑定承诺 E_i"],
    ["signature_share", "签名份额 z_i"]
  ];
  defs.forEach(([key, label]) => {
    const lab = el("label", {}, label);
    const inp = el("input", {class: "hex", spellcheck: "false", name: key,
      pattern: HEX_RE.source, required: "required"});
    if (p && p[key] !== undefined) inp.value = p[key];
    lab.appendChild(inp);
    fields.appendChild(lab);
  });
  row.appendChild(fields);
  const del = el("button", {type: "button", class: "del"}, "✕");
  del.onclick = () => row.remove();
  row.appendChild(del);
  return row;
}

function addRows(participants) {
  const box = document.getElementById("rows");
  box.innerHTML = "";
  rowSeq = 0;
  participants.forEach(p => box.appendChild(newRow(p)));
}

function collectPacket() {
  const form = document.getElementById("packetForm");
  const fd = new FormData(form);
  const participants = [];
  document.querySelectorAll("#rows .row").forEach((row, idx) => {
    const entry = {submitted_index: idx};
    row.querySelectorAll("input").forEach(inp => {
      if (inp.name && inp.value.trim() !== "") entry[inp.name] = inp.value.trim();
    });
    if (Object.keys(entry).length > 1) participants.push(entry);
  });
  return {
    audit_id: fd.get("audit_id"),
    message: fd.get("message"),
    threshold: Number(fd.get("threshold")),
    group_public_key: fd.get("group_public_key"),
    participants,
    aggregate_signature: {R: fd.get("R"), z: fd.get("z")}
  };
}

function addKV(box, k, v, full) {
  const kd = el("div", {class: full ? "full" : ""});
  kd.appendChild(el("div", {class: "k"}, k));
  kd.appendChild(el("code", {}, String(v)));
  box.appendChild(kd);
}

function addBool(box, k, v) {
  const kd = el("div");
  kd.appendChild(el("div", {class: "k"}, k));
  kd.appendChild(el("div", {class: v ? "pass-true" : "pass-false"},
    v ? "成立 ✓" : "不成立 ✗"));
  box.appendChild(kd);
}

function renderResult(resp) {
  const r = resp.result;
  const panel = document.getElementById("resultPanel");
  panel.hidden = false;
  const badge = document.getElementById("verdictBadge");
  badge.textContent = r.verdict === "ACCEPTED" ? "✔ 通过 ACCEPTED" : "✘ 拒绝 REJECTED";
  badge.className = "badge " + (r.verdict === "ACCEPTED" ? "accepted" : "rejected");

  const banner = document.getElementById("frozenBanner");
  banner.className = "banner " + resp.frozen_state;
  const stateText = {
    new: "首次提交，结论已按审计标识冻结。",
    identical_retransmit: "完全相同的会签包重传 —— 返回既有冻结结论，证据未改动。",
    conflict: "同审计标识下内容发生变化 —— 判定冲突，原始证据不被覆盖。"
  };
  banner.textContent =
    `冻结状态: ${resp.frozen_state} · ${stateText[resp.frozen_state] || ""} ` +
    `包摘要 ${resp.packet_digest.slice(0, 16)}…`;

  const reasons = document.getElementById("reasons");
  reasons.innerHTML = "";
  if (r.rejected_reasons.length) {
    reasons.appendChild(el("h3", {}, "拒绝原因 / 首个失败份额定位"));
    const ul = el("ul");
    r.rejected_reasons.forEach(x => ul.appendChild(el("li", {}, x)));
    reasons.appendChild(ul);
    if (r.first_failed_participant) {
      const note = el("p", {},
        `首个失败份额参与者: ${r.first_failed_participant}`);
      note.style.color = "var(--reject)";
      reasons.appendChild(note);
    }
  }

  const tb = document.getElementById("sharesTable").querySelector("tbody");
  tb.innerHTML = "";
  r.participants.forEach(p => {
    const tr = el("tr");
    tr.appendChild(el("td", {}, String(p.order)));
    tr.appendChild(el("td", {class: "mono"}, p.identifier));
    const st = el("td");
    st.appendChild(el("span", {class: "tag " + p.status}, p.status));
    tr.appendChild(st);
    tr.appendChild(el("td", {class: "mono"}, shortHex(p.binding_factor)));
    tr.appendChild(el("td", {class: "mono"}, shortHex(p.lagrange_lambda)));
    const resCell = el("td");
    if (p.residual) {
      resCell.appendChild(el("div", {class: "mono"}, "L=" + shortHex(p.residual.equation_left)));
      resCell.appendChild(el("div", {class: "mono"}, "R=" + shortHex(p.residual.equation_right)));
      resCell.appendChild(el("div", {class: "mono"}, "摘要 " + p.residual.residual_digest));
      resCell.appendChild(el("div", {class: p.residual.equal ? "pass-true" : "pass-false"},
        p.residual.equal ? "方程成立" : "方程不成立"));
    } else {
      resCell.textContent = "—";
    }
    tr.appendChild(resCell);
    tr.appendChild(el("td", {class: "mono"}, (p.reasons || []).join("；") || "—"));
    tb.appendChild(tr);
  });

  const agg = r.aggregate;
  const box = document.getElementById("aggBox");
  box.innerHTML = "";
  if (agg.status === "evaluated") {
    addKV(box, "挑战 c = H2(R‖PK‖msg)", agg.challenge, true);
    addKV(box, "提交的 R", agg.submitted_R);
    addKV(box, "由完整承诺集重算的 R′", agg.computed_R);
    addBool(box, "R == R′（防承诺拼接）", agg.R_matches_commitment_set);
    addKV(box, "提交的 z", agg.submitted_z);
    addKV(box, "重算的 z′ = Σz_i（防份额拼接）", agg.recomputed_z);
    addBool(box, "z == Σz_i", agg.z_matches_share_sum);
    addBool(box, "[8]zB = [8]R + [8]cPK", agg.cofactor_equation_holds);
    if (agg.residual) {
      addKV(box, "聚合方程左端 [8]zB", agg.residual.equation_left, true);
      addKV(box, "聚合方程右端 [8]R + [8]cPK", agg.residual.equation_right, true);
      addKV(box, "聚合残差摘要", agg.residual.residual_digest, true);
    }
    if (agg.reasons.length) {
      const ul = el("ul");
      agg.reasons.forEach(x => ul.appendChild(el("li", {}, x)));
      box.appendChild(ul);
    }
  } else {
    addKV(box, "聚合核对", "因结构/解码失败而跳过: " + (agg.reasons || []).join("；"), true);
  }

  refreshEvidence();
  panel.scrollIntoView({behavior: "smooth", block: "start"});
}

function fillForm(packet) {
  const form = document.getElementById("packetForm");
  form.audit_id.value = packet.audit_id;
  form.threshold.value = packet.threshold;
  form.group_public_key.value = packet.group_public_key;
  form.message.value = packet.message;
  form.R.value = packet.aggregate_signature.R;
  form.z.value = packet.aggregate_signature.z;
  addRows(packet.participants);
}

async function fetchDemo(tamper) {
  const audit = document.querySelector('input[name="audit_id"]').value
    || "AUDIT-DEMO-0001";
  const url = `/api/demo-package?audit_id=${encodeURIComponent(audit)}`
    + (tamper ? `&tamper=${tamper}&index=1` : "");
  const packet = await (await fetch(url)).json();
  if (packet.error) { alert(packet.error); return; }
  fillForm(packet);
}

async function submitVerify() {
  const packet = collectPacket();
  const hint = document.getElementById("formHint");
  if (packet.participants.length === 0) {
    hint.textContent = "请至少添加一名参与者。";
    return;
  }
  hint.textContent = "核验中…";
  try {
    const resp = await fetch("/api/verify", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(packet)
    });
    const body = await resp.json();
    if (body.result) renderResult(body);
    else hint.textContent = "接口返回: " + (body.error || resp.status);
  } catch (e) {
    hint.textContent = "请求失败: " + e;
  }
}

async function refreshEvidence() {
  const tb = document.getElementById("evidenceTable").querySelector("tbody");
  tb.innerHTML = "";
  const data = await (await fetch("/api/evidence")).json();
  data.evidence.forEach(rec => {
    const tr = el("tr");
    tr.appendChild(el("td", {class: "mono"}, rec.audit_id));
    tr.appendChild(el("td", {class: "mono"}, rec.frozen_at || "—"));
    const vd = el("td");
    vd.appendChild(el("span", {class: "tag " +
      (rec.verdict === "ACCEPTED" ? "valid" : "invalid")}, rec.verdict));
    tr.appendChild(vd);
    tr.appendChild(el("td", {class: "mono"}, rec.packet_digest.slice(0, 24) + "…"));
    const cc = el("td");
    cc.appendChild(el("span", {class: "tag " + (rec.conflict_count ? "invalid" : "valid")},
      String(rec.conflict_count)));
    tr.appendChild(cc);
    tb.appendChild(tr);
  });
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("addRow").onclick = () => {
    const rows = document.querySelectorAll("#rows .row");
    if (rows.length >= 8) {
      document.getElementById("formHint").textContent =
        "至多接受 8 名参与者的会签包。";
      return;
    }
    document.getElementById("rows").appendChild(newRow());
  };
  document.getElementById("loadValid").onclick = () => fetchDemo("");
  document.getElementById("loadBad").onclick = () => fetchDemo("share_add_one");
  document.getElementById("packetForm").onsubmit = (e) => {
    e.preventDefault();
    submitVerify();
  };
  document.getElementById("refreshEvidence").onclick = () => refreshEvidence();

  fetch("/healthz").then(r => r.json()).then(d => {
    document.getElementById("health").innerHTML =
      '<span class="dot ok"></span>接口在线 · ' + d.ciphersuite;
  }).catch(() => {
    document.getElementById("health").innerHTML =
      '<span class="dot bad"></span>接口不可达';
  });

  addRows([{}, {}]);
  refreshEvidence();
});
