// Project Slave — Ops Terminal client.
// Plain DOM, no framework. All server-provided strings are inserted as text
// nodes (never innerHTML) because agent/tool ids can come from external events.
"use strict";

const VIEWS = ["overview", "graph", "taint", "replay"];
const LOG_CAP = 400;
const HIST_CAP = 12;
const ALERT_BUDGET = "p*<1e-3";
const BLOCKS = "▁▂▃▄▅▆▇█";

const S = {
  snap: null,
  log: [],
  view: "overview",
  selSession: null,
  replay: null, // {sid, lines, i}
  hist: { sessions: [], agents: [], denials_1h: [], quarantined: [] },
};

// ---------- helpers ----------

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : String(kid));
  }
  return el;
}

const box = (title, kids, cls = "") =>
  h("section", { class: `box ${cls}` }, h("span", { class: "hd" }, title), kids);

const hhmmss = (iso) => new Date(iso).toLocaleTimeString("en-GB", { hour12: false });

function spark(series) {
  if (!series.length) return "";
  const max = Math.max(...series, 1);
  return series.map((v) => BLOCKS[Math.min(7, Math.round((v / max) * 7))]).join("");
}

function logLine(l, extra = "") {
  return h("div", { class: `ln ${extra}` },
    h("span", { class: "dim" }, hhmmss(l.ts)), " ",
    h("span", { class: `lv-${l.level}` }, l.level.padEnd(5)), " ",
    h("span", { class: "dim" }, l.session.replace("sess-", "")), " ",
    l.msg);
}

function pickSession(snap) {
  if (!snap || !snap.sessions.length) return null;
  if (S.selSession) {
    const s = snap.sessions.find((x) => x.id === S.selSession);
    if (s) return s;
  }
  return snap.sessions.reduce((best, s) => (s.max_tier > best.max_tier ? s : best), snap.sessions[0]);
}

// ---------- ascii agent tree ----------

function treeEl(session) {
  const pre = h("pre", { class: "tree", "aria-label": `Agent tree for ${session.id}` });
  const byId = Object.fromEntries(session.agents.map((a) => [a.id, a]));
  const children = {};
  for (const a of session.agents) {
    if (a.parent && byId[a.parent]) (children[a.parent] ||= []).push(a);
  }
  const roots = session.agents.filter((a) => !a.parent || !byId[a.parent]);
  const line = (prefix, parts) => pre.append(prefix, ...parts, "\n");

  function walk(a, prefix, isLast, isRoot) {
    const branch = isRoot ? "" : isLast ? "└── " : "├── ";
    const parts = [h("span", { class: `t${a.tier}` }, `${a.id} [T${a.tier}]`)];
    if (a.role) parts.push(h("span", { class: "dim" }, ` ${a.role}`));
    if (a.taint.length) parts.push(" ", h("span", { class: "taint" }, `{${a.taint.join(",")}}`));
    if (a.p_star != null && a.p_star < 1e-2) parts.push(h("span", { class: "dim" }, ` p*=${a.p_star.toExponential(1)}`));
    line(prefix + branch, parts);

    const childPrefix = isRoot ? prefix : prefix + (isLast ? "    " : "│   ");
    const items = [...a.tools.map((t) => ({ t })), ...(children[a.id] || []).map((c) => ({ c }))];
    items.forEach((it, i) => {
      const last = i === items.length - 1;
      if (it.t) {
        const t = it.t;
        const pfx = childPrefix + (last ? "└─" : "├─");
        const allowed = t.count - t.denied;
        if (t.denied) {
          line(pfx, [h("span", { class: "deny" }, `✖ ${t.tool} DENY ${t.rule || ""}`),
            allowed > 0 ? h("span", { class: "dim" }, ` (allowed ×${allowed})`) : ""]);
        } else {
          line(pfx, [`▶ ${t.tool} `, h("span", { class: "dim" }, `×${t.count}`)]);
        }
      } else {
        walk(it.c, childPrefix, last, false);
      }
    });
  }
  roots.forEach((r, i) => walk(r, "", i === roots.length - 1, true));
  if (!roots.length) pre.append(h("span", { class: "dim" }, "(no agents yet)"));
  return pre;
}

// ---------- views ----------

function viewOverview(snap) {
  const k = snap.kpis;
  const kpi = (title, key, val, cls = "", extra = null) =>
    box(title, [h("div", { class: `val ${cls}` }, val), extra || h("div", { class: "spark", "aria-hidden": "true" }, spark(S.hist[key]))],
      cls === "t3" && val > 0 ? "alert kpi" : "kpi");

  const qNames = snap.quarantined.map((q) => `${q.agent}@${q.session.replace("sess-", "")}`).join(" ") || "none";
  const sess = pickSession(snap);
  const logBox = h("div", { class: "log", "data-key": "log-main", "aria-live": "off" },
    S.log.slice(-80).map((l) => logLine(l)));

  return [
    h("div", { class: "kpis" },
      kpi("sessions", "sessions", k.sessions),
      kpi("agents", "agents", k.agents),
      kpi("gate_denials_1h", "denials_1h", k.denials_1h, k.denials_1h ? "t1" : ""),
      kpi("quarantined", "quarantined", k.quarantined, "t3", h("div", { class: "t3" }, qNames))),
    h("div", { class: "split" },
      box(sess ? `graph ${sess.id}` : "graph", sess ? treeEl(sess) : h("div", { class: "empty" }, "waiting for events…")),
      box("tail -f alerts.log", logBox)),
  ];
}

function viewGraph(snap) {
  const sess = pickSession(snap);
  const list = h("div", { class: "list" }, snap.sessions.map((s) =>
    h("button", {
      type: "button", "data-key": `sess-${s.id}`, "aria-pressed": String(sess && s.id === sess.id),
      onclick: () => { S.selSession = s.id; render(true); },
    }, h("span", { class: `t${s.max_tier}` }, `[T${s.max_tier}] `), s.id, h("span", { class: "dim" }, ` ${s.agents.length} agents`))));

  let detail = h("div", { class: "empty" }, "no session selected");
  if (sess) {
    const msgs = sess.messages.length
      ? h("table", null, h("thead", null, h("tr", null, h("th", null, "from"), h("th", null, "to"), h("th", null, "msgs"))),
        h("tbody", null, sess.messages.map((m) => h("tr", null, h("td", null, m.src), h("td", null, m.dst), h("td", null, `×${m.count}`)))))
      : h("div", { class: "empty" }, "no agent-to-agent messages");
    detail = [treeEl(sess), h("div", { class: "dim", style: "margin-top:14px" }, "-- MSG_SEND edges --"), msgs];
  }
  return [h("div", { class: "split wide-left" }, box("sessions", list), box(sess ? `graph ${sess.id}` : "graph", detail))];
}

function viewTaint(snap) {
  const rules = ["P1", "P2", "P3", "P4"];
  const desc = { P1: "untrusted → privileged", P2: "restricted → egress", P3: "confused deputy", P4: "caps" };
  const max = Math.max(1, ...rules.map((r) => snap.rule_hits[r] || 0));
  const bars = h("div", { class: "bars" }, rules.flatMap((r) => {
    const n = snap.rule_hits[r] || 0;
    return [h("span", null, `${r} `, h("span", { class: "dim" }, desc[r])),
      h("span", { class: n ? "t3" : "dim", "aria-hidden": "true" }, "█".repeat(Math.round((n / max) * 30)) || "·"),
      h("span", null, String(n))];
  }));

  const rows = [];
  for (const s of snap.sessions) {
    for (const a of s.agents) {
      if (a.taint.length || a.tier > 0) rows.push({ s, a });
    }
  }
  rows.sort((x, y) => y.a.tier - x.a.tier);
  const table = rows.length
    ? h("table", null,
      h("thead", null, h("tr", null, ["session", "agent", "role", "tier", "labels"].map((c) => h("th", null, c)))),
      h("tbody", null, rows.map(({ s, a }) => h("tr", null,
        h("td", { class: "dim" }, s.id), h("td", { class: `t${a.tier}` }, a.id), h("td", null, a.role || "-"),
        h("td", { class: `t${a.tier}` }, `T${a.tier}`), h("td", { class: "taint" }, a.taint.join(", ") || "-")))))
    : h("div", { class: "empty" }, "no tainted or flagged agents");

  return [box("rule hits", bars), box("tainted / flagged agents", table)];
}

async function openReplay(sid) {
  const res = await fetch(`/api/sessions/${encodeURIComponent(sid)}/log`);
  if (!res.ok) return;
  const lines = await res.json();
  S.replay = { sid, lines, i: 0 };
  render(true);
}

function stepReplay(d) {
  if (!S.replay || !S.replay.lines.length) return;
  const n = S.replay.lines.length;
  S.replay.i = d === "first" ? 0 : d === "last" ? n - 1 : Math.max(0, Math.min(n - 1, S.replay.i + d));
  render(true);
}

function viewReplay(snap) {
  const incidents = snap.sessions.filter((s) => s.max_tier >= 2);
  const list = incidents.length
    ? h("div", { class: "list" }, incidents.map((s) =>
      h("button", {
        type: "button", "data-key": `inc-${s.id}`, "aria-pressed": String(S.replay?.sid === s.id),
        onclick: () => openReplay(s.id),
      }, h("span", { class: `t${s.max_tier}` }, `[T${s.max_tier}] `), s.id)))
    : h("div", { class: "empty" }, "no incidents (tier ≥ 2) yet");

  let detail = h("div", { class: "empty" }, "select an incident to replay its event log");
  const r = S.replay;
  if (r && r.lines.length) {
    const cur = r.lines[r.i];
    detail = [
      h("div", { class: "stepper" },
        h("button", { class: "btn", type: "button", "data-key": "rp-first", onclick: () => stepReplay("first"), "aria-label": "First step" }, "|◀"),
        h("button", { class: "btn", type: "button", "data-key": "rp-prev", onclick: () => stepReplay(-1), "aria-label": "Previous step" }, "◀"),
        h("span", null, `step ${r.i + 1}/${r.lines.length}`),
        h("button", { class: "btn", type: "button", "data-key": "rp-next", onclick: () => stepReplay(1), "aria-label": "Next step" }, "▶"),
        h("button", { class: "btn", type: "button", "data-key": "rp-last", onclick: () => stepReplay("last"), "aria-label": "Last step" }, "▶|"),
        h("span", { class: "dim" }, "← → to step")),
      h("div", { style: "font-size:18px;margin-bottom:10px", "aria-live": "polite" },
        h("span", { class: `lv-${cur.level}` }, cur.level), " ", cur.msg),
      h("div", { class: "log", "data-key": "log-replay" },
        r.lines.map((l, i) => logLine(l, i === r.i ? "cur" : i > r.i ? "future" : ""))),
    ];
  } else if (r) {
    detail = h("div", { class: "empty" }, "this session has no log lines");
  }
  return [h("div", { class: "split wide-left" }, box("incidents", list), box(r ? `replay ${r.sid}` : "replay", detail))];
}

// ---------- render loop ----------

const viewFns = { overview: viewOverview, graph: viewGraph, taint: viewTaint, replay: viewReplay };
let renderTimer = null;

function render(now = false) {
  if (!now) {
    if (!renderTimer) renderTimer = setTimeout(() => { renderTimer = null; render(true); }, 300);
    return;
  }
  const main = document.getElementById("view");
  const focusKey = document.activeElement?.dataset?.key;
  const scroll = {};
  main.querySelectorAll("[data-key].log").forEach((el) => {
    scroll[el.dataset.key] = { top: el.scrollTop, atBottom: el.scrollTop + el.clientHeight >= el.scrollHeight - 8 };
  });

  main.replaceChildren(...(S.snap ? viewFns[S.view](S.snap) : [h("div", { class: "empty" }, "connecting to gateway…")]));

  main.querySelectorAll("[data-key].log").forEach((el) => {
    const prev = scroll[el.dataset.key];
    if (el.dataset.key === "log-replay") {
      el.querySelector(".cur")?.scrollIntoView({ block: "nearest" });
    } else if (!prev || prev.atBottom) {
      el.scrollTop = el.scrollHeight;
    } else {
      el.scrollTop = prev.top;
    }
  });
  if (focusKey) main.querySelector(`[data-key="${CSS.escape(focusKey)}"]`)?.focus();

  document.querySelectorAll(".tabs button").forEach((b) => {
    if (b.dataset.view === S.view) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  document.getElementById("cmd").textContent = {
    overview: "watch --all-sessions", graph: "graph --session", taint: "taint --rules", replay: "replay --incident",
  }[S.view];
  renderStatus();
}

function renderStatus() {
  const bar = document.getElementById("statusbar");
  if (!S.snap) { bar.replaceChildren(); return; }
  const k = S.snap.kpis;
  const item = (label, val) => h("span", null, `${label}=`, h("b", null, val));
  bar.replaceChildren(
    item("gate.p99", k.gate_p99_ms == null ? "n/a" : `${k.gate_p99_ms.toFixed(1)}ms`),
    item("events", String(k.events)),
    item("rule_hits", Object.entries(S.snap.rule_hits).map(([r, n]) => `${r}:${n}`).join(" ") || "0"),
    item("alert_budget", ALERT_BUDGET),
    item("tracked_sessions", String(S.snap.sessions.length)),
  );
}

function setView(v) {
  if (!VIEWS.includes(v) || v === S.view) return;
  S.view = v;
  render(true);
  document.getElementById("view").focus({ preventScroll: true });
}

// ---------- wiring ----------

document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => setView(b.dataset.view)));

document.addEventListener("keydown", (e) => {
  if (e.target.closest("input, textarea, select")) return;
  const fk = { F1: 0, F2: 1, F3: 2, F4: 3 }[e.key];
  if (fk != null) { e.preventDefault(); setView(VIEWS[fk]); return; }
  if (!e.ctrlKey && !e.metaKey && !e.altKey && ["1", "2", "3", "4"].includes(e.key)) { setView(VIEWS[+e.key - 1]); return; }
  if (S.view === "replay" && S.replay) {
    if (e.key === "ArrowLeft") { e.preventDefault(); stepReplay(-1); }
    if (e.key === "ArrowRight") { e.preventDefault(); stepReplay(1); }
  }
});

setInterval(() => {
  if (!S.snap) return;
  for (const key of Object.keys(S.hist)) {
    S.hist[key].push(S.snap.kpis[key] ?? 0);
    if (S.hist[key].length > HIST_CAP) S.hist[key].shift();
  }
  if (S.view === "overview") render();
}, 3000);

function connect(delay = 500) {
  const conn = document.getElementById("conn");
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
  ws.onopen = () => { conn.textContent = "● LIVE"; conn.className = "conn live"; delay = 500; };
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.type === "hello") {
      S.snap = msg.snapshot;
      S.log = msg.snapshot.log.slice(-LOG_CAP);
    } else if (msg.type === "update") {
      S.snap = msg.snapshot;
      if (msg.lines.length) {
        S.log.push(...msg.lines);
        if (S.log.length > LOG_CAP) S.log.splice(0, S.log.length - LOG_CAP);
      }
    }
    // Replay is a frozen view; don't re-render it on every event.
    if (S.view !== "replay" || !S.replay) render();
  };
  ws.onclose = () => {
    conn.textContent = "○ reconnecting"; conn.className = "conn down";
    setTimeout(() => connect(Math.min(delay * 2, 5000)), delay);
  };
}

render(true);
connect();
