/* Money dashboard. Static page: everything personal arrives encrypted (data/*.enc) and is decrypted
   in memory with a key that only the owner's Google account can read (Drive appDataFolder).
   Rendering uses textContent only; no data value is ever parsed as HTML. */
(function () {
  "use strict";
  if (window.top !== window.self) {            // no framing (meta CSP can't set frame-ancestors)
    document.getElementById("app").hidden = true;
    document.getElementById("frame-guard").hidden = false;
    return;
  }
  const CFG = window.MONEY_CFG || {};
  const AAD = new TextEncoder().encode("money-dash/v1");
  const IDLE_MS = 15 * 60 * 1000;
  const S = { token: null, book: null, prices: {}, pricesAt: null, status: null, month: 0, bucket: null };
  let idleTimer = null, hiddenAt = null;

  // ---------------------------------------------------------------- tiny DOM helpers (text only)
  function el(tag, attrs) {
    const n = document.createElement(tag);
    if (attrs) for (const k in attrs) {
      const v = attrs[k];
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = String(v);
      else if (k === "style") setStyles(n, v);
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? "" : String(v));
    }
    for (let i = 2; i < arguments.length; i++) add(n, arguments[i]);
    return n;
  }
  function add(n, c) {
    if (c === null || c === undefined || c === false) return;
    if (Array.isArray(c)) { c.forEach(x => add(n, x)); return; }
    n.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  // CSP allows no inline style attributes; set styles through the CSSOM instead.
  function setStyles(n, css) {
    String(css).split(";").forEach(d => { const i = d.indexOf(":"); if (i > 0) n.style.setProperty(d.slice(0, i).trim(), d.slice(i + 1).trim()); });
  }
  const SVGNS = "http://www.w3.org/2000/svg";
  function sv(tag, attrs, text) {
    const n = document.createElementNS(SVGNS, tag);
    for (const k in attrs || {}) {
      const v = String(attrs[k]);
      if ((k === "fill" || k === "stroke") && v.startsWith("var(")) n.style.setProperty(k, v);
      else n.setAttribute(k, v);
    }
    if (text !== undefined) n.textContent = String(text);
    return n;
  }
  function safeUrl(u) {
    try {
      const x = new URL(u);
      return (x.protocol === "https:" && /(^|\.)google\.com$/.test(x.hostname)) ? x.href : null;
    } catch (e) { return null; }
  }

  // ---------------------------------------------------------------- formatting
  function inr(v, opts) {
    if (v === null || v === undefined || isNaN(v)) return "—";
    const neg = v < 0; const a = Math.round(Math.abs(v));
    let s = String(a);
    if (s.length > 3) { const h = s.slice(0, -3), t = s.slice(-3); s = h.replace(/\B(?=(\d{2})+(?!\d))/g, ",") + "," + t; }
    return (neg ? "−" : (opts && opts.sign && v > 0 ? "+" : "")) + "₹" + s;
  }
  function short(v) {
    if (v === null || v === undefined || isNaN(v)) return "—";
    const a = Math.abs(v), sg = v < 0 ? "−" : "";
    if (a >= 1e7) return sg + "₹" + (a / 1e7).toFixed(2) + " Cr";
    if (a >= 1e5) return sg + "₹" + (a / 1e5).toFixed(2) + "L";
    if (a >= 1e3) return sg + "₹" + (a / 1e3).toFixed(1) + "k";
    return inr(v);
  }
  const pct = (v, d) => (v === null || isNaN(v)) ? "—" : (v >= 0 ? "+" : "−") + Math.abs(v * 100).toFixed(d === undefined ? 1 : d) + "%";
  const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  function istNow() { return new Date(Date.now() + (330 + new Date().getTimezoneOffset()) * 60000); }
  function ymd(d) { return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0"); }
  function monthKey(off) { const n = istNow(); const d = new Date(n.getFullYear(), n.getMonth() + off, 1); return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0"); }
  function monthLabel(key) { const [y, m] = key.split("-"); return MON[+m - 1] + " " + y; }
  function niceDate(iso) { if (!iso) return ""; const [y, m, d] = iso.slice(0, 10).split("-"); return (+d) + " " + MON[+m - 1] + (y !== String(istNow().getFullYear()) ? " " + y : ""); }

  // ---------------------------------------------------------------- crypto + auth
  function b64(s) { const b = atob(s); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
  async function decrypt(key, o) {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(o.iv), additionalData: AAD }, key, b64(o.ct));
    return JSON.parse(new TextDecoder().decode(pt));
  }
  async function gapi(url) {
    const r = await fetch(url, { headers: { Authorization: "Bearer " + S.token }, cache: "no-store", referrerPolicy: "no-referrer" });
    if (!r.ok) throw new Error("Google Drive answered " + r.status);
    return r;
  }
  async function loadKey() {
    const q = encodeURIComponent("name = 'money-dash-key.txt'");
    const list = await (await gapi("https://www.googleapis.com/drive/v3/files?spaces=appDataFolder&fields=files(id,name)&q=" + q)).json();
    if (!list.files || !list.files.length) throw new Error("No key in this Google account. Sign in with the owner's account.");
    const raw = (await (await gapi("https://www.googleapis.com/drive/v3/files/" + encodeURIComponent(list.files[0].id) + "?alt=media")).text()).trim();
    return crypto.subtle.importKey("raw", b64(raw), { name: "AES-GCM" }, false, ["decrypt"]);
  }
  async function fetchEnc(path) {
    const r = await fetch(path + "?t=" + Date.now(), { cache: "no-store" });
    if (!r.ok) throw new Error(path + " missing (" + r.status + ")");
    return r.json();
  }
  async function unlock() {
    msg("Unlocking…");
    try {
      const key = await loadKey();
      const [b, p, st] = await Promise.all([fetchEnc("data/book.enc"), fetchEnc("data/prices.enc"), fetch("data/status.json?t=" + Date.now(), { cache: "no-store" }).then(r => r.ok ? r.json() : null)]);
      S.book = await decrypt(key, b);
      const pr = await decrypt(key, p);
      S.prices = pr.prices || {}; S.pricesAt = pr.at; S.status = st;
      S.key = key;
      document.getElementById("lock").hidden = true;
      document.getElementById("dash").hidden = false;
      render();
      armIdle();
    } catch (e) {
      msg(e.message || "Couldn't unlock.");
      S.token = null;
    }
  }
  function msg(t) { document.getElementById("lock-msg").textContent = t; }
  function lockNow(reason) {
    if (S.token && window.google && google.accounts && google.accounts.oauth2) { try { google.accounts.oauth2.revoke(S.token, () => {}); } catch (e) {} }
    S.token = null; S.book = null; S.prices = {}; S.key = null;
    const d = document.getElementById("dash"); d.replaceChildren(); d.hidden = true;
    document.getElementById("lock").hidden = false;
    msg(reason || "Locked.");
  }
  function armIdle() {
    const reset = () => { clearTimeout(idleTimer); idleTimer = setTimeout(() => lockNow("Locked after 15 minutes idle."), IDLE_MS); };
    ["pointerdown", "keydown", "scroll", "touchstart"].forEach(ev => window.addEventListener(ev, reset, { passive: true }));
    reset();
  }
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) hiddenAt = Date.now();
    else if (hiddenAt && Date.now() - hiddenAt > IDLE_MS && S.book) lockNow("Locked while the tab was in the background.");
  });
  function initAuth() {
    const btn = document.getElementById("signin");
    if (!CFG.clientId) { msg("Setup incomplete: no Google client configured."); return; }
    const tc = google.accounts.oauth2.initTokenClient({
      client_id: CFG.clientId,
      scope: "https://www.googleapis.com/auth/drive.appdata",
      prompt: "",
      callback: (resp) => {
        if (resp.error || !resp.access_token) { msg("Sign-in didn't complete."); return; }
        if (!google.accounts.oauth2.hasGrantedAllScopes(resp, "https://www.googleapis.com/auth/drive.appdata")) { msg("Drive app-data access is needed to unlock."); return; }
        S.token = resp.access_token; unlock();
      },
      error_callback: () => msg("Sign-in was closed or blocked."),
    });
    btn.disabled = false;
    btn.addEventListener("click", () => tc.requestAccessToken());
  }
  (function waitGis(n) {
    if (window.google && google.accounts && google.accounts.oauth2) initAuth();
    else if (n < 100) setTimeout(() => waitGis(n + 1), 100);
    else msg("Google sign-in didn't load. Check your connection.");
  })(0);

  // ---------------------------------------------------------------- model
  function priceOf(h) {
    if (!h.key) return { p: h.nav_static, at: "static" };
    return S.prices[h.key] || { p: null, at: "no price" };
  }
  function valued() {
    return S.book.holdings.map(h => { const pr = priceOf(h); const v = pr.p === null ? null : h.units * pr.p; return Object.assign({}, h, { price: pr.p, priceAt: pr.at, value: v }); });
  }
  function bucketTotals(rows) {
    const t = {};
    rows.forEach(h => { for (const b in h.buckets) t[b] = (t[b] || 0) + (h.value || 0) * h.buckets[b]; });
    return t;
  }
  function monthData(key) {
    const m = (S.book.months.months || {})[key];
    if (m) return m;
    const lab = monthLabel(key);
    const r = S.book.plan.path.find(x => x.m === lab);
    if (!r) return { lines: [], one_offs: [], generated: true };
    const L = [
      { id: "salary", kind: "income", label: "Salary credited", planned: r.salary, done: 0, status: "due" },
      { id: "si", kind: "loan", label: "Loan SI (EMI account)", planned: r.si, done: 0, status: "due", from_bank: true },
      { id: "home", kind: "invest", bucket: "home_fund", label: "Home fund (plan: TDS pot / equity SIP / no-load)", planned: r.home, done: 0, status: "due", from_bank: true },
      { id: "retirement", kind: "invest", bucket: "retirement", label: "Retirement", planned: r.ret, done: 0, status: "due", from_bank: true },
    ];
    if (r.child) L.push({ id: "child", kind: "invest", bucket: "childcare", label: "Child fund (arbitrage)", planned: r.child, done: 0, status: "due", from_bank: true });
    L.push({ id: "living", kind: "spend", label: "Living costs (rent + living)", planned: r.rent + r.living, done: null, status: "due", from_bank: true });
    return { salary: r.salary, living_budget: r.rent + r.living, lines: L, one_offs: [], generated: true, note: r.note };
  }

  // ---------------------------------------------------------------- render
  function render() {
    const root = document.getElementById("dash");
    root.replaceChildren();
    const rows = valued();
    const bt = bucketTotals(rows);
    const book = rows.reduce((a, h) => a + (h.value || 0), 0);
    const cost = rows.reduce((a, h) => a + h.cost, 0);
    const T = S.book.plan.targets;
    const tgtTotal = Object.values(T).reduce((a, b) => a + b, 0);
    const mk = monthKey(S.month), mkNow = monthKey(0);

    root.append(header(mk));
    root.append(strip(book, cost, tgtTotal, mkNow));
    root.append(viewGoals(bt, T));
    root.append(viewHoldings(rows, bt));
    root.append(viewChecklist(mk));
    root.append(viewBank(mk));
    root.append(viewCalendar(mk));
    root.append(detailsFlat(), detailsLoan(), detailsSalary(), detailsCards(), detailsStocks(rows), detailsHealth());
  }

  function header(mk) {
    const seg = el("div", { class: "seg", role: "group", "aria-label": "Month" },
      el("button", { type: "button", "aria-pressed": S.month === 0 ? "true" : "false", onclick: () => { S.month = 0; render(); }, text: "This month · " + monthLabel(monthKey(0)) }),
      el("button", { type: "button", "aria-pressed": S.month === 1 ? "true" : "false", onclick: () => { S.month = 1; render(); }, text: "Next · " + monthLabel(monthKey(1)) }));
    const when = S.pricesAt ? new Date(S.pricesAt) : null;
    const age = when ? (Date.now() - when.getTime()) / 3600000 : 99;
    return el("div", { class: "top" },
      el("div", null, el("h1", { text: "Money" }),
        el("div", { class: "meta" }, "Priced " + (S.pricesAt ? S.pricesAt.replace("T", " ").slice(0, 16) + " IST" : "—") + " · data built " + S.book.built_at.replace("T", " ").slice(0, 16) + " IST ",
          age > 26 ? el("span", { class: "pill warn", text: "prices stale" }) : null)),
      el("div", { style: "display:flex;gap:8px;flex-wrap:wrap;align-items:center" }, seg,
        el("button", { type: "button", class: "ghost", onclick: () => lockNow("Locked."), text: "Lock" })));
  }

  function strip(book, cost, tgtTotal, mkNow) {
    const gap = book - tgtTotal;
    const m = monthData(mkNow);
    const lp = leftParts(m);
    const sp = spendable(mkNow);
    const nextAct = (S.book.calendar || []).filter(e => !e.done && e.date >= ymd(istNow())).slice(0, 1)[0];
    const band = S.book.plan.band;
    const st = Math.abs(gap / tgtTotal) <= band ? ["ok", "On track"] : gap < 0 ? ["bad", "Behind plan"] : ["ok", "Ahead of plan"];
    return el("div", { class: "strip" },
      tile("Book (live)", short(book), [inr(book - cost, { sign: true }) + " on cost " + short(cost)]),
      tile("vs 5-5-15 plan", inr(gap, { sign: true }), [el("span", { class: "pill " + st[0], text: st[1] }), " " + pct(gap / tgtTotal) + " of " + short(tgtTotal)]),
      tile("Salary left to invest · " + monthLabel(mkNow), inr(lp.salary), [lp.salary > 0 ? "due this month" : "salary money all invested", lp.other ? " · plus " + short(lp.other) + " from redemptions/proceeds" : ""]),
      tile("Spendable in bank", inr(sp.result), ["as of " + niceDate(S.book.months.bank.as_of)]),
      tile("Next action", nextAct ? niceDate(nextAct.date) : "—", [nextAct ? nextAct.title.slice(0, 60) : "nothing scheduled"]));
  }
  function tile(lab, big, sub) { return el("div", { class: "tile" }, el("div", { class: "lab", text: lab }), el("div", { class: "big", text: big }), el("div", { class: "sub" }, sub)); }

  // ---- view 1
  function viewGoals(bt, T) {
    const G = S.book.plan.goals, band = S.book.plan.band;
    const wrap = el("div", { class: "goals" });
    S.book.bucket_defs.forEach(b => {
      const v = bt[b.key] || 0, t = T[b.key] || 0, g = G[b.key] || {};
      if (!v && !t && !g.target) return;
      const gap = v - t, gp = t ? gap / t : 0;
      let pill;
      if (!t && !v) pill = el("span", { class: "pill info", text: "Not started" });
      else if (!t) pill = el("span", { class: "pill info", text: "No plan value yet" });
      else if (Math.abs(gp) <= band) pill = el("span", { class: "pill ok", text: "On track" });
      else if (gp < 0) pill = el("span", { class: "pill bad", text: "Behind" });
      else pill = el("span", { class: "pill ok", text: "Ahead" });
      const goal = g.target || null;
      const fill = goal ? Math.min(1, v / goal) : (t ? Math.min(1, v / (t * 1.2)) : 0);
      const mark = goal ? Math.min(1, t / goal) : (t ? 1 / 1.2 : 0);
      const nums = [el("span", null, "Now " + inr(v)), el("span", null, "Plan today " + inr(t)), el("span", null, "Gap " + inr(gap, { sign: true }) + (t ? " (" + pct(gp) + ")" : ""))];
      if (goal) nums.push(el("span", null, "Goal " + short(goal) + (g.date ? " by " + niceDate(g.date) : "")));
      if (b.key === "home_fund") {
        if (S.book.plan.funded_now) nums.push(el("span", null, "Funded " + Math.round(S.book.plan.funded_now * 100) + "%"));
        const s = S.book.plan.stress || {}; const k = Object.keys(s)[0];
        if (k) nums.push(el("span", null, "Stress (" + k + "): short " + inr(s[k])));
      }
      if (b.key === "retirement" && g.projection_dec_2036) nums.push(el("span", null, "Plan path: " + short(g.projection_dec_2036) + " by Dec 2036"));
      if (b.key === "loan_reserve" && g.alt) nums.push(el("span", null, g.alt_note || ("Alternative: " + inr(g.alt))));
      const row = el("div", { class: "goal", role: "button", tabindex: "0", "aria-current": S.bucket === b.key ? "true" : "false",
        onclick: () => { S.bucket = S.bucket === b.key ? null : b.key; render(); },
        onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); S.bucket = S.bucket === b.key ? null : b.key; render(); } } },
        el("div", null, el("div", { class: "gname", text: b.label }), el("div", { class: "gnote", text: b.note })),
        el("div", { class: "gbar" }, el("div", { class: "meter" }, el("i", { style: "width:" + (fill * 100).toFixed(1) + "%" }), mark ? el("b", { style: "left:" + (mark * 100).toFixed(1) + "%" }) : null), el("div", { class: "gnums" }, nums)),
        pill);
      wrap.append(row);
    });
    const adj = S.book.plan.active_adjustments || [];
    return el("section", { class: "view", id: "goals" },
      el("header", null, el("div", null, el("div", { class: "eyebrow", text: "1 · Goals" }), el("h2", { text: "Am I on track, bucket by bucket?" })),
        el("span", { class: "q", text: "Plan = 5-5-15 sim for " + S.book.plan.target_month + " · On track within ±" + Math.round(S.book.plan.band * 100) + "% · tap a bucket to see what's in it" })),
      wrap,
      adj.length ? el("p", { class: "small muted" }, "Timing adjustments in the plan values: " + adj.join("; ")) : null);
  }

  // ---- view 2
  function viewHoldings(rows, bt) {
    const defs = S.book.bucket_defs;
    const chips = el("div", { class: "chips" },
      el("button", { type: "button", class: "chip", "aria-pressed": S.bucket ? "false" : "true", onclick: () => { S.bucket = null; render(); }, text: "All buckets" }),
      defs.filter(d => bt[d.key]).map(d => el("button", { type: "button", class: "chip", "aria-pressed": S.bucket === d.key ? "true" : "false", onclick: () => { S.bucket = d.key; render(); }, text: d.label })));
    const tb = el("tbody");
    const order = S.bucket ? [S.bucket] : defs.map(d => d.key);
    let grand = 0;
    order.forEach(bk => {
      const inB = rows.filter(h => h.buckets[bk]);
      if (!inB.length) return;
      const lab = (defs.find(d => d.key === bk) || {}).label || bk;
      let sv_ = 0, sc = 0;
      const head = el("tr", { class: "sub" }, el("td", { text: lab }), el("td"), el("td"), el("td", { class: "n" }), el("td", { class: "n" }), el("td", { class: "n" }));
      tb.append(head);
      inB.sort((a, b) => (b.value || 0) * b.buckets[bk] - (a.value || 0) * a.buckets[bk]).forEach(h => {
        const w = h.buckets[bk], v = (h.value || 0) * w, c = h.cost * w; sv_ += v; sc += c;
        const split = Object.keys(h.buckets).length > 1 ? " (" + Math.round(w * 100) + "% of the line)" : "";
        const isAmt = h.kind === "liquid" || h.kind === "cash" || h.nav_static === 1;
        tb.append(el("tr", null,
          el("td", null, el("div", { text: h.name + split }), el("div", { class: "small muted" }, h.app + (h.pending ? " · " : ""), h.pending ? el("span", { class: "pill warn", text: "awaiting allotment" }) : null)),
          el("td", { class: "n", text: isAmt ? "₹ amount" : (h.units * w).toLocaleString("en-IN", { maximumFractionDigits: 3 }) }),
          el("td", { class: "n" }, el("div", { text: h.price === null ? "—" : (isAmt ? "—" : h.price.toLocaleString("en-IN", { maximumFractionDigits: 2 })) }), el("div", { class: "small muted", text: isAmt ? "" : h.priceAt })),
          el("td", { class: "n", text: inr(v) }),
          el("td", { class: "n", text: inr(c) }),
          el("td", { class: "n", text: inr(v - c, { sign: true }) + (c ? " " + pct((v - c) / c) : "") })));
      });
      head.children[3].textContent = inr(sv_); head.children[4].textContent = inr(sc); head.children[5].textContent = inr(sv_ - sc, { sign: true });
      grand += sv_;
    });
    if (!S.bucket) tb.append(el("tr", { class: "total" }, el("td", { text: "Whole book" }), el("td"), el("td"), el("td", { class: "n", text: inr(grand) }), el("td"), el("td")));
    return el("section", { class: "view", id: "holdings" },
      el("header", null, el("div", null, el("div", { class: "eyebrow", text: "2 · Holdings" }), el("h2", { text: "What I hold, and which bucket it belongs to" })),
        el("span", { class: "q", text: "Units as of " + S.book.units_as_of + " · values = units × latest price" })),
      chips,
      el("div", { class: "tw" }, el("table", null, el("thead", null, el("tr", null, el("th", { text: "Holding" }), el("th", { class: "n", text: "Units" }), el("th", { class: "n", text: "Price / NAV" }), el("th", { class: "n", text: "Value" }), el("th", { class: "n", text: "Cost" }), el("th", { class: "n", text: "Gain" }))), tb)));
  }

  // ---- view 3
  // Money still to put to work this month. "salary" = lines paid from the bank (this month's pay);
  // "other" = one-offs funded by redemptions or sale proceeds.
  function leftParts(m) {
    const o = { salary: 0, other: 0 };
    [].concat(m.lines || [], m.one_offs || []).forEach(l => {
      if (l.kind !== "invest" || !(l.status === "due" || l.status === "partly")) return;
      const owe = Math.max(0, (l.planned || 0) - (l.done || 0));
      if (l.from_bank) o.salary += owe; else o.other += owe;
    });
    return o;
  }
  function leftToInvest(m) { const o = leftParts(m); return o.salary + o.other; }
  function statusPill(l) {
    const today = ymd(istNow());
    if (l.status === "done") return el("span", { class: "pill ok", text: "Done" });
    if (l.status === "partly") return el("span", { class: "pill warn", text: "Partly" });
    if (l.status === "conditional") return el("span", { class: "pill info", text: "Conditional" });
    if (l.status === "skipped") return el("span", { class: "pill info", text: "Skipped" });
    if (l.due && l.due < today) return el("span", { class: "pill bad", text: "Overdue" });
    return el("span", { class: "pill warn", text: l.due ? "Due " + niceDate(l.due) : "Due" });
  }
  function viewChecklist(mk) {
    const m = monthData(mk);
    const all = [].concat(m.lines || [], m.one_offs || []).filter(l => l.kind !== "spend");
    const box = el("div");
    all.forEach(l => box.append(el("div", { class: "check" },
      statusPill(l),
      el("div", null, el("div", { text: l.label })),
      el("div", { class: "n num" }, el("div", { text: l.planned === null || l.planned === undefined ? "—" : inr(l.planned) }), l.status === "done" && l.done !== null && l.done !== undefined && l.done !== l.planned ? el("div", { class: "small muted", text: "done " + inr(l.done) }) : null),
      (l.how || l.date) ? el("div", { class: "how", text: [l.date ? niceDate(l.date) : "", l.how || ""].filter(Boolean).join(" · ") }) : null)));
    const lp = leftParts(m);
    return el("section", { class: "view", id: "checklist" },
      el("header", null, el("div", null, el("div", { class: "eyebrow", text: "3 · This month's money" }), el("h2", { text: "Have I invested everything due in " + monthLabel(mk) + "?" })),
        el("span", { class: "q", text: m.generated ? "From the 5-5-15 plan (no actuals yet)" + (m.note ? " · " + m.note.slice(0, 120) : "") : "Plan lines and what actually happened" })),
      box,
      el("div", { class: "foot" }, el("span", { text: "Salary money left to invest in " + monthLabel(mk) }), el("span", { class: "num", text: inr(lp.salary) })),
      lp.other ? el("div", { class: "foot", style: "border-top-width:1px;font-weight:600" }, el("span", { text: "Redemption / sale proceeds still to deploy" }), el("span", { class: "num", text: inr(lp.other) })) : null);
  }

  // ---- view 4
  function spendable(mk) {
    const doc = S.book.months, today = ymd(istNow());
    const rows = [];
    const isNow = mk === monthKey(0);
    if (isNow) {
      rows.push({ label: "Bank balance (reported " + niceDate(doc.bank.as_of) + ")", amt: doc.bank.balance });
      (doc.earmarks || []).forEach(e => { if (e.permanent || !e.until || e.until >= today) rows.push({ label: "Set aside: " + e.label + (e.until ? " (until " + niceDate(e.until) + ")" : ""), amt: -e.amount }); });
      const m = monthData(mk);
      [].concat(m.lines || [], m.one_offs || []).forEach(l => {
        if (!l.from_bank || l.kind === "spend" || l.kind === "income" || l.status === "conditional") return;
        if (l.status === "due" || l.status === "partly") { const owe = (l.planned || 0) - (l.done || 0); if (owe > 0) rows.push({ label: "Still to pay/invest: " + l.label, amt: -owe }); }
      });
      const res = rows.reduce((a, r) => a + r.amt, 0);
      return { rows, result: res, note: "Spending money for the rest of " + monthLabel(mk) + ". Next salary on the " + (doc.salary_day || 1) + "st." };
    }
    const m = monthData(mk);
    const sal = m.salary || 0;
    rows.push({ label: "Salary expected", amt: sal });
    [].concat(m.lines || [], m.one_offs || []).forEach(l => {
      if (!l.from_bank || l.kind === "income" || l.kind === "spend") return;
      if (l.planned) rows.push({ label: l.label, amt: -l.planned });
    });
    rows.push({ label: "Living budget (rent + living)", amt: -(m.living_budget || 0) });
    const res = rows.reduce((a, r) => a + r.amt, 0);
    return { rows, result: res, note: "Projection: what's left after the plan and the living budget. Card bills inside the living budget." };
  }
  function viewBank(mk) {
    const sp = spendable(mk);
    const wf = el("div", { class: "wf" }, sp.rows.map(r => el("div", { class: "wf-row" }, el("span", { text: r.label }), el("span", { class: "num", text: inr(r.amt, { sign: true }) }))),
      el("div", { class: "wf-row res" }, el("span", { text: mk === monthKey(0) ? "Spendable now" : "Unplanned surplus in " + monthLabel(mk) }), el("span", { class: "num", text: inr(sp.result) })));
    const cc = S.book.cc, ks = Object.keys(cc.months).sort(), last = cc.months[ks[ks.length - 1]];
    const over = last.regular_total - cc.budget;
    const ccBox = el("div", null,
      el("div", { class: "eyebrow", text: "Card · last statement" }),
      el("div", { class: "big num", style: "font-size:22px;font-weight:650", text: inr(last.regular_total) }),
      el("div", { class: "small" }, "Regular spend in " + last.label + " vs " + short(cc.budget) + " budget: ", el("span", { class: "pill " + (over > 0 ? "bad" : "ok"), text: over > 0 ? inr(over) + " over" : inr(-over) + " under" })),
      el("div", { class: "small muted", text: "Plus one-offs " + inr(last.outlier_total) + " · statement total " + inr(last.declared_total) + (last.due_date ? " · due " + niceDate(last.due_date) : "") + (last.paid_on ? " · paid " + niceDate(last.paid_on) : "") }));
    return el("section", { class: "view", id: "bank" },
      el("header", null, el("div", null, el("div", { class: "eyebrow", text: "4 · Bank" }), el("h2", { text: mk === monthKey(0) ? "What's actually spendable?" : "What will " + monthLabel(mk) + " leave me?" })),
        el("span", { class: "q", text: sp.note })),
      el("div", { class: "two" }, wf, ccBox));
  }

  // ---- view 5
  function viewCalendar(mk) {
    const today = ymd(istNow());
    const items = (S.book.calendar || []).filter(e => e.date.slice(0, 7) === mk || (S.month === 0 && !e.done && e.date < today));
    const tb = el("tbody");
    items.forEach(e => {
      const st = e.done ? ["ok", "Done"] : e.date < today ? ["bad", "Overdue"] : e.date === today ? ["warn", "Today"] : ["info", "Upcoming"];
      tb.append(el("tr", null,
        el("td", { class: "n" }, el("div", { text: niceDate(e.date) }), el("div", { class: "small muted", text: e.time ? e.time + " IST" : "all day" })),
        el("td", null, el("div", { text: e.title }), e.desc ? el("div", { class: "small muted", text: e.desc.slice(0, 220) + (e.desc.length > 220 ? "…" : "") }) : null),
        el("td", null, el("span", { class: "pill " + st[0], text: st[1] }), e.recurring ? el("div", { class: "small muted", text: "repeats" }) : null)));
    });
    return el("section", { class: "view", id: "calendar" },
      el("header", null, el("div", null, el("div", { class: "eyebrow", text: "5 · Calendar" }), el("h2", { text: "Action items in " + monthLabel(mk) })),
        el("span", { class: "q", text: "Money events from your Google Calendar" + (S.month === 0 ? ", plus anything overdue" : "") })),
      items.length ? el("div", { class: "tw" }, el("table", null, tb)) : el("p", { class: "muted", text: "Nothing on the calendar for " + monthLabel(mk) + " yet." }));
  }

  // ---- supporting detail
  function det(id, title, q, body, open) {
    return el("details", { class: "view", id: id, open: open || null },
      el("summary", null, el("div", null, el("h2", { text: title }), q ? el("div", { class: "q", text: q }) : null)), body);
  }
  function detailsFlat() {
    const A = S.book.assetz, ms = A.milestones;
    const paid = ms.filter(m => m.paid), tot = ms.reduce((a, m) => a + (m.total || 0), 0), pt = paid.reduce((a, m) => a + (m.total || 0), 0);
    const next = ms.filter(m => !m.paid).slice(0, 4);
    const tb = el("tbody");
    ms.forEach(m => {
      const slip = m.actual && m.planned ? Math.round((new Date(m.actual) - new Date(m.planned)) / 86400000) : null;
      tb.append(el("tr", null,
        el("td", { class: "n", text: m.n }),
        el("td", null, el("div", { text: m.name }), el("div", { class: "small muted", text: (m.pct || "") + "" })),
        el("td", { class: "n", text: niceDate(m.planned) }),
        el("td", { class: "n" }, m.actual ? niceDate(m.actual) : "—", slip !== null ? el("div", { class: "small " + (slip > 0 ? "" : "muted"), text: slip === 0 ? "on time" : (slip > 0 ? slip + " d late" : -slip + " d early") }) : null),
        el("td", { class: "n", text: inr(m.total) }),
        el("td", { class: "n" }, el("div", { text: inr(m.tds) }), el("div", { class: "small muted", text: inr((m.tds || 0) / 2) + " each" })),
        el("td", { class: "n", text: inr(m.net_due) }),
        el("td", null, el("span", { class: "pill " + (m.paid ? "ok" : "info"), text: m.paid ? "Paid" : "To come" }))));
    });
    const pays = el("tbody");
    A.payments.forEach(p => {
      const u = p.link ? safeUrl(p.link) : null;
      pays.append(el("tr", null,
        el("td", { class: "n", text: p.date }),
        el("td", null, el("div", { text: p.desc }), el("div", { class: "small muted", text: p.towards + (p.self === "N" ? " · paid by the lender" : "") })),
        el("td", { class: "n", text: inr(p.amount) }),
        el("td", null, u ? el("a", { href: u, target: "_blank", rel: "noopener noreferrer", text: "Proof" }) : el("span", { class: "pill bad", text: "No proof" }),
          p.cert ? el("div", { class: "small muted", text: "16B " + p.cert }) : null,
          p.check ? el("div", { class: "small muted", text: p.check.slice(0, 80) }) : el("div", { class: "small" }, el("span", { class: "pill warn", text: "unchecked" })))));
    });
    const extras = A.extras.map(x => el("li", null, x.name + ": " + inr(x.amount) + (x.planned ? " (" + niceDate(x.planned) + ")" : "")));
    return det("assetz", A.title || "The flat", paid.length + " of " + ms.length + " milestones paid · " + short(pt) + " of " + short(tot) + " · next: " + (next[0] ? next[0].name + " (" + niceDate(next[0].planned) + ")" : "—"),
      el("div", null,
        el("div", { class: "strip" },
          tile("Paid so far", short(pt), [Math.round(pt / tot * 100) + "% of the price"]),
          tile("Still to come", short(tot - pt), [next.length + " near-term milestones"]),
          tile("Next TDS", next[0] ? inr(next[0].tds) : "—", [next[0] ? "2 × " + inr(next[0].tds / 2) + " · " + niceDate(next[0].planned) : ""])),
        el("h3", { class: "small muted", text: "PAYMENT PLAN" }),
        el("div", { class: "tw" }, el("table", null, el("thead", null, el("tr", null, ["#", "Milestone", "Planned", "Actual", "Total", "TDS 1%", "Net to builder", ""].map((h, i) => el("th", { class: i === 1 || i === 7 ? "" : "n", text: h })))), tb)),
        el("p", { class: "small" }, "On top of the price: "), el("ul", { class: "list small" }, extras),
        el("h3", { class: "small muted", text: "PAYMENTS AND PROOFS" }),
        el("div", { class: "tw" }, el("table", null, el("thead", null, el("tr", null, ["Date", "What", "Amount", "Proof"].map((h, i) => el("th", { class: i === 2 || i === 0 ? "n" : "", text: h })))), pays))));
  }

  function lineChart(series, opts) {
    const W = 720, H = 220, pl = 64, pr = 12, pt = 12, pb = 26;
    const n = series[0].pts.length;
    const max = Math.max.apply(null, series.flatMap(s => s.pts.map(p => p.y))) * 1.08 || 1;
    const x = i => pl + (W - pl - pr) * (n > 1 ? i / (n - 1) : 0), y = v => pt + (H - pt - pb) * (1 - v / max);
    const svg = sv("svg", { viewBox: "0 0 " + W + " " + H, class: "chart", role: "img", "aria-label": opts.label });
    for (let i = 0; i <= 4; i++) { const v = max * i / 4; svg.append(sv("line", { x1: pl, x2: W - pr, y1: y(v), y2: y(v), stroke: "var(--line)" }), sv("text", { x: pl - 6, y: y(v) + 4, "text-anchor": "end" }, short(v))); }
    const step = Math.max(1, Math.round(n / 8));
    series[0].pts.forEach((p, i) => { if (i % step === 0) svg.append(sv("text", { x: x(i), y: H - 8, "text-anchor": "middle" }, p.x)); });
    series.forEach(s => {
      svg.append(sv("path", { d: s.pts.map((p, i) => (i ? "L" : "M") + x(i).toFixed(1) + " " + y(p.y).toFixed(1)).join(" "), fill: "none", stroke: s.color, "stroke-width": 2 }));
      const L = s.pts[s.pts.length - 1]; svg.append(sv("circle", { cx: x(n - 1), cy: y(L.y), r: 3, fill: s.color }));
    });
    return el("div", null, svg, el("div", { class: "legend" }, series.map(s => el("span", null, el("i", { style: "background:" + s.color }), s.name))));
  }
  function detailsLoan() {
    const P = S.book.plan.path.slice(0, 36);
    const firstOver = P.find(r => r.interest > r.si);
    return det("loan", "Home loan · interest vs what goes in", firstOver ? "Interest passes the SI in " + firstOver.m + " (" + inr(firstOver.interest) + " vs " + inr(firstOver.si) + ")" : "SI covers interest throughout",
      el("div", null,
        lineChart([{ name: "Monthly interest", color: "var(--bad)", pts: P.map(r => ({ x: r.m.replace(" 20", " '"), y: r.interest })) },
                   { name: "Loan SI paid", color: "var(--accent)", pts: P.map(r => ({ x: r.m.replace(" 20", " '"), y: r.si })) }], { label: "Interest vs SI" }),
        lineChart([{ name: "Loan outstanding", color: "var(--ink-2)", pts: S.book.plan.path.filter((r, i) => i % 3 === 0).map(r => ({ x: r.m.replace(" 20", " '"), y: r.loan })) }], { label: "Loan balance" })));
  }
  function detailsSalary() {
    const P = S.book.plan.path.filter(r => r.m.startsWith("Jan") || r.m === S.book.plan.path[0].m);
    const tb = el("tbody");
    P.forEach(r => tb.append(el("tr", null, el("td", { text: r.m }), el("td", { class: "n", text: inr(r.salary) }), el("td", { class: "n", text: inr(r.si) }), el("td", { class: "n", text: inr(r.home) }), el("td", { class: "n", text: inr(r.child) }), el("td", { class: "n", text: inr(r.ret) }), el("td", { class: "n", text: inr(r.rent + r.living) }), el("td", { class: "n", text: short(r.ret_fund) }))));
    return det("salary", "Salary and where it goes", S.book.plan.salary_note || "",
      el("div", null,
        lineChart([{ name: "Take-home", color: "var(--accent)", pts: P.map(r => ({ x: r.m.slice(-4), y: r.salary })) }, { name: "Loan SI", color: "var(--bad)", pts: P.map(r => ({ x: r.m.slice(-4), y: r.si })) }, { name: "Retirement flow", color: "var(--ok)", pts: P.map(r => ({ x: r.m.slice(-4), y: r.ret })) }], { label: "Salary path" }),
        el("div", { class: "tw" }, el("table", null, el("thead", null, el("tr", null, ["Month", "Take-home", "Loan SI", "Home", "Child", "Retirement", "Living", "Retirement fund"].map((h, i) => el("th", { class: i ? "n" : "", text: h })))), tb))));
  }
  function detailsCards() {
    const cc = S.book.cc, ks = Object.keys(cc.months).sort();
    const W = 720, H = 200, pl = 56, pb = 24, pt = 10;
    const max = Math.max.apply(null, ks.map(k => cc.months[k].declared_total)) * 1.08;
    const bw = (W - pl - 10) / ks.length;
    const y = v => pt + (H - pt - pb) * (1 - v / max);
    const svg = sv("svg", { viewBox: "0 0 " + W + " " + H, class: "chart", role: "img", "aria-label": "Card spend by month" });
    [0, 0.5, 1].forEach(f => { const v = max * f; svg.append(sv("line", { x1: pl, x2: W - 10, y1: y(v), y2: y(v), stroke: "var(--line)" }), sv("text", { x: pl - 6, y: y(v) + 4, "text-anchor": "end" }, short(v))); });
    svg.append(sv("line", { x1: pl, x2: W - 10, y1: y(cc.budget), y2: y(cc.budget), stroke: "var(--ink)", "stroke-dasharray": "4 3" }));
    ks.forEach((k, i) => {
      const m = cc.months[k], x0 = pl + i * bw + bw * 0.2, w = bw * 0.6;
      svg.append(sv("rect", { x: x0, y: y(m.regular_total), width: w, height: (H - pb) - y(m.regular_total), fill: m.regular_total > cc.budget ? "var(--bad)" : "var(--accent)" }));
      if (m.outlier_total) svg.append(sv("rect", { x: x0, y: y(m.declared_total), width: w, height: y(m.regular_total) - y(m.declared_total), fill: "var(--bar)" }));
      svg.append(sv("text", { x: x0 + w / 2, y: H - 8, "text-anchor": "middle" }, m.label.slice(0, 3)));
    });
    const last = cc.months[ks[ks.length - 1]];
    return det("cards", "Card spend by month", "Regular spend vs the " + short(cc.budget) + " budget (dashed); grey = one-offs such as property TDS",
      el("div", null, svg, el("div", { class: "legend" }, el("span", null, el("i", { style: "background:var(--accent)" }), "Regular, under budget"), el("span", null, el("i", { style: "background:var(--bad)" }), "Regular, over"), el("span", null, el("i", { style: "background:var(--bar)" }), "One-offs")),
        el("p", { class: "small muted", text: last.label + ": " + Object.entries(last.categories).filter(e => e[1]).map(e => e[0] + " " + inr(e[1])).join(" · ") })));
  }
  function detailsStocks(rows) {
    const tb = el("tbody");
    (S.book.stocks || []).forEach(s => {
      const pr = S.prices[s.key]; const p = pr ? pr.p : null;
      const c = s.call || {};
      const rules = (s.watch || []).map(w => {
        if (w.type.startsWith("close")) { const lvl = parseFloat(w.level); const d = p ? (p - lvl) / lvl : null; return w.type + " " + lvl + (d !== null ? " (" + pct(d) + " away)" : "") + ": " + w.action; }
        return w.type + " " + w.level + ": " + w.action;
      });
      tb.append(el("tr", null,
        el("td", null, el("div", { text: s.sym }), el("div", { class: "small muted", text: s.units + " sh" })),
        el("td", { class: "n", text: p ? p.toLocaleString("en-IN", { maximumFractionDigits: 2 }) : "—" }),
        el("td", null, c.call ? el("span", { class: "pill " + (c.call === "BUY" || c.call === "ADD" ? "ok" : c.call === "HOLD" ? "info" : "bad"), text: c.call }) : "—", c.date ? el("div", { class: "small muted", text: niceDate(c.date) + " · " + (c.conviction || "") }) : null),
        el("td", { class: "n" }, c.target ? inr(c.target) : "—", c.target && p ? el("div", { class: "small muted", text: pct(c.target / p - 1) }) : null),
        el("td", null, rules.length ? el("ul", { class: "list small" }, rules.map(r => el("li", { text: r.slice(0, 160) }))) : el("span", { class: "muted", text: "—" }))));
    });
    return det("stocks", "Stocks · calls and exit rules", "Latest research call per holding; rules from each research page's Watch table",
      el("div", { class: "tw" }, el("table", null, el("thead", null, el("tr", null, ["Stock", "Price", "Call", "Target", "Watch rules"].map((h, i) => el("th", { class: i === 1 || i === 3 ? "n" : "", text: h })))), tb)));
  }
  function detailsHealth() {
    const st = S.status || {};
    const items = [
      ["Prices", S.pricesAt, "every 30 min in market hours, 22:30 IST for NAVs (GitHub Actions)"],
      ["Data bundle", S.book.built_at, "daily 07:00 IST on the Mac, and after each Finn update"],
      ["Units file", S.book.units_as_of, "changes when you trade"],
      ["Bank balance", S.book.months.bank.as_of, "you report it to Finn"],
      ["Card statement", (Object.values(S.book.cc.months).slice(-1)[0] || {}).statement_date || "", "you send it to Finn"],
    ];
    const tb = el("tbody");
    items.forEach(i => tb.append(el("tr", null, el("td", { text: i[0] }), el("td", { class: "n", text: (i[1] || "—").replace("T", " ").slice(0, 16) }), el("td", { class: "small muted", text: i[2] }))));
    const drift = S.book.drift || [], gaps = S.book.gaps || [];
    return det("health", "Data freshness and sync", (drift.length ? drift.length + " sync issue(s)" : "Sources in sync") + (gaps.length ? " · " + gaps.length + " record gap(s)" : "") + (st.prices_failed ? " · " + st.prices_failed + " price(s) failed" : ""),
      el("div", null,
        el("div", { class: "tw" }, el("table", null, tb)),
        drift.length ? el("div", null, el("h3", { class: "small muted", text: "SYNC ISSUES (state files vs sheets)" }), el("ul", { class: "list small" }, drift.map(d => el("li", { text: d })))) : null,
        gaps.length ? el("div", null, el("h3", { class: "small muted", text: "RECORD GAPS" }), el("ul", { class: "list small" }, gaps.map(d => el("li", { text: d })))) : null));
  }
})();
