/* Finn: private money dashboard. Static page: everything personal arrives encrypted (data/*.enc) and is decrypted
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
  const SLIDE_MS = 24 * 3600 * 1000, MAX_MS = 7 * 24 * 3600 * 1000;   // stay signed in: 24 h from last visit, 7 days at most
  const S = { token: null, book: null, prices: {}, pricesAt: null, status: null, month: 0, bucket: null };


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
  // ---------------------------------------------------------------- status vocabulary (two fixed sets)
  // Goals: On track · Provisioned · Watch · Act.   Tasks: Done · Due · Upcoming · Waiting.
  // Provisioned = money deliberately set aside for a known upcoming payment that hasn't been asked for yet.
  const STATUS = {
    ontrack: ["ok", "✓", "On track"], provisioned: ["info", "◷", "Provisioned"], watch: ["warn", "!", "Watch"], act: ["bad", "✕", "Act"],
    done: ["ok", "✓", "Done"], due: ["warn", "!", "Due"], overdue: ["bad", "!", "Due"], upcoming: ["info", "○", "Upcoming"], waiting: ["info", "…", "Waiting"],
  };
  function pill(kind, extra) {
    const st = STATUS[kind] || STATUS.waiting;
    return el("span", { class: "pill " + st[0] }, el("span", { class: "pill-ic", "aria-hidden": "true", text: st[1] }), st[2] + (extra ? " " + extra : ""));
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
  // Prices come from the 'data' branch (written by the price job, which can't touch site code);
  // the builder's copy on main is the fallback. Whichever is newer wins.
  const DATA_BRANCH = "https://raw.githubusercontent.com/vrajeshiyengar/finn/data/data/";
  async function fetchJSON(url) { const r = await fetch(url + "?t=" + Date.now(), { cache: "no-store" }); if (!r.ok) throw new Error("missing"); return r.json(); }
  async function latestPrices(key) {
    const tries = await Promise.allSettled([fetchJSON(DATA_BRANCH + "prices.enc").then(o => decrypt(key, o)), fetchEnc("data/prices.enc").then(o => decrypt(key, o))]);
    const got = tries.filter(t => t.status === "fulfilled").map(t => t.value);
    if (!got.length) throw new Error("No prices available");
    return got.sort((a, b) => (a.at < b.at ? 1 : -1))[0];
  }
  async function latestStatus() {
    const tries = await Promise.allSettled([fetchJSON(DATA_BRANCH + "status.json"), fetchJSON("data/status.json")]);
    const got = tries.filter(t => t.status === "fulfilled").map(t => t.value);
    if (!got.length) return null;
    const m = Object.assign({}, ...got.slice().sort((a, b) => ((a.prices_at || "") < (b.prices_at || "") ? -1 : 1)));
    m.book_built_at = got.map(g => g.book_built_at).filter(Boolean).sort().pop();
    return m;
  }
  async function fetchEnc(path) {
    const r = await fetch(path + "?t=" + Date.now(), { cache: "no-store" });
    if (!r.ok) throw new Error(path + " missing (" + r.status + ")");
    return r.json();
  }
  // ---------------------------------------------------------------- remembered session (this device only)
  // The AES key is kept as a NON-EXTRACTABLE CryptoKey in IndexedDB: page code can decrypt with it, but the raw
  // key can't be read back out. 24 h sliding expiry, 7-day cap; Sign out deletes it.
  function idb() {
    return new Promise((res, rej) => {
      const r = indexedDB.open("money-dash", 1);
      r.onupgradeneeded = () => r.result.createObjectStore("s");
      r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
    });
  }
  async function idbDo(mode, fn) {
    const db = await idb();
    return new Promise((res, rej) => {
      const tx = db.transaction("s", mode), st = tx.objectStore("s"), r = fn(st);
      tx.oncomplete = () => { db.close(); res(r && r.result); }; tx.onerror = () => { db.close(); rej(tx.error); };
    });
  }
  async function saveSession(key, created) {
    try { await idbDo("readwrite", st => st.put({ key, created: created || Date.now(), seen: Date.now() }, "session")); } catch (e) {}
  }
  async function loadSession() {
    try {
      const v = await idbDo("readonly", st => st.get("session"));
      if (!v || !v.key) return null;
      const now = Date.now();
      if (now - v.seen > SLIDE_MS || now - v.created > MAX_MS) { await clearSession(); return null; }
      return v;
    } catch (e) { return null; }
  }
  async function clearSession() { try { await idbDo("readwrite", st => st.delete("session")); } catch (e) {} }

  function skeleton() {
    const d = document.getElementById("dash");
    d.replaceChildren(el("div", { class: "skel" }, el("div", { class: "sk sk-top" }), el("div", { class: "sk-row" }, [0, 1, 2, 3].map(() => el("div", { class: "sk sk-card" }))),
      el("div", { class: "sk sk-block" }), el("div", { class: "sk sk-block" })));
    d.hidden = false; document.getElementById("lock").hidden = true;
  }
  function unskeleton() { const d = document.getElementById("dash"); d.replaceChildren(); d.hidden = true; document.getElementById("lock").hidden = false; }
  async function openWith(key) {
    skeleton();
    const [b, st] = await Promise.all([fetchEnc("data/book.enc"), latestStatus()]);
    S.book = await decrypt(key, b);
    try { S.hist = await decrypt(key, await fetchEnc("data/history.enc")); } catch (e) { S.hist = {}; }
    const pr = await latestPrices(key);
    S.prices = pr.prices || {}; S.pricesAt = pr.at; S.status = st;
    S.key = key;
    document.getElementById("lock").hidden = true;
    document.getElementById("dash").hidden = false;
    S.intro = true;
    render();
    startLive();
  }
  async function unlock() {
    msg("Signing in…");
    try {
      const key = await loadKey();
      await openWith(key);
      await saveSession(key);
    } catch (e) {
      unskeleton();
      msg(e.message || "Couldn't sign in.");
      S.token = null;
    }
  }
  async function resume() {
    const v = await loadSession();
    if (!v) return false;
    msg("Signing in…");
    try { await openWith(v.key); await saveSession(v.key, v.created); return true; }
    catch (e) { unskeleton(); await clearSession(); msg("Your session expired. Sign in again."); return false; }
  }
  function msg(t) { document.getElementById("lock-msg").textContent = t; }

  // ---------------------------------------------------------------- live: price refresh, "x min ago", change flashes
  let liveTimer = null, tickTimer = null;
  function ago(iso) {
    if (!iso) return "—";
    const m = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
    if (m < 1) return "just now"; if (m < 60) return m + " min ago";
    const h = Math.round(m / 60); if (h < 36) return h + " h ago";
    return Math.round(h / 24) + " days ago";
  }
  function marketOpen() {
    const n = istNow(), d = n.getDay(), t = n.getHours() * 60 + n.getMinutes();
    return d >= 1 && d <= 5 && t >= 555 && t <= 945;
  }
  function liveLabel() {
    const age = S.pricesAt ? (Date.now() - new Date(S.pricesAt).getTime()) / 60000 : 1e9;
    const live = marketOpen() && age < 45;
    return { live, stale: age > 26 * 60, text: (live ? "Prices live · " : "Prices · ") + ago(S.pricesAt) + " · updated " + ago(S.book && S.book.built_at) };
  }
  function tick() {
    const n = document.getElementById("live"); if (!n || !S.book) return;
    const L = liveLabel();
    n.className = "live" + (L.live ? " on" : "") + (L.stale ? " stale" : "");
    n.lastChild.textContent = L.text;
  }
  async function poll() {
    if (!S.key || document.hidden) return;
    try {
      const st = await latestStatus();
      if (!st) return;
      let changed = false;
      if (st.prices_at && st.prices_at !== S.pricesAt) {
        const pr = await latestPrices(S.key);
        const flash = {};
        Object.keys(pr.prices || {}).forEach(k => { const o = S.prices[k], n = pr.prices[k]; if (o && n && n.p !== o.p) flash[k] = n.p > o.p ? "up" : "down"; });
        S.prices = pr.prices || {}; S.pricesAt = pr.at; S.flash = flash; changed = true;
      }
      if (st.book_built_at && S.book && st.book_built_at !== S.book.built_at) {
        S.book = await decrypt(S.key, await fetchEnc("data/book.enc")); changed = true;
        try { S.hist = await decrypt(S.key, await fetchEnc("data/history.enc")); S._hm = {}; } catch (e) {}
      }
      S.status = st;
      if (changed) { render(); setTimeout(() => { S.flash = {}; document.querySelectorAll(".flash-up,.flash-down").forEach(n => n.classList.remove("flash-up", "flash-down")); }, 1800); }
    } catch (e) { /* keep showing what we have */ }
  }
  function startLive() {
    clearInterval(liveTimer); clearInterval(tickTimer);
    liveTimer = setInterval(poll, 5 * 60 * 1000);
    tickTimer = setInterval(tick, 30 * 1000);
  }
  document.addEventListener("visibilitychange", () => { if (!document.hidden && S.key) { poll(); tick(); } });

  // ---------------------------------------------------------------- motion helpers (skipped when reduced motion is on)
  const REDUCED = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  function countUps(root) {
    if (REDUCED) return;
    root.querySelectorAll("[data-count]").forEach(n => {
      const to = parseFloat(n.getAttribute("data-count")), fmt = n.getAttribute("data-fmt") || "short", final = n.textContent;
      if (!isFinite(to)) return;
      const t0 = performance.now(), dur = 700;
      const f = x => fmt === "inr" ? inr(x) : fmt === "pct" ? pct(x) : short(x);
      const step = now => { const k = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - k, 3); n.textContent = k < 1 ? f(to * e) : final; if (k < 1) requestAnimationFrame(step); };
      requestAnimationFrame(step);
    });
  }
  async function signOut() {
    clearInterval(liveTimer); clearInterval(tickTimer);
    if (S.token && window.google && google.accounts && google.accounts.oauth2) { try { google.accounts.oauth2.revoke(S.token, () => {}); } catch (e) {} }
    await clearSession();
    S.token = null; S.book = null; S.prices = {}; S.key = null;
    const d = document.getElementById("dash"); d.replaceChildren(); d.hidden = true;
    document.getElementById("lock").hidden = false;
    msg("You're signed out.");
  }
  document.addEventListener("visibilitychange", async () => {
    if (!document.hidden && S.book && !(await loadSession())) signOut();   // expired while away
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
        if (!google.accounts.oauth2.hasGrantedAllScopes(resp, "https://www.googleapis.com/auth/drive.appdata")) { msg("Allow access to the app's Drive data to sign in."); return; }
        S.token = resp.access_token; unlock();
      },
      error_callback: () => msg("Sign-in was closed or blocked."),
    });
    btn.disabled = false;
    btn.addEventListener("click", () => tc.requestAccessToken());
  }
  resume();
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
    const openIds = Array.from(root.querySelectorAll("details[open]")).map(d => d.id);
    const y = window.scrollY;
    root.replaceChildren();
    const rows = valued();
    const bt = bucketTotals(rows);
    const book = rows.reduce((a, h) => a + (h.value || 0), 0);
    const cost = rows.reduce((a, h) => a + h.cost, 0);
    const T = S.book.plan.targets;
    const tgtTotal = Object.values(T).reduce((a, b) => a + b, 0);
    const mk = monthKey(S.month), mkNow = monthKey(0);

    root.append(header(mk));
    const today = todayMove(rows);
    S._oneDayBook = oneDay(rows); S._rows = rows;
    root.append(kpiRow(book, cost, tgtTotal, mkNow, today));
    root.append(attention(rows, bt, T, mkNow));
    root.append(viewGoals(bt, T, book, tgtTotal));
    root.append(viewHoldings(rows, bt));
    root.append(viewChecklist(mk));
    root.append(viewBank(mk));
    root.append(viewCalendar(mk));
    root.append(detailsFlat(), detailsLoan(), detailsSalary(), detailsCards(), detailsStocks(rows), detailsHealth());
    stackTables(root);
    openIds.forEach(id => { const d = document.getElementById(id); if (d) d.open = true; });
    window.scrollTo(0, y);
    root.querySelectorAll("h2").forEach(h => {          // a finished state gets an animated check mark
      if (!h.textContent.startsWith("✓ ")) return;
      const rest = h.textContent.slice(2);
      const ck = sv("svg", { viewBox: "0 0 24 24", class: "ck", "aria-hidden": "true" });
      ck.append(sv("path", { d: "M5 12.5l4.5 4.5L19 7.5", fill: "none", stroke: "var(--ok)", "stroke-width": 2.6, "stroke-linecap": "round", "stroke-linejoin": "round" }));
      h.replaceChildren(ck, document.createTextNode(rest));
    });
    if (S.intro) {
      root.classList.add("intro"); countUps(root); S.intro = false;
      setTimeout(() => root.classList.remove("intro"), 2200);
    }
    if (S.swap) { root.classList.add("swap"); S.swap = false; setTimeout(() => root.classList.remove("swap"), 500); }
  }

  // Phone pattern: each table row becomes a card; cells carry their column name for the label.
  function stackTables(root) {
    root.querySelectorAll("table").forEach(t => {
      t.classList.add("stack");
      const heads = Array.from(t.querySelectorAll(":scope > thead > tr > th")).map(th => th.textContent.trim());
      const fallback = t.dataset.labels ? t.dataset.labels.split("|") : [];
      t.querySelectorAll(":scope > tbody > tr").forEach(tr => {
        Array.from(tr.children).forEach((td, i) => {
          const lab = heads[i] || fallback[i] || "";
          if (lab && !td.hasAttribute("data-label")) td.setAttribute("data-label", lab);
        });
      });
    });
  }

  function signOutBtn() {
    const ic = sv("svg", { viewBox: "0 0 24 24", width: 16, height: 16, "aria-hidden": "true", class: "ic" });
    ic.append(sv("path", { d: "M10 4H5a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h5", fill: "none", stroke: "currentColor", "stroke-width": 2, "stroke-linecap": "round" }),
              sv("path", { d: "M15 8l4 4-4 4M19 12H9", fill: "none", stroke: "currentColor", "stroke-width": 2, "stroke-linecap": "round", "stroke-linejoin": "round" }));
    return el("button", { type: "button", class: "ghost signout", title: "Sign out", "aria-label": "Sign out", onclick: () => signOut() }, ic, el("span", { text: "Sign out" }));
  }
  function header(mk) {
    const seg = el("div", { class: "seg", role: "group", "aria-label": "Month" },
      el("button", { type: "button", "aria-pressed": S.month === 0 ? "true" : "false", onclick: () => { if (S.month !== 0) { S.month = 0; S.swap = true; render(); } }, text: monthLabel(monthKey(0)).split(" ")[0] + " (now)" }),
      el("button", { type: "button", "aria-pressed": S.month === 1 ? "true" : "false", onclick: () => { if (S.month !== 1) { S.month = 1; S.swap = true; render(); } }, text: monthLabel(monthKey(1)).split(" ")[0] + " (next)" }));
    const when = S.pricesAt ? new Date(S.pricesAt) : null;
    const age = when ? (Date.now() - when.getTime()) / 3600000 : 99;
    return el("div", { class: "top" },
      el("div", null, el("div", { class: "brand-row" }, el("img", { src: "assets/finn-mark-2.png", alt: "", class: "brand-mark sm", width: 28, height: 28 }), el("h1", { text: "Finn" })),
        (function () { const L = liveLabel(); return el("div", { id: "live", class: "live" + (L.live ? " on" : "") + (L.stale ? " stale" : ""), role: "status" }, el("span", { class: "dot", "aria-hidden": "true" }), el("span", { text: L.text })); })()),
      el("div", { class: "top-actions" }, seg,
        signOutBtn()),
      el("nav", { class: "jump", "aria-label": "Sections" },
        [["goals", "Goals"], ["holdings", "Holdings"], ["checklist", "This month"], ["bank", "Bank"], ["calendar", "Calendar"], ["flat", "Flat"], ["loan", "Loan"], ["cards", "Card"], ["stocks", "Stocks"], ["health", "Health"]]
          .map(([id, lab]) => el("a", { href: "#" + id, onclick: (e) => { e.preventDefault(); const t = document.getElementById(id); if (t) { if (t.tagName === "DETAILS") t.open = true; t.scrollIntoView({ behavior: "smooth", block: "start" }); } }, text: lab }))));
  }

  // ---------------------------------------------------------------- KPI row (≤5 cards; the primary one is the plan check)
  const ARROW = v => v > 0 ? "▲" : v < 0 ? "▼" : "■";
  // 1D change: latest price vs previous market close (stocks/ETFs) or previous NAV (funds), per unit held.
  // lines: valued holding rows; bucket: optional bucket key to weight by that bucket's share.
  function oneDay(lines, bucket) {
    let d = 0, base = 0;
    lines.forEach(h => {
      const w = bucket ? (h.buckets[bucket] || 0) : 1;
      if (!w) return;
      const pr = h.key ? S.prices[h.key] : null;
      if (pr && pr.pc && pr.p !== null && !h.pending) { d += h.units * w * (pr.p - pr.pc); base += h.units * w * pr.pc; }
      else base += (h.value || 0) * w;
    });
    return { d, base, pct: base ? d / base : 0 };
  }
  function d1(o, opts) {
    if (!o || (!o.d && !(opts && opts.showZero))) return el("div", { class: "d1 flat", text: "1D —" });
    const cls = o.d > 0 ? "upc" : o.d < 0 ? "dn" : "flat";
    return el("div", { class: "d1 " + cls, title: "Change since the previous market close (stocks/ETFs) or previous NAV (funds)" },
      "1D " + (o.d > 0 ? "▲ " : o.d < 0 ? "▼ " : "") + short(Math.abs(o.d)) + " (" + pct(o.pct, 2) + ")");
  }
  function todayMove(rows) {
    let d = 0, base = 0; const movers = [];
    rows.forEach(h => {
      if (!h.key || h.pending) return;
      const pr = S.prices[h.key]; if (!pr || !pr.pc || pr.p === null) return;
      const ch = h.units * (pr.p - pr.pc); d += ch; base += h.units * pr.pc;
      movers.push({ name: h.name.replace(/\s*\(.*?\)\s*/g, " ").trim(), ch, pc: pr.p / pr.pc - 1 });
    });
    movers.sort((a, b) => a.ch - b.ch);
    return { d, pct: base ? d / base : 0, worst: movers.slice(0, 3), best: movers.slice(-3).reverse() };
  }
  function sparkline(vals, opts) {
    const W = 220, H = 44, p = 3;
    const svg = sv("svg", { viewBox: "0 0 " + W + " " + H, class: "spark", role: "img", "aria-label": opts.label });
    if (vals.length < 2) { svg.append(sv("text", { x: 0, y: H / 2 + 4 }, "trend builds daily")); return svg; }
    const lo = Math.min.apply(null, vals.concat(opts.band ? [-opts.band] : [])), hi = Math.max.apply(null, vals.concat(opts.band ? [opts.band] : []));
    const x = i => p + (W - 2 * p) * i / (vals.length - 1), y = v => p + (H - 2 * p) * (1 - (v - lo) / ((hi - lo) || 1));
    if (opts.band) svg.append(sv("rect", { x: p, y: y(opts.band), width: W - 2 * p, height: Math.max(1, y(-opts.band) - y(opts.band)), fill: "var(--accent-soft)" }));
    if (opts.zero) svg.append(sv("line", { x1: p, x2: W - p, y1: y(0), y2: y(0), stroke: "var(--ink-3)", "stroke-dasharray": "3 3" }));
    svg.append(sv("path", { d: vals.map((v, i) => (i ? "L" : "M") + x(i).toFixed(1) + " " + y(v).toFixed(1)).join(" "), fill: "none", stroke: "var(--ink)", "stroke-width": 1.6 }));
    svg.append(sv("circle", { cx: x(vals.length - 1), cy: y(vals[vals.length - 1]), r: 3, fill: "var(--accent)" }));
    return svg;
  }
  function kpiRow(book, cost, tgtTotal, mkNow, today) {
    const gap = book - tgtTotal, gp = gap / tgtTotal, band = S.book.plan.band;
    const lp = leftParts(monthData(mkNow));
    const sp = spendable(mkNow);
    const hist = (S.book.history || []).filter(r => r.target);
    const gaps = hist.map(r => (r.total - r.target) / r.target);
    gaps[gaps.length - 1] = gp;                       // today's point priced live
    const status = Math.abs(gp) <= band ? "ontrack" : gp < 0 ? "act" : "watch";
    const headline = Math.abs(gp) <= band
      ? (gap < 0 ? short(-gap) + " behind plan, inside the ±" + Math.round(band * 100) + "% band" : short(gap) + " ahead of plan")
      : (gap < 0 ? short(-gap) + " behind plan: outside the band" : short(gap) + " ahead of plan");
    const primary = el("div", { class: "kpi primary" },
      el("div", { class: "lab", text: "Book vs " + (S.book.plan.name || "plan") }),
      el("div", { class: "kpi-head" }, el("span", { class: "big", "data-count": gp, "data-fmt": "pct", text: pct(gp) }), pill(status)),
      el("div", { class: "sub", text: headline }),
      d1(S._oneDayBook),
      sparkline(gaps, { band, zero: true, label: "Gap to plan over time, now " + pct(gp) + "; shaded band is ±" + Math.round(band * 100) + "%" }),
      el("div", { class: "sub muted", text: "Book " + inr(book) + " · plan " + inr(tgtTotal) + " · " + hist.length + " day trend" }));
    const tCls = S._oneDayBook.d > 0 ? "up" : S._oneDayBook.d < 0 ? "down" : "";
    return el("div", { class: "kpis" }, primary,
      el("div", { class: "kpi" }, el("div", { class: "lab", text: "Book value (live)" }), el("div", { class: "big", "data-count": Math.round(book), text: short(book) }),
        el("div", { class: "sub " + tCls, text: "1D " + ARROW(S._oneDayBook.d) + " " + inr(S._oneDayBook.d, { sign: true }) + " (" + pct(S._oneDayBook.pct, 2) + ") vs last close / NAV" }),
        el("div", { class: "sub muted", text: inr(book - cost, { sign: true }) + " on cost " + short(cost) })),
      el("div", { class: "kpi" }, el("div", { class: "lab", text: "Salary left to invest · " + monthLabel(mkNow).split(" ")[0] }), el("div", { class: "big", "data-count": lp.salary, "data-fmt": "inr", text: inr(lp.salary) }),
        el("div", { class: "sub", text: lp.salary > 0 ? "due this month" : "✓ all of this month's salary is invested" }),
        lp.other ? el("div", { class: "sub muted", text: short(lp.other) + " of proceeds still to deploy" }) : null),
      el("div", { class: "kpi" }, el("div", { class: "lab", text: "Spendable in bank" }), el("div", { class: "big", "data-count": Math.round(sp.result), "data-fmt": "inr", text: inr(sp.result) }),
        el("div", { class: "sub", text: "after earmarks · balance as of " + niceDate(S.book.months.bank.as_of) })));
  }

  // ---------------------------------------------------------------- Needs attention (status · driver · action)
  function attention(rows, bt, T, mkNow) {
    const items = [], today = ymd(istNow()), band = S.book.plan.band;
    const soon = new Date(istNow().getTime() + 3 * 86400000);
    const soonS = ymd(soon);
    // calendar actions due in the next 3 days
    (S.book.calendar || []).filter(e => !e.done && e.date >= today && e.date <= soonS).forEach(e =>
      items.push({ sev: e.date === today ? 2 : 1, what: (e.date === today ? "Today" : niceDate(e.date)) + (e.time ? " " + e.time : "") + " · " + e.title, act: "On your calendar", jump: "calendar" }));
    // buckets outside the band
    S.book.bucket_defs.forEach(b => {
      const v = bt[b.key] || 0, t = T[b.key] || 0; if (!t) return;
      const g = (v - t) / t;
      if (g < -band) {
        const drags = rows.filter(h => h.buckets[b.key] && h.value !== null && h.cost).map(h => ({ n: h.name.replace(/\s*\(.*?\)\s*/g, " ").trim(), d: (h.value - h.cost) * h.buckets[b.key] })).sort((a, c) => a.d - c.d).slice(0, 3);
        const bookOk = Math.abs((Object.keys(bt).reduce((a, k) => a + bt[k], 0) - Object.values(T).reduce((a, x) => a + x, 0)) / Object.values(T).reduce((a, x) => a + x, 0)) <= band;
        items.push({ sev: bookOk ? 1 : 2, what: b.label + " is " + pct(g) + " vs plan (" + inr(v - t, { sign: true }) + ")", why: "Biggest drags: " + drags.map(x => x.n + " " + inr(x.d, { sign: true })).join(", "), act: "Market, not missed money: no top-up. Exit rules and results checks handle the weak names.", jump: "goals" });
      }
    });
    // stock rules close to firing
    (S.book.stocks || []).forEach(st => {
      const pr = S.prices[st.key]; if (!pr) return;
      (st.watch || []).forEach(w => {
        if (!w.type.startsWith("close")) return;
        const lvl = parseFloat(w.level); if (!lvl) return;
        const d = (pr.p - lvl) / lvl, below = w.type === "close<";
        const breached = below ? pr.p < lvl : pr.p > lvl;
        if (breached) items.push({ sev: 3, what: st.sym + " at " + pr.p.toFixed(2) + " is past its " + w.type + " " + lvl + " line", act: w.action, jump: "stocks" });
        else if (below && d < 0.03) items.push({ sev: 1, what: st.sym + " is " + pct(d) + " above its exit line " + lvl, act: "If it closes below: " + w.action, jump: "stocks" });
      });
    });
    // TDS the builder has asked for
    (((S.book.ledgers || {}).home_tds || {}).requested || []).forEach(r =>
      items.push({ sev: 2, what: "Pay TDS " + inr(r.amount) + " for milestone " + r.milestone, act: (S.book.plan.tds_action || "File the TDS forms") + "; then tell Finn", jump: "goals" }));
    // salary money not yet invested
    const lp = leftParts(monthData(mkNow));
    if (lp.salary > 0) items.push({ sev: 2, what: inr(lp.salary) + " of " + monthLabel(mkNow) + " salary money is not invested yet", act: "See the month checklist", jump: "checklist" });
    // pending allotments
    const pend = rows.filter(h => h.pending);
    if (pend.length) items.push({ sev: 1, what: pend.length + " order(s) awaiting allotment (" + short(pend.reduce((a, h) => a + h.cost, 0)) + ")", act: "Valued at cost until units arrive", jump: "holdings" });
    // loan interest overtaking the SI
    const P = S.book.plan.path, cur = P.findIndex(r => r.m === monthLabel(mkNow));
    const over = P.slice(Math.max(0, cur), cur + 3).find(r => r.interest > r.si);
    if (over) items.push({ sev: 1, what: "From " + over.m + ", loan interest " + inr(over.interest) + " exceeds the SI " + inr(over.si), act: "Raise the SI or prepay (decision on your calendar)", jump: "loan" });
    // data health
    if ((S.book.drift || []).length) items.push({ sev: 2, what: S.book.drift.length + " sync issue(s) between the dashboard and your sheets", act: "Ask Finn to reconcile", jump: "health" });
    const age = S.pricesAt ? (Date.now() - new Date(S.pricesAt).getTime()) / 3600000 : 99;
    if (age > 26) items.push({ sev: 2, what: "Prices are " + Math.round(age) + " h old", act: "Check the price job (Health)", jump: "health" });

    items.sort((a, b) => b.sev - a.sev);
    const icon = s => s >= 3 ? ["bad", "✕"] : s === 2 ? ["warn", "!"] : ["info", "i"];
    const list = el("ul", { class: "attn" }, items.map(it => {
      const ic = icon(it.sev);
      return el("li", null, el("span", { class: "attn-ic " + ic[0], "aria-hidden": "true", text: ic[1] }),
        el("div", null, el("div", { class: "attn-what", text: it.what }), it.why ? el("div", { class: "meta", text: it.why }) : null,
          el("div", { class: "small" }, el("span", { class: "muted", text: "→ " }), it.act, it.jump ? el("a", { href: "#" + it.jump, class: "attn-go", onclick: (e) => { e.preventDefault(); const t = document.getElementById(it.jump); if (t) { if (t.tagName === "DETAILS") t.open = true; t.scrollIntoView({ behavior: "smooth" }); } }, text: " View" }) : null)));
    }));
    const need = items.filter(i => i.sev >= 2).length, watch = items.length - need;
    const title = need ? need + " item" + (need > 1 ? "s" : "") + " need" + (need > 1 ? "" : "s") + " you" + (watch ? " · " + watch + " to watch" : "") : "✓ Nothing needs you right now" + (watch ? " · " + watch + " to watch" : "");
    return el("section", { class: "view attention", id: "attention", "aria-label": "Needs attention" },
      el("header", null, el("div", null, el("div", { class: "eyebrow", text: "Needs attention" }), el("h2", { text: title }))),
      items.length ? list : el("p", { class: "muted", text: "All buckets inside the band, no rule close to firing, data fresh." }));
  }
  function tile(lab, big, sub) { return el("div", { class: "tile" }, el("div", { class: "lab", text: lab }), el("div", { class: "big", text: big }), el("div", { class: "sub" }, sub)); }

  // ---- view 1
  function goalsInsight(bt, T) {
    const band = S.book.plan.band;
    const gaps = S.book.bucket_defs.map(b => ({ l: b.label, g: (bt[b.key] || 0) - (T[b.key] || 0), t: T[b.key] || 0 })).filter(x => x.t);
    const worst = gaps.slice().sort((a, b) => a.g - b.g)[0];
    const out = gaps.filter(x => Math.abs(x.g / x.t) > band && x.g < 0);
    if (!out.length) return "Every bucket is on track; the biggest gap is " + worst.l + " at " + inr(worst.g, { sign: true });
    const o = out.sort((a, b) => a.g - b.g);
    return o.map(x => x.l + " is " + short(-x.g) + " behind (" + pct(x.g / x.t) + ")").join("; ") + "; " + (gaps.length - o.length === 0 ? "" : "every other bucket is on track or ahead");
  }
  // Waterfall: plan total → each bucket's gap → actual total. Orange = below plan, blue = above (colour-blind safe), signs on every bar.
  function gapBars(bt, T, book, tgtTotal) {
    const parts = S.book.bucket_defs.map(b => ({ l: b.label, d: (bt[b.key] || 0) - (T[b.key] || 0) })).filter(x => Math.abs(x.d) >= 500).sort((a, b) => a.d - b.d);
    const max = Math.max.apply(null, parts.map(p => Math.abs(p.d)).concat([1]));
    return el("figure", { class: "gapbars", "aria-label": "Gap to plan by bucket. " + parts.map(p => p.l + " " + inr(p.d, { sign: true })).join(", ") },
      el("div", { class: "gb-row gb-total" }, el("span", { text: "Plan today" }), el("span", { class: "num", text: inr(tgtTotal) })),
      parts.map(p => el("div", { class: "gb-row" }, el("span", { text: p.l }),
        el("span", { class: "gb-track" }, el("i", { class: p.d < 0 ? "neg" : "pos", style: "width:" + (Math.abs(p.d) / max * 50).toFixed(1) + "%;" + (p.d < 0 ? "right:50%" : "left:50%") })),
        el("span", { class: "num " + (p.d < 0 ? "dn" : "upc"), text: (p.d < 0 ? "▼ " : "▲ ") + short(Math.abs(p.d)) }))),
      el("div", { class: "gb-row gb-total" }, el("span", { text: "Actual" }), el("span", { class: "num", text: inr(book) })));
  }
  function gapWaterfall(bt, T, book, tgtTotal) {
    if (window.matchMedia && window.matchMedia("(max-width: 640px)").matches) return gapBars(bt, T, book, tgtTotal);
    const parts = S.book.bucket_defs.map(b => ({ l: b.label, d: (bt[b.key] || 0) - (T[b.key] || 0) })).filter(x => Math.abs(x.d) >= 500).sort((a, b) => b.d - a.d);
    const W = 720, H = 210, pl = 8, pr = 8, pt = 22, pb = 46;
    const steps = [{ l: "Plan today", v: tgtTotal, kind: "total" }].concat(parts.map(p => ({ l: p.l, v: p.d, kind: "delta" }))).concat([{ l: "Actual", v: book, kind: "total" }]);
    let run = tgtTotal; const bars = [];
    steps.forEach(st => {
      if (st.kind === "total") bars.push({ l: st.l, a: 0, b: st.v, v: st.v, kind: "total" });
      else { bars.push({ l: st.l, a: run, b: run + st.v, v: st.v, kind: st.v < 0 ? "neg" : "pos" }); run += st.v; }
    });
    // zoom the y-axis to the top of the bars so the deltas are visible; mark the axis break
    const tops = bars.map(b => Math.max(b.a, b.b)).concat(bars.filter(b => b.kind !== "total").map(b => Math.min(b.a, b.b)));
    const hi = Math.max.apply(null, tops), lo = Math.min.apply(null, bars.filter(b => b.kind !== "total").map(b => Math.min(b.a, b.b)).concat([Math.min(book, tgtTotal)]));
    const span = (hi - lo) || 1, floor = lo - span * 0.6, ceil = hi + span * 0.15;
    const y = v => pt + (H - pt - pb) * (1 - (Math.max(v, floor) - floor) / (ceil - floor));
    const bw = (W - pl - pr) / bars.length;
    const svg = sv("svg", { viewBox: "0 0 " + W + " " + H, class: "chart", role: "img",
      "aria-label": "Waterfall from plan " + inr(tgtTotal) + " to actual " + inr(book) + ". " + parts.map(p => p.l + " " + inr(p.d, { sign: true })).join(", ") + "." });
    svg.append(sv("line", { x1: pl, x2: W - pr, y1: y(tgtTotal), y2: y(tgtTotal), stroke: "var(--ink-3)", "stroke-dasharray": "4 3" }));
    bars.forEach((b, i) => {
      const x0 = pl + i * bw + bw * 0.18, w = bw * 0.64;
      const top = y(Math.max(b.a, b.b)), bot = b.kind === "total" ? H - pb : y(Math.min(b.a, b.b));
      const fill = b.kind === "total" ? "var(--ink-2)" : b.kind === "neg" ? "var(--neg)" : "var(--pos)";
      svg.append(sv("rect", { x: x0, y: top, width: w, height: Math.max(2, bot - top), fill, rx: 2 }));
      svg.append(sv("text", { x: x0 + w / 2, y: top - 6, "text-anchor": "middle", class: "wf-v" }, b.kind === "total" ? short(b.v) : (b.v > 0 ? "▲ " : "▼ ") + short(Math.abs(b.v))));
      const words = b.l.split(/[: ]+/).filter(Boolean); const l1 = words.slice(0, 2).join(" "), l2 = words.slice(2).join(" ");
      svg.append(sv("text", { x: x0 + w / 2, y: H - pb + 16, "text-anchor": "middle" }, l1));
      if (l2) svg.append(sv("text", { x: x0 + w / 2, y: H - pb + 30, "text-anchor": "middle" }, l2));
      if (i < bars.length - 1 && b.kind !== "total" || i === 0) {
        const lvl = b.kind === "total" ? b.b : b.b;
        svg.append(sv("line", { x1: x0 + w, x2: x0 + bw, y1: y(lvl), y2: y(lvl), stroke: "var(--ink-3)" }));
      }
    });

    return el("figure", { class: "wf-fig" }, svg,
      el("figcaption", { class: "meta", text: "How the book gets from the plan to today's value: ▼ orange is below plan, ▲ blue is above. Dashed line = plan." }));
  }

  // Cash-flow bucket ledger: planned vs actual money in and out to date, the growth that's left over, and why it differs.
  function ledgerBlock(L, value) {
    const net = L.act_in - L.act_out, growth = value - net;
    const sumLine = "In " + short(L.act_in) + " of " + short(L.plan_in) + " planned · Out " + short(L.act_out) + " of " + short(L.plan_out) + " planned · growth " + inr(growth, { sign: true });
    const tb = el("tbody");
    const rows = L.planned.map(p => ({ d: p.date, label: p.label, dir: p.dir, plan: p.amount, act: p.matched ? p.amount : null, flag: p.matched ? "ok" : p.requested ? "due" : p.provisioned ? "prov" : (p.date > ymd(istNow()) ? "up" : "miss") }));
    const matchedActs = new Set();
    L.actual.forEach(a => {
      const hit = rows.find(r => r.dir === a.dir && r.act !== null && Math.abs(r.plan - a.amount) <= 1000 && !matchedActs.has(r));
      if (hit) { matchedActs.add(hit); hit.act = a.amount; hit.how = a.how; hit.ad = a.date; }
      else rows.push({ d: a.date, label: a.label, dir: a.dir, plan: null, act: a.amount, flag: "extra", how: a.how });
    });
    rows.sort((a, b) => (a.ad || a.d) < (b.ad || b.d) ? -1 : 1).forEach(r => {
      const sign = r.dir === "out" ? -1 : 1;
      const st = r.flag === "ok" || r.flag === "extra" ? "done" : r.flag === "up" ? "upcoming" : r.flag === "prov" ? "provisioned" : r.flag === "due" ? "due" : "waiting";
      tb.append(el("tr", null,
        el("td", null, el("div", { text: (r.dir === "out" ? "Out · " : "In · ") + r.label }), r.how ? el("div", { class: "meta", text: r.how }) : null),
        el("td", { class: "n", text: niceDate(r.ad || r.d) }),
        el("td", { class: "n", text: r.plan === null ? "—" : inr(sign * r.plan, { sign: true }) }),
        el("td", { class: "n", text: r.act === null ? "—" : inr(sign * r.act, { sign: true }) }),
        el("td", null, pill(st), r.flag === "extra" ? el("div", { class: "meta", text: "not in the plan" }) : null)));
    });
    tb.append(el("tr", { class: "total" }, el("td", { text: "Growth / market (value − net money in)" }), el("td"), el("td"), el("td", { class: "n", text: inr(growth, { sign: true }) }), el("td")));
    const why = (L.reasons || []).filter(r => !r.startsWith("Upcoming"));
    const whyCls = why.length && why[0].startsWith("Provisioned") ? "why info" : "why";
    return el("div", { class: "ledger" },
      el("p", { class: "meta", text: sumLine }), why.length ? el("p", { class: whyCls, text: why[0] }) : null,
      el("div", { class: "tw" }, el("table", { class: "ledger-t" }, el("thead", null, el("tr", null, ["Flow", "Date", "Planned", "Actual", ""].map((h, i) => el("th", { class: i === 0 || i === 4 ? "" : "n", text: h })))), tb)),
      (L.reasons || []).length ? el("ul", { class: "list small" }, L.reasons.map(r => el("li", { text: r }))) : null);
  }

  // ---- view 1: goal rows (icon/ring · name + goal · Now | Plan | Gap · status · chevron), expanding in place
  function goalStatus(v, t, band, L) {
    if (!t) return "ontrack";
    const g = (v - t) / t;
    if (Math.abs(g) <= band) return "ontrack";
    if (L && L.provisioned && Math.abs((v - t - L.provisioned) / t) <= band) return "provisioned";
    const book = S._book, tgt = S._tgt;
    if (g < 0 && Math.abs((book - tgt) / tgt) > band) return "act";
    return "watch";
  }
  const ICONS = {   // 24×24 line icons
    emergency: "M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z",
    home_tds: "M7 3h10v18l-2.5-1.5L12 21l-2.5-1.5L7 21V3zM9.5 8h5M9.5 11.5h5M9.5 15h3",
    home_fund: "M4 11l8-7 8 7M6 9.5V20h12V9.5M10 20v-5h4v5",
    loan_reserve: "M3 9l9-5 9 5M5 10v8M9.5 10v8M14.5 10v8M19 10v8M3 20h18",
    childcare: "M12 20s-7-4.3-7-9.5A4 4 0 0 1 12 8a4 4 0 0 1 7 2.5C19 15.7 12 20 12 20z",
    retirement: "M12 4v2M5 12H3M21 12h-2M6.3 6.3l1.4 1.4M17.7 6.3l-1.4 1.4M7 16a5 5 0 0 1 10 0M3 19h18",
  };
  function ring(frac, key) {
    const R = 19, C = 2 * Math.PI * R, f = Math.max(0, Math.min(1, frac || 0));
    const svg = sv("svg", { viewBox: "0 0 48 48", class: "ring", "aria-hidden": "true" });
    svg.append(sv("circle", { cx: 24, cy: 24, r: R, fill: "none", stroke: "var(--line)", "stroke-width": 4 }));
    if (frac !== null) {
      const arc = sv("circle", { cx: 24, cy: 24, r: R, fill: "none", stroke: "var(--accent)", "stroke-width": 4, "stroke-linecap": "round",
        "stroke-dasharray": C.toFixed(2), "stroke-dashoffset": (C * (1 - f)).toFixed(2), transform: "rotate(-90 24 24)", class: "ring-arc" });
      arc.style.setProperty("--c", C.toFixed(2)); svg.append(arc);
    }
    const g = sv("g", { transform: "translate(14 14) scale(0.8333)" });
    g.append(sv("path", { d: ICONS[key] || ICONS.retirement, fill: "none", stroke: "var(--ink-2)", "stroke-width": 1.8, "stroke-linecap": "round", "stroke-linejoin": "round" }));
    svg.append(g);
    return svg;
  }
  function bucketHoldings(key) {
    const rows = valued().filter(h => h.buckets[key]).map(h => ({ h, v: (h.value || 0) * h.buckets[key], c: h.cost * h.buckets[key] })).sort((a, b) => b.v - a.v);
    if (!rows.length) return el("p", { class: "meta", text: "Nothing in this bucket yet." });
    return el("ul", { class: "mini" }, rows.map(r => el("li", null,
      el("span", { class: "rowtitle", text: r.h.name.replace(/\s*\(.*?\)\s*/g, " ").trim() + (Object.keys(r.h.buckets).length > 1 ? " · " + Math.round(r.h.buckets[key] * 100) + "%" : "") }),
      el("span", { class: "num", text: inr(r.v) }),
      el("span", { class: "meta num " + (r.v - r.c >= 0 ? "upc" : "dn"), text: delta(r.v - r.c, r.c) }))));
  }
  function delta(d, base) {
    if (d === null || isNaN(d)) return "—";
    return (d > 0 ? "▲ " : d < 0 ? "▼ " : "") + short(Math.abs(d)) + (base ? " (" + pct(d / base) + ")" : "");
  }
  function viewGoals(bt, T, book, tgtTotal) {
    const G = S.book.plan.goals, band = S.book.plan.band;
    S._book = book; S._tgt = tgtTotal;
    S.openB = S.openB || {};
    const wrap = el("div", { class: "goals" });
    S.book.bucket_defs.forEach(b => {
      const v = bt[b.key] || 0, t = T[b.key] || 0, g = G[b.key] || {};
      if (!v && !t && !g.target) return;
      const gap = v - t;
      const goal = g.target || (b.key === "home_tds" && g.outflows ? g.outflows.reduce((a, o) => a + o[1], 0) : null);
      const goalLine = b.key === "retirement" ? "Goal " + short(goal) + " · plan path " + short(g.projection_dec_2036) + " by Dec 2036"
        : b.key === "home_tds" ? (function () { const Lt = (S.book.ledgers || {}).home_tds || {}; if ((Lt.requested || []).length) return short(Lt.requested.reduce((a, r) => a + r.amount, 0)) + " TDS asked for by the builder, due soon · "; return Lt.provisioned ? short(Lt.provisioned) + " provisioned for a TDS ask not received yet · " : ""; })() + "covers the next " + (g.outflows || []).length + " TDS payments"
        : goal ? "Goal " + short(goal) + (g.date ? " by " + niceDate(g.date) : "") : b.note;
      const open = !!S.openB[b.key];
      const toggle = () => { S.openB[b.key] = !open; render(); };
      const row = el("div", { class: "goal" + (open ? " open" : ""), role: "button", tabindex: "0", "aria-expanded": open ? "true" : "false",
        onclick: toggle, onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } } },
        ring(goal ? v / goal : null, b.key),
        el("div", { class: "g-name" }, el("div", { class: "rowtitle", text: b.label }), el("div", { class: "meta", text: goalLine })),
        el("div", { class: "g-cols" },
          el("div", null, el("div", { class: "lab", text: "Now" }), el("div", { class: "num", "data-count": Math.round(v), text: short(v) }), d1(oneDay((S._rows || []).filter(h => h.buckets[b.key]), b.key))),
          el("div", null, el("div", { class: "lab", text: "Plan" }), el("div", { class: "num", text: short(t) })),
          el("div", null, el("div", { class: "lab", text: "Gap" }), el("div", { class: "num " + (gap < 0 ? "dn" : gap > 0 ? "upc" : ""), text: t ? delta(gap) : "—" }))),
        pill(goalStatus(v, t, band, (S.book.ledgers || {})[b.key])),
        el("span", { class: "chev", "aria-hidden": "true", text: "›" }));
      wrap.append(row);
      if (open) {
        const L = (S.book.ledgers || {})[b.key];
        const extra = [];
        if (b.key === "home_fund") {
          const st = S.book.plan.stress || {}; const k = Object.keys(st)[0];
          extra.push(el("p", { class: "meta", text: "Funded " + Math.round((S.book.plan.funded_now || 0) * 100) + "% of the goal, counting the money still to come" + (k ? " · stress case (" + k + "): short by " + short(st[k]) : "") }));
        }
        if (b.key === "loan_reserve" && g.alt_note) extra.push(el("p", { class: "meta", text: g.alt_note }));
        wrap.append(el("div", { class: "g-panel" },
          extra,
          L ? el("div", null, el("div", { class: "lab", text: "Money in and out" }), ledgerBlock(L, v)) : null,
          el("div", null, el("div", { class: "lab", text: "What's in it" }), bucketHoldings(b.key))));
      }
    });
    const adj = Array.from(new Set((S.book.plan.active_adjustments || []).map(a => a.replace(/ \(money still sits[^)]*\)/, ""))));
    return el("section", { class: "view", id: "goals" },
      el("header", null, el("div", null, el("div", { class: "eyebrow", text: "Goals" }), el("h2", { text: goalsInsight(bt, T) }),
        el("div", { class: "meta", text: "Against " + (S.book.plan.name || "the plan") + " for " + S.book.plan.target_month + " · on track within ±" + Math.round(band * 100) + "% · open a bucket for its money in and out" }))),
      gapWaterfall(bt, T, book, tgtTotal),
      wrap,
      adj.length ? el("p", { class: "meta", text: "Plan timing: " + adj.join("; ") }) : null);
  }

  function holdingsInsight(rows) {
    const t = todayMove(rows);
    const f = (m) => m.name.split(" ").slice(0, 3).join(" ") + " " + pct(m.pc);
    if (!t.best.length) return "Units × latest price, split by bucket";
    return "Last move " + ARROW(t.d) + " " + inr(t.d, { sign: true }) + " · best " + f(t.best[0]) + " · worst " + f(t.worst[0]);
  }
  // ---- view 2: holdings, one row per instrument per bucket, expandable to its purchases; value over time
  const WINDOWS = [["1D", 1], ["1W", 7], ["1M", 30], ["3M", 91], ["6M", 182], ["1Y", 365], ["All", 99999]];
  const DAY = 86400000;
  function histMap(key) {          // key → sorted [[ms, price]] with today's live price appended
    S._hm = S._hm || {};
    if (S._hm[key] && S._hm[key].at === S.pricesAt) return S._hm[key].pts;
    const h = (S.hist || {})[key]; const pts = [];
    if (h && h.p) { const d0 = Date.parse(h.s + "T00:00:00+05:30"); h.d.forEach((off, i) => pts.push([d0 + off * DAY, h.p[i]])); }
    const live = S.prices[key];
    if (live && live.p) { const t = Date.parse(ymd(istNow()) + "T00:00:00+05:30"); if (!pts.length || pts[pts.length - 1][0] < t) pts.push([t, live.p]); else pts[pts.length - 1][1] = live.p; }
    S._hm[key] = { at: S.pricesAt, pts };
    return pts;
  }
  function priceAt(pts, t) {        // last price on or before t (carry forward); first price if t is earlier
    if (!pts.length) return null;
    let lo = 0, hi = pts.length - 1;
    if (t < pts[0][0]) return pts[0][1];
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (pts[mid][0] <= t) lo = mid; else hi = mid - 1; }
    return pts[lo][1];
  }
  // parts: [{key, units, constant}] → [[ms, value]] for the chosen window and granularity
  function seriesFor(parts) {
    const win = (WINDOWS.find(w => w[0] === S.win) || WINDOWS[2])[1];
    const today = Date.parse(ymd(istNow()) + "T00:00:00+05:30");
    const keyed = parts.filter(p => p.key && histMap(p.key).length);
    const constant = parts.filter(p => !(p.key && histMap(p.key).length)).reduce((a, p) => a + (p.constant || 0), 0);
    let dates = new Set();
    keyed.forEach(p => histMap(p.key).forEach(x => dates.add(x[0])));
    dates = Array.from(dates).sort((x, y) => x - y);
    if (!dates.length) return [];
    let start = win >= 99999 ? dates[0] : today - win * DAY;
    if (S.win === "1D") { const prior = dates.filter(t => t < today); start = prior.length ? prior[prior.length - 1] : dates[0]; }
    let pts = dates.filter(t => t >= start);
    const before = dates.filter(t => t < start); if (before.length && (!pts.length || pts[0] > start)) pts.unshift(before[before.length - 1]);
    if (S.gran === "monthly" && pts.length > 2) {
      const byM = new Map(); pts.forEach(t => byM.set(new Date(t).toISOString().slice(0, 7), t));
      const m = Array.from(byM.values()); if (m[0] !== pts[0]) m.unshift(pts[0]); pts = m;
    }
    return pts.map(t => [t, keyed.reduce((a, p) => a + p.units * priceAt(histMap(p.key), t), 0) + constant]);
  }
  function partsOf(lines, bucket) {
    return lines.map(h => { const w = bucket ? (h.buckets[bucket] || 0) : 1; return { key: h.key, units: h.units * w, constant: (h.value || 0) * w }; });
  }
  function areaChart(ser, opts) {
    const W = opts.w || 720, H = opts.h || 200, pl = 8, pr = 8, pt = 18, pb = 22;
    const wrap = el("div", { class: "area-wrap" });
    if (ser.length < 2) { wrap.append(el("p", { class: "meta", text: "Not enough price history for this window yet." })); return wrap; }
    const vs = ser.map(x => x[1]), lo = Math.min.apply(null, vs), hi = Math.max.apply(null, vs), pad = (hi - lo) * 0.12 || hi * 0.01 || 1;
    const y0 = lo - pad, y1 = hi + pad, t0 = ser[0][0], t1 = ser[ser.length - 1][0];
    const x = t => pl + (W - pl - pr) * ((t - t0) / ((t1 - t0) || 1)), y = v => pt + (H - pt - pb) * (1 - (v - y0) / (y1 - y0));
    const up = vs[vs.length - 1] >= vs[0], col = up ? "var(--pos)" : "var(--neg)";
    const svg = sv("svg", { viewBox: "0 0 " + W + " " + H, class: "chart area", role: "img", "aria-label": opts.label + ": " + short(vs[0]) + " to " + short(vs[vs.length - 1]) });
    const line = ser.map((p, i) => (i ? "L" : "M") + x(p[0]).toFixed(1) + " " + y(p[1]).toFixed(1)).join(" ");
    const fill = sv("path", { d: line + " L" + x(t1).toFixed(1) + " " + (H - pb) + " L" + x(t0).toFixed(1) + " " + (H - pb) + " Z", fill: col, opacity: 0.12 });
    svg.append(sv("line", { x1: pl, x2: W - pr, y1: y(vs[0]), y2: y(vs[0]), stroke: "var(--ink-3)", "stroke-dasharray": "3 4" }), fill,
      sv("path", { d: line, fill: "none", stroke: col, "stroke-width": 2, class: "area-line" }),
      sv("circle", { cx: x(t1), cy: y(vs[vs.length - 1]), r: 3.5, fill: col }));
    const lab = t => { const d = new Date(t + 5.5 * 3600000); return d.getUTCDate() + " " + MON[d.getUTCMonth()] + (t1 - t0 > 300 * DAY ? " '" + String(d.getUTCFullYear()).slice(2) : ""); };
    svg.append(sv("text", { x: pl, y: H - 6 }, lab(t0)), sv("text", { x: W - pr, y: H - 6, "text-anchor": "end" }, lab(t1)),
      sv("text", { x: W - pr, y: 12, "text-anchor": "end" }, "High " + short(hi) + " · Low " + short(lo)));
    // hover / touch readout
    const cur = sv("line", { x1: 0, x2: 0, y1: pt, y2: H - pb, stroke: "var(--ink-3)", opacity: 0 }), dot = sv("circle", { r: 4, fill: col, opacity: 0 });
    svg.append(cur, dot);
    const tip = el("div", { class: "tip", hidden: true });
    const move = ev => {
      const r = svg.getBoundingClientRect(), px = ((ev.touches ? ev.touches[0].clientX : ev.clientX) - r.left) / r.width * W;
      let best = 0; ser.forEach((p, i) => { if (Math.abs(x(p[0]) - px) < Math.abs(x(ser[best][0]) - px)) best = i; });
      const p = ser[best]; cur.setAttribute("x1", x(p[0])); cur.setAttribute("x2", x(p[0])); cur.setAttribute("opacity", 1);
      dot.setAttribute("cx", x(p[0])); dot.setAttribute("cy", y(p[1])); dot.setAttribute("opacity", 1);
      tip.hidden = false; tip.textContent = lab(p[0]) + " · " + inr(p[1]) + " · " + delta(p[1] - vs[0], vs[0]);
      tip.style.setProperty("left", Math.min(78, Math.max(0, x(p[0]) / W * 100 - 10)) + "%");
    };
    svg.addEventListener("pointermove", move); svg.addEventListener("touchmove", move, { passive: true });
    svg.addEventListener("pointerleave", () => { cur.setAttribute("opacity", 0); dot.setAttribute("opacity", 0); tip.hidden = true; });
    wrap.append(tip, svg);
    return wrap;
  }
  function windowControls() {
    return el("div", { class: "winbar" },
      el("div", { class: "chips", role: "group", "aria-label": "Window" }, WINDOWS.map(w => el("button", { type: "button", class: "chip", "aria-pressed": S.win === w[0] ? "true" : "false", onclick: () => { S.win = w[0]; render(); }, text: w[0] }))),
      el("div", { class: "seg small-seg", role: "group", "aria-label": "Granularity" },
        ["daily", "monthly"].map(g => el("button", { type: "button", "aria-pressed": S.gran === g ? "true" : "false", onclick: () => { S.gran = g; render(); }, text: g === "daily" ? "Daily" : "Monthly" }))));
  }
  function changeLine(ser) {
    if (ser.length < 2) return null;
    const a = ser[0][1], b = ser[ser.length - 1][1], d = b - a;
    return el("div", { class: "chg " + (d >= 0 ? "upc" : "dn") }, el("span", { class: "num big2", text: (d >= 0 ? "▲ " : "▼ ") + inr(Math.abs(d)) }),
      el("span", { class: "num", text: " " + pct(a ? d / a : 0) }), el("span", { class: "meta", text: " " + (S.win === "All" ? "since " : "over ") + (S.win === "All" ? new Date(ser[0][0]).toISOString().slice(0, 10) : S.win) }));
  }
  function viewHoldings(rows, bt) {
    S.win = S.win || "1M"; S.gran = S.gran || "daily"; S.openG = S.openG || {};
    const defs = S.book.bucket_defs;
    const chips = el("div", { class: "chips" },
      el("button", { type: "button", class: "chip", "aria-pressed": S.bucket ? "false" : "true", onclick: () => { S.bucket = null; render(); }, text: "All buckets" }),
      defs.filter(d => bt[d.key]).map(d => el("button", { type: "button", class: "chip", "aria-pressed": S.bucket === d.key ? "true" : "false", onclick: () => { S.bucket = d.key; render(); }, text: d.label })));
    const scope = S.bucket ? rows.filter(h => h.buckets[S.bucket]) : rows;
    const ser = seriesFor(partsOf(scope, S.bucket));
    const tb = el("tbody");
    const order = S.bucket ? [S.bucket] : defs.map(d => d.key);
    let grand = 0;
    order.forEach(bk => {
      const inB = rows.filter(h => h.buckets[bk]);
      if (!inB.length) return;
      const lab = (defs.find(d => d.key === bk) || {}).label || bk;
      const groups = new Map();
      inB.forEach(h => { const g = groups.get(h.group) || { key: h.group, name: h.display, apps: new Set(), lots: [] }; g.apps.add(h.app); g.lots.push(h); groups.set(h.group, g); });
      const G = Array.from(groups.values()).map(g => {
        const w = h => h.buckets[bk];
        g.value = g.lots.reduce((a, h) => a + (h.value || 0) * w(h), 0);
        g.cost = g.lots.reduce((a, h) => a + h.cost * w(h), 0);
        g.isAmt = g.lots.every(h => h.kind === "liquid" || h.kind === "cash" || h.nav_static === 1);
        g.units = g.lots.reduce((a, h) => a + h.units * w(h), 0);
        g.price = g.lots[0].price; g.priceAt = g.lots[0].priceAt; g.pkey = g.lots[0].key;
        g.pending = g.lots.some(h => h.pending);
        g.ser = seriesFor(partsOf(g.lots, bk));
        g.wchg = g.ser.length > 1 ? g.ser[g.ser.length - 1][1] - g.ser[0][1] : null;
        return g;
      }).sort((a, b) => b.value - a.value);
      const sv_ = G.reduce((a, g) => a + g.value, 0), sc = G.reduce((a, g) => a + g.cost, 0), sw = G.reduce((a, g) => a + (g.wchg || 0), 0);
      tb.append(el("tr", { class: "sub" }, el("td", { text: lab }), el("td"), el("td"), el("td", { class: "n" }, el("div", { text: inr(sv_) }), d1(oneDay(inB, bk))), el("td", { class: "n", text: delta(sv_ - sc, sc) }), el("td", { class: "n", text: delta(sw) })));
      grand += sv_;
      G.forEach(g => {
        const id = bk + "|" + g.key, open = !!S.openG[id], multi = g.lots.length > 1;
        const toggle = () => { S.openG[id] = !open; render(); };
        tb.append(el("tr", { class: "grow" + (open ? " open" : ""), role: "button", tabindex: "0", "aria-expanded": open ? "true" : "false", onclick: toggle, onkeydown: e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } } },
          el("td", null, el("div", { class: "rowtitle" }, el("span", { class: "chev", "aria-hidden": "true", text: "›" }), " " + g.name),
            el("div", { class: "meta" }, Array.from(g.apps).join(", ") + " · " + g.lots.length + (g.lots.length > 1 ? " purchases" : " purchase"), g.pending ? " · " : "", g.pending ? pill("waiting", "· allotment") : null)),
          el("td", { class: "n num", text: g.isAmt ? "—" : g.units.toLocaleString("en-IN", { maximumFractionDigits: 3 }) }),
          el("td", { class: "n" }, el("div", { class: "num", text: g.isAmt || g.price === null ? "—" : g.price.toLocaleString("en-IN", { maximumFractionDigits: 2 }) }), el("div", { class: "meta", text: g.isAmt ? "" : g.priceAt })),
          el("td", { class: "n num" + (S.flash && g.pkey && S.flash[g.pkey] ? " flash-" + S.flash[g.pkey] : "") }, el("div", { text: inr(g.value) }), d1(oneDay(g.lots, bk))),
          el("td", { class: "n num " + (g.value - g.cost >= 0 ? "upc" : "dn"), text: delta(g.value - g.cost, g.cost) }),
          el("td", { class: "n num " + ((g.wchg || 0) >= 0 ? "upc" : "dn"), text: g.wchg === null ? "—" : delta(g.wchg) })));
        if (open) {
          const lotsT = el("table", { class: "lots" }, el("thead", null, el("tr", null, ["Bought", "Units", "Buy price", "Cost", "Value", "Gain"].map((h, i) => el("th", { class: i ? "n" : "", text: h })))),
            el("tbody", null, g.lots.slice().sort((a, b) => (a.lot_date || "") < (b.lot_date || "") ? -1 : 1).map(h => {
              const w = h.buckets[bk], v = (h.value || 0) * w, c = h.cost * w, amt = h.kind === "liquid" || h.kind === "cash" || h.nav_static === 1;
              return el("tr", null,
                el("td", null, el("div", { class: "num", text: h.lot_date ? niceDate(h.lot_date) : "Before Oct 2026" }), el("div", { class: "meta", text: h.app + (w < 1 ? " · " + Math.round(w * 100) + "% in this bucket" : "") + (h.pending ? " · awaiting allotment" : "") })),
                el("td", { class: "n num", text: amt ? "—" : (h.units * w).toLocaleString("en-IN", { maximumFractionDigits: 3 }) }),
                el("td", { class: "n num", text: amt || !h.units ? "—" : (h.cost / h.units).toLocaleString("en-IN", { maximumFractionDigits: h.cost / h.units < 100 ? 4 : 2 }) }),
                el("td", { class: "n num", text: inr(c) }),
                el("td", { class: "n num" }, el("div", { text: inr(v) }), d1(oneDay([h], bk))),
                el("td", { class: "n num " + (v - c >= 0 ? "upc" : "dn"), text: delta(v - c, c) }));
            })));
          tb.append(el("tr", { class: "lot-panel" }, el("td", { colspan: 6 },
            el("div", { class: "lot-wrap" }, el("div", null, changeLine(g.ser), areaChart(g.ser, { w: 420, h: 170, label: g.name + " value" })), el("div", { class: "tw" }, lotsT)))));
        }
      });
    });
    if (!S.bucket) tb.append(el("tr", { class: "total" }, el("td", { text: "Whole book" }), el("td"), el("td"), el("td", { class: "n", text: inr(grand) }), el("td"), el("td")));
    return el("section", { class: "view", id: "holdings" },
      el("header", null, el("div", null, el("div", { class: "eyebrow", text: "Holdings" }), el("h2", { text: holdingsInsight(rows) }),
        el("div", { class: "meta", text: "Units as of " + niceDate(S.book.units_as_of) + " · the chart values today's holdings at each day's price (buys and sells ignored), so changes are market moves only" }))),
      windowControls(),
      el("div", { class: "hold-chart" }, changeLine(ser), areaChart(ser, { label: (S.bucket ? (defs.find(d => d.key === S.bucket) || {}).label : "Whole book") + " value" })),
      chips,
      el("div", { class: "tw" }, el("table", { class: "hold2" }, el("thead", null, el("tr", null, ["Holding", "Units", "Price / NAV", "Value", "Gain on cost", "Change · " + S.win].map((h, i) => el("th", { class: i ? "n" : "", text: h })))), tb)));
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
    if (l.status === "done" || l.status === "skipped") return pill("done");
    if (l.status === "conditional") return pill("waiting");
    if (l.due && l.due < today) return pill("overdue", niceDate(l.due));
    if (l.due && l.due > today) return pill("upcoming", niceDate(l.due));
    return pill("due", l.due ? niceDate(l.due) : "");
  }
  function viewChecklist(mk) {
    const m = monthData(mk);
    const all = [].concat(m.lines || [], m.one_offs || []).filter(l => l.kind !== "spend");
    const box = el("div");
    all.forEach(l => box.append(el("div", { class: "check" },
      statusPill(l),
      el("div", null, el("div", { text: l.label })),
      el("div", { class: "n num" }, el("div", { text: l.planned === null || l.planned === undefined ? "—" : inr(l.planned) }), l.status === "done" && l.done !== null && l.done !== undefined && l.done !== l.planned ? el("div", { class: "meta", text: "done " + inr(l.done) }) : null),
      (l.how || l.date) ? el("div", { class: "how", text: [l.date ? niceDate(l.date) : "", l.how || ""].filter(Boolean).join(" · ") }) : null)));
    const lp = leftParts(m);
    return el("section", { class: "view", id: "checklist" },
      el("header", null, el("div", null, el("div", { class: "eyebrow", text: "This month" }), el("h2", { text: (function () { const o = leftParts(m); return o.salary > 0 ? inr(o.salary) + " of " + monthLabel(mk) + " salary still to invest" : (m.generated ? monthLabel(mk) + ": " + inr([].concat(m.lines).filter(l => l.kind === "invest").reduce((a, l) => a + (l.planned || 0), 0)) + " to invest from salary" : "✓ All of " + monthLabel(mk) + "'s salary money is invested") + (o.other ? " · " + short(o.other) + " of proceeds due" : ""); })() })),
        el("span", { class: "q", text: m.generated ? "From " + (S.book.plan.name || "the plan") + " (no actuals yet)" + (m.note ? " · " + m.note.slice(0, 120) : "") : "Plan lines and what actually happened" })),
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
      el("div", { class: "eyebrow", text: "Card" }),
      el("div", { class: "big num", style: "font-size:22px;font-weight:650", text: inr(last.regular_total) }),
      el("div", { class: "small" }, "Regular spend in " + last.label + " vs " + short(cc.budget) + " budget: ", pill(over > 0 ? "watch" : "ontrack", over > 0 ? "· " + short(over) + " over" : "· " + short(-over) + " under")),
      el("div", { class: "meta", text: "Plus one-offs " + inr(last.outlier_total) + " · statement total " + inr(last.declared_total) + (last.due_date ? " · due " + niceDate(last.due_date) : "") + (last.paid_on ? " · paid " + niceDate(last.paid_on) : "") }));
    return el("section", { class: "view", id: "bank" },
      el("header", null, el("div", null, el("div", { class: "eyebrow", text: "Bank" }), el("h2", { text: mk === monthKey(0) ? inr(sp.result) + " is spendable until the next salary" : monthLabel(mk) + " leaves " + inr(sp.result) + " after the plan and living costs" })),
        el("span", { class: "q", text: sp.note })),
      el("div", { class: "two" }, wf, ccBox));
  }

  // ---- view 5
  function viewCalendar(mk) {
    const today = ymd(istNow());
    const items = (S.book.calendar || []).filter(e => e.date.slice(0, 7) === mk);
    const ahead = items.filter(e => !e.done && e.date >= today), earlier = items.filter(e => e.done || e.date < today);
    const rowOf = (e, kind) => el("tr", { class: kind === "earlier" ? "past" : null },
      el("td", null, el("div", { class: "rowtitle", text: e.title }), e.desc ? el("div", { class: "meta clamp", text: e.desc }) : null),
      el("td", { class: "n" }, el("div", { class: "num", text: niceDate(e.date) }), el("div", { class: "meta", text: e.time ? e.time + " IST" : "all day" })),
      el("td", null, kind === "earlier" ? (e.done ? pill("done") : el("span", { class: "meta", text: "past" })) : pill(e.date === today ? "due" : "upcoming", e.date === today ? "today" : "")));
    const tbA = el("tbody", null, ahead.map(e => rowOf(e, "ahead")));
    const titleTxt = ahead.length ? ahead.length + " action" + (ahead.length > 1 ? "s" : "") + " left in " + monthLabel(mk) + " · next " + niceDate(ahead[0].date) : "✓ No actions left in " + monthLabel(mk);
    return el("section", { class: "view", id: "calendar" },
      el("header", null, el("div", null, el("div", { class: "eyebrow", text: "Calendar" }), el("h2", { text: titleTxt }),
        el("div", { class: "meta", text: "Money items from your Google Calendar" }))),
      ahead.length ? el("div", { class: "tw" }, el("table", { "data-labels": "What|When|Status", class: "cal" }, tbA)) : null,
      earlier.length ? el("details", { class: "earlier" }, el("summary", { class: "meta", text: "Earlier this month (" + earlier.length + ")" }),
        el("div", { class: "tw" }, el("table", { "data-labels": "What|When|Status", class: "cal" }, el("tbody", null, earlier.map(e => rowOf(e, "earlier")))))) : null);
  }

  // ---- supporting detail
  function det(id, title, q, body, open) {
    return el("details", { class: "view", id: id, open: open || null },
      el("summary", null, el("div", null, el("h2", { text: title }), q ? el("div", { class: "q", text: q }) : null)), body);
  }
  function detailsFlat() {
    const A = S.book.property, ms = A.milestones;
    const paid = ms.filter(m => m.paid), tot = ms.reduce((a, m) => a + (m.total || 0), 0), pt = paid.reduce((a, m) => a + (m.total || 0), 0);
    const next = ms.filter(m => !m.paid).slice(0, 4);
    const tb = el("tbody");
    const showPaid = !!S.showPaid;
    ms.forEach(m => {
      if (m.paid && !showPaid) return;
      const slip = m.actual && m.planned ? Math.round((new Date(m.actual) - new Date(m.planned)) / 86400000) : null;
      tb.append(el("tr", null,
        el("td", null, el("div", { text: m.n + " · " + m.name }), el("div", { class: "meta", text: (m.pct || "") + "" })),
        el("td", { class: "n", text: niceDate(m.planned) }),
        el("td", { class: "n" }, m.actual ? niceDate(m.actual) : "—", slip !== null ? el("div", { class: "small " + (slip > 0 ? "" : "muted"), text: slip === 0 ? "on time" : (slip > 0 ? slip + " d late" : -slip + " d early") }) : null),
        el("td", { class: "n", text: inr(m.total) }),
        el("td", { class: "n" }, el("div", { text: inr(m.tds) }), ((S.book.property.shares || 1) > 1 ? el("div", { class: "meta", text: inr((m.tds || 0) / S.book.property.shares) + " each" }) : null)),
        el("td", { class: "n", text: inr(m.net_due) }),
        el("td", null, pill(m.paid ? "done" : "upcoming"))));
    });
    const pays = el("tbody");
    A.payments.forEach(p => {
      const u = p.link ? safeUrl(p.link) : null;
      pays.append(el("tr", null,
        el("td", { class: "n", text: p.date }),
        el("td", null, el("div", { text: p.desc }), el("div", { class: "meta", text: p.towards + (p.self === "N" ? " · paid by the lender" : "") })),
        el("td", { class: "n", text: inr(p.amount) }),
        el("td", null, u ? el("a", { href: u, target: "_blank", rel: "noopener noreferrer", text: "Proof" }) : pill("due", "· proof missing"),
          p.cert ? el("div", { class: "meta", text: "16B " + p.cert }) : null,
          p.check ? el("div", { class: "meta", text: p.check.slice(0, 80) }) : el("div", { class: "meta", text: "proof not checked yet" }))));
    });
    const extras = A.extras.map(x => el("li", null, x.name + ": " + inr(x.amount) + (x.planned ? " (" + niceDate(x.planned) + ")" : "")));
    return det("flat", A.title || "The flat", paid.length + " of " + ms.length + " milestones paid · " + short(pt) + " of " + short(tot) + " · next: " + (next[0] ? next[0].name + " (" + niceDate(next[0].planned) + ")" : "—"),
      el("div", null,
        el("div", { class: "strip" },
          tile("Paid so far", short(pt), [Math.round(pt / tot * 100) + "% of the price"]),
          tile("Still to come", short(tot - pt), [next.length + " near-term milestones"]),
          tile("Next TDS", next[0] ? inr(next[0].tds) : "—", [next[0] ? niceDate(next[0].planned) : ""])),
        el("div", { class: "row-between" }, el("h3", { class: "meta", text: "PAYMENT PLAN" }),
          el("button", { type: "button", class: "chip", "aria-pressed": showPaid ? "true" : "false", onclick: () => { S.showPaid = !showPaid; render(); }, text: showPaid ? "Hide paid (" + paid.length + ")" : "Show paid (" + paid.length + ")" })),
        el("div", { class: "tw" }, el("table", null, el("thead", null, el("tr", null, ["Milestone", "Planned", "Actual", "Total", "TDS 1%", "Net to builder", ""].map((h, i) => el("th", { class: i === 0 || i === 6 ? "" : "n", text: h })))), tb)),
        el("p", { class: "small" }, "On top of the price: "), el("ul", { class: "list small" }, extras),
        el("h3", { class: "meta", text: "PAYMENTS AND PROOFS" }),
        el("div", { class: "tw" }, el("table", null, el("thead", null, el("tr", null, ["Date", "What", "Amount", "Proof"].map((h, i) => el("th", { class: i === 2 || i === 0 ? "n" : "", text: h })))), pays))));
  }

  function lineChart(series, opts) {
    const W = 720, H = 220, pl = 64, pr = 12, pt = 12, pb = 26;
    const n = series[0].pts.length;
    const max = Math.max.apply(null, series.flatMap(s => s.pts.map(p => p.y))) * 1.08 || 1;
    const x = i => pl + (W - pl - pr) * (n > 1 ? i / (n - 1) : 0), y = v => pt + (H - pt - pb) * (1 - v / max);
    const svg = sv("svg", { viewBox: "0 0 " + W + " " + H, class: "chart", role: "img", "aria-label": opts.label });
    for (let i = 0; i <= 2; i++) { const v = max * i / 2; svg.append(sv("line", { x1: pl, x2: W - pr, y1: y(v), y2: y(v), stroke: "var(--line)" }), sv("text", { x: pl - 6, y: y(v) + 4, "text-anchor": "end" }, short(v))); }
    const step = Math.max(1, Math.round(n / 8));
    series[0].pts.forEach((p, i) => { if (i % step === 0) svg.append(sv("text", { x: x(i), y: H - 8, "text-anchor": "middle" }, p.x)); });
    series.forEach(s => {
      svg.append(sv("path", { d: s.pts.map((p, i) => (i ? "L" : "M") + x(i).toFixed(1) + " " + y(p.y).toFixed(1)).join(" "), fill: "none", stroke: s.color, "stroke-width": 2 }));
      const L = s.pts[s.pts.length - 1]; svg.append(sv("circle", { cx: x(n - 1), cy: y(L.y), r: 3, fill: s.color }));
      svg.append(sv("text", { x: x(n - 1) - 4, y: y(L.y) - 7, "text-anchor": "end", class: "wf-v" }, s.name + " " + short(L.y)));
    });
    return el("div", null, svg, el("div", { class: "legend" }, series.map(s => el("span", null, el("i", { style: "background:" + s.color }), s.name))));
  }
  function detailsLoan() {
    const P = S.book.plan.path.slice(0, 36);
    const firstOver = P.find(r => r.interest > r.si);
    return det("loan", "Home loan · interest vs what goes in", firstOver ? "Interest passes the SI in " + firstOver.m + " (" + inr(firstOver.interest) + " vs " + inr(firstOver.si) + ")" : "SI covers interest throughout",
      el("div", null,
        lineChart([{ name: "Monthly interest", color: "var(--neg)", pts: P.map(r => ({ x: r.m.replace(" 20", " '"), y: r.interest })) },
                   { name: "Loan SI paid", color: "var(--pos)", pts: P.map(r => ({ x: r.m.replace(" 20", " '"), y: r.si })) }], { label: "Interest vs SI" }),
        lineChart([{ name: "Loan outstanding", color: "var(--ink-2)", pts: S.book.plan.path.filter((r, i) => i % 3 === 0).map(r => ({ x: r.m.replace(" 20", " '"), y: r.loan })) }], { label: "Loan balance" })));
  }
  function detailsSalary() {
    const P = S.book.plan.path.filter(r => r.m.startsWith("Jan") || r.m === S.book.plan.path[0].m);
    const tb = el("tbody");
    P.forEach(r => tb.append(el("tr", null, el("td", { text: r.m }), el("td", { class: "n", text: inr(r.salary) }), el("td", { class: "n", text: inr(r.si) }), el("td", { class: "n", text: inr(r.home) }), el("td", { class: "n", text: inr(r.child) }), el("td", { class: "n", text: inr(r.ret) }), el("td", { class: "n", text: inr(r.rent + r.living) }), el("td", { class: "n", text: short(r.ret_fund) }))));
    return det("salary", "Salary and where it goes", S.book.plan.salary_note || "",
      el("div", null,
        lineChart([{ name: "Take-home", color: "var(--accent)", pts: P.map(r => ({ x: r.m.slice(-4), y: r.salary })) }, { name: "Loan SI", color: "var(--neg)", pts: P.map(r => ({ x: r.m.slice(-4), y: r.si })) }, { name: "Retirement flow", color: "var(--ink-3)", pts: P.map(r => ({ x: r.m.slice(-4), y: r.ret })) }], { label: "Salary path" }),
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
      svg.append(sv("rect", { x: x0, y: y(m.regular_total), width: w, height: (H - pb) - y(m.regular_total), fill: m.regular_total > cc.budget ? "var(--neg)" : "var(--pos)" }));
      if (m.outlier_total) svg.append(sv("rect", { x: x0, y: y(m.declared_total), width: w, height: y(m.regular_total) - y(m.declared_total), fill: "var(--bar)" }));
      svg.append(sv("text", { x: x0 + w / 2, y: H - 8, "text-anchor": "middle" }, m.label.slice(0, 3)));
      svg.append(sv("text", { x: x0 + w / 2, y: y(m.regular_total) - 4, "text-anchor": "middle", class: "wf-v" }, (m.regular_total > cc.budget ? "▲" : "") + short(m.regular_total)));
    });
    const last = cc.months[ks[ks.length - 1]];
    const under = ks.filter(k => cc.months[k].regular_total <= cc.budget).length;
    return det("cards", "Card: " + last.label + " regular spend " + short(last.regular_total) + " · under budget in " + under + " of " + ks.length + " months", "Regular spend vs the " + short(cc.budget) + " budget (dashed); grey = one-offs such as property TDS",
      el("div", null, svg, el("div", { class: "legend" }, el("span", null, el("i", { style: "background:var(--pos)" }), "Regular, under budget"), el("span", null, el("i", { style: "background:var(--neg)" }), "Regular, over (labelled ▲)"), el("span", null, el("i", { style: "background:var(--bar)" }), "One-offs")),
        el("p", { class: "meta", text: last.label + ": " + Object.entries(last.categories).filter(e => e[1]).map(e => e[0] + " " + inr(e[1])).join(" · ") })));
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
        el("td", null, el("div", { text: s.sym }), el("div", { class: "meta", text: s.units + " sh" })),
        el("td", { class: "n" }, el("div", { text: p ? p.toLocaleString("en-IN", { maximumFractionDigits: 2 }) : "—" }),
          pr && pr.pc ? el("div", { class: "d1 " + (pr.p >= pr.pc ? "upc" : "dn"), text: "1D " + (pr.p >= pr.pc ? "▲ " : "▼ ") + pct(pr.p / pr.pc - 1, 2) }) : null),
        el("td", null, c.call ? el("span", { class: "tag", text: c.call }) : "—", c.date ? el("div", { class: "meta", text: niceDate(c.date) + " · " + (c.conviction || "") }) : null),
        el("td", { class: "n" }, c.target ? inr(c.target) : "—", c.target && p ? el("div", { class: "meta", text: pct(c.target / p - 1) }) : null),
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
    items.forEach(i => tb.append(el("tr", null, el("td", { text: i[0] }), el("td", { class: "n", text: (i[1] || "—").replace("T", " ").slice(0, 16) }), el("td", { class: "meta", text: i[2] }))));
    const drift = S.book.drift || [], gaps = S.book.gaps || [];
    return det("health", "Data freshness and sync", (drift.length ? drift.length + " sync issue(s)" : "Sources in sync") + (gaps.length ? " · " + gaps.length + " record gap(s)" : "") + (st.prices_failed ? " · " + st.prices_failed + " price(s) failed" : ""),
      el("div", null,
        el("div", { class: "tw" }, el("table", null, tb)),
        drift.length ? el("div", null, el("h3", { class: "meta", text: "SYNC ISSUES (state files vs sheets)" }), el("ul", { class: "list small" }, drift.map(d => el("li", { text: d })))) : null,
        gaps.length ? el("div", null, el("h3", { class: "meta", text: "RECORD GAPS" }), el("ul", { class: "list small" }, gaps.map(d => el("li", { text: d })))) : null));
  }
})();
