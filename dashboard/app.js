/* ==========================================================================
   HybridSec dashboard - app.js

   HOW THIS FILE IS ORGANISED
   The dashboard is a single page. index.html contains one <section class="view">
   per screen; this file fills those sections with data from the FastAPI backend.
   Read it top to bottom:

     1. Utilities         small helpers: DOM lookup ($ / $$), esc() for HTML escaping,
                          date and number formatting, the api() fetch wrapper, toasts,
                          the confirm dialog and button busy states.
     2. Shared renderers  HTML snippets several views reuse (status pills, risk bars,
                          KPI tiles, chips, empty states) and the shared `state` object
                          with its loadTools / loadHealth / loadRuns caches.
     3. Router            turns the URL hash (#runs, #run/<id>, #compare?base=..) into a
                          call of one render function and hands out a "route sequence"
                          token so a slow response from an abandoned page can never
                          paint over the current one.
     4-11. Views          one numbered section per screen (Overview, AI Planner, New Run,
                          Runs, Run detail, Compare, Settings, Custom tools). Each owns its
                          render function(s), its HTML builders and its event handlers.
     12. Boot             picks the initial route and starts the app.

   HOW A VIEW RENDERS (the request / render cycle)
     user action or hashchange
       -> route()                    reads the hash, bumps routeSeq, shows the <section>
       -> renderXxx(params, seq)     awaits api("/api/...")
       -> if (!isCurrent(seq)) return   a newer navigation happened: stop quietly
       -> build an HTML string, passing every server or user value through esc()
       -> element.innerHTML = html, then bind the event handlers that region needs
     Errors thrown by api() carry the server's `detail` text and surface as toasts or
     inline empty states. Nothing is written to the console.

   CONVENTIONS
     - esc() wraps EVERY dynamic value placed into HTML; ids used in URLs go through encode().
     - Double quotes for JavaScript strings; single quotes only when the literal itself
       contains HTML attribute quotes.
     - Name prefixes: render<Screen>(..., seq) is the router's entry for one screen (fetch,
       check isCurrent(seq), fill the section). Other render* functions build one region or
       item and either return the HTML (renderPortsTab, renderTimeline) or write it into their
       fixed container (renderRunsTable fills #runs-table). *Html helpers return run-detail
       fragments, most of them shared by the first paint and the poller. paint* draws the run
       page or its tab panel from scratch, patch* rewrites only what changed, update* refreshes
       elements already on the page, load* fetches with a cache (loadPlanInto: fetch, then
       renderPlan), apply* copies server data into existing form controls.
   ========================================================================== */
(function () {
  "use strict";

  /* ========================================================================
     1. Utilities
     Owns: DOM shortcuts, escaping/encoding, formatting, the api() wrapper,
     toasts, button busy states, the confirm dialog, client-side downloads
     and query-string parsing. Nothing here knows about any particular view.
     ======================================================================== */

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  /** Escape a value for safe insertion into HTML. Every dynamic string goes through here. */
  function esc(value) {
    if (value === null || value === undefined) return "";
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  /** Encode a value for use inside a URL hash or query component. */
  function encode(value) {
    return encodeURIComponent(value === null || value === undefined ? "" : String(value));
  }

  /** decodeURIComponent that tolerates stray percent signs (e.g. #compare?base=50%). */
  function safeDecode(value) {
    try { return decodeURIComponent(value); } catch (_) { return value; }
  }

  /** Unique, truthy entries of an array, first occurrence wins. */
  function uniq(arr) {
    return (arr || []).filter((x, i, a) => x && a.indexOf(x) === i);
  }

  /** Structural equality by JSON text; good enough for the API's plain data objects. */
  function sameJson(a, b) {
    return JSON.stringify(a === undefined ? null : a) === JSON.stringify(b === undefined ? null : b);
  }

  /** Full date and time in the user's locale. */
  function fmtDate(iso) {
    if (!iso) return "-";
    const d = new Date(iso);
    if (isNaN(d.getTime())) return esc(iso);
    return d.toLocaleString(undefined, {
      year: "numeric", month: "short", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  }

  /** Compact date and time for table cells. */
  function fmtDateShort(iso) {
    if (!iso) return "-";
    const d = new Date(iso);
    if (isNaN(d.getTime())) return esc(iso);
    return d.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
  }

  /** Duration as "12.4s", "3m 05s" or "1h 12m". */
  function fmtDur(seconds) {
    if (seconds === null || seconds === undefined || isNaN(Number(seconds))) return "-";
    const s = Number(seconds);
    if (s < 59.95) return s.toFixed(1) + "s"; // 59.95 s and up would print "60.0s", so they take the minutes branch
    const t = Math.round(s); // round once, before splitting into units, so 119.6 s is "2m 00s", never "1m 60s"
    const m = Math.floor(t / 60);
    if (m < 60) return m + "m " + String(t % 60).padStart(2, "0") + "s";
    const h = Math.floor(m / 60);
    return h + "h " + (m - h * 60) + "m";
  }

  /** Locale-formatted number with a fallback for missing values. */
  function fmtNum(n, fallback) {
    if (n === null || n === undefined || isNaN(Number(n))) return fallback === undefined ? "-" : fallback;
    return Number(n).toLocaleString();
  }

  /** Escaped value, or a faint dash when empty. */
  function dash(v) {
    return v === null || v === undefined || v === "" ? '<span class="faint">-</span>' : esc(v);
  }

  /** Turn a FastAPI `detail` payload (string, list of validation errors or object) into one readable line. */
  function detailToMessage(detail) {
    if (!detail) return "";
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail.map((d) => {
        if (typeof d === "string") return d;
        const loc = Array.isArray(d.loc) ? d.loc.filter((p) => p !== "body").join(".") : "";
        return (loc ? loc + ": " : "") + (d.msg || JSON.stringify(d));
      }).join("; ");
    }
    if (typeof detail === "object") return detail.msg || detail.message || JSON.stringify(detail);
    return String(detail);
  }

  /**
   * The only place that talks to the backend. JSON in, JSON out. On a non-2xx response it throws
   * an Error whose message is the server's `detail` text (status code on err.status). Accepts a
   * `signal` so the run-detail poller can abort an in-flight request; AbortError is re-thrown as-is.
   */
  async function api(path, options) {
    const opts = Object.assign({ headers: {} }, options || {});
    const onHeaders = opts.onHeaders;   // optional callback that receives the response headers (not sent to fetch)
    delete opts.onHeaders;
    if (opts.body !== undefined && typeof opts.body !== "string") {
      opts.body = JSON.stringify(opts.body);
      opts.headers["Content-Type"] = "application/json";
    }
    opts.headers["Accept"] = "application/json";
    let res;
    try {
      res = await fetch(path, opts);
    } catch (e) {
      if (e && e.name === "AbortError") throw e;
      throw new Error("Network error: could not reach the API (" + e.message + ")");
    }
    if (onHeaders && res.ok) onHeaders(res.headers);
    if (res.status === 204) return null;
    const text = await res.text();
    let data = null;
    if (text) {
      try { data = JSON.parse(text); } catch (_) { data = text; }
    }
    if (!res.ok) {
      let msg = "";
      if (data && typeof data === "object" && "detail" in data) msg = detailToMessage(data.detail);
      else if (typeof data === "string") msg = data.slice(0, 300);
      const err = new Error(msg || ("HTTP " + res.status + " " + res.statusText));
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  /* Toasts: transient notifications in the bottom-right corner. */
  const toastStack = $("#toasts");

  /** Show a toast of type info | success | warn | error; errors stay longer and are announced assertively. */
  function toast(message, type, title) {
    const el = document.createElement("div");
    el.className = "toast " + (type || "info");
    el.setAttribute("role", type === "error" ? "alert" : "status");
    el.innerHTML =
      '<div class="toast-body">' +
      (title ? '<div class="toast-title">' + esc(title) + "</div>" : "") +
      "<div>" + esc(message) + "</div></div>" +
      '<button class="toast-close" type="button" aria-label="Dismiss notification">&times;</button>';
    const remove = () => {
      if (!el.parentNode) return;
      el.classList.add("leaving");
      setTimeout(() => el.remove(), 220);
    };
    $(".toast-close", el).addEventListener("click", remove);
    toastStack.appendChild(el);
    setTimeout(remove, type === "error" ? 8000 : 4500);
  }

  /** Error toast from an Error object (uses the server's detail message). */
  const toastError = (err, title) => toast(err && err.message ? err.message : String(err), "error", title || "Error");

  /** Put a button into a spinner "busy" state while a request is in flight (clearBusy restores it). */
  function setBusy(btn, label) {
    if (!btn.dataset.label) btn.dataset.label = btn.textContent;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> ' + esc(label || "Working...");
  }
  function clearBusy(btn) {
    btn.disabled = false;
    btn.textContent = btn.dataset.label || btn.textContent;
  }

  /** Ask for confirmation with the shared <dialog>; resolves true when the primary button is pressed. */
  function confirmDialog(message, okLabel, title) {
    const dlg = $("#confirm-dialog");
    $("#confirm-title").textContent = title || "Confirm";
    $("#confirm-message").textContent = message;
    $("#confirm-ok").textContent = okLabel || "OK";
    return new Promise((resolve) => {
      if (typeof dlg.showModal !== "function") {      // very old browsers: fall back to window.confirm
        resolve(window.confirm(message));
        return;
      }
      const onClose = () => {
        dlg.removeEventListener("close", onClose);
        resolve(dlg.returnValue === "ok");
      };
      dlg.addEventListener("close", onClose);
      dlg.returnValue = "cancel";
      dlg.showModal();
    });
  }

  /** Download a string as a file without a round trip to the server. */
  function downloadBlob(filename, content, mime) {
    const blob = new Blob([content], { type: mime || "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  /** Parse "?a=1&b=2" into an object; malformed percent-escapes are kept verbatim. */
  function parseQuery(qs) {
    const out = {};
    if (!qs) return out;
    qs.replace(/^\?/, "").split("&").forEach((pair) => {
      if (!pair) return;
      const i = pair.indexOf("=");
      const k = safeDecode(i >= 0 ? pair.slice(0, i) : pair);
      const v = i >= 0 ? safeDecode(pair.slice(i + 1).replace(/\+/g, " ")) : "";
      out[k] = v;
    });
    return out;
  }

  /* ========================================================================
     2. Shared renderers and shared state
     Owns: the small HTML building blocks used by more than one view (pills,
     risk bar, KPI tile, chips, empty state, run title cell) and the single
     `state` object with its cached loaders. Views read and write `state`
     directly; there is no other hidden state.
     ======================================================================== */

  const STATUS_PILL = {
    queued: "pill-muted", running: "pill-accent", completed: "pill-green", failed: "pill-red",
    pending: "pill-muted", skipped: "pill-muted", simulated: "pill-purple", planned: "pill-blue", ok: "pill-green",
  };

  const isActiveStatus = (s) => s === "queued" || s === "running";

  /** Status pill; queued/running statuses get a small spinner. */
  function statusPill(status) {
    const s = String(status || "unknown");
    const cls = STATUS_PILL[s] || "pill-muted";
    const spin = isActiveStatus(s) ? '<span class="spinner sm"></span>' : "";
    return '<span class="pill ' + cls + '">' + spin + esc(s) + "</span>";
  }

  /** True for a completed run whose summary says a stage did not examine everything it was given. */
  const isPartial = (run) => !!(run && run.status === "completed" && run.summary && run.summary.partial);

  /** Amber "partial" pill shown after the status pill of such a run (the stage notes say what is missing). */
  function partialPill(run) {
    if (!isPartial(run)) return "";
    return ' <span class="pill pill-amber" title="A stage did not examine everything it was given (it ran out of time, or a tool produced nothing); see the stage notes">partial</span>';
  }

  /** live / simulated pill. */
  function modePill(mode) {
    if (mode === "simulated") return '<span class="pill pill-purple">simulated</span>';
    if (mode === "live") return '<span class="pill pill-blue">live</span>';
    return '<span class="pill pill-muted">' + esc(mode || "-") + "</span>";
  }

  const SEVERITY_PILL = { info: "pill-blue", low: "pill-green", medium: "pill-amber", high: "pill-red", critical: "pill-red" };
  const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

  function severityPill(sev) {
    const s = String(sev || "info").toLowerCase();
    return '<span class="pill ' + (SEVERITY_PILL[s] || "pill-muted") + '">' + esc(s) + "</span>";
  }

  /** Colour class for a 0-100 risk score: green < 30, amber < 70, red otherwise. */
  function riskClass(score) {
    const n = Number(score);
    if (isNaN(n)) return "muted";
    if (n < 30) return "green";
    if (n < 70) return "amber";
    return "red";
  }

  /** Word for each riskClass() colour, shown under the run-detail gauge. */
  const RISK_LABEL = { green: "Low", amber: "Moderate", red: "High" };

  /** The risk score to show for a run or history item: only a completed run has been scored. A queued or
   *  running run has no score yet, and a failed one never gets a complete one, so neither reads as "0, low". */
  function shownRisk(r) {
    return r && r.status === "completed" && r.summary ? r.summary.risk_score : null;
  }

  /** A count from a run's summary, or null when it would mislead: a queued or running run has no summary yet
   *  (it is computed when the run ends), and a failed run that found nothing established nothing, so "0 open
   *  ports" would read as a clean result. A failed run keeps the counts of what it found before it failed. The
   *  run tables, the Overview tile and the run's own KPI tiles all use this one rule. */
  function countFor(r, n) {
    if (!r || (r.status !== "completed" && r.status !== "failed")) return null;   // queued, running or unreadable
    if (r.status === "failed" && !Number(n)) return null;
    return n === undefined ? null : n;
  }

  /** A count from a run's summary for a table cell (see countFor). */
  function shownCount(r, n) {
    return fmtNum(countFor(r, n));
  }

  /** Small horizontal risk bar with the numeric score. */
  function riskBar(score) {
    if (score === null || score === undefined || isNaN(Number(score))) return '<span class="faint">-</span>';
    const n = Math.max(0, Math.min(100, Number(score)));
    const cls = riskClass(n);
    return '<span class="risk-bar" role="img" aria-label="Risk score ' + Math.round(n) + ' of 100"><span class="risk-track"><span class="risk-fill ' + cls + '" style="width:' + n + '%"></span></span><span class="risk-num ' + cls + '">' + Math.round(n) + "</span></span>";
  }

  /** KPI tile: label, big value (already-safe HTML) and an optional sub line. */
  function kpiTile(label, value, opts) {
    const o = opts || {};
    return '<div class="kpi ' + esc(o.cls || "") + '"><div class="kpi-label">' + esc(label) + '</div><div class="kpi-value">' + value + "</div>" + (o.sub ? '<div class="kpi-sub">' + esc(o.sub) + "</div>" : "") + "</div>";
  }

  /** Row of chips, or "none". `titleFor(item)` may return a tooltip for a chip (empty for none). */
  function chips(items, cls, titleFor) {
    if (!items || !items.length) return '<span class="faint">none</span>';
    return '<div class="chip-row">' + items.map((i) => {
      const title = titleFor ? titleFor(i) : "";
      return '<span class="chip ' + (cls || "") + '"' + (title ? ' title="' + esc(title) + '"' : "") + ">" + esc(i) + "</span>";
    }).join("") + "</div>";
  }

  /** Centered empty state with a focusable heading (the router moves focus to it). */
  function emptyState(title, text, actionHtml) {
    return '<div class="empty-state"><h2 tabindex="-1">' + esc(title) + "</h2>" + (text ? '<p class="muted">' + esc(text) + "</p>" : "") + (actionHtml || "") + "</div>";
  }

  /** Green yes / red no pill. */
  function boolPill(v, yes, no) {
    return v ? '<span class="pill pill-green">' + esc(yes || "yes") + "</span>" : '<span class="pill pill-red">' + esc(no || "no") + "</span>";
  }

  /** Title cell for run tables: a real link (keyboard reachable) plus the target or short id underneath. */
  function runTitleCell(r) {
    const name = r.label || r.target;
    return '<div class="cell-title"><a class="row-link" href="#run/' + encode(r.id) + '">' + esc(name) + "</a></div>" +
      '<div class="cell-sub">' + esc(r.label ? r.target : String(r.id).slice(0, 8)) + "</div>";
  }

  /* Shared state. Everything the views remember between renders lives here. */
  const state = {
    health: null,          // GET /api/health (provider, tools, limits, scope)
    tools: null,           // GET /api/tools, then the custom tools of GET /api/tools/custom tagged custom: true (see loadTools)
    runs: null,            // GET /api/runs (RunListItem[])
    currentPlan: null,     // plan shown in the planner (last viewed or generated)
    runPlan: null,         // {id, tools} attached to the New Run form from the planner
    runDetailRun: null,    // Run currently painted in the detail view
    runDetailTab: "summary",
    runSelection: new Set(), // run ids ticked in the Runs table for Compare
    settings: null,        // SettingsView as last loaded/saved (baseline for diffs)
    runsTotal: 0,          // runs stored on the server (X-Total-Count); more than state.runs.length when capped
  };

  /** The tool catalogue: the built-in tools, then the registered custom tools (tagged custom: true). A failed custom
   *  request never blanks the built-in tools on New Run, the Overview or the Planner. */
  async function loadTools(force) {
    if (state.tools && !force) return state.tools;
    const [builtIn, custom] = await Promise.all([api("/api/tools"), api("/api/tools/custom").catch(() => null)]);
    // Custom tools are local-only: another machine gets 403 and sees the built-in tools alone.
    state.tools = builtIn.concat(custom && custom.tools ? custom.tools.map((t) => Object.assign({ custom: true }, t)) : []);
    return state.tools;
  }

  async function loadHealth(force) {
    if (state.health && !force) return state.health;
    state.health = await api("/api/health");
    return state.health;
  }

  /** Most runs the dashboard lists (the API's own maximum). The Overview totals come from /api/health instead, and
   *  the Runs and Compare pages say when older runs are not listed. */
  const RUN_LIST_LIMIT = 1000;

  async function loadRuns(force) {
    if (state.runs && !force) return state.runs;
    let total = null;
    const runs = await api("/api/runs?limit=" + RUN_LIST_LIMIT, { onHeaders: (h) => { total = Number(h.get("X-Total-Count")); } });
    state.runs = runs;
    state.runsTotal = Number.isFinite(total) && total > runs.length ? total : runs.length;
    return state.runs;
  }

  /** "Showing the newest 1,000 of 1,234 runs." when the run list is not the whole history, else "". */
  function runsTruncatedText() {
    const shown = (state.runs || []).length;
    // Fewer runs than asked for is the whole history (the total may also count rows the list cannot show).
    return shown >= RUN_LIST_LIMIT && state.runsTotal > shown ? "Showing the newest " + fmtNum(shown) + " of " + fmtNum(state.runsTotal) + " runs; older runs are not listed." : "";
  }

  /** Tools pre-checked on the planner and New Run forms (DEFAULT_TOOLS in app/tools/registry.py). */
  const DEFAULT_TOOLS = ["nmap", "whatweb"];

  /** Is a tool installed on the server? Prefers /api/tools, falls back to the health flags. */
  function toolInstalled(name) {
    if (state.tools) {
      const t = state.tools.find((x) => x.name === name);
      if (t) return !!t.installed;
    }
    if (state.health && state.health.tools) return !!state.health.tools[name];
    return false;
  }

  /** Is a catalogue entry a custom tool (registered on the Custom tools page) rather than a built-in one? */
  function isCustomTool(t) { return !!(t && t.custom); }

  /** How a custom tool runs, in the words the Custom tools form, its list and New Run use. */
  const SCOPE_LABEL = { target: "once on the target", url: "once per web URL" };

  /** The label of a tool's profile (the preset option set a run used), from the catalogue in state.tools; the
   *  key itself when the catalogue is not loaded or no longer lists it. */
  function profileLabel(tool, key) {
    const t = state.tools && state.tools.find((x) => x.name === tool);
    const p = t && (t.profiles || []).find((x) => x.key === key);
    return p ? p.label : (key || "");
  }

  function toolDisplayName(name) {
    const t = state.tools && state.tools.find((x) => x.name === name);
    return t ? t.display_name || t.name : name;
  }

  /* ========================================================================
     3. Router
     Owns: hash parsing, the route sequence token, showing/hiding the view
     sections, moving focus to the new page heading and the mobile menu.
     Routes:  #overview  #planner[?plan=ID]  #new-run[?plan_id=ID&tools=a,b]
              #runs  #run/<id>  #compare[?base=ID&other=ID]  #settings  #tools  #about
     ======================================================================== */

  const views = {};
  $$(".view").forEach((v) => { views[v.dataset.view] = v; });

  // Every navigation bumps the sequence. Async renderers capture it and compare after each await,
  // so a slow response belonging to a page the user already left can never paint over the current one.
  let routeSeq = 0;
  const isCurrent = (seq) => seq === routeSeq;

  /** Split "#name/param?query" into { name, params, query }. */
  function parseHash() {
    const raw = (location.hash || "#overview").slice(1);
    const qIndex = raw.indexOf("?");
    const pathPart = qIndex >= 0 ? raw.slice(0, qIndex) : raw;
    const query = parseQuery(qIndex >= 0 ? raw.slice(qIndex) : "");
    const segments = pathPart.split("/").filter(Boolean);
    return { name: segments[0] || "overview", params: segments.slice(1).map(safeDecode), query };
  }

  function closeMobileNav() {
    $("#nav").classList.remove("open");
    $("#nav-toggle").setAttribute("aria-expanded", "false");
  }

  /** Move keyboard / screen-reader focus to the first heading of a container without scrolling. */
  function focusHeading(root) {
    if (!root) return;
    const h = root.querySelector("h1, h2");
    if (!h) return;
    if (!h.hasAttribute("tabindex")) h.setAttribute("tabindex", "-1");
    try { h.focus({ preventScroll: true }); } catch (_) { h.focus(); }
  }

  /** Show exactly one view section, mark its nav item current, close the mobile menu, focus its heading. */
  function showView(name) {
    Object.keys(views).forEach((k) => { views[k].hidden = k !== name; });
    const navName = name === "run" ? "runs" : name;
    $$(".nav-item").forEach((a) => {
      const active = a.dataset.route === navName;
      a.classList.toggle("active", active);
      if (active) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    });
    closeMobileNav();
    window.scrollTo({ top: 0 });
    focusHeading(views[name]);
  }

  /** The dispatcher: stop background work, take a new sequence number, render the view for the hash. */
  async function route() {
    stopRunPolling();           // first: nothing from the previous page may keep painting
    const seq = ++routeSeq;
    const r = parseHash();
    switch (r.name) {
      case "overview": showView("overview"); await renderOverview(seq); break;
      case "planner": showView("planner"); await renderPlanner(r, seq); break;
      case "new-run": showView("new-run"); await renderNewRun(r, seq); break;
      case "runs": showView("runs"); await renderRuns(seq); break;
      case "run":
        if (!r.params[0]) { location.replace("#runs"); return; }   // replace, so Back does not loop
        showView("run"); await renderRunDetail(r.params[0], seq); break;
      case "compare": showView("compare"); await renderCompare(r, seq); break;
      case "settings": showView("settings"); await renderSettings(seq); break;
      case "tools": showView("tools"); await renderTools(seq); break;
      case "about": showView("about"); break;
      default: showView("notfound");
    }
  }

  window.addEventListener("hashchange", () => { route().catch(toastError); });

  $("#nav-toggle").addEventListener("click", () => {
    const nav = $("#nav");
    const open = nav.classList.toggle("open");
    $("#nav-toggle").setAttribute("aria-expanded", open ? "true" : "false");
  });
  // Tapping the item for the current page fires no hashchange, so close the menu on any nav click.
  $$(".nav-item").forEach((a) => a.addEventListener("click", closeMobileNav));

  /* ========================================================================
     4. Overview (#overview)
     Owns: the health card, the tool cards, the KPI tiles computed from the
     run list and the "recent runs" table. Everything is re-fetched on each
     visit and on the Refresh button.
     ======================================================================== */

  /** Sidebar health line (dot + "app vX / provider"). */
  function renderHealthMini(health, error) {
    const dot = $("#health-dot");
    const txt = $("#health-mini-text");
    if (error || !health) {
      dot.className = "dot dot-red";
      txt.textContent = "API unreachable";
      return;
    }
    dot.className = "dot " + (health.status === "ok" ? "dot-green" : "dot-amber");
    txt.textContent = (health.app || "HybridSec") + " v" + (health.version || "?") + " / " + (health.ai_provider || "rules");
  }

  /** Service health card: version, provider/model, simulation flag, allowed scope, tool availability. */
  function renderHealthCard(health) {
    $("#health-status-pill").className = "pill " + (health.status === "ok" ? "pill-green" : "pill-amber");
    $("#health-status-pill").textContent = health.status || "unknown";
    const scope = (health.allowed_targets && health.allowed_targets.length)
      ? chips(health.allowed_targets, "mono")
      : '<span class="pill pill-amber">any target</span> <span class="muted small">(no HYBRIDSEC_ALLOWED_TARGETS restriction)</span>';
    const toolPills = Object.keys(health.tools || {}).map((t) => {
      const ok = !!(health.tools && health.tools[t]);
      return '<span class="pill ' + (ok ? "pill-green" : "pill-muted") + '">' + esc(t) + " " + (ok ? "installed" : "missing") + "</span>";
    }).join(" ");
    $("#health-body").innerHTML =
      '<dl class="kv">' +
      "<dt>Application</dt><dd>" + esc(health.app || "HybridSec") + "</dd>" +
      '<dt>Version</dt><dd class="mono">' + esc(health.version || "-") + "</dd>" +
      '<dt>AI provider</dt><dd><span class="pill pill-accent">' + esc(health.ai_provider || "rules") + "</span>" + (health.ai_model ? ' <span class="mono small">' + esc(health.ai_model) + "</span>" : ' <span class="muted small">no model</span>') + "</dd>" +
      "<dt>Simulation</dt><dd>" + boolPill(health.simulation_allowed, "allowed", "disabled") + "</dd>" +
      "<dt>Allowed scope</dt><dd>" + scope + "</dd>" +
      "<dt>Tools</dt><dd>" + toolPills + "</dd>" +
      "</dl>" +
      (health.ai_provider === "rules" ? '<div class="hint" style="margin-top:12px">The built-in rules planner is in use. <a href="#settings">Configure an AI provider in Settings</a></div>' : "");
  }

  /** One card per built-in tool from /api/tools, with the install hint when the tool is missing. Custom tools are
   *  listed on their own page (a hint under the cards links to it). */
  function renderToolCards(tools) {
    tools = (tools || []).filter((t) => !isCustomTool(t));
    const wrap = $("#tool-cards");
    if (!tools || !tools.length) { wrap.innerHTML = emptyState("No tools reported", "The backend returned an empty tool list."); return; }
    wrap.innerHTML = tools.map((t) => {
      const installed = !!t.installed;
      return '<div class="card tool-card"><div class="card-body">' +
        '<div class="tool-title"><h3>' + esc(t.display_name || t.name) + "</h3>" + boolPill(installed, "installed", "not installed") + "</div>" +
        '<div class="tool-meta">' +
        (t.stage ? '<span class="chip chip-accent">' + esc(t.stage) + "</span>" : "") +
        (t.category ? '<span class="chip chip-muted">' + esc(t.category) + "</span>" : "") +
        (t.version ? '<span class="chip mono">' + esc(t.version) + "</span>" : "") +
        "</div>" +
        '<p class="muted small" style="margin:0">' + esc(t.description || "") + "</p>" +
        (installed && t.path ? '<div class="small mono faint" style="overflow-wrap:anywhere">' + esc(t.path) + "</div>" : "") +
        (!installed && t.install_hint ? '<div class="tool-hint"><strong>Install:</strong> <code>' + esc(t.install_hint) + "</code></div>" : "") +
        "</div></div>";
    }).join("");
  }

  /** Numbers for the KPI tiles. The totals come from `counts` (the run counts in /api/health, which cover the
   *  whole history) when available, else from the run list (newest first, capped at RUN_LIST_LIMIT). */
  function computeKpis(runs, counts) {
    const total = counts ? counts.total : runs.length;
    const completed = counts ? counts.completed : runs.filter((r) => r.status === "completed").length;
    const failed = counts ? counts.failed : runs.filter((r) => r.status === "failed").length;
    const active = counts ? counts.active : runs.filter((r) => isActiveStatus(r.status)).length;
    const last = runs[0];
    const lastPorts = last && last.summary ? countFor(last, last.summary.open_ports) : null;
    const scored = runs.filter((r) => r.summary && r.summary.risk_score !== null && r.summary.risk_score !== undefined && r.status === "completed");
    const avgRisk = scored.length ? scored.reduce((a, r) => a + Number(r.summary.risk_score), 0) / scored.length : null;
    return { total, completed, failed, active, lastPorts, avgRisk, averaged: scored.length, partialAverage: runs.length >= RUN_LIST_LIMIT && total > runs.length };
  }

  function renderOverviewKpis(runs, counts) {
    const k = computeKpis(runs, counts);
    $("#overview-kpis").innerHTML =
      kpiTile("Total runs", fmtNum(k.total, "0")) +
      kpiTile("Completed", fmtNum(k.completed, "0"), { cls: "green", sub: k.failed ? k.failed + " failed" : (k.active ? k.active + " active" : "") }) +
      kpiTile("Open ports (last run)", k.lastPorts === null || k.lastPorts === undefined ? '<span class="faint">-</span>' : fmtNum(k.lastPorts), { cls: "accent" }) +
      kpiTile("Avg risk score", k.avgRisk === null ? '<span class="faint">-</span>' : Math.round(k.avgRisk), { cls: k.avgRisk === null ? "" : riskClass(k.avgRisk), sub: k.partialAverage && k.averaged ? "newest " + fmtNum(runs.length) + " runs" : "" });
  }

  /** "Recent runs" table: the eight newest runs, each title linking to its detail page. */
  function renderRecentRuns(runs) {
    const wrap = $("#recent-runs");
    if (!runs.length) {
      wrap.innerHTML = emptyState("No runs yet", "Execute the first hybrid workflow to populate this table.", '<a class="btn btn-primary" href="#new-run">New Run</a>');
      return;
    }
    const rows = runs.slice(0, 8).map((r) => {
      const s = r.summary || {};
      return '<tr class="clickable" data-href="#run/' + encode(r.id) + '">' +
        "<td>" + runTitleCell(r) + "</td>" +
        "<td>" + statusPill(r.status) + partialPill(r) + "</td>" +
        "<td>" + modePill(r.mode) + "</td>" +
        "<td>" + fmtDateShort(r.created_at) + "</td>" +
        '<td class="num">' + fmtDur(r.duration_seconds) + "</td>" +
        '<td class="num">' + shownCount(r, s.open_ports) + "</td>" +
        "<td>" + riskBar(shownRisk(r)) + "</td></tr>";
    }).join("");
    wrap.innerHTML = '<div class="table-wrap"><table class="table"><thead><tr><th>Run</th><th>Status</th><th>Mode</th><th>Created</th><th class="num">Duration</th><th class="num">Open ports</th><th>Risk</th></tr></thead><tbody>' + rows + "</tbody></table></div>";
  }

  /** Overview render: three requests in parallel; each card shows its own error if one fails. */
  async function renderOverview(seq) {
    const results = await Promise.allSettled([loadHealth(true), loadTools(true), loadRuns(true)]);
    if (!isCurrent(seq)) return;
    const [h, t, r] = results;
    if (h.status === "fulfilled") { renderHealthCard(h.value); renderHealthMini(h.value); }
    else { renderHealthMini(null, true); $("#health-body").innerHTML = '<div class="notice notice-danger" style="margin:0">' + esc(h.reason.message) + "</div>"; }
    if (t.status === "fulfilled") renderToolCards(t.value);
    else $("#tool-cards").innerHTML = '<div class="notice notice-danger" style="margin:0">' + esc(t.reason.message) + "</div>";
    if (r.status === "fulfilled") { renderOverviewKpis(r.value, h.status === "fulfilled" ? h.value.runs : null); renderRecentRuns(r.value); }
    else { $("#overview-kpis").innerHTML = ""; $("#recent-runs").innerHTML = emptyState("Could not load runs", r.reason.message); }
  }

  $("#overview-refresh").addEventListener("click", () => renderOverview(routeSeq).catch(toastError));

  /* ========================================================================
     5. AI Planner (#planner, #planner?plan=ID)
     Owns: the plan request form, the saved-plans list, the plan detail panel
     (summary, workflow steps, safety controls, download, "Execute this plan")
     and the refinement card. Plans are immutable once created, so a plan
     cached in state.currentPlan can be reused without re-fetching.
     ======================================================================== */

  /** Tool checkboxes for the plan request (nmap + whatweb pre-checked). Plans never include custom tools. */
  function renderPlanToolChecks(tools) {
    tools = (tools || []).filter((t) => !isCustomTool(t));
    const wrap = $("#plan-tools");
    if (!tools || !tools.length) { wrap.innerHTML = '<span class="muted">No tools available.</span>'; return; }
    wrap.innerHTML = tools.map((t) => {
      const checked = DEFAULT_TOOLS.includes(t.name);
      return '<label class="check-item"><input type="checkbox" name="tools" value="' + esc(t.name) + '"' + (checked ? " checked" : "") + "><span>" + esc(t.display_name || t.name) + '</span><span class="check-meta">' + (t.installed ? "installed" : "not installed") + "</span></label>";
    }).join("");
  }

  /** Workflow steps of a plan ordered by their `order` field. */
  function sortedSteps(plan) {
    return (((plan && plan.plan) || {}).workflow || []).slice().sort((a, b) => (a.order || 0) - (b.order || 0));
  }

  /** The tools a run of this plan may use: the workflow steps (normalisation or refinement can drop requested tools). */
  function planWorkflowTools(plan) {
    const fromSteps = uniq(sortedSteps(plan).map((s) => s.tool));
    return fromSteps.length ? fromSteps : uniq((plan && plan.request && plan.request.tools) || []);
  }

  function planHash(id) { return "#planner?plan=" + encode(id); }

  /** Replace the plan panel with a not-found notice and forget the cached plan. */
  function renderPlanNotFound(id, message) {
    state.currentPlan = null;
    $("#plan-result").innerHTML = '<div class="card">' + emptyState("Plan not found", message || ("No plan with id " + id + " exists. It may have been deleted."), '<a class="btn btn-ghost" href="#planner">Back to the planner</a>') + "</div>";
  }

  /** Fetch a plan and render it, unless the route changed while waiting. */
  async function loadPlanInto(id, seq, scroll) {
    try {
      const plan = await api("/api/ai/plans/" + encode(id));
      if (!isCurrent(seq)) return;
      renderPlan(plan, { scroll });
    } catch (e) {
      if (!isCurrent(seq)) return;
      if (e.status === 404) renderPlanNotFound(id, e.message); else toastError(e);
    }
  }

  /** One numbered step card of the workflow. */
  function renderPlanStep(s, index, avail) {
    const available = avail[s.tool];
    return '<div class="step-card"><div class="step-num" aria-hidden="true">' + esc(s.order || index + 1) + "</div><div>" +
      '<div class="step-head"><span class="step-tool">' + esc(toolDisplayName(s.tool)) + "</span>" +
      (s.stage ? '<span class="pill pill-accent">' + esc(s.stage) + "</span>" : "") +
      (available === undefined ? "" : boolPill(available, "available", "not installed")) +
      "</div>" +
      '<div class="muted">' + esc(s.purpose || "") + "</div>" +
      '<div class="step-io"><div><div class="step-io-label">Inputs</div>' + chips(s.inputs) + '</div><div><div class="step-io-label">Outputs</div>' + chips(s.outputs) + "</div></div>" +
      (s.command_template ? '<div class="cmd"><span class="prompt">$ </span>' + esc(s.command_template) + "</div>" : "") +
      "</div></div>";
  }

  /** Bulleted list or "none". */
  function listOrNone(arr) {
    return (arr && arr.length) ? '<ul class="list-plain">' + arr.map((x) => "<li>" + esc(x) + "</li>").join("") + "</ul>" : '<div class="faint small">none</div>';
  }

  const FEEDBACK_MIN = 3, FEEDBACK_MAX = 2000;   // bounds of RefineRequest.feedback in app/schemas.py

  /** The "Refine this plan" card (textarea + button) appended under every plan. */
  function renderRefineCard(nextRevision) {
    return '<div class="card" id="plan-refine-card"><div class="card-head"><h2>Refine this plan</h2><span class="muted small">Creates revision ' + nextRevision + "</span></div>" +
      '<div class="card-body">' +
      '<div class="field"><label for="plan-refine-feedback">Feedback</label>' +
      '<textarea id="plan-refine-feedback" rows="3" maxlength="' + FEEDBACK_MAX + '" placeholder="What should change? For example: drop Nikto, shorten the limitations, add detail on rate limiting."></textarea>' +
      '<div class="hint">' + FEEDBACK_MIN + " to " + FEEDBACK_MAX + " characters. The planner produces a new revision and keeps this one unchanged.</div></div>" +
      '<div class="form-actions"><span class="muted small" id="plan-refine-status" role="status" hidden>Asking the planner, this can take up to a minute</span>' +
      '<button class="btn btn-primary" type="button" id="plan-refine-submit">Refine</button></div>' +
      "</div></div>";
  }

  /**
   * Paint the plan detail panel. `opts.scroll` scrolls the panel into view (only when the URL
   * asked for a specific plan or one was just created, so plain #planner stays at the form).
   */
  function renderPlan(plan, opts) {
    const o = opts || {};
    state.currentPlan = plan;
    const p = plan.plan || {};
    const sc = p.safety_controls || {};
    const steps = sortedSteps(plan);
    const avail = plan.tools_available || {};
    const rev = Number(plan.revision) || 1;
    const stepsHtml = steps.length ? steps.map((s, i) => renderPlanStep(s, i, avail)).join("") : '<div class="empty-inline">The plan has no workflow steps.</div>';

    // Execute uses the workflow's tools, never the original request (which may include tools the plan dropped).
    const tools = planWorkflowTools(plan);
    const execHash = "#new-run?plan_id=" + encode(plan.id) + "&tools=" + encode(tools.join(","));

    $("#plan-result").innerHTML =
      '<div class="card"><div class="card-head"><div class="plan-header-row"><h2 tabindex="-1">Plan</h2>' + statusPill(plan.status) +
      '<span class="pill pill-blue">' + esc(plan.provider || "rules") + (plan.model ? " / " + esc(plan.model) : "") + "</span>" +
      '<span class="pill pill-muted">Rev ' + rev + "</span>" +
      '<span class="muted small mono">' + esc(plan.id) + "</span></div>" +
      '<div class="view-actions"><a class="btn btn-primary" href="' + esc(execHash) + '">Execute this plan</a>' +
      '<button class="btn btn-ghost" type="button" id="plan-download">Download plan JSON</button></div></div>' +
      '<div class="card-body">' +
      (plan.provider === "rules" && !plan.note ? '<div class="hint" style="margin-bottom:12px">This plan comes from the built-in rules planner. <a href="#settings">Configure an AI provider in Settings</a> for model-written plans.</div>' : "") +
      (plan.note ? '<div class="notice notice-warn" style="margin:0 0 16px"><strong>Planner note:</strong> ' + esc(plan.note) + "</div>" : "") +
      (plan.parent_id ? '<div class="hint" style="margin-bottom:12px">Refined from <a class="mono" href="' + esc(planHash(plan.parent_id)) + '">' + esc(plan.parent_id) + "</a></div>" : "") +
      (plan.feedback ? '<div class="quote"><div class="quote-label">' + (plan.note ? "Feedback (not applied: see the planner note)" : "Feedback applied") + "</div>" + esc(plan.feedback) + "</div>" : "") +
      '<p class="plan-summary">' + esc(p.summary || "No summary provided.") + "</p>" +
      '<div class="muted small">Created ' + fmtDate(plan.created_at) + (plan.request && plan.request.target_hint ? ' &middot; target hint <span class="mono">' + esc(plan.request.target_hint) + "</span>" : "") + "</div>" +
      '<h3 class="sub-h" style="margin-top:20px">Workflow</h3>' +
      '<div class="plan-steps">' + stepsHtml + "</div>" +
      '<div class="grid grid-2" style="margin-top:20px">' +
      '<div><h3 class="sub-h">Inputs</h3>' + listOrNone(p.inputs) + "</div>" +
      '<div><h3 class="sub-h">Outputs</h3>' + listOrNone(p.outputs) + "</div>" +
      "</div>" +
      '<h3 class="sub-h" style="margin-top:20px">Safety controls</h3>' +
      '<div class="grid grid-2">' +
      '<div><div class="step-io-label">Authorization required</div>' + boolPill(sc.authorization_required !== false, "required", "not required") +
      '<div class="step-io-label" style="margin-top:12px">Scope restrictions</div>' + listOrNone(sc.scope_restrictions) + "</div>" +
      '<div><div class="step-io-label">Rate limits</div>' + listOrNone(sc.rate_limits) +
      '<div class="step-io-label" style="margin-top:12px">Data handling</div>' + listOrNone(sc.data_handling) + "</div>" +
      "</div>" +
      '<h3 class="sub-h" style="margin-top:20px">Limitations</h3>' + listOrNone(p.limitations) +
      (plan.request && plan.request.objective ? '<h3 class="sub-h" style="margin-top:20px">Objective</h3><p class="muted">' + esc(plan.request.objective) + "</p>" : "") +
      "</div></div>" +
      renderRefineCard(rev + 1);

    $("#plan-download").addEventListener("click", () => {
      downloadBlob("hybridsec-plan-" + String(plan.id).slice(0, 12) + ".json", JSON.stringify(plan, null, 2), "application/json");
    });
    $("#plan-refine-submit").addEventListener("click", () => refinePlan(plan, rev));
    if (o.scroll) $("#plan-result").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  /** Send operator feedback to POST /api/ai/plans/{id}/refine and navigate to the new revision. */
  async function refinePlan(plan, rev) {
    const btn = $("#plan-refine-submit");
    const ta = $("#plan-refine-feedback");
    const status = $("#plan-refine-status");
    const feedback = ta.value.trim();
    if (feedback.length < FEEDBACK_MIN) { toast("Describe what should change (at least " + FEEDBACK_MIN + " characters).", "warn", "Refine"); ta.focus(); return; }
    if (feedback.length > FEEDBACK_MAX) { toast("Feedback must be " + FEEDBACK_MAX + " characters or fewer.", "warn", "Refine"); ta.focus(); return; }
    const seq = routeSeq;
    status.hidden = false;
    ta.disabled = true;
    setBusy(btn, "Refining...");
    try {
      const revised = await api("/api/ai/plans/" + encode(plan.id) + "/refine", { method: "POST", body: { feedback } });
      toast("Revision " + (revised.revision || rev + 1) + " created", "success", "Planner");
      if (!isCurrent(seq)) return;             // user navigated away meanwhile: do not pull them back
      state.currentPlan = revised;
      const target = planHash(revised.id);
      if (location.hash === target) { renderPlan(revised, { scroll: true }); renderSavedPlans(); }
      else location.hash = target;              // route() renders the revision and refreshes the saved-plans list
    } catch (e) {
      toastError(e, "Refinement failed");       // textarea content is kept for another attempt
    } finally {
      if (document.body.contains(btn)) { clearBusy(btn); status.hidden = true; ta.disabled = false; }
    }
  }

  /** One row of the saved-plans list: a link to #planner?plan=ID with revision and status pills. */
  function renderSavedPlanItem(pl) {
    const tools = (pl.request && pl.request.tools) || [];
    const summary = (pl.plan && pl.plan.summary) || (pl.request && pl.request.objective) || pl.id;
    const revision = Number(pl.revision) || 1;
    return '<a class="plan-list-item" href="' + esc(planHash(pl.id)) + '" data-plan-id="' + esc(pl.id) + '" title="' + esc(summary) + '">' +
      '<div style="min-width:0"><div class="pl-title">' + esc(summary) + '</div><div class="pl-meta"><span>' + fmtDateShort(pl.created_at) + "</span><span>" + esc(pl.provider || "rules") + "</span><span>" + esc(tools.join(", ")) + "</span></div></div>" +
      '<div class="pl-pills">' + (revision > 1 ? '<span class="pill pill-muted">Rev ' + revision + "</span>" : "") + '<span class="pill pill-blue">' + esc(pl.status || "planned") + "</span></div></a>";
  }

  /** Saved plans from GET /api/ai/plans, in the API's order (newest first). */
  async function renderSavedPlans() {
    const wrap = $("#saved-plans");
    // Only blank the list on first load; later refreshes swap the content in place to avoid flicker.
    if (!$(".plan-list-item", wrap)) wrap.innerHTML = '<div class="loading-row"><span class="spinner"></span> Loading plans...</div>';
    let plans;
    try { plans = await api("/api/ai/plans"); }
    catch (e) { wrap.innerHTML = '<div class="empty-inline">' + esc(e.message) + "</div>"; return; }
    if (!plans || !plans.length) { wrap.innerHTML = '<div class="empty-inline">No saved plans yet. Generate one to see it here.</div>'; return; }
    wrap.innerHTML = plans.map(renderSavedPlanItem).join("");
    $$(".plan-list-item", wrap).forEach((el) => {
      el.addEventListener("click", (ev) => {
        // Normal link navigation handles the common case; re-selecting the open plan re-fetches it.
        if (location.hash !== planHash(el.dataset.planId)) return;
        ev.preventDefault();
        loadPlanInto(el.dataset.planId, routeSeq, true);
      });
    });
  }

  /** Planner render: tool checkboxes (once), saved plans, and the plan named in ?plan= if any. */
  async function renderPlanner(r, seq) {
    try {
      const tools = await loadTools();
      if (!isCurrent(seq)) return;
      if (!$("#plan-tools input")) renderPlanToolChecks(tools);
    } catch (e) {
      if (!isCurrent(seq)) return;
      if (!$("#plan-tools input")) $("#plan-tools").innerHTML = '<span class="muted">' + esc(e.message) + "</span>";
    }
    renderSavedPlans();
    const wanted = r && r.query && r.query.plan;
    if (wanted) {
      if (state.currentPlan && state.currentPlan.id === wanted) renderPlan(state.currentPlan, { scroll: true });
      else await loadPlanInto(wanted, seq, true);
    } else if (state.currentPlan) {
      renderPlan(state.currentPlan, { scroll: false });   // plain #planner: show it, but stay at the form
    }
  }

  /** POST /api/ai/plan from the request form, then navigate to the new plan. */
  async function submitPlanForm(ev) {
    ev.preventDefault();
    const tools = $$("#plan-tools input:checked").map((i) => i.value);
    if (!tools.length) { toast("Select at least one tool.", "warn", "Validation"); return; }
    const body = { tools, objective: $("#plan-objective").value.trim() };
    const hint = $("#plan-target-hint").value.trim();
    if (hint) body.target_hint = hint;
    const btn = $("#plan-submit");
    const seq = routeSeq;
    setBusy(btn, "Planning...");
    try {
      const plan = await api("/api/ai/plan", { method: "POST", body });
      toast("Plan generated with " + (plan.provider || "rules") + ".", "success", "Planner");
      state.currentPlan = plan;
      if (!isCurrent(seq)) return;
      const target = planHash(plan.id);
      if (location.hash === target) { renderPlan(plan, { scroll: true }); renderSavedPlans(); }
      else location.hash = target;
    } catch (e) {
      toastError(e, "Planning failed");
    } finally {
      clearBusy(btn);
    }
  }

  $("#plan-form").addEventListener("submit", submitPlanForm);
  $("#plans-refresh").addEventListener("click", () => renderSavedPlans());

  /* ========================================================================
     6. New Run (#new-run, #new-run?plan_id=ID&tools=a,b)
     Owns: the run form, the tool checkboxes, the optional plan attachment
     (chip + state.runPlan), the simulation suggestion and the server limits.
     Invariant: the tool checkboxes are always painted from state.runPlan
     (plan attached) or from the installed defaults (no plan), so the chip
     and the checkboxes can never disagree.
     ======================================================================== */

  const RUN_TOOL_ORDER = ["nmap", "whatweb", "nikto"];
  const DEFAULT_TOP_PORTS = 100;   // spec default; capped by the server's max_top_ports

  /**
   * Paint the tool rows: a checkbox per tool and, beside it, a drop-down of the tool's profiles
   * (the preset option sets /api/tools lists for it, default first). With a plan attached the
   * plan's workflow decides what is checked and selectable (tools may be dropped, never added);
   * without one the installed defaults (nmap, whatweb) are pre-checked. `keep` ({tools, waiting,
   * profiles}, see currentToolSelection) preserves the user's ticks and profile choices when only
   * the simulation toggle changed. A box that cannot be ticked yet (Nikto not installed, simulation
   * off) carries data-waiting when it is meant to be ticked, so the tick returns once the tool can run.
   * Custom tools follow the built-in ones (in the API's order, by name, which is the order they run in), are never
   * pre-checked, have no profile and, like Nikto, can only be ticked when installed or simulated; a plan run never
   * lists them, so with a plan attached they show "not in plan".
   */
  function renderRunToolChecks(tools, keep) {
    const wrap = $("#run-tools");
    const byName = {};
    (tools || []).forEach((t) => { byName[t.name] = t; });
    const ordered = RUN_TOOL_ORDER.filter((n) => byName[n]).concat((tools || []).map((t) => t.name).filter((n) => RUN_TOOL_ORDER.indexOf(n) < 0));
    if (!ordered.length) { wrap.innerHTML = '<span class="muted">No tools available.</span>'; return; }
    const simulate = $("#run-simulate").checked;
    const plan = state.runPlan;
    const preselected = keep ? keep.tools.concat(keep.waiting || []) : null;
    const keptProfiles = (keep && keep.profiles) || {};
    wrap.innerHTML = ordered.map((name, i) => {
      const t = byName[name];
      const usable = !t.refused && (!!t.installed || simulate);  // a refused custom tool cannot run at all
      const inPlan = !plan || plan.tools.indexOf(name) >= 0;
      let checked;
      if (plan) checked = inPlan && (preselected ? preselected.indexOf(name) >= 0 : true);
      else if (preselected) checked = preselected.indexOf(name) >= 0;
      else checked = DEFAULT_TOOLS.includes(name) && usable;        // never pre-check a missing tool
      // Nikto and the custom tools are optional and only offered when usable; a plan run may drop tools from its
      // workflow but not add any.
      const selectable = inPlan && (usable || !(name === "nikto" || isCustomTool(t)));
      const disabled = !selectable;
      const on = checked && !disabled;
      let meta;
      if (!inPlan) meta = "not in plan";
      else if (isCustomTool(t)) meta = customToolMeta(t, simulate);
      else if (t.installed) meta = t.version || "installed";
      else if (simulate) meta = "simulated";
      else meta = plan ? "in plan, not installed" : "not installed";
      return '<div class="tool-row' + (disabled ? " disabled" : "") + '">' +
        '<label class="check-item' + (disabled ? " disabled" : "") + '"><input type="checkbox" name="tools" value="' + esc(name) + '"' + (on ? " checked" : "") + (disabled ? " disabled" : "") + (disabled && checked ? " data-waiting" : "") + "><span>" + (i + 1) + ". " + esc(t.display_name || name) + '</span><span class="check-meta">' + esc(meta) + "</span></label>" +
        profileSelectHtml(t, keptProfiles[name], !on) +
        "</div>";
    }).join("");
    $$(".tool-profile-select", wrap).forEach(updateProfileHint);
  }

  /** The meta text of a custom tool's row on New Run: that it is custom, how it runs and whether it can run here. A
   *  blocked tool (its program was found, but the file it resolves to is refused) cannot run live; like a missing
   *  one it can still be simulated. */
  function customToolMeta(t, simulate) {
    if (t.refused) return "custom, refused by the current rules (see Custom tools)";
    const meta = "custom, " + (SCOPE_LABEL[t.scope] || t.scope);
    if (t.installed) return meta;
    if (t.blocked) return meta + (simulate ? ", simulated (its program is refused for live runs)" : ", program refused (see Custom tools)");
    return meta + (simulate ? ", simulated" : ", not installed");
  }

  /**
   * The profile drop-down of one tool plus the hint line that explains the chosen profile. `chosenKey`
   * (a key kept from the previous paint) wins when the tool still offers it; otherwise the tool's default
   * is selected. The control is disabled while the tool is unticked, so only ticked tools send a profile.
   */
  function profileSelectHtml(tool, chosenKey, disabled) {
    const profiles = tool.profiles || [];
    if (!profiles.length) return "";
    const fallback = profiles.find((p) => p.default) || profiles[0];
    const current = profiles.some((p) => p.key === chosenKey) ? chosenKey : fallback.key;
    const id = "run-profile-" + tool.name;
    return '<div class="tool-profile">' +
      '<label class="sr-only" for="' + esc(id) + '">' + esc(tool.display_name || tool.name) + " profile</label>" +
      '<select id="' + esc(id) + '" class="tool-profile-select" data-tool="' + esc(tool.name) + '" aria-describedby="' + esc(id) + '-hint"' + (disabled ? " disabled" : "") + ">" +
      profiles.map((p) => '<option value="' + esc(p.key) + '"' + (p.key === current ? " selected" : "") + ">" + esc(p.label) + "</option>").join("") +
      "</select>" +
      '<div class="hint tool-profile-hint" id="' + esc(id) + '-hint"></div>' +
      "</div>";
  }

  /** Write the explanation of a drop-down's selected profile (its description, then the flags it adds) under it. */
  function updateProfileHint(select) {
    const tool = state.tools && state.tools.find((t) => t.name === select.dataset.tool);
    const profile = tool && (tool.profiles || []).find((p) => p.key === select.value);
    const hint = select.nextElementSibling;
    if (!hint) return;
    hint.textContent = profile ? profile.description + " " + (profile.flags ? "Adds: " + profile.flags : "No extra options.") : "";
  }

  /** What the operator has ticked and chosen right now: {tools: [...], waiting: [...], profiles: {tool: profile key}}.
   *  `waiting` names the tools meant to be ticked whose box is disabled until they can run; they are not sent. */
  function currentToolSelection() {
    const selection = { tools: [], waiting: $$('#run-tools input[name="tools"][data-waiting]').map((input) => input.value), profiles: {} };
    $$('#run-tools input[name="tools"]:checked').forEach((input) => {
      selection.tools.push(input.value);
      const row = input.closest(".tool-row");
      const select = row && row.querySelector(".tool-profile-select");
      if (select && select.value) selection.profiles[input.value] = select.value;
    });
    return selection;
  }

  /** Repaint the tool rows from the current state; `keep` ({tools, profiles}) preserves existing ticks and profile
   *  choices. No-op until the tool list is loaded. */
  function syncRunTools(keep) {
    if (!state.tools) return;      // an error message may be showing in the tool area
    renderRunToolChecks(state.tools, keep || null);
  }

  /** Attach (or detach, with null) a plan to the form: updates state, the chip and the checkboxes together. */
  function setRunPlan(planId, tools) {
    const field = $("#run-plan-field");
    const chip = $("#run-plan-chip");
    const hint = $("#run-plan-tools");
    if (planId) {
      state.runPlan = { id: planId, tools: uniq(tools) };
      field.hidden = false;
      chip.textContent = planId;
      hint.textContent = state.runPlan.tools.length ? "Plan workflow: " + state.runPlan.tools.join(" -> ") + ". Tools can be dropped but not added." : "";
    } else {
      state.runPlan = null;
      field.hidden = true;
      chip.textContent = "";
      hint.textContent = "";
    }
    syncRunTools(null);
  }

  /**
   * Workflow tools of a plan: from the cached plan when possible, otherwise fetched. The hand-off list in the
   * URL is only a fallback for a transient failure (network, 5xx); a 404 means the plan no longer exists, and
   * attaching it would give a form whose every submit fails with "Plan not found".
   */
  async function resolvePlanTools(planId, fallback) {
    if (state.currentPlan && state.currentPlan.id === planId) return planWorkflowTools(state.currentPlan);
    try {
      return planWorkflowTools(await api("/api/ai/plans/" + encode(planId)));
    } catch (e) {
      if (e.status !== 404 && fallback && fallback.length) return fallback;
      throw e;
    }
  }

  /** Copy the server's limits (health.limits) onto the timeout / top-ports inputs; user edits are kept. */
  function applyRunLimits(limits) {
    const l = limits || {};
    const timeout = $("#run-timeout");
    const ports = $("#run-top-ports");
    if (l.max_timeout_seconds) timeout.max = l.max_timeout_seconds; else timeout.removeAttribute("max");
    if (l.max_top_ports) ports.max = l.max_top_ports; else ports.removeAttribute("max");
    if (!timeout.dataset.userEdited && l.default_timeout_seconds) timeout.value = l.default_timeout_seconds;
    if (!ports.dataset.userEdited) ports.value = l.max_top_ports ? Math.min(DEFAULT_TOP_PORTS, Number(l.max_top_ports)) : DEFAULT_TOP_PORTS;
    $("#run-limits-hint").textContent = l.max_timeout_seconds
      ? "Server limits: timeout up to " + fmtNum(l.max_timeout_seconds) + " s, top ports up to " + fmtNum(l.max_top_ports) +
        (l.max_concurrent_runs ? ", " + fmtNum(l.max_concurrent_runs) + " concurrent run" + (Number(l.max_concurrent_runs) === 1 ? "" : "s") : "") + "."
      : "";
  }

  /** Amber hint under the simulation toggle: recommend it when nmap is missing, warn when the server forbids it. */
  function updateSimulationSuggestion() {
    const el = $("#run-simulate-suggest");
    const nmapOk = toolInstalled("nmap");
    const allowed = !state.health || state.health.simulation_allowed !== false;
    if (!nmapOk && allowed && !$("#run-simulate").checked) {
      el.hidden = false;
      el.textContent = "Nmap is not installed on the server, so a live run will fail. Simulation mode is recommended.";
    } else if (!allowed && $("#run-simulate").checked) {
      el.hidden = false;
      el.textContent = "Simulation is disabled by the server configuration (HYBRIDSEC_ALLOW_SIMULATION=false).";
    } else {
      el.hidden = true;
      el.textContent = "";
    }
  }

  /** New Run render: load tools + fresh health, attach the plan named in the URL, apply limits, paint checkboxes. */
  async function renderNewRun(r, seq) {
    const q = (r && r.query) || {};
    const results = await Promise.allSettled([loadTools(true), loadHealth(true)]);   // both refreshed: live limits and scope, and a tool installed or removed since the catalogue was cached
    if (!isCurrent(seq)) return;
    const toolsError = results[0].status === "rejected" ? results[0].reason : null;

    // Until the operator flips the switch, simulation is on when nmap is missing. This must come before the
    // plan hand-off below, which paints the tool rows: whether a tool that is not installed can be ticked
    // depends on it, and a row painted too early would drop a plan's missing tool (Nikto) from the run.
    if (!$("#run-simulate").dataset.touched) {
      const allowed = !state.health || state.health.simulation_allowed !== false;
      $("#run-simulate").checked = allowed && !toolInstalled("nmap");
    }

    // Plan hand-off from the planner: the plan's workflow decides which tools may run.
    if (q.plan_id) {
      const fallback = q.tools ? q.tools.split(",").map((s) => s.trim()).filter(Boolean) : [];
      try {
        const planTools = await resolvePlanTools(q.plan_id, fallback);
        if (!isCurrent(seq)) return;
        setRunPlan(q.plan_id, planTools);
      } catch (e) {
        if (!isCurrent(seq)) return;
        setRunPlan(null);
        toast("Plan " + q.plan_id + " could not be loaded (" + e.message + "). Choose the tools manually.", "warn", "Plan");
      }
    }
    // Without plan_id in the URL an attached plan stays until the operator clears it. The target is never prefilled from the URL.

    applyRunLimits(state.health && state.health.limits);

    if (toolsError) $("#run-tools").innerHTML = '<span class="hint hint-warn">Could not load the tool list: ' + esc(toolsError.message) + "</span>";
    // Coming back to the form keeps the tools and profiles the operator chose, like the target and the other
    // fields; only the first paint starts from the defaults (or from the plan, which setRunPlan already painted).
    else syncRunTools($$("#run-tools .tool-row").length ? currentToolSelection() : null);
    updateSimulationSuggestion();

    const scope = state.health && state.health.allowed_targets;
    $("#run-scope-hint").textContent = scope && scope.length
      ? "Allowed scope: " + scope.join(", ")
      : "No scope restriction is configured on the server.";
  }

  /** POST /api/hybridizations/execute, then reset the per-run inputs and open the run detail page. */
  async function submitRunForm(ev) {
    ev.preventDefault();
    const target = $("#run-target").value.trim();
    if (!target) { toast("Target is required.", "warn", "Validation"); return; }
    if (!$("#run-authorized").checked) { toast("You must confirm that you are authorized to test this target.", "warn", "Authorization"); return; }
    const selection = currentToolSelection();
    const tools = selection.tools;
    if (!tools.length) { toast("Select at least one tool.", "warn", "Validation"); return; }
    const body = { target, authorized: true, tools, simulate: $("#run-simulate").checked };
    if (Object.keys(selection.profiles).length) body.profiles = selection.profiles;   // one entry per ticked tool
    const timeout = Number($("#run-timeout").value);
    if (timeout > 0) body.timeout_seconds = timeout;        // blank: the server applies its default
    const topPorts = Number($("#run-top-ports").value);
    if (topPorts > 0) body.top_ports = topPorts;
    const label = $("#run-label").value.trim();
    if (label) body.label = label;
    if (state.runPlan) body.plan_id = state.runPlan.id;

    const btn = $("#run-submit");
    setBusy(btn, "Queuing...");
    try {
      const run = await api("/api/hybridizations/execute", { method: "POST", body });
      state.runs = null;
      toast("Run queued" + (run.mode === "simulated" ? " in simulation mode" : "") + ".", "success", "Run " + String(run.id).slice(0, 8));
      // Nothing carries over to the next run: target, authorization, label, plan and edited limits are reset,
      // and the plan is dropped from this history entry so Back does not re-attach the plan just executed.
      $("#run-label").value = "";
      $("#run-target").value = "";
      $("#run-authorized").checked = false;
      ["#run-timeout", "#run-top-ports"].forEach((sel) => { delete $(sel).dataset.userEdited; });
      setRunPlan(null);
      history.replaceState(null, "", "#new-run");
      location.hash = "#run/" + encode(run.id);
    } catch (e) {
      toastError(e, e.status === 429 ? "Too many concurrent runs" : "Could not start run");
    } finally {
      clearBusy(btn);
    }
  }

  $("#run-form").addEventListener("submit", submitRunForm);
  $("#run-simulate").addEventListener("change", () => {
    $("#run-simulate").dataset.touched = "1";
    syncRunTools(currentToolSelection());
    updateSimulationSuggestion();
  });
  // Ticking a tool enables its profile drop-down (an unticked tool sends no profile); choosing a profile updates its hint.
  $("#run-tools").addEventListener("change", (ev) => {
    const el = ev.target;
    if (el.matches('input[name="tools"]')) {
      const row = el.closest(".tool-row");
      const select = row && row.querySelector(".tool-profile-select");
      if (select) select.disabled = !el.checked;
    } else if (el.matches(".tool-profile-select")) {
      updateProfileHint(el);
    }
  });
  $("#run-plan-clear").addEventListener("click", () => {
    setRunPlan(null);
    toast("Plan reference cleared. The run will use the selected tools only.", "info");
  });
  // Authorization is per target: any edit to the target revokes the confirmation.
  $("#run-target").addEventListener("input", () => { $("#run-authorized").checked = false; });
  ["#run-timeout", "#run-top-ports"].forEach((sel) => $(sel).addEventListener("input", (ev) => { ev.target.dataset.userEdited = "1"; }));

  /* ========================================================================
     7. Runs (#runs)
     Owns: the table of all runs, the per-row Delete button, the checkbox
     selection that enables "Compare selected" and the delegated row click.
     ======================================================================== */

  function updateCompareButton() {
    const btn = $("#runs-compare");
    btn.disabled = state.runSelection.size !== 2;
    btn.textContent = state.runSelection.size === 2 ? "Compare selected" : "Compare selected (" + state.runSelection.size + "/2)";
  }

  /** One table row for a RunListItem. Delete is disabled while the run is queued or running. */
  function renderRunRow(r) {
    const s = r.summary || {};
    const name = r.label || r.target;
    const checked = state.runSelection.has(r.id);
    const active = isActiveStatus(r.status);
    return '<tr class="clickable" data-href="#run/' + encode(r.id) + '">' +
      '<td class="noclick"><input type="checkbox" class="run-select" value="' + esc(r.id) + '"' + (checked ? " checked" : "") + ' aria-label="Select run ' + esc(name) + ' for comparison"></td>' +
      "<td>" + runTitleCell(r) + "</td>" +
      "<td>" + statusPill(r.status) + partialPill(r) + "</td>" +
      "<td>" + modePill(r.mode) + "</td>" +
      '<td class="col-tools">' + chips(r.tools, "chip-muted", (t) => (r.profiles && r.profiles[t] ? profileLabel(t, r.profiles[t]) : "")) + "</td>" +
      '<td class="col-date">' + fmtDateShort(r.created_at) + "</td>" +
      '<td class="num">' + fmtDur(r.duration_seconds) + "</td>" +
      '<td class="num">' + shownCount(r, s.open_ports) + "</td>" +
      '<td class="num">' + shownCount(r, s.web_services) + "</td>" +
      '<td class="num">' + shownCount(r, s.vulnerabilities) + "</td>" +
      "<td>" + riskBar(shownRisk(r)) + "</td>" +
      '<td class="actions noclick"><button class="btn btn-danger btn-sm run-delete" type="button" data-id="' + esc(r.id) + '" data-name="' + esc(name) + '" aria-label="Delete run ' + esc(name) + '"' +
      (active ? ' disabled title="Runs can be deleted once they have finished"' : "") + ">Delete</button></td>" +
      "</tr>";
  }

  /** Confirm, DELETE /api/runs/{id}, then reload the table. */
  async function deleteRunFromTable(btn) {
    const ok = await confirmDialog('Delete run "' + btn.dataset.name + '"? This cannot be undone.', "Delete", "Delete run");
    if (!ok) return;
    try {
      await api("/api/runs/" + encode(btn.dataset.id), { method: "DELETE" });
      state.runSelection.delete(btn.dataset.id);
      toast("Run deleted.", "success");
      await renderRuns(routeSeq);
    } catch (e) { toastError(e, "Delete failed"); }
  }

  /** Paint the runs table and bind its checkboxes and Delete buttons. */
  function renderRunsTable(runs) {
    const wrap = $("#runs-table");
    if (!runs.length) {
      wrap.innerHTML = emptyState("No runs recorded", "Start a workflow against an authorized target or try simulation mode.", '<a class="btn btn-primary" href="#new-run">New Run</a>');
      return;
    }
    const truncated = runsTruncatedText();
    wrap.innerHTML = (truncated ? '<div class="notice notice-info" style="margin:0 0 12px">' + esc(truncated) + "</div>" : "") +
      '<div class="table-wrap"><table class="table table-compact runs-table"><thead><tr><th><span class="sr-only">Select</span></th><th>Run</th><th>Status</th><th>Mode</th><th class="col-tools">Tools</th><th>Created</th><th class="num">Duration</th><th class="num">Ports</th><th class="num">Web</th><th class="num">Vulns</th><th>Risk</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody>' +
      runs.map(renderRunRow).join("") + "</tbody></table></div>";
    $$(".run-select", wrap).forEach((cb) => {
      cb.addEventListener("click", (ev) => ev.stopPropagation());
      cb.addEventListener("change", () => {
        if (cb.checked) state.runSelection.add(cb.value); else state.runSelection.delete(cb.value);
        updateCompareButton();
      });
    });
    $$(".run-delete", wrap).forEach((btn) => {
      btn.addEventListener("click", (ev) => { ev.stopPropagation(); deleteRunFromTable(btn); });
    });
    updateCompareButton();
  }

  /** Runs render: always re-fetch; drop selections for runs that no longer exist. */
  async function renderRuns(seq) {
    const wrap = $("#runs-table");
    if (!state.runs) wrap.innerHTML = '<div class="loading-row"><span class="spinner"></span> Loading runs...</div>';
    try {
      // The tool catalogue names the profiles shown as chip tooltips; without it the keys are shown instead.
      const [runs] = await Promise.all([loadRuns(true), loadTools().catch(() => null)]);
      if (!isCurrent(seq)) return;
      const ids = new Set(runs.map((r) => r.id));
      Array.from(state.runSelection).forEach((id) => { if (!ids.has(id)) state.runSelection.delete(id); });
      renderRunsTable(runs);
    } catch (e) {
      if (!isCurrent(seq)) return;
      wrap.innerHTML = emptyState("Could not load runs", e.message);
    }
  }

  $("#runs-refresh").addEventListener("click", () => renderRuns(routeSeq).catch(toastError));
  $("#runs-compare").addEventListener("click", () => {
    const ids = Array.from(state.runSelection);
    if (ids.length !== 2) return;
    // Base = older, other = newer (runs are newest first)
    const order = (state.runs || []).map((r) => r.id);
    const sorted = ids.slice().sort((a, b) => order.indexOf(b) - order.indexOf(a));
    location.hash = "#compare?base=" + encode(sorted[0]) + "&other=" + encode(sorted[1]);
  });

  // Row click navigation (delegated); links, buttons and inputs inside the row keep their own behaviour.
  document.addEventListener("click", (ev) => {
    const row = ev.target.closest("tr.clickable[data-href]");
    if (!row) return;
    if (ev.target.closest(".noclick, a, button, input, label")) return;
    location.hash = row.dataset.href;
  });

  /* ========================================================================
     8. Run detail (#run/<id>)
     Owns: the run header, the tab strip, the six tab panels (seven when the
     run used custom tools: Tool output) and live polling.
     Approach: the page is painted once (paintRunDetail); while the run is
     active a poller fetches it every 2 s and updateRunDetail PATCHES only the
     regions whose data changed, so focus, text selection and scroll positions
     survive. Polling is a single self-rescheduling setTimeout guarded by an
     AbortController and the route sequence token.
     ======================================================================== */

  const RUN_POLL_MS = 2000;   // how often the run page re-fetches a queued or running run

  const RUN_TABS = [
    { id: "summary", label: "Summary" },
    { id: "ports", label: "Ports", count: (run) => (run.ports || []).length },
    { id: "web", label: "Web Technologies", count: (run) => (run.web || []).length },
    { id: "vulns", label: "Vulnerabilities", count: (run) => (run.vulns || []).length },
    { id: "output", label: "Tool output", count: (run) => (run.custom_outputs || []).length },
    { id: "log", label: "Log", count: (run) => (run.log || []).length },
    { id: "raw", label: "Raw JSON" },
  ];

  /** The tabs a run offers: Tool output only when the run used custom tools. run.custom_tools is fixed when the run
   *  is created, so the set of tabs never changes while the run is polled. */
  function runTabs(run) {
    return RUN_TABS.filter((t) => t.id !== "output" || Object.keys((run && run.custom_tools) || {}).length);
  }

  /** Semi-circle SVG gauge for the 0-100 risk score (dasharray trick: arc length * score). */
  function gaugeHtml(score, unscored) {
    const has = score !== null && score !== undefined && !isNaN(Number(score));
    const n = has ? Math.max(0, Math.min(100, Number(score))) : 0;
    const cls = has ? riskClass(n) : "muted";
    const r = 70;
    const len = Math.PI * r;
    const offset = len - (len * n) / 100;
    return '<div class="gauge-wrap" role="img" aria-label="' + (has ? "Risk score " + Math.round(n) + " of 100" : esc(unscored || "Not scored yet")) + '"><div class="gauge"><svg viewBox="0 0 170 95" aria-hidden="true">' +
      '<path class="gauge-track" d="M15 85 A70 70 0 0 1 155 85"/>' +
      '<path class="gauge-fill ' + cls + '" d="M15 85 A70 70 0 0 1 155 85" stroke-dasharray="' + len.toFixed(2) + '" stroke-dashoffset="' + offset.toFixed(2) + '"/>' +
      "</svg>" +
      '<div class="gauge-value ' + cls + '">' + (has ? Math.round(n) : "-") + "</div></div>" +
      '<div class="gauge-caption">Risk score / 100</div>' +
      '<div class="small" style="color:var(--' + (cls === "muted" ? "text-muted" : cls) + ')">' + (has ? RISK_LABEL[cls] + " risk" : esc(unscored || "Not scored yet")) + "</div></div>";
  }

  function stageDot(status) {
    const map = { completed: "dot-green", simulated: "dot-green", running: "dot-amber", failed: "dot-red", pending: "dot-muted", skipped: "dot-muted" };
    return '<span class="dot ' + (map[status] || "dot-muted") + '"></span>';
  }

  /** Readable stage names for the timeline ("Port scan" instead of port_scan); an unknown stage keeps its name with
   *  spaces for underscores. */
  const STAGE_LABEL = { port_scan: "Port scan", web_fingerprint: "Web fingerprint", web_vuln_scan: "Web vulnerability scan", custom_tool: "Custom tool" };
  function stageLabel(stage) {
    const key = String(stage || "stage");
    return Object.prototype.hasOwnProperty.call(STAGE_LABEL, key) ? STAGE_LABEL[key] : key.replace(/_/g, " ");
  }

  /** One timeline entry per stage: tool (with the profile it used, from `profiles`), status, duration/exit code,
   *  command and error. */
  function renderTimeline(stages, profiles) {
    if (!stages || !stages.length) return '<div class="empty-inline">No stages recorded.</div>';
    return '<ul class="timeline">' + stages.map((s) => {
      const profile = profiles && s.tool && profiles[s.tool] ? profileLabel(s.tool, profiles[s.tool]) : "";
      return "<li>" +
        '<div class="tl-marker">' + (s.status === "running" ? '<span class="spinner"></span>' : stageDot(s.status)) + "</div>" +
        "<div>" +
        '<div class="tl-head"><span class="tl-stage">' + esc(stageLabel(s.stage)) + '</span><span class="tl-tool">' + esc(s.tool || "") + "</span>" +
        (profile ? '<span class="tl-profile" title="Profile: the option set chosen for this tool">' + esc(profile) + "</span>" : "") + statusPill(s.status) +
        '<span class="tl-dur">' + (s.duration_seconds !== null && s.duration_seconds !== undefined ? fmtDur(s.duration_seconds) : (s.started_at ? "started " + fmtDateShort(s.started_at) : "")) +
        (s.exit_code !== null && s.exit_code !== undefined ? " &middot; exit " + esc(s.exit_code) : "") +
        (s.raw_output_chars ? " &middot; " + fmtNum(s.raw_output_chars) + " chars" : "") + "</span></div>" +
        (s.command ? '<div class="cmd tl-cmd"><span class="prompt">$ </span>' + esc(s.command) + "</div>" : "") +
        (s.error ? '<div class="tl-error">' + esc(s.error) + "</div>" : "") +
        "</div></li>";
    }).join("") + "</ul>";
  }

  /** The gauge of a run's Summary tab: the score of a completed run, otherwise why there is none. */
  function runGauge(run) {
    return gaugeHtml(shownRisk(run), run.status === "failed" ? "Not scored: the run failed" : "Not scored yet");
  }

  function renderKpis(run) {
    const s = run.summary || {};
    // A dash, not a zero, where a count would mislead: no summary yet, or a failed run that found nothing (countFor).
    const value = (n) => { const c = countFor(run, n); return c === null ? '<span class="faint">-</span>' : fmtNum(c, "0"); };
    return kpiTile("Hosts up", value(s.hosts_up)) +
      kpiTile("Open ports", value(s.open_ports), { cls: "accent" }) +
      kpiTile("Web services", value(s.web_services)) +
      kpiTile("Technologies", value(s.technologies)) +
      kpiTile("Vulnerabilities", value(s.vulnerabilities), { cls: Number(countFor(run, s.vulnerabilities)) > 0 ? "amber" : "" });
  }

  /** Whether the run's workflow includes `tool`, and that tool's stage (null when it has none). */
  function hasTool(run, tool) {
    return (run.tools || []).indexOf(tool) >= 0;
  }

  function stageOf(run, tool) {
    return (run.stages || []).find((s) => s.tool === tool) || null;
  }

  /** Why a tool of a completed run has nothing to show: its stage was skipped or failed (a later stage may
   *  fail while the run still completes). Empty when the stage ran normally. */
  function stageGap(run, tool, name) {
    const s = stageOf(run, tool);
    if (run.status !== "completed" || !s) return "";
    if (s.status === "skipped") return name + " did not run: " + (s.error || "nothing to scan.");
    if (s.status === "failed") return name + " failed: " + (s.error || "no output.");
    return "";
  }

  /** Empty-state text for a run's result tabs: what a finished run found, what is still to come, or why a failed
   *  run has nothing (its data will never arrive, so "will appear once ..." would be a false promise). */
  function noResultsText(run, found, pending, failed) {
    if (run.status === "completed") return found;
    if (run.status === "failed") return failed;
    return pending;
  }

  function renderHighlights(run) {
    const highlights = (run.summary && run.summary.highlights) || [];
    if (highlights.length) return '<ul class="highlights">' + highlights.map((h) => "<li>" + esc(h) + "</li>").join("") + "</ul>";
    return '<div class="empty-inline">' + noResultsText(run, "No highlights were produced.", "Highlights appear when the run completes.", "The run failed, so no highlights were produced.") + "</div>";
  }

  function runErrorHtml(run) {
    return run.error ? '<div class="notice notice-danger" style="margin:0 0 16px"><strong>Run error:</strong> ' + esc(run.error) + "</div>" : "";
  }

  /** Summary-tab notice for a run with partial results, listing the notes of the stages that were cut short. Custom
   *  stages are left out, as in the reports: "partial" describes the parsed findings only, and a custom tool's notes
   *  stay in the stage timeline and the Tool output tab. */
  function partialNoticeHtml(run) {
    if (!isPartial(run)) return "";
    const notes = (run.stages || []).filter((s) => (s.partial || s.status === "failed") && s.error && s.stage !== "custom_tool").map((s) => "<li><strong>" + esc(s.tool) + ":</strong> " + esc(s.error) + "</li>").join("");
    return '<div class="notice notice-warn" style="margin:0 0 16px"><strong>Partial results.</strong> A stage did not examine everything it was given, so a port, technology or finding that is missing here is not evidence of its absence.' +
      (notes ? '<ul style="margin:8px 0 0 18px">' + notes + "</ul>" : "") + "</div>";
  }

  /** Summary tab. Each region has its own id so polling can repaint only what changed. */
  function renderSummaryTab(run) {
    const s = run.summary || {};
    return '<div class="summary-grid">' +
      '<div class="card" style="margin:0"><div class="card-head"><h2>Key metrics</h2></div><div class="card-body"><div class="kpi-grid" id="run-kpis">' + renderKpis(run) + "</div>" +
      '<h3 class="sub-h" style="margin-top:20px">Highlights</h3><div id="run-highlights">' + renderHighlights(run) + "</div>" +
      "</div></div>" +
      '<div class="card" style="margin:0"><div class="card-head"><h2>Risk score</h2></div><div class="card-body" id="run-gauge">' + runGauge(run) + "</div></div>" +
      "</div>" +
      '<div id="run-partial">' + partialNoticeHtml(run) + "</div>" +
      '<div id="run-error">' + runErrorHtml(run) + "</div>" +
      '<div class="card"><div class="card-head"><h2>Stage timeline</h2></div><div class="card-body" id="run-timeline">' + renderTimeline(run.stages, run.profiles) + "</div></div>";
  }

  /** Summary tab patch: compare the previous and new run and rewrite only the regions that differ. */
  function patchSummaryTab(prev, run) {
    const s = run.summary || {};
    if (!sameJson(prev.summary, run.summary) || prev.status !== run.status) {
      $("#run-kpis").innerHTML = renderKpis(run);
      $("#run-highlights").innerHTML = renderHighlights(run);
      $("#run-gauge").innerHTML = runGauge(run);
    }
    if (prev.error !== run.error) $("#run-error").innerHTML = runErrorHtml(run);
    if (!sameJson(prev.stages, run.stages) || isPartial(prev) !== isPartial(run)) $("#run-partial").innerHTML = partialNoticeHtml(run);
    if (!sameJson(prev.stages, run.stages)) $("#run-timeline").innerHTML = renderTimeline(run.stages, run.profiles);
  }

  /** Ports tab: one row per open port, sorted by host then port. */
  function renderPortsTab(run) {
    const ports = run.ports || [];
    if (!ports.length) {
      const text = !hasTool(run, "nmap") ? "This workflow has no port scan. Add Nmap to discover open ports."
        : noResultsText(run, "The scan did not find any open ports.", "Ports will appear once the discovery stage completes.", "The run failed before the discovery stage produced results.");
      return '<div class="card">' + emptyState("No open ports", text) + "</div>";
    }
    const sorted = ports.slice().sort((a, b) => String(a.host).localeCompare(String(b.host)) || (a.port - b.port));
    return '<div class="card"><div class="table-wrap"><table class="table"><thead><tr><th>Host</th><th class="num">Port</th><th>Proto</th><th>State</th><th>Service</th><th>Product</th><th>Version</th><th>Extra</th><th>Web</th></tr></thead><tbody>' +
      sorted.map((p) => "<tr>" +
        '<td class="mono">' + esc(p.host) + "</td>" +
        '<td class="num mono">' + esc(p.port) + "</td>" +
        "<td>" + esc(p.protocol || "tcp") + "</td>" +
        '<td><span class="pill ' + (p.state === "open" ? "pill-green" : "pill-muted") + '">' + esc(p.state || "-") + "</span></td>" +
        "<td>" + dash(p.service) + "</td>" +
        "<td>" + dash(p.product) + "</td>" +
        '<td class="mono">' + dash(p.version) + "</td>" +
        '<td class="small muted wrap">' + dash(p.extra) + "</td>" +
        "<td>" + (p.is_web ? '<span class="pill pill-accent">web</span>' : '<span class="faint">-</span>') + "</td>" +
        "</tr>").join("") +
      "</tbody></table></div></div>";
  }

  function techChip(t) {
    const extra = t.version || t.string;
    return '<span class="chip" title="' + esc(t.category || "") + '">' + esc(t.name) + (extra ? ' <span class="chip-ver">' + esc(extra) + "</span>" : "") + "</span>";
  }

  /** Web Technologies tab: one card per URL with status code, title and technology chips. */
  function renderWebTab(run) {
    const web = run.web || [];
    if (!web.length) {
      const found = hasTool(run, "nmap") ? "No HTTP/HTTPS services were found on the discovered ports." : "No HTTP/HTTPS service answered on the standard ports 80 and 443.";
      const text = !hasTool(run, "whatweb") ? "Add WhatWeb to the workflow to fingerprint web services."
        : stageGap(run, "whatweb", "WhatWeb") || noResultsText(run, found, "Web fingerprints will appear once WhatWeb finishes.", "The run failed before WhatWeb produced results.");
      return '<div class="card">' + emptyState("No web services", text) + "</div>";
    }
    return '<div class="web-grid">' + web.map((w) => {
      const code = w.status_code;
      const codeCls = !code ? "pill-muted" : code < 300 ? "pill-green" : code < 400 ? "pill-blue" : code < 500 ? "pill-amber" : "pill-red";
      return '<div class="web-card"><div class="web-url">' + esc(w.url) + "</div>" +
        (w.title ? '<div class="web-title">' + esc(w.title) + "</div>" : '<div class="web-title faint">No title</div>') +
        '<div class="web-meta"><span class="pill ' + codeCls + '">' + (code ? "HTTP " + esc(code) : "no response") + "</span>" +
        '<span class="small muted mono">' + esc(w.host) + ":" + esc(w.port) + "</span></div>" +
        '<div class="web-tech">' + ((w.technologies && w.technologies.length) ? w.technologies.map(techChip).join("") : '<span class="faint small">No technologies identified</span>') + "</div>" +
        "</div>";
    }).join("") + "</div>";
  }

  /** Vulnerabilities tab: findings sorted by severity, references rendered as links when they are URLs. */
  function renderVulnsTab(run) {
    const vulns = run.vulns || [];
    if (!vulns.length) {
      let text;
      if (!hasTool(run, "nikto")) text = "Add Nikto to the workflow to collect web vulnerability findings.";
      else text = stageGap(run, "nikto", "Nikto") || noResultsText(run, "Nikto did not report any findings.", "Findings will appear once Nikto finishes.", "The run failed before Nikto produced results.");
      return '<div class="card">' + emptyState("No vulnerabilities recorded", text) + "</div>";
    }
    const sorted = vulns.slice().sort((a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0));
    return '<div class="card"><div class="table-wrap"><table class="table"><thead><tr><th>Severity</th><th>URL</th><th>Description</th><th>Reference</th></tr></thead><tbody>' +
      sorted.map((v) => "<tr>" +
        "<td>" + severityPill(v.severity) + "</td>" +
        '<td class="mono wrap">' + esc(v.url) + "</td>" +
        '<td class="wrap">' + esc(v.description) + "</td>" +
        '<td class="wrap small">' + (v.reference ? (/^https?:\/\//i.test(v.reference) ? '<a href="' + esc(v.reference) + '" target="_blank" rel="noopener noreferrer">' + esc(v.reference) + "</a>" : esc(v.reference)) : '<span class="faint">-</span>') + "</td>" +
        "</tr>").join("") +
      "</tbody></table></div></div>";
  }

  /** How one custom-tool call ended, for its block on the Tool output tab. Only a call that exited by itself has an
   *  exit code of its own (o.ended "exited"); a call HybridSec stopped, could not start or only simulated says so
   *  instead. A run stored before `ended` existed reads as "exited": there timed_out still means the time limit, and
   *  `simulated` (the run's mode is simulated, so no custom tool was started) replaces the exit code 0 it stored. */
  function outputStatus(o, simulated) {
    const words = {
      time_limit: "stopped at its time limit",
      output_limit: "stopped for printing too much",
      shutdown: "stopped by the server shutdown",
      not_started: "could not start",
      simulated: "simulated, not started",
    };
    const ended = o.ended && o.ended !== "exited" ? String(o.ended) : simulated ? "simulated" : o.timed_out ? "time_limit" : "exited";
    if (Object.prototype.hasOwnProperty.call(words, ended)) return words[ended];
    return o.exit_code === null || o.exit_code === undefined ? "no exit code" : "exit " + o.exit_code;
  }

  /** Tool output tab (runs that used custom tools only): one block per call with the tool, its target or URL, how it
   *  ended, the command and what it printed. The text is shown as kept by the server (control characters removed),
   *  escaped like everything else; it is never parsed into findings or scored. Each pane has an id so the focus
   *  restore of updateRunDetail keeps a focused pane focused when the poller repaints the tab. */
  function renderOutputTab(run) {
    const outputs = run.custom_outputs || [];
    if (!outputs.length) {
      const active = isActiveStatus(run.status);
      return '<div class="card">' + (active
        ? emptyState("No custom tool output yet", "Output appears as each custom tool finishes.")
        : emptyState("No custom tool output", "The stage timeline on the Summary tab says why.")) + "</div>";
    }
    const note = "Kept as each tool printed it. Not parsed into findings and not part of the risk score." + (run.mode === "simulated" ? " Simulation mode: the text is synthetic." : "");
    return '<div class="card"><div class="card-body" id="run-outputs"><p class="hint">' + esc(note) + "</p>" +
      outputs.map((o, i) => outputBlockHtml(o, i, run.mode === "simulated")).join("") + "</div></div>";
  }

  /** One call's block on the Tool output tab. `i` gives its pane a stable id (run-output-<i>); `simulated` is true in
   *  a simulated run (see outputStatus). Two limits can cut a call's output: its own limit per call (truncated), and
   *  the run's limit on custom-tool output summed over all calls (run_limit, which also says so under the pane). A
   *  call cut at its own limit can be left with nothing when all it printed was control characters, which are
   *  removed. */
  function outputBlockHtml(o, i, simulated) {
    const text = (o.stdout || "") + (o.stderr ? "\n--- stderr ---\n" + o.stderr : "");
    let empty = "The tool printed nothing.";
    if (o.run_limit) empty = "Nothing was kept: the run had already stored as much custom-tool output as it keeps.";
    else if (o.truncated) empty = "Nothing printable was kept: the output was cut at a limit.";
    const cut = o.run_limit ? "The run's limit on custom-tool output (all calls together) was reached, so the end of this call's output was not kept"
      : "The output was longer than the limit per call, so the end of it was cut or the tool was stopped";
    return '<div class="output-block"><div class="tl-head"><span class="tl-stage">' + esc(o.tool) + '</span><span class="tl-tool">' + esc(o.target) + "</span>" +
      '<span class="tl-dur">' + esc(outputStatus(o, simulated)) + " &middot; " + fmtDur(o.duration_seconds) + "</span>" +
      (o.truncated || o.run_limit ? '<span class="pill pill-amber" title="' + esc(cut) + '">truncated</span>' : "") + "</div>" +
      '<div class="cmd"><span class="prompt">$ </span>' + esc(o.command) + "</div>" +
      '<div class="log-pane output-pane" id="run-output-' + i + '" tabindex="0" aria-label="Output of ' + esc(o.tool) + " for " + esc(o.target) + '">' +
      (text ? esc(text) : '<span class="faint">' + esc(empty) + "</span>") + "</div>" +
      (o.run_limit && text ? '<div class="hint hint-warn output-note">' + esc(cut) + ".</div>" : "") + "</div>";
  }

  /** Outputs are only ever appended while a run executes, so new calls are added below the existing blocks: a pane
   *  the reader has scrolled or selected text in stays as it is. Anything else (the first output replacing the
   *  empty state) repaints the tab. */
  function patchOutputTab(prev, run) {
    const before = prev.custom_outputs || [];
    const after = run.custom_outputs || [];
    const list = $("#run-outputs");
    if (list && before.length && after.length >= before.length && sameJson(before, after.slice(0, before.length))) {
      if (after.length > before.length) {
        list.insertAdjacentHTML("beforeend", after.slice(before.length).map((o, k) => outputBlockHtml(o, before.length + k, run.mode === "simulated")).join(""));
      }
      return;
    }
    patchListTab(prev, run, "custom_outputs", renderOutputTab);
  }

  /** Re-render a list tab only when its data changed; keeps the table's horizontal scroll position. */
  function patchListTab(prev, run, key, renderFn) {
    if (sameJson(prev[key], run[key]) && prev.status === run.status) return;
    const panel = $("#run-tab-panel");
    const wrapBefore = $(".table-wrap", panel);
    const left = wrapBefore ? wrapBefore.scrollLeft : 0;
    panel.innerHTML = renderFn(run);
    const wrapAfter = $(".table-wrap", panel);
    if (wrapAfter) wrapAfter.scrollLeft = left;
  }

  /** Colour class for a log line based on simple keyword matching. */
  function logLineClass(line) {
    const l = String(line).toLowerCase();
    if (/\b(error|failed|fatal|exception|traceback)\b/.test(l)) return "err";
    if (/\b(warn|warning|timeout|skipp)/.test(l)) return "warn";
    if (/\b(completed|done|finished|success)\b/.test(l)) return "ok";
    return "";
  }

  const LOG_EMPTY = '<span class="faint" id="run-log-empty">Log is empty.</span>';
  function logLineHtml(line, i) {
    return '<span class="log-line ' + logLineClass(line) + '"><span class="ln">' + (i + 1) + "</span>" + esc(line) + "</span>";
  }

  function renderLogTab(run) {
    const log = run.log || [];
    return '<div class="log-pane" id="run-log" tabindex="0" role="log" aria-label="Run log">' + (log.length ? log.map(logLineHtml).join("") : LOG_EMPTY) + "</div>";
  }

  /** Log tab patch: append new lines in place; follow the tail only if the user was already at the bottom. */
  function patchLogTab(prev, run) {
    const pane = $("#run-log");
    if (!pane) return;
    const oldLog = prev.log || [];
    const newLog = run.log || [];
    const pinned = pane.scrollHeight - pane.scrollTop - pane.clientHeight < 24;
    const prefixSame = newLog.length >= oldLog.length && oldLog.every((l, i) => newLog[i] === l);
    if (prefixSame) {
      if (newLog.length === oldLog.length) return;
      const empty = $("#run-log-empty", pane);
      if (empty) empty.remove();
      pane.insertAdjacentHTML("beforeend", newLog.slice(oldLog.length).map((l, i) => logLineHtml(l, oldLog.length + i)).join(""));
    } else {                                   // log was rewritten (rare): repaint, keep the reading position
      const top = pane.scrollTop;
      pane.innerHTML = newLog.length ? newLog.map(logLineHtml).join("") : LOG_EMPTY;
      if (!pinned) pane.scrollTop = top;
    }
    if (pinned) pane.scrollTop = pane.scrollHeight;
  }

  /** JSON syntax highlighter: tokenise the raw text first, then escape each piece (never the other way round). */
  function highlightJson(obj) {
    const json = JSON.stringify(obj, null, 2);
    const re = /("(?:\\u[0-9a-fA-F]{4}|\\[^u]|[^\\"])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
    let out = "";
    let last = 0;
    let m;
    while ((m = re.exec(json)) !== null) {
      out += esc(json.slice(last, m.index));
      if (m[1] !== undefined) {
        out += '<span class="' + (m[2] ? "k" : "s") + '">' + esc(m[1]) + "</span>" + esc(m[2] || "");
      } else if (m[3] !== undefined) {
        out += '<span class="' + (m[3] === "null" ? "z" : "b") + '">' + m[3] + "</span>";
      } else {
        out += '<span class="n">' + esc(m[0]) + "</span>";
      }
      last = re.lastIndex;
    }
    return out + esc(json.slice(last));
  }

  function renderRawTab(run) {
    return '<div class="log-pane json-pane" id="run-raw" tabindex="0" aria-label="Raw run JSON">' + highlightJson(run) + "</div>";
  }

  /** Raw tab patch: repaint only when the JSON changed and keep the scroll position. */
  function patchRawTab(prev, run) {
    if (sameJson(prev, run)) return;
    const pane = $("#run-raw");
    if (!pane) return;
    const top = pane.scrollTop, left = pane.scrollLeft;
    pane.innerHTML = highlightJson(run);
    pane.scrollTop = top;
    pane.scrollLeft = left;
  }

  /* Header pieces that change while a run is active */
  function finishedHtml(run) {
    return run.finished_at ? '<span class="sep">&middot;</span> <span>Finished ' + fmtDate(run.finished_at) + "</span>" : "";
  }
  function durationHtml(run) {
    return isActiveStatus(run.status) ? '<span class="spinner sm"></span> in progress' : fmtDur(run.duration_seconds);
  }
  function liveNoticeHtml(run) {
    if (!isActiveStatus(run.status)) return "";
    return '<div class="notice notice-info live-notice" role="status"><span class="spinner"></span> The run is ' + esc(run.status) + ". Live updates every " + RUN_POLL_MS / 1000 + " seconds.</div>";
  }
  function pausedNoticeHtml(err) {
    return '<div class="notice notice-warn live-notice" role="status"><span>Live updates paused: ' + esc(err && err.message ? err.message : "request failed") + '</span><button class="btn btn-ghost btn-sm" type="button" id="run-poll-retry">Retry</button></div>';
  }

  /** Tab buttons with WAI-ARIA tab semantics (roving tabindex: only the active tab is in the Tab order). */
  function tabsHtml(run) {
    return runTabs(run).map((t) => {
      const count = t.count ? t.count(run) : null;
      const active = state.runDetailTab === t.id;
      return '<button class="tab' + (active ? " active" : "") + '" type="button" role="tab" id="run-tab-' + t.id + '" data-tab="' + t.id + '" aria-selected="' + (active ? "true" : "false") + '" aria-controls="run-tab-panel" tabindex="' + (active ? "0" : "-1") + '">' +
        esc(t.label) + (count !== null ? ' <span class="count">' + count + "</span>" : "") + "</button>";
    }).join("");
  }

  function patchTabCounts(run) {
    runTabs(run).forEach((t) => {
      if (!t.count) return;
      const el = $("#run-tab-" + t.id + " .count");
      if (!el) return;
      const c = String(t.count(run));
      if (el.textContent !== c) el.textContent = c;
    });
  }

  /** Static skeleton of the page: back link, header, download row, live-notice slot, tab strip and empty panel. */
  function runHeaderHtml(run) {
    const active = isActiveStatus(run.status);
    const reportBase = "/api/runs/" + encode(run.id) + "/report?format=";
    const dl = (fmt, label) => '<a class="btn btn-ghost btn-sm" href="' + reportBase + fmt + '" download target="_blank" rel="noopener">' + label + "</a>";
    return '<a class="back-link" href="#runs">&larr; All runs</a>' +
      '<div class="run-head"><div style="min-width:0">' +
      '<div class="plan-header-row"><h1 tabindex="-1">' + esc(run.target) + '</h1><span id="run-status-pill">' + statusPill(run.status) + partialPill(run) + '</span><span id="run-mode-pill">' + modePill(run.mode) + "</span></div>" +
      (run.label ? '<div style="margin-top:4px;font-weight:600">' + esc(run.label) + "</div>" : "") +
      '<div class="run-head-meta">' +
      '<span class="mono">' + esc(run.id) + "</span>" +
      '<span class="sep">&middot;</span><span>Created ' + fmtDate(run.created_at) + "</span>" +
      '<span id="run-finished">' + finishedHtml(run) + "</span>" +
      '<span class="sep">&middot;</span><span>Duration <span id="run-duration">' + durationHtml(run) + "</span></span>" +
      '<span class="sep">&middot;</span><span>Tools: ' + esc((run.tools || []).join(" -> ")) + "</span>" +
      (run.plan_id ? '<span class="sep">&middot;</span><a href="' + esc(planHash(run.plan_id)) + '">Plan ' + esc(String(run.plan_id).slice(0, 8)) + "</a>" : "") +
      "</div></div>" +
      '<div class="download-row">' + dl("json", "JSON") + dl("csv", "CSV") + dl("html", "HTML report") + dl("md", "Markdown") +
      '<button class="btn btn-danger btn-sm" type="button" id="run-detail-delete"' + (active ? ' disabled title="Runs can be deleted once they have finished"' : "") + ">Delete</button></div>" +
      "</div>" +
      '<div id="run-live">' + liveNoticeHtml(run) + "</div>" +
      '<div class="tabs" role="tablist" aria-label="Run sections" id="run-tabs">' + tabsHtml(run) + "</div>" +
      '<div class="tab-panel" id="run-tab-panel" role="tabpanel" aria-labelledby="run-tab-' + state.runDetailTab + '"></div>';
  }

  /** Paint the active tab's panel from scratch (tab switch or first load). */
  function paintPanel(run) {
    const panel = $("#run-tab-panel");
    if (!panel) return;
    switch (state.runDetailTab) {
      case "ports": panel.innerHTML = renderPortsTab(run); break;
      case "web": panel.innerHTML = renderWebTab(run); break;
      case "vulns": panel.innerHTML = renderVulnsTab(run); break;
      case "output": panel.innerHTML = renderOutputTab(run); break;
      case "log": {
        panel.innerHTML = renderLogTab(run);
        const pane = $("#run-log");
        if (pane) pane.scrollTop = pane.scrollHeight;      // start pinned to the tail
        break;
      }
      case "raw": panel.innerHTML = renderRawTab(run); break;
      default: panel.innerHTML = renderSummaryTab(run);
    }
  }

  /** Patch the active tab's panel with a newer run (polling). */
  function patchPanel(prev, run) {
    switch (state.runDetailTab) {
      case "ports": patchListTab(prev, run, "ports", renderPortsTab); break;
      case "web": patchListTab(prev, run, "web", renderWebTab); break;
      case "vulns": patchListTab(prev, run, "vulns", renderVulnsTab); break;
      case "output": patchOutputTab(prev, run); break;
      case "log": patchLogTab(prev, run); break;
      case "raw": patchRawTab(prev, run); break;
      default: patchSummaryTab(prev, run);
    }
  }

  /** Activate a tab: update ARIA state on the buttons and paint its panel. */
  function selectTab(id) {
    if (!runTabs(state.runDetailRun).some((t) => t.id === id)) return;
    state.runDetailTab = id;
    $$("#run-tabs .tab").forEach((b) => {
      const on = b.dataset.tab === id;
      b.classList.toggle("active", on);
      b.setAttribute("aria-selected", on ? "true" : "false");
      b.tabIndex = on ? 0 : -1;
    });
    const panel = $("#run-tab-panel");
    if (panel) panel.setAttribute("aria-labelledby", "run-tab-" + id);
    if (state.runDetailRun) paintPanel(state.runDetailRun);
  }

  /** Arrow / Home / End keys move between tabs, as the WAI-ARIA tabs pattern expects. */
  function onTabsKeydown(ev) {
    const tabs = runTabs(state.runDetailRun);
    const idx = tabs.findIndex((t) => t.id === state.runDetailTab);
    let next = null;
    if (ev.key === "ArrowRight") next = (idx + 1) % tabs.length;
    else if (ev.key === "ArrowLeft") next = (idx - 1 + tabs.length) % tabs.length;
    else if (ev.key === "Home") next = 0;
    else if (ev.key === "End") next = tabs.length - 1;
    if (next === null) return;
    ev.preventDefault();
    selectTab(tabs[next].id);
    const btn = $("#run-tab-" + tabs[next].id);
    if (btn) btn.focus();
  }

  /** Delete the run shown on the detail page (refused while it is still active). */
  async function deleteCurrentRun() {
    const run = state.runDetailRun;
    if (!run) return;
    if (isActiveStatus(run.status)) { toast("Wait for the run to finish before deleting it.", "warn"); return; }
    const ok = await confirmDialog('Delete run "' + (run.label || run.target) + '"? This cannot be undone.', "Delete", "Delete run");
    if (!ok) return;
    try {
      await api("/api/runs/" + encode(run.id), { method: "DELETE" });
      stopRunPolling();
      state.runs = null;
      toast("Run deleted.", "success");
      location.hash = "#runs";
    } catch (e) { toastError(e, "Delete failed"); }
  }

  /** Bind the handlers of the skeleton once per paint (tabs, retry, delete). */
  function bindRunDetail() {
    const tabs = $("#run-tabs");
    tabs.addEventListener("click", (ev) => {
      const b = ev.target.closest(".tab");
      if (b) selectTab(b.dataset.tab);
    });
    tabs.addEventListener("keydown", onTabsKeydown);
    $("#run-live").addEventListener("click", (ev) => {
      if (ev.target.closest("#run-poll-retry")) resumeRunPolling();
    });
    $("#run-detail-delete").addEventListener("click", deleteCurrentRun);
  }

  /** Full paint: first load of a run (or a different run). */
  function paintRunDetail(run) {
    state.runDetailRun = run;
    if (!runTabs(run).some((t) => t.id === state.runDetailTab)) state.runDetailTab = "summary";   // Tool output of a run without custom tools
    const wrap = $("#run-detail");
    wrap.innerHTML = runHeaderHtml(run);
    paintPanel(run);
    bindRunDetail();
    focusHeading(wrap);
  }

  /**
   * Incremental paint used by the poller. Rebuilding the whole page every 2 s would drop focus,
   * text selection and scroll positions, so only the regions whose data changed are rewritten.
   */
  function updateRunDetail(run) {
    const prev = state.runDetailRun;
    if (!prev || prev.id !== run.id || !$("#run-tabs")) { paintRunDetail(run); return; }
    state.runDetailRun = run;
    const focusedId = document.activeElement && document.activeElement.id;
    if (prev.status !== run.status || isPartial(prev) !== isPartial(run)) {
      $("#run-status-pill").innerHTML = statusPill(run.status) + partialPill(run);
      $("#run-mode-pill").innerHTML = modePill(run.mode);
      $("#run-live").innerHTML = liveNoticeHtml(run);
      const del = $("#run-detail-delete");
      del.disabled = isActiveStatus(run.status);
      if (del.disabled) del.title = "Runs can be deleted once they have finished"; else del.removeAttribute("title");
    }
    if (prev.finished_at !== run.finished_at) $("#run-finished").innerHTML = finishedHtml(run);
    if (prev.status !== run.status || prev.duration_seconds !== run.duration_seconds) $("#run-duration").innerHTML = durationHtml(run);
    patchTabCounts(run);
    patchPanel(prev, run);
    if (focusedId) {                                   // a repainted region may have held the focused element
      const el = document.getElementById(focusedId);
      if (el && document.activeElement !== el) { try { el.focus({ preventScroll: true }); } catch (_) { /* ignore */ } }
    }
  }

  /* Polling. One poller exists at a time; route() stops it before rendering anything else. */
  let runPoller = null;

  function stopRunPolling() {
    if (runPoller) { runPoller.stop(); runPoller = null; }
  }

  function resumeRunPolling() {
    if (runPoller) runPoller.resume();
  }

  /**
   * Start polling GET /api/runs/{id} every 2 s while the run is queued/running.
   * Why this shape: a self-rescheduling setTimeout (not setInterval) means the next request is
   * only scheduled after the previous one finished, so ticks can never overlap; the
   * AbortController cancels an in-flight request when the user navigates away; the route
   * sequence token makes a late response for an abandoned page a no-op; the timer handle is
   * local to this closure so stopping one poller can never clear another one's timer.
   */
  function startRunPolling(id, seq, initialStatus) {
    stopRunPolling();
    const ctrl = new AbortController();
    let timer = null;
    let inFlight = false;
    let previousStatus = initialStatus;

    const poller = {
      stop() {
        ctrl.abort();
        if (timer) { clearTimeout(timer); timer = null; }
      },
      resume() {                                      // Retry button after a transient error
        if (ctrl.signal.aborted || inFlight) return;
        if (timer) { clearTimeout(timer); timer = null; }
        if (state.runDetailRun) $("#run-live").innerHTML = liveNoticeHtml(state.runDetailRun);
        tick();
      },
    };

    function schedule(ms) {
      if (ctrl.signal.aborted) return;
      timer = setTimeout(tick, ms);
    }

    function announceStatusChange(fresh) {
      if (fresh.status === previousStatus) return;
      previousStatus = fresh.status;
      if (fresh.status === "completed") {
        const score = fresh.summary && fresh.summary.risk_score !== null && fresh.summary.risk_score !== undefined ? fresh.summary.risk_score : "-";
        if (isPartial(fresh)) toast("Run completed with partial results (see the stage notes); risk score " + score + ".", "warn", "Run finished");
        else toast("Run completed with risk score " + score + ".", "success", "Run finished");
      } else if (fresh.status === "failed") {
        toast(fresh.error || "The run failed.", "error", "Run failed");
      }
    }

    async function tick() {
      timer = null;
      if (ctrl.signal.aborted || inFlight) return;
      inFlight = true;
      try {
        const fresh = await api("/api/runs/" + encode(id), { signal: ctrl.signal });
        if (ctrl.signal.aborted || !isCurrent(seq)) return;        // stale: a newer page owns the screen
        updateRunDetail(fresh);
        announceStatusChange(fresh);
        if (!isActiveStatus(fresh.status)) {                       // finished: stop for good
          state.runs = null;
          poller.stop();
          if (runPoller === poller) runPoller = null;
          return;
        }
        schedule(RUN_POLL_MS);
      } catch (e) {
        if (ctrl.signal.aborted || (e && e.name === "AbortError") || !isCurrent(seq)) return;
        $("#run-live").innerHTML = pausedNoticeHtml(e);            // transient error: pause, offer Retry
      } finally {
        inFlight = false;
      }
    }

    runPoller = poller;
    schedule(RUN_POLL_MS);
  }

  /** Run detail render: fetch once, paint (or patch when returning to the same run), then poll while active. */
  async function renderRunDetail(id, seq) {
    const wrap = $("#run-detail");
    const sameRun = !!(state.runDetailRun && state.runDetailRun.id === id && $("#run-tabs"));
    if (!sameRun) {
      state.runDetailTab = "summary";
      state.runDetailRun = null;
      wrap.innerHTML = '<div class="loading-row"><span class="spinner"></span> Loading run...</div>';
    }
    let run;
    try {
      // The tool catalogue names the profiles the stage timeline shows; without it the keys are shown instead.
      [run] = await Promise.all([api("/api/runs/" + encode(id)), loadTools().catch(() => null)]);
    } catch (e) {
      if (!isCurrent(seq)) return;
      state.runDetailRun = null;
      wrap.innerHTML = '<a class="back-link" href="#runs">&larr; All runs</a>' + emptyState(e.status === 404 ? "Run not found" : "Could not load run", e.message, '<a class="btn btn-primary" href="#runs">Back to runs</a>');
      focusHeading(wrap);
      return;
    }
    if (!isCurrent(seq)) return;
    if (sameRun) {
      updateRunDetail(run);
      // This fetch succeeded, so a "Live updates paused" banner left from before the user navigated away is stale.
      $("#run-live").innerHTML = liveNoticeHtml(run);
    } else {
      paintRunDetail(run);
    }
    if (isActiveStatus(run.status)) startRunPolling(id, seq, run.status);
  }

  /* ========================================================================
     9. Compare (#compare, #compare?base=ID&other=ID)
     Owns: the two run selects and the diff panel (risk delta, ports added /
     removed / changed, technologies and vulnerabilities added / removed).
     The URL is the source of truth: the form only changes the hash.
     ======================================================================== */

  /** A run as a picker option. An unlabelled run carries its short id, as in the Runs table, so two runs of the same
   *  target started in the same minute can be told apart. */
  function runOptionLabel(r) {
    return (r.label ? r.label + " - " : "") + r.target + " (" + fmtDateShort(r.created_at) + ", " + r.status +
      (r.label ? "" : ", " + String(r.id).slice(0, 8)) + ")";
  }

  /** Fill both <select>s with the run list and preselect the ids from the URL. */
  function fillCompareSelects(runs, base, other) {
    const truncated = runs.length ? runsTruncatedText() : "";
    const more = truncated ? '<option value="" disabled>' + esc(truncated) + "</option>" : "";
    const opts = (selected) => '<option value="">Select a run...</option>' + runs.map((r) => '<option value="' + esc(r.id) + '"' + (r.id === selected ? " selected" : "") + ">" + esc(runOptionLabel(r)) + "</option>").join("") + more;
    $("#compare-base").innerHTML = opts(base);
    $("#compare-other").innerHTML = opts(other);
  }

  function portRows(ports) {
    return ports.map((p) => '<tr><td class="mono">' + esc(p.host) + '</td><td class="num mono">' + esc(p.port) + "</td><td>" + esc(p.protocol || "tcp") + "</td><td>" + dash(p.service) + "</td><td>" + dash(p.product) + '</td><td class="mono">' + dash(p.version) + "</td></tr>").join("");
  }
  const PORT_HEAD = '<thead><tr><th>Host</th><th class="num">Port</th><th>Proto</th><th>Service</th><th>Product</th><th>Version</th></tr></thead>';
  const TECH_HEAD = "<thead><tr><th>URL</th><th>Technology</th><th>Version</th></tr></thead>";
  const VULN_HEAD = "<thead><tr><th>Severity</th><th>URL</th><th>Description</th><th>Reference</th></tr></thead>";

  /** A diff card: title, count pill and either a table or an empty-state line. */
  function diffSection(title, count, tableHtml, emptyText, tone) {
    return '<div class="card"><div class="card-head"><h2>' + esc(title) + '</h2><span class="pill ' + (count ? (tone || "pill-accent") : "pill-muted") + '">' + count + "</span></div>" +
      (count ? '<div class="table-wrap">' + tableHtml + "</div>" : '<div class="empty-inline">' + esc(emptyText) + "</div>") + "</div>";
  }

  /** Rows for ports whose service/product/version changed; differing cells show "before -> after". */
  function changedPortRows(list) {
    return list.map((p) => {
      const cell = (k) => {
        const b = p.before ? p.before[k] : null;
        const a = p.after ? p.after[k] : null;
        if ((b || "") === (a || "")) return dash(a);
        return '<span class="diff-before">' + (b ? esc(b) : "none") + '</span> &rarr; <span class="diff-after">' + (a ? esc(a) : "none") + "</span>";
      };
      return '<tr><td class="mono">' + esc(p.host) + '</td><td class="num mono">' + esc(p.port) + "</td><td>" + esc(p.protocol || "tcp") + "</td><td>" + cell("service") + "</td><td>" + cell("product") + "</td><td>" + cell("version") + "</td></tr>";
    }).join("");
  }

  function techRows(list) {
    return list.map((t) => '<tr><td class="mono wrap">' + esc(t.url) + "</td><td>" + esc(t.name) + '</td><td class="mono">' + dash(t.version) + "</td></tr>").join("");
  }

  function vulnRows(list) {
    return list.map((v) => "<tr><td>" + severityPill(v.severity) + '</td><td class="mono wrap">' + esc(v.url) + '</td><td class="wrap">' + esc(v.description) + '</td><td class="wrap small">' + dash(v.reference) + "</td></tr>").join("");
  }

  /** One side (base / other) of the comparison header. */
  function compareSide(label, r) {
    return '<div class="compare-side"><div class="cs-label">' + label + '</div><div class="cs-target"><a href="#run/' + encode(r.id) + '">' + esc(r.label || r.target) + "</a></div>" +
      '<div class="cs-meta">' + esc(r.target) + " &middot; " + fmtDate(r.created_at) + " &middot; " + statusPill(r.status) + partialPill(r) + " " + modePill(r.mode) + "</div>" +
      '<div style="margin-top:8px">' + riskBar(shownRisk(r)) + "</div></div>";
  }

  /** Paint the whole comparison from a GET /api/compare response. */
  function renderCompareResult(c) {
    const baseRisk = shownRisk(c.base);
    const otherRisk = shownRisk(c.other);
    // A delta needs two scores: a run that did not complete has none, so there is no delta either. The server sends
    // risk_delta null then (an older one sent a number anyway, so the statuses are checked as well); a null delta
    // is never shown as 0.
    const scored = baseRisk !== null && otherRisk !== null && c.risk_delta !== null && c.risk_delta !== undefined;
    const delta = scored ? Number(c.risk_delta) : null;
    const deltaCls = !scored ? "flat" : delta > 0 ? "up" : delta < 0 ? "down" : "flat";
    const deltaText = !scored ? "-" : (delta > 0 ? "+" : "") + delta;
    const deltaSub = scored ? fmtNum(baseRisk) + " &rarr; " + fmtNum(otherRisk)
      : "Not scored" + (baseRisk === null || otherRisk === null ? ": only completed runs have a risk score" : "");
    const lists = ["ports_added", "ports_removed", "ports_changed", "tech_added", "tech_removed", "vulns_added", "vulns_removed"].map((k) => c[k] || []);
    const total = lists.reduce((n, l) => n + l.length, 0);
    const [portsAdded, portsRemoved, portsChanged, techAdded, techRemoved, vulnsAdded, vulnsRemoved] = lists;
    const table = (head, rows) => '<table class="table table-compact">' + head + "<tbody>" + rows + "</tbody></table>";

    $("#compare-result").innerHTML =
      '<div class="card"><div class="card-body"><div class="compare-head">' +
      compareSide("Base", c.base) +
      '<div style="text-align:center"><div class="cs-label" style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--text-faint)">Risk delta</div><div class="delta ' + deltaCls + '">' + esc(deltaText) + '</div><div class="small muted">' + deltaSub + "</div></div>" +
      compareSide("Other", c.other) +
      "</div>" +
      (c.note ? '<div class="notice notice-warn" style="margin-top:16px">' + esc(c.note) + "</div>" : "") +
      (total === 0 ? '<div class="notice notice-info" style="margin-top:16px">No differences were detected between these two runs.</div>' : "") +
      "</div></div>" +
      '<div class="grid grid-2">' +
      diffSection("Ports added", portsAdded.length, table(PORT_HEAD, portRows(portsAdded)), "No new open ports.", "pill-red") +
      diffSection("Ports removed", portsRemoved.length, table(PORT_HEAD, portRows(portsRemoved)), "No ports were closed.", "pill-green") +
      "</div>" +
      diffSection("Ports changed", portsChanged.length, table(PORT_HEAD, changedPortRows(portsChanged)), "No service, product or version changes on shared ports.", "pill-amber") +
      '<div class="grid grid-2">' +
      diffSection("Technologies added", techAdded.length, table(TECH_HEAD, techRows(techAdded)), "No new technologies detected.", "pill-accent") +
      diffSection("Technologies removed", techRemoved.length, table(TECH_HEAD, techRows(techRemoved)), "No technologies disappeared.", "pill-muted") +
      "</div>" +
      '<div class="grid grid-2">' +
      diffSection("Vulnerabilities added", vulnsAdded.length, table(VULN_HEAD, vulnRows(vulnsAdded)), "No new vulnerabilities.", "pill-red") +
      diffSection("Vulnerabilities removed", vulnsRemoved.length, table(VULN_HEAD, vulnRows(vulnsRemoved)), "No vulnerabilities were resolved.", "pill-green") +
      "</div>";
  }

  const PICK_TWO = '<div class="card">' + emptyState("Pick two runs", "Choose a base run and another run to see what changed.") + "</div>";

  /** GET /api/compare for two ids and paint the result (or an empty state when the ids are missing or equal). */
  async function runCompare(base, other, seq) {
    const wrap = $("#compare-result");
    if (!base || !other) { wrap.innerHTML = PICK_TWO; return; }
    if (base === other) {
      toast("Pick two different runs.", "warn", "Compare");
      wrap.innerHTML = '<div class="card">' + emptyState("Pick two different runs", "The base and the other run are the same, so there is nothing to compare.") + "</div>";
      return;
    }
    wrap.innerHTML = '<div class="loading-row"><span class="spinner"></span> Comparing...</div>';
    try {
      const c = await api("/api/compare?base=" + encode(base) + "&other=" + encode(other));
      if (!isCurrent(seq)) return;
      renderCompareResult(c);
    } catch (e) {
      if (!isCurrent(seq)) return;
      wrap.innerHTML = '<div class="card">' + emptyState("Comparison failed", e.message) + "</div>";
    }
  }

  /** Compare render: fill the selects from the run list, then compare if the URL names both runs. */
  async function renderCompare(r, seq) {
    const q = (r && r.query) || {};
    try {
      const runs = await loadRuns(true);
      if (!isCurrent(seq)) return;
      fillCompareSelects(runs, q.base || "", q.other || "");
      if (!runs.length) {
        $("#compare-result").innerHTML = '<div class="card">' + emptyState("No runs to compare", "Execute at least two runs first.", '<a class="btn btn-primary" href="#new-run">New Run</a>') + "</div>";
        return;
      }
    } catch (e) {
      if (!isCurrent(seq)) return;
      toastError(e);
      fillCompareSelects([], "", "");
    }
    if (q.base && q.other) await runCompare(q.base, q.other, seq);
    else $("#compare-result").innerHTML = PICK_TWO;
  }

  $("#compare-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const base = $("#compare-base").value;
    const other = $("#compare-other").value;
    if (!base || !other) { toast("Select both runs.", "warn", "Compare"); return; }
    const target = "#compare?base=" + encode(base) + "&other=" + encode(other);
    if (location.hash === target) runCompare(base, other, routeSeq);
    else location.hash = target;
  });

  /* ========================================================================
     10. Settings (#settings)
     Owns: the AI planner card (provider, API keys, models, base URL, test
     button) and the scanning-limits card. The SettingsView loaded from the
     server is kept in state.settings as a BASELINE: a Save button sends only
     the fields that differ from it (so a stale page never reverts someone
     else's .env edit) and repaints only its own section (so unsaved edits in
     the other card survive). Key values are never read back from the API.
     ======================================================================== */

  const KEY_ROWS = [
    { prefix: "anthropic", field: "anthropic_api_key", flag: "anthropic_key_configured", source: "anthropic_key_source", envVar: "ANTHROPIC_API_KEY", label: "Anthropic API key" },
    { prefix: "openai", field: "openai_api_key", flag: "openai_key_configured", source: "openai_key_source", envVar: "OPENAI_API_KEY", label: "OpenAI-compatible API key" },
  ];

  const LIMIT_FIELDS = [
    { key: "max_timeout_seconds", sel: "#settings-max-timeout", label: "Max timeout" },
    { key: "default_timeout_seconds", sel: "#settings-default-timeout", label: "Default timeout" },
    { key: "max_top_ports", sel: "#settings-max-top-ports", label: "Max top ports" },
  ];

  const PLANNER_TEXT_FIELDS = [
    { key: "anthropic_model", sel: "#settings-anthropic-model" },
    { key: "openai_model", sel: "#settings-openai-model" },
    { key: "openai_base_url", sel: "#settings-openai-base-url" },
  ];

  /** Cyan pill for a real AI provider, grey for the rules engine. */
  function providerPill(provider) {
    const p = String(provider || "rules");
    const cls = (p === "anthropic" || p === "openai") ? "pill-accent" : "pill-muted";
    return '<span class="pill ' + cls + '">' + esc(p) + "</span>";
  }

  function numOrEmpty(v) {
    return v === null || v === undefined ? "" : String(v);
  }

  function settingsWritable(view) {
    return !view || view.env_file_writable !== false;
  }

  /** Toggle a key input between password and text, keeping the eye button's ARIA state in sync. */
  function setEye(input, show) {
    input.type = show ? "text" : "password";
    const btn = $('.eye-toggle[data-target="' + input.id + '"]');
    if (btn) {
      btn.classList.toggle("active", show);
      btn.setAttribute("aria-pressed", show ? "true" : "false");
      btn.setAttribute("aria-label", show ? "Hide key" : "Show key");
    }
  }

  /** Paint one key row's Configured / Not set pill and enable Clear only when a key exists. */
  function applyKeyRow(row, view, writable) {
    const configured = !!view[row.flag];
    // A key the server's own environment sets cannot be cleared here: a blank line in .env never masks it.
    const fromEnvironment = configured && view[row.source] === "environment";
    const pill = $("#settings-" + row.prefix + "-pill");
    pill.className = "pill " + (configured ? "pill-green" : "pill-muted");
    pill.textContent = fromEnvironment ? "Set in environment" : (configured ? "Configured" : "Not set");
    pill.title = fromEnvironment ? row.envVar + " is set in the environment of the server process, not in .env." : "";
    const clear = $("#settings-" + row.prefix + "-clear");
    clear.disabled = !writable || !configured || fromEnvironment;
    clear.title = fromEnvironment ? "Set in the server's environment: unset " + row.envVar + " where HybridSec is started." : "";
  }

  /** Common chrome: env path, read-only banner, fieldset state, active-planner line. Also resets the diff baseline. */
  function applySettingsCommon(view) {
    state.settings = view;
    const writable = settingsWritable(view);
    $("#settings-env-path").textContent = view.env_file ? view.env_file : "No .env file configured";
    $("#settings-readonly-banner").hidden = writable;
    $("#settings-planner-fields").disabled = !writable;
    $("#settings-limits-fields").disabled = !writable;
    $("#settings-active").innerHTML =
      "<span>Active planner:</span>" + providerPill(view.ai_provider_resolved) +
      (view.ai_model ? '<span class="mono">' + esc(view.ai_model) + "</span>" : '<span class="faint">no model</span>') +
      (view.ai_provider_setting && view.ai_provider_setting !== view.ai_provider_resolved
        ? '<span class="small faint">(provider setting: ' + esc(view.ai_provider_setting) + ")</span>" : "");
  }

  function applyKeyRows(view) {
    const writable = settingsWritable(view);
    KEY_ROWS.forEach((row) => applyKeyRow(row, view, writable));
  }

  /** Planner card controls (never the password inputs). */
  function applyPlannerSection(view) {
    const providerSelect = $("#settings-provider");
    providerSelect.value = view.ai_provider_setting || "auto";
    if (providerSelect.selectedIndex < 0) providerSelect.value = "auto";
    applyKeyRows(view);
    PLANNER_TEXT_FIELDS.forEach((f) => { $(f.sel).value = view[f.key] || ""; });
  }

  /** Scanning-limits card controls. */
  function applyLimitsSection(view) {
    $("#settings-allowed-targets").value = (view.allowed_targets || []).join("\n");
    $("#settings-allow-sim").checked = !!view.allow_simulation;
    $("#settings-max-timeout").value = numOrEmpty(view.max_timeout_seconds);
    $("#settings-default-timeout").value = numOrEmpty(view.default_timeout_seconds);
    $("#settings-max-top-ports").value = numOrEmpty(view.max_top_ports);
  }

  function applySettings(view) {
    applySettingsCommon(view);
    applyPlannerSection(view);
    applyLimitsSection(view);
  }

  /** Editable controls of each card: their diff baseline may change only when that card is repainted. */
  const PLANNER_KEYS = ["ai_provider_setting"].concat(PLANNER_TEXT_FIELDS.map((f) => f.key));
  const LIMIT_KEYS = ["allowed_targets", "allow_simulation"].concat(LIMIT_FIELDS.map((f) => f.key));

  /** PUT a partial update, repaint the common chrome plus only the saved section, refresh the cached health. */
  async function putSettings(body, successMessage, repaintSection, sectionKeys) {
    const view = await api("/api/settings", { method: "PUT", body });
    const previous = state.settings;
    applySettingsCommon(view);
    if (previous) {
      // A card that is not repainted still shows the values it was painted from, so it must keep diffing
      // against them; otherwise an .env edit made since the page loaded would be sent back as a user edit.
      const baseline = Object.assign({}, view);
      PLANNER_KEYS.concat(LIMIT_KEYS).forEach((k) => {
        if (!(sectionKeys || []).includes(k)) baseline[k] = previous[k];
      });
      state.settings = baseline;
    }
    if (repaintSection) repaintSection(view);
    state.health = null;
    loadHealth(true).then((h) => renderHealthMini(h)).catch(() => {});
    // A value saved blank does not override one the server's environment sets: say so instead of "saved".
    const fromEnv = Object.keys(body).map((k) => (view.environment_settings || {})[k]).filter(Boolean);
    if (successMessage && fromEnv.length) toast("Saved to .env, but the server's environment still sets " + fromEnv.join(", ") + ", and a blank value in .env does not override it. Unset it where HybridSec is started.", "warn", "Settings");
    else if (successMessage) toast(successMessage, "success", "Settings");
    return view;
  }

  /** Settings render: GET /api/settings and paint everything (a 403 means "not the local machine"). */
  async function renderSettings(seq) {
    const loading = $("#settings-loading");
    const content = $("#settings-content");
    const errBox = $("#settings-error");
    errBox.hidden = true;
    if (!state.settings) { loading.hidden = false; content.hidden = true; }
    try {
      const view = await api("/api/settings");
      if (!isCurrent(seq)) return;
      applySettings(view);
      loading.hidden = true;
      content.hidden = false;
    } catch (e) {
      if (!isCurrent(seq)) return;
      loading.hidden = true;
      content.hidden = true;
      $("#settings-env-path").textContent = "";
      $("#settings-readonly-banner").hidden = true;
      errBox.hidden = false;
      // The server's 403 text is shared with the Custom tools page, so the lead sentence here says it for Settings.
      errBox.innerHTML = '<div class="notice notice-danger" style="margin:0 0 16px"><strong>' +
        (e.status === 403 ? "Settings can only be changed from the machine running HybridSec.</strong> Open the dashboard there to view or change them."
          : "Could not load settings.</strong> " + esc(e.message)) + "</div>";
    }
  }

  /** Result panel of POST /api/settings/test-planner. */
  function renderTestResult(r) {
    const ok = !!r.ok;
    const steps = Array.isArray(r.steps) ? r.steps : [];
    $("#settings-test-result").innerHTML =
      '<div class="test-result" role="status">' +
      '<div class="plan-header-row"><h3>Planner test</h3>' + providerPill(r.provider) +
      (r.model ? '<span class="chip mono">' + esc(r.model) + "</span>" : "") +
      (ok ? '<span class="pill pill-green">Planner responded</span>' : '<span class="pill pill-amber">Fell back to rules</span>') +
      '<span class="muted small" style="margin-left:auto">' + fmtDur(r.elapsed_seconds) + "</span></div>" +
      (r.note ? '<div class="notice ' + (ok ? "notice-info" : "notice-warn") + '">' + esc(r.note) + "</div>" : "") +
      (r.summary ? '<p class="plan-summary" style="margin:12px 0 0">' + esc(r.summary) + "</p>" : "") +
      (steps.length   // the server numbers the steps itself ("1. nmap (port_scan)"), so the list adds no numbers
        ? '<ul class="list-plain list-bare">' + steps.map((s) => "<li>" + esc(s) + "</li>").join("") + "</ul>"
        : '<div class="faint small" style="margin-top:8px">No steps returned.</div>') +
      '<div class="muted small" style="margin-top:8px">Elapsed ' + fmtDur(r.elapsed_seconds) + "</div>" +
      "</div>";
  }

  /** Save a pasted key: PUT {<field>: value}; the input is emptied afterwards, the pill repainted. */
  async function saveApiKey(row, input, saveBtn) {
    const value = input.value.trim();
    if (!value) { toast("Paste a key first.", "warn", row.label); input.focus(); return; }
    setBusy(saveBtn, "Saving...");
    try {
      const body = {};
      body[row.field] = value;
      await putSettings(body, row.label + " saved.", applyKeyRows);
      input.value = "";
      setEye(input, false);
    } catch (e) {
      toastError(e, "Could not save key");
    } finally {
      clearBusy(saveBtn);
    }
  }

  /** Clear a stored key after confirmation: PUT {<field>: ""}. */
  async function clearApiKey(row, input, clearBtn) {
    const ok = await confirmDialog(
      "Remove the stored " + row.label + " from .env? Without a key the planner falls back to another provider or the rules engine, unless the server's environment also sets " + row.envVar + ".",
      "Clear key", "Clear " + row.label);
    if (!ok) return;
    setBusy(clearBtn, "Clearing...");
    try {
      const body = {};
      body[row.field] = "";
      const view = await putSettings(body, null, applyKeyRows);
      // The line in .env is cleared either way; say so only when the key really is gone.
      if (view[row.flag]) toast(row.label + " removed from .env, but the server's environment still sets " + row.envVar + ", so that key stays in use. Unset it where HybridSec is started to stop using it.", "warn", "Settings");
      else toast(row.label + " cleared.", "success", "Settings");
      input.value = "";
      setEye(input, false);
    } catch (e) {
      toastError(e, "Could not clear key");
    } finally {
      clearBusy(clearBtn);
      if (state.settings) applyKeyRow(row, state.settings, settingsWritable(state.settings));
    }
  }

  /** Wire one key row: Save, Clear, Enter-to-save. Key values are never read back from the API or logged. */
  function bindKeyRow(row) {
    const input = $("#settings-" + row.prefix + "-key");
    const saveBtn = $("#settings-" + row.prefix + "-save");
    const clearBtn = $("#settings-" + row.prefix + "-clear");
    saveBtn.addEventListener("click", () => saveApiKey(row, input, saveBtn));
    clearBtn.addEventListener("click", () => clearApiKey(row, input, clearBtn));
    input.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") { ev.preventDefault(); saveBtn.click(); }
    });
  }

  /** Planner card Save: send only provider/model/base-URL fields that differ from the baseline ("" = use default). */
  async function savePlannerSettings() {
    const btn = $("#settings-save-planner");
    const base = state.settings || {};
    const body = {};
    const provider = $("#settings-provider").value;
    if (provider !== (base.ai_provider_setting || "auto")) body.ai_provider = provider;
    PLANNER_TEXT_FIELDS.forEach((f) => {
      const val = $(f.sel).value.trim();
      if (val !== String(base[f.key] || "")) body[f.key] = val;
    });
    if (!Object.keys(body).length) { toast("No planner changes to save.", "info", "Settings"); return; }
    setBusy(btn, "Saving...");
    try {
      await putSettings(body, "Planner settings saved.", applyPlannerSection, PLANNER_KEYS);
    } catch (e) {
      toastError(e, "Could not save planner settings");
    } finally {
      clearBusy(btn);
    }
  }

  /** Test planner: POST /api/settings/test-planner (can take up to a minute) and show the result panel. */
  async function testPlanner() {
    const btn = $("#settings-test");
    const panel = $("#settings-test-result");
    setBusy(btn, "Testing...");
    panel.innerHTML = '<div class="test-result"><div class="loading-row" style="padding:0" role="status"><span class="spinner"></span> Asking the planner for a short plan. This can take up to a minute...</div></div>';
    try {
      const result = await api("/api/settings/test-planner", { method: "POST" });
      renderTestResult(result);
    } catch (e) {
      panel.innerHTML = "";
      toastError(e, "Planner test failed");
    } finally {
      clearBusy(btn);
    }
  }

  /** Scanning-limits Save: validate the numbers, then send only the fields that differ from the baseline. */
  async function saveScanningLimits() {
    const btn = $("#settings-save-limits");
    const base = state.settings || {};
    const body = {};
    const targets = $("#settings-allowed-targets").value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    if (targets.join("\n") !== (base.allowed_targets || []).join("\n")) body.allowed_targets = targets;
    const sim = $("#settings-allow-sim").checked;
    if (sim !== !!base.allow_simulation) body.allow_simulation = sim;
    const values = {};
    for (const f of LIMIT_FIELDS) {
      const el = $(f.sel);
      const raw = el.value.trim();
      if (raw === "") { toast(f.label + " is required.", "warn", "Validation"); el.focus(); return; }
      const n = Number(raw);
      if (!Number.isInteger(n) || n <= 0) { toast(f.label + " must be a positive whole number.", "warn", "Validation"); el.focus(); return; }
      // The inputs carry the API's bounds as min/max attributes, but attributes alone do nothing for a
      // type="button" save outside a <form>, so enforce them here with a readable message.
      const min = Number(el.min) || 1;
      const max = Number(el.max) || Infinity;
      if (n < min || n > max) {
        toast(f.label + " must be between " + fmtNum(min) + " and " + fmtNum(max) + ".", "warn", "Validation");
        el.focus();
        return;
      }
      values[f.key] = n;
      if (n !== Number(base[f.key])) body[f.key] = n;
    }
    if (values.default_timeout_seconds > values.max_timeout_seconds) {
      toast("Default timeout cannot exceed the max timeout.", "warn", "Validation");
      return;
    }
    if (!Object.keys(body).length) { toast("No scanning-limit changes to save.", "info", "Settings"); return; }
    setBusy(btn, "Saving...");
    try {
      await putSettings(body, "Scanning limits saved.", applyLimitsSection, LIMIT_KEYS);
    } catch (e) {
      toastError(e, "Could not save scanning limits");
    } finally {
      clearBusy(btn);
    }
  }

  KEY_ROWS.forEach(bindKeyRow);
  $$(".eye-toggle").forEach((btn) => {
    btn.addEventListener("click", () => {
      const input = document.getElementById(btn.dataset.target);
      if (input) setEye(input, input.type === "password");
    });
  });
  $("#settings-save-planner").addEventListener("click", savePlannerSettings);
  $("#settings-test").addEventListener("click", testPlanner);
  $("#settings-save-limits").addEventListener("click", saveScanningLimits);
  $("#settings-refresh").addEventListener("click", () => renderSettings(routeSeq).catch(toastError));

  /* ========================================================================
     11. Custom tools (#tools)
     Owns: the registration form (with its one-chip-per-argument preview),
     the list of registered custom tools with their install status and
     Delete buttons, and the local-only notice. Every /api/tools/custom
     request answers 403 to a browser on another machine, which then sees
     the notice instead of the page. The server checks every rule and
     explains a refusal; the form only checks that the required fields are
     filled in. A create or delete drops state.tools, so New Run, Runs and
     Run detail fetch the catalogue again.
     ======================================================================== */

  /** One row of the registered-tools list, in the saved-plans row pattern: the name, the command as chips (one per
   *  argument), how it runs, its time limit, the program's path (or why it cannot run), the description, the
   *  install pill and Delete. The pill says "refused" both when the definition no longer passes the rules
   *  (refused) and when the program was found but the file it resolves to is refused (blocked); install_hint says
   *  why, with a long path cut in the middle by the server so the file name stays. */
  function customToolItemHtml(t) {
    return '<div class="plan-list-item ct-item"><div style="min-width:0"><div class="pl-title mono">' + esc(t.name) + "</div>" +
      chips([t.program].concat(t.args || []), "chip-muted mono") +
      '<div class="pl-meta"><span>' + esc(SCOPE_LABEL[t.scope] || t.scope) + "</span><span>" + esc(String(t.timeout_seconds)) + " s per call</span>" +
      (t.installed ? '<span class="mono">' + esc(t.path) + "</span>" : "<span>" + esc(t.install_hint) + "</span>") + "</div>" +
      (t.description ? '<div class="muted small">' + esc(t.description) + "</div>" : "") + "</div>" +
      '<div class="pl-pills">' + boolPill(t.installed, "installed", t.refused || t.blocked ? "refused" : "not installed") +
      '<button class="btn btn-danger btn-sm" type="button" data-delete-tool="' + esc(t.name) + '" aria-label="Delete custom tool ' + esc(t.name) + '">Delete</button></div></div>';
  }

  /** One row for a stored custom tool whose saved definition can no longer be read (GET /api/tools/custom's
   *  unreadable), under the name of its stored row. It still counts towards the limit and holds its name, so it is
   *  listed with Delete, which removes it by that name. */
  function unreadableToolItemHtml(name) {
    return '<div class="plan-list-item ct-item"><div style="min-width:0"><div class="pl-title mono">' + esc(name) + "</div>" +
      '<div class="pl-meta"><span>Its saved definition can no longer be read (damaged, or written by another version). It still counts towards the limit and holds its name: delete it to free both.</span></div></div>' +
      '<div class="pl-pills"><span class="pill pill-red">unreadable</span>' +
      '<button class="btn btn-danger btn-sm" type="button" data-delete-tool="' + esc(name) + '" aria-label="Delete unreadable custom tool ' + esc(name) + '">Delete</button></div></div>';
  }

  /** Paint the registered-tools list (or its empty state), the unreadable stored tools after them, and bind the
   *  Delete buttons. */
  function renderCustomToolsList(tools, unreadable) {
    const wrap = $("#custom-tools-list");
    const readable = tools || [];
    const broken = unreadable || [];
    if (!readable.length && !broken.length) { wrap.innerHTML = emptyState("No custom tools yet", "Add one with the form above."); return; }
    wrap.innerHTML = readable.map(customToolItemHtml).join("") + broken.map(unreadableToolItemHtml).join("");
    $$("[data-delete-tool]", wrap).forEach((btn) => {
      btn.addEventListener("click", () => deleteCustomTool(btn));
    });
  }

  /** The arguments typed into the form, split on whitespace: each piece is one argument (no quoting, no shell). */
  function splitArgs(text) {
    return text.trim() ? text.trim().split(/\s+/) : [];
  }

  /** Show the command the form describes as one chip per argv item, so the argument boundaries are visible. */
  function updateToolPreview() {
    $("#tool-preview").innerHTML = chips([$("#tool-program").value.trim() || "program"].concat(splitArgs($("#tool-args").value)), "chip-muted mono");
  }

  /** Replace the page with a notice: on 403 that custom tools are local-only, otherwise why the list could not be
   *  loaded (the Settings pattern). Focus inside the hidden form moves to the page heading. */
  function showToolsError(err) {
    const content = $("#tools-content");
    const box = $("#tools-error");
    const focusWasInside = content.contains(document.activeElement);
    content.hidden = true;
    box.hidden = false;
    box.innerHTML = err && err.status === 403
      ? '<div class="notice notice-warn" style="margin:0 0 16px">Custom tools are only available on the machine running HybridSec. Open the dashboard there to add, list or delete them.</div>'
      : '<div class="notice notice-danger" style="margin:0 0 16px"><strong>Could not load the custom tools.</strong> ' + esc(err && err.message ? err.message : String(err)) + "</div>";
    if (focusWasInside) focusHeading(views.tools);
  }

  /** Custom tools render: GET /api/tools/custom (local machine only) and fresh limits for the time-limit input. */
  async function renderTools(seq) {
    const [list, health] = await Promise.allSettled([api("/api/tools/custom"), loadHealth(true)]);
    if (!isCurrent(seq)) return;
    const limits = health.status === "fulfilled" ? health.value.limits || {} : {};
    if (limits.max_timeout_seconds) $("#tool-timeout").max = limits.max_timeout_seconds;
    if (list.status === "rejected") { showToolsError(list.reason); return; }
    $("#tools-error").hidden = true;
    $("#tools-content").hidden = false;
    // allowed_programs is the allow-list as written in .env (or the defaults), already without the entries that are
    // always refused, so every name offered here can be registered. An empty list means every entry is refused.
    const listed = Array.isArray(list.value.allowed_programs);
    const allowed = listed ? list.value.allowed_programs : [];
    $("#tool-programs").innerHTML = allowed.map((p) => '<option value="' + esc(p) + '"></option>').join("");
    $("#tool-program-hint").textContent = (allowed.length ? "Allowed here: " + allowed.join(", ") + " (HYBRIDSEC_CUSTOM_PROGRAMS in .env). "
      : listed ? "No program can be registered here: HYBRIDSEC_CUSTOM_PROGRAMS in .env lists only programs that are always refused. " : "") +
      "Known shells, interpreters and launchers, script files, attack tools and the built-in scanners are always refused; the allow-list in .env decides the rest.";
    renderCustomToolsList(list.value.tools, list.value.unreadable);
    updateToolPreview();
  }

  /** POST /api/tools/custom from the form. Only the required fields are checked here: the server checks every rule
   *  and its message (a 422 list is flattened by detailToMessage) says which one a definition breaks. */
  async function submitToolForm(ev) {
    ev.preventDefault();
    const checked = $('#tool-form input[name="tool-scope"]:checked');
    const body = {
      name: $("#tool-name").value.trim().toLowerCase(),
      description: $("#tool-description").value.trim(),
      program: $("#tool-program").value.trim(),
      args: splitArgs($("#tool-args").value),
      scope: checked ? checked.value : "target",
      timeout_seconds: Number($("#tool-timeout").value),
    };
    if (!body.name) { toast("Name is required.", "warn", "Validation"); $("#tool-name").focus(); return; }
    if (!body.program) { toast("Program is required.", "warn", "Validation"); $("#tool-program").focus(); return; }
    if (!body.args.length) { toast("Arguments are required: use {target} or {url} in them.", "warn", "Validation"); $("#tool-args").focus(); return; }
    if ($("#tool-timeout").value.trim() === "") { toast("Time limit is required.", "warn", "Validation"); $("#tool-timeout").focus(); return; }
    const btn = $("#tool-submit");
    const seq = routeSeq;
    setBusy(btn, "Adding...");
    try {
      const tool = await api("/api/tools/custom", { method: "POST", body });
      toast("Custom tool " + tool.name + " added.", "success", "Custom tools");
      $("#tool-form").reset();
      state.tools = null;
      await renderTools(seq);
    } catch (e) {
      if (e.status === 403) showToolsError(e); else toastError(e, "Could not add tool");   // the form keeps the input
    } finally {
      clearBusy(btn);
    }
  }

  /** Confirm, DELETE /api/tools/custom/{name}, then repaint the list and put the focus on the next Delete button (or
   *  the empty state's heading). Runs that already used the tool keep their own copy of it. */
  async function deleteCustomTool(btn) {
    const name = btn.dataset.deleteTool;
    const ok = await confirmDialog('Delete custom tool "' + name + '"? Runs that already used it keep their copy and their output.', "Delete", "Delete custom tool");
    if (!ok) return;
    const index = $$("#custom-tools-list [data-delete-tool]").indexOf(btn);
    const seq = routeSeq;
    try {
      await api("/api/tools/custom/" + encode(name), { method: "DELETE" });
      state.tools = null;
      toast("Custom tool " + name + " deleted.", "success");
      await renderTools(seq);
      if (!isCurrent(seq)) return;
      const rest = $$("#custom-tools-list [data-delete-tool]");
      if (rest.length) rest[Math.max(0, Math.min(index, rest.length - 1))].focus(); else focusHeading($("#custom-tools-list"));
    } catch (e) {
      if (e.status === 403) { showToolsError(e); return; }
      toastError(e, "Delete failed");
      if (e.status === 404) renderTools(seq).catch(toastError);   // already gone: show the list as it is now
    }
  }

  $("#tool-form").addEventListener("submit", submitToolForm);
  $("#tools-refresh").addEventListener("click", () => renderTools(routeSeq).catch(toastError));
  ["#tool-program", "#tool-args"].forEach((sel) => $(sel).addEventListener("input", updateToolPreview));
  $$('#tool-form input[name="tool-scope"]').forEach((radio) => radio.addEventListener("change", updateToolPreview));

  /* ========================================================================
     12. Boot
     Owns: choosing the initial route and the first health fetch for the
     sidebar. replaceState (not `location.hash =`) is used so the first
     route() is the only one; a hashchange would render the Overview twice.
     ======================================================================== */

  async function boot() {
    if (!location.hash) history.replaceState(null, "", "#overview");
    // The Overview fetches health itself; other start pages only need the sidebar health line.
    if (parseHash().name !== "overview") {
      loadHealth(true).then((h) => renderHealthMini(h)).catch(() => {
        renderHealthMini(null, true);
        toast("Could not reach the HybridSec API. Is the backend running?", "error", "API unreachable");
      });
    }
    await route();
  }

  boot().catch(toastError);
})();
