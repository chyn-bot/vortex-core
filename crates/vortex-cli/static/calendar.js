/* Configurable calendar view. The shell ships the field registry + current
 * config in #calendar-root's data-* attributes; this script renders the grid
 * (Month / Week / Day), a config bar, a color legend, and fetches events for
 * the visible range from /calendar/{model}/data. Config changes (date/title/
 * color field, mode) reload the page with query params so they persist through
 * saved views, exactly like the pivot/graph/kanban views. Date navigation
 * (prev/next/today) re-fetches without a reload. No build step, no deps, no
 * eval, no inline handlers. */
(function () {
  "use strict";
  var root = document.getElementById("calendar-root");
  if (!root) return;

  var MODEL = root.dataset.model;
  var FIELDS = JSON.parse(root.dataset.fields || "[]"); // [{name,label,type,date,colorable}]
  var cfg = {};
  try { cfg = JSON.parse(root.dataset.config || "{}"); } catch (e) {}

  // Distinct, theme-neutral palette assigned per color-group in sort order.
  var PALETTE = ["#3b82f6", "#22c55e", "#f59e0b", "#ef4444", "#a855f7",
    "#14b8a6", "#ec4899", "#84cc16", "#6366f1", "#f97316", "#06b6d4", "#eab308"];
  var MONTHS = ["January", "February", "March", "April", "May", "June", "July",
    "August", "September", "October", "November", "December"];
  var WD = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

  var params = new URLSearchParams(location.search);
  var anchor = parseYmd(params.get("d")) || new Date();
  anchor.setHours(0, 0, 0, 0);
  var mode = cfg.mode || "month";

  // ---- date helpers ------------------------------------------------------
  function pad(n) { return (n < 10 ? "0" : "") + n; }
  function ymd(d) { return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()); }
  function parseYmd(s) {
    if (!s) return null;
    var m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
    if (!m) return null;
    return new Date(+m[1], +m[2] - 1, +m[3]);
  }
  function addDays(d, n) { var x = new Date(d); x.setDate(x.getDate() + n); return x; }
  function startOfWeek(d) { return addDays(d, -d.getDay()); }
  function sameDay(a, b) { return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate(); }
  function el(tag, cls, txt) { var e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; }

  // ---- visible range for the current mode/anchor -------------------------
  function range() {
    if (mode === "day") return { from: new Date(anchor), to: new Date(anchor) };
    if (mode === "week") { var s = startOfWeek(anchor); return { from: s, to: addDays(s, 6) }; }
    // month: pad out to full weeks so leading/trailing days render.
    var first = new Date(anchor.getFullYear(), anchor.getMonth(), 1);
    var last = new Date(anchor.getFullYear(), anchor.getMonth() + 1, 0);
    return { from: startOfWeek(first), to: addDays(startOfWeek(last), 6) };
  }

  function periodLabel() {
    if (mode === "day") return WD_FULL(anchor) + ", " + MONTHS[anchor.getMonth()] + " " + anchor.getDate() + " " + anchor.getFullYear();
    if (mode === "week") {
      var s = startOfWeek(anchor), e = addDays(s, 6);
      var sm = MONTHS[s.getMonth()].slice(0, 3), em = MONTHS[e.getMonth()].slice(0, 3);
      return sm + " " + s.getDate() + " – " + (sm === em ? "" : em + " ") + e.getDate() + ", " + e.getFullYear();
    }
    return MONTHS[anchor.getMonth()] + " " + anchor.getFullYear();
  }
  function WD_FULL(d) { return ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"][d.getDay()]; }

  // ---- config bar --------------------------------------------------------
  function nav() {
    var p = new URLSearchParams();
    if (dateSel.value) p.set("date_field", dateSel.value);
    if (endSel.value) p.set("end_field", endSel.value);
    if (titleSel.value) p.set("title_field", titleSel.value);
    if (colorSel.value) p.set("color_field", colorSel.value);
    p.set("mode", mode);
    p.set("d", ymd(anchor));
    location.search = p.toString();
  }
  var dateSel, endSel, titleSel, colorSel;
  function opt(sel, name, label, selected) {
    var o = el("option", null, label); o.value = name; if (selected) o.selected = true; sel.appendChild(o);
  }
  function labeled(text, node) {
    var w = el("label", "cal-ctl"); w.appendChild(el("span", "cal-ctl-k", text)); w.appendChild(node); return w;
  }
  function buildBar() {
    var bar = document.getElementById("cal-config");
    if (!bar) return;
    bar.innerHTML = "";

    dateSel = el("select");
    FIELDS.filter(function (f) { return f.date; }).forEach(function (f) { opt(dateSel, f.name, f.label, f.name === cfg.date_field); });
    dateSel.addEventListener("change", nav);
    bar.appendChild(labeled("Start", dateSel));

    endSel = el("select");
    opt(endSel, "", "(none)", !cfg.end_field);
    FIELDS.filter(function (f) { return f.date && f.name !== cfg.date_field; }).forEach(function (f) { opt(endSel, f.name, f.label, f.name === cfg.end_field); });
    endSel.addEventListener("change", nav);
    bar.appendChild(labeled("End", endSel));

    titleSel = el("select");
    FIELDS.forEach(function (f) { opt(titleSel, f.name, f.label, f.name === cfg.title_field); });
    titleSel.addEventListener("change", nav);
    bar.appendChild(labeled("Title", titleSel));

    colorSel = el("select");
    opt(colorSel, "", "(none)", !cfg.color_field);
    FIELDS.filter(function (f) { return f.colorable; }).forEach(function (f) { opt(colorSel, f.name, f.label, f.name === cfg.color_field); });
    colorSel.addEventListener("change", nav);
    bar.appendChild(labeled("Color by", colorSel));
  }

  // ---- toolbar (mode + navigation) ---------------------------------------
  function buildToolbar() {
    var tb = document.getElementById("cal-toolbar");
    if (!tb) return;
    tb.innerHTML = "";

    var navg = el("div", "cal-nav");
    var prev = el("button", "btn btn-sm btn-ghost", "‹"); prev.type = "button";
    var today = el("button", "btn btn-sm", "Today"); today.type = "button";
    var next = el("button", "btn btn-sm btn-ghost", "›"); next.type = "button";
    prev.addEventListener("click", function () { step(-1); });
    next.addEventListener("click", function () { step(1); });
    today.addEventListener("click", function () { anchor = new Date(); anchor.setHours(0, 0, 0, 0); refresh(); });
    navg.appendChild(prev); navg.appendChild(today); navg.appendChild(next);
    tb.appendChild(navg);

    tb.appendChild(el("h2", "cal-period", periodLabel()));

    var modes = el("div", "cal-modes btn-group");
    [["month", "Month"], ["week", "Week"], ["day", "Day"]].forEach(function (m) {
      var b = el("button", "btn btn-sm" + (mode === m[0] ? " btn-active" : ""), m[1]); b.type = "button";
      b.addEventListener("click", function () { if (mode !== m[0]) { mode = m[0]; nav(); } });
      modes.appendChild(b);
    });
    tb.appendChild(modes);
  }

  function step(dir) {
    if (mode === "day") anchor = addDays(anchor, dir);
    else if (mode === "week") anchor = addDays(anchor, 7 * dir);
    else anchor = new Date(anchor.getFullYear(), anchor.getMonth() + dir, 1);
    refresh();
  }
  function refresh() {
    var p = new URLSearchParams(location.search);
    p.set("d", ymd(anchor));
    history.replaceState(null, "", location.pathname + "?" + p.toString());
    buildToolbar();
    load();
  }

  // ---- data --------------------------------------------------------------
  var colorMap = {}; // group value -> color
  function assignColors(events) {
    colorMap = {};
    if (!cfg.color_field) return;
    var groups = {};
    events.forEach(function (e) { if (e.group != null) groups[e.group] = e.groupLabel || e.group; });
    Object.keys(groups).sort().forEach(function (g, i) { colorMap[g] = PALETTE[i % PALETTE.length]; });
    buildLegend(groups);
  }
  function buildLegend(groups) {
    var lg = document.getElementById("cal-legend");
    if (!lg) return;
    lg.innerHTML = "";
    var keys = Object.keys(groups).sort();
    if (!cfg.color_field || !keys.length) { lg.style.display = "none"; return; }
    lg.style.display = "flex";
    keys.forEach(function (g) {
      var item = el("span", "cal-leg-item");
      var dot = el("span", "cal-leg-dot"); dot.style.background = colorMap[g];
      item.appendChild(dot); item.appendChild(el("span", null, groups[g] || "—"));
      lg.appendChild(item);
    });
  }

  function eventsByDay(events) {
    var map = {};
    events.forEach(function (e) {
      var s = parseYmd(e.start); if (!s) return;
      var end = parseYmd(e.end) || s;
      if (end < s) end = s;
      for (var d = new Date(s); d <= end; d = addDays(d, 1)) {
        var k = ymd(d);
        (map[k] = map[k] || []).push(e);
      }
    });
    return map;
  }

  var loadSeq = 0;
  function load() {
    var body = document.getElementById("cal-body");
    if (!cfg.date_field) { body.innerHTML = ""; body.appendChild(el("div", "cal-empty", "Pick a Start date field to plot events.")); return; }
    var r = range();
    var q = new URLSearchParams();
    q.set("date_field", cfg.date_field);
    if (cfg.end_field) q.set("end_field", cfg.end_field);
    if (cfg.title_field) q.set("title_field", cfg.title_field);
    if (cfg.color_field) q.set("color_field", cfg.color_field);
    q.set("start", ymd(r.from));
    q.set("end", ymd(r.to));
    var seq = ++loadSeq;
    body.classList.add("cal-loading");
    fetch("/calendar/" + encodeURIComponent(MODEL) + "/data?" + q.toString(), { headers: { "Accept": "application/json" } })
      .then(function (resp) { return resp.json(); })
      .then(function (data) {
        if (seq !== loadSeq) return; // a newer request superseded this one
        body.classList.remove("cal-loading");
        if (!data || !data.ok) { body.innerHTML = ""; body.appendChild(el("div", "cal-empty", (data && data.error) || "Could not load events.")); return; }
        assignColors(data.events || []);
        render(data.events || []);
      })
      .catch(function () {
        if (seq !== loadSeq) return;
        body.classList.remove("cal-loading");
        body.innerHTML = ""; body.appendChild(el("div", "cal-empty", "Network error loading events."));
      });
  }

  // ---- rendering ---------------------------------------------------------
  function chip(e) {
    var a = el("a", "cal-chip");
    // Generic record page (the plain /{model}/{id} path is not routed).
    a.href = "/form/" + encodeURIComponent(MODEL) + "/" + encodeURIComponent(e.id);
    if (cfg.color_field && e.group != null && colorMap[e.group]) {
      a.style.background = colorMap[e.group];
      a.classList.add("cal-chip-colored");
    }
    var t = e.title || "(untitled)";
    if (e.startTime) { var tm = el("span", "cal-chip-t", e.startTime); a.appendChild(tm); }
    a.appendChild(document.createTextNode(t));
    a.title = t + (e.startTime ? " · " + e.startTime : "");
    return a;
  }
  function createHref(dateStr) {
    // The generic create form lives at /form/{model}/new; it seeds field values
    // from query params, so the clicked day pre-fills the start-date field.
    var p = new URLSearchParams();
    if (cfg.date_field) p.set(cfg.date_field, dateStr);
    return "/form/" + encodeURIComponent(MODEL) + "/new?" + p.toString();
  }

  function render(events) {
    var body = document.getElementById("cal-body");
    body.innerHTML = "";
    var byDay = eventsByDay(events);
    if (mode === "month") renderMonth(body, byDay);
    else if (mode === "week") renderWeek(body, byDay);
    else renderDay(body, byDay);
  }

  function renderMonth(body, byDay) {
    var grid = el("div", "cal-month");
    WD.forEach(function (w) { grid.appendChild(el("div", "cal-dow", w)); });
    var r = range();
    var today = new Date(); today.setHours(0, 0, 0, 0);
    for (var d = new Date(r.from); d <= r.to; d = addDays(d, 1)) {
      var cur = new Date(d);
      var cell = el("div", "cal-cell");
      if (cur.getMonth() !== anchor.getMonth()) cell.classList.add("cal-out");
      if (sameDay(cur, today)) cell.classList.add("cal-today");
      var head = el("div", "cal-cell-head");
      var num = el("button", "cal-daynum", String(cur.getDate())); num.type = "button";
      (function (dd) { num.addEventListener("click", function (ev) { ev.stopPropagation(); location = createHref(ymd(dd)); }); })(cur);
      head.appendChild(num);
      cell.appendChild(head);
      var list = el("div", "cal-cell-events");
      var evs = byDay[ymd(cur)] || [];
      evs.slice(0, 3).forEach(function (e) { list.appendChild(chip(e)); });
      if (evs.length > 3) {
        var more = el("button", "cal-more", "+" + (evs.length - 3) + " more"); more.type = "button";
        (function (dd, all) { more.addEventListener("click", function (ev) { ev.stopPropagation(); openPopover(ev.currentTarget, dd, all); }); })(cur, evs);
        list.appendChild(more);
      }
      cell.appendChild(list);
      (function (dd) { cell.addEventListener("click", function () { location = createHref(ymd(dd)); }); })(cur);
      grid.appendChild(cell);
    }
    body.appendChild(grid);
  }

  function renderWeek(body, byDay) {
    var wrap = el("div", "cal-week");
    var s = startOfWeek(anchor);
    var today = new Date(); today.setHours(0, 0, 0, 0);
    for (var i = 0; i < 7; i++) {
      var day = addDays(s, i);
      var col = el("div", "cal-wcol");
      if (sameDay(day, today)) col.classList.add("cal-today");
      var h = el("div", "cal-wcol-head");
      h.appendChild(el("span", "cal-wcol-dow", WD[day.getDay()]));
      h.appendChild(el("span", "cal-wcol-num", String(day.getDate())));
      col.appendChild(h);
      var listWrap = el("div", "cal-wcol-body");
      var evs = (byDay[ymd(day)] || []).slice().sort(byTime);
      evs.forEach(function (e) { listWrap.appendChild(chip(e)); });
      (function (dd) { listWrap.addEventListener("click", function (ev) { if (ev.target === listWrap) location = createHref(ymd(dd)); }); })(day);
      col.appendChild(listWrap);
      wrap.appendChild(col);
    }
    body.appendChild(wrap);
  }

  function renderDay(body, byDay) {
    var wrap = el("div", "cal-day");
    var evs = (byDay[ymd(anchor)] || []).slice().sort(byTime);
    if (!evs.length) {
      var empty = el("div", "cal-empty", "No events. Click to add one.");
      empty.addEventListener("click", function () { location = createHref(ymd(anchor)); });
      wrap.appendChild(empty);
    } else {
      evs.forEach(function (e) {
        var row = el("div", "cal-agenda-row");
        row.appendChild(el("span", "cal-agenda-time", e.startTime || "all-day"));
        var c = chip(e); c.classList.add("cal-agenda-chip");
        row.appendChild(c);
        wrap.appendChild(row);
      });
      var add = el("button", "btn btn-sm cal-add", "+ New on this day"); add.type = "button";
      add.addEventListener("click", function () { location = createHref(ymd(anchor)); });
      wrap.appendChild(add);
    }
    body.appendChild(wrap);
  }
  function byTime(a, b) { return (a.startTime || "").localeCompare(b.startTime || ""); }

  // ---- day popover (month "+N more") -------------------------------------
  var pop = null;
  function openPopover(target, day, evs) {
    closePopover();
    pop = el("div", "cal-pop");
    var head = el("div", "cal-pop-head", MONTHS[day.getMonth()].slice(0, 3) + " " + day.getDate());
    pop.appendChild(head);
    evs.slice().sort(byTime).forEach(function (e) { pop.appendChild(chip(e)); });
    document.body.appendChild(pop);
    var r = target.getBoundingClientRect();
    pop.style.top = (window.scrollY + r.bottom + 4) + "px";
    pop.style.left = Math.min(window.scrollX + r.left, window.scrollX + document.documentElement.clientWidth - pop.offsetWidth - 8) + "px";
    setTimeout(function () { document.addEventListener("click", onDoc, true); }, 0);
  }
  function onDoc(ev) { if (pop && !pop.contains(ev.target)) closePopover(); }
  function closePopover() { if (pop) { pop.remove(); pop = null; document.removeEventListener("click", onDoc, true); } }

  // ---- boot --------------------------------------------------------------
  buildBar();
  buildToolbar();
  load();
})();
