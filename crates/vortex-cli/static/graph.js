/* Configurable graph view. Shares the pivot's aggregation engine
 * (/pivot/{model}/data) and renders with the vendored Chart.js (v4).
 *
 * Drag a dimension into X-axis (with day/month/quarter/year bucketing for
 * dates), optionally a Series/breakdown dimension, and one or more measures
 * with an aggregation; pick a chart type. Config mirrors to the URL and the
 * Saved-views form so a chart is shareable and saveable, exactly like the pivot.
 * No build step, no new dependency (Chart.js is already vendored). */
(function () {
  "use strict";
  var root = document.getElementById("graph-root");
  if (!root || typeof Chart === "undefined") return;

  var MODEL = root.dataset.model;
  var DATA_URL = root.dataset.dataUrl; // /pivot/{model}/data — the pivot engine
  var FIELDS = JSON.parse(root.dataset.fields || "[]"); // [{name,label,numeric,date}]
  var FIELD_BY = {};
  FIELDS.forEach(function (f) { FIELD_BY[f.name] = f; });

  var AGGS = [["count", "Count"], ["sum", "Sum"], ["avg", "Average"], ["min", "Min"], ["max", "Max"]];
  var AGG_OK = { count: 1, sum: 1, avg: 1, min: 1, max: 1 };
  var GRANS = [["day", "Day"], ["week", "Week"], ["month", "Month"], ["quarter", "Quarter"], ["year", "Year"]];
  var GRAN_OK = { day: 1, week: 1, month: 1, quarter: 1, year: 1 };
  var TYPES = [
    ["bar", "Column"], ["hbar", "Bar"], ["line", "Line"], ["area", "Area"],
    ["pie", "Pie"], ["doughnut", "Donut"], ["stacked", "Stacked"], ["stackedarea", "Stacked area"],
  ];
  var TYPE_OK = {}; TYPES.forEach(function (t) { TYPE_OK[t[0]] = 1; });
  var PALETTE = ["#8BC53F", "#3b82f6", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899",
    "#14b8a6", "#f97316", "#6366f1", "#84cc16", "#06b6d4", "#eab308"];

  // ---- helpers -----------------------------------------------------------
  function el(tag, cls, txt) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (txt != null) e.textContent = txt;
    return e;
  }
  function labelOf(n) { return (FIELD_BY[n] && FIELD_BY[n].label) || n; }
  function isDate(n) { return !!(FIELD_BY[n] && FIELD_BY[n].date); }
  function isNumeric(n) { return !!(FIELD_BY[n] && FIELD_BY[n].numeric); }
  function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }
  function b64e(s) { return btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
  function b64d(s) {
    s = String(s).replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    try { return decodeURIComponent(escape(atob(s))); } catch (e) { return ""; }
  }
  function cmp(a, b) {
    var na = parseFloat(a), nb = parseFloat(b);
    if (!isNaN(na) && !isNaN(nb) && String(na) === a && String(nb) === b) return na - nb;
    return a < b ? -1 : a > b ? 1 : 0;
  }
  function hexA(hex, a) {
    var m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex);
    if (!m) return hex;
    return "rgba(" + parseInt(m[1], 16) + "," + parseInt(m[2], 16) + "," + parseInt(m[3], 16) + "," + a + ")";
  }

  // ---- state -------------------------------------------------------------
  var initial = {};
  try { initial = JSON.parse(root.dataset.config || "{}"); } catch (e) {}
  var gran = {};
  function parseDim(str) {
    if (!str) return null;
    var s = String(str).split(",")[0], i = s.indexOf(":");
    var f = i < 0 ? s : s.slice(0, i), g = i < 0 ? "" : s.slice(i + 1);
    if (!FIELD_BY[f]) return null;
    if (g && GRAN_OK[g] && isDate(f)) gran[f] = g;
    return f;
  }
  function parseVals(str) {
    var out = [];
    if (!str) return out;
    String(str).split(",").filter(Boolean).forEach(function (tok) {
      var i = tok.indexOf("."), agg = i < 0 ? tok : tok.slice(0, i), field = i < 0 ? "id" : tok.slice(i + 1);
      if (!AGG_OK[agg]) return;
      if (field === "id") { out.push({ field: "", agg: "count" }); return; }
      if (!FIELD_BY[field]) return;
      out.push({ field: field, agg: agg });
    });
    return out;
  }
  function parseFilters(str) {
    var out = [];
    if (!str) return out;
    String(str).split(",").filter(Boolean).forEach(function (tok) {
      var i = tok.indexOf("."); if (i < 0) return;
      var field = tok.slice(0, i);
      if (!FIELD_BY[field]) return;
      out.push({ field: field, value: b64d(tok.slice(i + 1)) });
    });
    return out;
  }
  var state = {
    x: parseDim(initial.group_by),
    series: parseDim(initial.series),
    values: parseVals(initial.vals),
    filters: parseFilters(initial.filters),
    gran: gran,
    type: TYPE_OK[initial.type] ? initial.type : "bar",
  };

  // ---- DOM refs ----------------------------------------------------------
  var paneFields = document.getElementById("g-fields");
  var zoneEls = {
    filters: document.getElementById("g-zone-filters"),
    x: document.getElementById("g-zone-x"),
    series: document.getElementById("g-zone-series"),
    values: document.getElementById("g-zone-values"),
  };
  var typesBox = document.getElementById("g-types");
  var canvas = document.getElementById("g-canvas");
  var chartWrap = document.getElementById("g-chart-wrap");

  // ---- field pane --------------------------------------------------------
  function usedSet() {
    var u = {};
    if (state.x) u[state.x] = 1;
    if (state.series) u[state.series] = 1;
    state.values.forEach(function (v) { if (v.field) u[v.field] = 1; });
    state.filters.forEach(function (f) { u[f.field] = 1; });
    return u;
  }
  function renderPane() {
    var used = usedSet();
    paneFields.innerHTML = "";
    FIELDS.forEach(function (f) {
      var chip = el("div", "pv-field" + (f.numeric ? " pv-num" : "") + (used[f.name] ? " pv-used" : ""));
      chip.appendChild(el("span", "pv-grip", "⠿"));
      chip.appendChild(el("span", "pv-label", f.label));
      chip.appendChild(el("span", "pv-badge", f.numeric ? "#" : (f.date ? "date" : "abc")));
      chip.draggable = true;
      chip.addEventListener("dragstart", function (ev) {
        ev.dataTransfer.setData("text/plain", JSON.stringify({ field: f.name, from: "list" }));
      });
      paneFields.appendChild(chip);
    });
    renderDimZone("x");
    renderDimZone("series");
    renderFilters();
    renderValues();
    renderTypes();
  }

  function granSelect(name) {
    var sel = el("select"); sel.title = "Group dates by";
    GRANS.forEach(function (g) {
      var o = el("option", null, g[1]); o.value = g[0];
      if (g[0] === (state.gran[name] || "month")) o.selected = true;
      sel.appendChild(o);
    });
    sel.addEventListener("click", function (ev) { ev.stopPropagation(); });
    sel.addEventListener("change", function () { state.gran[name] = sel.value; changed(); });
    return sel;
  }

  // X-axis and Series are single-capacity zones.
  function renderDimZone(zone) {
    var box = zoneEls[zone];
    box.querySelectorAll(".pv-chip, .pv-zone-empty").forEach(function (n) { n.remove(); });
    var name = state[zone];
    if (!name) {
      box.appendChild(el("div", "pv-zone-empty", zone === "x" ? "Drop a dimension" : "Optional breakdown"));
      return;
    }
    var chip = el("div", "pv-chip");
    chip.appendChild(el("span", "pv-label", labelOf(name)));
    if (isDate(name)) chip.appendChild(granSelect(name));
    var x = el("span", "pv-x", "×"); x.title = "Remove";
    x.addEventListener("click", function () { state[zone] = null; changed(); });
    chip.appendChild(x);
    box.appendChild(chip);
  }

  function renderValues() {
    var box = zoneEls.values;
    box.querySelectorAll(".pv-chip, .pv-zone-empty, .pv-addcalc").forEach(function (n) { n.remove(); });
    if (!state.values.length) {
      var d = el("div", "pv-chip pv-chip-default");
      d.appendChild(el("span", "pv-label", "Count of records"));
      box.appendChild(d);
    }
    state.values.forEach(function (v, idx) {
      var chip = el("div", "pv-chip");
      if (v.field === "") {
        chip.appendChild(el("span", "pv-label", "Count of records"));
      } else {
        chip.appendChild(el("span", "pv-label", labelOf(v.field)));
        var sel = el("select");
        AGGS.forEach(function (a) {
          var o = el("option", null, a[1]); o.value = a[0];
          if (a[0] === v.agg) o.selected = true;
          sel.appendChild(o);
        });
        sel.addEventListener("change", function () { v.agg = sel.value; changed(); });
        chip.appendChild(sel);
      }
      var x = el("span", "pv-x", "×"); x.title = "Remove";
      x.addEventListener("click", function () { state.values.splice(idx, 1); changed(); });
      chip.appendChild(x);
      box.appendChild(chip);
    });
  }

  // ---- filters (value picker fetched from the pivot values endpoint) -----
  var valuesCache = {};
  function loadFieldValues(field, cb) {
    if (valuesCache[field]) { cb(valuesCache[field]); return; }
    fetch("/pivot/" + encodeURIComponent(MODEL) + "/values?field=" + encodeURIComponent(field), { headers: { Accept: "application/json" } })
      .then(function (r) { return r.json(); })
      .then(function (d) { var vs = (d && d.ok && d.values) || []; valuesCache[field] = vs; cb(vs); })
      .catch(function () { cb([]); });
  }
  function renderFilters() {
    var box = zoneEls.filters;
    box.querySelectorAll(".pv-chip, .pv-zone-empty").forEach(function (n) { n.remove(); });
    if (!state.filters.length) { box.appendChild(el("div", "pv-zone-empty", "Drop a field to filter")); return; }
    state.filters.forEach(function (f, idx) {
      var chip = el("div", "pv-chip");
      chip.appendChild(el("span", "pv-label", labelOf(f.field)));
      var sel = el("select");
      var all = el("option", null, "(All)"); all.value = ""; sel.appendChild(all);
      if (f.value) { var cur = el("option", null, f.value); cur.value = f.value; cur.selected = true; sel.appendChild(cur); }
      sel.addEventListener("focus", function () {
        loadFieldValues(f.field, function (vals) {
          var chosen = sel.value;
          sel.innerHTML = "";
          var a0 = el("option", null, "(All)"); a0.value = ""; sel.appendChild(a0);
          vals.forEach(function (val) { var o = el("option", null, val); o.value = val; if (val === chosen) o.selected = true; sel.appendChild(o); });
        });
      });
      sel.addEventListener("change", function () { f.value = sel.value; changed(); });
      chip.appendChild(sel);
      var x = el("span", "pv-x", "×"); x.title = "Remove";
      x.addEventListener("click", function () { state.filters.splice(idx, 1); changed(); });
      chip.appendChild(x);
      box.appendChild(chip);
    });
  }
  function activeFilters() { return state.filters.filter(function (f) { return f.value; }); }

  // ---- chart-type picker -------------------------------------------------
  function renderTypes() {
    typesBox.innerHTML = "";
    TYPES.forEach(function (t) {
      var b = el("button", "g-type" + (state.type === t[0] ? " g-type-on" : ""), t[1]);
      b.type = "button";
      b.addEventListener("click", function () { state.type = t[0]; syncState(); renderTypes(); drawChart(); });
      typesBox.appendChild(b);
    });
  }

  // ---- drag & drop -------------------------------------------------------
  function onDrop(zone, ev) {
    ev.preventDefault();
    var raw = ev.dataTransfer.getData("text/plain"); if (!raw) return;
    var d; try { d = JSON.parse(raw); } catch (e) { return; }
    var field = d.field; if (!field || !FIELD_BY[field]) return;
    // Remove from a previous single-capacity source zone.
    if (d.from === "x") state.x = null;
    if (d.from === "series") state.series = null;
    if (zone === "x") state.x = field;
    else if (zone === "series") state.series = field;
    else if (zone === "values") {
      if (!isNumeric(field)) { state.values.push({ field: field, agg: "count" }); }
      else if (!state.values.some(function (v) { return v.field === field; })) state.values.push({ field: field, agg: "sum" });
    } else if (zone === "filters") {
      if (!state.filters.some(function (f) { return f.field === field; })) state.filters.push({ field: field, value: "" });
    }
    if (isDate(field) && (zone === "x" || zone === "series") && !state.gran[field]) state.gran[field] = "month";
    changed();
  }
  Object.keys(zoneEls).forEach(function (zone) {
    var box = zoneEls[zone];
    box.addEventListener("dragover", function (ev) { ev.preventDefault(); box.classList.add("pv-over"); });
    box.addEventListener("dragleave", function () { box.classList.remove("pv-over"); });
    box.addEventListener("drop", function (ev) { box.classList.remove("pv-over"); onDrop(zone, ev); });
  });

  // ---- config → query + persistence -------------------------------------
  function dimParam(f) { return (isDate(f) && state.gran[f]) ? f + ":" + state.gran[f] : f; }
  function valsParam() { return state.values.map(function (v) { return v.agg + "." + (v.field || "id"); }).join(","); }
  function filtersParam() { return activeFilters().map(function (f) { return f.field + "." + b64e(f.value); }).join(","); }
  function dataQuery() {
    var p = new URLSearchParams();
    if (state.x) p.set("rows", dimParam(state.x));
    if (state.series) p.set("cols", dimParam(state.series));
    var vp = valsParam(); if (vp) p.set("vals", vp);
    var fp = filtersParam(); if (fp) p.set("filters", fp);
    return p.toString();
  }
  function cfg() {
    return {
      group_by: state.x ? dimParam(state.x) : "",
      series: state.series ? dimParam(state.series) : "",
      vals: valsParam(),
      filters: filtersParam(),
      type: state.type,
    };
  }
  function syncState() {
    var c = cfg();
    var p = new URLSearchParams();
    Object.keys(c).forEach(function (k) { if (c[k]) p.set(k, c[k]); });
    var qs = p.toString();
    history.replaceState(null, "", location.pathname + (qs ? "?" + qs : ""));
    updateSaveInputs(c);
  }
  function updateSaveInputs(c) {
    var form = document.querySelector('form[action="/views/save"]');
    if (!form) return;
    form.querySelectorAll('input[name^="cfg_"]').forEach(function (n) { n.remove(); });
    Object.keys(c).forEach(function (k) {
      if (c[k] === "") return;
      var i = document.createElement("input");
      i.type = "hidden"; i.name = "cfg_" + k; i.value = c[k];
      form.appendChild(i);
    });
  }

  // ---- fetch + render ----------------------------------------------------
  var lastData = null, chart = null, reqSeq = 0;
  function changed() { renderPane(); syncState(); fetchAndRender(); }
  function hint(msg) {
    if (chart) { chart.destroy(); chart = null; }
    chartWrap.querySelector(".g-hint") && chartWrap.querySelector(".g-hint").remove();
    canvas.style.display = "none";
    var h = el("div", "g-hint", msg); chartWrap.appendChild(h);
  }
  function clearHint() {
    var h = chartWrap.querySelector(".g-hint"); if (h) h.remove();
    canvas.style.display = "";
  }
  function fetchAndRender() {
    if (!state.x) { hint("Drag a field into X-axis to build a chart."); return; }
    var seq = ++reqSeq;
    chartWrap.classList.add("pv-busy");
    fetch(DATA_URL + "?" + dataQuery(), { headers: { Accept: "application/json" } })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (seq !== reqSeq) return;
        chartWrap.classList.remove("pv-busy");
        if (!data || !data.ok) { hint("Could not compute this chart."); return; }
        lastData = data;
        drawChart();
      })
      .catch(function () { if (seq === reqSeq) { chartWrap.classList.remove("pv-busy"); hint("Network error."); } });
  }

  function themeColors() {
    var cs = getComputedStyle(document.documentElement);
    var bc = cs.getPropertyValue("--bc").trim();
    return {
      text: bc ? "oklch(" + bc + ")" : "#888",
      grid: bc ? "oklch(" + bc + " / 0.12)" : "rgba(128,128,128,.15)",
    };
  }

  function cellKey(r, c) { return r.join("") + "" + c.join(""); }

  function buildChartConfig(data) {
    var measures = (data.measures && data.measures.length) ? data.measures : [{ label: "Count" }];
    var rowN = (data.rowFields || []).length;
    var colN = (data.colFields || []).length;
    var map = {}, cats = [], catSeen = {}, sers = [], serSeen = {};
    (data.cells || []).forEach(function (cell) {
      map[cellKey(cell.r, cell.c)] = cell.vs;
      if (cell.r.length === rowN) {
        var cat = rowN ? cell.r[0] : "Total";
        if (!catSeen[cat]) { catSeen[cat] = 1; cats.push({ key: cat, r: cell.r }); }
      }
      if (colN && cell.c.length === colN) {
        var sv = cell.c[0];
        if (!serSeen[sv]) { serSeen[sv] = 1; sers.push({ key: sv, c: cell.c }); }
      }
    });
    cats.sort(function (a, b) { return cmp(a.key, b.key); });
    sers.sort(function (a, b) { return cmp(a.key, b.key); });
    function valAt(r, c, mi) { var vs = map[cellKey(r, c)]; if (!vs) return 0; var v = vs[mi]; return v == null ? 0 : v; }
    function catLabel(k) { return k === "" ? "(empty)" : k; }

    var t = state.type;
    var isPie = t === "pie" || t === "doughnut";
    var labels = cats.map(function (c) { return catLabel(c.key); });
    var datasets;

    if (isPie) {
      // One slice per category; value = the category total (ROLLUP row-total,
      // which the engine provides at c=[]). Series is ignored for pie.
      datasets = [{
        data: cats.map(function (c) { return valAt(c.r, [], 0); }),
        backgroundColor: cats.map(function (_, i) { return PALETTE[i % PALETTE.length]; }),
        borderWidth: 0,
      }];
    } else if (colN) {
      // Series breakdown: one dataset per distinct series value, measure 0.
      datasets = sers.map(function (s, i) {
        return { label: catLabel(s.key), _col: PALETTE[i % PALETTE.length],
          data: cats.map(function (c) { return valAt(c.r, s.c, 0); }) };
      });
    } else {
      // No breakdown: one dataset per measure (row-total cells at c=[]).
      datasets = measures.map(function (m, i) {
        return { label: m.label, _col: PALETTE[i % PALETTE.length],
          data: cats.map(function (c) { return valAt(c.r, [], i); }) };
      });
    }

    var stacked = t === "stacked" || t === "stackedarea";
    var filled = t === "area" || t === "stackedarea";
    var line = t === "line" || t === "area" || t === "stackedarea";
    var chartType = isPie ? t : (line ? "line" : "bar");
    if (!isPie) {
      datasets.forEach(function (ds) {
        var col = ds._col; delete ds._col;
        ds.backgroundColor = filled ? hexA(col, 0.3) : col;
        ds.borderColor = col;
        ds.fill = filled;
        ds.borderWidth = line ? 2 : 1;
        ds.tension = 0.25;
        ds.pointRadius = line ? 2 : 0;
        ds.borderRadius = (!line && !stacked) ? 3 : 0;
      });
    }

    var tc = themeColors();
    var options = {
      responsive: true, maintainAspectRatio: false,
      animation: { duration: 250 },
      plugins: {
        legend: { display: isPie || datasets.length > 1, position: isPie ? "right" : "top", labels: { color: tc.text, boxWidth: 12 } },
        tooltip: { callbacks: {} },
      },
    };
    if (!isPie) {
      options.indexAxis = t === "hbar" ? "y" : "x";
      var valAxis = { stacked: stacked, beginAtZero: true, ticks: { color: tc.text }, grid: { color: tc.grid } };
      var catAxis = { stacked: stacked, ticks: { color: tc.text }, grid: { color: tc.grid } };
      options.scales = t === "hbar" ? { x: valAxis, y: catAxis } : { x: catAxis, y: valAxis };
    }
    return { type: chartType, data: { labels: labels, datasets: datasets }, options: options };
  }

  function drawChart() {
    if (!lastData) return;
    clearHint();
    var conf = buildChartConfig(lastData);
    if (chart) chart.destroy();
    chart = new Chart(canvas.getContext("2d"), conf);
  }

  // Re-theme on light/dark toggle (the toggle stamps data-theme on <html>).
  var themeObserver = new MutationObserver(function () { if (chart) drawChart(); });
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

  // ---- export (PNG / PDF) ------------------------------------------------
  function exportTitle() {
    var h = document.querySelector("main h1");
    return (h && h.textContent && h.textContent.trim()) || MODEL;
  }
  // Composite the chart onto a white background (the canvas is transparent) with
  // a title bar, at device-pixel resolution so exports are crisp.
  function composited() {
    var dpr = window.devicePixelRatio || 1;
    var cssW = canvas.clientWidth || 800, cssH = canvas.clientHeight || 400, titleH = 30;
    var out = document.createElement("canvas");
    out.width = Math.round(cssW * dpr);
    out.height = Math.round((cssH + titleH) * dpr);
    var ctx = out.getContext("2d");
    ctx.scale(dpr, dpr);
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, cssW, cssH + titleH);
    ctx.fillStyle = "#111827";
    ctx.font = "600 15px system-ui, -apple-system, sans-serif";
    ctx.fillText(exportTitle(), 6, 21);
    ctx.drawImage(canvas, 0, titleH, cssW, cssH);
    return out;
  }
  function download(blob, name) {
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 0);
  }
  function exportPng() {
    if (!chart) return;
    composited().toBlob(function (blob) { if (blob) download(blob, MODEL + "-chart.png"); }, "image/png");
  }
  function dataUrlBytes(u) {
    var bin = atob(u.slice(u.indexOf(",") + 1)), n = bin.length, arr = new Uint8Array(n);
    for (var i = 0; i < n; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }
  // Minimal single-page PDF embedding the chart JPEG (DCTDecode) — no library.
  // Byte-accurate xref offsets are tracked as the objects are appended.
  function buildPdf(jpeg, w, h) {
    var enc = function (s) { return new TextEncoder().encode(s); };
    var chunks = [], len = 0, off = {};
    function push(b) { chunks.push(b); len += b.length; }
    function pushStr(s) { push(enc(s)); }
    function obj(n) { off[n] = len; }
    pushStr("%PDF-1.4\n");
    obj(1); pushStr("1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n");
    obj(2); pushStr("2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n");
    obj(3); pushStr("3 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 " + w + " " + h + "]/Resources<</XObject<</Im0 4 0 R>>>>/Contents 5 0 R>>\nendobj\n");
    obj(4); pushStr("4 0 obj\n<</Type/XObject/Subtype/Image/Width " + w + "/Height " + h + "/ColorSpace/DeviceRGB/BitsPerComponent 8/Filter/DCTDecode/Length " + jpeg.length + ">>\nstream\n");
    push(jpeg); pushStr("\nendstream\nendobj\n");
    var content = "q\n" + w + " 0 0 " + h + " 0 0 cm\n/Im0 Do\nQ\n";
    obj(5); pushStr("5 0 obj\n<</Length " + content.length + ">>\nstream\n" + content + "endstream\nendobj\n");
    var xrefAt = len;
    var xref = "xref\n0 6\n0000000000 65535 f \n";
    for (var i = 1; i <= 5; i++) xref += ("0000000000" + off[i]).slice(-10) + " 00000 n \n";
    pushStr(xref);
    pushStr("trailer\n<</Size 6/Root 1 0 R>>\nstartxref\n" + xrefAt + "\n%%EOF");
    var out = new Uint8Array(len), o = 0;
    chunks.forEach(function (c) { out.set(c, o); o += c.length; });
    return out;
  }
  function exportPdf() {
    if (!chart) return;
    var cv = composited();
    var bytes = dataUrlBytes(cv.toDataURL("image/jpeg", 0.92));
    download(new Blob([buildPdf(bytes, cv.width, cv.height)], { type: "application/pdf" }), MODEL + "-chart.pdf");
  }
  (function () {
    var png = document.getElementById("g-export-png"), pdf = document.getElementById("g-export-pdf");
    if (png) png.addEventListener("click", function () { exportPng(); if (document.activeElement) document.activeElement.blur(); });
    if (pdf) pdf.addEventListener("click", function () { exportPdf(); if (document.activeElement) document.activeElement.blur(); });
  })();

  renderPane();
  fetchAndRender();
})();
