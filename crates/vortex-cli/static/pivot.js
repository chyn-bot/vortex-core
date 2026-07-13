/* Excel-style interactive pivot table.
 *
 * Reads its configuration from `#pivot-root` data-* attributes, renders a
 * PivotTable-Fields pane (drag fields into Filters / Rows / Columns / Values),
 * and on any change fetches aggregated data from `/pivot/{model}/data` and
 * renders the matrix client-side — with expand/collapse, subtotals and grand
 * totals computed in SQL (ROLLUP), so averages and min/max are correct at every
 * level rather than faked by summing leaves.
 *
 * Features: multiple value fields (each with its own aggregation), a Filters
 * zone that pins field=value conditions (values fetched from
 * `/pivot/{model}/values`), collapse state that persists into a saved view, and
 * one-click Export to Excel (CSV). No build step, no dependencies. Config is
 * mirrored to the URL and the "Saved views" save-form so a view is shareable and
 * saveable.
 */
(function () {
  "use strict";
  var root = document.getElementById("pivot-root");
  if (!root) return;

  var MODEL = root.dataset.model;
  var DATA_URL = root.dataset.dataUrl; // /pivot/{model}/data
  var FIELDS = JSON.parse(root.dataset.fields || "[]"); // [{name,label,numeric}]
  var FIELD_BY = {};
  FIELDS.forEach(function (f) { FIELD_BY[f.name] = f; });

  var AGGS = [
    ["count", "Count"], ["sum", "Sum"], ["avg", "Average"],
    ["min", "Min"], ["max", "Max"],
  ];
  var AGG_CODES = { count: 1, sum: 1, avg: 1, min: 1, max: 1 };

  // "Show value as" display modes (computed client-side from the aggregated
  // cells + their ROLLUP totals — no server involvement).
  var SHOWS = [
    ["", "No comparison"], ["pct_grand", "% of grand total"],
    ["pct_row", "% of row"], ["pct_col", "% of column"],
    ["diff_prev", "Δ vs previous"], ["pct_prev", "% vs previous"],
    ["diff_first", "Δ vs first"], ["pct_first", "% vs first"],
    ["run_total", "Running total"],
    ["rank_row", "Rank in row"], ["rank_col", "Rank in column"],
  ];
  var SHOW_OK = {
    "": 1, pct_grand: 1, pct_row: 1, pct_col: 1, diff_prev: 1, pct_prev: 1,
    diff_first: 1, pct_first: 1, run_total: 1, rank_row: 1, rank_col: 1,
  };
  function showLabel(s) { for (var i = 0; i < SHOWS.length; i++) if (SHOWS[i][0] === s) return SHOWS[i][1]; return s; }

  // ---- base64url (UTF-8 safe) for filter values & collapse keys -----------
  function b64e(s) {
    return btoa(unescape(encodeURIComponent(s)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function b64d(s) {
    s = String(s).replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    try { return decodeURIComponent(escape(atob(s))); } catch (e) { return ""; }
  }

  // ---- state -------------------------------------------------------------
  var initial = {};
  try { initial = JSON.parse(root.dataset.config || "{}"); } catch (e) {}

  function parseVals(init) {
    var out = [];
    if (init.vals) {
      String(init.vals).split(",").filter(Boolean).forEach(function (tok) {
        var i = tok.indexOf(".");
        var agg = i < 0 ? tok : tok.slice(0, i);
        var field = i < 0 ? "id" : tok.slice(i + 1);
        if (!AGG_CODES[agg]) return;
        if (field === "id") { out.push({ field: "", agg: "count" }); return; }
        if (!FIELD_BY[field]) return;
        out.push({ field: field, agg: agg });
      });
    } else if (init.measure && init.measure !== "id" && FIELD_BY[init.measure]) {
      out.push({ field: init.measure, agg: AGG_CODES[init.agg] ? init.agg : "count" });
    }
    return out;
  }

  // The value list: aggregate measures {field, agg, show}, calculated-field
  // measures {expr, agg, label, show} (server-computed), and calculated measures
  // {calc, label, show} (client-computed formula over the other value columns).
  // `mx` (base64 JSON) is the authoritative full list; `vals` is the legacy
  // aggregate-only fallback so old URLs/saved views keep working.
  function parseMeasures(init) {
    if (init.mx) {
      try {
        var arr = JSON.parse(b64d(init.mx));
        if (Array.isArray(arr)) {
          return arr.map(function (v) {
            if (!v || typeof v !== "object") return null;
            var show = SHOW_OK[v.show] ? v.show : "";
            if (v.calc != null) return { calc: String(v.calc), label: String(v.label || "Calc"), show: show };
            if (v.expr != null) {
              return { expr: String(v.expr), agg: AGG_CODES[v.agg] ? v.agg : "sum", label: String(v.label || "Calc field"), show: show };
            }
            var f = v.field ? String(v.field) : "";
            if (f && !FIELD_BY[f]) return null;
            return { field: f, agg: AGG_CODES[v.agg] ? v.agg : "count", show: show };
          }).filter(Boolean);
        }
      } catch (e) { /* fall through */ }
    }
    return parseVals(init).map(function (v) { return { field: v.field, agg: v.agg, show: "" }; });
  }
  function parseFilters(str) {
    var out = [];
    if (!str) return out;
    String(str).split(",").filter(Boolean).forEach(function (tok) {
      var i = tok.indexOf(".");
      if (i < 0) return;
      var field = tok.slice(0, i);
      if (!FIELD_BY[field]) return;
      out.push({ field: field, value: b64d(tok.slice(i + 1)) });
    });
    return out;
  }
  function parseCollapsed(str) {
    var out = {};
    if (!str) return out;
    String(str).split(",").filter(Boolean).forEach(function (b) {
      out[b64d(b)] = false; // false == collapsed
    });
    return out;
  }

  var GRANS = [["day", "Day"], ["week", "Week"], ["month", "Month"], ["quarter", "Quarter"], ["year", "Year"]];
  var GRAN_OK = { day: 1, week: 1, month: 1, quarter: 1, year: 1 };
  function isDateField(name) { return !!(FIELD_BY[name] && FIELD_BY[name].date); }

  // Row/column tokens may be `field` or (for a date) `field:granularity`.
  // Splits the granularity out into the shared `gran` map.
  var gran = {};
  function parseDims(arr) {
    var out = [];
    (arr || []).forEach(function (tok) {
      var s = String(tok);
      var i = s.indexOf(":");
      var f = i < 0 ? s : s.slice(0, i);
      var g = i < 0 ? "" : s.slice(i + 1);
      if (!FIELD_BY[f]) return;
      out.push(f);
      if (g && GRAN_OK[g] && isDateField(f)) gran[f] = g;
    });
    return out;
  }

  var state = {
    rows: parseDims(initial.rows),
    cols: parseDims(initial.cols),
    values: parseMeasures(initial),        // aggregate / calc-field / calc measures
    filters: parseFilters(initial.filters),// [{field, value}]
    expanded: parseCollapsed(initial.collapsed), // key -> false means collapsed
    gran: gran,                            // field -> day|week|month|quarter|year
    colDesc: String(initial.coldesc) === "1", // reverse column order (newest first)
  };

  // ---- helpers -----------------------------------------------------------
  function el(tag, cls, txt) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (txt != null) e.textContent = txt;
    return e;
  }
  function labelOf(name) { return (FIELD_BY[name] && FIELD_BY[name].label) || name; }
  function isNumeric(name) { return !!(FIELD_BY[name] && FIELD_BY[name].numeric); }
  function keyOf(arr) { return arr.join(" "); }
  function cellKey(r, c) { return keyOf(r) + "" + keyOf(c); }
  function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }
  function displayVal(v) { return v === "" ? "(empty)" : v; }

  // ---- calculated-measure formula evaluator (safe; NO eval) --------------
  // Grammar: number | #k (k-th value column) | + - * / ( ). Recursive descent.
  // `vs` is the cell's array of aggregated SQL-measure values.
  function tokenizeFormula(s) {
    var toks = [], re = /\s*(#\d+|\d+\.?\d*|\.\d+|[()+\-*/])/g, m, last = 0;
    while ((m = re.exec(s)) !== null) {
      if (m.index !== last) throw "bad";
      toks.push(m[1]); last = re.lastIndex;
    }
    if (last !== s.length) throw "bad";
    return toks;
  }
  function evalFormula(formula, vs) {
    try {
      var toks = tokenizeFormula(String(formula || ""));
      if (!toks.length) return null;
      var p = { i: 0 };
      function peek() { return toks[p.i]; }
      function next() { return toks[p.i++]; }
      function factor() {
        var t = peek();
        if (t === "(") { next(); var v = expr(); if (next() !== ")") throw "paren"; return v; }
        if (t === "-") { next(); return -factor(); }
        if (t === "+") { next(); return factor(); }
        if (t && t.charAt(0) === "#") {
          next();
          var k = parseInt(t.slice(1), 10);
          var raw = vs ? vs[k - 1] : null;
          if (raw == null) throw "null";
          return Number(raw);
        }
        if (t != null && /^[\d.]/.test(t)) { next(); return parseFloat(t); }
        throw "tok";
      }
      function term() {
        var v = factor();
        while (peek() === "*" || peek() === "/") {
          var op = next(); var r = factor();
          v = op === "*" ? v * r : v / r;
        }
        return v;
      }
      function expr() {
        var v = term();
        while (peek() === "+" || peek() === "-") {
          var op = next(); var r = term();
          v = op === "+" ? v + r : v - r;
        }
        return v;
      }
      var out = expr();
      if (p.i !== toks.length) return null; // trailing junk
      return isFinite(out) ? out : null;
    } catch (e) { return null; }
  }

  function fmtNum(v, agg) {
    if (v == null) return "";
    var n = Number(v);
    if (!isFinite(n)) return "";
    var dec = (agg === "avg" || (n % 1 !== 0)) ? 2 : 0;
    return n.toLocaleString(undefined, { minimumFractionDigits: dec, maximumFractionDigits: dec });
  }
  function activeFilters() {
    return state.filters.filter(function (f) { return f.value != null && f.value !== ""; });
  }
  function collapsedKeys() {
    return Object.keys(state.expanded).filter(function (k) { return state.expanded[k] === false; });
  }

  // Which fields are already placed (to dim them in the list).
  function usedSet() {
    var s = {};
    state.rows.forEach(function (n) { s[n] = 1; });
    state.cols.forEach(function (n) { s[n] = 1; });
    state.values.forEach(function (v) { if (v.field) s[v.field] = 1; });
    state.filters.forEach(function (f) { s[f.field] = 1; });
    return s;
  }

  // ---- pane rendering ----------------------------------------------------
  var paneFields = document.getElementById("pv-fields");
  var zoneEls = {
    filters: document.getElementById("pv-zone-filters"),
    rows: document.getElementById("pv-zone-rows"),
    cols: document.getElementById("pv-zone-cols"),
    values: document.getElementById("pv-zone-values"),
  };

  function renderPane() {
    var used = usedSet();
    paneFields.innerHTML = "";
    FIELDS.forEach(function (f) {
      var chip = el("div", "pv-field" + (f.numeric ? " pv-num" : "") + (used[f.name] ? " pv-used" : ""));
      chip.appendChild(el("span", "pv-grip", "⠿"));
      chip.appendChild(el("span", "pv-label", f.label));
      chip.appendChild(el("span", "pv-badge", f.numeric ? "#" : "abc"));
      chip.draggable = true;
      chip.addEventListener("dragstart", function (ev) {
        ev.dataTransfer.setData("text/plain", JSON.stringify({ field: f.name, from: "list" }));
      });
      paneFields.appendChild(chip);
    });

    renderFilters();
    renderZone("rows");
    renderZone("cols");
    renderZoneValues();
  }

  function renderZone(zone) {
    var box = zoneEls[zone];
    box.querySelectorAll(".pv-chip, .pv-zone-empty, .pv-colsort").forEach(function (n) { n.remove(); });
    var arr = state[zone];
    if (!arr.length) {
      box.appendChild(el("div", "pv-zone-empty", "Drop fields here"));
      return;
    }
    arr.forEach(function (name, idx) {
      var chip = el("div", "pv-chip");
      chip.draggable = true;
      chip.appendChild(el("span", "pv-label", labelOf(name)));
      // Date/datetime dimensions get a grouping-granularity selector.
      if (isDateField(name)) {
        var gsel = el("select");
        gsel.title = "Group dates by";
        GRANS.forEach(function (g) {
          var o = el("option", null, g[1]); o.value = g[0];
          if (g[0] === (state.gran[name] || "month")) o.selected = true;
          gsel.appendChild(o);
        });
        gsel.addEventListener("click", function (ev) { ev.stopPropagation(); });
        gsel.addEventListener("change", function () { state.gran[name] = gsel.value; changed(); });
        chip.appendChild(gsel);
      }
      var x = el("span", "pv-x", "×");
      x.title = "Remove";
      x.addEventListener("click", function () { arr.splice(idx, 1); changed(); });
      chip.appendChild(x);
      chip.addEventListener("dragstart", function (ev) {
        chip.classList.add("pv-dragging");
        ev.dataTransfer.setData("text/plain", JSON.stringify({ field: name, from: zone }));
      });
      chip.addEventListener("dragend", function () { chip.classList.remove("pv-dragging"); });
      chip.addEventListener("dragover", function (ev) { ev.preventDefault(); ev.stopPropagation(); });
      chip.addEventListener("drop", function (ev) { ev.preventDefault(); ev.stopPropagation(); onDrop(zone, ev, idx); });
      box.appendChild(chip);
    });
    // Column-order toggle: reverse the displayed columns (newest period first).
    // Comparisons still compute on chronological order, so only the view flips.
    if (zone === "cols") {
      var lbl = el("label", "pv-colsort");
      var cb = el("input"); cb.type = "checkbox"; cb.checked = state.colDesc;
      cb.addEventListener("change", function () { state.colDesc = cb.checked; changed(); });
      lbl.appendChild(cb);
      lbl.appendChild(el("span", null, "Newest first (reverse columns)"));
      box.appendChild(lbl);
    }
  }

  // A "show as / compare" selector, offered on every value chip. `onChange` lets
  // the default Count chip materialise itself into a real measure when a
  // comparison is picked (so you can compare without first adding a value field).
  function showSelect(v, onChange) {
    var ssel = el("select", "pv-showas"); ssel.title = "Show value as / compare (e.g. % vs previous month)";
    SHOWS.forEach(function (s) {
      var o = el("option", null, s[1]); o.value = s[0];
      if (s[0] === (v.show || "")) o.selected = true;
      ssel.appendChild(o);
    });
    ssel.addEventListener("change", function () { v.show = ssel.value; (onChange || changed)(); });
    return ssel;
  }

  // Hint listing the numbered value columns a formula can reference (#1, #2…).
  function measureRefsHint() {
    var refs = [], k = 0;
    state.values.forEach(function (v) {
      if (v.calc != null) return; // calc measures aren't referenceable
      k++;
      var lbl = v.expr != null ? (v.label || "Calc field")
        : (v.field ? (capitalize(v.agg) + " of " + labelOf(v.field)) : "Count of records");
      refs.push("#" + k + " = " + lbl);
    });
    return refs.length ? refs.join("\n") : "(add value fields first, e.g. Sum of Revenue)";
  }
  function addCalc() {
    var name = window.prompt("Name this calculation (e.g. Margin %)", "Margin %");
    if (name == null) return;
    var formula = window.prompt(
      "Formula — reference the value columns by number:\n\n" + measureRefsHint() +
      "\n\nOperators: + - * / ( )   Example:  (#1 - #2) / #1 * 100", "");
    if (formula == null || !formula.trim()) return;
    state.values.push({ calc: formula.trim(), label: name.trim() || "Calc", show: "" });
    changed();
  }
  function editCalc(idx) {
    var v = state.values[idx];
    if (!v || v.calc == null) return;
    var name = window.prompt("Name", v.label || "Calc");
    if (name == null) return;
    var formula = window.prompt("Formula:\n\n" + measureRefsHint(), v.calc);
    if (formula == null || !formula.trim()) return;
    v.label = name.trim() || v.label;
    v.calc = formula.trim();
    changed();
  }

  // Hint listing the numeric columns a calculated field's expression can use.
  function numericFieldsHint() {
    var ns = FIELDS.filter(function (f) { return f.numeric; })
      .map(function (f) { return f.name + "  (" + f.label + ")"; });
    return ns.length ? ns.join("\n") : "(this model has no numeric fields)";
  }
  // A calculated *field* is an expression over the raw numeric columns that is
  // aggregated server-side (e.g. SUM(quantity * unit_price)). The expression is
  // compiled to safe SQL on the server; here we just collect it.
  function addCalcField() {
    var name = window.prompt("Name this field (e.g. Line Total)", "Line Total");
    if (name == null) return;
    var expr = window.prompt(
      "Expression over numeric columns (aggregated per cell):\n\n" + numericFieldsHint() +
      "\n\nOperators: + - * / ( )   Example:  quantity * unit_price", "");
    if (expr == null || !expr.trim()) return;
    state.values.push({ expr: expr.trim(), agg: "sum", label: name.trim() || "Calc field", show: "" });
    changed();
  }
  function editCalcField(idx) {
    var v = state.values[idx];
    if (!v || v.expr == null) return;
    var name = window.prompt("Name", v.label || "Calc field");
    if (name == null) return;
    var expr = window.prompt("Expression over numeric columns:\n\n" + numericFieldsHint(), v.expr);
    if (expr == null || !expr.trim()) return;
    v.label = name.trim() || v.label;
    v.expr = expr.trim();
    changed();
  }

  function renderZoneValues() {
    var box = zoneEls.values;
    box.querySelectorAll(".pv-chip, .pv-zone-empty, .pv-addcalc").forEach(function (n) { n.remove(); });
    if (!state.values.length) {
      var d = el("div", "pv-chip pv-chip-default");
      d.appendChild(el("span", "pv-label", "Count of records"));
      // Picking a comparison here turns the implicit count into a real measure.
      var dv = { field: "", agg: "count", show: "" };
      d.appendChild(showSelect(dv, function () { state.values.push(dv); changed(); }));
      box.appendChild(d);
    }
    state.values.forEach(function (v, idx) {
      var chip = el("div", "pv-chip");
      if (v.calc != null) {
        chip.appendChild(el("span", "pv-fx", "ƒ"));
        var clbl = el("span", "pv-label pv-calc", v.label || "Calc");
        clbl.title = "ƒ " + v.calc + "  ·  click to edit";
        clbl.addEventListener("click", function () { editCalc(idx); });
        chip.appendChild(clbl);
      } else if (v.field === "" && v.expr == null) {
        chip.appendChild(el("span", "pv-label", "Count of records"));
      } else {
        if (v.expr != null) {
          chip.appendChild(el("span", "pv-fx", "∑"));
          var elbl = el("span", "pv-label pv-calc", v.label || "Calc field");
          elbl.title = "∑ " + v.expr + "  ·  click to edit";
          elbl.addEventListener("click", (function (i) { return function () { editCalcField(i); }; })(idx));
          chip.appendChild(elbl);
        } else {
          chip.appendChild(el("span", "pv-label", labelOf(v.field)));
        }
        var sel = el("select");
        AGGS.forEach(function (a) {
          var o = el("option", null, a[1]); o.value = a[0];
          if (a[0] === v.agg) o.selected = true;
          sel.appendChild(o);
        });
        sel.addEventListener("change", function () { v.agg = sel.value; changed(); });
        chip.appendChild(sel);
      }
      chip.appendChild(showSelect(v));
      var x = el("span", "pv-x", "×"); x.title = "Remove";
      x.addEventListener("click", function () { state.values.splice(idx, 1); changed(); });
      chip.appendChild(x);
      box.appendChild(chip);
    });
    var add = el("div", "pv-addcalc");
    var btn = el("button", null, "ƒ Add calculation");
    btn.type = "button";
    btn.addEventListener("click", addCalc);
    add.appendChild(btn);
    var btn2 = el("button", null, "∑ Add calculated field");
    btn2.type = "button";
    btn2.addEventListener("click", addCalcField);
    add.appendChild(btn2);
    box.appendChild(add);
  }

  // ---- filters zone ------------------------------------------------------
  var valuesCache = {};
  function loadFieldValues(field, cb) {
    if (valuesCache[field]) { cb(valuesCache[field]); return; }
    fetch("/pivot/" + encodeURIComponent(MODEL) + "/values?field=" + encodeURIComponent(field), { headers: { "Accept": "application/json" } })
      .then(function (r) { return r.json(); })
      .then(function (d) { var vals = (d && d.ok && d.values) || []; valuesCache[field] = vals; cb(vals); })
      .catch(function () { cb([]); });
  }

  function renderFilters() {
    var box = zoneEls.filters;
    box.querySelectorAll(".pv-chip, .pv-zone-empty").forEach(function (n) { n.remove(); });
    if (!state.filters.length) {
      box.appendChild(el("div", "pv-zone-empty", "Drop a field to filter"));
      return;
    }
    state.filters.forEach(function (f, idx) {
      var chip = el("div", "pv-chip");
      chip.appendChild(el("span", "pv-label", labelOf(f.field)));
      var sel = el("select");
      var all = el("option", null, "(All)"); all.value = ""; sel.appendChild(all);
      loadFieldValues(f.field, function (vals) {
        vals.forEach(function (v) {
          var o = el("option", null, v === "" ? "(empty)" : v); o.value = v;
          if (v === f.value) o.selected = true;
          sel.appendChild(o);
        });
        sel.value = f.value || "";
      });
      sel.value = f.value || "";
      sel.addEventListener("change", function () { f.value = sel.value; changed(); });
      chip.appendChild(sel);
      var x = el("span", "pv-x", "×"); x.title = "Remove";
      x.addEventListener("click", function () { state.filters.splice(idx, 1); changed(); });
      chip.appendChild(x);
      box.appendChild(chip);
    });
  }

  // ---- drag & drop into zones -------------------------------------------
  function onDrop(zone, ev, insertIdx) {
    var raw = ev.dataTransfer.getData("text/plain");
    if (!raw) return;
    var payload;
    try { payload = JSON.parse(raw); } catch (e) { return; }
    var field = payload.field;
    if (!FIELD_BY[field]) return;

    if (zone === "filters") {
      if (!state.filters.some(function (f) { return f.field === field; })) {
        state.filters.push({ field: field, value: "" });
      }
      changed();
      return;
    }

    // rows / cols / values: pull the field out of rows & cols first (a move).
    ["rows", "cols"].forEach(function (z) {
      var i = state[z].indexOf(field);
      if (i >= 0) state[z].splice(i, 1);
    });

    if (zone === "values") {
      state.values.push({ field: field, agg: isNumeric(field) ? "sum" : "count" });
    } else {
      var arr = state[zone];
      var at = (insertIdx == null) ? arr.length : insertIdx;
      if (at > arr.length) at = arr.length;
      arr.splice(at, 0, field);
      // Dates default to grouping by month (like Odoo) rather than by raw day.
      if (isDateField(field) && !state.gran[field]) state.gran[field] = "month";
    }
    changed();
  }

  Object.keys(zoneEls).forEach(function (zone) {
    var box = zoneEls[zone];
    box.addEventListener("dragover", function (ev) { ev.preventDefault(); box.classList.add("pv-over"); });
    box.addEventListener("dragleave", function () { box.classList.remove("pv-over"); });
    box.addEventListener("drop", function (ev) {
      ev.preventDefault(); box.classList.remove("pv-over");
      onDrop(zone, ev, null);
    });
  });

  // ---- query / url / save-form sync -------------------------------------
  // Encode a row/col list, appending `:granularity` for date dimensions.
  function dimsParam(arr) {
    return arr.map(function (f) {
      return (isDateField(f) && state.gran[f]) ? f + ":" + state.gran[f] : f;
    }).join(",");
  }
  // SQL measures the server computes (aggregate or calc-field), in order —
  // calc measures are client-only and excluded. A calc field is `agg.=<b64expr>`.
  function valsParam() {
    return state.values.filter(function (v) { return v.calc == null; })
      .map(function (v) {
        if (v.expr != null) return v.agg + ".=" + b64e(v.expr);
        return v.agg + "." + (v.field || "id");
      }).join(",");
  }
  // The authoritative full value list (aggregate + calc-field + calc + show-as),
  // base64-JSON. The server ignores it; the client rebuilds `state.values` from it.
  function mxParam() {
    return state.values.length ? b64e(JSON.stringify(state.values)) : "";
  }
  function filtersParam() {
    return activeFilters().map(function (f) { return f.field + "." + b64e(f.value); }).join(",");
  }
  function queryString() {
    var p = new URLSearchParams();
    if (state.rows.length) p.set("rows", dimsParam(state.rows));
    if (state.cols.length) p.set("cols", dimsParam(state.cols));
    var vp = valsParam();
    if (vp) p.set("vals", vp);
    var mx = mxParam();
    if (mx) p.set("mx", mx);
    var fp = filtersParam();
    if (fp) p.set("filters", fp);
    if (state.colDesc) p.set("coldesc", "1");
    return p.toString();
  }

  function syncState() {
    var qs = queryString();
    var ck = collapsedKeys();
    var url = qs;
    if (ck.length) url += (url ? "&" : "") + "collapsed=" + ck.map(b64e).join(",");
    history.replaceState(null, "", location.pathname + (url ? "?" + url : ""));
    updateSaveInputs();
  }

  // Rebuild the "Saved views" save-form hidden inputs from the live state so a
  // saved view captures exactly what's on screen (incl. multiple values,
  // filters and collapse state).
  function updateSaveInputs() {
    var form = document.querySelector('form[action="/views/save"]');
    if (!form) return;
    form.querySelectorAll('input[name^="cfg_"]').forEach(function (n) { n.remove(); });
    var cfg = {
      rows: dimsParam(state.rows),
      cols: dimsParam(state.cols),
      vals: valsParam(),
      mx: mxParam(),
      filters: filtersParam(),
      collapsed: collapsedKeys().map(b64e).join(","),
      coldesc: state.colDesc ? "1" : "",
      // legacy single-measure keys, for older readers / defaults
      measure: state.values.length ? (state.values[0].field || "id") : "id",
      agg: state.values.length ? state.values[0].agg : "count",
    };
    Object.keys(cfg).forEach(function (k) {
      if (cfg[k] === "") return;
      var i = document.createElement("input");
      i.type = "hidden"; i.name = "cfg_" + k; i.value = cfg[k];
      form.appendChild(i);
    });
  }

  // ---- fetch + render ----------------------------------------------------
  var tableWrap = document.getElementById("pv-table-wrap");
  var reqSeq = 0;
  var lastData = null;

  function changed() {
    renderPane();
    syncState();
    fetchAndRender();
  }

  function fetchAndRender() {
    if (!state.rows.length && !state.cols.length) {
      lastData = null;
      tableWrap.innerHTML = '<div class="pv-hint">Drag a field into <b>Rows</b> or <b>Columns</b> to build a pivot.</div>';
      return;
    }
    var seq = ++reqSeq;
    tableWrap.classList.add("pv-busy");
    fetch(DATA_URL + "?" + queryString(), { headers: { "Accept": "application/json" } })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (seq !== reqSeq) return; // stale
        tableWrap.classList.remove("pv-busy");
        if (!data || !data.ok) { tableWrap.innerHTML = '<div class="pv-hint">' + escapeHtml((data && data.error) || "Could not compute pivot.") + "</div>"; return; }
        renderTable(data);
      })
      .catch(function () {
        if (seq !== reqSeq) return;
        tableWrap.classList.remove("pv-busy");
        tableWrap.innerHTML = '<div class="pv-hint">Network error computing pivot.</div>';
      });
  }

  function escapeHtml(s) { var d = el("div"); d.textContent = s == null ? "" : String(s); return d.innerHTML; }

  // ---- measures: resolve the client value list against the server cells --
  // The server returns one aggregated value per SQL measure (aggregate or
  // calc-field), in `vals`/`mx` order, in each cell's `vs`. The client value
  // list interleaves those with client-only calc measures; here we tag each with
  // how to get its number, and each carries an optional show-as mode.
  function clientMeasures(data) {
    var sqlMeasures = (data.measures && data.measures.length) ? data.measures : [{ agg: "count", field: "id", label: "Count" }];
    var list = [], si = 0;
    state.values.forEach(function (v) {
      if (v.calc != null) {
        list.push({ kind: "calc", label: v.label || "Calc", formula: v.calc, agg: "", show: v.show || "" });
      } else {
        var sm = sqlMeasures[si] || { agg: v.agg || "count", label: "Value" };
        // A calc field carries its own client-side label/agg (the server labels
        // it generically "Calc field"); a plain field uses the server metadata.
        var label = (v.expr != null && v.label) ? v.label : sm.label;
        var agg = (v.expr != null) ? (v.agg || "sum") : sm.agg;
        list.push({ kind: "agg", label: label, agg: agg, sqlIndex: si, show: v.show || "" });
        si++;
      }
    });
    if (!list.length) list.push({ kind: "agg", label: sqlMeasures[0].label, agg: sqlMeasures[0].agg, sqlIndex: 0, show: "" });
    return list;
  }
  // Expand measures into rendered sub-columns. A plain measure is one column; a
  // measure with a comparison becomes a PAIR — the raw value plus the comparison
  // beside it (Odoo-style), so the underlying number stays visible. Each part
  // carries an effective measure (`mo`) whose `show` drives dispVal.
  function renderColsOf(measures) {
    var out = [];
    measures.forEach(function (mo, mi) {
      var base = {}; for (var k in mo) base[k] = mo[k]; base.show = "";
      out.push({ mi: mi, mo: base, agg: mo.agg, label: mo.label, variation: false });
      if (mo.show) {
        var v = {}; for (var k2 in mo) v[k2] = mo[k2]; // keeps mo.show
        out.push({ mi: mi, mo: v, agg: mo.agg, label: showLabel(mo.show), variation: true });
      }
    });
    return out;
  }
  // Raw (pre-show-as) value of a measure at a cell.
  function rawVal(vsAt, rowPath, colPath, mo) {
    var vs = vsAt(rowPath, colPath);
    if (!vs) return null;
    if (mo.kind === "calc") return evalFormula(mo.formula, vs);
    var v = vs[mo.sqlIndex];
    return v == null ? null : v;
  }
  // The leaf column immediately before `colPath` that shares the same parent
  // (all keys but the last) — i.e. the previous period when the innermost column
  // dimension is a date grouping. `colLeaves` is chronologically sorted and
  // same-parent leaves are contiguous, so it's the entry just before, provided
  // its parent matches (else `colPath` is the first period in its group).
  function prevColPath(colLeaves, colPath) {
    if (!colPath || !colPath.length) return null;
    var key = keyOf(colPath), idx = -1;
    for (var i = 0; i < colLeaves.length; i++) {
      if (keyOf(colLeaves[i]) === key) { idx = i; break; }
    }
    if (idx <= 0) return null;
    var cand = colLeaves[idx - 1];
    if (cand.length !== colPath.length) return null;
    for (var j = 0; j < colPath.length - 1; j++) if (cand[j] !== colPath[j]) return null;
    return cand;
  }
  // All leaf paths sharing `path`'s parent (same length, same keys but the last),
  // in canonical order — `path`'s peers, used by first/running-total/rank modes.
  // Empty when `path` has no dimension (grand row/col) or isn't a full leaf.
  function siblingsOf(leaves, path) {
    if (!path || !path.length) return [];
    var res = [];
    for (var i = 0; i < leaves.length; i++) {
      var L = leaves[i];
      if (L.length !== path.length) continue;
      var ok = true;
      for (var j = 0; j < path.length - 1; j++) if (L[j] !== path[j]) { ok = false; break; }
      if (ok) res.push(L);
    }
    return res;
  }
  // 1-based rank of `base` among `values` (nulls ignored), largest = 1.
  function rankOf(base, values) {
    if (base == null) return null;
    var higher = 0;
    for (var i = 0; i < values.length; i++) if (values[i] != null && values[i] > base) higher++;
    return higher + 1;
  }
  // Display value + whether it's a percentage. Applies the show-as transform:
  // pct_* use the ROLLUP totals (grand / row / column) the server returned;
  // diff_prev / pct_prev compare the cell to the previous column (period).
  function dispVal(m, rowPath, colPath, mo) {
    var vsAt = m.vsAt;
    var base = rawVal(vsAt, rowPath, colPath, mo);
    if (base == null || !mo.show) return { v: base, pct: false };
    if (mo.show === "pct_grand" || mo.show === "pct_row" || mo.show === "pct_col") {
      var denom = null;
      if (mo.show === "pct_grand") denom = rawVal(vsAt, [], [], mo);
      else if (mo.show === "pct_row") denom = rawVal(vsAt, rowPath, [], mo);
      else denom = rawVal(vsAt, [], colPath, mo);
      if (denom == null || denom === 0) return { v: null, pct: true };
      return { v: base / denom * 100, pct: true };
    }
    if (mo.show === "diff_prev" || mo.show === "pct_prev") {
      var pct = mo.show === "pct_prev";
      var prev = prevColPath(m.colLeaves, colPath);
      if (!prev) return { v: null, pct: pct };
      var pv = rawVal(vsAt, rowPath, prev, mo);
      if (pv == null) return { v: null, pct: pct };
      if (!pct) return { v: base - pv, pct: false };
      if (pv === 0) return { v: null, pct: true };
      return { v: (base - pv) / pv * 100, pct: true };
    }
    if (mo.show === "diff_first" || mo.show === "pct_first") {
      var pctf = mo.show === "pct_first";
      var sibs = siblingsOf(m.colLeaves, colPath);
      if (!sibs.length) return { v: null, pct: pctf };
      var fv = rawVal(vsAt, rowPath, sibs[0], mo);
      if (fv == null) return { v: null, pct: pctf };
      if (!pctf) return { v: base - fv, pct: false };
      if (fv === 0) return { v: null, pct: true };
      return { v: (base - fv) / fv * 100, pct: true };
    }
    if (mo.show === "run_total") {
      var run = siblingsOf(m.colLeaves, colPath);
      if (!run.length) return { v: base, pct: false };
      var key = keyOf(colPath), acc = null;
      for (var i = 0; i < run.length; i++) {
        var cv = rawVal(vsAt, rowPath, run[i], mo);
        if (cv != null) acc = (acc == null ? 0 : acc) + cv;
        if (keyOf(run[i]) === key) break; // stop at (and include) this column
      }
      return { v: acc, pct: false };
    }
    if (mo.show === "rank_row") {
      var rs = siblingsOf(m.colLeaves, colPath);
      if (!rs.length) return { v: null, pct: false };
      var rvals = rs.map(function (c) { return rawVal(vsAt, rowPath, c, mo); });
      return { v: rankOf(base, rvals), rank: true };
    }
    if (mo.show === "rank_col") {
      var cs = siblingsOf(m.rowLeaves, rowPath);
      if (!cs.length) return { v: null, pct: false };
      var cvals = cs.map(function (r) { return rawVal(vsAt, r, colPath, mo); });
      return { v: rankOf(base, cvals), rank: true };
    }
    return { v: base, pct: false };
  }
  function dataCellD(d, agg, extraCls) {
    var td = el("td", "pv-num-cell" + (extraCls ? " " + extraCls : ""));
    if (d.v == null) { td.className += " pv-empty-cell"; td.textContent = "—"; }
    else if (d.rank) { td.textContent = "#" + d.v; }
    else if (d.pct) { td.textContent = Number(d.v).toLocaleString(undefined, { minimumFractionDigits: 1, maximumFractionDigits: 1 }) + "%"; }
    else td.textContent = fmtNum(d.v, agg);
    return td;
  }

  // ---- matrix rendering --------------------------------------------------
  // Shared shape used by both the table renderer and the CSV exporter.
  function matrix(data) {
    var rowFields = data.rowFields || [];
    var colFields = data.colFields || [];
    var measures = clientMeasures(data);
    var M = measures.length;
    var cells = {};
    data.cells.forEach(function (c) { cells[cellKey(c.r, c.c)] = c.vs; });
    // `colLeaves` stays chronologically ascending — it is the CANONICAL order the
    // positional show-as modes (vs previous/first, running total, rank) compute
    // against, so those stay correct even when the display is reversed.
    var colLeaves = collectFullPaths(data.cells, "c", colFields.length);
    var rowLeaves = collectFullPaths(data.cells, "r", rowFields.length);
    var rowTree = buildTree(rowLeaves);
    var displayColLeaves = state.colDesc ? colLeaves.slice().reverse() : colLeaves;
    var leafColPaths = colFields.length === 0 ? [[]] : displayColLeaves;
    var renderCols = renderColsOf(measures);   // value + paired-variation sub-columns
    var RC = renderCols.length;
    var outputCols = [];
    leafColPaths.forEach(function (cp) {
      renderCols.forEach(function (rc) {
        outputCols.push({ cp: cp, mi: rc.mi, mo: rc.mo, agg: rc.agg, variation: rc.variation, label: rc.label });
      });
    });
    function vsAt(r, c) { return cells[cellKey(r, c)] || null; }
    return {
      rowFields: rowFields, colFields: colFields, measures: measures, M: M,
      renderCols: renderCols, RC: RC,
      colLeaves: colLeaves, displayColLeaves: displayColLeaves, rowLeaves: rowLeaves,
      rowTree: rowTree, outputCols: outputCols,
      showGrandCol: colFields.length > 0, showMeasureLevel: RC > 1, vsAt: vsAt,
    };
  }

  function renderTable(data) {
    lastData = data;
    var m = matrix(data);
    var rowFields = m.rowFields, colFields = m.colFields, measures = m.measures;
    var RC = m.RC, renderCols = m.renderCols;
    var outputCols = m.outputCols, colLeaves = m.displayColLeaves;
    var showGrandCol = m.showGrandCol, showMeasureLevel = m.showMeasureLevel;
    var vsAt = m.vsAt;
    // Sub-column header label: base part uses the measure name; a variation part
    // used on its own line (no columns) is qualified with the measure name.
    function subLabel(rc, qualify) {
      return rc.variation && qualify ? measures[rc.mi].label + " · " + rc.label : rc.label;
    }

    var table = el("table", "pv-table");

    // ----- header -----
    var thead = el("thead");
    var baseLevels = colFields.length;
    var headerRows = Math.max(1, baseLevels + (showMeasureLevel ? 1 : 0));
    var corner = el("th", "pv-corner", rowFields.map(function (f) { return f.label; }).join(" / ") || "");
    corner.rowSpan = headerRows;

    if (baseLevels === 0) {
      var tr0 = el("tr");
      tr0.appendChild(corner);
      renderCols.forEach(function (rc) {
        var th = el("th", rc.variation ? "pv-variation" : null, subLabel(rc, true));
        tr0.appendChild(th);
      });
      thead.appendChild(tr0);
    } else {
      var levels = buildColHeaderLevels(colLeaves, baseLevels);
      levels.forEach(function (cellsAtLevel, li) {
        var tr = el("tr");
        if (li === 0) tr.appendChild(corner);
        cellsAtLevel.forEach(function (h) {
          var th = el("th", null, h.label);
          th.colSpan = h.span * RC;
          tr.appendChild(th);
        });
        if (li === 0) {
          var gt = el("th", null, "Grand Total");
          if (showMeasureLevel) { gt.colSpan = RC; gt.rowSpan = baseLevels; }
          else { gt.rowSpan = headerRows; }
          tr.appendChild(gt);
        }
        thead.appendChild(tr);
      });
      if (showMeasureLevel) {
        var trm = el("tr");
        colLeaves.forEach(function () {
          renderCols.forEach(function (rc) { trm.appendChild(el("th", "pv-mhdr" + (rc.variation ? " pv-variation" : ""), subLabel(rc, false))); });
        });
        renderCols.forEach(function (rc) { trm.appendChild(el("th", "pv-mhdr" + (rc.variation ? " pv-variation" : ""), subLabel(rc, false))); }); // under grand total
        thead.appendChild(trm);
      }
    }
    table.appendChild(thead);

    // ----- body -----
    var tbody = el("tbody");
    function rowCells(path) {
      var frag = [];
      outputCols.forEach(function (oc) { frag.push(dataCellD(dispVal(m, path, oc.cp, oc.mo), oc.agg, oc.variation ? "pv-variation" : "")); });
      if (showGrandCol) renderCols.forEach(function (rc) { frag.push(dataCellD(dispVal(m, path, [], rc.mo), rc.agg, "pv-subtotal" + (rc.variation ? " pv-variation" : ""))); });
      return frag;
    }

    function renderNode(node, path, depth) {
      var names = Object.keys(node.children).sort(cmpVals);
      var isLeafLevel = depth === rowFields.length;
      if (isLeafLevel) return;
      names.forEach(function (name) {
        var childPath = path.concat([name]);
        var child = node.children[name];
        var childIsLeaf = (depth + 1) === rowFields.length;
        var key = keyOf(childPath);
        var tr = el("tr");
        if (!childIsLeaf) tr.className = "pv-subtotal";
        var hdr = el("td", "pv-rowhdr");
        var pad = el("span", "pv-indent"); pad.style.paddingLeft = (depth * 1.1) + "rem";
        hdr.appendChild(pad);
        if (!childIsLeaf) {
          var tog = el("span", "pv-toggle", state.expanded[key] === false ? "▸" : "▾");
          tog.addEventListener("click", function () {
            state.expanded[key] = (state.expanded[key] === false); // flip collapsed<->expanded
            renderTable(data);
            syncState();
          });
          hdr.appendChild(tog);
        } else {
          hdr.appendChild(el("span", "pv-toggle pv-leaf", "▾"));
        }
        hdr.appendChild(document.createTextNode(displayVal(name)));
        tr.appendChild(hdr);
        rowCells(childPath).forEach(function (td) { tr.appendChild(td); });
        tbody.appendChild(tr);

        if (!childIsLeaf && state.expanded[key] !== false) {
          renderNode(child, childPath, depth + 1);
        }
      });
    }

    if (rowFields.length === 0) {
      var trt = el("tr");
      trt.appendChild(el("td", "pv-rowhdr", "Total"));
      rowCells([]).forEach(function (td) { trt.appendChild(td); });
      tbody.appendChild(trt);
    } else {
      renderNode(m.rowTree, [], 0);
    }
    table.appendChild(tbody);

    // ----- grand total footer -----
    if (rowFields.length > 0) {
      var tfoot = el("tfoot");
      var trg = el("tr", "pv-grand");
      trg.appendChild(el("td", "pv-rowhdr pv-grand", "Grand Total"));
      outputCols.forEach(function (oc) { trg.appendChild(dataCellD(dispVal(m, [], oc.cp, oc.mo), oc.agg, oc.variation ? "pv-variation" : "")); });
      if (showGrandCol) renderCols.forEach(function (rc) { trg.appendChild(dataCellD(dispVal(m, [], [], rc.mo), rc.agg, rc.variation ? "pv-variation" : "")); });
      tfoot.appendChild(trg);
      table.appendChild(tfoot);
    }

    tableWrap.innerHTML = "";
    tableWrap.appendChild(table);
  }

  function dataCell(v, agg, extraCls) {
    var td = el("td", "pv-num-cell" + (extraCls ? " " + extraCls : ""));
    if (v == null) { td.className += " pv-empty-cell"; td.textContent = "—"; }
    else td.textContent = fmtNum(v, agg);
    return td;
  }
  function cmpVals(a, b) {
    var na = parseFloat(a), nb = parseFloat(b);
    if (!isNaN(na) && !isNaN(nb) && String(na) === a && String(nb) === b) return na - nb;
    return a < b ? -1 : a > b ? 1 : 0;
  }

  function collectFullPaths(cells, which, len) {
    var seen = {}, out = [];
    cells.forEach(function (c) {
      var p = c[which];
      if (p.length !== len) return;
      var k = keyOf(p);
      if (!seen[k]) { seen[k] = 1; out.push(p); }
    });
    out.sort(function (a, b) {
      for (var i = 0; i < a.length; i++) { var d = cmpVals(a[i], b[i]); if (d) return d; }
      return 0;
    });
    return out;
  }

  function buildTree(leaves) {
    var r = { children: {} };
    leaves.forEach(function (p) {
      var node = r;
      p.forEach(function (v) {
        if (!node.children[v]) node.children[v] = { children: {} };
        node = node.children[v];
      });
    });
    return r;
  }

  function buildColHeaderLevels(leaves, depth) {
    var levels = [];
    for (var lvl = 0; lvl < depth; lvl++) {
      var cellsAtLevel = [];
      var i = 0;
      while (i < leaves.length) {
        var prefix = leaves[i].slice(0, lvl + 1).join(" ");
        var span = 0;
        while (i + span < leaves.length && leaves[i + span].slice(0, lvl + 1).join(" ") === prefix) span++;
        cellsAtLevel.push({ label: displayVal(leaves[i][lvl]), span: span });
        i += span;
      }
      levels.push(cellsAtLevel);
    }
    return levels;
  }

  // ---- export to Excel (CSV) ---------------------------------------------
  function csvCell(s) {
    s = s == null ? "" : String(s);
    if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  }
  function numStr(v) { return v == null ? "" : String(v); }

  function exportCsv() {
    if (!lastData) return;
    var data = lastData;
    var m = matrix(data);
    var rowFields = m.rowFields, colFields = m.colFields, measures = m.measures;
    var outputCols = m.outputCols, renderCols = m.renderCols, showGrandCol = m.showGrandCol, vsAt = m.vsAt;
    var lines = [];
    // Column header text for a rendered sub-column: measure name, plus the
    // comparison tag for a variation part.
    function ocLabel(oc) { return oc.variation ? measures[oc.mi].label + " " + oc.label : oc.label; }
    function rcLabel(rc) { return rc.variation ? measures[rc.mi].label + " " + rc.label : rc.label; }

    // header row
    var head = [];
    if (rowFields.length) rowFields.forEach(function (f) { head.push(f.label); });
    else head.push("");
    outputCols.forEach(function (oc) {
      var parts = [];
      if (oc.cp.length) parts.push(oc.cp.map(displayVal).join(" / "));
      if (renderCols.length > 1 || colFields.length === 0) parts.push(ocLabel(oc));
      head.push(parts.join(" / ") || ocLabel(oc));
    });
    if (showGrandCol) renderCols.forEach(function (rc) { head.push("Grand Total" + (renderCols.length > 1 ? " / " + rcLabel(rc) : "")); });
    lines.push(head);

    function emit(path) {
      var line = [];
      if (rowFields.length) {
        for (var i = 0; i < rowFields.length; i++) line.push(i < path.length ? displayVal(path[i]) : "");
      } else line.push("Total");
      outputCols.forEach(function (oc) { line.push(numStr(dispVal(m, path, oc.cp, oc.mo).v)); });
      if (showGrandCol) renderCols.forEach(function (rc) { line.push(numStr(dispVal(m, path, [], rc.mo).v)); });
      lines.push(line);
    }
    function walk(node, path, depth) {
      Object.keys(node.children).sort(cmpVals).forEach(function (name) {
        var childPath = path.concat([name]);
        var childIsLeaf = (depth + 1) === rowFields.length;
        emit(childPath);
        if (!childIsLeaf && state.expanded[keyOf(childPath)] !== false) walk(node.children[name], childPath, depth + 1);
      });
    }
    if (rowFields.length === 0) emit([]);
    else walk(m.rowTree, [], 0);

    if (rowFields.length > 0) {
      var g = ["Grand Total"];
      for (var j = 1; j < rowFields.length; j++) g.push("");
      outputCols.forEach(function (oc) { g.push(numStr(dispVal(m, [], oc.cp, oc.mo).v)); });
      if (showGrandCol) renderCols.forEach(function (rc) { g.push(numStr(dispVal(m, [], [], rc.mo).v)); });
      lines.push(g);
    }

    var csv = lines.map(function (r) { return r.map(csvCell).join(","); }).join("\r\n");
    var blob = new Blob(["\ufeff" + csv], { type: "text/csv;charset=utf-8;" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = MODEL + "-pivot.csv";
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 0);
  }

  var exportBtn = document.getElementById("pv-export");
  if (exportBtn) exportBtn.addEventListener("click", exportCsv);

  // ---- boot --------------------------------------------------------------
  renderPane();
  updateSaveInputs();
  fetchAndRender();
})();
