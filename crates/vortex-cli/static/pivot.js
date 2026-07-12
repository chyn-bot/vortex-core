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

  var state = {
    rows: (initial.rows || []).filter(function (n) { return FIELD_BY[n]; }),
    cols: (initial.cols || []).filter(function (n) { return FIELD_BY[n]; }),
    values: parseVals(initial),            // [{field, agg}]; field "" == count of records
    filters: parseFilters(initial.filters),// [{field, value}]
    expanded: parseCollapsed(initial.collapsed), // key -> false means collapsed
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
    box.querySelectorAll(".pv-chip, .pv-zone-empty").forEach(function (n) { n.remove(); });
    var arr = state[zone];
    if (!arr.length) {
      box.appendChild(el("div", "pv-zone-empty", "Drop fields here"));
      return;
    }
    arr.forEach(function (name, idx) {
      var chip = el("div", "pv-chip");
      chip.draggable = true;
      chip.appendChild(el("span", "pv-label", labelOf(name)));
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
  }

  function renderZoneValues() {
    var box = zoneEls.values;
    box.querySelectorAll(".pv-chip, .pv-zone-empty").forEach(function (n) { n.remove(); });
    if (!state.values.length) {
      var d = el("div", "pv-chip pv-chip-default");
      d.appendChild(el("span", "pv-label", "Count of records"));
      box.appendChild(d);
      return;
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
  function valsParam() {
    return state.values.map(function (v) { return v.agg + "." + (v.field || "id"); }).join(",");
  }
  function filtersParam() {
    return activeFilters().map(function (f) { return f.field + "." + b64e(f.value); }).join(",");
  }
  function queryString() {
    var p = new URLSearchParams();
    if (state.rows.length) p.set("rows", state.rows.join(","));
    if (state.cols.length) p.set("cols", state.cols.join(","));
    if (state.values.length) p.set("vals", valsParam());
    var fp = filtersParam();
    if (fp) p.set("filters", fp);
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
      rows: state.rows.join(","),
      cols: state.cols.join(","),
      vals: valsParam(),
      filters: filtersParam(),
      collapsed: collapsedKeys().map(b64e).join(","),
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

  // ---- matrix rendering --------------------------------------------------
  // Shared shape used by both the table renderer and the CSV exporter.
  function matrix(data) {
    var rowFields = data.rowFields || [];
    var colFields = data.colFields || [];
    var measures = (data.measures && data.measures.length) ? data.measures : [{ agg: "count", field: "id", label: "Count" }];
    var M = measures.length;
    var cells = {};
    data.cells.forEach(function (c) { cells[cellKey(c.r, c.c)] = c.vs; });
    var colLeaves = collectFullPaths(data.cells, "c", colFields.length);
    var rowTree = buildTree(collectFullPaths(data.cells, "r", rowFields.length));
    var leafColPaths = colFields.length === 0 ? [[]] : colLeaves;
    var outputCols = [];
    leafColPaths.forEach(function (cp) { measures.forEach(function (m, mi) { outputCols.push({ cp: cp, mi: mi }); }); });
    function vsAt(r, c) { return cells[cellKey(r, c)] || null; }
    return {
      rowFields: rowFields, colFields: colFields, measures: measures, M: M,
      colLeaves: colLeaves, rowTree: rowTree, outputCols: outputCols,
      showGrandCol: colFields.length > 0, showMeasureLevel: M > 1, vsAt: vsAt,
    };
  }

  function renderTable(data) {
    lastData = data;
    var m = matrix(data);
    var rowFields = m.rowFields, colFields = m.colFields, measures = m.measures, M = m.M;
    var outputCols = m.outputCols, colLeaves = m.colLeaves;
    var showGrandCol = m.showGrandCol, showMeasureLevel = m.showMeasureLevel;
    var vsAt = m.vsAt;

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
      measures.forEach(function (mm) { tr0.appendChild(el("th", null, mm.label)); });
      thead.appendChild(tr0);
    } else {
      var levels = buildColHeaderLevels(colLeaves, baseLevels);
      levels.forEach(function (cellsAtLevel, li) {
        var tr = el("tr");
        if (li === 0) tr.appendChild(corner);
        cellsAtLevel.forEach(function (h) {
          var th = el("th", null, h.label);
          th.colSpan = h.span * M;
          tr.appendChild(th);
        });
        if (li === 0) {
          var gt = el("th", null, "Grand Total");
          if (showMeasureLevel) { gt.colSpan = M; gt.rowSpan = baseLevels; }
          else { gt.rowSpan = headerRows; }
          tr.appendChild(gt);
        }
        thead.appendChild(tr);
      });
      if (showMeasureLevel) {
        var trm = el("tr");
        colLeaves.forEach(function () { measures.forEach(function (mm) { trm.appendChild(el("th", "pv-mhdr", mm.label)); }); });
        measures.forEach(function (mm) { trm.appendChild(el("th", "pv-mhdr", mm.label)); }); // under grand total
        thead.appendChild(trm);
      }
    }
    table.appendChild(thead);

    // ----- body -----
    var tbody = el("tbody");
    function rowCells(path) {
      var frag = [];
      outputCols.forEach(function (oc) { var vs = vsAt(path, oc.cp); frag.push(dataCell(vs ? vs[oc.mi] : null, measures[oc.mi].agg)); });
      if (showGrandCol) measures.forEach(function (mm, mi) { var vs = vsAt(path, []); frag.push(dataCell(vs ? vs[mi] : null, mm.agg, "pv-subtotal")); });
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
      outputCols.forEach(function (oc) { var vs = vsAt([], oc.cp); trg.appendChild(dataCell(vs ? vs[oc.mi] : null, measures[oc.mi].agg)); });
      if (showGrandCol) measures.forEach(function (mm, mi) { var vs = vsAt([], []); trg.appendChild(dataCell(vs ? vs[mi] : null, mm.agg)); });
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
    var outputCols = m.outputCols, showGrandCol = m.showGrandCol, vsAt = m.vsAt;
    var lines = [];

    // header row
    var head = [];
    if (rowFields.length) rowFields.forEach(function (f) { head.push(f.label); });
    else head.push("");
    outputCols.forEach(function (oc) {
      var parts = [];
      if (oc.cp.length) parts.push(oc.cp.map(displayVal).join(" / "));
      if (measures.length > 1 || colFields.length === 0) parts.push(measures[oc.mi].label);
      head.push(parts.join(" / ") || measures[oc.mi].label);
    });
    if (showGrandCol) measures.forEach(function (mm) { head.push("Grand Total" + (measures.length > 1 ? " / " + mm.label : "")); });
    lines.push(head);

    function emit(path) {
      var line = [];
      if (rowFields.length) {
        for (var i = 0; i < rowFields.length; i++) line.push(i < path.length ? displayVal(path[i]) : "");
      } else line.push("Total");
      outputCols.forEach(function (oc) { var vs = vsAt(path, oc.cp); line.push(numStr(vs ? vs[oc.mi] : null)); });
      if (showGrandCol) measures.forEach(function (mm, mi) { var vs = vsAt(path, []); line.push(numStr(vs ? vs[mi] : null)); });
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
      outputCols.forEach(function (oc) { var vs = vsAt([], oc.cp); g.push(numStr(vs ? vs[oc.mi] : null)); });
      if (showGrandCol) measures.forEach(function (mm, mi) { var vs = vsAt([], []); g.push(numStr(vs ? vs[mi] : null)); });
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
