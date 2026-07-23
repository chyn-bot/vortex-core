/* Report Studio — pixel-perfect banded report designer.
 *
 * Vanilla ES module served directly (no build step, CSP-safe: no inline
 * scripts). Reads bootstrap JSON from #rs-boot, edits an in-memory ReportLayout
 * that mirrors the Rust serde model exactly (camelCase band keys, element
 * "type"), and saves/previews via the typed fetch endpoints. Coordinates are
 * stored in document units (pt/mm/px); the canvas scales them to screen px.
 */
(function () {
  "use strict";

  var boot = {};
  try { boot = JSON.parse(document.getElementById("rs-boot").textContent || "{}"); } catch (e) { boot = {}; }

  // Standard bands rendered as fixed lanes, in flow order.
  var STD_BANDS = [
    ["title", "Title"],
    ["pageHeader", "Page Header"],
    ["columnHeader", "Column Header"],
    ["detail", "Detail"],
    ["columnFooter", "Column Footer"],
    ["pageFooter", "Page Footer"],
    ["summary", "Summary"],
  ];

  var GRID = 4;              // snap grid, document units
  var app = document.getElementById("rs-app");
  var runUrl = app.getAttribute("data-run-url") || "";

  var S = {
    model: normalize(boot.layout || {}),
    fields: boot.fields || [],
    name: boot.name || "Report",
    model_name: boot.model || "",
    reportId: boot.reportId || "",
    zoom: 1,
    sel: null,        // {band, key, idx}
    dirty: false,
  };

  // ── Model helpers ───────────────────────────────────────────────────────

  function normalize(m) {
    m.unit = m.unit || "pt";
    m.page = m.page || {};
    var p = m.page;
    p.size = p.size || "A4"; p.orientation = p.orientation || "portrait";
    p.width = num(p.width, 595); p.height = num(p.height, 842);
    p.margin = p.margin || {}; var mg = p.margin;
    mg.top = num(mg.top, 36); mg.right = num(mg.right, 36); mg.bottom = num(mg.bottom, 36); mg.left = num(mg.left, 36);
    p.columns = num(p.columns, 1); p.columnGap = num(p.columnGap, 0);
    m.dataset = m.dataset || { model: S ? S.model_name : "", sort: [], groups: [] };
    m.dataset.groups = m.dataset.groups || [];
    m.dataset.sort = m.dataset.sort || [];
    m.params = m.params || [];
    m.variables = m.variables || [];
    m.bands = m.bands || {};
    var b = m.bands;
    STD_BANDS.forEach(function (bd) { b[bd[0]] = ensureBand(b[bd[0]]); });
    b.groupHeaders = b.groupHeaders || {};
    b.groupFooters = b.groupFooters || {};
    Object.keys(b.groupHeaders).forEach(function (k) { b.groupHeaders[k] = ensureBand(b.groupHeaders[k]); });
    Object.keys(b.groupFooters).forEach(function (k) { b.groupFooters[k] = ensureBand(b.groupFooters[k]); });
    return m;
  }
  function ensureBand(bd) { bd = bd || {}; bd.height = num(bd.height, 0); bd.elements = bd.elements || []; return bd; }
  function num(v, d) { v = parseFloat(v); return isNaN(v) ? d : v; }

  function bandList() {
    // [ {key, label, band} ] including group bands interleaved sensibly.
    var out = [];
    var b = S.model.bands;
    out.push({ key: "title", label: "Title", band: b.title });
    out.push({ key: "pageHeader", label: "Page Header", band: b.pageHeader });
    out.push({ key: "columnHeader", label: "Column Header", band: b.columnHeader });
    (S.model.dataset.groups || []).forEach(function (g, i) {
      if (g.header && b.groupHeaders[g.header]) out.push({ key: "gh:" + g.header, label: "Group Header · " + g.header, band: b.groupHeaders[g.header] });
    });
    out.push({ key: "detail", label: "Detail", band: b.detail });
    (S.model.dataset.groups || []).slice().reverse().forEach(function (g) {
      if (g.footer && b.groupFooters[g.footer]) out.push({ key: "gf:" + g.footer, label: "Group Footer · " + g.footer, band: b.groupFooters[g.footer] });
    });
    out.push({ key: "columnFooter", label: "Column Footer", band: b.columnFooter });
    out.push({ key: "pageFooter", label: "Page Footer", band: b.pageFooter });
    out.push({ key: "summary", label: "Summary", band: b.summary });
    return out;
  }
  function bandByKey(key) {
    var b = S.model.bands;
    if (key.indexOf("gh:") === 0) return b.groupHeaders[key.slice(3)];
    if (key.indexOf("gf:") === 0) return b.groupFooters[key.slice(3)];
    return b[key];
  }

  // Unit → px conversion (at zoom 1).
  function pxPerUnit() {
    var u = S.model.unit;
    if (u === "mm") return 96 / 25.4;
    if (u === "px") return 1;
    return 96 / 72; // pt
  }
  function u2px(v) { return v * pxPerUnit() * S.zoom; }
  function px2u(v) { return v / (pxPerUnit() * S.zoom); }
  function snap(v) { return Math.round(v / GRID) * GRID; }

  // ── Render ──────────────────────────────────────────────────────────────

  function render() {
    app.innerHTML = "";
    app.appendChild(renderToolbar());
    app.appendChild(renderPalette());
    app.appendChild(renderCanvas());
    app.appendChild(renderInspector());
    ensurePreviewOverlay();
  }

  function el(tag, cls, txt) { var e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; }
  function btn(label, cls, on) { var b = el("button", cls, label); b.addEventListener("click", on); return b; }

  function exitDesigner() {
    if (S.dirty && !confirm("You have unsaved changes. Leave the designer?")) return;
    S.dirty = false; // skip the beforeunload prompt on intentional exit
    window.location.href = "/settings/reports";
  }

  function renderToolbar() {
    var t = el("div", "rs-toolbar");
    t.appendChild(btn("← Exit", "", exitDesigner));
    t.appendChild(el("span", "rs-title", "📐 " + S.name));

    t.appendChild(btn("💾 Save", "rs-primary", save));
    t.appendChild(btn("👁 Preview", "", preview));
    var pdf = btn("⬇ PDF", "", function () { window.open(runUrl + "?format=pdf", "_blank"); });
    t.appendChild(pdf);
    t.appendChild(el("span", "rs-sep"));

    // Page setup
    var sizeSel = el("select");
    [["A4", "A4"], ["Letter", "Letter"], ["Legal", "Legal"], ["custom", "Custom"]].forEach(function (o) {
      var op = el("option", null, o[1]); op.value = o[0]; if (S.model.page.size === o[0]) op.selected = true; sizeSel.appendChild(op);
    });
    sizeSel.addEventListener("change", function () { setPageSize(sizeSel.value); });
    t.appendChild(sizeSel);

    var orient = el("select");
    [["portrait", "Portrait"], ["landscape", "Landscape"]].forEach(function (o) {
      var op = el("option", null, o[1]); op.value = o[0]; if (S.model.page.orientation === o[0]) op.selected = true; orient.appendChild(op);
    });
    orient.addEventListener("change", function () { setOrientation(orient.value); });
    t.appendChild(orient);

    var unit = el("select");
    [["pt", "pt"], ["mm", "mm"], ["px", "px"]].forEach(function (o) {
      var op = el("option", null, o[1]); op.value = o[0]; if (S.model.unit === o[0]) op.selected = true; unit.appendChild(op);
    });
    unit.addEventListener("change", function () { S.model.unit = unit.value; markDirty(); render(); });
    t.appendChild(unit);

    t.appendChild(el("span", "rs-sep"));
    t.appendChild(btn("−", "", function () { S.zoom = Math.max(0.4, S.zoom - 0.15); render(); }));
    t.appendChild(el("span", "rs-status", Math.round(S.zoom * 100) + "%"));
    t.appendChild(btn("+", "", function () { S.zoom = Math.min(2.5, S.zoom + 0.15); render(); }));

    t.appendChild(el("span", "rs-sep"));
    t.appendChild(btn("＋ Group", "", addGroup));
    t.appendChild(btn("📋 Template", "", scaffoldPrompt));
    t.appendChild(btn("⬆ Import", "", importPrompt));
    t.appendChild(btn("⬇ Export", "", function () { window.open("/reports/design/" + S.reportId + "/export", "_blank"); }));
    t.appendChild(el("span", "rs-sep"));
    var status = el("span", "rs-status", S.dirty ? "● unsaved" : "saved");
    status.id = "rs-dirty";
    t.appendChild(status);
    return t;
  }

  var ELEMENT_TOOLS = [
    ["staticText", "🔤 Static text"],
    ["field", "🔗 Data field"],
    ["box", "▭ Box"],
    ["line", "／ Line"],
    ["image", "🖼 Image"],
    ["barcode", "▦ Barcode / QR"],
    ["subreport", "📄 Subreport"],
  ];

  function renderPalette() {
    var p = el("div", "rs-palette");
    p.appendChild(el("h4", null, "Elements"));
    ELEMENT_TOOLS.forEach(function (tool) {
      var d = el("div", "rs-tool", tool[1]);
      d.setAttribute("draggable", "true");
      d.addEventListener("dragstart", function (ev) { ev.dataTransfer.setData("text/rs-tool", tool[0]); });
      p.appendChild(d);
    });
    p.appendChild(el("h4", null, "Fields — " + (S.model_name || "no model")));
    if (!S.fields.length) p.appendChild(el("div", "rs-empty", "No fields"));
    S.fields.forEach(function (f) {
      var d = el("div", "rs-tool rs-field");
      d.appendChild(document.createTextNode(f.label || f.name));
      var ft = el("span", "rs-ft", f.type || ""); d.appendChild(ft);
      d.setAttribute("draggable", "true");
      d.addEventListener("dragstart", function (ev) {
        ev.dataTransfer.setData("text/rs-field", f.name);
      });
      p.appendChild(d);
    });
    return p;
  }

  function renderCanvas() {
    var wrap = el("div", "rs-canvas-wrap");
    var page = el("div", "rs-page");
    var pw = u2px(S.model.page.width);
    page.style.width = pw + "px";

    // Left/right margin guides.
    var mL = el("div", "rs-margin"); mL.style.left = "0"; mL.style.width = u2px(S.model.page.margin.left) + "px"; page.appendChild(mL);
    var mR = el("div", "rs-margin"); mR.style.right = "0"; mR.style.width = u2px(S.model.page.margin.right) + "px"; page.appendChild(mR);

    var contentLeft = u2px(S.model.page.margin.left);
    var contentW = u2px(S.model.page.width - S.model.page.margin.left - S.model.page.margin.right);

    bandList().forEach(function (bl) {
      var lane = el("div", "rs-band");
      var h = Math.max(bandEffectiveH(bl.band), 6);
      lane.style.height = u2px(h) + "px";
      lane.setAttribute("data-band", bl.key);
      lane.appendChild(el("div", "rs-band-label", bl.label));

      // Content area within margins where elements live.
      var area = el("div");
      area.style.position = "absolute"; area.style.top = "0"; area.style.bottom = "0";
      area.style.left = contentLeft + "px"; area.style.width = contentW + "px";
      lane.appendChild(area);

      (bl.band.elements || []).forEach(function (elm, idx) { area.appendChild(renderEl(bl.key, elm, idx)); });

      // Drop target for palette items.
      lane.addEventListener("dragover", function (ev) { ev.preventDefault(); lane.classList.add("rs-dragover"); });
      lane.addEventListener("dragleave", function () { lane.classList.remove("rs-dragover"); });
      lane.addEventListener("drop", function (ev) {
        ev.preventDefault(); lane.classList.remove("rs-dragover");
        var rect = area.getBoundingClientRect();
        var x = snap(px2u(ev.clientX - rect.left));
        var y = snap(px2u(ev.clientY - rect.top));
        var tool = ev.dataTransfer.getData("text/rs-tool");
        var fld = ev.dataTransfer.getData("text/rs-field");
        if (fld) addElement(bl.key, "field", x, y, { expr: "$F{" + fld + "}", text: null });
        else if (tool) addElement(bl.key, tool, x, y, {});
      });

      // Band height resize grip.
      var grip = el("div", "rs-band-resize");
      attachBandResize(grip, bl.band);
      lane.appendChild(grip);

      // Click empty lane clears selection.
      lane.addEventListener("mousedown", function (ev) { if (ev.target === lane || ev.target === area) select(null); });

      page.appendChild(lane);
    });

    wrap.appendChild(page);
    return wrap;
  }

  function bandEffectiveH(band) {
    var ext = 0; (band.elements || []).forEach(function (e) { ext = Math.max(ext, num(e.y, 0) + num(e.h, 0)); });
    return Math.max(num(band.height, 0), ext);
  }

  function renderEl(bandKey, elm, idx) {
    var d = el("div", "rs-el");
    if (S.sel && S.sel.band === bandKey && S.sel.idx === idx) d.classList.add("sel");
    d.style.left = u2px(num(elm.x, 0)) + "px";
    d.style.top = u2px(num(elm.y, 0)) + "px";
    d.style.width = u2px(num(elm.w, 40)) + "px";
    d.style.height = u2px(num(elm.h, 14)) + "px";
    var st = elm.style || {};
    d.style.color = st.color || "#111";
    if (st.bg) d.style.background = st.bg;
    d.style.fontSize = Math.max(8, (num(st.size, 10)) * (96 / 72) * S.zoom) + "px";
    d.style.fontWeight = st.bold ? "700" : "400";
    d.style.fontStyle = st.italic ? "italic" : "normal";
    d.style.justifyContent = st.align === "center" ? "center" : st.align === "right" ? "flex-end" : "flex-start";
    if (elm.type === "box") d.style.border = "1px solid " + ((st.border && st.border.color) || "#999");
    if (elm.type === "line") { d.style.borderTop = "1px solid " + ((st.border && st.border.color) || "#333"); d.style.height = "1px"; }

    var lbl = el("span", "rs-elbl", elLabel(elm));
    d.appendChild(lbl);

    var handle = el("div", "rs-handle");
    d.appendChild(handle);

    attachElInteractions(d, handle, bandKey, idx);
    return d;
  }

  function elLabel(elm) {
    if (elm.type === "staticText") return elm.text || "(text)";
    if (elm.type === "field") return elm.expr || "(field)";
    if (elm.type === "barcode") return "▦ " + (elm.expr || "");
    if (elm.type === "image") return "🖼 image";
    if (elm.type === "subreport") return "📄 " + ((elm.subreport && elm.subreport.code) || "subreport");
    if (elm.type === "box") return "";
    if (elm.type === "line") return "";
    return elm.type;
  }

  // ── Interactions ────────────────────────────────────────────────────────

  function attachElInteractions(node, handle, bandKey, idx) {
    node.addEventListener("mousedown", function (ev) {
      if (ev.target === handle) return;
      ev.preventDefault();
      select({ band: bandKey, idx: idx });
      var band = bandByKey(bandKey); var elm = band.elements[idx];
      var startX = ev.clientX, startY = ev.clientY, ox = num(elm.x, 0), oy = num(elm.y, 0);
      function mv(e) {
        elm.x = Math.max(0, snap(ox + px2u(e.clientX - startX)));
        elm.y = Math.max(0, snap(oy + px2u(e.clientY - startY)));
        node.style.left = u2px(elm.x) + "px"; node.style.top = u2px(elm.y) + "px";
        syncInspectorPos(elm);
      }
      function up() { document.removeEventListener("mousemove", mv); document.removeEventListener("mouseup", up); markDirty(); }
      document.addEventListener("mousemove", mv); document.addEventListener("mouseup", up);
    });

    handle.addEventListener("mousedown", function (ev) {
      ev.preventDefault(); ev.stopPropagation();
      select({ band: bandKey, idx: idx });
      var band = bandByKey(bandKey); var elm = band.elements[idx];
      var startX = ev.clientX, startY = ev.clientY, ow = num(elm.w, 40), oh = num(elm.h, 14);
      function mv(e) {
        elm.w = Math.max(GRID, snap(ow + px2u(e.clientX - startX)));
        elm.h = Math.max(GRID, snap(oh + px2u(e.clientY - startY)));
        node.style.width = u2px(elm.w) + "px"; node.style.height = u2px(elm.h) + "px";
        syncInspectorPos(elm);
      }
      function up() { document.removeEventListener("mousemove", mv); document.removeEventListener("mouseup", up); markDirty(); }
      document.addEventListener("mousemove", mv); document.addEventListener("mouseup", up);
    });
  }

  function attachBandResize(grip, band) {
    grip.addEventListener("mousedown", function (ev) {
      ev.preventDefault();
      var startY = ev.clientY, oh = num(band.height, 0);
      function mv(e) { band.height = Math.max(0, snap(oh + px2u(e.clientY - startY))); renderCanvasOnly(); }
      function up() { document.removeEventListener("mousemove", mv); document.removeEventListener("mouseup", up); markDirty(); render(); }
      document.addEventListener("mousemove", mv); document.addEventListener("mouseup", up);
    });
  }

  function renderCanvasOnly() {
    var old = app.querySelector(".rs-canvas-wrap");
    if (old) { var fresh = renderCanvas(); old.replaceWith(fresh); }
  }

  // ── Element CRUD ────────────────────────────────────────────────────────

  function addElement(bandKey, type, x, y, extra) {
    var band = bandByKey(bandKey);
    var id = type + "_" + Math.floor(performance.now()).toString(36) + "_" + band.elements.length;
    var e = {
      id: id, type: type, x: x || 0, y: y || 0,
      w: type === "line" ? 120 : (type === "barcode" ? 60 : 120),
      h: type === "line" ? 2 : (type === "barcode" ? 60 : 16),
      expr: extra.expr != null ? extra.expr : (type === "field" || type === "barcode" ? "$F{}" : null),
      text: type === "staticText" ? (extra.text != null ? extra.text : "Text") : null,
      style: { size: 10, align: "left", color: "#111111" },
    };
    if (type === "barcode") e.barcode = { symbology: "qr" };
    if (type === "subreport") e.subreport = { code: "", paramMap: {} };
    band.elements.push(e);
    markDirty();
    select({ band: bandKey, idx: band.elements.length - 1 });
    render();
  }

  function deleteSelected() {
    if (!S.sel) return;
    var band = bandByKey(S.sel.band);
    band.elements.splice(S.sel.idx, 1);
    S.sel = null; markDirty(); render();
  }

  function select(sel) { S.sel = sel; render(); }

  // ── Inspector ───────────────────────────────────────────────────────────

  function renderInspector() {
    var ins = el("div", "rs-inspector");
    if (!S.sel) {
      ins.appendChild(el("h4", null, "Page & dataset"));
      pageInspector(ins);
      return ins;
    }
    var band = bandByKey(S.sel.band); var elm = band.elements[S.sel.idx];
    if (!elm) { S.sel = null; return renderInspector(); }
    ins.appendChild(el("h4", null, elm.type + " element"));

    var st = elm.style = elm.style || {};

    if (elm.type === "staticText") row(ins, "Text", inputBind(elm, "text", "text"));
    if (elm.type === "field" || elm.type === "barcode" || elm.type === "image")
      row(ins, "Expr", areaBind(elm, "expr"));
    if (elm.type === "barcode") {
      elm.barcode = elm.barcode || { symbology: "qr" };
      row(ins, "Symbol", selectBind(elm.barcode, "symbology", [["qr", "QR"], ["code128", "Code128"], ["ean13", "EAN-13"]]));
    }
    if (elm.type === "subreport") {
      elm.subreport = elm.subreport || { code: "", paramMap: {} };
      row(ins, "Code", inputBind(elm.subreport, "code", "text"));
    }

    ins.appendChild(el("h4", null, "Position (" + S.model.unit + ")"));
    var g = el("div", "rs-grid4");
    ["x", "y", "w", "h"].forEach(function (k) { g.appendChild(numInput(elm, k)); });
    ins.appendChild(g);

    if (elm.type !== "line" && elm.type !== "box" && elm.type !== "image" && elm.type !== "subreport") {
      ins.appendChild(el("h4", null, "Text style"));
      row(ins, "Font size", numInput(st, "size"));
      row(ins, "Align", selectBind(st, "align", [["left", "Left"], ["center", "Center"], ["right", "Right"], ["justify", "Justify"]]));
      row(ins, "V-align", selectBind(st, "valign", [["top", "Top"], ["middle", "Middle"], ["bottom", "Bottom"]]));
      row(ins, "Color", inputBind(st, "color", "color"));
      row(ins, "Format", inputBind(st, "format", "text"));
      var flags = el("div", "rs-row");
      flags.appendChild(checkBind(st, "bold", "B"));
      flags.appendChild(checkBind(st, "italic", "I"));
      flags.appendChild(checkBind(st, "underline", "U"));
      flags.appendChild(checkBind(st, "wrap", "Wrap"));
      ins.appendChild(flags);
    }
    if (elm.type === "box" || elm.type === "line") {
      st.border = st.border || {};
      ins.appendChild(el("h4", null, "Border"));
      row(ins, "Color", inputBind(st.border, "color", "color"));
      if (elm.type === "box") row(ins, "Fill", inputBind(st, "bg", "color"));
    }

    ins.appendChild(el("h4", null, "Visibility"));
    row(ins, "printWhen", areaBind(elm, "printWhen"));

    var del = el("button", "rs-del", "🗑 Delete element");
    del.addEventListener("click", deleteSelected);
    ins.appendChild(del);
    return ins;
  }

  function pageInspector(ins) {
    var p = S.model.page;
    row(ins, "Width", numInput(p, "width"));
    row(ins, "Height", numInput(p, "height"));
    ins.appendChild(el("h4", null, "Margins"));
    var g = el("div", "rs-grid4");
    ["top", "right", "bottom", "left"].forEach(function (k) { g.appendChild(numInput(p.margin, k)); });
    ins.appendChild(g);
    ins.appendChild(el("h4", null, "Columns"));
    row(ins, "Count", numInput(p, "columns"));
    row(ins, "Gap", numInput(p, "columnGap"));

    ins.appendChild(el("h4", null, "Groups"));
    (S.model.dataset.groups || []).forEach(function (grp, i) {
      row(ins, "Expr " + (i + 1), inputBind(grp, "expr", "text"));
    });
    ins.appendChild(el("h4", null, "Variables"));
    (S.model.variables || []).forEach(function (v, i) {
      var r = el("div", "rs-row");
      r.appendChild(el("label", null, v.name || ("V" + i)));
      r.appendChild(document.createTextNode((v.calc || "sum") + " " + (v.expr || "")));
      ins.appendChild(r);
    });
    var addv = el("button", "rs-del", "＋ Add SUM variable");
    addv.style.background = "#dbeafe"; addv.style.color = "#1e40af"; addv.style.borderColor = "#bfdbfe";
    addv.addEventListener("click", addVariable);
    ins.appendChild(addv);
  }

  function row(parent, label, control) { var r = el("div", "rs-row"); r.appendChild(el("label", null, label)); r.appendChild(control); parent.appendChild(r); }

  function inputBind(obj, key, type) {
    var i = document.createElement("input"); i.type = type || "text"; i.value = obj[key] != null ? obj[key] : "";
    i.addEventListener("input", function () { obj[key] = i.value; markDirty(); refreshCanvas(); });
    return i;
  }
  function areaBind(obj, key) {
    var t = document.createElement("textarea"); t.value = obj[key] != null ? obj[key] : "";
    t.addEventListener("input", function () { obj[key] = t.value || null; markDirty(); refreshCanvas(); });
    return t;
  }
  function numInput(obj, key) {
    var i = document.createElement("input"); i.type = "number"; i.step = "1"; i.value = num(obj[key], 0);
    i.title = key;
    i.addEventListener("input", function () { obj[key] = num(i.value, 0); markDirty(); refreshCanvas(); });
    i.dataset.pos = key;
    return i;
  }
  function selectBind(obj, key, opts) {
    var s = document.createElement("select");
    opts.forEach(function (o) { var op = el("option", null, o[1]); op.value = o[0]; if (obj[key] === o[0]) op.selected = true; s.appendChild(op); });
    s.addEventListener("change", function () { obj[key] = s.value; markDirty(); refreshCanvas(); });
    return s;
  }
  function checkBind(obj, key, label) {
    var wrap = el("label"); wrap.style.flex = "1"; wrap.style.display = "flex"; wrap.style.alignItems = "center"; wrap.style.gap = "3px";
    var c = document.createElement("input"); c.type = "checkbox"; c.checked = !!obj[key];
    c.addEventListener("change", function () { obj[key] = c.checked; markDirty(); refreshCanvas(); });
    wrap.appendChild(c); wrap.appendChild(document.createTextNode(label));
    return wrap;
  }

  function syncInspectorPos(elm) {
    var ins = app.querySelector(".rs-inspector");
    if (!ins) return;
    ["x", "y", "w", "h"].forEach(function (k) {
      var i = ins.querySelector('input[data-pos="' + k + '"]');
      if (i) i.value = num(elm[k], 0);
    });
  }
  function refreshCanvas() { renderCanvasOnly(); }

  // ── Page setup ──────────────────────────────────────────────────────────

  var PAPERS = { A4: [595, 842], Letter: [612, 792], Legal: [612, 1008] };
  function setPageSize(size) {
    S.model.page.size = size;
    if (PAPERS[size]) {
      var d = PAPERS[size];
      // Store in pt then convert to current unit.
      var toU = ptToUnit();
      var w = d[0] * toU, h = d[1] * toU;
      if (S.model.page.orientation === "landscape") { S.model.page.width = h; S.model.page.height = w; }
      else { S.model.page.width = w; S.model.page.height = h; }
    }
    markDirty(); render();
  }
  function setOrientation(o) {
    if (o === S.model.page.orientation) return;
    S.model.page.orientation = o;
    var w = S.model.page.width, h = S.model.page.height;
    S.model.page.width = h; S.model.page.height = w;
    markDirty(); render();
  }
  function ptToUnit() { var u = S.model.unit; if (u === "mm") return 25.4 / 72; if (u === "px") return 96 / 72; return 1; }

  function addGroup() {
    var expr = prompt("Group by expression (e.g. $F{partner}):", "$F{}");
    if (!expr) return;
    var n = (S.model.dataset.groups.length + 1);
    var hk = "g" + n + "h", fk = "g" + n + "f";
    S.model.dataset.groups.push({ expr: expr, header: hk, footer: fk, reprint: true });
    S.model.bands.groupHeaders[hk] = { height: 18, elements: [] };
    S.model.bands.groupFooters[fk] = { height: 18, elements: [] };
    markDirty(); render();
  }

  function addVariable() {
    var name = prompt("Variable name (referenced as $V{name}):", "total");
    if (!name) return;
    var expr = prompt("Sum expression (e.g. $F{amount}):", "$F{amount}");
    if (!expr) return;
    var reset = prompt("Reset scope (report | page | group):", "report") || "report";
    S.model.variables.push({ name: name, calc: "sum", expr: expr, reset: reset });
    markDirty(); render();
  }

  // ── Persistence ─────────────────────────────────────────────────────────

  function markDirty() { S.dirty = true; var d = document.getElementById("rs-dirty"); if (d) { d.textContent = "● unsaved"; } }
  function markClean() { S.dirty = false; var d = document.getElementById("rs-dirty"); if (d) { d.textContent = "saved"; } }

  function save() {
    fetch("/reports/design/" + S.reportId + "/save", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(S.model),
    }).then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        if (res.ok && res.j.ok) { markClean(); toast("Saved"); }
        else if (res.j.issues) toast("Invalid: " + res.j.issues.join("; "), true);
        else toast("Save failed: " + (res.j.error || "error"), true);
      }).catch(function (e) { toast("Save failed: " + e, true); });
  }

  function preview() {
    var ov = ensurePreviewOverlay();
    var frame = ov.querySelector("iframe");
    frame.srcdoc = '<p style="font:14px sans-serif;padding:20px;color:#555">Rendering preview…</p>';
    ov.classList.add("show");
    fetch("/reports/design/" + S.reportId + "/preview", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "text/html" },
      body: JSON.stringify(S.model),
    }).then(function (r) { return r.text(); })
      .then(function (html) { frame.srcdoc = html; })
      .catch(function (e) { frame.srcdoc = "<pre>" + String(e) + "</pre>"; });
  }

  function scaffoldPrompt() {
    var tmpl = prompt("Start from a template: invoice, statement, or labels", "invoice");
    if (!tmpl) return;
    if (S.dirty && !confirm("This replaces the current layout. Continue?")) return;
    fetch("/reports/design/" + S.reportId + "/scaffold", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ template: tmpl }),
    }).then(function (r) { return r.json(); })
      .then(function (j) { if (j.ok) { toast("Template applied — reloading"); setTimeout(function () { location.reload(); }, 500); } else toast("Failed: " + (j.error || "error"), true); })
      .catch(function (e) { toast("Failed: " + e, true); });
  }

  function importPrompt() {
    var inp = document.createElement("input"); inp.type = "file"; inp.accept = ".json,application/json";
    inp.addEventListener("change", function () {
      var f = inp.files && inp.files[0]; if (!f) return;
      var rd = new FileReader();
      rd.onload = function () {
        var payload; try { payload = JSON.parse(rd.result); } catch (e) { toast("Not valid JSON", true); return; }
        fetch("/reports/design/" + S.reportId + "/import", {
          method: "POST", credentials: "same-origin",
          headers: { "Content-Type": "application/json", "Accept": "application/json" },
          body: JSON.stringify(payload),
        }).then(function (r) { return r.json(); })
          .then(function (j) { if (j.ok) { toast("Imported — reloading"); setTimeout(function () { location.reload(); }, 500); } else toast("Import failed: " + (j.error || "error"), true); })
          .catch(function (e) { toast("Import failed: " + e, true); });
      };
      rd.readAsText(f);
    });
    inp.click();
  }

  function ensurePreviewOverlay() {
    var ov = document.getElementById("rs-preview");
    if (ov) return ov;
    ov = el("div", "rs-preview"); ov.id = "rs-preview";
    var bar = el("div", "rs-preview-bar");
    bar.appendChild(el("span", "rs-title", "Preview — live data"));
    bar.appendChild(btn("⬇ PDF", "", function () { window.open(runUrl + "?format=pdf", "_blank"); }));
    bar.appendChild(btn("✕ Close", "", function () { ov.classList.remove("show"); }));
    ov.appendChild(bar);
    var frame = document.createElement("iframe"); ov.appendChild(frame);
    document.body.appendChild(ov);
    return ov;
  }

  function toast(msg, err) {
    var t = el("div", "rs-toast" + (err ? " err" : ""), msg);
    document.body.appendChild(t);
    requestAnimationFrame(function () { t.classList.add("show"); });
    setTimeout(function () { t.classList.remove("show"); setTimeout(function () { t.remove(); }, 250); }, err ? 4000 : 1600);
  }

  // Keyboard: delete selected, arrow-nudge, ctrl+s save.
  document.addEventListener("keydown", function (ev) {
    if (ev.key === "s" && (ev.ctrlKey || ev.metaKey)) { ev.preventDefault(); save(); return; }
    if (!S.sel) return;
    var tag = (ev.target && ev.target.tagName) || "";
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
    var band = bandByKey(S.sel.band); var elm = band.elements[S.sel.idx]; if (!elm) return;
    if (ev.key === "Delete" || ev.key === "Backspace") { ev.preventDefault(); deleteSelected(); return; }
    var step = ev.shiftKey ? GRID * 3 : GRID;
    if (ev.key === "ArrowLeft") { elm.x = Math.max(0, elm.x - step); }
    else if (ev.key === "ArrowRight") { elm.x = elm.x + step; }
    else if (ev.key === "ArrowUp") { elm.y = Math.max(0, elm.y - step); }
    else if (ev.key === "ArrowDown") { elm.y = elm.y + step; }
    else return;
    ev.preventDefault(); markDirty(); refreshCanvas();
  });

  window.addEventListener("beforeunload", function (e) { if (S.dirty) { e.preventDefault(); e.returnValue = ""; } });

  render();
})();
