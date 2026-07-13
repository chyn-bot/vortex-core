/* Configurable kanban board. The board (columns/cards/totals) is rendered
 * server-side; this script adds the interactivity:
 *   - a config bar (Group by / Card fields / column Total / Drag toggle) that
 *     reloads the page with query params, saveable like the other views;
 *   - drag a card to another column to change its stage — POSTs to
 *     /kanban/{model}/move, which routes the write through the audited,
 *     registry-validated update path. Optimistic move with revert-on-error.
 * No build step, no dependencies. */
(function () {
  "use strict";
  var root = document.getElementById("kanban-root");
  if (!root) return;

  var MODEL = root.dataset.model;
  var GROUP = root.dataset.group || "";
  var DRAG = root.dataset.drag === "1";
  var FIELDS = JSON.parse(root.dataset.fields || "[]"); // [{name,label,numeric,groupable}]
  var FIELD_BY = {}; FIELDS.forEach(function (f) { FIELD_BY[f.name] = f; });
  var cfg = {}; try { cfg = JSON.parse(root.dataset.config || "{}"); } catch (e) {}
  var cardsSel = (cfg.cards || "").split(",").filter(Boolean);
  var agg = cfg.agg || "sum";

  function el(tag, cls, txt) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (txt != null) e.textContent = txt;
    return e;
  }

  // ---- config bar --------------------------------------------------------
  function nav() {
    var p = new URLSearchParams();
    if (groupSel.value) p.set("group_by", groupSel.value);
    if (cardsSel.length) p.set("cards", cardsSel.join(","));
    if (measureSel.value) { p.set("measure", measureSel.value); p.set("agg", aggSel.value); }
    p.set("drag", dragChk.checked ? "1" : "0");
    location.search = p.toString();
  }

  var bar = document.getElementById("kb-config");
  var groupSel, measureSel, aggSel, dragChk;

  function labeled(text, node) {
    var w = el("label", "kb-ctl");
    w.appendChild(el("span", "kb-ctl-k", text));
    w.appendChild(node);
    return w;
  }
  function buildBar() {
    if (!bar) return;
    bar.innerHTML = "";

    // Group by
    groupSel = el("select");
    FIELDS.filter(function (f) { return f.groupable; }).forEach(function (f) {
      var o = el("option", null, f.label); o.value = f.name;
      if (f.name === (cfg.group_by || GROUP)) o.selected = true;
      groupSel.appendChild(o);
    });
    groupSel.addEventListener("change", nav);
    bar.appendChild(labeled("Group by", groupSel));

    // Card fields (checkbox dropdown)
    var dd = el("div", "kb-dd");
    var ddBtn = el("button", "btn btn-sm", "Cards ▾"); ddBtn.type = "button";
    var ddMenu = el("div", "kb-dd-menu");
    FIELDS.forEach(function (f) {
      if (f.name === (cfg.group_by || GROUP)) return;
      var row = el("label", "kb-dd-item");
      var cb = el("input"); cb.type = "checkbox"; cb.checked = cardsSel.indexOf(f.name) >= 0;
      cb.addEventListener("change", function () {
        if (cb.checked) { if (cardsSel.indexOf(f.name) < 0) cardsSel.push(f.name); }
        else cardsSel = cardsSel.filter(function (n) { return n !== f.name; });
        nav();
      });
      row.appendChild(cb); row.appendChild(el("span", null, f.label));
      ddMenu.appendChild(row);
    });
    ddBtn.addEventListener("click", function () { dd.classList.toggle("kb-dd-open"); });
    document.addEventListener("click", function (ev) { if (!dd.contains(ev.target)) dd.classList.remove("kb-dd-open"); });
    dd.appendChild(ddBtn); dd.appendChild(ddMenu);
    bar.appendChild(labeled("Cards", dd));

    // Column total: measure + agg
    measureSel = el("select");
    var none = el("option", null, "(no total)"); none.value = ""; measureSel.appendChild(none);
    FIELDS.filter(function (f) { return f.numeric; }).forEach(function (f) {
      var o = el("option", null, f.label); o.value = f.name;
      if (f.name === cfg.measure) o.selected = true;
      measureSel.appendChild(o);
    });
    measureSel.addEventListener("change", nav);
    aggSel = el("select");
    [["sum", "Sum"], ["avg", "Average"], ["min", "Min"], ["max", "Max"], ["count", "Count"]].forEach(function (a) {
      var o = el("option", null, a[1]); o.value = a[0];
      if (a[0] === agg) o.selected = true;
      aggSel.appendChild(o);
    });
    aggSel.addEventListener("change", nav);
    var totWrap = el("span", "kb-tot");
    totWrap.appendChild(measureSel); totWrap.appendChild(aggSel);
    bar.appendChild(labeled("Column total", totWrap));

    // Drag toggle
    dragChk = el("input"); dragChk.type = "checkbox"; dragChk.checked = DRAG;
    dragChk.addEventListener("change", nav);
    bar.appendChild(labeled("Drag to change stage", dragChk));
  }
  buildBar();

  // ---- card click (open record) -----------------------------------------
  var lastDragEnd = 0;
  root.addEventListener("click", function (ev) {
    var card = ev.target.closest(".kb-card");
    if (!card) return;
    if (Date.now() - lastDragEnd < 250) return; // ignore the click that ends a drag
    var url = card.dataset.url;
    if (url) window.location = url;
  });

  // ---- column total recompute (live, from data-m) ------------------------
  function fmtNum(v) { return (Math.abs(v) < 1e15 && v % 1 === 0) ? String(v) : v.toFixed(2); }
  function recompute(colBody) {
    var cards = colBody.querySelectorAll(".kb-card");
    var head = colBody.parentNode.querySelector(".kb-col-meta");
    if (!head) return;
    var count = cards.length;
    var meta = String(count);
    if (cfg.measure) {
      var vals = [];
      cards.forEach(function (c) { if (c.dataset.m != null && c.dataset.m !== "") vals.push(parseFloat(c.dataset.m)); });
      var t = 0;
      if (agg === "count") t = count;
      else if (vals.length) {
        if (agg === "avg") t = vals.reduce(function (a, b) { return a + b; }, 0) / vals.length;
        else if (agg === "min") t = Math.min.apply(null, vals);
        else if (agg === "max") t = Math.max.apply(null, vals);
        else t = vals.reduce(function (a, b) { return a + b; }, 0);
      }
      meta += " · " + fmtNum(t);
    }
    head.textContent = meta;
  }

  // ---- drag & drop -------------------------------------------------------
  function toast(msg, err) {
    var t = document.getElementById("kb-toast");
    if (!t) return;
    t.textContent = msg; t.className = "kb-toast kb-toast-show" + (err ? " kb-toast-err" : "");
    setTimeout(function () { t.className = "kb-toast"; }, 2600);
  }

  function move(card, fromBody, toBody) {
    var id = card.dataset.id, value = toBody.dataset.value;
    toBody.appendChild(card); // optimistic
    recompute(fromBody); recompute(toBody);
    var body = new URLSearchParams();
    body.set("id", id); body.set("field", GROUP); body.set("value", value);
    fetch("/kanban/" + encodeURIComponent(MODEL) + "/move", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" },
      body: body.toString(),
    })
      .then(function (r) { return r.json().catch(function () { return { ok: false }; }).then(function (j) { return { ok: r.ok && j && j.ok, j: j }; }); })
      .then(function (res) {
        if (!res.ok) {
          fromBody.appendChild(card); recompute(fromBody); recompute(toBody); // revert
          toast((res.j && res.j.error) || "Could not move card.", true);
        } else {
          toast("Moved.");
        }
      })
      .catch(function () { fromBody.appendChild(card); recompute(fromBody); recompute(toBody); toast("Network error.", true); });
  }

  function wireDrag() {
    var dragging = null, sourceBody = null;
    root.querySelectorAll(".kb-card").forEach(function (card) {
      card.setAttribute("draggable", "true");
      card.addEventListener("dragstart", function (ev) {
        dragging = card; sourceBody = card.parentNode;
        card.classList.add("kb-dragging");
        ev.dataTransfer.effectAllowed = "move";
        ev.dataTransfer.setData("text/plain", card.dataset.id);
      });
      card.addEventListener("dragend", function () {
        card.classList.remove("kb-dragging"); dragging = null; lastDragEnd = Date.now();
      });
    });
    root.querySelectorAll(".kb-col-body").forEach(function (body) {
      body.addEventListener("dragover", function (ev) { ev.preventDefault(); body.classList.add("kb-over"); });
      body.addEventListener("dragleave", function () { body.classList.remove("kb-over"); });
      body.addEventListener("drop", function (ev) {
        ev.preventDefault(); body.classList.remove("kb-over");
        if (!dragging || body === sourceBody) return;
        move(dragging, sourceBody, body);
      });
    });
  }

  if (DRAG && GROUP) {
    wireDrag();
  } else {
    root.querySelectorAll(".kb-card").forEach(function (c) { c.removeAttribute("draggable"); });
  }
})();
