# Report Studio — Pixel-Perfect Banded Report Engine (Build Plan)

Status: **✅ SHIPPED (all phases 0→6)** on branch `feat/report-studio`, 2026-07-19 · vortex-core primitive (always compiled; PDF behind the `pdf` feature)

## What shipped

Engine crate `vortex-framework::banded_report` (`model`, `expr`, `datasource`, `layout`, `render`, `mod`) + 30 unit tests. Migration `163_report_layout` (`ir_report_layout`, JSONB document, `report_type='banded'`). `pdf.rs` gained `PdfOptions.exact_in` for 1:1 CSS-page printing. Async worker (`report_jobs`) renders queued banded reports. Server routes under `/reports/design/{id}` (designer shell, save, preview, fields, export, import, scaffold) + banded dispatch in `report_run` (`?format=pdf`). WYSIWYG canvas `static/report-studio.{js,css}` (drag-drop palette, move/resize, property inspector, groups, variables, live preview, keyboard nudge, export/import, starter templates). Three starter templates: `invoice`, `statement`, `labels`.

**Author flow:** Settings → Reports → New → type **Banded** → opens `/reports/design/{id}`. Run/print via `/reports/run/{id}` and `?format=pdf`; queue heavy runs to the Generated Reports inbox.

Remaining polish (post-v1): variable-height "stretch/grow" bands (v1 is fixed-height by design for determinism), cryptographic (vs. sha256-checksum) export signing, embedded chart element, richer 8-handle resize.

---

Original plan follows.

Target: **vortex-core primitive** (always compiled; PDF output behind existing `pdf` feature) · Author date: 2026-07-19

## 1. Goal

Add Crystal Reports / JasperReports-class **pixel-perfect, banded, absolutely-positioned**
report authoring and rendering to Vortex core. Users design a report on a WYSIWYG canvas
(bands + XY-placed elements, rulers, snap-to-grid), bind elements to dataset fields /
parameters / aggregate variables, and render deterministic, repeatable PDF/HTML.

This is a **new report shape** — it does **not** replace the existing systems, it joins them:

| Shape | Layout model | Status |
|---|---|---|
| `tabular` | flow table + group subtotals | shipped (`user_reports`) |
| `template` | authored HTML + sandboxed `{{ }}` engine | shipped (`user_reports`) |
| **`banded`** | **bands + absolute XY elements + expressions** | **this plan** |

## 2. Why this architecture

- **Chromium PDF is already in-tree** (`vortex_framework::pdf::html_to_pdf`). Absolute-positioned
  HTML/CSS in `pt`/`mm` renders to *exact* device coordinates — pixel-perfect output is
  essentially free once we emit positioned HTML.
- **Fixed band heights ⇒ deterministic pagination.** Like Jasper, if every band has a known
  height, page breaks, repeating headers/footers, and group breaks are **pure arithmetic** in
  Rust — no browser measurement, fully repeatable, snapshot-testable. (Variable-height "stretch"
  bands are a later, opt-in extension; v1 is fixed-height for determinism.)
- **Reuse ~70% of shipped plumbing:** `ir_report` (roles/params/dataset), `report_jobs`
  (async + inbox), `FileStore`, `pdf`, `ident()` SQL allow-listing, audit `BulkExport`.

## 3. Data model

Extend the existing report surface rather than forking it.

- `ir_report.report_type` gains a third value: `'banded'`. Reuse `code/name/description/
  model_name/required_role/paper_size/orientation/row_limit/active`.
- Reuse `ir_report_filter` rows as **run-time parameters** (already bound, allow-listed).
- **New table** (migration `1NN_report_layout`):

```sql
CREATE TABLE ir_report_layout (
    report_id   UUID PRIMARY KEY REFERENCES ir_report(id) ON DELETE CASCADE,
    document    JSONB NOT NULL,          -- the ReportLayout doc (§4)
    version     INT   NOT NULL DEFAULT 1,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  UUID REFERENCES users(id)
);
```

JSON-blob storage mirrors `doc_print_templates.config` (`LayoutConfig`) — proven pattern.

## 4. `ReportLayout` document schema (serde structs in `banded_report::model`)

```jsonc
{
  "unit": "pt",                       // pt | mm | px  (canvas + output unit)
  "page": {
    "size": "A4", "orientation": "portrait",
    "width": 595, "height": 842,      // resolved absolute size in `unit`
    "margin": { "top": 36, "right": 36, "bottom": 36, "left": 36 },
    "columns": 1, "columnGap": 0      // multi-column detail (labels/mailmerge)
  },
  "dataset": {
    "model": "sale_order",            // -> ir_model; SQL built by existing datasource layer
    "sort":  [ { "field": "partner", "dir": "asc" } ],
    "groups": [ { "expr": "$F{partner}", "header": "g0h", "footer": "g0f" } ]
  },
  "params":    [ { "name": "date_from", "type": "date", "label": "From", "default": null } ],
  "variables": [ { "name": "amt_total", "calc": "sum", "expr": "$F{amount}", "reset": "report" } ],
  "bands": {
    "title":        { "height": 80, "elements": [ /* … */ ] },
    "pageHeader":   { "height": 40, "elements": [] },
    "columnHeader": { "height": 24, "elements": [] },
    "groupHeaders": { "g0h": { "height": 24, "elements": [] } },
    "detail":       { "height": 20, "elements": [] },
    "groupFooters": { "g0f": { "height": 24, "elements": [] } },
    "columnFooter": { "height": 0,  "elements": [] },
    "pageFooter":   { "height": 30, "elements": [] },
    "summary":      { "height": 60, "elements": [] }
  }
}
```

**Element:**

```jsonc
{
  "id": "e1",
  "type": "field",          // staticText | field | line | box | image | barcode | subreport
  "x": 10, "y": 4, "w": 200, "h": 16,
  "expr": "$F{name}",       // field/staticText/barcode value expression
  "text": "Invoice",        // static text literal
  "printWhen": "$F{qty}>0", // optional visibility expression
  "style": {
    "font": "Helvetica", "size": 10, "bold": false, "italic": false,
    "align": "left", "valign": "middle", "color": "#111", "bg": null,
    "border": { "top": 0, "right": 0, "bottom": 1, "left": 0, "color": "#ccc" },
    "format": "#,##0.00",   // number/date mask
    "wrap": true
  },
  "barcode":   { "symbology": "qr" },              // qr | code128 | ean13
  "subreport": { "code": "line_items", "paramMap": { "order_id": "$F{id}" } }
}
```

## 5. Expression + variable evaluator (`banded_report::expr`)

Small, **sandboxed** recursive-descent evaluator (no arbitrary code — consistent with the
existing `{{ }}` engine and security policy):

- Refs: `$F{field}` (current row), `$P{param}`, `$V{variable}`.
- Ops: `+ - * /`, comparisons, `and/or/not`, parentheses, string concat.
- Functions: `if(cond,a,b)`, `format(x,mask)`, `page()`, `pages()`, `rowNum()`, `upper/lower/trim`.
- Values: Decimal / String / Bool / Date; format masks for number & date.
- **Variables** = aggregates computed during the row walk: `sum|count|avg|min|max`, with
  `reset: report | page | group:<name>`. This is what gives per-group subtotals and grand totals.

All data values are **HTML-escaped** at emit time; identifiers reaching SQL go through existing
`ident()` allow-listing; parameter values are bound. No `eval`, no code execution.

## 6. Deterministic paginator (`banded_report::layout`)

Pure arithmetic over fixed band heights. Algorithm:

1. Fetch dataset rows (reuse `user_reports` datasource: model introspection + parameterized SQL
   + many2one resolution). Apply sort. Compute group boundaries.
2. `content_h = page.height - margin.top - margin.bottom - pageHeader.h - pageFooter.h`.
3. Walk rows maintaining a `y` cursor and open groups:
   - On report start: place `title` (first page only), `columnHeader`.
   - On group change: place `groupFooter`(s) for closed groups, then `groupHeader`(s) for opened
     ones (with "reprint on new page" support).
   - Place `detail`. If `y + band.h > content_h` → **close page** (emit `pageFooter`, page-break),
     **open page** (emit `pageHeader`, repeat `columnHeader` + still-open `groupHeader`s), reset `y`.
   - Multi-column: advance a column cursor before breaking the page.
4. At end: close open group footers, place `summary` (keep-together aware).
5. Result: `Vec<Page>` where each `Page` is a list of `PlacedElement { abs_x, abs_y, w, h, html }`.

Because heights are known up front, `page()`/`pages()` resolve in a cheap second pass.

## 7. HTML/PDF emitter (`banded_report::render`)

- One `<div class="rpt-page">` per page; every element an absolutely-positioned `<div>` in `unit`.
- `@page { size: <w><unit> <h><unit>; margin: 0 }`, `.rpt-page{ position:relative; width/height;
  page-break-after:always; overflow:hidden }`. Fonts embedded/standard; CSS inlined (offline,
  deterministic — same discipline as `REPORT_CSS`).
- Barcodes/QR → inline **SVG** (`qrcode` crate → SVG; `barcoders` for 1D). Images → data-URI from
  FileStore. Lines/boxes → bordered/filled divs.
- Feed to `pdf::html_to_pdf`. **pdf.rs enhancement:** add exact-point page sizing +
  `prefer_css_page_size(true)` path (today it forces inches + `false`) so CSS `@page` drives size
  1:1. Small, backward-compatible `PdfOptions` addition.

## 8. Designer UI (WYSIWYG canvas)

Follows the shipped **`/static/pivot.js`** pattern (external ES module, data-attribute config,
typed `fetch` — CSP-compliant, no inline scripts per CLAUDE.md).

- **Shell**: server-rendered `GET /reports/design/{id}` (toolbar, band lanes, palette, inspector),
  reusing `render_app_shell`.
- **`/static/report-studio.js`**: ruler + snap-to-grid canvas; band lanes (drag band edge to set
  height); drag from **field palette** (dataset fields, params, variables, static/box/line/image/
  barcode) onto a band; select / move / resize (8 handles); **property inspector** (position, font,
  align, border, format mask, expression, printWhen); zoom; undo/redo; multi-select align/distribute.
- **Save**: `POST /reports/design/{id}/save` (validated `ReportLayout` JSON, bumps `version`).
- **Live preview**: `POST /reports/design/{id}/preview` renders first-N rows through the real
  engine → returns HTML into an iframe (and a "PDF preview" button hitting the run route).
- Serve versioned like other assets (`?v=`), file under `crates/vortex-cli/static/`.

## 9. Run + async

- Extend `report_run` (`server.rs`): dispatch `report_type == 'banded'` → `banded_report::render_*`.
  `?format=pdf|html` supported now; `csv/xlsx` N/A for positioned layout (data export stays tabular).
- Extend `report_jobs::render_and_store` with a `banded` branch → same `report_runs` inbox,
  FileStore artifact, "report ready" mail. No new queue infra.
- Params prompt: reuse the existing run-time filter/param form; typed inputs from `params`.
- Audit: emit `AuditAction::BulkExport` per render (matches `reports/routes.rs`).

## 10. Security (must-hold)

- Sandboxed evaluator — no code exec; only refs/ops/whitelisted fns.
- SQL identifiers allow-listed (`ident()`); param values bound; per-tenant pool via existing
  resolution (`db_name`).
- All dataset values HTML-escaped at emit; CSS tokens sanitized (reuse `sanitize_css_token`).
- Designer JS is an external file (CSP: no inline `<script>`); no `innerHTML` with user data
  (build DOM nodes / escape) per CLAUDE.md.
- Access gated by `report_author()` for design, `ReportDef::can_run` for execution.

## 11. Phased delivery

- **Phase 0 — Foundations.** Migration (`report_type='banded'` + `ir_report_layout`); serde model
  structs + validation; `pdf.rs` exact-page-size option. *Ships: schema + a hand-written JSON
  renders a 1-element PDF.*
- **Phase 1 — Engine core.** Datasource fetch + grouping (reuse `user_reports`), expression
  evaluator, variables/aggregates. Unit-tested.
- **Phase 2 — Paginator + emitter.** Fixed-height band layout → positioned HTML → PDF.
  Golden-snapshot tests on a multi-page, grouped fixture. *Ships: real pixel-perfect PDF from JSON.*
- **Phase 3 — Designer UI.** `report-studio.js` canvas + shell + save/preview routes. *Ships:
  end-to-end author→preview→PDF.*
- **Phase 4 — Element richness.** Barcodes/QR (SVG), images (FileStore), format masks,
  borders/boxes/lines, conditional `printWhen`/styling, multi-column.
- **Phase 5 — Advanced.** Subreports, embedded charts (SVG), `page N of M`, running totals,
  keep-together, band reprint-on-break.
- **Phase 6 — Lifecycle.** Async wiring polish, signed layout export/import (match Blueprint export
  convention), `vortex scaffold` sample templates (invoice, statement, label sheet), docs.

## 12. Crate / file layout (all in `vortex-framework`, "core")

```
crates/vortex-framework/src/banded_report/
  mod.rs        // public API: load, render_html, render_pdf, validate
  model.rs      // ReportLayout, Band, Element, Style (serde)
  expr.rs       // sandboxed evaluator + variables/aggregates
  datasource.rs // dataset fetch + grouping (wraps user_reports internals)
  layout.rs     // deterministic paginator -> Vec<Page>
  render.rs     // Page -> positioned HTML; barcode/image/box emitters
  studio.css    // canvas + output CSS (include_str!)
crates/vortex-cli/static/report-studio.js   // WYSIWYG canvas
migrations/1NN_report_layout/postgres.sql
docs/REPORT_STUDIO_BUILD_PLAN.md             // this file
```

New deps (vendored, offline): `qrcode`, `barcoders` (both pure-Rust, SVG output). No JS build step.

## 13. Testing

- Evaluator: unit tests (refs, ops, functions, format masks, aggregate resets).
- Paginator: deterministic golden tests — fixture dataset → asserted page count + element XY.
- Emitter: HTML snapshot + one feature-gated PDF smoke test.
- Validation: reject malformed layouts (overlapping ids, negative geometry, unknown field refs).

## 14. Open decisions (defaults chosen; flag to change)

1. **Module name** `banded_report` (feature brand: "Report Studio"). — default.
2. **v1 = fixed-height bands** (deterministic); variable-height "stretch/grow" deferred to a
   post-v1 measured-layout pass. — default.
3. **Barcode deps** `qrcode` + `barcoders`. — default (both permissively licensed, pure Rust).
