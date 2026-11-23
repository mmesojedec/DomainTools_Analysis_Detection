"""
HTML building blocks for the analysis report (core.analysis_report): headings, notes, metric cards, tables from
DataFrames, Plotly charts and inline SVG, assembled into one self-contained page with a table of contents and print
styles. Every value is escaped. Charts are interactive Plotly: plotly.js is embedded once (works offline), loaded from
a CDN (small file, needs internet) or left out (tables only).
"""
import html
import json
import re
from dataclasses import dataclass, field

import pandas as pd

from core.intel_data import SEVERITY_COLORS

CHARTS_EMBED, CHARTS_CDN, CHARTS_NONE = "embed", "cdn", "none"
VIZ_CDN = "https://cdn.jsdelivr.net/npm/@viz-js/viz@3.11.0/lib/viz-standalone.js"
def plotly_cdn():
    """plotly.js from the CDN, the version the installed plotly embeds."""
    from plotly.offline import get_plotlyjs_version
    return f"https://cdn.plot.ly/plotly-{get_plotlyjs_version()}.min.js"
# The app draws charts with Streamlit's theme: inside Streamlit, Plotly figures carry placeholder colours (#000001 to
# #000040) that only Streamlit's page replaces with the theme palette, so a figure written to a file as it is shows them
# black. These are the values the app shows (Streamlit's dark theme: categorical, sequential and diverging palettes);
# the greys and backgrounds are the light equivalents for the white report.
CATEGORICAL = ["#83c9ff", "#0068c9", "#ffabab", "#ff2b2b", "#7defa1", "#29b09d", "#ffd16a", "#ff8700", "#6d3fc0",
               "#d5dae5"]
SEQUENTIAL = ["#004280", "#0054a3", "#0068c9", "#1c83e1", "#3d9df3", "#60b4ff", "#83c9ff", "#a6dcff", "#c7ebff",
              "#e4f5ff"]
DIVERGING = ["#7d353b", "#bd4043", "#ff4b4b", "#ff8c8c", "#ffc7c7", "#a6dcff", "#60b4ff", "#1c83e1", "#0054a3",
             "#004280"]
_OTHER = {32: "#29b09d", 33: "#ff2b2b", 34: "#0068c9", 35: "#9ea3ad", 36: "#31333f", 37: "#262730", 38: "#ffffff",
          39: "#e6e9ef", 40: "#f0f2f6"}
PLACEHOLDERS = {f"#{n:06d}": color for n, color in
                [*enumerate(CATEGORICAL, 1), *enumerate(SEQUENTIAL, 11), *enumerate(DIVERGING, 21), *_OTHER.items()]}
_PLACEHOLDER_RE = re.compile(r"#0000[0-4][0-9](?![0-9a-fA-F])")


def app_colors(text):
    """`text` (a figure's JSON) with Streamlit's placeholder colours replaced by the colours the app shows."""
    return _PLACEHOLDER_RE.sub(lambda m: PLACEHOLDERS.get(m.group(0), m.group(0)), text)


# Graphs (AS paths, CNAME chains) draw plain nodes near-black for the app's dark page: on the white report they take
# the slate the app uses for neutral nodes elsewhere, with their white text.
GRAPH_DARK, GRAPH_NEUTRAL = "#2f2f2f", "#607d8b"
MAX_CELL = 600          # characters kept per table cell (the data export has the rest)
MONO_HINTS = ("hash", "sha", "ja4", "value", "ip", "prefix", "query", "command", "fingerprint", "indicator")
TOOL_ROWS = 12          # tables with more rows get a filter box (and every table sorts on a header click)
CSS = """
:root { color-scheme: light; --ink: #0f172a; --muted: #64748b; --line: #e2e8f0; --soft: #f8fafc; --accent: #4f46e5;
        --accent-soft: #eef2ff; --side: 272px; }
* { box-sizing: border-box; }
html { scroll-behavior: smooth; scroll-padding-top: 16px; }
body { font: 14px/1.55 Inter, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: var(--ink);
       background: #f1f5f9; margin: 0; }
a { color: var(--accent); }
.side { position: fixed; inset: 0 auto 0 0; width: var(--side); background: #0f172a; color: #cbd5e1;
        display: flex; flex-direction: column; z-index: 20; }
.side .brand { padding: 18px 18px 10px; border-bottom: 1px solid #1e293b; }
.side .brand b { display: block; color: #fff; font-size: 14px; line-height: 1.35; }
.side .brand span { font-size: 11.5px; color: #94a3b8; }
.side input { margin: 12px 14px 6px; padding: 7px 10px; border-radius: 8px; border: 1px solid #334155;
              background: #1e293b; color: #e2e8f0; font: inherit; font-size: 13px; }
.nav { overflow-y: auto; padding: 4px 8px 16px; flex: 1; }
.nav a { display: block; color: #cbd5e1; text-decoration: none; padding: 4px 10px; border-radius: 6px;
         font-size: 13px; }
.nav a:hover { background: #1e293b; color: #fff; }
.nav a.lvl1 { color: #818cf8; font-size: 11px; letter-spacing: .08em; text-transform: uppercase; margin-top: 12px;
              font-weight: 700; }
.nav a.lvl2 { padding-left: 16px; }
.nav a.active { background: var(--accent); color: #fff; }
.side .tools { display: flex; gap: 6px; padding: 10px 14px; border-top: 1px solid #1e293b; }
.side .tools button { flex: 1; }
button.btn { font: inherit; font-size: 12px; border: 1px solid #334155; background: #1e293b; color: #e2e8f0;
             border-radius: 7px; padding: 5px 8px; cursor: pointer; }
button.btn:hover { background: #334155; }
.menu { display: none; }
main { margin-left: var(--side); padding: 28px 36px 60px; max-width: calc(1320px + var(--side)); }
.hero { background: linear-gradient(135deg, #312e81 0%, #4f46e5 55%, #0ea5e9 100%); color: #fff; border-radius: 16px;
        padding: 26px 30px; box-shadow: 0 10px 30px rgba(79, 70, 229, .25); }
.hero h1 { margin: 6px 0 14px; font-size: 27px; line-height: 1.25; }
.hero .level { display: inline-block; background: rgba(255, 255, 255, .18); border: 1px solid rgba(255, 255, 255, .35);
               border-radius: 999px; padding: 2px 12px; font-size: 12px; font-weight: 600; letter-spacing: .03em; }
.header-grid { display: grid; grid-template-columns: 160px 1fr; gap: 4px 16px; font-size: 13.5px; margin: 0; }
.header-grid dt { color: rgba(255, 255, 255, .72); } .header-grid dd { margin: 0; }
.notes { background: #fff; border-left: 4px solid var(--accent); border-radius: 10px; padding: 14px 18px;
         white-space: pre-wrap; margin: 16px 0 0; box-shadow: 0 1px 2px rgba(15, 23, 42, .06); }
.notes-title { font-size: 12px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); margin: 22px 0 0;
               font-weight: 700; }
.disclaimer { color: var(--muted); font-size: 12px; margin: 12px 2px 0; }
.part { font-size: 12px; letter-spacing: .12em; text-transform: uppercase; color: var(--accent); margin: 40px 0 10px;
        font-weight: 800; display: flex; align-items: center; gap: 12px; }
.part::after { content: ""; flex: 1; height: 1px; background: #c7d2fe; }
.sec { background: #fff; border: 1px solid var(--line); border-radius: 14px; margin: 14px 0;
       box-shadow: 0 1px 3px rgba(15, 23, 42, .05); }
.sec-head { display: flex; align-items: center; gap: 10px; padding: 14px 20px; cursor: pointer; user-select: none; }
.sec-head h2 { font-size: 19px; margin: 0; flex: 1; }
.sec-head .chev { color: var(--muted); transition: transform .15s; font-size: 13px; }
.sec.collapsed .chev { transform: rotate(-90deg); }
.sec-body { padding: 0 20px 18px; }
.sec.collapsed .sec-body { display: none; }
h3 { font-size: 16px; margin: 24px 0 6px; } h4 { font-size: 14px; margin: 16px 0 4px; color: #334155; }
.muted { color: var(--muted); font-size: 12.5px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin: 8px 0; }
.card { border: 1px solid var(--line); border-radius: 10px; padding: 10px 14px; background: var(--soft); }
.card b { display: block; font-size: 21px; line-height: 1.3; } .card span { color: var(--muted); font-size: 12px; }
.tbl { margin-top: 6px; } .tbl .filter { padding: 5px 9px; border: 1px solid var(--line); border-radius: 7px;
       font: inherit; font-size: 12.5px; width: 260px; max-width: 100%; margin-bottom: 4px; }
.scroll { overflow: auto; max-height: 620px; border: 1px solid var(--line); border-radius: 10px; }
table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
th, td { text-align: left; vertical-align: top; padding: 6px 9px; border-bottom: 1px solid #eef2f7; }
th { background: #f1f5f9; font-weight: 600; position: sticky; top: 0; z-index: 1; cursor: pointer; white-space: nowrap; }
th.asc::after { content: " ▲"; font-size: 9px; } th.desc::after { content: " ▼"; font-size: 9px; }
tbody tr:hover { background: #f8fafc; } tr { break-inside: avoid; }
td.mono, .mono { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; word-break: break-all; }
td.mono { min-width: 18ch; }
.pill { display: inline-block; color: #fff; border-radius: 10px; padding: 1px 8px; font-size: 11.5px;
        font-weight: 600; white-space: nowrap; }
.table-note { color: var(--muted); font-size: 12px; margin: 4px 0 0; }
.callout { border-left: 4px solid #f59e0b; background: #fffbeb; padding: 9px 14px; margin: 8px 0; border-radius: 8px; }
.chart { border: 1px solid var(--line); border-radius: 10px; padding: 4px; margin: 8px 0; break-inside: avoid;
         overflow: hidden; }
.svgbox { overflow-x: auto; border: 1px solid var(--line); border-radius: 10px; padding: 8px; background: var(--soft); }
.svgbox svg { display: block; max-width: none; }
.domain-card { border: 1px solid var(--line); border-radius: 12px; padding: 12px 16px; margin: 14px 0;
               break-inside: avoid; background: #fcfdff; }
.domain-card h4 { margin-top: 0; font-size: 15px; color: var(--ink); }
.attention { display: grid; gap: 8px; margin: 8px 0; }
.att { display: flex; gap: 12px; align-items: flex-start; border: 1px solid var(--line); border-radius: 10px;
       padding: 10px 14px; background: var(--soft); }
.att .dot { width: 10px; height: 10px; border-radius: 50%; margin-top: 6px; flex: none; }
.att b { display: block; } .att span.muted { overflow-wrap: anywhere; } .att a { font-size: 12px; white-space: nowrap; margin-left: auto; }
.yes { color: #15803d; font-weight: 600; }
.top { position: fixed; right: 22px; bottom: 22px; background: var(--accent); color: #fff; border: 0; border-radius: 50%;
       width: 40px; height: 40px; font-size: 18px; cursor: pointer; box-shadow: 0 6px 16px rgba(79, 70, 229, .35);
       display: none; z-index: 30; }
@media (max-width: 900px) {
  .side { transform: translateX(-100%); transition: transform .2s; } body.nav-open .side { transform: none; }
  main { margin-left: 0; padding: 60px 14px 40px; }
  .menu { display: block; position: fixed; top: 12px; left: 12px; z-index: 25; background: #0f172a; color: #fff;
          border: 0; border-radius: 8px; padding: 7px 12px; font: inherit; }
  .header-grid { grid-template-columns: 1fr; } .header-grid dt { margin-top: 6px; }
}
@media print {
  body { background: #fff; } .side, .menu, .top, .filter { display: none !important; }
  main { margin: 0; padding: 0; max-width: none; } .sec { box-shadow: none; border: none; }
  .sec.collapsed .sec-body { display: block; } .sec-head .chev { display: none; }
  .scroll { max-height: none; overflow: visible; border: none; } th { position: static; }
  .hero { box-shadow: none; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .pill, .att .dot { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .part { break-before: page; } h2, h3 { break-after: avoid; } a { color: inherit; }
}
"""
# Navigation, scroll spy, collapsing sections, table filter and sort, back to top: plain JavaScript, no library.
SCRIPT = r"""
(function () {
  var links = Array.prototype.slice.call(document.querySelectorAll(".nav a"));
  var byId = {}; links.forEach(function (a) { byId[a.getAttribute("href").slice(1)] = a; });
  function open(id) { var el = document.getElementById(id); if (el && el.classList.contains("collapsed")) toggle(el); }
  function toggle(sec) { sec.classList.toggle("collapsed"); window.dispatchEvent(new Event("resize")); }
  document.querySelectorAll(".sec-head").forEach(function (h) {
    h.addEventListener("click", function () { toggle(h.parentNode); }); });
  links.forEach(function (a) { a.addEventListener("click", function () {
    open(a.getAttribute("href").slice(1)); document.body.classList.remove("nav-open"); }); });
  function all(collapse) { document.querySelectorAll(".sec").forEach(function (s) {
    s.classList.toggle("collapsed", collapse); }); window.dispatchEvent(new Event("resize")); }
  var ex = document.getElementById("expand-all"), co = document.getElementById("collapse-all");
  if (ex) ex.onclick = function () { all(false); }; if (co) co.onclick = function () { all(true); };
  var pr = document.getElementById("print"); if (pr) pr.onclick = function () { all(false); window.print(); };
  window.addEventListener("beforeprint", function () { all(false); });
  var menu = document.querySelector(".menu");
  if (menu) menu.onclick = function () { document.body.classList.toggle("nav-open"); };
  var search = document.getElementById("nav-search");
  if (search) search.addEventListener("input", function () {
    var q = search.value.toLowerCase();
    links.forEach(function (a) { a.style.display = !q || a.classList.contains("lvl1") ||
      a.textContent.toLowerCase().indexOf(q) >= 0 ? "" : "none"; }); });
  if ("IntersectionObserver" in window) {
    var spy = new IntersectionObserver(function (entries) { entries.forEach(function (en) {
      if (en.isIntersecting && byId[en.target.id]) {
        links.forEach(function (a) { a.classList.remove("active"); }); byId[en.target.id].classList.add("active"); } });
    }, { rootMargin: "0px 0px -75% 0px" });
    document.querySelectorAll(".sec, .part").forEach(function (s) { spy.observe(s); });
  }
  var top = document.querySelector(".top");
  if (top) { top.onclick = function () { window.scrollTo(0, 0); };
    window.addEventListener("scroll", function () { top.style.display = window.scrollY > 600 ? "block" : "none"; }); }
  function value(td) { var t = td.textContent.trim(), n = parseFloat(t.replace(/[,%]/g, ""));
    return /^-?[\d,.]+ ?%?$/.test(t) && !isNaN(n) ? n : t.toLowerCase(); }
  document.querySelectorAll(".tbl").forEach(function (box) {
    var table = box.querySelector("table"); if (!table || !table.tBodies.length) return;
    var body = table.tBodies[0], rows = Array.prototype.slice.call(body.rows);
    table.querySelectorAll("th").forEach(function (th, i) { th.addEventListener("click", function () {
      var asc = !th.classList.contains("asc");
      table.querySelectorAll("th").forEach(function (o) { o.classList.remove("asc", "desc"); });
      th.classList.add(asc ? "asc" : "desc");
      rows.sort(function (a, b) { var x = value(a.cells[i]), y = value(b.cells[i]);
        if (typeof x !== typeof y) { x = String(x); y = String(y); } return (x > y ? 1 : x < y ? -1 : 0) * (asc ? 1 : -1); });
      rows.forEach(function (r) { body.appendChild(r); }); }); });
    if (rows.length > TOOL_ROWS) {
      var input = document.createElement("input"); input.className = "filter";
      input.placeholder = "Filter " + rows.length + " rows…"; box.insertBefore(input, box.firstChild);
      input.addEventListener("input", function () { var q = input.value.toLowerCase();
        rows.forEach(function (r) { r.style.display = !q || r.textContent.toLowerCase().indexOf(q) >= 0 ? "" : "none"; });
      }); }
  });
})();
""".replace("TOOL_ROWS", str(TOOL_ROWS))


def e(value):
    """Escaped text; empty for None / NaN."""
    if value is None:
        return ""
    if not isinstance(value, (list, tuple, set, dict, str)):
        try:
            if pd.isna(value):
                return ""
        except (TypeError, ValueError):
            pass
    return html.escape(str(value))


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-") or "section"


def pill(severity):
    color = SEVERITY_COLORS.get(str(severity), "#6b7280")
    return f'<span class="pill" style="background:{color}">{e(severity)}</span>' if severity else ""


def _cell_text(value):
    if isinstance(value, (list, tuple, set)):
        value = ", ".join(str(v) for v in value)
    elif isinstance(value, dict):
        value = json.dumps(value, default=str)
    elif isinstance(value, bool):
        return '<span class="yes">✓</span>' if value else ""
    elif isinstance(value, float):
        if pd.isna(value):
            return ""
        value = f"{value:,.0f}" if value.is_integer() else f"{value:,.2f}"
    elif isinstance(value, pd.Timestamp):
        if pd.isna(value):
            return ""
        value = value.strftime("%Y-%m-%d %H:%M") if (value.hour or value.minute) else value.strftime("%Y-%m-%d")
    text = "" if value is None else str(value)
    if text.lower() in ("nan", "nat", "none", "<na>"):
        return ""
    if len(text) > MAX_CELL:
        text = text[:MAX_CELL].rstrip() + " …"
    return e(text)


def frame_table(frame, max_rows=None, columns=None, mono=None, html_columns=(), note_more=True,
                more="the Data export has them all"):
    """An HTML table from a DataFrame. `html_columns` hold ready HTML (e.g. severity pills); hash-like columns use a
    fixed-width font. With `max_rows`, a note says how many rows were left out (and where to find them: `more`)."""
    if frame is None or frame.empty:
        return '<p class="muted">No rows.</p>'
    if columns:
        frame = frame[[c for c in columns if c in frame.columns]]
    total = len(frame)
    if max_rows and total > max_rows:
        frame = frame.head(max_rows)
    mono = set(mono if mono is not None else
               [c for c in frame.columns if any(h in str(c).lower() for h in MONO_HINTS) and c not in html_columns])
    head = "".join(f"<th>{e(c)}</th>" for c in frame.columns)
    rows = []
    for record in frame.itertuples(index=False):
        cells = []
        for column, value in zip(frame.columns, record):
            content = str(value) if column in html_columns else _cell_text(value)
            if column == "Severity" and column not in html_columns:
                content = pill(value)
            css = ' class="mono"' if column in mono else ""
            cells.append(f"<td{css}>{content}</td>")
        rows.append("<tr>" + "".join(cells) + "</tr>")
    note = (f'<p class="table-note">The first {len(frame):,} of {total:,} rows; {e(more)}.</p>'
            if note_more and len(frame) < total else "")
    return (f'<div class="tbl"><div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}'
            f"</tbody></table></div>{note}</div>")


@dataclass
class Builder:
    """Collects the report body, its navigation and its charts.

    `row_cap` caps every table (the High level report), `unlimited` lifts every table's own cap (the Complete report)
    and `detail` False leaves out the secondary charts; `level` is the report's name shown in its header and sidebar.
    """
    charts: str = CHARTS_EMBED
    row_cap: int = None
    unlimited: bool = False
    detail: bool = True
    level: str = ""
    more: str = "the Data export has them all"
    parts: list = field(default_factory=list)
    toc: list = field(default_factory=list)       # (level, anchor, title)
    figures: int = 0
    graphs: int = 0
    next_anchor: str = None                        # the anchor of the next section (set per report section)
    _anchors: set = field(default_factory=set)
    _open: bool = False

    def _anchor(self, title):
        base = anchor = slug(title)
        number = 2
        while anchor in self._anchors:
            anchor, number = f"{base}-{number}", number + 1
        self._anchors.add(anchor)
        return anchor

    def _close(self):
        if self._open:
            self.parts.append("</div></section>")
            self._open = False

    def part(self, title):
        """A top-level part of the report (High level, Overview, Infrastructure, ...)."""
        self._close()
        anchor = self._anchor(title)
        self.toc.append((1, anchor, title))
        self.parts.append(f'<p class="part" id="{anchor}">{e(title)}</p>')

    def section(self, title, intro=None):
        """A section card (collapsible); everything added after it goes inside, up to the next section or part."""
        self._close()
        anchor = self._anchor(self.next_anchor or title)
        self.next_anchor = None
        self.toc.append((2, anchor, title))
        self.parts.append(f'<section class="sec" id="{anchor}"><div class="sec-head"><span class="chev">▼</span>'
                          f'<h2>{e(title)}</h2></div><div class="sec-body">')
        self._open = True
        if intro:
            self.note(intro)

    def heading(self, title):
        self.parts.append(f"<h3>{e(title)}</h3>")

    def subheading(self, title):
        self.parts.append(f"<h4>{e(title)}</h4>")

    def note(self, text):
        self.parts.append(f'<p class="muted">{e(text)}</p>')

    def text(self, text):
        self.parts.append(f"<p>{e(text)}</p>")

    def callout(self, text):
        self.parts.append(f'<div class="callout">{e(text)}</div>')

    def raw(self, markup):
        """Ready HTML (built from escaped values only)."""
        self.parts.append(markup)

    def bullets(self, items):
        items = [i for i in items if i]
        if items:
            self.parts.append("<ul>" + "".join(f"<li>{e(i)}</li>" for i in items) + "</ul>")

    def cards(self, items):
        """Metric cards: [(label, value)]."""
        items = [(k, v) for k, v in items if v not in (None, "")]
        if items:
            self.parts.append('<div class="cards">' + "".join(
                f'<div class="card"><b>{e(f"{v:,}" if isinstance(v, int) else v)}</b><span>{e(k)}</span></div>'
                for k, v in items) + "</div>")

    def rows(self, requested=None):
        """How many rows a table may show: its own cap, within the report's (none in the Complete report)."""
        if self.unlimited:
            return None
        if self.row_cap is None:
            return requested
        return min(requested, self.row_cap) if requested else self.row_cap

    def table(self, frame, max_rows=None, exact=False, **kwargs):
        """A table, capped by the report level unless `exact` (the table's own limit is the point, e.g. IOCs)."""
        kwargs.setdefault("more", self.more)
        self.parts.append(frame_table(frame, max_rows=max_rows if exact else self.rows(max_rows), **kwargs))

    def svg(self, markup):
        if markup:
            self.parts.append(f'<div class="svgbox">{markup}</div>')

    def dot(self, source):
        """A Graphviz graph, drawn in the browser by viz.js (from the CDN: offline, a note says it needs internet)."""
        if not source or self.charts == CHARTS_NONE:
            return
        self.graphs += 1
        source = source.replace(f'"{GRAPH_DARK}"', f'"{GRAPH_NEUTRAL}"')
        self.parts.append(f'<div class="svgbox dot" data-dot="{e(source)}"><span class="muted">Graph: needs internet '
                          "access to draw (viz.js); the tables next to it hold the same data.</span></div>")

    def figure(self, fig, height=None, secondary=False):
        """An interactive Plotly chart (nothing when charts are off, or for a `secondary` chart in a short report)."""
        if fig is None or self.charts == CHARTS_NONE or (secondary and not self.detail):
            return
        fig.update_layout(template="plotly_white", paper_bgcolor="white", plot_bgcolor="white", colorway=CATEGORICAL,
                          colorscale={"sequential": SEQUENTIAL, "diverging": DIVERGING},
                          **({"height": height} if height else {}))
        self.figures += 1
        spec = app_colors(fig.to_json()).replace("</", "<\\/")
        tall = int(fig.layout.height or 450)   # responsive charts fill their box: the box carries the height
        self.parts.append(f'<div class="chart" id="fig{self.figures}" style="height:{tall + 10}px"></div>'
                          f'<script>(function(){{var f = {spec}; '
                          f'if (window.Plotly) Plotly.newPlot("fig{self.figures}", f.data, f.layout, '
                          '{responsive: true, displaylogo: false});})();</script>')

    def html(self, title, header_html):
        self._close()
        nav = "".join(f'<a class="lvl{level}" href="#{anchor}">{e(text)}</a>' for level, anchor, text in self.toc)
        script = ""
        if self.figures and self.charts == CHARTS_EMBED:
            from plotly.offline import get_plotlyjs
            script = f"<script>{get_plotlyjs()}</script>"
        elif self.figures and self.charts == CHARTS_CDN:
            script = f'<script src="{plotly_cdn()}"></script>'
        graphs = ""
        if self.graphs:
            graphs = (f'<script src="{VIZ_CDN}"></script><script>if (window.Viz) Viz.instance().then(function(viz)'
                      '{document.querySelectorAll(".dot").forEach(function(box){try{box.innerHTML="";'
                      'box.appendChild(viz.renderSVGElement(box.dataset.dot));}catch(err){}});});</script>')
        side = (f'<aside class="side"><div class="brand"><b>{e(title)}</b><span>{e(self.level or "Report")}</span></div>'
                '<input id="nav-search" type="search" placeholder="Find a section…" aria-label="Find a section">'
                f'<nav class="nav" aria-label="Contents">{nav}</nav><div class="tools">'
                '<button class="btn" id="expand-all" type="button" title="Expand every section">Expand</button>'
                '<button class="btn" id="collapse-all" type="button" title="Collapse every section">Collapse</button>'
                '<button class="btn" id="print" type="button" title="Print or save as PDF">Print</button></div></aside>')
        return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width, initial-scale=1">'
                f"<title>{e(title)}</title><style>{CSS}</style>{script}</head><body>"
                f'<button class="menu" type="button">☰ Contents</button>{side}<main>'
                f"{header_html}{''.join(self.parts)}</main>"
                f'<button class="top" type="button" title="Back to top">↑</button>'
                f"<script>{SCRIPT}</script>{graphs}</body></html>")
