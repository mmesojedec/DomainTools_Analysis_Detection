"""
The hunt report: one self-contained HTML page (no scripts, no network; print it to PDF from the browser) with
everything the hunt found, in full, for further analysis or to present to other teams. It has:
  * the status, verdict and summary, and summary figures;
  * the hunt map, drawn here as SVG (no Graphviz needed);
  * every run, with each value it followed;
  * the cluster, the core indicators (with the domains that share them), every indicator of every domain, the alerts
    by type and every alert with its evidence;
  * the open next steps.
Built from the saved runs only (no API calls).
"""
import html
from collections import Counter, defaultdict
from datetime import datetime
from datetime import timezone as dt_timezone

from core.case_report import CSS
from core.hunt_result import STATUS_LABELS, norm, start_links
from core.intel_data import SEVERITY_COLORS, SEVERITY_ORDER
from core.run_history import format_created

RANK = {severity: number for number, severity in enumerate(SEVERITY_ORDER)}
KIND_ORDER = ("IP", "Name Server", "MX", "Email", "Certificate", "JA4X", "Hostname")
EXTRA_CSS = """
.map { overflow-x: auto; border: 1px solid #e5e7eb; border-radius: 8px; padding: 8px; background: #fafafa; }
.map svg { display: block; max-width: none; }
.legend { color: #6b7280; font-size: 12px; margin-top: 6px; }
ul.values { margin: 0; padding-left: 16px; } ul.values li { margin: 0; }
.shared { font-weight: 700; } .sev-dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%;
          margin-right: 4px; vertical-align: middle; }
h3 { font-size: 15px; margin: 20px 0 4px; }
.small { font-size: 12px; }
@media print { .map { overflow: visible; border: none; padding: 0; } .map svg { max-width: 100%; height: auto; } }
"""
NODE_W, LINE_H, PAD, GAP_X, GAP_Y, GAP_DOWN = 280, 15, 9, 150, 22, 46
LR_MAX_DEPTH = 3   # this many runs deep or more: the map is drawn top to bottom
TARGET_LINES = 5   # targets written in a map box; the Runs table lists all of them


def _e(value):
    return html.escape(str(value if value is not None else ""))


def _counted(counter, limit=3):
    """'4 Certificates, 1 IP' from a Counter of kinds."""
    return ", ".join(f"{count} {kind}{'s' if count > 1 and not kind.endswith('s') else ''}"
                     for kind, count in counter.most_common(limit))


def _clip(text, width):
    text = str(text)
    return text if len(text) <= width else text[:width - 1] + "…"


def _pill(severity):
    return f'<span class="pill" style="background:{SEVERITY_COLORS.get(severity, "#6b7280")}">{_e(severity)}</span>'


def _values(items):
    items = [item for item in items if item not in (None, "")]
    if not items:
        return ""
    return '<ul class="values">' + "".join(f"<li>{item}</li>" for item in items) + "</ul>"


def _table(columns, rows, mono=()):
    """`rows`: lists of cells already escaped (HTML)."""
    if not rows:
        return '<p class="muted">None.</p>'
    head = "".join(f"<th>{_e(column)}</th>" for column in columns)
    body = "".join("<tr>" + "".join(f'<td class="mono">{cell}</td>' if column in mono else f"<td>{cell}</td>"
                                    for column, cell in zip(columns, row)) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _kind_of(value):
    text = str(value)
    if text.startswith(("sha256:", "sha1:")):
        return "Certificate"
    if text.replace(".", "").isdigit() or ":" in text or "/" in text:
        return "IP / range"
    return "Domain"


def _number(value):
    """A score as written: 100 rather than 100.0; empty when missing."""
    if value in (None, ""):
        return ""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    return f"{number:.0f}" if number == int(number) else f"{number:.1f}"


def _worst(alerts):
    return min((a.get("Severity") for a in alerts), key=lambda s: RANK.get(s, 99), default="")


def _severity_text(alerts):
    counts = Counter(a.get("Severity") for a in alerts)
    return ", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts.get(s))


class _Hunt:
    """The hunt's runs in order, with numbers, parents and what led to each run."""

    def __init__(self, members, steps_by_run, timezone):
        self.members = members
        self.snapshots = [snapshot for _, snapshot, _ in members]
        self.by_id = {snapshot["id"]: snapshot for snapshot in self.snapshots}
        self.depth = {snapshot["id"]: depth for _, snapshot, depth in members}
        self.number = {snapshot["id"]: number for number, snapshot in enumerate(self.snapshots, 1)}
        self.timezone = timezone
        self.steps = steps_by_run or {}
        self.led_to = defaultdict(list)   # run id -> followed steps of its parent that started it
        for items in self.steps.values():
            for item in items:
                if item.get("done") and item.get("child"):
                    self.led_to[item["child"]["id"]].append(item)

    def parent(self, snapshot):
        parent_id = (snapshot.get("parent") or {}).get("id")
        return parent_id if parent_id in self.by_id else None

    def when(self, snapshot, fmt="%Y-%m-%d %H:%M"):
        return format_created(snapshot.get("created"), self.timezone, fmt=fmt)

    def label(self, snapshot):
        return f"Run {self.number[snapshot['id']]}"

    def followed(self, snapshot):
        """[(kind, value)] this run followed: the steps that led to it, else its certificate seeds and new targets."""
        steps = self.led_to.get(snapshot["id"])
        if steps:
            return [(str(item.get("kind") or ""), str(item.get("value") or "")) for item in steps]
        parent = self.by_id.get(self.parent(snapshot)) if self.parent(snapshot) else None
        known = {norm(t) for t in (parent or {}).get("targets") or []}
        values = [*(snapshot.get("seeds") or []),
                  *[t for t in snapshot.get("targets") or [] if norm(t) not in known]]
        return [(_kind_of(value), norm(value)) for value in values]

    def method(self, snapshot):
        via = str((snapshot.get("parent") or {}).get("via") or "")
        return via.split(":", 1)[0].strip() if ":" in via else via

    def started_from(self, snapshot):
        """The run's origin in full: an IrisQL / CertsQL query is kept as written, a hunt step lists its values."""
        via = str((snapshot.get("parent") or {}).get("via") or "")
        if via.startswith(("IrisQL", "CertsQL")) or not self.parent(snapshot):
            return via or "Targets entered"
        return self.method(snapshot) or "Followed"


def _run_rows(hunt, links):
    rows = []
    for _, snapshot, depth in hunt.members:
        alerts = snapshot.get("alerts") or []
        link = links.get(snapshot["id"])
        linked = ("starting point" if not depth else "no new domains" if link is None else
                  _counted(link, 10) or "no: drifted")
        parent = hunt.parent(snapshot)
        followed = [f"{_e(kind)}: <span class='mono'>{_e(value)}</span>" for kind, value in hunt.followed(snapshot)] \
            if depth else [f"Certificate: <span class='mono'>{_e(norm(seed))}</span>" for seed in snapshot.get("seeds") or []]
        rows.append([f"<b>{_e(hunt.label(snapshot))}</b><br><span class='muted'>{_e(hunt.when(snapshot))}</span>",
                     _e(hunt.label(hunt.by_id[parent])) if parent else "—",
                     _e(hunt.started_from(snapshot)) + _values(followed),
                     _values([f"<span class='mono'>{_e(t)}</span>" for t in snapshot.get("targets") or []]),
                     _e(len(snapshot.get("targets") or [])),
                     _e(_severity_text(alerts)) or "none", _e(linked)])
    return rows


def _domain_data(hunt):
    """({domain: {kind: [values]}}, {domain: profile}, {(domain, type): alert}) across the runs, newest wins."""
    values, profiles, alerts = defaultdict(lambda: defaultdict(list)), {}, {}
    for snapshot in sorted(hunt.snapshots, key=lambda s: str(s.get("created"))):
        for domain, kinds in (snapshot.get("artifacts") or {}).items():
            for kind, items in kinds.items():
                for item in items or []:
                    if item not in values[domain][kind]:
                        values[domain][kind].append(item)
        for profile in snapshot.get("profiles") or []:
            profiles[profile.get("Domain")] = profile
        for alert in snapshot.get("alerts") or []:
            alerts[(alert.get("Domain"), alert.get("Threat Type"))] = alert
    return values, profiles, alerts


def _wrap(text, width):
    """Lines of at most `width` characters (long tokens are cut)."""
    words, lines, line = str(text).split(), [], ""
    for word in words:
        if len(line) + len(word) + 1 > width and line:
            lines.append(line)
            line = ""
        line = f"{line} {word}".strip()
    if line:
        lines.append(line)
    return [_clip(item, width) for item in lines] or [""]


def hunt_map_svg(hunt, links, open_steps=0):
    """The hunt map as SVG: one box per run (left to right by depth), arrows labelled with what was followed."""
    children = defaultdict(list)
    for snapshot in hunt.snapshots:
        if hunt.parent(snapshot):
            children[hunt.parent(snapshot)].append(snapshot["id"])
    newest = max(hunt.snapshots, key=lambda s: str(s.get("created")))["id"]
    boxes = {}
    for _, snapshot, depth in hunt.members:
        alerts = snapshot.get("alerts") or []
        targets = list(snapshot.get("targets") or []) or [norm(s) for s in snapshot.get("seeds") or []]
        lines = [("title", f"{hunt.label(snapshot)}{' · start' if not depth else ''} · {hunt.when(snapshot, '%m-%d %H:%M')}")]
        lines += [("mono", _clip(t, 40)) for t in targets[:TARGET_LINES]]
        if len(targets) > TARGET_LINES:
            lines.append(("muted", f"and {len(targets) - TARGET_LINES} more: see {hunt.label(snapshot)} under Runs"))
        lines.append(("text", f"{len(snapshot.get('targets') or [])} domain(s) / IP(s)"))
        if alerts:
            for part in _wrap("Alerts: " + _severity_text(alerts), 44):
                lines.append(("text", part))
        else:
            lines.append(("muted", "No alerts"))
        link = links.get(snapshot["id"])
        if depth and link is not None:
            lines.append(("link" if link else "drift", "Linked to start: " + (_counted(link, 2) if link
                                                                               else "no (drifted)")))
        boxes[snapshot["id"]] = {"lines": lines, "h": PAD * 2 + LINE_H * len(lines), "worst": _worst(alerts),
                                 "depth": depth, "drift": depth and link is not None and not link}
    if open_steps:
        boxes["open"] = {"lines": [("muted", f"{open_steps} open next step(s)"), ("muted", "see Open next steps")],
                         "h": PAD * 2 + LINE_H * 2, "depth": boxes[newest]["depth"] + 1, "open": True}
        children[newest].append("open")
    # Left to right for a shallow hunt, top to bottom from LR_MAX_DEPTH runs deep (like the map's Auto layout):
    # across = the axis siblings share (depth-first, a parent centred on its children), down = the depth axis.
    vertical = max(box["depth"] for box in boxes.values()) >= LR_MAX_DEPTH
    size = {node: (NODE_W if vertical else box["h"]) for node, box in boxes.items()}
    gap = GAP_Y if not vertical else 24
    across, cursor = {}, [0]

    def place(node):
        kids = children.get(node, [])
        for kid in kids:
            place(kid)
        if kids:
            centre = (across[kids[0]] + size[kids[0]] / 2 + across[kids[-1]] + size[kids[-1]] / 2) / 2
            across[node] = max(0, centre - size[node] / 2)
            cursor[0] = max(cursor[0], across[node] + size[node] + gap)
        else:
            across[node] = cursor[0]
            cursor[0] += size[node] + gap

    for root in [s["id"] for s in hunt.snapshots if not hunt.parent(s)]:
        place(root)
    if vertical:
        row_h = defaultdict(int)
        for box in boxes.values():
            row_h[box["depth"]] = max(row_h[box["depth"]], box["h"])
        top = {depth: 10 + sum(row_h[d] + GAP_DOWN for d in range(depth)) for depth in row_h}
        x = {node: 10 + across[node] for node in boxes}
        y = {node: top[box["depth"]] for node, box in boxes.items()}
    else:
        x = {node: 10 + box["depth"] * (NODE_W + GAP_X) for node, box in boxes.items()}
        y = {node: 10 + across[node] for node in boxes}
    width = max(x.values()) + NODE_W + (230 if vertical else 10)   # top to bottom: room for the arrow labels
    height = max(y[node] + box["h"] for node, box in boxes.items()) + 10
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" '
             f'viewBox="0 0 {width:.0f} {height:.0f}" font-family="-apple-system, Segoe UI, Roboto, Arial, sans-serif" '
             'font-size="12"><defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
             'markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#43a047"/></marker>'
             '<marker id="arrow-open" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
             'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#9ca3af"/></marker></defs>']
    for parent, kids in children.items():
        for kid in kids:
            if vertical:
                x1, y1 = x[parent] + NODE_W / 2, y[parent] + boxes[parent]["h"]
                x2, y2 = x[kid] + NODE_W / 2, y[kid]
                mid = (y1 + y2) / 2
                path = f"M{x1:.0f},{y1:.0f} C{x1:.0f},{mid:.0f} {x2:.0f},{mid:.0f} {x2:.0f},{y2 - 2:.0f}"
                label_x, label_y, anchor = (x1 + x2) / 2 + 10, mid - 2, "start"
            else:
                x1, y1 = x[parent] + NODE_W, y[parent] + boxes[parent]["h"] / 2
                x2, y2 = x[kid], y[kid] + boxes[kid]["h"] / 2
                mid = (x1 + x2) / 2
                path = f"M{x1:.0f},{y1:.0f} C{mid:.0f},{y1:.0f} {mid:.0f},{y2:.0f} {x2 - 2:.0f},{y2:.0f}"
                label_x, label_y, anchor = mid, (y1 + y2) / 2 - 14, "middle"
            is_open = kid == "open"
            parts.append(f'<path d="{path}" fill="none" stroke="{"#9ca3af" if is_open else "#43a047"}" '
                         'stroke-width="1.6"' + (' stroke-dasharray="5,4"' if is_open else "")
                         + f' marker-end="url(#{"arrow-open" if is_open else "arrow"})"/>')
            if not is_open:
                child = hunt.by_id[kid]
                kinds = Counter(kind for kind, _ in hunt.followed(child))
                label = (hunt.method(child) or "followed") + (": " + _counted(kinds) if kinds else "")
                lines = _wrap(label, 30)[:3] if vertical else _wrap(label, 22)[:3]
                for number, part in enumerate(lines):
                    parts.append(f'<text x="{label_x:.0f}" y="{label_y + number * 13:.0f}" text-anchor="{anchor}" '
                                 f'fill="#2e7d32" font-size="10.5">{_e(part)}</text>')
    styles = {"title": 'font-weight="700" fill="#111827"', "mono": 'font-family="Menlo, Consolas, monospace" '
              'font-size="11" fill="#1f2937"', "text": 'fill="#374151"', "muted": 'fill="#6b7280"',
              "link": 'fill="#1d4ed8"', "drift": 'fill="#b91c1c"'}
    for node, box in boxes.items():
        border = "#9ca3af" if box.get("open") else "#b91c1c" if box.get("drift") else \
            "#4f46e5" if not box["depth"] else "#cbd5e1"
        parts.append(f'<rect x="{x[node]}" y="{y[node]:.0f}" width="{NODE_W}" height="{box["h"]}" rx="8" '
                     f'fill="#ffffff" stroke="{border}" stroke-width="{2 if not box["depth"] else 1.4}"'
                     + (' stroke-dasharray="5,4"' if box.get("open") else "") + "/>")
        if box.get("worst"):
            parts.append(f'<rect x="{x[node]}" y="{y[node]:.0f}" width="6" height="{box["h"]}" rx="3" '
                         f'fill="{SEVERITY_COLORS.get(box["worst"], "#6b7280")}"/>')
        for number, (style, text) in enumerate(box["lines"]):
            parts.append(f'<text x="{x[node] + 14}" y="{y[node] + PAD + LINE_H * number + 11:.0f}" '
                         f'{styles[style]}>{_e(text)}</text>')
    return "".join(parts) + "</svg>"


def hunt_report_html(title, members, result, status, steps_by_run=None, open_steps=None, verdict=None, note="",
                     timezone="UTC", generated=None):
    """
    The full hunt report (see the module docstring). `members`: hunt_members(); `result`: hunt_result();
    `status`: (status, reason); `steps_by_run`: {run id: plan items} (what each run followed); `open_steps`: the
    newest run's steps not followed yet.
    """
    hunt = _Hunt(members, steps_by_run, timezone)
    root = hunt.snapshots[0]
    links = start_links(hunt.snapshots, root)
    values, profiles, alerts = _domain_data(hunt)
    open_steps = list(open_steps or [])
    generated = generated or datetime.now(dt_timezone.utc)
    all_alerts = list(alerts.values())
    cluster = {row["Domain"] for row in result["cluster"]}
    shared = {(row["Kind"], norm(row["Value"])) for row in result["core"]}
    domains = list(dict.fromkeys([row["Domain"] for row in result["cluster"]]
                                 + [t for s in hunt.snapshots for t in s.get("targets") or []]))

    parts = [f"<h1>{_e(title)}</h1>",
             f'<p class="meta">Status: <b>{_e(STATUS_LABELS.get(status[0], status[0]))}</b> ({_e(status[1])})'
             + (f" · Verdict: <b>{_e(verdict)}</b>" if verdict else "")
             + f" · Started {_e(hunt.when(root))} from {_e(hunt.started_from(root))}"
             + f" · Report generated {_e(format_created(generated.isoformat(), timezone))} ({_e(timezone)})</p>"]
    if note:
        parts.append(f'<h2>Summary</h2><div class="notes">{_e(note)}</div>')
    counts = Counter(a.get("Severity") for a in all_alerts)
    cards = [("Runs", len(hunt.snapshots)), ("Domains / IPs analyzed", len(domains)),
             ("Linked to the start", len(result["cluster"])), ("Core indicators", len(result["core"])),
             ("Distinct alerts", len(all_alerts))] + [(f"{s} alerts", counts[s]) for s in SEVERITY_ORDER if counts.get(s)]
    parts.append('<div class="cards">' + "".join(f'<div class="card"><b>{_e(v)}</b><span>{_e(k)}</span></div>'
                                                 for k, v in cards) + "</div>")

    parts += ["<h2>Hunt map</h2>", f'<div class="map">{hunt_map_svg(hunt, links, len(open_steps))}</div>',
              '<p class="legend">Each box is a run: its targets, how many domains or IPs it analyzed, its alerts and '
              "what it shares with the starting run. The coloured edge is the worst alert. Arrows show what was "
              "followed to start the next run (every value is listed under Runs). Blue border: the starting run; red "
              "border: a run whose new domains share nothing with the start (drifted); dashed: steps not followed "
              "yet.</p>"]

    parts += ["<h2>Runs</h2>",
              '<p class="muted">Every value each run followed and every target it analyzed, in full.</p>',
              _table(["Run", "From", "Started from / values followed", "Targets", "Domains", "Alerts",
                      "Linked to start"], _run_rows(hunt, links))]

    rows = []
    for row in result["cluster"]:
        domain = row["Domain"]
        mine = [a for a in all_alerts if a.get("Domain") == domain]
        profile = profiles.get(domain) or {}
        first = hunt.by_id.get(row["First run"])
        rows.append([f"<span class='mono'>{_e(domain)}</span>", _e(row["Linked by"]),
                     _e(hunt.label(first) if first else row["First run"]),
                     _e(_number(profile.get("Unified Risk"))), _e(_number(profile.get("Base Domain Risk Score"))),
                     (_pill(_worst(mine)) + " " if mine else "") + _e(_severity_text(mine) or "none")])
    parts += [f"<h2>Cluster: {len(result['cluster'])} domain(s) linked to the starting point</h2>",
              _table(["Domain", "Linked by", "First run", "Unified risk", "DomainTools risk", "Alerts"], rows)]

    rows = [[_e(row["Kind"]), f"<span class='mono'>{_e(row['Value'])}</span>", _e(row["Domains"]),
             _values([f"<span class='mono'>{_e(d)}</span>" for d in row.get("Shared by", [])])]
            for row in result["core"]]
    parts += ["<h2>Core indicators</h2>",
              '<p class="muted">Values that two or more cluster domains share (CDNs, large DNS providers, role and '
              "privacy mailboxes left out), with the domains that share each.</p>",
              _table(["Kind", "Value", "Domains", "Shared by"], rows)]

    parts.append("<h2>Indicators by domain</h2>")
    parts.append('<p class="muted">Every value the runs recorded for each domain or IP. <b>Bold</b>: a core '
                 "indicator.</p>")
    for domain in domains:
        kinds = values.get(domain) or {}
        if not kinds:
            continue
        order = [k for k in KIND_ORDER if k in kinds] + sorted(k for k in kinds if k not in KIND_ORDER)
        rows = [[_e(kind), _e(len(kinds[kind])), _values([
            f"<span class='mono{' shared' if (kind, norm(v)) in shared else ''}'>{_e(v)}</span>" for v in kinds[kind]])]
            for kind in order]
        parts += [f"<h3>{_e(domain)}{' · in the cluster' if domain in cluster else ''}</h3>",
                  _table(["Kind", "Count", "Values"], rows)]

    by_type = defaultdict(list)
    for alert in all_alerts:
        by_type[alert.get("Threat Type")].append(alert)
    rows = [[_e(kind), _pill(_worst(items)), _e(len({a.get("Domain") for a in items})),
             _values([f"<span class='mono'>{_e(d)}</span>" for d in sorted({a.get("Domain") for a in items})]),
             _e(items[0].get("MITRE ATT&CK", ""))]
            for kind, items in sorted(by_type.items(), key=lambda kv: (RANK.get(_worst(kv[1]), 99), kv[0] or ""))]
    parts += ["<h2>Alerts by type</h2>", _table(["Threat Type", "Worst", "Domains", "Which", "MITRE ATT&CK"], rows)]

    rows = [[_pill(a.get("Severity")), f"<span class='mono'>{_e(a.get('Domain'))}</span>", _e(a.get("Threat Type")),
             _e(a.get("Confidence")), _e(a.get("Category")), _e(a.get("MITRE ATT&CK")),
             f"<div class='evidence'>{_e(a.get('Threat Logic'))}</div>"]
            for a in sorted(all_alerts, key=lambda a: (RANK.get(a.get("Severity"), 99), str(a.get("Domain")),
                                                       str(a.get("Threat Type"))))]
    parts += ["<h2>Alert details</h2>", '<p class="muted">Every distinct alert (domain and threat type) across the '
              "runs, with its evidence; the newest run's wording.</p>",
              _table(["Severity", "Domain", "Threat Type", "Confidence", "Category", "MITRE ATT&CK", "Evidence"], rows)]

    rows = [[_e(item.get("step")), _e(item.get("kind")), f"<span class='mono'>{_e(item.get('value'))}</span>",
             _e(item.get("action")), _e(item.get("score")), _e(item.get("why"))] for item in open_steps]
    parts += ["<h2>Open next steps</h2>", '<p class="muted">Steps of the newest run not followed anywhere in the '
              "hunt.</p>", _table(["Step", "Kind", "Value", "Action", "Score", "Why"], rows)]
    parts.append(f'<p class="muted" style="margin-top:32px">Built from {len(hunt.snapshots)} saved run(s) with '
                 "DomainTools Analytics and Detection; no API queries. Print to PDF from the browser.</p>")
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{_e(title)}</title>"
            f"<style>{CSS}{EXTRA_CSS}</style></head><body><main>{''.join(parts)}</main></body></html>")
