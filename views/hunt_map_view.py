"""
Hunt map (Hunt menu): one place to see and steer a hunt. *This hunt* draws the hunt the loaded run belongs to, from
its first run: every run with its alerts and new domains, the suggested steps each run left open (with what an analyst
needs to choose: score, Iris count, alerts naming it, where to start), and the steps already followed, marked done
and linked to the run they started. Below, the loaded run's next steps to pick and run. *All investigations* is the
timeline of every saved run and the infrastructure different investigations share. Reading it makes no API call.
"""
import html

import streamlit as st

from core.helpers import md_escape
from core.hunt_plan import mark_done, plan_items, runnable
from core.hunt_report import hunt_report_html
from core.hunt_result import (
    CONVERGE_DOMAINS,
    MAX_DEPTH,
    MAX_DOMAINS,
    STATUS_LABELS,
    followed_values,
    hunt_result,
    hunt_status,
    link_text,
    norm,
    run_yield,
    start_links,
    top_types,
)
from core.hunt_tree import collapse_repeats, hunt_members, hunt_root, hunt_tree
from core.hunt_tree import hunt_trail as _trail
from core.intel_data import SEVERITY_COLORS_ON_DARK
from core.offline import list_offline_datasets
from core.persistence import load_all_runs, save_hunt_result, save_watch
from core.run_history import format_created
from core.use_cases import find_case
from views import navigation
from views.common import empty_state
from views.history_view import _offline_by_run, render_run_actions
from views.hunt_actions import current_run_id
from views.hunt_run_view import render_guide, render_picked, run_dialog
from views.hunting_graph_view import render_hunting_graph

TAB_KEY = "hunt_map_tab"
THIS_TAB, COMBINED_TAB, ALL_TAB, PIVOTS_TAB = "This hunt", "Combined hunts", "All investigations", "All pivots"
HUNT_KEY = "hunt_map_hunt"
RUN_KEY = "hunt_map_run"
FILTER_KEY = "hunt_map_filter"
FOCUS_KEY = "hunt_map_focus"   # per hunt: the start indicator the map and next steps focus on
ALL_INDICATORS = "All indicators"
DEPTH_KEY, DOMAINS_KEY = "hunt_limit_depth", "hunt_limit_domains"
VERDICTS = ("Malicious cluster", "Suspicious", "Benign", "Inconclusive")
OPEN_LOADED, OPEN_OTHER, DONE_SHOWN = 6, 3, 4   # open steps drawn under the loaded run / other runs; done steps
SEVERITIES = (("Critical", "Crit"), ("High", "High"), ("Medium-High", "Med-High"), ("Medium", "Med"), ("Low", "Low"))
SEVERITY_COLORS = SEVERITY_COLORS_ON_DARK
RANK = {name: rank for rank, (name, _) in enumerate(SEVERITIES)}
FILL = {"run": "#2f2f2f", "loaded": "#1f3b57", "done": "#1b5e20", "Branch": "#36404d", "Start": "#5d3a10"}
HEADER = ('digraph { graph [rankdir=LR, bgcolor="transparent", nodesep=0.18, ranksep=0.45]; '
          'node [shape=box, style="rounded,filled", fontname="Courier", fontsize=9, fontcolor="white", '
          'color="#555555", penwidth=0.6, margin="0.08,0.04"]; '
          'edge [color="#888888", arrowsize=0.5, penwidth=0.8, fontname="Courier", fontsize=8, fontcolor="#aaaaaa"];')
# Map options (This hunt → Map options): what each box shows, the layout and the size on the page
DETAILS = {"gain": "New domains & alerts", "types": "Top alert types", "link": "Link to the start",
           "lookup": "Lookup details (use case, window, options, API queries, what led to it)",
           "done": "Followed steps"}
DEFAULT_DETAILS = ("gain", "types", "link", "done")   # hunt_map_dot's default: everything but the lookup details
MAP_DETAILS = ("gain", "link", "done")                # the page's default: compact boxes
LAYOUTS = {"Auto": None, "Left to right": "LR", "Top to bottom": "TB"}
AUTO_LR_RUNS = 3          # Auto: left to right up to this many runs, then top to bottom (a long chain stays readable)
SIZES = ("Fit", "Fill width")
MAP_DETAILS_KEY, MAP_LAYOUT_KEY, MAP_SIZE_KEY, MAP_OPEN_KEY = ("hunt_map_details", "hunt_map_layout",
                                                               "hunt_map_size", "hunt_map_open")
LEGEND = ("Boxes are runs: targets, when, what the run added to the hunt (new domains and alerts), its alerts and "
          "top alert types, and whether its new domains share infrastructure with the starting point (red outline: "
          "drifted, nothing shared). Dashed boxes are steps still open: orange *start here* (an indicator the alerts "
          "name), grey a lead, with score, Iris count and the alerts naming it. Green ✓ steps were followed, on to "
          "the run they started. A step is only ever open once in a hunt.")


def _short(text, limit=26):
    text = str(text)
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _e(text):
    return html.escape(str(text), quote=True)


def _targets(snapshot, limit=2):
    targets = list(snapshot.get("targets") or []) or list(snapshot.get("seeds") or [])
    return ", ".join(_short(t, 24) for t in targets[:limit]) + (f" +{len(targets) - limit}" if len(targets) > limit
                                                                 else "")


def severities(snapshot):
    """{severity: count} of a run's alerts (from its summary, else counted)."""
    counts = ((snapshot.get("summary") or {}).get("by_severity") or {}).copy()
    if not counts:
        for alert in snapshot.get("alerts") or []:
            counts[alert.get("Severity")] = counts.get(alert.get("Severity"), 0) + 1
    return counts


def _alerts_line(snapshot):
    counts = severities(snapshot)
    total = sum(counts.values())
    if not total:
        return '<FONT COLOR="#8bc34a">no alerts</FONT>'
    parts = [f'<FONT COLOR="{SEVERITY_COLORS[name]}">{counts[name]} {short}</FONT>'
             for name, short in SEVERITIES if counts.get(name)][:3]
    return f"{total} alerts: " + " · ".join(parts)


def _types_line(snapshot):
    types = top_types(snapshot)
    return " · ".join(f"{_short(kind, 22)} ×{count}" for kind, count in types)


def lookup_lines(snapshot):
    """What a run looked up: its use case and window, its main collection options, the API queries it made and
    what led to it (lines for the map's *Lookup details*)."""
    options = snapshot.get("options") or {}
    case = find_case(options.get("use_case")) if options.get("use_case") else None
    window = snapshot.get("window") or options.get("analysis_window")
    first = " · ".join(filter(None, [case.title if case else "", window]))
    if options.get("opt_vpndb_only"):
        parts = ["VPNDB IP check only"]
    else:
        parts = [f"DNSDB {int(options['opt_dnsdb_limit']):,}" if options.get("opt_dnsdb_limit") else "",
                 f"CT {options.get('opt_ct_max')}" if options.get("opt_ct") else "",
                 "VPNDB" if options.get("opt_vpndb") else "",
                 f"IP pivots {options.get('opt_pivot_max')}" if options.get("opt_pivot") else ""]
    queries = snapshot.get("queries") or {}
    spent = sum(queries.values())
    lines = [first, " · ".join(filter(None, parts)),
             f"{spent:,} API quer{'y' if spent == 1 else 'ies'}: " + ", ".join(
                 f"{_short(name, 18)} {count:,}" for name, count in sorted(queries.items(), key=lambda kv: -kv[1])[:3]
                 if count) if spent else ""]
    via = (snapshot.get("parent") or {}).get("via")
    if via:
        lines.append("via " + _short(via, 40))
    return [line for line in lines if line]


def _repeat_line(runs, timezone):
    """'4 runs of these targets · first 11-17 08:00': a box standing for a run and its reruns."""
    return _e(f"{len(runs)} runs of these targets · first "
              f"{format_created(runs[0].get('created'), timezone, fmt='%m-%d %H:%M')}")


def _run_label(snapshot, timezone, loaded, gain=None, link=None, root=False, details=DEFAULT_DETAILS, runs=None):
    """A run: targets, when and how many domains, what it added to the hunt, its alerts, link to the start (and the
    other `details`, see DETAILS)."""
    targets = list(snapshot.get("targets") or [])
    rows = [f"<B>{_e(_targets(snapshot))}</B>",
            _e(f"{format_created(snapshot.get('created'), timezone, fmt='%m-%d %H:%M')} · {len(targets)} domain(s)")]
    if runs:
        rows.append(f'<FONT COLOR="#b0bec5">{_repeat_line(runs, timezone)}</FONT>')
    if root:
        rows.append('<FONT COLOR="#90caf9">starting point</FONT>')
    elif gain is not None and "gain" in details:
        color = "#8bc34a" if gain["new_domains"] > CONVERGE_DOMAINS or gain["new_types"] else "#bdbdbd"
        rows.append(f'<FONT COLOR="{color}">' + _e(f"+{gain['new_domains']} new domain(s) · +{gain['new_alerts']} new "
                                                    f"alert(s)" + (f" ({gain['new_high']} High+)" if gain["new_high"]
                                                                   else "")) + "</FONT>")
    rows.append(_alerts_line(snapshot))
    types = _types_line(snapshot) if "types" in details else ""
    if types:
        rows.append(f'<FONT POINT-SIZE="8" COLOR="#cfcfcf">{_e(types)}</FONT>')
    if "lookup" in details:
        rows += [f'<FONT POINT-SIZE="8" COLOR="#b0bec5">{_e(line)}</FONT>' for line in lookup_lines(snapshot)]
    if link is not None and not root and "link" in details:
        rows.append(f'<FONT COLOR="#90caf9">{_e("linked to start: " + link_text(link))}</FONT>' if link else
                    '<FONT COLOR="#ff8a80">no link to start: drifted</FONT>')
    if loaded:
        rows.append('<FONT COLOR="#90caf9">● loaded: next steps below</FONT>')
    return "<" + '<TABLE BORDER="0" CELLSPACING="0" CELLPADDING="1">' + "".join(
        f"<TR><TD>{row}</TD></TR>" for row in rows) + "</TABLE>>"


def step_facts(item):
    """'Iris 4 · 3 alerts (High)' and the like: what an analyst weighs a step by."""
    parts = []
    if item.get("iris"):
        parts.append(f"Iris {int(item['iris']):,}")
    if item.get("alerts"):
        parts.append(f"{item['alerts']} alert(s)" + (f" ({item['worst']})" if item.get("worst") else ""))
    if item.get("domains"):
        parts.append(f"{item['domains']} of your domains")
    return " · ".join(parts)


def _step_label(item):
    head = f"#{item['step']} {item['kind']}" + (f" · score {item['score']}" if item.get("score") is not None else "")
    rows = [f"<B>{_e(head)}</B>", _e(_short(item["value"], 30))]
    facts = step_facts(item)
    if facts:
        rows.append(f'<FONT POINT-SIZE="8">{_e(facts)}</FONT>')
    if item.get("types"):
        rows.append(f'<FONT POINT-SIZE="8" COLOR="#cfcfcf">{_e(", ".join(_short(t, 22) for t in item["types"][:2]))}'
                    "</FONT>")
    if item["source"] == "Start":
        rows.append('<FONT POINT-SIZE="8" COLOR="#ffcc80">start here</FONT>')
    return "<" + '<TABLE BORDER="0" CELLSPACING="0" CELLPADDING="0">' + "".join(
        f"<TR><TD>{row}</TD></TR>" for row in rows) + "</TABLE>>"


def run_plan(snapshot, live=None):
    """The run's suggested steps: the live ones for the loaded run, else those kept with the run."""
    return live if live is not None else list(snapshot.get("plan") or [])


def matches(highlight, snapshot=None, item=None):
    """Whether a run (any of its alerts) or a step (the alerts naming it) fits the alert filter."""
    if not highlight:
        return True
    kind, value = highlight
    if snapshot is not None:
        alerts = snapshot.get("alerts") or []
        if kind == "type":
            return any(a.get("Threat Type") == value for a in alerts)
        return any(RANK.get(a.get("Severity"), 99) <= RANK[value] for a in alerts)
    if kind == "type":
        return value in (item.get("types") or [])
    return RANK.get(item.get("worst"), 99) <= RANK[value]


def run_items(members, live_items=None, loaded_id=None):
    """
    {run id: its steps with "done" and "child"}: steps a run of the hunt followed elsewhere are left out (a step is
    only ever open once), so an older run's saved steps don't come back after the hunt moved on.
    """
    snapshots = [snapshot for _, snapshot, _ in members]
    children = {}
    for snapshot in snapshots[1:]:
        children.setdefault((snapshot.get("parent") or {}).get("id"), []).append(snapshot)
    result = {}
    for snapshot in snapshots:
        own = children.get(snapshot["id"], [])
        elsewhere = followed_values([s for s in snapshots if s not in own])
        items = mark_done(run_plan(snapshot, live_items if snapshot["id"] == loaded_id else None), own)
        result[snapshot["id"]] = [item for item in items if item["done"] or norm(item["value"]) not in elsewhere
                                  and norm(item.get("target") or "") not in elsewhere]
    return result


def _of(item):
    """The start indicators a step belongs to (lower case), or None for a step saved before they were recorded."""
    of = item.get("of")
    return None if of is None else {str(value).lower() for value in of}


def step_in_focus(item, focus):
    """Whether a step belongs to the start indicator `focus` (every step without a focus, or without a record)."""
    of = _of(item)
    return not focus or not of or str(focus).lower() in of


def focus_hunt(members, steps, focus):
    """
    The hunt narrowed to one start indicator: the first run with only the steps that indicator led to, and the runs
    that grew from those steps (with everything after them). A run started otherwise from the first run (Run again,
    a join) stays, as does every step saved before steps recorded their indicator. (members, steps).
    """
    if not focus or len(members) < 1:
        return members, steps
    root_id = members[0][1]["id"]
    led_by = {}
    for item in steps.get(root_id, []):
        if item["done"] and item.get("child"):
            led_by.setdefault(item["child"]["id"], []).append(item)
    keep = {root_id}
    for _, snapshot, _ in members[1:]:
        parent = (snapshot.get("parent") or {}).get("id")
        if parent == root_id:
            ofs = [_of(item) for item in led_by.get(snapshot["id"], []) if _of(item)]
            if not ofs or any(str(focus).lower() in of for of in ofs):
                keep.add(snapshot["id"])
        elif parent in keep:
            keep.add(snapshot["id"])
    kept = [member for member in members if member[1]["id"] in keep]
    narrowed = {run_id: items for run_id, items in steps.items() if run_id in keep}
    narrowed[root_id] = [item for item in steps.get(root_id, []) if step_in_focus(item, focus)
                         and (not item["done"] or item["child"]["id"] in keep)]
    return kept, narrowed


def map_direction(layout, runs):
    """Graphviz rankdir of a map layout (LAYOUTS); Auto turns a hunt of more than AUTO_LR_RUNS runs top to bottom."""
    return LAYOUTS.get(layout) or ("LR" if runs <= AUTO_LR_RUNS else "TB")


def hunt_map_dot(members, timezone="UTC", loaded_id=None, live_items=None, highlight=None, details=DEFAULT_DETAILS,
                 direction="LR", open_limit=OPEN_LOADED, focus=None):
    """
    Graphviz DOT of one hunt: its runs (what each added, its alerts, its link to the first run), the steps each run
    left open (dashed) and the ones followed (✓, on to the run they started). `members`: hunt_members();
    `live_items`: the loaded run's current steps (plan_items()); `highlight`: ("type" | "severity", value);
    `details`: what the boxes show (DETAILS keys); `direction`: "LR" or "TB"; `open_limit`: open steps drawn under
    the loaded run (other runs: at most OPEN_OTHER; 0 draws none); `focus`: a start indicator (focus_hunt).
    """
    members, repeats, alias = collapse_repeats(members)   # reruns of the same targets: one box
    loaded_id = alias.get(loaded_id, loaded_id)
    snapshots = [snapshot for _, snapshot, _ in members]
    by_id = {snapshot["id"]: snapshot for snapshot in snapshots}
    root = snapshots[0]
    gains = run_yield(snapshots)
    links = start_links(snapshots, root)
    steps = run_items(members, live_items, loaded_id)
    members, steps = focus_hunt(members, steps, focus)
    snapshots = [snapshot for _, snapshot, _ in members]
    by_id = {snapshot["id"]: snapshot for snapshot in snapshots}
    children = {}
    for _, snapshot, depth in members:
        if depth:
            children.setdefault((snapshot.get("parent") or {}).get("id"), []).append(snapshot)
    done_into = {}   # run id -> values of the steps that led to it
    for items in steps.values():
        for item in items:
            if item["done"]:
                done_into.setdefault(item["child"]["id"], set()).add(norm(item["value"]))
    lines = [HEADER.replace("rankdir=LR", f"rankdir={direction}")]

    def dim(hit):
        return "" if hit or not highlight else ', fontcolor="#777777", fillcolor="#1c1c1c", color="#333333"'

    for _, snapshot, depth in members:
        run_id = snapshot["id"]
        loaded = run_id == loaded_id
        hit = highlight and matches(highlight, snapshot=snapshot)
        link = links.get(run_id)
        border = ', color="#4c8bf5", penwidth=2' if loaded else ', color="#ff8a80", penwidth=1.5' if \
            link is not None and not link else ""
        if hit:
            border = ', color="#ff5252", penwidth=2.5'
        lines.append(f'"run::{run_id}" [label={_run_label(snapshot, timezone, loaded, gains.get(run_id), link, not depth, details, repeats.get(run_id))}'
                     f', fillcolor="{FILL["loaded" if loaded else "run"]}"{border}{dim(hit)}];')
        if depth > 1 and link and "link" in details:
            lines.append(f'"run::{root["id"]}" -> "run::{run_id}" [style=dotted, color="#6d8fb3", constraint=false, '
                         f'arrowhead=none, label="{_e("shares " + link_text(link, 2))}", fontcolor="#6d8fb3"];')
        items = steps[run_id]
        done = [item for item in items if item["done"]]
        linked = set()
        by_child = {}
        for item in done:
            by_child.setdefault(item["child"]["id"], []).append(item)
        parent_id = (snapshot.get("parent") or {}).get("id")
        for child_id, group in (by_child.items() if "done" in details else ()):
            repeated = [item for item in group if parent_id and norm(item["value"]) in done_into.get(run_id, set())]
            group = [item for item in group if item not in repeated]
            if repeated:   # steps that had already led to this run: one box, not the same steps all over again
                node = f"done::{run_id}::{child_id}::same"
                lines.append(f'"{node}" [label="{_e(f"✓ {len(repeated)} step(s) repeated from before")}", '
                             f'fillcolor="#2e3b2e", color="#43a047", fontcolor="#bbbbbb"];')
                lines.append(f'"run::{run_id}" -> "{node}" [color="#43a047"];')
                lines.append(f'"{node}" -> "run::{child_id}" [color="#43a047"];')
                linked.add(child_id)
            for number, item in enumerate(group[:DONE_SHOWN]):
                node = f"done::{run_id}::{child_id}::{number}"
                lines.append(f'"{node}" [label="{_e("✓ #" + str(item["step"]) + " " + str(item["kind"]))}\\n'
                             f'{_e(_short(item["value"], 28))}", fillcolor="{FILL["done"]}", color="#43a047"];')
                lines.append(f'"run::{run_id}" -> "{node}" [color="#43a047"];')
                lines.append(f'"{node}" -> "run::{child_id}" [color="#43a047"];')
            if len(group) > DONE_SHOWN:
                node = f"done::{run_id}::{child_id}::more"
                lines.append(f'"{node}" [label="✓ +{len(group) - DONE_SHOWN} more step(s)", fillcolor="{FILL["done"]}"];')
                lines.append(f'"run::{run_id}" -> "{node}" [color="#43a047"];')
                lines.append(f'"{node}" -> "run::{child_id}" [color="#43a047"];')
            linked.add(child_id)
        for child in children.get(run_id, []):
            if child["id"] not in linked and child["id"] in by_id:
                via = (child.get("parent") or {}).get("via") or "followed"
                joined = via.startswith("Joined")
                lines.append(f'"run::{run_id}" -> "run::{child["id"]}" [color="{"#ab47bc" if joined else "#43a047"}", '
                             + ("style=bold, " if joined else "") + f'label="{_e(("" if joined else "✓ ") + _short(via, 34))}"];')
        open_ = [item for item in items if not item["done"]]
        limit = int(open_limit) if loaded else min(int(open_limit), OPEN_OTHER)
        for item in open_[:limit]:
            node = f"open::{run_id}::{item['id']}"
            item_hit = highlight and matches(highlight, item=item)
            color = "#ff5252" if item_hit else "#e0882b" if item["source"] == "Start" else "#8fa3bf"
            lines.append(f'"{node}" [label={_step_label(item)}, fillcolor="{FILL[item["source"]]}", '
                         f'style="rounded,filled,dashed", color="{color}"' + (", penwidth=2" if item_hit else "")
                         + f"{dim(item_hit)}];")
            lines.append(f'"run::{run_id}" -> "{node}" [style=dashed, color="#777777"];')
        if len(open_) > limit and limit:
            node = f"open::{run_id}::more"
            lines.append(f'"{node}" [label="+{len(open_) - limit} more open step(s)", style="rounded,dashed", '
                         'fontcolor="#aaaaaa"];')
            lines.append(f'"run::{run_id}" -> "{node}" [style=dashed, color="#777777"];')
        if direction == "TB" and open_[:limit]:   # top to bottom: a run's open steps on its own row, beside it
            row = [f'"open::{run_id}::{item["id"]}"' for item in open_[:limit]]
            row += [f'"open::{run_id}::more"'] if len(open_) > limit else []
            lines.append(f'{{rank=same; "run::{run_id}"; {"; ".join(row)}}}')
            lines += [f'{a} -> {b} [style=invis];' for a, b in zip([f'"run::{run_id}"'] + row, row)]   # in order
    return "\n".join(lines + ["}"])


def hunt_choices(runs, loaded_id=None):
    """{root run id: label} of every hunt (two or more linked runs), and the loaded run's own hunt even when alone."""
    by_id = {snapshot["id"]: snapshot for _, snapshot in runs}
    roots = [row["Run"] for row in hunt_tree(runs) if row["Depth"] == 0]
    loaded_root = hunt_root(runs, loaded_id) if loaded_id in by_id else None
    if loaded_root and loaded_root not in roots:
        roots.append(loaded_root)
    choices = {}
    for root in sorted(roots, key=lambda r: str(by_id[r].get("created")), reverse=True):
        members = hunt_members(runs, root)
        last = max(str(snapshot.get("created")) for _, snapshot, _ in members)
        closed = (by_id[root].get("hunt_result") or {}).get("verdict")
        choices[root] = (f"{_targets(by_id[root], 3)} · {len(members)} run(s) · last {last[5:10]} {last[11:16]}"
                         + (" · loaded" if root == loaded_root else "") + (f" · closed: {closed}" if closed else ""))
    return choices, loaded_root


def short_path(trail):
    """'7h1r0.cc +3 → (4 certificates) snmbml0471.cc +9 → …' for the path to the loaded run."""
    parts = []
    for number, snapshot in enumerate(trail):
        via = (snapshot.get("parent") or {}).get("via") or ""
        steps = len(snapshot.get("seeds") or []) or len(snapshot.get("targets") or [])
        how = f" *({steps} step(s))* → " if via.startswith(("Suggested hunt", "Guided hunt")) else \
            f" *({_short(via, 30)})* → " if via else " → "
        parts.append(("" if not number else how) + f"**{md_escape(_targets(snapshot, 1))}**")
    return "".join(parts)


def _open_steps(members, steps, newest):
    return [item for item in steps.get(newest["id"], []) if not item["done"] and item["action"] in ("Analyze", "Iris")]


def _render_status(status, root_key, root):
    label = STATUS_LABELS[status[0]]
    text = f"**Hunt status: {label}**: {status[1]}."
    if status[0] == "growing":
        st.success(text, icon=":material/trending_up:")
    elif status[0] == "converging":
        st.warning(text + " See the *Hunt result* below and close the hunt, or set wider limits.",
                   icon=":material/trending_flat:")
    elif status[0] == "done":
        st.info(text + " See the *Hunt result* below.", icon=":material/flag:")
    else:
        st.info(text + (f": {root['hunt_result'].get('note')}" if root["hunt_result"].get("note") else ""),
                icon=":material/task_alt:")


def _render_filter(snapshots, key=FILTER_KEY):
    """Alert filter: a severity or a threat type; the runs and steps it applies to stand out on the map."""
    counts = {}
    for snapshot in snapshots:
        for alert in snapshot.get("alerts") or []:
            counts[alert.get("Threat Type")] = counts.get(alert.get("Threat Type"), 0) + 1
    options = ["Everything"] + [f"Severity: {name} or worse" for name, _ in SEVERITIES[:3]] + \
        [f"{kind} ({count})" for kind, count in sorted(counts.items(), key=lambda kv: -kv[1]) if kind]
    choice = st.selectbox("Highlight alerts", options, key=key,
                          help="Outlines in red the runs with such alerts and the open steps those alerts name; the "
                               "rest is dimmed. Shows whether a detection runs through the whole hunt or one branch.")
    if choice == "Everything":
        return None
    if choice.startswith("Severity: "):
        return "severity", choice[len("Severity: "):].removesuffix(" or worse")
    return "type", choice.rsplit(" (", 1)[0]


def _map_options():
    state = st.session_state
    details = [key for key in state.get(MAP_DETAILS_KEY, MAP_DETAILS) if key in DETAILS]
    return (tuple(details), state.get(MAP_LAYOUT_KEY, "Auto"), state.get(MAP_SIZE_KEY, SIZES[0]),
            int(state.get(MAP_OPEN_KEY, OPEN_LOADED)))


def _render_map_options():
    """*Map options*: what the boxes show (add the lookup details as the hunt grows), the layout and the size."""
    state = st.session_state
    state.setdefault(MAP_DETAILS_KEY, list(MAP_DETAILS))
    state.setdefault(MAP_LAYOUT_KEY, "Auto")
    state.setdefault(MAP_SIZE_KEY, SIZES[0])
    state.setdefault(MAP_OPEN_KEY, OPEN_LOADED)
    with st.popover("Map options", icon=":material/tune:", width="stretch"):
        st.multiselect("Show on the map", list(DETAILS), key=MAP_DETAILS_KEY, format_func=DETAILS.get,
                       help="Each run's box always shows its targets, when it ran, how many domains and its alerts. "
                            "Add *Lookup details* to see what each run looked up and how it was reached.")
        st.number_input("Open steps under the loaded run", 0, 20, key=MAP_OPEN_KEY,
                        help=f"Other runs show at most {OPEN_OTHER}. 0 hides the open steps (the list below the "
                             "map still has them).")
        st.segmented_control("Layout", list(LAYOUTS), key=MAP_LAYOUT_KEY, required=True,
                             help=f"Auto: left to right up to {AUTO_LR_RUNS} runs, then top to bottom so a long "
                                  "hunt stays readable.")
        st.segmented_control("Size", SIZES, key=MAP_SIZE_KEY, required=True,
                             help="Fit: the map's own size, shrunk to the page when it is wider. Fill width: "
                                  "stretched to the page width (large for a small hunt).")


def _render_limits():
    with st.popover("Hunt limits", icon=":material/tune:"):
        st.number_input("Runs deep", 2, 12, key=DEPTH_KEY, help="The hunt is done at this many runs from the start")
        st.number_input("Domains in the hunt", 10, 1000, step=10, key=DOMAINS_KEY,
                        help="The hunt is done when its runs have analyzed this many domains")
        st.caption(f"Converging: the newest run added {CONVERGE_DOMAINS} new domains or fewer and no new kind of "
                   "alert.")


def _runs_table(members, timezone, gains, links):
    rows = []
    for _, snapshot, depth in members:
        link = links.get(snapshot["id"])
        rows.append({"Run": format_created(snapshot.get("created"), timezone, fmt="%m-%d %H:%M"),
                     "Targets": _targets(snapshot, 3), "Domains": len(snapshot.get("targets") or []),
                     "New domains": gains[snapshot["id"]]["new_domains"], "Alerts": len(snapshot.get("alerts") or []),
                     "Linked to start": "starting point" if not depth else "no new domains" if link is None else
                     link_text(link) or "no: drifted",
                     "Started from": (snapshot.get("parent") or {}).get("via") or ""})
    return rows


def _render_result(members, root_key, root, status, timezone, label, steps_by_run=None, open_steps=None):
    """The hunt's result: the cluster linked to the start, core indicators, alerts by type; close, report, watch."""
    snapshots = [snapshot for _, snapshot, _ in members]
    result = hunt_result(snapshots, root)
    gains, links = run_yield(snapshots), start_links(snapshots, root)
    with st.expander(f"Hunt result: {len(result['cluster'])} domain(s) linked to the starting point",
                     expanded=status[0] != "growing", icon=":material/summarize:"):
        columns = st.columns(4)
        columns[0].metric("Cluster", len(result["cluster"]), help="Domains of the start, and every domain the hunt "
                                                                   "found that shares a value with them")
        columns[1].metric("Core indicators", len(result["core"]), help="Values two or more cluster domains share")
        columns[2].metric("Alert types", len(result["alerts"]))
        columns[3].metric("Drifted runs", len(result["drifted"]), help="Runs whose new domains share nothing with "
                                                                       "the starting point")
        t_cluster, t_core, t_alerts, t_runs = st.tabs(["Cluster", "Core indicators", "Alerts by type", "Runs"])
        when = {snapshot["id"]: format_created(snapshot.get("created"), timezone, fmt="%m-%d %H:%M")
                for snapshot in snapshots}
        t_cluster.dataframe([{**row, "First run": when.get(row["First run"], "")} for row in result["cluster"]],
                            hide_index=True, width="stretch")
        t_core.dataframe(result["core"][:200], hide_index=True, width="stretch",
                         column_config={"Value": st.column_config.TextColumn(width="large")})
        t_alerts.dataframe(result["alerts"], hide_index=True, width="stretch",
                           column_config={"Threat Type": st.column_config.TextColumn(width="large")})
        runs = _runs_table(members, timezone, gains, links)
        t_runs.dataframe(runs, hide_index=True, width="stretch")
        closed = root.get("hunt_result")
        st.markdown("**Close the hunt**" if not closed else f"**Closed as {closed.get('verdict')}**")
        c_verdict, c_note = st.columns([1, 3])
        verdict = c_verdict.selectbox("Verdict", VERDICTS, key="hunt_verdict",
                                      index=VERDICTS.index(closed["verdict"]) if closed and closed.get("verdict")
                                      in VERDICTS else 0)
        note = c_note.text_input("Note", key="hunt_note", value=(closed or {}).get("note", ""),
                                 placeholder="What the hunt showed and what you recommend")
        with st.container(horizontal=True):
            if st.button("Close hunt" if not closed else "Update verdict", key="hunt_close", type="primary",
                         icon=":material/task_alt:"):
                save_hunt_result(root_key, root["id"], {"verdict": verdict, "note": note})
                st.rerun()
            if closed and st.button("Reopen", key="hunt_reopen", icon=":material/undo:"):
                save_hunt_result(root_key, root["id"], None)
                st.rerun()
            st.download_button("Download hunt report (HTML)",
                               lambda: hunt_report_html(f"Hunt: {label}", members, result, status, steps_by_run,
                                                        open_steps, verdict if closed else None, note,
                                                        timezone).encode("utf-8"),
                               "hunt_report.html", "text/html", icon=":material/download:", on_click="ignore",
                               help="Everything the hunt found in full (the hunt map, every run and the values it "
                                    "followed, indicators by domain, every alert with its evidence, open next "
                                    "steps), as one page that also prints to PDF")
            if st.button("Use in the case report", key="hunt_case", icon=":material/description:",
                         help="Opens Data Export with this result as the case report's summary"):
                st.session_state["report_notes"] = case_summary(label, result, status, verdict, note)
                navigation.go("export")
            domains = [row["Domain"] for row in result["cluster"]]
            if domains and st.button(f"Watch these {len(domains)} domains", key="hunt_watch",
                                     icon=":material/visibility:",
                                     help="Adds the cluster as a watched target list (Runs → Compare & trends → Watched Lists)"):
                save_watch(f"Hunt: {label}", domains)
                st.toast(f"Watching {len(domains)} domains: Runs → Compare & trends → Watched Lists")


def hunt_report_for_run(run_id, timezone="UTC"):
    """
    (file name, HTML) of the hunt report of the hunt that saved run `run_id` belongs to (its whole hunt, from the
    starting run), or None when the run is not saved. Built from the saved runs only, like the Hunt map's download.
    """
    runs = load_all_runs()
    if run_id not in {snapshot["id"] for _, snapshot in runs}:
        return None
    members = hunt_members(runs, hunt_root(runs, run_id))
    snapshots = [snapshot for _, snapshot, _ in members]
    root = snapshots[0]
    steps = run_items(members, None, None)
    newest = max(snapshots, key=lambda snapshot: str(snapshot.get("created")))
    open_steps = _open_steps(members, steps, newest)
    distinct = collapse_repeats(members)[0]
    closed = root.get("hunt_result") or {}
    status = hunt_status([snapshot for _, snapshot, _ in distinct], [depth for _, _, depth in distinct], open_steps,
                         int(st.session_state.get(DEPTH_KEY, MAX_DEPTH)),
                         int(st.session_state.get(DOMAINS_KEY, MAX_DOMAINS)), closed or None)
    label = _targets(root, 3)
    page = hunt_report_html(f"Hunt: {label}", members, hunt_result(snapshots, root), status, steps, open_steps,
                            closed.get("verdict"), closed.get("note", ""), timezone)
    name = "".join(c if c.isalnum() or c in "-." else "_" for c in (root.get("targets") or ["hunt"])[0])
    return f"hunt_report_{name}.html", page


def case_summary(label, result, status, verdict, note):
    """The case report's summary text for a hunt result."""
    core = ", ".join(f"{row['Kind']} {row['Value']} ({row['Domains']})" for row in result["core"][:5])
    alerts = ", ".join(f"{row['Threat Type']} ({row['Domains']}, {row['Worst']})" for row in result["alerts"][:5])
    lines = [f"Hunt from {label}: {STATUS_LABELS[status[0]].lower()} ({status[1]})."
             + (f" Verdict: {verdict}." if verdict else ""),
             f"Cluster: {len(result['cluster'])} domain(s) linked to the starting point.",
             f"Core indicators: {core}." if core else "", f"Alerts: {alerts}." if alerts else "", note]
    return "\n".join(line for line in lines if line)


def _render_run_picker(members, timezone):
    """Pick a run of the hunt: its alerts and actions (Run again, Load offline copy, Compare & trends)."""
    names = {f"{_targets(snapshot)} · {format_created(snapshot.get('created'), timezone, fmt='%m-%d %H:%M')}":
             (key, snapshot) for key, snapshot, _ in members}
    name = st.pills("Run", list(names), key=RUN_KEY, label_visibility="collapsed",
                    help="A run of this hunt: load its offline copy to get its next steps here")
    if not name:
        return
    key, snapshot = names[name]
    counts = severities(snapshot)
    via = (snapshot.get("parent") or {}).get("via")
    st.caption(" · ".join(filter(None, [f"{len(snapshot.get('targets') or [])} domain(s)",
                                        ", ".join(f"{counts[n]} {n}" for n, _ in SEVERITIES if counts.get(n))
                                        or "no alerts", f"started from: {via}" if via else ""])))
    render_run_actions({**snapshot, "key": key}, _offline_by_run(list_offline_datasets()).get(snapshot["id"]),
                       prefix="hunt_map")


def _render_focus(root_id, root, root_items):
    """
    The start indicator to focus the hunt on, when the first run analyzed several: All indicators, or one of its
    targets, each with the steps it led to. Returns the target, or None for all of them.
    """
    targets = list(dict.fromkeys(root.get("seeds") or root.get("targets") or []))
    if len(targets) < 2:
        return None
    key = f"{FOCUS_KEY}::{root_id}"
    if st.session_state.get(key) not in [ALL_INDICATORS, *targets]:
        st.session_state[key] = ALL_INDICATORS

    recorded = any(_of(item) is not None for item in root_items)

    def label(option):
        if option == ALL_INDICATORS or not recorded:
            return option
        own = [item for item in root_items if _of(item) and option.lower() in _of(item)]
        left = sum(1 for item in own if not item["done"])
        return f"{option} · {left} open" if own else f"{option} · no steps"
    picked = st.pills("Focus on a start indicator", [ALL_INDICATORS, *targets], key=key, format_func=label,
                      help="The hunt of one indicator the first run analyzed: its own suggested steps (from its "
                           "alerts and the leads it shares) and the runs that grew from them. All indicators draws "
                           "the whole hunt.")
    if not recorded and root_items:
        st.caption("The first run of this hunt was saved before its steps recorded which indicator they came from, so "
                   "a focus shows every step. Load that run (*Runs of this hunt* → *Load offline copy*, or run it "
                   "again) to split them.")
    return None if picked in (None, ALL_INDICATORS) else picked


def _render_next(ctx, loaded_label, status, leads, steps, children, items, focus=None):
    """
    The loaded run's hunting work: alert decisions, what to check next, the suggested hunt (run it all, pick steps,
    or read each one's reasons) and the other strong leads. `focus`: only what one start indicator led to.
    """
    from core.triage import domain_verdicts, load_triage
    from views.hunt_next_view import render_alert_decisions, render_check_next, render_more_leads
    from views.hunt_plan_view import render_suggested_hunt  # loaded on use
    alerts = ctx.view.active
    if focus:
        alerts = alerts[alerts["Domain"].astype(str).str.lower() == focus.lower()] if not alerts.empty else alerts
        items = [item for item in items if step_in_focus(item, focus)]
        leads = [lead for lead in leads if focus.lower() in {d.strip().lower() for d in
                                                              str(lead.get("Shared With") or "").split(",")}]
        steps = [step for step in steps if focus.lower() in {str(d).lower() for d in step.get("domains") or []}
                 or (step["kind"] == "Lead" and step.get("lead") in leads)]
        loaded_label = focus
    st.markdown(f"#### Next steps from the loaded run · {md_escape(loaded_label)}")
    if not alerts.empty:
        render_alert_decisions(alerts, domain_verdicts(load_triage(), ctx.ds.selected_domains))
    render_check_next(ctx, alerts)
    if not items:
        st.caption("No lead worth following and no open alert naming an indicator: this hunt has nothing left to "
                   "follow from here. See the *Hunt result* above.")
    else:
        if status[0] != "growing":
            st.caption(f":orange[The hunt is {STATUS_LABELS[status[0]].lower()}: {status[1]}. More steps can still "
                       "be run, but the *Hunt result* above is probably the better next move.]")
        with st.container(horizontal=True, vertical_alignment="center"):
            if st.button("Run suggested hunt…", icon=":material/play_arrow:", type="primary" if status[0] == "growing"
                         else "secondary", disabled=not runnable(items),
                         help="Every step in order, ticked: run them all at once or one at a time"):
                run_dialog(items, current_run_id(), loaded_label)
            st.caption("or pick steps:")
        names = {f"#{item['step']} {_short(item['value'], 22)}" + (" ✓" if item["done"] else ""): item
                 for item in items}
        chosen = st.pills("Pick steps", list(names), selection_mode="multi", key="hunt_map_pick",
                          label_visibility="collapsed")
        render_picked(ctx.ds, alerts, [names[name] for name in chosen or []], current_run_id(), key="hunt_map_picked")
    render_suggested_hunt(ctx.ds, alerts, leads, steps, children)
    listed = {norm(item["value"]) for item in items} | {norm(lead["Value"]) for lead in leads if lead["Stop"]}
    render_more_leads(ctx.ds, listed)


def _render_this_hunt(timezone, ctx):
    runs = load_all_runs()
    loaded_id = current_run_id()
    loaded = ctx is not None and getattr(ctx, "ds", None) is not None
    choices, loaded_root = hunt_choices(runs, loaded_id if loaded else None)
    render_guide()
    if not choices:
        st.info("No hunt yet. Analyze targets (or load an offline dataset): the run's suggested steps appear here, "
                "and each step you run grows the map, marked done, with the new run's own next steps.")
        return
    if st.session_state.get(HUNT_KEY) not in choices:
        st.session_state[HUNT_KEY] = loaded_root or next(iter(choices))
    c_hunt, c_limits = st.columns([5, 1], vertical_alignment="bottom")
    root_id = c_hunt.selectbox("Hunt", list(choices), key=HUNT_KEY, format_func=choices.get,
                               help="Each hunt starts at a run and grows with every run started from one of its "
                                    "steps or leads. The loaded run's hunt comes first.")
    st.session_state.setdefault(DEPTH_KEY, MAX_DEPTH)
    st.session_state.setdefault(DOMAINS_KEY, MAX_DOMAINS)
    with c_limits:
        _render_limits()
    members = hunt_members(runs, root_id)
    in_hunt = loaded and any(snapshot["id"] == loaded_id for _, snapshot, _ in members)
    live, plan_parts = None, None
    if in_hunt:
        from views.hunt_plan_view import plan
        leads, steps, children = plan(ctx.ds, ctx.view.active)
        live = plan_items(steps, leads, children)
        plan_parts = (leads, steps, children, live)
        members = hunt_members(load_all_runs(), root_id)   # the plan was just kept with the run
    root_key, root, _ = members[0]
    snapshots = [snapshot for _, snapshot, _ in members]
    steps_by_run = run_items(members, live, loaded_id if in_hunt else None)
    focus = _render_focus(root_id, root, steps_by_run.get(root["id"], []))
    whole = members   # the hunt's every run: joins, detaches and the runs list work on the whole hunt
    if focus:
        members, steps_by_run = focus_hunt(members, steps_by_run, focus)
        snapshots = [snapshot for _, snapshot, _ in members]
    newest = max(snapshots, key=lambda snapshot: str(snapshot.get("created")))
    open_steps = _open_steps(members, steps_by_run, newest)
    distinct = collapse_repeats(members)[0]   # runs of the same targets again add no depth and no domains
    status = hunt_status([snapshot for _, snapshot, _ in distinct], [depth for _, _, depth in distinct], open_steps,
                         int(st.session_state[DEPTH_KEY]), int(st.session_state[DOMAINS_KEY]), root.get("hunt_result"))
    trail = _trail(runs, loaded_id) if in_hunt else []
    if len(trail) > 1:
        st.caption("Path to the loaded run: " + short_path(trail))
    _render_status(status, root_key, root)
    result = hunt_result(snapshots, root)
    columns = st.columns(5)
    columns[0].metric("Runs", len(snapshots))
    columns[1].metric("Domains analyzed", f"{len({t for s in snapshots for t in s.get('targets') or []}):,}")
    columns[2].metric("Distinct alerts", f"{len({(a.get('Domain'), a.get('Threat Type')) for s in snapshots for a in s.get('alerts') or []}):,}",
                      help="Domain and threat type, across the hunt's runs")
    columns[3].metric("Linked to start", len(result["cluster"]), help="Domains of the start, and every domain the "
                                                                       "hunt found that shares a value with them")
    columns[4].metric("Open next steps", len(open_steps), help="Of the newest run, not followed anywhere in the hunt")
    c_filter, c_options = st.columns([5, 1], vertical_alignment="bottom")
    with c_filter:
        highlight = _render_filter(snapshots)
    with c_options:
        _render_map_options()
    details, layout, size, open_limit = _map_options()
    st.graphviz_chart(hunt_map_dot(whole, timezone, loaded_id if in_hunt else None, live,
                                   highlight, details, map_direction(layout, len(members)), open_limit, focus),
                      width="stretch" if size == "Fill width" else "content")   # Fit: its own size, shrunk to the page
    st.caption(LEGEND)
    from views.hunt_combine_view import render_join_controls  # it imports this module
    render_join_controls(runs, whole)
    label = _targets(root, 3)
    _render_result(members, root_key, root, status, timezone, label, steps_by_run, open_steps)
    with st.expander("Runs of this hunt", icon=":material/list:"):
        _render_run_picker(whole, timezone)
    if in_hunt and any(s["id"] == loaded_id for s in snapshots):
        _render_next(ctx, _targets(next(s for s in snapshots if s["id"] == loaded_id), 3), status, *plan_parts,
                     focus=focus if loaded_id == root["id"] else None)
    elif in_hunt:
        st.info(f"The loaded run did not grow from {focus}: pick *{ALL_INDICATORS}* above for its next steps.")
    else:
        st.info("The loaded run is not part of this hunt. Pick one of its runs under *Runs of this hunt* and load "
                "its offline copy (or run it again) to get its next steps with buttons here."
                if loaded else "Load a run of this hunt (*Runs of this hunt* → *Load offline copy*) to get its next "
                               "steps with buttons here.")


def render_hunt_map(timezone="UTC", ctx=None):
    st.header("Hunt map", help="Read from the loaded run and the saved runs (dt_runs/); nothing here makes an API "
                               "call until you click a step's button.")
    st.caption("Where your hunt stands and where to go next: every run, the steps each one suggested (open, or done "
               "and linked to the run they started), and the loaded run's next steps to run.")
    tabs = st.tabs([THIS_TAB, COMBINED_TAB, ALL_TAB, PIVOTS_TAB], key=TAB_KEY, on_change="rerun")
    navigation.scroll_to_tab()
    if tabs[0].open is not False:
        with tabs[0]:
            _render_this_hunt(timezone, ctx)
    if tabs[1].open is not False:
        with tabs[1]:
            from views.hunt_combine_view import render_combined  # it imports this module
            render_combined(timezone, ctx)
    if tabs[2].open is not False:
        with tabs[2]:
            render_hunting_graph(timezone, header=False)
    if tabs[3].open is not False:
        with tabs[3]:
            if ctx is None or ctx.ds is None:
                empty_state("No analysis loaded: the pivots are the values the loaded run's domains share.", "home")
            else:
                from views.pivot_view import render_pivot_lens  # it imports the hunt actions, which import this page
                render_pivot_lens(ctx.ds)
