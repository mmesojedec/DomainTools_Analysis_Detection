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
from core.hunt_result import (
    CONVERGE_DOMAINS,
    MAX_DEPTH,
    MAX_DOMAINS,
    STATUS_LABELS,
    followed_values,
    hunt_report_html,
    hunt_result,
    hunt_status,
    link_text,
    norm,
    run_yield,
    start_links,
    top_types,
)
from core.hunt_tree import hunt_members, hunt_root, hunt_tree
from core.hunt_tree import hunt_trail as _trail
from core.offline import list_offline_datasets
from core.persistence import load_all_runs, save_hunt_result, save_watch
from core.run_history import format_created
from views import navigation
from views.history_view import _offline_by_run, render_run_actions
from views.hunt_actions import current_run_id
from views.hunt_run_view import render_guide, render_picked, run_dialog
from views.hunting_graph_view import render_hunting_graph

TAB_KEY = "hunt_map_tab"
THIS_TAB, COMBINED_TAB, ALL_TAB = "This hunt", "Combined hunts", "All investigations"
HUNT_KEY = "hunt_map_hunt"
RUN_KEY = "hunt_map_run"
FILTER_KEY = "hunt_map_filter"
DEPTH_KEY, DOMAINS_KEY = "hunt_limit_depth", "hunt_limit_domains"
VERDICTS = ("Malicious cluster", "Suspicious", "Benign", "Inconclusive")
OPEN_LOADED, OPEN_OTHER, DONE_SHOWN = 6, 3, 4   # open steps drawn under the loaded run / other runs; done steps
SEVERITIES = (("Critical", "Crit"), ("High", "High"), ("Medium-High", "Med-High"), ("Medium", "Med"), ("Low", "Low"))
SEVERITY_COLORS = {"Critical": "#ff6b6b", "High": "#ffa94d", "Medium-High": "#ffd43b", "Medium": "#c0c0c0",
                   "Low": "#9e9e9e"}
RANK = {name: rank for rank, (name, _) in enumerate(SEVERITIES)}
FILL = {"run": "#2f2f2f", "loaded": "#1f3b57", "done": "#1b5e20", "Branch": "#36404d", "Start": "#5d3a10"}
HEADER = ('digraph { graph [rankdir=LR, bgcolor="transparent", nodesep=0.18, ranksep=0.45]; '
          'node [shape=box, style="rounded,filled", fontname="Courier", fontsize=9, fontcolor="white", '
          'color="#555555", penwidth=0.6, margin="0.08,0.04"]; '
          'edge [color="#888888", arrowsize=0.5, penwidth=0.8, fontname="Courier", fontsize=8, fontcolor="#aaaaaa"];')
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


def _run_label(snapshot, timezone, loaded, gain=None, link=None, root=False):
    """A run: targets, when and how many domains, what it added to the hunt, its alerts, link to the start."""
    targets = list(snapshot.get("targets") or [])
    rows = [f"<B>{_e(_targets(snapshot))}</B>",
            _e(f"{format_created(snapshot.get('created'), timezone, fmt='%m-%d %H:%M')} · {len(targets)} domain(s)")]
    if root:
        rows.append('<FONT COLOR="#90caf9">starting point</FONT>')
    elif gain is not None:
        color = "#8bc34a" if gain["new_domains"] > CONVERGE_DOMAINS or gain["new_types"] else "#bdbdbd"
        rows.append(f'<FONT COLOR="{color}">' + _e(f"+{gain['new_domains']} new domain(s) · +{gain['new_alerts']} new "
                                                    f"alert(s)" + (f" ({gain['new_high']} High+)" if gain["new_high"]
                                                                   else "")) + "</FONT>")
    rows.append(_alerts_line(snapshot))
    types = _types_line(snapshot)
    if types:
        rows.append(f'<FONT POINT-SIZE="8" COLOR="#cfcfcf">{_e(types)}</FONT>')
    if link is not None and not root:
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


def hunt_map_dot(members, timezone="UTC", loaded_id=None, live_items=None, highlight=None):
    """
    Graphviz DOT of one hunt: its runs (what each added, its alerts, its link to the first run), the steps each run
    left open (dashed) and the ones followed (✓, on to the run they started). `members`: hunt_members();
    `live_items`: the loaded run's current steps (plan_items()); `highlight`: ("type" | "severity", value).
    """
    snapshots = [snapshot for _, snapshot, _ in members]
    by_id = {snapshot["id"]: snapshot for snapshot in snapshots}
    root = snapshots[0]
    gains = run_yield(snapshots)
    links = start_links(snapshots, root)
    steps = run_items(members, live_items, loaded_id)
    children = {}
    for _, snapshot, depth in members:
        if depth:
            children.setdefault((snapshot.get("parent") or {}).get("id"), []).append(snapshot)
    done_into = {}   # run id -> values of the steps that led to it
    for items in steps.values():
        for item in items:
            if item["done"]:
                done_into.setdefault(item["child"]["id"], set()).add(norm(item["value"]))
    lines = [HEADER]

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
        lines.append(f'"run::{run_id}" [label={_run_label(snapshot, timezone, loaded, gains.get(run_id), link, not depth)}'
                     f', fillcolor="{FILL["loaded" if loaded else "run"]}"{border}{dim(hit)}];')
        if depth > 1 and link:
            lines.append(f'"run::{root["id"]}" -> "run::{run_id}" [style=dotted, color="#6d8fb3", constraint=false, '
                         f'arrowhead=none, label="{_e("shares " + link_text(link, 2))}", fontcolor="#6d8fb3"];')
        items = steps[run_id]
        done = [item for item in items if item["done"]]
        linked = set()
        by_child = {}
        for item in done:
            by_child.setdefault(item["child"]["id"], []).append(item)
        parent_id = (snapshot.get("parent") or {}).get("id")
        for child_id, group in by_child.items():
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
        limit = OPEN_LOADED if loaded else OPEN_OTHER
        for item in open_[:limit]:
            node = f"open::{run_id}::{item['id']}"
            item_hit = highlight and matches(highlight, item=item)
            color = "#ff5252" if item_hit else "#e0882b" if item["source"] == "Start" else "#8fa3bf"
            lines.append(f'"{node}" [label={_step_label(item)}, fillcolor="{FILL[item["source"]]}", '
                         f'style="rounded,filled,dashed", color="{color}"' + (", penwidth=2" if item_hit else "")
                         + f"{dim(item_hit)}];")
            lines.append(f'"run::{run_id}" -> "{node}" [style=dashed, color="#777777"];')
        if len(open_) > limit:
            node = f"open::{run_id}::more"
            lines.append(f'"{node}" [label="+{len(open_) - limit} more open step(s)", style="rounded,dashed", '
                         'fontcolor="#aaaaaa"];')
            lines.append(f'"run::{run_id}" -> "{node}" [style=dashed, color="#777777"];')
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


def _render_result(members, root_key, root, status, timezone, label):
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
            report = hunt_report_html(f"Hunt: {label}", result, runs, status, verdict if closed else None, note)
            st.download_button("Download hunt report (HTML)", report.encode("utf-8"), "hunt_report.html", "text/html",
                               icon=":material/download:", on_click="ignore")
            if st.button("Use in the case report", key="hunt_case", icon=":material/description:",
                         help="Opens Data Export with this result as the case report's summary"):
                st.session_state["report_notes"] = case_summary(label, result, status, verdict, note)
                navigation.go("export")
            domains = [row["Domain"] for row in result["cluster"]]
            if domains and st.button(f"Watch these {len(domains)} domains", key="hunt_watch",
                                     icon=":material/visibility:",
                                     help="Adds the cluster as a watched target list (Runs & Diffs → Watched Lists)"):
                save_watch(f"Hunt: {label}", domains)
                st.toast(f"Watching {len(domains)} domains: Runs & Diffs → Watched Lists")


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
    """Pick a run of the hunt: its alerts and actions (Run again, Load offline copy, Open in Runs & Diffs)."""
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


def _render_next(ctx, loaded_label, status, leads, steps, children, items):
    """
    The loaded run's hunting work: alert decisions, what to check next, the suggested hunt (run it all, pick steps,
    or read each one's reasons) and the other strong leads.
    """
    from core.triage import domain_verdicts, load_triage
    from views.hunt_next_view import render_alert_decisions, render_check_next, render_more_leads
    from views.hunt_plan_view import render_suggested_hunt  # loaded on use
    alerts = ctx.view.active
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
    newest = max(snapshots, key=lambda snapshot: str(snapshot.get("created")))
    open_steps = _open_steps(members, steps_by_run, newest)
    status = hunt_status(snapshots, [depth for _, _, depth in members], open_steps,
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
    highlight = _render_filter(snapshots)
    st.graphviz_chart(hunt_map_dot(members, timezone, loaded_id if in_hunt else None, live, highlight))
    st.caption(LEGEND)
    from views.hunt_combine_view import render_join_controls  # it imports this module
    render_join_controls(runs, members)
    label = _targets(root, 3)
    _render_result(members, root_key, root, status, timezone, label)
    with st.expander("Runs of this hunt", icon=":material/list:"):
        _render_run_picker(members, timezone)
    if in_hunt:
        _render_next(ctx, _targets(next(s for s in snapshots if s["id"] == loaded_id), 3), status, *plan_parts)
    else:
        st.info("The loaded run is not part of this hunt. Pick one of its runs under *Runs of this hunt* and load "
                "its offline copy (or run it again) to get its next steps with buttons here."
                if loaded else "Load a run of this hunt (*Runs of this hunt* → *Load offline copy*) to get its next "
                               "steps with buttons here.")


def render_hunt_map(timezone="UTC", ctx=None):
    st.subheader("Hunt map", help="Read from the loaded run and the saved runs (dt_runs/); nothing here makes an API "
                                  "call until you click a step's button.")
    st.caption("Where your hunt stands and where to go next: every run, the steps each one suggested (open, or done "
               "and linked to the run they started), and the loaded run's next steps to run.")
    tabs = st.tabs([THIS_TAB, COMBINED_TAB, ALL_TAB], key=TAB_KEY, on_change="rerun")
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
