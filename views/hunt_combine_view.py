"""
Combined hunts (Hunt map tab) and joining hunts: pick several hunts and see them on one map, each hunt in its own frame,
with dashed links between runs of different hunts that recorded the same values (certificate, IP, name server,
tracker, email, or a domain both analyzed), and one result over all of them. *Join* makes hunts one for good (the
joined hunt's first run is attached to the run of the other hunt it shares the most with); *Detach* undoes it.
Reading makes no API call.
"""
from collections import Counter

import streamlit as st

from core.hunt_combine import best_anchor, combined_result, cross_links, hunt_roots, related_hunts, run_values
from core.hunt_result import link_text, run_yield
from core.hunt_tree import collapse_repeats, hunt_members, hunt_root
from core.persistence import detach_run, join_run, load_all_runs, save_watch
from core.run_history import format_created
from views.hunt_actions import current_run_id
from views.hunt_map_view import (
    FILL,
    HEADER,
    HUNT_KEY,
    TAB_KEY,
    THIS_TAB,
    _e,
    _render_filter,
    _run_label,
    _short,
    _targets,
    matches,
)

PICK_KEY = "hunt_combine_pick"
FILTER_KEY = "hunt_combine_filter"
MAIN_KEY = "hunt_combine_main"
DEFAULT_RELATED = 2   # related hunts picked with the loaded one at first
FRAMES = ("#4c8bf5", "#e0882b", "#43a047", "#ab47bc", "#26a69a", "#ef5350")   # one frame color per hunt


def hunt_label(runs, root_id, members=None):
    members = members or hunt_members(runs, root_id)
    root = members[0][1]
    last = max(str(snapshot.get("created")) for _, snapshot, _ in members)
    return f"{_targets(root, 3)} · {len(members)} run(s) · last {last[5:10]} {last[11:16]}"


def joined_text(counter):
    return "Joined: shares " + link_text(counter, 3) if counter else "Joined by hand"


def join_hunt(runs, root_id, main_id):
    """Attaches hunt `root_id` to the run of hunt `main_id` it shares the most with. Returns that run id."""
    members = hunt_members(runs, main_id)
    key, root, _ = hunt_members(runs, root_id)[0]
    anchor = best_anchor(members, root)
    anchor_snapshot = next(snapshot for _, snapshot, _ in members if snapshot["id"] == anchor)
    shared = Counter(kind for kind, _ in run_values(root) & run_values(anchor_snapshot))
    join_run(key, root_id, anchor, joined_text(shared))
    return anchor


def _join_all(roots, main):
    """Button callback (before the page is drawn, so it may set the widgets' state): joins, then opens the hunt."""
    runs = load_all_runs()
    for root in roots:
        if root != main:
            join_hunt(runs, root, main)
    st.session_state[HUNT_KEY] = main
    st.session_state[PICK_KEY] = [main]
    st.session_state[TAB_KEY] = THIS_TAB


def _join_one(root_id):
    target = st.session_state.get("hunt_join_target")
    if target:
        join_hunt(load_all_runs(), root_id, target)
        st.session_state[HUNT_KEY] = target


def _detach(key, run_id):
    detach_run(key, run_id)


def combined_dot(hunts, labels, timezone="UTC", loaded_id=None, highlight=None, links=()):
    """
    Graphviz DOT of several hunts (`hunts`: {root id: members}): each hunt in a frame with its runs and the links
    between them, and dashed links between runs of different hunts that share values (`links`: cross_links()).
    """
    collapsed = {root_id: collapse_repeats(members) for root_id, members in hunts.items()}   # reruns: one box
    hunts = {root_id: members for root_id, (members, _, _) in collapsed.items()}
    repeats = {run_id: runs for _, found, _ in collapsed.values() for run_id, runs in found.items()}
    alias = {run_id: kept for _, _, found in collapsed.values() for run_id, kept in found.items()}
    loaded_id = alias.get(loaded_id, loaded_id)
    links = [{**link, "source": alias.get(link["source"], link["source"]),
              "target": alias.get(link["target"], link["target"])} for link in links]
    links = list({(link["source"], link["target"]): link for link in reversed(links)}.values())[::-1]   # once a pair
    snapshots = [snapshot for members in hunts.values() for _, snapshot, _ in members]
    gains = run_yield(snapshots)
    lines = [HEADER.replace("rankdir=LR", "rankdir=TB").replace("nodesep=0.18", "nodesep=0.35")]   # hunts side by side

    def dim(hit):
        return "" if hit or not highlight else ', fontcolor="#777777", fillcolor="#1c1c1c", color="#333333"'

    for number, (root_id, members) in enumerate(hunts.items()):
        color = FRAMES[number % len(FRAMES)]
        lines.append(f'subgraph "cluster_{number}" {{ label="{_e(f"Hunt {number + 1}: " + _short(labels[root_id].split(" · ")[0], 34))}";'
                     f' fontname="Courier"; fontsize=10; fontcolor="{color}"; color="{color}"; style="rounded,dashed";')
        ids = {snapshot["id"] for _, snapshot, _ in members}
        for _, snapshot, depth in members:
            run_id = snapshot["id"]
            loaded = run_id == loaded_id
            hit = highlight and matches(highlight, snapshot=snapshot)
            border = ', color="#ff5252", penwidth=2.5' if hit else ', color="#4c8bf5", penwidth=2' if loaded else ""
            lines.append(f'"run::{run_id}" [label={_run_label(snapshot, timezone, loaded, gains.get(run_id), None, not depth, runs=repeats.get(run_id))}'
                         f', fillcolor="{FILL["loaded" if loaded else "run"]}"{border}{dim(hit)}];')
            parent = (snapshot.get("parent") or {}).get("id")
            if depth and parent in ids:
                via = (snapshot.get("parent") or {}).get("via") or "followed"
                style = ', style=bold, color="#ab47bc"' if via.startswith("Joined") else ', color="#43a047"'
                lines.append(f'"run::{parent}" -> "run::{run_id}" [label="{_e(_short(via, 22))}"{style}];')
        lines.append("}")
    for link in links:
        width = 1 + min(4, len(link["values"]) / 4)
        lines.append(f'"run::{link["source"]}" -> "run::{link["target"]}" [dir=none, style=dashed, color="#26c6da", '
                     f'penwidth={width:.1f}, constraint=false, fontcolor="#26c6da", '
                     f'label="{_e(short_link(link["shared"]))}"];')
    return "\n".join(lines + ["}"])


SHORT_KINDS = {"Certificate": "Cert", "Web Tracker": "Tracker", "Name Server": "NS", "Domain": "Domain"}


def short_link(counter, limit=2):
    """'18 Cert · 12 IP': a cross-hunt link's label on the map (the full list is under *Connections*)."""
    return " · ".join(f"{count} {SHORT_KINDS.get(kind, kind)}" for kind, count in counter.most_common(limit))


def _connections(links, by_id, timezone):
    rows = []
    for link in links:
        a, b = by_id[link["source"]], by_id[link["target"]]
        rows.append({"Run": f"{_targets(a, 2)} · {format_created(a.get('created'), timezone, fmt='%m-%d %H:%M')}",
                     "Other run": f"{_targets(b, 2)} · {format_created(b.get('created'), timezone, fmt='%m-%d %H:%M')}",
                     "Shared": link_text(link["shared"], 6),
                     "Values": ", ".join(value for _, value in link["values"][:8])
                     + (f" +{len(link['values']) - 8}" if len(link["values"]) > 8 else "")})
    return rows


def _render_result(hunts, labels):
    result = combined_result(hunts)
    with st.expander(f"Combined result: {len(result['cluster'])} domain(s) linked to the starting points",
                     icon=":material/summarize:"):
        columns = st.columns(3)
        columns[0].metric("Cluster", len(result["cluster"]), help="The hunts' starting domains, and every domain any "
                                                                   "of the hunts found that shares a value with them")
        columns[1].metric("Core indicators", len(result["core"]), help="Values two or more cluster domains share")
        columns[2].metric("Alert types", len(result["alerts"]))
        t_cluster, t_core, t_alerts = st.tabs(["Cluster", "Core indicators", "Alerts by type"])
        t_cluster.dataframe([{k: v for k, v in row.items() if k != "First run"} for row in result["cluster"]],
                            hide_index=True, width="stretch")
        t_core.dataframe(result["core"][:200], hide_index=True, width="stretch",
                         column_config={"Value": st.column_config.TextColumn(width="large")})
        t_alerts.dataframe(result["alerts"], hide_index=True, width="stretch",
                           column_config={"Threat Type": st.column_config.TextColumn(width="large")})
        domains = [row["Domain"] for row in result["cluster"]]
        if domains and st.button(f"Watch these {len(domains)} domains", key="hunt_combine_watch",
                                 icon=":material/visibility:",
                                 help="Adds the combined cluster as a watched target list (Runs → Compare & trends → Watched Lists)"):
            name = " + ".join(_short(labels[root].split(" · ")[0], 30) for root in hunts)
            save_watch(f"Hunts: {name}", domains)
            st.toast(f"Watching {len(domains)} domains: Runs → Compare & trends → Watched Lists")


def _render_join(hunts, labels):
    """Join the picked hunts into one, for good (each other hunt attaches where it shares the most)."""
    roots = list(hunts)
    st.markdown("**Join them into one hunt**", help="Each other hunt's first run is attached to the run of the main "
                                                    "hunt it shares the most with. From then on they are one hunt "
                                                    "everywhere (map, status, result). *Detach* on the Hunt map "
                                                    "undoes it.")
    if st.session_state.get(MAIN_KEY) not in roots:
        st.session_state[MAIN_KEY] = roots[0]
    c_main, c_button = st.columns([3, 1], vertical_alignment="bottom")
    main = c_main.selectbox("Main hunt", roots, key=MAIN_KEY, format_func=labels.get)
    c_button.button(f"Join {len(roots) - 1} hunt(s) to it", key="hunt_combine_join", icon=":material/merge:",
                    width="stretch", on_click=_join_all, args=(roots, main))


def render_combined(timezone="UTC", ctx=None):
    runs = load_all_runs()
    if not runs:
        st.info("No saved runs yet.")
        return
    roots = hunt_roots(runs)
    members_of = {root: hunt_members(runs, root) for root in roots}
    labels = {root: hunt_label(runs, root, members_of[root]) for root in roots}
    loaded_id = current_run_id()
    base = hunt_root(runs, loaded_id) if loaded_id else None
    base = base if base in members_of else roots[0]
    related = related_hunts(runs, base, roots)
    shares = {other: counter for other, counter in related}
    order = [base] + [other for other, _ in related] + [root for root in roots if root != base and root not in shares]
    st.caption("Pick hunts to see on one map. Hunts that share values with the loaded hunt are listed first, with "
               "what they share; each hunt keeps its own frame, and dashed lines join runs of different hunts that "
               "recorded the same certificate, IP, name server, tracker, email or domain.")
    if PICK_KEY not in st.session_state or not set(st.session_state[PICK_KEY]) <= set(order):
        st.session_state[PICK_KEY] = [base] + [other for other, _ in related[:DEFAULT_RELATED]]

    def option(root):
        extra = (" · loaded" if root == base else "") + (f" · shares {link_text(shares[root], 3)}" if root in shares
                                                          else "")
        return labels[root] + extra

    picked = st.multiselect("Hunts", order, key=PICK_KEY, format_func=option,
                            help="Every hunt, single runs included; the related ones come first")
    if len(picked) < 2:
        st.info("Pick two or more hunts." + ("" if related else " No other hunt shares values with the loaded one."))
        return
    hunts = {root: members_of[root] for root in picked}
    links = cross_links(hunts)
    snapshots = [snapshot for members in hunts.values() for _, snapshot, _ in members]
    columns = st.columns(4)
    columns[0].metric("Hunts", len(hunts))
    columns[1].metric("Runs", len(snapshots))
    columns[2].metric("Domains analyzed", f"{len({t for s in snapshots for t in s.get('targets') or []}):,}")
    columns[3].metric("Links between hunts", len(links), help="Pairs of runs of different hunts that share values "
                                                               "(the strongest few per pair of hunts)")
    highlight = _render_filter(snapshots, key=FILTER_KEY)
    st.graphviz_chart(combined_dot(hunts, labels, timezone, loaded_id, highlight, links), width="content")   # its own size, shrunk to the page when wider
    st.caption("Each frame is one hunt; purple bold arrows are joined hunts. Dashed cyan lines: runs of different "
               "hunts that share values (thicker: more values).")
    unlinked = [root for root in picked if not any(root_of(hunts, link["source"]) == root
                                                   or root_of(hunts, link["target"]) == root for link in links)]
    if unlinked:
        st.caption(":orange[Nothing shared with the other picked hunts: "
                   + ", ".join(_short(labels[root].split(" · ")[0], 40) for root in unlinked) + ".]")
    if links:
        by_id = {snapshot["id"]: snapshot for snapshot in snapshots}
        with st.expander(f"Connections between the hunts: {len(links)}", icon=":material/link:"):
            st.dataframe(_connections(links, by_id, timezone), hide_index=True, width="stretch",
                         column_config={"Values": st.column_config.TextColumn(width="large")})
    _render_result(hunts, labels)
    _render_join(hunts, labels)


def root_of(hunts, run_id):
    return next((root for root, members in hunts.items() if any(s["id"] == run_id for _, s, _ in members)), None)


def render_join_controls(runs, members):
    """
    On *This hunt*: *Detach* for each run that was joined in, and *Join to another hunt* (the hunts sharing the most
    with this one first).
    """
    joined = [(key, snapshot) for key, snapshot, depth in members if depth and "joined" in snapshot]
    for key, snapshot in joined:
        c_text, c_button = st.columns([5, 1], vertical_alignment="center")
        c_text.caption(f":material/merge: **{_e(_targets(snapshot, 2))}** was joined to this hunt "
                       f"({_e((snapshot.get('parent') or {}).get('via', ''))}).")
        c_button.button("Detach", key=f"hunt_detach::{snapshot['id']}", icon=":material/call_split:",
                        help="It starts its own hunt again, as before the join", on_click=_detach,
                        args=(key, snapshot["id"]))
    root_id = members[0][1]["id"]
    with st.popover("Join to another hunt", icon=":material/merge:"):
        related = related_hunts(runs, root_id, limit=15)
        if not related:
            st.caption("No other hunt shares a value with this one. Combined hunts lists every hunt.")
            return
        labels = {other: hunt_label(runs, other) + " · shares " + link_text(counter, 3) for other, counter in related}
        target = st.selectbox("Join this hunt to", list(labels), format_func=labels.get, key="hunt_join_target",
                              help="This hunt's first run is attached to the run of that hunt it shares the most "
                                   "with; they become one hunt. Detach undoes it.")
        st.button("Join", key="hunt_join", type="primary", icon=":material/merge:", on_click=_join_one,
                  args=(root_id,), disabled=not target)
