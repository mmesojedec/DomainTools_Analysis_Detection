"""
Hunt tree (Hunt menu): the hunt the loaded run suggests (its best leads as branches, with the ones already followed)
and every hunt you ran, from its first run to each run started from one of its leads. Both as an indented tree or a
graph.
"""
import html

import streamlit as st

from core.helpers import md_escape
from core.hunt_plan import BRANCHES, followed
from core.hunt_tree import hunt_tree
from core.persistence import load_all_runs
from core.run_history import format_created
from views import navigation
from views.cname_view import _Graph
from views.sidebar import start_hunt

VIEW_KEY = "hunt_tree_view"
VIEWS = ("Tree", "Graph")
LABEL = 34              # characters of a value shown in a graph node
ROOT_COLOR, FOLLOWED_COLOR, SUGGESTED_COLOR, START_COLOR, RUN_COLOR = "#1f3b57", "#2e7d32", "#5b6b7f", "#8a4b08", "#2f2f2f"
EXAMPLE = """```text
example.com                               11-02 09:10 · 4 alerts
  ↳ 185.220.101.5                         11-02 09:25 · 2 alerts · via IP 185.220.101.5
      ↳ login-example.com, pay-example.com  11-02 09:40 · 6 alerts · via Iris search IP 185.220.101.5
  ↳ sha256:3f1c…9a2e                      11-02 10:05 · 1 alert  · via certificate 3f1c…9a2e
```"""


def _short(text, limit=LABEL):
    text = str(text)
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _label(*lines):
    """A Graphviz label: lines escaped for DOT and joined."""
    return "\\n".join(html.escape(str(line)).replace('"', "'") for line in lines if line)


def suggested_dot(targets, leads, steps, children, branches=BRANCHES):
    """
    Graphviz DOT of the loaded run's suggested hunt: the run, its best leads (dashed, with their score; green when a
    run was started from them, then that run), and the Start here steps as a dotted chain.
    """
    graph = _Graph()
    root = "run"
    graph.node(root, ROOT_COLOR, _label("This run", _short(", ".join(targets[:3]) + (
        f" +{len(targets) - 3}" if len(targets) > 3 else ""))), shape="ellipse")
    for number, lead in enumerate([lead for lead in leads if not lead["Stop"]][:branches]):
        node = f"lead::{number}"
        child = followed(lead, children)
        count = f"{lead['Iris Domains']:,} in Iris" if lead["Iris Domains"] else ""
        graph.node(node, FOLLOWED_COLOR if child else SUGGESTED_COLOR,
                   _label(lead["Type"], _short(lead["Value"]), f"score {lead['Score']}" + (f" · {count}" if count else "")))
        graph.edge(root, node, None if child else "dashed", None, "followed" if child else "suggested")
        if child:
            run = f"child::{child.get('id')}"
            alerts = len(child.get("alerts") or [])
            graph.node(run, RUN_COLOR, _label(_short(", ".join(child.get("targets") or [])), f"{alerts} alert(s)"),
                       shape="ellipse")
            graph.edge(node, run)
    previous = root
    for step in [step for step in steps if step["kind"] != "Lead"][:4]:
        node = f"step::{step['step']}"
        graph.node(node, START_COLOR, _label(f"{step['step']}. confirm {step['kind']}", _short(step["value"])))
        graph.edge(previous, node, "dotted", "#c27c0e", "start here" if previous == root else None)
        previous = node
    return graph.dot()


def hunts_dot(rows, timezone="UTC"):
    """Graphviz DOT of every hunt: one node per run, an arrow (labelled with what led there) to each run started from it."""
    graph = _Graph()
    for row in rows:
        node = f"run::{row['Run']}"
        graph.node(node, ROOT_COLOR if row["Depth"] == 0 else RUN_COLOR,
                   _label(_short(row["Targets"]), f"{format_created(row['Created'], timezone, fmt='%m-%d %H:%M')} · "
                                                  f"{row['Alerts']} alert(s)"), shape="ellipse" if row["Depth"] == 0 else "box")
        if row["Parent"]:
            graph.edge(f"run::{row['Parent']}", node, None, None, _short(row["Via"], 28) if row["Via"] else None)
    return graph.dot()


def _render_suggested(ctx, view):
    """The loaded run's suggested hunt (Summary → Suggested hunt) as a tree or a graph."""
    from views.hunt_plan_view import plan, render_suggested_hunt  # the Summary's views; loaded on use
    alerts = ctx.view.active
    leads, steps, children = plan(ctx.ds, alerts)
    if view == "Graph":
        st.markdown("**Suggested hunt for the loaded run**",
                    help="Dashed: suggested branches, with their score. Green: a branch you followed, then the run it "
                         "started. Dotted (orange): where to start, the indicators the open alerts name.")
        if not [lead for lead in leads if not lead["Stop"]] and not steps:
            st.caption("No lead worth following and no open alert naming an indicator.")
        else:
            st.graphviz_chart(suggested_dot(list(ctx.ds.selected_domains), leads, steps, children))
            st.caption("Open the Summary for each branch's reasons, look-ahead and buttons, or switch to *Tree*.")
    else:
        render_suggested_hunt(ctx.ds, alerts, leads, steps, children)


def _render_hunts(rows, timezone, current_run_id, view):
    hunts = sum(row["Depth"] == 0 for row in rows)
    st.markdown(f"**Your hunts** · {hunts} hunt(s), {len(rows)} run(s)",
                help="Runs started from a lead of another run. *Analyze again* reruns a branch's targets at the same "
                     "place in the tree, with the current collection options (live lookups).")
    if view == "Graph":
        st.graphviz_chart(hunts_dot(rows, timezone))
        return
    for row in rows:
        if row["Depth"] == 0 and row is not rows[0]:
            st.divider()
        c_text, c_button = st.columns([6, 1], vertical_alignment="center")
        indent = "&nbsp;" * 6 * row["Depth"] + ("↳ " if row["Depth"] else "")
        via = f" · *via {md_escape(row['Via'])}*" if row["Via"] else ""
        current = " :blue-badge[current]" if row["Run"] == current_run_id else ""
        c_text.markdown(f"{indent}**{md_escape(row['Targets'])}** · {format_created(row['Created'], timezone)} · "
                        f"{row['Alerts']} alert(s){via}{current}")
        c_button.button("Analyze again", key=f"hunt_again::{row['Run']}", on_click=start_hunt,
                        args=(row["Target List"], row["Via"] or "Analyzed again", row["Parent"]), width="stretch",
                        help="Runs this branch's targets again (same place in the tree) with the current options.")


def render_hunt_tree(timezone="UTC", current_run_id=None, ctx=None):
    st.subheader("Hunt tree", help="Read from the loaded run and the saved runs (dt_runs/); no API calls.")
    st.caption("The hunt the loaded run suggests (its best leads, scored as on the Summary) and the hunts you ran: a "
               "run started from a lead, a certificate or an Iris search remembers the run it came from.")
    view = st.segmented_control("View", VIEWS, key=VIEW_KEY, default=VIEWS[0], label_visibility="collapsed") or VIEWS[0]
    loaded = ctx is not None and getattr(ctx, "ds", None) is not None
    if loaded:
        _render_suggested(ctx, view)
        st.divider()
    rows = hunt_tree(load_all_runs())
    if rows:
        _render_hunts(rows, timezone, current_run_id, view)
    elif loaded:
        st.caption("No hunts run yet: *Analyze* or *Find in Iris* on a suggested branch starts one, linked to this run.")
    else:
        st.info("No hunts yet, and no run loaded. Analyze targets or load an offline dataset: the Summary then suggests "
                "where to start and which leads to follow, and this page shows that hunt. Each run you start from a "
                "lead (*Analyze* on a lead, *Analyze its domains* on a certificate, *Analyze the top …* on Iris search "
                "results) is linked to the run it came from.")
        st.markdown("**What a hunt looks like** (an example, not your data):")
        st.markdown(EXAMPLE)
        st.caption("Here the analyst analyzed example.com, followed its hosting IP as a lead, searched Iris for the "
                   "other domains on that IP and analyzed the riskiest ones, then went back and followed the "
                   "self-signed certificate example.com used.")
    navigation.link("hunt_graph", label="See every run over time on the Hunting graph", icon=":material/account_tree:")
