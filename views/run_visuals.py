"""
Visual run views: the Recent runs timeline, run cards and runs-and-detections-per-day chart (Recent runs page), and the Hunting graph
page (Hunt menu). Data comes from core/run_views.py; nothing here makes API calls.
"""
import html
import math

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from core.helpers import md_escape
from core.run_history import SEVERITY_ORDER, format_created
from core.run_views import SEVERITY_COLORS, activity_frame, hunting_graph, shared_indicators, shared_text
from views.common import chart

BADGE = {"Critical": "red", "High": "orange", "Medium-High": "orange", "Medium": "yellow", "Low": "blue"}
LANE_LABEL = 38   # characters of a target list shown on a lane


def _local(created, timezone):
    value = pd.to_datetime(created, errors="coerce", utc=True)
    return value.tz_convert(timezone).tz_localize(None) if pd.notna(value) else value


def _short(text, limit=LANE_LABEL):
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _marker_size(alerts):
    return 12 + min(26, 4 * math.sqrt(max(0, int(alerts or 0))))


def _hover(run, label, timezone, use_case):
    risk = run.get("max_risk")
    lines = [f"<b>{html.escape(label)}</b>", format_created(run["created"], timezone),
             f"{run['alerts']} alert(s), highest: {run['top_severity']}" if run["alerts"] else "No alerts",
             f"Highest Unified Risk: {risk:g}" if risk is not None else "", f"Use case: {use_case}" if use_case else "",
             f"Window: {run['window']}" if run.get("window") else "",
             f"API queries: {run['queries']}" if run.get("queries") is not None else ""]
    return "<br>".join(line for line in lines if line)


def _severity_legend(fig, present):
    """One legend entry per severity present (the run traces themselves stay out of the legend)."""
    for severity in [*SEVERITY_ORDER, "None"]:
        if severity in present:
            fig.add_trace(go.Scatter(x=[None], y=[None], mode="markers", name=severity if severity != "None" else "No alerts",
                                     marker={"size": 11, "color": SEVERITY_COLORS[severity]}, hoverinfo="skip"))


def recent_timeline(runs, labels, timezone, use_cases, selected_id, key="recent_timeline"):
    """
    One lane per target list, one dot per run (size: alerts, color: highest severity). Returns the run id clicked, or
    None. `labels` maps a target list key to its label, `use_cases` a run id to its use case title.
    """
    lanes = list(dict.fromkeys(labels[run["key"]] for run in runs))
    fig = go.Figure()
    for run in runs:
        label = labels[run["key"]]
        selected = run["id"] == selected_id
        fig.add_trace(go.Scatter(
            x=[_local(run["created"], timezone)], y=[_short(label)], mode="markers", showlegend=False,
            customdata=[run["id"]], hovertext=[_hover(run, label, timezone, use_cases.get(run["id"]))],
            hoverinfo="text",
            marker={"size": _marker_size(run["alerts"]), "color": SEVERITY_COLORS[run["top_severity"]],
                    "line": {"width": 3 if selected else 1, "color": "#111827" if selected else "white"}}))
    _severity_legend(fig, {run["top_severity"] for run in runs})
    fig.update_layout(height=max(220, 70 + 46 * len(lanes)), margin={"l": 10, "r": 10, "t": 10, "b": 10},
                      legend={"orientation": "h", "y": -0.25}, xaxis_title=None, yaxis_title=None,
                      yaxis={"categoryorder": "array", "categoryarray": [_short(lane) for lane in reversed(lanes)]})
    return _picked(chart(fig, key=key, selectable=True), [run["id"] for run in runs])


def _picked(points, trace_ids):
    """
    The run id of the first clicked run marker, or None. `trace_ids` is the run id of each trace in drawing order
    (one trace per run): the selection event names the trace even when it leaves out customdata.
    """
    for point in points or []:
        data = point.get("customdata")
        data = data[0] if isinstance(data, (list, tuple)) and data else data
        if isinstance(data, str) and data:
            return data
        curve = point.get("curve_number", point.get("curveNumber"))
        if isinstance(curve, int) and 0 <= curve < len(trace_ids) and trace_ids[curve]:
            return trace_ids[curve]
    return None


SPARK = "▁▂▃▄▅▆▇█"
CARDS_PER_ROW = 4
CARD_INDICATORS = 10   # shared indicators listed in a card's Shares popover


def sparkline(values):
    """A text sparkline ("▂▃▅▇") of the numbers in `values` (None skipped); "" with fewer than two."""
    values = [v for v in values if v is not None]
    if len(values) < 2:
        return ""
    low, high = min(values), max(values)
    span = (high - low) or 1
    return "".join(SPARK[round((v - low) / span * (len(SPARK) - 1))] if high != low else SPARK[3] for v in values)


def _compact_change(change):
    if change is None:
        return ":gray[first run]"
    parts = ([f":red[+{change['new']} new]"] if change["new"] else []) + \
        ([f":green[−{change['resolved']} resolved]"] if change["resolved"] else [])
    return " ".join(parts) or ":gray[no change]"


def _compact_severity(summary):
    by_severity = (summary or {}).get("by_severity") or {}
    badges = [f":{BADGE[s]}-badge[{int(by_severity[s])} {s.lower()}]" for s in SEVERITY_ORDER if by_severity.get(s)]
    return " ".join(badges[:3]) if badges else ":gray-badge[no alerts]"


def _risk_text(run):
    if run.get("max_risk") is None:
        return ""
    trend = [v for v in run["risk_trend"] if v is not None]
    delta = trend[-1] - trend[-2] if len(trend) >= 2 else 0
    arrow = f" :red[↑{delta:g}]" if delta > 0 else f" :green[↓{-delta:g}]" if delta < 0 else ""
    line = sparkline(trend)
    return f"Risk **{run['max_risk']:g}**{arrow}" + (f" :blue[{line}]" if line else "")


def run_card(run, label, timezone, use_case, other_labels, selected, on_select, on_find=None, on_show_all=None):
    """
    One run as a compact card: targets, when and how, severity badges and the change since the previous run of the
    same list, the highest Unified Risk with a sparkline of the list's last runs, Select and, when it shares
    indicators with other lists, a Shares popover: clicking one calls `on_find(value)` (Indicator Sightings).
    Details are in the card's tooltip.
    """
    when = format_created(run["created"], timezone, fmt="%m-%d %H:%M")
    meta = " · ".join(part for part in (when, use_case, run.get("window")) if part)
    shared = run["shared"]
    lines = [f"**{md_escape(_short(label, 32))}**" + (" :blue-badge[selected]" if selected else ""),
             f":gray[{md_escape(meta)}]",
             f"{_compact_severity(run['summary'])} {_compact_change(run['change'])}",
             _risk_text(run)]
    repeats = run.get("repeats") or [run]
    if len(repeats) > 1:   # the list's runs: one card (Show all runs lists each in the Table)
        first = format_created(repeats[-1]["created"], timezone, fmt="%m-%d %H:%M")
        changed = sum(1 for r in repeats if (r.get("change") or {}).get("new") or (r.get("change") or {}).get("resolved"))
        lines.insert(2, f":violet-badge[{len(repeats)} runs] :gray[since {first}"
                        + (f", {changed} with changed alerts]" if changed else ", same alerts]"))
    change = run["change"]
    details = [f"**{md_escape(label)}**", f"{format_created(run['created'], timezone)} · {md_escape(meta)}",
               "First run of this list." if change is None else
               f"Since the previous run: {change['new']} new, {change['resolved']} resolved alert(s).",
               f"Highest Unified Risk over the list's last {len([v for v in run['risk_trend'] if v is not None])} "
               "run(s): " + ", ".join(f"{v:g}" for v in run["risk_trend"] if v is not None)
               if run.get("max_risk") is not None else ""]
    if shared:
        details.append("Shares IPs, name servers, certificates, JA4X, trackers or emails with other target lists, on "
                       "other domains (CDN IPs and large DNS providers left out):\n"
                       + "\n".join(f"- **{md_escape(_short(other_labels.get(other, other), 50))}**: "
                                   f"{md_escape(shared_text(items))}" for other, items in shared.items()))
    with st.container(border=True, gap="small"):
        st.markdown("  \n".join(line for line in lines if line),
                    help="\n\n".join(part for part in details if part))
        with st.container(horizontal=True, gap="small", vertical_alignment="center"):
            st.button("Select", key=f"recent_card::{run['id']}", on_click=on_select, args=(run["id"],),
                      type="tertiary", icon=":material/check_circle:" if selected else ":material/radio_button_unchecked:",
                      disabled=selected, help="Pick this run for Run again, Load offline copy and Compare & trends.")
            if on_show_all is not None and len(repeats) > 1:
                st.button("Show all runs", key=f"recent_card_all::{run['id']}", type="tertiary",
                          icon=":material/table_rows:", on_click=on_show_all, args=(run["key"],),
                          help=f"The Table view with all {len(repeats)} runs of this target list and their details")
            if shared:
                _shared_list(run, other_labels, on_find)


def _shared_list(run, other_labels, on_find):
    """'Shares N' on a card: the indicators the run shares with other lists, each a link to its sightings."""
    indicators = shared_indicators(run, other_labels)
    with st.popover(f"Shares {len(indicators)}", type="tertiary", icon=":material/link:",
                    help=f"Indicators also seen in {len(run['shared'])} other target list(s), on other domains. "
                         "Click one to see everywhere it was observed."):
        for number, row in enumerate(indicators[:CARD_INDICATORS]):
            st.button(f"{row['Kind']}: {row['Indicator']}", key=f"recent_card_find::{run['id']}::{number}",
                      type="tertiary", icon=":material/visibility:", disabled=on_find is None,
                      on_click=on_find, args=(row["Indicator"],),
                      help=f"Where else was it seen? Also in: {row['Also in']}")
        if len(indicators) > CARD_INDICATORS:
            st.caption(f"+{len(indicators) - CARD_INDICATORS} more: select the run for the full list.")


ACTIVITY_COLORS = {"Runs": "#93c5fd", "Hunt runs": "#6d28d9"}
ACTIVITY_SPANS = {"2 weeks": 14, "6 weeks": 42, "12 weeks": 84}


def activity_figure(frame, new_only=True):
    """Runs per day (new investigations and hunt runs) above alerts per day by severity, on one dated axis."""
    from plotly.subplots import make_subplots
    fig = make_subplots(rows=2, cols=1, shared_xaxes=True, vertical_spacing=0.08, row_heights=[0.38, 0.62],
                        subplot_titles=("Runs", "New detections" if new_only else "Alerts found"))
    hover_day = [f"{d:%a %d %b %Y} · week {w}" for d, w in zip(frame["Date"], frame["Week"], strict=True)]
    others = frame["Runs"] - frame["Hunt runs"]
    for name, values, color in (("New investigation", others, ACTIVITY_COLORS["Runs"]),
                                ("Hunt run (from a lead)", frame["Hunt runs"], ACTIVITY_COLORS["Hunt runs"])):
        fig.add_trace(go.Bar(x=frame["Date"], y=values, name=name, marker_color=color, legendgroup="runs",
                             legendgrouptitle_text="Runs", customdata=hover_day,
                             hovertemplate="%{customdata}<br>" + name + ": %{y}<extra></extra>"), row=1, col=1)
    for severity in SEVERITY_ORDER:
        column = f"New {severity}" if new_only else severity
        fig.add_trace(go.Bar(x=frame["Date"], y=frame[column], name=severity, legendgroup="alerts",
                             legendgrouptitle_text="New detections" if new_only else "Alerts",
                             marker_color=SEVERITY_COLORS.get(severity), customdata=hover_day,
                             hovertemplate="%{customdata}<br>" + severity + ": %{y}<extra></extra>"), row=2, col=1)
    span = len(frame)
    mondays = frame[frame["Date"].dt.day_of_week == 0]
    ticks = frame if span <= 14 else mondays   # a tick per day for 2 weeks, else per week (its Monday)
    labels = [f"{d:%a %d %b}<br>W{w}" if span <= 14 else f"W{w}<br>Mon {d:%d %b}"
              for d, w in zip(ticks["Date"], ticks["Week"], strict=True)]
    for monday in mondays["Date"]:   # week boundaries
        fig.add_vline(x=monday - pd.Timedelta(hours=12), line_width=1, line_dash="dot",
                      line_color="rgba(148,163,184,0.45)")
    fig.update_layout(barmode="stack", height=430, bargap=0.15, margin={"l": 10, "r": 10, "t": 30, "b": 10},
                      legend={"groupclick": "toggleitem", "orientation": "h", "yanchor": "top", "y": -0.22,
                              "x": 0, "traceorder": "grouped"}, hovermode="x unified")
    fig.update_xaxes(tickangle=0, range=[frame["Date"].min() - pd.Timedelta(hours=12),
                                         frame["Date"].max() + pd.Timedelta(days=2 if span > 14 else 0.6)])
    fig.update_xaxes(tickvals=ticks["Date"], ticktext=labels, row=2, col=1)
    fig.update_yaxes(rangemode="tozero", tickformat="d")
    return fig


def runs_activity(all_runs, timezone_note=""):
    """Runs and detections per day: when the hunting happened and what it found."""
    c_span, c_kind = st.columns([1, 1.4])
    span = c_span.segmented_control("Period", list(ACTIVITY_SPANS), default="6 weeks", key="recent_activity_span")
    kind = c_kind.segmented_control("Alerts", ["New detections", "All alerts found"], default="New detections",
                                    key="recent_activity_alerts",
                                    help="New detections: a domain and threat type no earlier run had found. All "
                                         "alerts found: every alert of each run, so re-running a list counts again.")
    frame = activity_frame(all_runs, days=ACTIVITY_SPANS.get(span or "6 weeks", 42))
    new_only = (kind or "New detections") == "New detections"
    chart(activity_figure(frame, new_only))
    alert_columns = [f"New {s}" if new_only else s for s in SEVERITY_ORDER]
    alerts = int(frame[alert_columns].sum().sum())
    high = int(frame[alert_columns[:2]].sum().sum())
    st.caption(f"{int(frame['Runs'].sum())} run(s), {int(frame['Hunt runs'].sum())} of them hunt runs, and {alerts} "
               f"{'new detection(s)' if new_only else 'alert(s)'} ({high} Critical or High) from "
               f"{frame['Date'].min():%a %d %b} (week {frame['Week'].iloc[0]}) to {frame['Date'].max():%a %d %b} "
               f"(week {frame['Week'].iloc[-1]}), UTC days" + timezone_note + ".")


# --- Hunting graph ----------------------------------------------------------------------------------------------------
def _edge_kinds(edge, kinds):
    return [item for item in edge.get("items", []) if item[0] in kinds]


def hunting_figure(nodes, edges, labels, timezone, selected_id, kinds):
    """
    (figure, run id per trace): runs on a time × target list grid; solid arrows from a run to the run started from
    one of its leads, dashed lines between target lists that share artifacts of `kinds` (width: how many).
    """
    lanes = list(dict.fromkeys(labels[node["key"]] for node in nodes))
    lane_y = {lane: len(lanes) - 1 - i for i, lane in enumerate(lanes)}   # first lane at the top
    position = {node["id"]: (_local(node["created"], timezone), lane_y[labels[node["key"]]]) for node in nodes}
    fig = go.Figure()
    mid_x, mid_y, mid_text = [], [], []
    for edge in edges:
        if edge["source"] not in position or edge["target"] not in position:
            continue
        (x0, y0), (x1, y1) = position[edge["source"]], position[edge["target"]]
        if edge["kind"] == "lead":
            fig.add_annotation(x=x1, y=y1, ax=x0, ay=y0, xref="x", yref="y", axref="x", ayref="y", showarrow=True,
                               arrowhead=3, arrowsize=1.2, arrowwidth=2, arrowcolor="#6d28d9", standoff=10,
                               startstandoff=10, text="")
            mid_text.append(f"Lead: {html.escape(edge.get('via') or 'started from this run')}")
        else:
            items = _edge_kinds(edge, kinds)
            if not items:
                continue
            fig.add_trace(go.Scatter(x=[x0, x1], y=[y0, y1], mode="lines", showlegend=False, hoverinfo="skip",
                                     line={"color": "#0f766e", "dash": "dash", "width": 1 + min(5, len(items) / 3)}))
            mid_text.append("Shared: " + html.escape(shared_text(items, limit=6)))
        mid_x.append(x0 + (x1 - x0) / 2)
        mid_y.append((y0 + y1) / 2)
    if mid_x:   # invisible markers in the middle of each link carry its hover text
        fig.add_trace(go.Scatter(x=mid_x, y=mid_y, mode="markers", marker={"size": 10, "color": "rgba(0,0,0,0)"},
                                 hovertext=mid_text, hoverinfo="text", showlegend=False))
    trace_ids = [None] * len(fig.data)   # the run id of each trace, for clicks
    for node in nodes:
        trace_ids.append(node["id"])
        label = labels[node["key"]]
        selected = node["id"] == selected_id
        text = [f"<b>{html.escape(label)}</b>", format_created(node["created"], timezone),
                f"{node['alerts']} alert(s), highest: {node['top_severity']}" if node["alerts"] else "No alerts",
                f"Highest Unified Risk: {node['max_risk']:g}" if node.get("max_risk") is not None else "",
                f"Started from a lead: {html.escape(node['via'])}" if node.get("via") else ""]
        fig.add_trace(go.Scatter(
            x=[position[node["id"]][0]], y=[position[node["id"]][1]], mode="markers", showlegend=False,
            customdata=[node["id"]], hovertext=["<br>".join(t for t in text if t)], hoverinfo="text",
            marker={"size": _marker_size(node["alerts"]), "color": SEVERITY_COLORS[node["top_severity"]],
                    "line": {"width": 3 if selected else 1, "color": "#111827" if selected else "white"}}))
    _severity_legend(fig, {node["top_severity"] for node in nodes})
    fig.add_trace(go.Scatter(x=[None], y=[None], mode="lines", name="Started from a lead",
                             line={"color": "#6d28d9", "width": 2}))
    fig.add_trace(go.Scatter(x=[None], y=[None], mode="lines", name="Shares artifacts",
                             line={"color": "#0f766e", "dash": "dash", "width": 2}))
    fig.update_layout(height=max(320, 90 + 40 * len(lanes)), margin={"l": 10, "r": 10, "t": 10, "b": 10},
                      legend={"orientation": "h", "y": -0.12},
                      yaxis={"tickmode": "array", "tickvals": [lane_y[lane] for lane in lanes],
                             "ticktext": [_short(lane) for lane in lanes], "range": [-0.6, len(lanes) - 0.4],
                             "zeroline": False})
    return fig, trace_ids


def graph_data(all_runs, max_runs, kinds, linked_only):
    """(nodes, edges) of the Hunting graph, without isolated runs when `linked_only`."""
    nodes, edges = hunting_graph(all_runs, max_runs=max_runs)
    edges = [edge for edge in edges if edge["kind"] == "lead" or _edge_kinds(edge, kinds)]
    if linked_only:
        linked = {edge["source"] for edge in edges} | {edge["target"] for edge in edges}
        nodes = [node for node in nodes if node["id"] in linked]
    return nodes, edges


