"""CNAME Chains lens: where each hostname's CNAME redirects lead, chased to the final addresses like DNSDB Scout."""
import pandas as pd
import streamlit as st

from config import (
    CNAME_CHASE_MAX_STEPS,
    CNAME_CHASE_QUERIES_PER_DOMAIN,
    CNAME_RDATA_MAX_PER_CLICK,
    CNAME_RDATA_RECORD_LIMIT,
)
from core.cname import (
    COLLECTED,
    LINK_KINDS,
    NOT_CHASED,
    QUERY_LIMIT,
    SERVICE_TYPES,
    SHARED_SERVICE_TYPES,
    chase_plan,
    cname_links,
    dataset_cname_map,
    full_path,
    merge_chases,
    merge_rdata,
    order_by_domain,
    rdata_candidates,
    rdata_summary,
    related_domains,
)
from core.hostnames import clean_hostname
from integrations.collector import chase_cnames, reverse_cnames
from integrations.credentials import load_dnsdb_key
from integrations.dnsdb import CHASE_OUTCOMES
from integrations.http import StatusLog
from views.common import selected_rows, selection_key
from views.sidebar import APP_RERUN_KEY, TOAST_KEY, rerun_app_if_requested

OTHER = "Other"
TABLE_COLUMNS = ["Domain", "Hostname", "Target", "Count", "Chased", "From Cache", "Cached At", "Chased At", "Chase Age",
                 "Chain",
                 "Current", "Service Type", "Service", "Outcome", "Hops", "Final", "Last Seen", "First Seen", "Note"]
ORDERS = {"Domain, then count": (["_domain", "Count", "Last Seen"], [True, False, False]),
          "Count": (["Count", "Last Seen"], [False, False]),
          "Last seen": (["Last Seen", "Count"], [False, False])}
REVEALED_KEY = "cname_revealed"   # "hostname|target" of the rows the analyst chased (their chains are shown)
NOT_CHASED_NOTE = "Not chased yet: select the hostnames and click Chase CNAMEs"
OUTCOMES = {**{k: v for k, v in CHASE_OUTCOMES.items() if k != QUERY_LIMIT},
            NOT_CHASED: "Not chased yet, or the chain leaves the collected data and DNSDB was not asked yet"}
COLUMN_HELP = {
    "Hostname": "Name of the run that has the CNAME record",
    "Target": "The name the CNAME points to",
    "Current": "The hostname's most recent CNAME target, not replaced by A / AAAA records since",
    "Service Type": "; ".join(f"{kind}: {text}" for kind, text in SERVICE_TYPES.items())
                    + f"; {OTHER}: not on any of the known service lists (an ordinary domain, often the operator's own)",
    "Service": "The provider or platform the target belongs to, from the known service lists (empty for Other)",
    "Outcome": "; ".join(f"{name}: {text}" for name, text in OUTCOMES.items()),
    "Hops": "CNAMEs followed from the hostname to the end of the chain",
    "Count": "Times DNSDB saw this hostname → target CNAME (its count): the busiest CNAMEs are the most used",
    "Chased": "The chain was chased: filled in when you chase the hostname (from the collected passive DNS, free, or "
              "DNSDB lookups)",
    "From Cache": "Every DNSDB lookup of the chase came from the lookup cache (Settings → Lookup cache), so the chain is "
                  "as DNSDB knew it at Chased at. Re-chase it for fresh lookups",
    "Chased At": "When the chase's DNSDB lookups were made (for cached ones, when they were first fetched). Empty when "
                 "the chain resolved in the collected passive DNS",
    "Cached At": "From cache: when the cached DNSDB lookups were made (they expire after the Cache lifetime (Settings))",
    "Chase Age": "How long ago that was",
    "Chain": "Filled in once chased: the analyzed domain → the hostname → every CNAME after it → the final addresses, "
             "through the collected passive DNS and then the DNSDB chase",
    "Final": "Addresses of the last name (A / AAAA seen within a day of its latest record)",
    "Last Seen": "Last time passive DNS saw this hostname → target record",
    "First Seen": "First time passive DNS saw this hostname → target record",
    "Note": "Where the chain was resolved, or why it stopped",
}
GRAPH_MAX_CHAINS = 40
NODE_COLORS = {"Dynamic DNS / tunnel": "#e45756", "Takeover-prone": "#f58518", "Free hosting": "#b279a2",
               "CDN": "#4c78a8", "Parking": "#7f7f7f", "": "#72b7b2"}
HISTORY_COLOR = "#bbbbbb"
LINK_COLORS = {"CNAME into analyzed domain": "#e45756", "Shared CNAME": "#f58518", "Shared final address": "#2ca02c"}
GRAPH_HEADER = ('digraph { graph [rankdir=LR, bgcolor="transparent", nodesep=0.12, ranksep=0.3]; '
                'node [shape=box, style="rounded,filled", fontname="Courier", fontsize=8, height=0.2, '
                'margin="0.1,0.04", fontcolor="white", color="#555555", penwidth=0.5]; '
                'edge [color="#888888", arrowsize=0.5, penwidth=0.7];')


class _Graph:
    """Compact Graphviz DOT builder: each node once, labels separate from ids."""

    def __init__(self):
        self.lines, self.seen, self.clusters = [GRAPH_HEADER], set(), {}

    def node(self, node_id, color, label=None, shape="box", cluster=None):
        """`cluster`: draw the node inside a dashed box with the other nodes of that cluster (one per domain)."""
        if node_id not in self.seen:
            self.seen.add(node_id)
            line = f'"{node_id}" [label="{label or node_id}", fillcolor="{color}", shape={shape}];'
            (self.clusters.setdefault(cluster, []) if cluster else self.lines).append(line)

    def edge(self, a, b, style=None, color=None, label=None):
        attrs = ", ".join(filter(None, [f"style={style}" if style else "", f'color="{color}"' if color else "",
                                        f'label="{label}", fontsize=7, fontcolor="#999999"' if label else ""]))
        self.lines.append(f'"{a}" -> "{b}"' + (f" [{attrs}];" if attrs else ";"))

    def dot(self):
        # emitted last-first: a left-to-right layout stacks the first declared cluster at the bottom
        clusters = [f'subgraph "cluster_{i}" {{ style="rounded,dashed"; color="#999999"; label=""; {" ".join(lines)} }}'
                    for i, lines in reversed(list(enumerate(self.clusters.values())))]
        return "\n".join(self.lines[:1] + clusters + self.lines[1:] + ["}"])


def chain_groups(rows, limit=None, by_hostname=False):
    """
    Rows grouped by (domain, chain after the hostname, hostname when `by_hostname`): many hostnames aliasing the same
    target draw as one node unless expanded. Groups keep the row order (order_by_domain); with `limit`, every domain's
    first groups are kept before any domain's later ones.
    """
    rest = rows["Chain"].str.split(" → ").str[1:].str.join(" → ")
    host = rows["Hostname"] if by_hostname else ""
    groups = list(rows.assign(_rest=rest, _host=host).groupby(["Domain", "_rest", "_host"], sort=False))
    if limit is None or len(groups) <= limit:
        return groups
    turns, seen = [], {}
    for (domain, _, _), _group in groups:
        seen[domain] = seen.get(domain, -1) + 1
        turns.append(seen[domain])
    keep = set(sorted(range(len(groups)), key=lambda i: (turns[i], i))[:limit])
    return [g for i, g in enumerate(groups) if i in keep]


def _chain_graph(rows, tz="UTC", by_hostname=False):
    """
    Graphviz DOT of the chains, one dashed box per analyzed domain: domain → hostnames (grouped per target unless
    `by_hostname`) → target → ... → addresses. An earlier (no longer current) CNAME is a dashed grey arrow labelled
    with the day it was last seen (in `tz`); the arrow into the final addresses or outcome is dotted.
    """
    graph = _Graph()
    for (domain, rest, host), group in chain_groups(rows, GRAPH_MAX_CHAINS, by_hostname):
        row = group.iloc[0]
        hosts = list(dict.fromkeys(group["Hostname"]))
        root = f"domain::{domain}"
        graph.node(root, "#1f3b57", clean_hostname(domain), shape="ellipse", cluster=domain)
        if hosts == [clean_hostname(domain)]:
            start = root
        else:
            start = f"hosts::{domain}::{rest}::{host}"
            graph.node(start, "#2f2f2f", hosts[0] if len(hosts) == 1 else f"{hosts[0]}\\n+{len(hosts) - 1} more",
                       cluster=domain)
            graph.edge(root, start)
        names = rest.split(" → ")
        for name in names:
            graph.node(name, NODE_COLORS.get(row["Service Type"] if name == row["Target"] else "", "#72b7b2"))
        current = bool(group["Current"].any())
        if current:
            graph.edge(start, names[0])
        else:
            last = pd.Timestamp(group["Last Seen"].max())
            graph.edge(start, names[0], "dashed", HISTORY_COLOR,
                       f"until {last.tz_localize('UTC').tz_convert(tz):%Y-%m-%d}" if pd.notna(last) else None)
        for a, b in zip(names, names[1:]):
            graph.edge(a, b)
        addresses = [a for a in str(row["Final"] or "").split(", ") if a]
        end = ("\\n".join(addresses[:3]) + (f"\\n+{len(addresses) - 3} more" if len(addresses) > 3 else "")) \
            if addresses else ("✕ " + row["Outcome"] if row["Outcome"] not in (NOT_CHASED, "Resolves") else "")
        if end:
            graph.node(end, "#2ca02c" if addresses else "#d62728", shape="ellipse")
            graph.edge(names[-1], end, "dotted")
    return graph.dot()


def _links_graph(links):
    """Graphviz DOT of cross-domain links: analyzed domains (dark) → the names and addresses they share."""
    graph = _Graph()
    for row in links.head(GRAPH_MAX_CHAINS).to_dict("records"):
        graph.node(f"link::{row['Link']}", LINK_COLORS[row["Kind"]], row["Link"])
        for domain in row["Domains"].split(", "):
            graph.node(f"domain::{domain}", "#2f2f2f", domain, shape="ellipse")
            graph.edge(f"domain::{domain}", f"link::{row['Link']}")
    return graph.dot()


def render_cname_lens(ds, collected):
    st.header("CNAME Chains", help="Every CNAME record of the analysis window: where it points, what service the target "
                                   "runs on, and where the chain ends. Chains are followed through the collected "
                                   "passive DNS first, then by CNAME chasing in DNSDB (as in DNSDB Scout): one "
                                   f"exact-name lookup per step, at most {CNAME_CHASE_MAX_STEPS} steps.")
    cmap = order_by_domain(dataset_cname_map(ds), ds.selected_domains)
    if cmap.empty:
        st.info("No CNAME records in the passive DNS for the selected domains and window. Busy domains need "
                "*Settings → Collection options → CNAME lookup* when the main lookup stops at its limit.")
        return
    current = cmap[cmap["Current"]]
    metrics = [
        ("Hostnames with a CNAME", cmap["Hostname"].nunique(), "Hostnames with at least one CNAME record in the window"),
        ("Current external", int(current["External"].sum()), "Current CNAMEs that point outside the analyzed domain"),
        ("Dead ends", int((current["Outcome"] == "Dead end").sum()), OUTCOMES["Dead end"]),
        ("Takeover-prone", int((current["Service Type"] == "Takeover-prone").sum()), SERVICE_TYPES["Takeover-prone"]),
        ("Dynamic DNS / tunnel", int((cmap["Service Type"] == "Dynamic DNS / tunnel").sum()),
         SERVICE_TYPES["Dynamic DNS / tunnel"]),
    ]
    for col, (label, value, help_text) in zip(st.columns(len(metrics)), metrics):
        col.metric(label, f"{value:,}", help=help_text)
    st.caption("Every CNAME record of the domains below. Select hostnames (or none for every one shown) and click "
               f"**Chase CNAMEs** to fill in their chains: from the collected passive DNS where it already knows the "
               f"rest (free), otherwise by DNSDB lookups, at most {CNAME_CHASE_QUERIES_PER_DOMAIN} queries per domain "
               f"per click. {len(ds.cname_chases):,} name(s) chased in DNSDB so far.")
    _render_chain_table(ds, collected, cmap)
    _render_links(cmap, ds.selected_domains, ds.cname_rdata)
    _render_related(ds, collected, cmap)


def _row_keys(rows):
    return rows["Hostname"] + "|" + rows["Target"]


def _masked(cmap):
    """
    The map as the table shows it: chains only for chased rows (Chased: the analyst chased them, or a DNSDB chase
    reached them); other rows stop at their target, Not chased.
    """
    revealed = st.session_state.get(REVEALED_KEY, set())
    by_dnsdb = (cmap["Note"] != COLLECTED) & (cmap["Outcome"] != NOT_CHASED)
    view = cmap.assign(Chased=_row_keys(cmap).isin(revealed) | by_dnsdb)
    hide = ~view["Chased"]
    view.loc[hide, "Chain"] = view.loc[hide, "Hostname"] + " → " + view.loc[hide, "Target"]
    view.loc[hide, "Final"] = ""
    view.loc[hide, "Final Last Seen"] = pd.NaT
    view.loc[hide, "Outcome"] = NOT_CHASED
    view.loc[hide, "Note"] = NOT_CHASED_NOTE
    view.loc[hide, "Hops"] = 1
    view.loc[hide, "Chased At"] = pd.NaT
    view.loc[hide, "From Cache"] = False
    view["From Cache"] = view["From Cache"].fillna(False).astype(bool)
    return view


def _age(timestamps):
    """'3 h ago' per UTC timestamp (empty for none)."""
    now = pd.Timestamp.now("UTC").tz_localize(None)

    def one(ts):
        if pd.isna(ts):
            return ""
        seconds = max(0, (now - ts).total_seconds())
        for unit, size in (("d", 86400), ("h", 3600), ("min", 60)):
            if seconds >= size:
                return f"{seconds / size:.0f} {unit} ago"
        return "just now"
    return pd.to_datetime(timestamps, errors="coerce").map(one)


CHASE_RESULT_COLUMNS = ["Domain", "Hostnames", "Count", "Examples", "Chain", "Hops", "Outcome", "Final",
                        "Final Last Seen", "From Cache", "Cached At", "Chased At", "Current", "Last Seen", "Note"]


def chase_results(rows):
    """
    Chased rows grouped like the chain map, per domain and chain after the hostname; most hostnames first, then the
    largest DNSDB count.
    """
    rows = rows[rows["Chased"]]
    out = []
    for (domain, rest, _), group in chain_groups(rows):
        first = group.iloc[0]
        hosts = list(dict.fromkeys(group["Hostname"]))
        out.append({"Domain": domain, "Hostnames": len(hosts), "Count": int(group["Count"].fillna(0).sum()),
                    "Examples": ", ".join(hosts[:5]) + (f" +{len(hosts) - 5} more" if len(hosts) > 5 else ""),
                    "Chain": full_path("", rest, first["Final"], first["Outcome"]), "Hops": int(first["Hops"]),
                    "Outcome": first["Outcome"], "Final": first["Final"], "Final Last Seen": first["Final Last Seen"],
                    "From Cache": bool(first["From Cache"]),
                    "Cached At": first["Chased At"] if first["From Cache"] else pd.NaT, "Chased At": first["Chased At"],
                    "Current": bool(group["Current"].any()), "Last Seen": group["Last Seen"].max(),
                    "Note": first["Note"]})
    frame = pd.DataFrame(out, columns=CHASE_RESULT_COLUMNS)
    return frame.sort_values(["Hostnames", "Count"], ascending=[False, False], kind="stable").reset_index(drop=True)


def _render_chase_results(ds, rows):
    """The chased chains, grouped: one row per domain and chain with the hostnames that lead into it."""
    results = chase_results(rows)
    with st.expander(f"Chase results ({len(results):,} chain(s), most hostnames first)", expanded=not results.empty):
        if results.empty:
            st.caption("Nothing chased yet among these hostnames.")
            return
        st.dataframe(results.assign(**{c: _local(results[c], ds.timezone) for c in ("Final Last Seen", "Last Seen",
                                                                                  "Cached At", "Chased At")}),
                     hide_index=True, column_config={
            "Hostnames": st.column_config.NumberColumn("Hostnames", help="Hostnames whose CNAME leads into this chain"),
            "Count": st.column_config.NumberColumn("Count", help="DNSDB count of those hostnames' CNAMEs, summed"),
            "From Cache": st.column_config.CheckboxColumn("From cache", help=COLUMN_HELP["From Cache"]),
            "Chased At": st.column_config.DatetimeColumn("Chased at", format="YYYY-MM-DD HH:mm",
                                                         help=COLUMN_HELP["Chased At"]),
            "Cached At": st.column_config.DatetimeColumn("Cached at", format="YYYY-MM-DD HH:mm",
                                                         help=COLUMN_HELP["Cached At"]),
            "Examples": st.column_config.Column("Examples", help="Some of those hostnames"),
            "Chain": st.column_config.TextColumn("Chain", width="large", help="The target → every CNAME after it → "
                                                                              "the final addresses"),
            "Hops": st.column_config.NumberColumn("Hops", help=COLUMN_HELP["Hops"]),
            "Outcome": st.column_config.Column("Outcome", help=COLUMN_HELP["Outcome"]),
            "Final": st.column_config.Column("Final", help=COLUMN_HELP["Final"]),
            "Final Last Seen": st.column_config.DatetimeColumn("Final Last Seen", format="YYYY-MM-DD HH:mm",
                                                               help="Last time the final addresses were seen"),
            "Current": st.column_config.CheckboxColumn("Current", help="A current CNAME of at least one hostname"),
            "Last Seen": st.column_config.DatetimeColumn("Last Seen", format="YYYY-MM-DD HH:mm",
                                                         help="Last time passive DNS saw one of these CNAMEs"),
            "Note": st.column_config.Column("Note", help=COLUMN_HELP["Note"]),
        })


@st.fragment
def _render_chain_table(ds, collected, cmap):
    """A fragment: filters, selection and chases rerun only this part."""
    c_domain, c_type, c_outcome, c_search, c_current = st.columns([2, 2, 2, 2, 1])
    domains = c_domain.multiselect("Domain", sorted(cmap["Domain"].unique()), key="cname_domains", placeholder="All domains")
    types = c_type.multiselect("Service type", [*SERVICE_TYPES, OTHER], key="cname_types", placeholder="Any service")
    outcomes = c_outcome.multiselect("Outcome", list(OUTCOMES), key="cname_outcomes", placeholder="Any outcome")
    search = c_search.text_input("Hostname or chain contains", key="cname_search").strip().lower()
    only_current = c_current.toggle("Current only", value=False, key="cname_current",
                                    help="Only each hostname's most recent CNAME target. Off: every CNAME the hostname "
                                         "ever had, earlier ones dashed grey in the chain map")
    shown = _masked(cmap)
    if only_current:
        shown = shown[shown["Current"]]
    if domains:
        shown = shown[shown["Domain"].isin(domains)]
    if types:
        shown = shown[shown["Service Type"].replace("", OTHER).isin(types)]
    if outcomes:
        shown = shown[shown["Outcome"].isin(outcomes)]
    if search:
        shown = shown[shown["Chain"].str.contains(search, regex=False)]
    c_caption, c_order = st.columns([3, 1], vertical_alignment="bottom")
    order = c_order.selectbox("Order rows by", list(ORDERS), key="cname_order",
                              help="Domain, then count: grouped by domain in the order of the target list, the CNAMEs "
                                   "DNSDB saw most often first. Count: most seen first across every domain. Last seen: "
                                   "most recent first.")
    c_caption.caption(f"{len(shown):,} of {len(cmap):,} CNAME record(s), one per hostname and target.")
    if shown.empty:
        return
    domain_rank = {d: i for i, d in enumerate(dict.fromkeys(cmap["Domain"]))}
    columns, ascending = ORDERS[order]
    shown = shown.assign(_domain=shown["Domain"].map(domain_rank)) \
        .sort_values(columns, ascending=ascending, kind="stable", na_position="last") \
        .drop(columns="_domain").reset_index(drop=True)
    picked_rows = _render_hostname_table(ds, shown)
    _render_chase_button(ds, collected, picked_rows, shown, cmap)
    picked = picked_rows if not picked_rows.empty else shown
    _render_chase_results(ds, picked)
    by_hostname = st.toggle("Every hostname in the map", value=False, key="cname_map_hosts",
                            help="Draw each hostname as its own node instead of grouping hostnames that share a chain "
                                 "(\"+N more\"). To expand a single group, select its hostnames in the table: the "
                                 "map then draws only the selected rows.")
    groups = len(chain_groups(picked, by_hostname=by_hostname))
    st.markdown(f"**Chain map** · {min(groups, GRAPH_MAX_CHAINS):,} of {groups:,} chain(s)"
                + (" (selected rows)" if not picked_rows.empty else " (rows shown)"))
    if picked["Chased"].any():
        st.graphviz_chart(_chain_graph(picked, ds.timezone, by_hostname))
    else:
        st.caption("Chase the hostnames to draw where their chains lead; until then the map only shows hostname → "
                   "target.")
        with st.expander("Show the map anyway"):
            st.graphviz_chart(_chain_graph(picked, ds.timezone, by_hostname))
    with st.expander("How to read the chain map"):
        st.caption("One dashed box per analyzed domain (dark blue) with its hostnames (dark, grouped per target) → targets "
                   "colored by service type: red dynamic DNS / tunnel, orange takeover-prone, purple free hosting, blue "
                   "CDN, grey parking, teal other. Green ends are addresses, red ends dead ends, loops or incomplete "
                   "chases.")
        st.caption(
            "- **Solid arrow** from a hostname: its **current** CNAME, the target it pointed to most recently "
            "(seen within a day of its latest CNAME record) and not replaced by A / AAAA records since. Current means "
            "the latest in the data, not still live: check **Last Seen** in the table.\n"
            "- **Dashed grey arrow, *until* date**: an **earlier** CNAME of the hostname, replaced by a newer target or "
            "by A / AAAA records more than a day later; the date is the last time passive DNS saw it.\n"
            "- **Solid arrows after the target**: the rest of the chain, each name's most recent CNAME (collected "
            "passive DNS or DNSDB chase), whenever it was seen.\n"
            "- **Dotted arrow** into the end: the last name's latest addresses (A / AAAA seen within a day of its "
            "latest record), or how the chain stopped.\n\n"
            "Current and earlier are judged within the **analysis window**: with *Last 30 days*, only CNAMEs seen in the "
            "last 30 days are drawn, and the latest of them is current. Pick *All time* for the full history.")
    with st.expander(f"Copy {len(picked):,} chain(s)" + (" (selected)" if not picked_rows.empty else " (every row shown)")):
        st.code("\n".join(full_path(d, c, f, o) for d, c, f, o in
                          zip(picked["Domain"], picked["Chain"], picked["Final"], picked["Outcome"])), language=None)
        st.caption("Not chased rows stop at their target; chase them to see the rest.")
    rerun_app_if_requested()


def _local(series, tz):
    return pd.to_datetime(series, errors="coerce").dt.tz_localize("UTC").dt.tz_convert(tz).dt.tz_localize(None)


def _render_hostname_table(ds, shown):
    """One row per hostname and target; returns the selected rows."""
    view = shown.assign(**{"Chase Age": "", "Cached At": pd.NaT})[TABLE_COLUMNS].copy()
    view["Chain"] = [full_path(d, c, f, o) if chased else "" for d, c, f, o, chased in
                     zip(shown["Domain"], shown["Chain"], shown["Final"], shown["Outcome"], shown["Chased"])]
    view["Hops"] = view["Hops"].where(shown["Chased"])
    view["Chase Age"] = _age(shown["Chased At"])
    view["Cached At"] = _local(shown["Chased At"].where(shown["From Cache"]), ds.timezone)
    view["Chased At"] = _local(shown["Chased At"], ds.timezone)
    view["Service Type"] = view["Service Type"].replace("", OTHER)
    for col in ("Last Seen", "First Seen"):
        view[col] = _local(view[col], ds.timezone)
    column_config = {col: st.column_config.Column(col, help=text) for col, text in COLUMN_HELP.items()}
    column_config.update({col: st.column_config.DatetimeColumn(col, help=COLUMN_HELP[col], format="YYYY-MM-DD HH:mm")
                          for col in ("Last Seen", "First Seen")})
    column_config["Chain"] = st.column_config.TextColumn("Chain", help=COLUMN_HELP["Chain"], width="large")
    column_config["Chased"] = st.column_config.CheckboxColumn("Chased", help=COLUMN_HELP["Chased"])
    column_config["From Cache"] = st.column_config.CheckboxColumn("From cache", help=COLUMN_HELP["From Cache"])
    column_config["Chased At"] = st.column_config.DatetimeColumn("Chased at", help=COLUMN_HELP["Chased At"],
                                                                 format="YYYY-MM-DD HH:mm")
    column_config["Chase Age"] = st.column_config.Column("Chase age", help=COLUMN_HELP["Chase Age"])
    column_config["Cached At"] = st.column_config.DatetimeColumn("Cached at", help=COLUMN_HELP["Cached At"],
                                                                 format="YYYY-MM-DD HH:mm")
    column_config["Count"] = st.column_config.NumberColumn("Count", help=COLUMN_HELP["Count"], format="%d")
    event = st.dataframe(view, hide_index=True, column_config=column_config, on_select="rerun",
                         selection_mode="multi-row", key=selection_key("cname_table", shown["Hostname"] + shown["Target"]))
    rows = selected_rows(event, shown)
    return shown.iloc[rows]


def _render_chase_button(ds, collected, picked, shown, cmap):
    """
    Chases the selected hostnames, or every one shown: their chains are filled in from the collected passive DNS where
    it knows the rest (free) and by DNSDB lookups elsewhere, at most CNAME_CHASE_QUERIES_PER_DOMAIN queries per domain.
    """
    scope = picked if not picked.empty else shown
    keys = set(_row_keys(scope))
    c_button, c_fresh = st.columns([3, 1], vertical_alignment="center")
    fresh = c_fresh.toggle("Re-chase (skip cache)", value=False, key="cname_rechase",
                           help="Also chase rows that were already chased, with fresh DNSDB lookups instead of the "
                                "cache (see From cache and Chase age). The new results replace the old ones.")
    plan = chase_plan(cmap[_row_keys(cmap).isin(keys)], rechase=fresh, chases=ds.cname_chases)
    names = sum(len(v) for v in plan.values())
    hosts = scope["Hostname"].nunique()
    what = f"{hosts:,} selected hostname(s)" if not picked.empty else f"all {hosts:,} hostname(s) shown"
    has_key = bool(load_dnsdb_key())
    pending = not scope["Chased"].all()
    clicked = c_button.button(
        ("Re-chase" if fresh else "Chase") + f" CNAMEs of {what} – up to {CNAME_CHASE_QUERIES_PER_DOMAIN} queries per domain",
        disabled=not (names and has_key) and not pending, key="cname_chase", icon=":material/route:",
        help=f"Fills in the chains of {what}. Where the collected passive DNS already knows the rest of a chain it is "
             f"shown without any query. Elsewhere each chain is followed in DNSDB from where it stops, one exact-name "
             f"lookup per step (CNAME, then A / AAAA at the end, at most {CNAME_CHASE_MAX_STEPS} steps), riskiest "
             f"targets and those most hostnames share first, until the domain has made "
             f"{CNAME_CHASE_QUERIES_PER_DOMAIN} DNSDB queries. Lookups from the cache are free. A chase cut off by "
             "that limit keeps its path and continues on the next click. Uses DNSDB quota, also with an offline "
             "dataset. Detections update with the results." + ("" if has_key else " Needs a DNSDB API key."))
    st.caption(f"{names:,} name(s) to look up in DNSDB across {len(plan):,} domain(s); the other chains of {what} "
               "resolve in the collected passive DNS." if names else
               f"Every chain of {what} resolves in the collected passive DNS or was chased: no DNSDB query needed.")
    if not clicked:
        return
    st.session_state[REVEALED_KEY] = st.session_state.get(REVEALED_KEY, set()) | keys
    message = f"Chains of {what} filled in"
    if plan and has_key:
        log = StatusLog()
        with st.spinner(f"Chasing {names} name(s) in DNSDB, up to {CNAME_CHASE_QUERIES_PER_DOMAIN} queries per "
                        "domain..."):
            run = chase_cnames(plan, log, fresh=fresh)
        collected.cname_chases = ds.cname_chases = merge_chases(ds.cname_chases, run.chases)
        collected.statuses = list(collected.statuses) + log.rows
        counts = run.chases["Outcome"].value_counts()
        message = (f"Chased {len(run.chases)} name(s) with {run.queries} DNSDB queries ({run.cached} lookups from the "
                   "cache): " + ", ".join(f"{outcome} {n}" for outcome, n in counts.items())
                   + (f". {run.left} name(s) wait for the next click (query limit)." if run.left else ".")
                   + " Detections are updated.")
    st.session_state[TOAST_KEY] = message
    st.session_state[APP_RERUN_KEY] = True


def _render_related(ds, collected, cmap):
    """Reverse CNAME lookups and their results: other domains whose hostnames point to the same targets."""
    st.subheader("Related domains (reverse CNAME)",
                 help="DNSDB RDATA lookups (rdata/name/{target}/CNAME): every hostname, of any domain, that DNSDB saw "
                      "pointing to a target by CNAME. Shows which other domains share the redirect.")
    _render_rdata_lookup(ds, collected, cmap)
    rdata = ds.cname_rdata
    if rdata is None or rdata.empty:
        st.caption("No reverse CNAME lookups yet.")
        return
    related = related_domains(rdata)
    others = related[~related["Analyzed"]]
    summary = rdata_summary(rdata, cmap)
    metrics = [("Other domains", len(others), "Registrable domains outside the run pointing to the looked-up targets"),
               ("Names", rdata["Hostname"].nunique(), "Hostnames pointing to the looked-up targets"),
               ("Targets looked up", rdata["Target"].nunique(), "Names looked up in DNSDB"),
               ("Analyzed domains", len({d for ds_ in summary["Analyzed Domains"]
                                          for d in ds_.split(", ") if d}),
                "Domains of this run pointing to the looked-up targets, in DNSDB or in their own chains")]
    for col, (label, value, help_text) in zip(st.columns(len(metrics)), metrics):
        col.metric(label, f"{value:,}", help=help_text)
    st.dataframe(summary.assign(**{c: _local(summary[c], ds.timezone) for c in ("First Seen", "Last Seen")}),
                 hide_index=True, column_config={
        "Target": st.column_config.Column("Target", help="The name looked up"),
        "Other Domains": st.column_config.NumberColumn("Other domains", help="Domains outside the run pointing to it: "
                                                       "a few means a dedicated target, a strong lead; hundreds or "
                                                       "thousands a shared hosting, parking or CDN service"),
        "Names": st.column_config.NumberColumn("Names", help="Hostnames pointing to it"),
        "Analyzed Domains": st.column_config.Column("Analyzed domains", help="Domains of this run pointing to it"),
        "First Seen": st.column_config.DatetimeColumn("First Seen", format="YYYY-MM-DD HH:mm"),
        "Last Seen": st.column_config.DatetimeColumn("Last Seen", format="YYYY-MM-DD HH:mm"),
        "Truncated": st.column_config.CheckboxColumn(
            "Truncated", help=f"DNSDB stopped at the limit of {CNAME_RDATA_RECORD_LIMIT:,} records: more names "
                              "point to the target than listed"),
    })
    if summary["Truncated"].any():
        st.warning(f"{int(summary['Truncated'].sum())} lookup(s) stopped at DNSDB's limit of "
                   f"{CNAME_RDATA_RECORD_LIMIT:,} records: the target is widely shared and the lists below are "
                   "incomplete.")
    st.caption(f"{len(others):,} other domain(s): those pointing to several looked-up targets first, then those on "
               "the least shared target. Other domains sharing a dedicated target are candidates for the same "
               "operator; on a parking or hosting service they are usually just other customers.")
    view = related.assign(**{c: _local(related[c], ds.timezone) for c in ("First Seen", "Last Seen")})
    st.dataframe(view, hide_index=True, column_config={
        "Domain": st.column_config.Column("Domain", help="Registrable domain of the hostnames"),
        "Analyzed": st.column_config.CheckboxColumn("Analyzed", help="One of the domains of this run"),
        "Targets": st.column_config.Column("Targets", help="Looked-up targets its hostnames point to"),
        "Target Shared By": st.column_config.NumberColumn(
            "Target shared by", help="Domains found on its least shared target: low means a dedicated target, a "
                                     "stronger lead; hundreds mean a parking or hosting service"),
        "Hostnames": st.column_config.NumberColumn("Hostnames"),
        "First Seen": st.column_config.DatetimeColumn("First Seen", format="YYYY-MM-DD HH:mm"),
        "Last Seen": st.column_config.DatetimeColumn("Last Seen", format="YYYY-MM-DD HH:mm"),
    })
    with st.expander(f"Copy {len(others):,} other domain(s)"):
        st.code("\n".join(others["Domain"]), language=None)
    with st.expander(f"Every name found ({len(rdata):,})"):
        st.dataframe(rdata.assign(**{c: _local(rdata[c], ds.timezone) for c in ("First Seen", "Last Seen")}),
                     hide_index=True)


def _render_rdata_lookup(ds, collected, cmap):
    """Names to look up: picked from the chains or typed; with none picked, the suggested chain targets."""
    suggested = rdata_candidates(cmap, CNAME_RDATA_MAX_PER_CLICK)
    c_names, c_button = st.columns([3, 1], vertical_alignment="bottom")
    picked = c_names.multiselect(
        "Names to look up", rdata_candidates(cmap, len(cmap) * CNAME_CHASE_MAX_STEPS, skip_shared=False),
        key="cname_rdata_names", accept_new_options=True,
        placeholder="Pick chain targets or type any name, e.g. line.txcdnline.com",
        help="Any CNAME target, from the chains above or typed. With none picked, looks up the suggested targets: "
             "external names of the chains shown, one per domain first, without CDN and parking targets (thousands "
             "of unrelated customers)." + (f" Suggested now: {', '.join(suggested)}." if suggested else ""))
    names = list(dict.fromkeys(filter(None, map(clean_hostname, picked)))) or suggested
    names = names[:CNAME_RDATA_MAX_PER_CLICK]
    has_key = bool(load_dnsdb_key())
    label = (f"Look up {len(names):,} name(s)" if picked else f"Look up {len(names):,} suggested target(s)") \
        if names else "No external target to look up"
    clicked = c_button.button(label, disabled=not names or not has_key, key="cname_rdata", icon=":material/call_split:",
                              help=f"Reverse CNAME lookup in DNSDB, at most {CNAME_RDATA_MAX_PER_CLICK} names per "
                                   f"click and {CNAME_RDATA_RECORD_LIMIT:,} results each. Uses DNSDB quota."
                                   + ("" if has_key else " Needs a DNSDB API key."))
    if not clicked:
        return
    log = StatusLog()
    with st.spinner(f"Looking up names pointing to {len(names)} target(s) in DNSDB..."):
        rows = reverse_cnames(names, ds.selected_domains, log)
    collected.cname_rdata = ds.cname_rdata = merge_rdata(ds.cname_rdata, rows)
    collected.statuses = list(collected.statuses) + log.rows
    others = rows.loc[~rows["Analyzed"], "Apex"].nunique() if not rows.empty else 0
    st.session_state[TOAST_KEY] = (f"Reverse CNAME: {len(rows):,} name(s) point to {len(names)} target(s), "
                                   f"{others:,} other domain(s).")
    st.session_state[APP_RERUN_KEY] = True
    rerun_app_if_requested()


def _render_links(cmap, domains, rdata=None):
    """Cross-domain CNAME links: what connects the analyzed domains through their chains."""
    st.subheader("Cross-domain links", help="; ".join(f"{kind}: {text}" for kind, text in LINK_KINDS.items()))
    links = cname_links(cmap, domains, rdata)
    if links.empty:
        linked = cmap["Domain"].nunique()
        st.caption(f"No CNAME chain connects the analyzed domains ({linked} domain(s) have CNAMEs in the window). "
                   "Chasing open chains can reveal more.")
        return
    strong = links[~links["Service Type"].isin(SHARED_SERVICE_TYPES)]
    st.caption(f"{len(strong):,} link(s) between {len({d for ds_ in strong['Domains'] for d in ds_.split(', ')}):,} "
               "analyzed domains, strongest first; links through a CDN or parking service are listed last and are weak.")
    st.dataframe(links, hide_index=True, column_config={
        "Link": st.column_config.Column("Link", help="The name or address the domains share"),
        "Kind": st.column_config.Column("Kind", help="; ".join(f"{k}: {t}" for k, t in LINK_KINDS.items())),
        "Domains": st.column_config.Column("Domains", help="The analyzed domains it connects"),
        "Domain Count": st.column_config.NumberColumn("Domains #"),
        "Hostnames": st.column_config.NumberColumn("Hostnames", help="Hostnames whose chains pass through it"),
        "Examples": st.column_config.TextColumn("Example chains", width="large"),
    })
    if not strong.empty:
        st.markdown(f"**Link map** · {min(len(strong), GRAPH_MAX_CHAINS):,} of {len(strong):,} link(s)")
        st.caption("Analyzed domains (dark) → what connects them: red a CNAME into another analyzed domain, orange a "
                   "shared name, green a shared final address. CDN and parking links are left out. Links come from the "
                   "collected passive DNS and every chase (yours, or restored from the cache); chasing more can add "
                   "links.")
        st.graphviz_chart(_links_graph(strong))
