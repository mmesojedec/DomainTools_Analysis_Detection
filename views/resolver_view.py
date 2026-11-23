"""
DNS resolution lens, like DomainTools' Super Resolver: the analyzed domains' DNS tree resolved record by record (CNAME
chains, MX and NS hosts, SPF includes) to IP addresses, and the dangling records found on the way (core.resolver).
"""
import pandas as pd
import streamlit as st

from config import (
    BGPDB_RESOLVE_MAX_IPS,
    RESOLVE_DEFAULT_QUERIES,
    RESOLVE_QUERY_OPTIONS,
    RESOLVE_RECORD_LIMIT,
    RESOLVE_TREE_DAYS,
)
from core import resolver as res
from core.intel_data import SEVERITY_COLORS, SEVERITY_ICONS
from integrations import bgpdb
from integrations.collector import resolve_tree, route_ips
from integrations.credentials import load_dnsdb_key
from integrations.http import StatusLog
from views.common import metric, metric_slots
from views.sidebar import APP_RERUN_KEY, TOAST_KEY

STATUS_COLORS = {res.RESOLVES: "#22c55e", res.DANGLING: "#ef4444", res.PENDING: "#94a3b8", res.LOOP: "#f59e0b",
                 res.NO_ADDRESS: "#64748b", res.STALE: "#b45309"}
GRAPH_ROWS = 60          # records drawn in the graph (most severe first)
DANGLING_COLUMNS = ["Severity", "Domain", "Name", "Type", "Dangling", "Service", "Reason", "Records", "Last Seen"]
STALE_COLUMNS = ["Domain", "Name", "Type", "Stale", "Service", "Reason", "Records", "Last Seen"]
TREE_TABLE_COLUMNS = ["Severity", "Domain", "Name", "Type", "Status", "Records", "Targets", "IPv4", "IPv6", "Origins",
                      "Dangling", "Stale", "Warnings", "Routing", "Path", "Last Seen"]
TAKEOVER_HELP = """
**What a dangling record gives away**

| Record | Points to | Whoever claims the dangling name receives |
| --- | --- | --- |
| CNAME | another name (often a cloud resource) | the subdomain's visitors, its cookies and the right to get certificates for it |
| MX | the mail server | the domain's incoming mail, password resets included |
| NS | the zone's name servers | the whole zone: every name under it |
| SPF include | another domain's SPF record | the right to send mail as the domain |

Only claimable targets count as dangling. A name is claimable when its domain is unregistered or lapsed (anyone can register it) or when it lives on a
takeover-prone service (S3, Azure, Heroku, GitHub Pages, ...) where anyone can create the missing resource.
Passive DNS shows what was seen, not what answers now: confirm a dangling record with a live lookup before acting.
"""


def _severity(values):
    return [f"{SEVERITY_ICONS.get(v, '')} {v}".strip() for v in values]


def _dot(text):
    return str(text).replace("\\", "\\\\").replace('"', '\\"')


def tree_graph(tree, limit=GRAPH_ROWS):
    """Graphviz DOT of the tree: domain → name (record type) → targets → addresses; dangling targets in red."""
    if tree is None or tree.empty:
        return ""
    rows = tree.head(limit)
    lines = ['digraph { rankdir=LR; bgcolor="transparent"; node [shape=box, style="rounded,filled", fontname="Helvetica",'
             ' fontsize=10, fillcolor="#2f2f2f", fontcolor="white", color="#555"]; edge [color="#888"];']
    added = set()

    def node(key, label, color):
        if key not in added:
            added.add(key)
            lines.append(f'"{_dot(key)}" [label="{_dot(label)}", fillcolor="{color}"];')
    for row in rows.to_dict("records"):
        domain = f"d:{row['Domain']}"
        node(domain, row["Domain"], "#4f46e5")
        record = f"r:{row['Name']}|{row['Type']}"
        node(record, f"{row['Name']}\n{row['Type']}", STATUS_COLORS.get(row["Status"], "#2f2f2f"))
        lines.append(f'"{_dot(domain)}" -> "{_dot(record)}";')
        dangling = set(row["Dangling"])
        for target in row["Targets"][:8]:
            key = f"t:{target}"
            node(key, target, SEVERITY_COLORS.get(row["Severity"], "#ef4444") if target in dangling else "#2f2f2f")
            lines.append(f'"{_dot(record)}" -> "{_dot(key)}";')
        ips = row["IPv4"] + row["IPv6"]
        if ips:
            key = f"i:{row['Name']}|{row['Type']}"
            node(key, "\n".join(ips[:4]) + (f"\n+{len(ips) - 4} more" if len(ips) > 4 else ""), "#0f766e")
            lines.append(f'"{_dot(record)}" -> "{_dot(key)}" [style=dashed];')
        for target in dangling - set(row["Targets"]):
            key = f"t:{target}"
            node(key, target, SEVERITY_COLORS.get(row["Severity"], "#ef4444"))
            lines.append(f'"{_dot(record)}" -> "{_dot(key)}" [color="#ef4444"];')
    lines.append("}")
    return "\n".join(lines)


def render_resolver_lens(ds, collected):
    st.header("DNS resolution", help="Like the Super Resolver: every current name of the analyzed domains' DNS tree "
                                     "(DNSDB passive DNS) resolved record by record until IP addresses, and the "
                                     "dangling records found on the way.")
    st.caption("Each current record (seen within the last "
               f"{res.CURRENT_DAYS} days of the newest record) is followed to IP addresses: CNAME chains, the hosts of "
               "MX and NS records and the includes of SPF records. Names outside the collected passive DNS are looked "
               "up in DNSDB when you click Resolve. A target that resolves nowhere is **dangling**: whoever claims it "
               "receives what points to it.")
    tree, todo, routing = res.dataset_tree(ds)
    counts = res.summary(tree)
    slots = metric_slots(8)
    for slot, (label, value, help_text) in zip(slots, [
            ("Names", counts["Names"], "Current names of the DNS tree"),
            ("Records", counts["Records"], "Current A, AAAA, CNAME, MX, NS and SPF records"),
            ("Resolve to IPs", counts["Resolves"], res.STATUSES[res.RESOLVES]),
            ("Dangling", counts["Dangling"], res.STATUSES[res.DANGLING]),
            ("Critical / high", f"{counts['Critical']} / {counts['High']}", "Dangling records by severity"),
            ("Stale", counts["Stale"], res.STATUSES[res.STALE]),
            ("Not resolved yet", counts["Pending"], res.STATUSES[res.PENDING]),
            ("With warnings", counts["Warnings"], "Internal IPs and bogons in public DNS, BGP findings (bogon origin "
                                                  "or prefix, unauthorized or several origins, low visibility)")]):
        metric(slot, label, value, help=help_text)
    _render_resolve_button(ds, collected, todo)
    _render_routing_button(ds, collected, tree)
    if tree.empty:
        st.info("No current A, AAAA, CNAME, MX, NS or SPF record of the analyzed domains in the passive DNS of the "
                "analysis window.")
        return
    domains = sorted(tree["Domain"].unique())
    if len(domains) > 1:
        chosen = st.multiselect("Domains", domains, key="resolver_domains", placeholder="All domains")
        if chosen:
            tree = tree[tree["Domain"].isin(chosen)]
    t_dang, t_tree, t_graph, t_origins = st.tabs(["Dangling DNS", "Resolution tree", "Graph", "Origins"])
    with t_dang:
        _render_dangling(tree)
    with t_tree:
        _render_tree(tree)
    with t_graph:
        _render_graph(tree)
    with t_origins:
        _render_origins(tree, routing)


def _render_resolve_button(ds, collected, todo):
    has_key = bool(load_dnsdb_key())
    c_button, c_budget, c_fresh = st.columns([3, 1, 1], vertical_alignment="bottom")
    budget = c_budget.selectbox("DNSDB queries", RESOLVE_QUERY_OPTIONS,
                                index=RESOLVE_QUERY_OPTIONS.index(RESOLVE_DEFAULT_QUERIES), key="resolver_budget",
                                help="The most DNSDB queries one click may spend; lookups from the cache are free")
    fresh = c_fresh.toggle("Re-resolve (skip cache)", value=False, key="resolver_fresh",
                           help="Look every name up again with fresh DNSDB lookups instead of the cache")
    lookups = ds.resolutions
    exact = lookups[lookups["Lookup"] == lookups["Name"]] if "Lookup" in lookups else lookups
    looked = exact["Name"].nunique() if not exact.empty else 0
    discovered = res.discovered_domains(lookups)
    trees = [d for d in ds.selected_domains if "/" not in str(d) and d not in discovered]
    work = bool(todo or trees)
    clicked = c_button.button(
        ("Re-resolve" if fresh else "Resolve") + f" the DNS tree – up to {budget} DNSDB queries",
        key="resolver_run", icon=":material/lan:", type="primary" if work else "secondary",
        disabled=not has_key or not (work or fresh),
        help="First discovers each domain's current tree (DNSDB *.domain, records of the last "
             f"{RESOLVE_TREE_DAYS} days: a busy domain's main lookup is cut off and misses current names). Then looks "
             "up in DNSDB, one exact name at a time (every record type, up to "
             f"{RESOLVE_RECORD_LIMIT} records), the names the tree reaches outside the collected passive DNS (CNAME, "
             "MX and NS targets, SPF includes) and the domains of dead targets, round after round until everything "
             "resolves or the budget is spent. Lookups from the cache are free. Uses DNSDB quota, also with an "
             "offline dataset." + ("" if has_key else " Needs a DNSDB API key."))
    st.caption("; ".join(part for part in (
        f"{len(trees):,} domain tree(s) to discover" if trees else "",
        f"{len(todo):,} name(s) to look up in DNSDB" if todo else "",
        "Nothing left to look up" if not work else "",
        f"{looked:,} name(s) looked up so far") if part) + ".")
    if not clicked:
        return
    log = StatusLog()
    with st.spinner(f"Resolving the DNS tree in DNSDB, up to {budget} queries..."):
        run = resolve_tree(ds.pdns_utc, list(ds.selected_domains), ds.pdns_coverage, ds.resolutions, log,
                           max_queries=budget, fresh=fresh)
    collected.resolutions = ds.resolutions = run.lookups
    message = ((f"Discovered the current tree of {run.discovered} domain(s)"
                + (f" ({run.cut_off} still cut off at the record limit)" if run.cut_off else "") + ". "
                if run.discovered else "")
               + f"Looked up {run.looked} name(s); {run.queries} DNSDB queries ({run.cached} from the cache)"
               + (f"; {run.left} name(s) wait for the next click." if run.left else "."))
    if bgpdb.load_bgpdb_host():     # then the routing of the addresses the lookups reached (BGPDB, no quota)
        tree = res.dataset_tree(ds)[0]     # keyed by the new lookups: rebuilt with them
        routed = _route(ds, collected, res.unrouted_ips(tree, ds.bgp_origins, ds.resolution_routing), log)
        message += f" {routed}"
    collected.statuses = list(collected.statuses) + log.rows
    st.session_state[TOAST_KEY] = message
    st.session_state[APP_RERUN_KEY] = True


def _route(ds, collected, ips, log):
    """BGPDB routing of `ips` into the dataset; returns a sentence for the toast."""
    if not ips:
        return ""
    with st.spinner(f"Looking up the routing of {min(len(ips), BGPDB_RESOLVE_MAX_IPS)} address(es) in BGPDB..."):
        run = route_ips(ips, ds.resolution_routing, log)
    collected.resolution_routing = ds.resolution_routing = run.origins
    run.keep_raw(collected, ds)
    if run.stopped and not run.looked:
        return "BGPDB did not answer (it is only reachable on the DomainTools network)."
    return (f"Routing of {run.looked} address(es) from BGPDB ({run.cached} from the cache)"
            + (f"; {run.left} wait for the next click." if run.left else "."))


def _render_routing_button(ds, collected, tree):
    """BGPDB routing (prefix, origin, RPKI / IRR, visibility) of the resolved addresses the run has none for."""
    if tree.empty:
        return
    pending = res.unrouted_ips(tree, ds.bgp_origins, ds.resolution_routing)
    if not pending:
        return
    has_host = bool(bgpdb.load_bgpdb_host())
    c_button, c_note = st.columns([3, 2], vertical_alignment="center")
    clicked = c_button.button(
        f"Look up the routing of {len(pending):,} resolved address(es) (BGPDB)", key="resolver_route",
        icon=":material/hub:", disabled=not has_host,
        help="One BGPDB `ip` lookup per address (up to "
             f"{BGPDB_RESOLVE_MAX_IPS} per click): the announced prefix, the origin network, whether RPKI and the IRR "
             "authorize it, other origins seen and how many route collectors see it. BGPDB uses no DomainTools API "
             "quota but is only reachable on the DomainTools network." + ("" if has_host else
                                                                         " Needs a BGPDB host (Settings)."))
    c_note.caption("The run's hosting IPs already have their routing from the BGP stage; these are the addresses "
                   "only the resolution reached (CNAME, MX and NS targets).")
    if not clicked:
        return
    log = StatusLog()
    message = _route(ds, collected, pending, log)
    collected.statuses = list(collected.statuses) + log.rows
    st.session_state[TOAST_KEY] = message
    st.session_state[APP_RERUN_KEY] = True


def _render_dangling(tree):
    dangling = res.display(tree[tree["Status"] == res.DANGLING])
    stale = res.display(tree[tree["Status"] == res.STALE])
    st.markdown(res.DANGLING_DEFINITION)
    with st.expander("What a dangling record gives away", icon=":material/help:"):
        st.markdown(TAKEOVER_HELP)
    pending = int((tree["Status"] == res.PENDING).sum())
    if pending:
        st.warning(f"{pending:,} record(s) are **Not resolved yet**: their targets were not looked up, so whether they "
                   "dangle is unknown. Click **Resolve the DNS tree** above (again, while names are left).",
                   icon=":material/pending:")
    config = {"Reason": st.column_config.TextColumn(width="large"),
              "Last Seen": st.column_config.DatetimeColumn(format="YYYY-MM-DD")}
    if dangling.empty:
        if not pending:
            st.success("No dangling record.")
    else:
        shown = dangling[DANGLING_COLUMNS].assign(Severity=_severity(dangling["Severity"]))
        st.dataframe(shown, hide_index=True, width="stretch", column_config=config)
    if not stale.empty:
        st.markdown(f"**Stale records ({len(stale):,})**",
                    help=res.STATUSES[res.STALE])
        st.caption("Their target doesn't exist either, but nobody else can claim it: certificate validation (DCV) "
                   "leftovers on the CA's own domain, and missing names of the analyzed domain itself. Not dangling; "
                   "worth cleaning up.")
        st.dataframe(stale[STALE_COLUMNS], hide_index=True, width="stretch", column_config=config)


def _render_tree(tree):
    c_type, c_status = st.columns(2)
    kinds = c_type.pills("Record types", list(res.RESOLVE_TYPES), selection_mode="multi", key="resolver_types")
    statuses = c_status.pills("Status", list(res.STATUSES), selection_mode="multi", key="resolver_status",
                              help="\n".join(f"- **{k}**: {v}" for k, v in res.STATUSES.items()))
    search = st.text_input("Search names, targets and addresses", key="resolver_search", placeholder="e.g. mail or 10.")
    shown = res.display(tree)
    if kinds:
        shown = shown[shown["Type"].isin(kinds)]
    if statuses:
        shown = shown[shown["Status"].isin(statuses)]
    if search:
        text = shown[["Name", "Records", "Targets", "IPv4", "IPv6", "Dangling"]].astype(str).agg(" ".join, axis=1)
        shown = shown[text.str.contains(search.strip(), case=False, regex=False)]
    st.caption(f"{len(shown):,} of {len(tree):,} record(s). SPF records are the TXT rows (other TXT records are not "
               "resolved).")
    st.dataframe(shown[TREE_TABLE_COLUMNS].assign(Severity=_severity(shown["Severity"])), hide_index=True,
                 width="stretch", column_config={"Last Seen": st.column_config.DatetimeColumn(format="YYYY-MM-DD")})
    st.download_button("Download the tree (CSV)", lambda: res.display(tree).to_csv(index=False).encode(),
                       "dns_resolution_tree.csv", "text/csv", on_click="ignore", icon=":material/download:")


def _render_graph(tree):
    st.caption(f"Each domain → its records (green: resolves, red: dangling, grey: not resolved yet) → their targets → "
               f"their addresses. The {GRAPH_ROWS} most severe records; narrow it with Domains above.")
    only = st.toggle("Only dangling, stale and unresolved records", value=bool((tree["Status"] != res.RESOLVES).any()),
                     key="resolver_graph_only")
    rows = tree[tree["Status"] != res.RESOLVES] if only else tree
    if rows.empty:
        st.caption("Nothing to draw.")
        return
    st.graphviz_chart(tree_graph(rows), width="content")


def _render_origins(tree, routing):
    frame = res.origins(tree, routing)
    if frame.empty:
        st.caption("Origin networks come from BGPDB (only reachable on the DomainTools network): the run's hosting IPs "
                   "from the BGP stage, the other resolved addresses with *Look up the routing* above.")
        return
    st.caption("The networks announcing the tree's addresses (BGPDB), unauthorized routes first. *Valid*, "
               "*Unauthorized* and *Not in RPKI / IRR* count the addresses by whether RPKI or the IRR authorizes their "
               f"origin; *Min Collectors* is the least visible route (under {res.LOW_VISIBILITY} route collectors is "
               "flagged).")
    st.dataframe(frame, hide_index=True, width="stretch")
    routes = pd.DataFrame(sorted(routing.values(), key=lambda r: r["IP"]))
    ips = set(res.tree_ips(tree))
    routes = routes[routes["IP"].isin(ips)] if not routes.empty else routes
    if not routes.empty:
        st.markdown("**Per address**")
        st.dataframe(routes.assign(Origins=routes["Origins"].map(", ".join)), hide_index=True, width="stretch")

