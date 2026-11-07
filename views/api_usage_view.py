"""
API usage on screen: the cost estimate of the next Analyze (sidebar), the queries a run made (Data sources page),
and the products a run skips because the account does not have them.
"""
import pandas as pd
import streamlit as st

from core.account import STAGE_NAMES, STAGE_PRODUCTS, unavailable_stages
from core.api_usage import DNSDB, VPNDB, compare_estimate, run_usage
from core.cert_inputs import parse_inputs
from core.helpers import normalize_to_apex
from integrations.account import account_information, known_products
from integrations.credentials import load_dtapi_credentials
from integrations.estimate import estimate_run
from integrations.vpndb import last_quota

DNSDB_QUOTA_KEY = "dnsdb_quota"   # session: (FetchResult of the DNSDB rate limit, fetched at)
STATUS_ICONS = {"ok": "🟢 ok", "may exceed": "🟡 may exceed", "over": "🔴 over", "unknown": "⚪ unknown"}


SHORT_NAMES = {"iris-investigate": "Iris", "domain-history": "History", "certificate-search": "Cert search",
               "certificate-events": "Cert events", "Iris pDNS (web session)": "Iris pDNS"}
COMPACT_CONFIG = {
    "Product": st.column_config.TextColumn(help="Iris: iris-investigate · History: domain-history · Cert search: "
                                           "certificate-search · Cert events: certificate-events (DomainTools "
                                           "products); DNSDB, VPNDB and Iris pDNS are separate services"),
    "Queries": st.column_config.TextColumn(help="API queries of the run: a range where it depends on the answers "
                                           "(pages of a busy domain, supplements, VPNDB verdicts). Cached lookups "
                                           "are left out."),
    "Left": st.column_config.TextColumn(help="Left this month (DomainTools, from the Account page), in the current "
                                        "quota period (DNSDB, after *Check DNSDB quota* on the Account page) or today "
                                        "(VPNDB, from its last answer); — when not known yet"),
    "": st.column_config.TextColumn(width=28, help="🟢 fits · 🟡 may exceed what is left · 🔴 over · ⚪ not known"),
}


def compact_estimate(frame):
    """The estimate for the narrow sidebar: product, queries (a range), what is left, and a status dot."""
    queries = [f"{low:,}" if low == high else f"{low:,}–{high:,}"
               for low, high in zip(frame["Queries (min)"], frame["Queries (max)"])]
    left = ["—" if pd.isna(value) else f"{int(value):,}" for value in frame["Left"]]
    return pd.DataFrame({"": frame["Status"].map(lambda status: STATUS_ICONS[status].split()[0]),
                         "Product": frame["Product"].map(lambda p: SHORT_NAMES.get(p, p)), "Queries": queries,
                         "Left": left})


def target_list(raw_input):
    """The plain targets (domains as their apex, IPs, CIDR ranges) and the number of certificate inputs in `raw_input`."""
    items = parse_inputs(raw_input or "")
    plain, _ = normalize_to_apex([i.value for i in items if not i.is_certificate])
    return plain, sum(1 for i in items if i.is_certificate)


def service_quotas():
    """{service: what is left} known without a query: DNSDB from its last rate-limit check, VPNDB from its last answer."""
    quotas = {}
    dnsdb = st.session_state.get(DNSDB_QUOTA_KEY)
    if dnsdb and dnsdb[0].ok:
        left = (dnsdb[0].data or {}).get("remaining")
        if isinstance(left, int):
            quotas[DNSDB] = left
    vpndb = last_quota()
    for key in ("remaining_day", "remaining"):
        try:
            quotas[VPNDB] = int(vpndb[key])
            break
        except (KeyError, TypeError, ValueError):
            continue
    return quotas


def missing_stage_lines(products):
    return [f"**{STAGE_NAMES[stage]}** ({' or '.join(STAGE_PRODUCTS[stage])})" for stage in sorted(unavailable_stages(products))]


def render_cost_estimate(raw_input, settings):
    """Sidebar: the queries the next Analyze would make, next to what the account has left."""
    targets, certificates = target_list(raw_input)
    if not targets:
        return
    products = known_products()
    frame = compare_estimate(estimate_run(targets, settings, unavailable_stages(products)), products, service_quotas())
    worst = "over" if (frame["Status"] == "over").any() else "may exceed" if (frame["Status"] == "may exceed").any() \
        else None
    label = "API cost of the next Analyze" + (f" — {STATUS_ICONS[worst]}" if worst else "")
    with st.sidebar.expander(label, icon=":material/data_usage:", expanded=worst == "over"):
        if frame.empty:
            st.caption("No API queries: every lookup is answered from the lookup cache.")
        else:
            st.dataframe(compact_estimate(frame), hide_index=True, width="stretch", column_config=COMPACT_CONFIG)
        lookups, cached = int(frame["Lookups"].sum()), int(frame["From cache"].sum())
        notes = [f"{lookups:,} lookups, {cached:,} of them answered by the lookup cache (no query)."]
        if certificates:
            notes.append(f"{certificates} certificate input(s) add certificate searches before you pick their targets.")
        missing = missing_stage_lines(products)
        if missing:
            notes.append("Not in this account, so skipped: " + ", ".join(missing) + ".")
        st.caption(" ".join(notes))
        if products is None and load_dtapi_credentials():
            if st.button("Compare with account limits", key="estimate_account", icon=":material/account_circle:",
                         help="Loads the account's products and what is left this month (one Account Information "
                              "query, kept for an hour)."):
                account_information()
                st.rerun()


def render_run_usage(statuses, run_label="this run"):
    """Data sources page: the API queries of a run per service and product, and how many lookups the cache answered."""
    usage = run_usage(statuses)
    if usage.empty:
        return
    total, cached = int(usage["Queries"].sum()), int(usage["From cache"].sum())
    st.subheader("API queries", help="Queries each service and DomainTools product counted for this run: every HTTP "
                 "request that reached an API, including the pages of a long answer and retries after a rate limit "
                 "or server error. Lookups answered from the lookup cache cost none. VPNDB counts each address of a "
                 "bulk request as one query.")
    st.caption(f"{total:,} API queries for {run_label}; {cached:,} lookup(s) answered from the lookup cache.")
    st.dataframe(usage, hide_index=True, width="stretch", column_config={
        "Queries": st.column_config.NumberColumn(format="localized"),
        "From cache": st.column_config.NumberColumn("Cached lookups")})


def skipped_products_note(products):
    """A line for the Analyze status when stages are skipped because the account lacks their product, else ''."""
    missing = missing_stage_lines(products)
    return ("Skipped, not in this DomainTools account: " + ", ".join(missing)) if missing else ""


def quota_age(at):
    return pd.Timestamp(at, unit="s", tz="UTC").strftime("%Y-%m-%d %H:%M UTC") if at else ""

