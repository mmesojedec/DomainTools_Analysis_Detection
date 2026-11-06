"""
One IP in full, wherever a VPNDB table row is selected: VPNDB's verdict, its whole answer as tables, the weekly
history, what the run knows about the IP (domains and passive DNS dates, Iris Investigate, the /24 and the network,
CIDR targets) and its place in the Tor network. An IP without a full verdict can fetch one on demand.
"""
import ipaddress
import json

import pandas as pd
import plotly.express as px
import streamlit as st

from core.anonymizers import answer_tables, exit_week_rows, neighbour_cidr, shared_exit, tor_context
from core.network_intel import explode_ip_events
from integrations.vpndb import ip_history, lookup_ip
from views import navigation
from views.common import chart

FETCHED_KEY = "vpndb_fetched"   # {ip: {"verdict", "history", "error"}} fetched on demand from an IP card
TABS = ["Verdict", "Full VPNDB answer", "Weekly history", "In this run", "Tor network"]
DETAIL_FIELDS = ["Category", "Provider", "Attribution", "Confidence", "Basis", "Tor", "Sharing", "IOC Value",
                 "Infrastructure", "Types", "Network", "ASN", "AS Organization", "Country", "Geo Mismatch", "Last Seen",
                 "Method", "Feeds", "Tor Exit First Seen", "Tor Exit Last Seen", "Tor Exit Current", "Tor Relays",
                 "Tor Exit Probability", "Tor Family", "Tor Reached Via", "Note"]


def _raw_answer(ds, endpoint, ip):
    """The run's VPNDB answer for `endpoint` and `ip` (Raw Records), else one fetched from this card."""
    raw = getattr(ds, "vpndb_raw", None) if ds is not None else None
    if raw is not None and not raw.empty:
        hit = raw[(raw["Endpoint"] == endpoint) & (raw["Target"].astype(str) == ip)]
        if not hit.empty and hit.iloc[0]["Response"] not in ("", "null"):
            return json.loads(hit.iloc[0]["Response"])
    fetched = st.session_state.get(FETCHED_KEY, {}).get(ip) or {}
    return fetched.get("verdict" if endpoint == "/ip/{ip}" else "history")


def _fetch(ip):
    """Button callback: the full verdict and weekly history of one IP (two VPNDB queries; cached like the run's)."""
    verdict, history = lookup_ip(ip), ip_history(ip)
    st.session_state.setdefault(FETCHED_KEY, {})[ip] = {
        "verdict": verdict.data if verdict.ok else None, "history": history.data if history.ok else None,
        "error": "; ".join(r.error for r in (verdict, history) if r.error)}


def _value(row, name):
    value = row.get(name)
    if name == "Tor Exit Current":   # only worth a line for a Tor address
        return "yes" if value is True else ""
    if name == "Tor Exit Probability" and isinstance(value, float) and value == value:
        return f"{value:.3%} of all Tor exit traffic"
    return "" if value is None or str(value) in ("nan", "<NA>", "None", "False") else str(value)


def render_ip_card(row, key, ds=None):
    """Everything the run knows about `row["IP"]`, in tabs."""
    ip = row["IP"]
    tabs = st.tabs(TABS, key=f"{key}::ipcard::{ip}", on_change="rerun")
    with tabs[0]:
        _verdict(row, key)
    with tabs[1]:
        _full_answer(ip, key, ds)
    with tabs[2]:
        _history(ip, ds)
    with tabs[3]:
        _in_run(row, ds)
    with tabs[4]:
        _tor(row, ds)


def _verdict(row, key):
    facts = [{"Field": name, "Value": _value(row, name)} for name in DETAIL_FIELDS]
    st.dataframe([f for f in facts if f["Value"]], hide_index=True, width="stretch")
    if shared_exit(row):
        st.caption("Shared exit: it identifies the service, not the actor; do not block it as an indicator on its own.")
    domains = [d for d in str(row.get("Domains") or "").split(", ") if d and d != row["IP"]]
    for i, domain in enumerate(domains[:5]):
        navigation.jump_button("profile", f"Profile of {domain}", {"profile_domain": domain},
                               button_key=f"{key}::profile::{i}", type="tertiary", icon=":material/domain:")


def _fetch_button(ip, key):
    fetched = st.session_state.get(FETCHED_KEY, {}).get(ip)
    if fetched and fetched.get("error"):
        st.error(f"VPNDB: {fetched['error']}")
    st.button("Fetch the full verdict and weekly history (2 VPNDB queries)", key=f"{key}::fetch::{ip}",
              on_click=_fetch, args=(ip,), icon=":material/download:",
              help="Asks VPNDB for this IP's full verdict (/ip/{ip}) and weekly history (/ip/{ip}/history). Shown on "
                   "this card for the session; the run itself does not change.")


def _full_answer(ip, key, ds):
    answer = _raw_answer(ds, "/ip/{ip}", ip)
    if answer is None:
        st.caption("The run has only VPNDB's bulk summary of this IP: the full verdict is fetched for exits, within "
                   "the use case's budget.")
        _fetch_button(ip, key)
        return
    if isinstance(answer, dict) and answer.get("observed") is False:
        st.info(f"VPNDB has not observed this address ({answer.get('reason', 'not observed')}): not an all-clear.")
    for name, frame in answer_tables(answer).items():
        if frame.empty:
            continue
        st.markdown(f"**{name}**" + (f" ({len(frame):,})" if name != "Fields" else ""))
        st.dataframe(frame.astype(str), hide_index=True, width="stretch")
    with st.expander("As received (JSON)"):
        st.json(answer, expanded=False)


def _history(ip, ds):
    answer = _raw_answer(ds, "/ip/{ip}/history", ip)
    weeks = exit_week_rows({ip: answer}) if isinstance(answer, dict) else pd.DataFrame()
    if weeks.empty and ds is not None and getattr(ds, "exit_weeks", None) is not None and not ds.exit_weeks.empty:
        weeks = ds.exit_weeks[ds.exit_weeks["IP"] == ip]
    if answer is None and weeks.empty:
        st.caption("No weekly history for this IP (it is fetched for exits, or with the button on *Full VPNDB "
                   "answer*).")
        return
    if isinstance(answer, dict):
        c1, c2, c3 = st.columns(3)
        c1.metric("First week", str(answer.get("firstWeek") or "–"))
        c2.metric("Last week", str(answer.get("lastWeek") or "–"))
        c3.metric("Weeks with evidence", f"{len(weeks):,}")
    if weeks.empty:
        st.caption("VPNDB holds no week of exit evidence for this address.")
    else:
        fig = px.bar(weeks.assign(Weeks=1), x="Week", y="Weeks", color="Status", hover_data=["Provider", "Weight"],
                     color_discrete_map={"probe": "#d62728", "scan": "#ff7f0e", "interpolated": "#c9a227"})
        fig.update_layout(margin=dict(t=10, l=10, r=10, b=10), yaxis_visible=False, legend_title_text="Evidence",
                          bargap=0.1)
        chart(fig, key=f"ipcard_history::{ip}", height=200)
    providers = (answer or {}).get("providers") if isinstance(answer, dict) else None
    if providers:
        st.markdown("**Providers seen on the address**")
        st.dataframe(pd.json_normalize(providers, sep=".").astype(str), hide_index=True, width="stretch")


def _in_run(row, ds):
    ip = row["IP"]
    if ds is None:
        return
    events = getattr(ds, "events_all_utc", pd.DataFrame())
    uses = explode_ip_events(events) if events is not None and not events.empty else pd.DataFrame()
    uses = uses[uses["IP"].astype(str) == ip] if not uses.empty else uses
    st.markdown("**Domains that resolved to it** (passive DNS and Domain History, full history)")
    if uses.empty:
        st.caption("No DNS record of the run points to this IP (an IP target, or a current Iris IP only).")
    else:
        seen = uses.assign(_last=pd.to_datetime(uses["Last Seen"], errors="coerce").fillna(uses["Date"]))
        table = seen.groupby("Domain").agg(Names=("RRName", lambda n: ", ".join(sorted({str(x) for x in n if
                                                                                         pd.notna(x)})[:5])),
                                           Records=("IP", "size"), First=("Date", "min"), Last=("_last", "max"))
        st.dataframe(table.reset_index().rename(columns={"First": "First seen (UTC)", "Last": "Last seen (UTC)"}),
                     hide_index=True, width="stretch")
    intel = (getattr(ds, "ip_intel", None) or {}).get(ip)
    if intel:
        st.markdown("**Iris Investigate**")
        st.dataframe([{"Field": k, "Value": str(v)} for k, v in (   # text only: a mixed column breaks Arrow
            ("Domains on the IP in Iris", f"{intel['count']:,}" if intel.get("count") else ""),
            ("Run domains on it now", ", ".join(sorted(intel.get("domains") or ()))), ("ASN", intel.get("asn") or ""),
            ("ISP", intel.get("isp") or ""), ("Country", intel.get("country") or "")) if v != ""],
            hide_index=True, width="stretch")
    cidr = neighbour_cidr(ip)
    ranges = getattr(ds, "neighbour_ranges", None)
    if cidr and ranges is not None and not ranges.empty and cidr in set(ranges["CIDR"]):
        hit = ranges[ranges["CIDR"] == cidr].iloc[0]
        st.markdown(f"**Its /24** `{cidr}`: {int(hit['Known Exits'])} known exit(s)"
                    + (f" of {hit['Providers']}" if hit["Providers"] else "") + (f" ({hit['Coverage']})"
                                                                               if hit["Coverage"] else ""))
    asns = getattr(ds, "hosting_asns", None)
    asn = row.get("ASN") if pd.notna(row.get("ASN")) else (intel or {}).get("asn")
    if asn and asns is not None and not asns.empty and int(asn) in set(asns["ASN"]):
        hit = asns[asns["ASN"] == int(asn)].iloc[0]
        st.markdown(f"**Its network** AS{int(asn)} {hit['AS Organization']}: {int(hit['Known Exits']):,} known exit(s)"
                    + (f", top provider {hit['Top Provider']}" if hit["Top Provider"] else "")
                    + (" (single tenant)" if hit["Single Tenant"] else ""))
    prefixes = getattr(ds, "prefixes", None)
    if prefixes is not None and not prefixes.empty:
        inside = [c for c in prefixes["CIDR"] if _contains(c, ip)]
        if inside:
            st.markdown("**In CIDR target(s):** " + ", ".join(f"`{c}`" for c in inside))


def _contains(cidr, ip):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _tor(row, ds):
    overview = getattr(ds, "tor_overview", None) if ds is not None else None
    if not overview:
        st.caption("No Tor overview in this run (VPNDB /tor is fetched with the VPNDB check).")
        return
    asn = int(row["ASN"]) if pd.notna(row.get("ASN")) else None
    context = tor_context(overview, row["IP"], asn, row.get("Country"))
    if row.get("Tor"):
        st.markdown(f"**Tor role of the IP:** {row['Tor']}")
    if not context:
        st.caption("Its network, prefix and country carry no Tor exit traffic in VPNDB's overview.")
    for what, text in context:
        st.markdown(f"- **{what}:** {text}")
    st.caption(f"Tor Project relay list published {overview.get('relaysPublished', '?')}.")
