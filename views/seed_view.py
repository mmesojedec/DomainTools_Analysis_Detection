"""Certificate inputs: preview of the domains / IPs they resolve to, and their provenance after a run."""
import pandas as pd
import streamlit as st

from config import SEED_MAX_TARGETS
from core.cert_inputs import SEARCH_AS, host_focus_from, input_problems, item_for, search_as_label, seed_query
from core.helpers import md_escape
from views.common import table

SEED_TABLE_COLUMNS = ["Input", "Certificates", "Observations", "Derived Targets", "Note"]
CERTIFICATE_COLUMNS = ["Common Name", "Organization", "Issuer", "Validation", "Not Before", "Not After", "SANs", "SHA-256"]
DERIVED_HELP = {
    "Via": "SAN DNS / SAN IP: named in a certificate's Subject Alternative Names. CN: the certificate's common name "
           "(only when it has no SANs). Observed domain / hostname / IP: where Certificate Events saw the certificate.",
    "Hostnames": "Full hostnames under this domain in the certificates found (see Hostnames below)",
    "Certificates": "How many of the found certificates name this target",
    "Seeds": "Certificate inputs that led to this target",
}
HOSTNAME_HELP = {
    "Focus": "Tick to focus the results on this hostname. The domain is still looked up in full (and analyzed even if "
             "not ticked above); the focus can be changed after the run under Global View Filters.",
    "Apex": "Registered domain the hostname belongs to; Domain History, Risk and Iris Investigate run on it",
    "Certificates": "How many of the found certificates name this hostname",
    "Seeds": "Certificate inputs that led to this hostname",
}


def certificate_rows(hits):
    """One row per certificate the inputs found: who it was issued to and by, validity, and the names it covers."""
    rows = [{
        "Common Name": hit.get("subject_common_name") or "",
        "Organization": hit.get("subject_organization") or "",
        "Issuer": hit.get("issuer_common_name") or hit.get("issuer_organization") or "",
        "Validation": str(hit.get("validation_level") or "").upper(),
        "Not Before": str(hit.get("validity_not_before") or "")[:10],
        "Not After": str(hit.get("validity_not_after") or "")[:10],
        "SANs": ", ".join([*(hit.get("san_dns") or []), *(hit.get("san_ip_v4") or []), *(hit.get("san_ip_v6") or [])]),
        "SHA-256": hit.get("sha256") or "",
    } for hit in hits or []]
    frame = pd.DataFrame(rows, columns=CERTIFICATE_COLUMNS)
    return frame.sort_values("Not Before", ascending=False, kind="stable").reset_index(drop=True)


def render_seed_query_step(state):
    """
    Step 1 for certificate inputs (no API calls yet): each recognized input with how it will be searched, changeable
    per row, and the CertsQL that will run. Returns ("search", items), ("cancel", None), or (None, None) while waiting.
    """
    st.subheader("Certificate inputs: review the searches",
                 help="Each certificate detail you entered was recognized and turned into a Certificate Search (CertsQL). "
                      "Edit a value or change **Search as** if it was read as the wrong field, untick rows to skip them, "
                      "then search. Text that is not a domain or IP (e.g. a company name) is searched as a certificate "
                      "organization.")
    if state["plain"]:
        st.caption("Also analyzed as entered: " + md_escape(", ".join(state["plain"])))
    rows = pd.DataFrame({"Search": True, "Value": [item.value for item in state["items"]],
                         "Search as": [search_as_label(item) for item in state["items"]]})
    edited = st.data_editor(
        rows, key="seed_query_editor", hide_index=True, width="stretch",
        column_config={
            "Search": st.column_config.CheckboxColumn("Search", help="Run this Certificate Search"),
            "Value": st.column_config.TextColumn("Value", help="As entered (normalized); edit to adjust the search"),
            "Search as": st.column_config.SelectboxColumn(
                "Search as", options=list(SEARCH_AS), required=True,
                help="Certificate field to search. 'MD5 or serial' / 'SHA-1 or serial' search both fields in one query; "
                     "'SHA-256 (or public key)' retries as a public key hash when no certificate matches. Text "
                     "matching ignores case; 'contains' needs 3 to 63 characters."),
        },
    )
    items = [item_for(row["Value"] or "", row["Search as"]) for _, row in edited.iterrows() if row["Search"]]
    problems = input_problems(items)
    for problem in problems:
        st.error(problem)
    if items:
        with st.expander(f"CertsQL for {len(items)} search(es)", expanded=False):
            for item in items:
                if not input_problems([item]):
                    st.markdown(f"**{md_escape(item.display)}**")
                    st.code(seed_query(item), language="text")
    col_go, col_cancel, _ = st.columns([1, 1, 3])
    if col_go.button("Search certificates", type="primary", disabled=bool(problems) or not items, width="stretch"):
        return "search", items
    if col_cancel.button("Cancel", key="seed_query_cancel", width="stretch"):
        return "cancel", None
    return None, None


def render_seed_preview(preview):
    """
    Shows what each certificate input found and lets the user pick the derived targets and an optional hostname focus.
    Returns ("analyze", (selected targets, host focus)), ("cancel", None), or (None, None) while waiting.
    """
    resolution, plain = preview["resolution"], preview["plain"]
    st.subheader("Certificate inputs: choose what to analyze",
                 help="Certificate inputs are looked up first (Certificate Search, plus Certificate Events for SHA-256 "
                      "fingerprints). The domains and IPs their certificates cover can then be analyzed like entered targets.")
    table(resolution.seeds[SEED_TABLE_COLUMNS])
    with st.expander("CertsQL queries used"):
        for _, row in resolution.seeds.iterrows():
            st.markdown(f"**{md_escape(row['Input'])}**")
            st.code(row["Query"], language="text")

    found = certificate_rows(resolution.hits)
    if not found.empty:
        with st.expander(f"Certificates found ({len(found)})", expanded=False):
            table(found)

    derived = resolution.derived
    selected = []
    if derived.empty:
        st.warning("The certificate inputs found no domains or IPs to analyze. Shared CDN names (e.g. Cloudflare SNI "
                   "certificates) and private IPs are not offered.")
    else:
        st.markdown(f"**Derived targets ({len(derived)})** — the first {int(derived['Analyze'].sum())} are pre-selected; "
                    "tick or untick to change.")
        edited = st.data_editor(
            derived, key="seed_preview_editor", hide_index=True, width="stretch",
            disabled=[c for c in derived.columns if c != "Analyze"],
            column_config={"Analyze": st.column_config.CheckboxColumn("Analyze", help="Include this target in the run"),
                           **{col: st.column_config.Column(col, help=text) for col, text in DERIVED_HELP.items()}},
        )
        selected = edited.loc[edited["Analyze"], "Target"].tolist()

    focus = render_hostname_focus(resolution.hostnames)
    selected += [apex for apex in focus if apex not in selected]   # a ticked hostname analyzes its domain

    over_limit = len(selected) > SEED_MAX_TARGETS
    focused = sum(len(hosts) for hosts in focus.values())
    st.caption(f"{len(plain)} entered target(s) + {len(selected)} derived target(s) selected"
               + (f", focus on {focused} hostname(s)" if focus else "")
               + ". Each target costs the usual lookups (Domain History, Risk, Iris, passive DNS, certificates).")
    if over_limit:
        st.error(f"Select at most {SEED_MAX_TARGETS} derived targets per run.")
    col_go, col_cancel, _ = st.columns([1, 1, 3])
    if col_go.button("Analyze selected", type="primary", disabled=over_limit or not (plain or selected), width="stretch"):
        return "analyze", (selected, focus)
    if col_cancel.button("Cancel", width="stretch"):
        return "cancel", None
    return None, None


def render_hostname_focus(hostnames):
    """Optional hostname focus. Returns {apex: [hostnames]} for the ticked rows."""
    if hostnames is None or hostnames.empty or (hostnames["Hostname"] == hostnames["Apex"]).all():
        return {}
    st.markdown(f"**Hostnames ({len(hostnames)})** — optional: tick hostnames to focus the results on them. Domains are "
                "still looked up in full (every subdomain), so nothing is lost and the focus can be changed after the run.")
    edited = st.data_editor(
        hostnames, key="seed_hostname_editor", hide_index=True, width="stretch",
        disabled=[c for c in hostnames.columns if c != "Focus"],
        column_config={col: (st.column_config.CheckboxColumn(col, help=text) if col == "Focus"
                             else st.column_config.Column(col, help=text)) for col, text in HOSTNAME_HELP.items()},
    )
    return host_focus_from(edited)


def render_seed_provenance(collected):
    """Which certificate inputs this run started from and which analyzed targets came from them."""
    seeds = getattr(collected, "seeds", None)
    if seeds is None or seeds.empty:
        return
    derived = collected.derived if collected.derived is not None else pd.DataFrame()
    with st.expander(f"Certificate inputs: {len(seeds)} input(s) → {len(derived)} derived target(s) analyzed",
                     expanded=False):
        table(seeds[[c for c in SEED_TABLE_COLUMNS if c in seeds.columns]])
        if not derived.empty:
            st.markdown("**Derived targets in this run**")
            table(derived[[c for c in derived.columns if c != "Analyze"]],
                  column_config={col: st.column_config.Column(col, help=text) for col, text in DERIVED_HELP.items()})
