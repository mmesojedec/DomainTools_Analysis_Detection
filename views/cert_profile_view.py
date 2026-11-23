"""
Certificate profile page (Overview): one certificate of the run, field by field (core.cert_profile): the flags, its
anatomy (core.cert_anatomy: every field in one view), the related certificates, where it was seen and the alerts citing
it.
"""
import pandas as pd
import streamlit as st

from core import cert_profile as cp
from core.cert_anatomy import anatomy_html
from core.intel_data import SEVERITY_ICONS
from views import navigation
from views.common import metric, metric_slots

SELECTED_KEY = "cert_profile_hash"      # the certificate shown (a hash); other pages set it to open one
DOMAIN_KEY = "cert_profile_domain"
ORDER_KEY = "cert_profile_order"
SHOW_KEY = "cert_profile_show"
ORDER_HELP = ("**Most relevant**: valid certificates first; among them the one for the domain itself (Apex), then a "
              "wildcard over it, then subdomain certificates; served on the website now first; then the newest. "
              "**Newest issued**: by Not Before. **Expiring soonest**: valid ones closest to expiry, then the most "
              "recently expired. **Most severe flag**: what stands out most first.")


def _reset():
    """A new domain, order or filter opens the first certificate of the new list."""
    st.session_state.pop(SELECTED_KEY, None)


def open_button(digest, label="Open in Certificate profile", key=None, container=None, domain=None):
    """A button that opens the Certificate profile on certificate `digest` (listed for `domain` when given)."""
    state = {SELECTED_KEY: digest, **({DOMAIN_KEY: domain} if domain else {})}
    navigation.jump_button("cert_profile", label, state=state, container=container,
                           button_key=key or f"cert_profile_open::{digest}", icon=":material/badge:", type="tertiary")


def _severity(values):
    return [f"{SEVERITY_ICONS.get(v, '')} {v}".strip() for v in values]


def render_cert_profile(ds, alerts=None):
    st.header("Certificate profile", help="One certificate of the run, field by field: what it is, who issued it, its "
                                          "key and extensions, what stands out, and how it relates to the run's other "
                                          "certificates.")
    certs = cp.certificates(ds.ssl)
    if certs.empty:
        st.info("No certificate in the analysis window. Certificates come from the Certificate API and Iris "
                "Investigate (Settings → Collection options).")
        return
    domains = sorted({d for values in certs["Domains"] for d in values}) if "Domains" in certs else []
    if len(domains) > 1:
        c_domain, c_order, c_show = st.columns([2, 2, 3])
        domain = c_domain.selectbox("Domain", ["All domains", *domains], key=DOMAIN_KEY, on_change=_reset)
    else:                                   # one domain: no picker, and no empty column for it
        c_order, c_show = st.columns([2, 3])
        domain = domains[0] if domains else "All domains"
    order = c_order.selectbox("Order", cp.ORDERS, key=ORDER_KEY, on_change=_reset, help=ORDER_HELP)
    shown = certs if domain == "All domains" else certs[certs["Domains"].map(lambda v: domain in v)]
    shown = cp.ranked(shown, None if domain == "All domains" else domain, order)
    keep = c_show.pills("Show", ["Valid now", "Served now", "Domain itself"], selection_mode="multi", key=SHOW_KEY,
                        on_change=_reset, help="Valid now: within its dates. Served now: on the domain's website "
                                               "today (Iris Investigate). Domain itself: names the analyzed domain "
                                               "(Apex) or every name under it (Wildcard).")
    filtered = shown
    if "Valid now" in keep:
        filtered = filtered[filtered["Status"] == "Valid"]
    if "Served now" in keep:
        filtered = filtered[filtered["Served"]]
    if "Domain itself" in keep:
        filtered = filtered[filtered["Role"].isin(["Apex", "Wildcard"])]
    if filtered.empty:
        st.caption(f"No certificate is {', '.join(keep).lower()}: showing them all.")
    else:
        shown = filtered
    hashes = list(shown["Hash"])
    if st.session_state.get(SELECTED_KEY) not in hashes:      # opened from another page on another domain: show all
        if st.session_state.get(SELECTED_KEY) in set(certs["Hash"]):
            shown = cp.ranked(certs, None, order)
            hashes = list(shown["Hash"])
        else:
            st.session_state[SELECTED_KEY] = hashes[0]
    labels = {row["Hash"]: cp.label(row) for row in shown.to_dict("records")}
    digest = st.selectbox(f"Certificate ({len(hashes):,})", hashes, format_func=labels.get, key=SELECTED_KEY,
                          help=f"{order} first. The tags say how it covers the domain (Apex, Wildcard, Subdomain), "
                               "whether it is valid now and whether the website serves it now. Other pages open a "
                               "certificate here with *Open in Certificate profile*.")
    cert = shown[shown["Hash"] == digest].iloc[0].to_dict()
    related = cp.related_certificates(cert, certs)
    found = cp.flags(cert, related=related)
    _render_summary(cert, found, related)
    t_anatomy, t_related, t_seen = st.tabs(["Anatomy", "Related certificates", "Where seen"])
    with t_anatomy:
        _render_anatomy(cert, found)
    with t_related:
        _render_related(related)
    with t_seen:
        _render_seen(ds, digest, alerts)


def _render_summary(cert, found, related):
    start, end = cp.when(cert.get("Not Before")), cp.when(cert.get("Not After"))
    now = pd.Timestamp.now(tz="UTC").tz_localize(None)
    left = (end - now).days if pd.notna(end) else None
    worst = found["Severity"].iloc[0] if not found.empty else "None"
    slots = metric_slots(6)
    for slot, (name, value, help_text) in zip(slots, [
            ("Issuer", cp.text(cert.get("Issuer Org")) or cp.text(cert.get("Issuer")) or "–", cp.text(cert.get("Issuer"))),
            ("Validation", (cp.text(cert.get("Validation Level")) or "–").upper(), "DV / OV / EV"),
            ("Valid for", f"{(end - start).days} d" if pd.notna(start) and pd.notna(end) else "–",
             f"{start:%Y-%m-%d} → {end:%Y-%m-%d}" if pd.notna(start) and pd.notna(end) else None),
            ("Expires in", f"{left} d" if left is not None and left >= 0 else "Expired" if left is not None else "–",
             None),
            ("Key", f"{cp.text(cert.get('Public Key Algo'))} {cp.text(cert.get('Public Key Bits'))}".strip() or "–", None),
            ("Most severe flag", f"{SEVERITY_ICONS.get(worst, '')} {worst}".strip(), f"{len(found)} flag(s)")]):
        metric(slot, name, value, help=help_text)
    tags = [f"Covers: {cert['Role']}" if cert.get("Role") else "", cert.get("Status") or "",
            "served on the website now" if cp._bool(cert.get("Served")) else ""]
    st.caption(" · ".join(t for t in tags if t) + " · Domains: " + (cp.text(cert.get("Domains")) or "–") + " · Sources: " + (cp.text(cert.get("Sources")) or "–")
               + f" · {len(related['Hash'].unique()) if not related.empty else 0} related certificate(s)")
    if found.empty:
        st.success("Nothing stands out in this certificate.")
    else:
        st.dataframe(found.assign(Severity=_severity(found["Severity"]),
                                  Field=found["Field"].map(_field_label)), hide_index=True, width="stretch")


def _field_label(column):
    return next((f"{section} · {label}" for section, label, c in cp.FIELDS if c == column), column)


def _render_anatomy(cert, found):
    """Every field of the certificate in one view (core.cert_anatomy): the trust flow and verdict, the field
    fingerprint, the validity timeline and key strength, then a card per X.509 section with the flags under their
    fields."""
    c_only, c_explain, c_find = st.columns([1, 1, 2])
    only = c_only.toggle("Only filled fields", value=True, key="cert_profile_filled",
                         help="Off: every X.509 field, the empty ones dimmed, so you see what the certificate lacks "
                              "(no organization on a DV certificate, no SCTs, no policy).")
    explain = c_explain.toggle("Explain fields", value=False, key="cert_profile_explain",
                               help="A line under each field saying what it is and what to look for. Hovering a "
                                    "field's name shows the same.")
    query = c_find.text_input("Find a field or value", key="cert_profile_find", placeholder="e.g. sha1, ca:true, "
                              "letsencrypt, a SAN", label_visibility="collapsed")
    st.html(anatomy_html(cert, found, only_filled=only, query=query, explain=explain))
    value = cert.get("JA4X")
    if cp.text(value):
        from views.ssl_view import render_ja4x_card
        with st.expander("JA4X: how the certificate was generated", icon=":material/fingerprint:"):
            render_ja4x_card(cp.text(value), key="cert_profile_ja4x")
    with st.expander("As a table (sort, copy)", icon=":material/table:"):
        rows = cp.field_rows(cert).drop(columns="Column")
        if only:
            rows = rows[rows["Value"] != ""]
        st.dataframe(rows, hide_index=True, width="stretch",
                     column_config={"Value": st.column_config.TextColumn(width="large")})


def _render_related(related):
    if related.empty:
        st.caption("No other certificate of the run shares this one's public key, notable JA4X, SAN set or common "
                   "name.")
        return
    st.caption("The run's other certificates that share the public key (the same key re-certified, or reused across "
               "sites), a notable or rare JA4X (made by the same tool), the exact SAN set or the common name.")
    st.dataframe(related, hide_index=True, width="stretch",
                 column_config={"Not Before": st.column_config.DatetimeColumn(format="YYYY-MM-DD"),
                                "Not After": st.column_config.DatetimeColumn(format="YYYY-MM-DD")})
    names = {row["Hash"]: f"{row['Common Name'] or '(no CN)'} · {row['Issuer']} · "
                          f"{cp.when(row['Not Before']):%Y-%m-%d} · {row['Hash'][:12]}" if pd.notna(cp.when(row["Not Before"]))
             else f"{row['Common Name']} · {row['Hash'][:12]}" for row in related.to_dict("records")}
    picked = st.selectbox("Open a related certificate", ["", *names], key="cert_related_pick",
                          format_func=lambda h: names.get(h, ""))
    if picked:
        open_button(picked, label="Open it", key="cert_profile_related_open")


def _render_seen(ds, digest, alerts):
    seen = cp.where_seen(digest, getattr(ds, "ctl", None), getattr(ds, "cert_observations", None),
                         getattr(ds, "cert_hostnames", None))
    for name, rows in seen.items():
        st.markdown(f"**{name}** ({len(rows):,})")
        st.dataframe(rows, hide_index=True, width="stretch", height=min(320, 35 * (len(rows) + 1) + 3))
    cited = cp.citing_alerts(digest, alerts)
    if not cited.empty:
        st.markdown(f"**Alerts citing this certificate** ({len(cited):,})")
        st.dataframe(cited[[c for c in ("Severity", "Domain", "Threat Type", "Confidence", "Category") if c in cited]],
                     hide_index=True, width="stretch")
    if not seen and cited.empty:
        st.caption("No CT log entry, observation or hostname event of this certificate in the run, and no alert names "
                   "it. CT log entries and observations are collected for the newest certificates (Settings → "
                   "Collection options).")
    st.code(digest, language=None)
