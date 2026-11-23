"""
Certificate profile page (Overview): one certificate of the run, field by field (core.cert_profile): its field map, the
flags, every field grouped as in the certificate, the related certificates, where it was seen and the alerts citing it.
"""
import pandas as pd
import streamlit as st

from core import cert_profile as cp
from core.intel_data import SEVERITY_ICONS
from views import navigation
from views.common import metric, metric_slots

SELECTED_KEY = "cert_profile_hash"      # the certificate shown (a hash); other pages set it to open one
DOMAIN_KEY = "cert_profile_domain"


def open_button(digest, label="Open in Certificate profile", key=None, container=None):
    """A button that opens the Certificate profile on certificate `digest`."""
    navigation.jump_button("cert_profile", label, state={SELECTED_KEY: digest}, container=container,
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
    c_domain, c_cert = st.columns([1, 3])
    domain = c_domain.selectbox("Domain", ["All domains", *domains], key=DOMAIN_KEY) if len(domains) > 1 \
        else "All domains"
    shown = certs if domain == "All domains" else certs[certs["Domains"].map(lambda v: domain in v)]
    hashes = list(shown["Hash"])
    if st.session_state.get(SELECTED_KEY) not in hashes:      # opened from another page on another domain: show all
        if st.session_state.get(SELECTED_KEY) in set(certs["Hash"]):
            hashes = list(certs["Hash"])
            shown = certs
        else:
            st.session_state[SELECTED_KEY] = hashes[0]
    labels = {row["Hash"]: cp.label(row) for row in shown.to_dict("records")}
    digest = c_cert.selectbox(f"Certificate ({len(hashes):,})", hashes, format_func=labels.get, key=SELECTED_KEY,
                              help="Newest first. Other pages open a certificate here with *Open in Certificate "
                                   "profile*.")
    cert = shown[shown["Hash"] == digest].iloc[0].to_dict()
    related = cp.related_certificates(cert, certs)
    found = cp.flags(cert, related=related)
    _render_summary(cert, found, related)
    t_map, t_fields, t_related, t_seen = st.tabs(["Field map", "All fields", "Related certificates", "Where seen"])
    with t_map:
        _render_map(cert, found)
    with t_fields:
        _render_fields(cert)
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
    st.caption("Domains: " + (cp.text(cert.get("Domains")) or "–") + " · Sources: " + (cp.text(cert.get("Sources")) or "–")
               + f" · {len(related['Hash'].unique()) if not related.empty else 0} related certificate(s)")
    if found.empty:
        st.success("Nothing stands out in this certificate.")
    else:
        st.dataframe(found.assign(Severity=_severity(found["Severity"]),
                                  Field=found["Field"].map(_field_label)), hide_index=True, width="stretch")


def _field_label(column):
    return next((f"{section} · {label}" for section, label, c in cp.FIELDS if c == column), column)


def _render_map(cert, found):
    st.caption("The certificate's structure: each section and every field with its value. Coloured fields are the "
               "flags above (red: critical / high, amber: medium, blue: low); grey fields are empty in the Certificate "
               "API's answer.")
    st.graphviz_chart(cp.field_map(cert, found), width="content")
    value = cert.get("JA4X")
    if cp.text(value):
        from views.ssl_view import render_ja4x_card
        with st.expander("JA4X: how the certificate was generated", icon=":material/fingerprint:"):
            render_ja4x_card(cp.text(value), key="cert_profile_ja4x")


def _render_fields(cert):
    rows = cp.field_rows(cert)
    only = st.toggle("Only filled fields", value=True, key="cert_profile_filled")
    if only:
        rows = rows[rows["Value"] != ""]
    for section, group in rows.groupby("Section", sort=False):
        st.markdown(f"**{section}**")
        st.dataframe(group[["Field", "Value"]], hide_index=True, width="stretch",
                     column_config={"Value": st.column_config.TextColumn(width="large")})
    sans = cp._values(cert.get("SAN DNS")) or cp._values(cert.get("Alt Names List"))
    if sans:
        domains = set(cp._values(cert.get("Domains")))
        own = [s for s in sans if any(s.lstrip("*.") == d or s.lstrip("*.").endswith("." + d) for d in domains)]
        other = [s for s in sans if s not in own]
        st.markdown(f"**SANs: {len(own)} of the analyzed domains, {len(other)} other**",
                    help="Other names on the same certificate share its key and were requested together: leads to "
                         "related infrastructure (shared hosting and CDN certificates aside).")
        st.dataframe(pd.DataFrame({"SAN": own + other, "Analyzed domain": [True] * len(own) + [False] * len(other)}),
                     hide_index=True, width="stretch", height=min(400, 35 * (len(sans) + 1) + 3))


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
