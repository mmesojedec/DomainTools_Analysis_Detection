"""Lens 3: SSL/TLS certificate intelligence."""
import copy

import pandas as pd
import plotly.express as px
import streamlit as st

from config import DT_BLUE, DT_GREEN, DT_ORANGE, DT_SLATE
from core import certsql, ja4x
from core.caa import (
    CAA_COVERAGE_LABELS,
    caa_coverage_status,
    cert_is_wildcard,
    extract_domain_caa_policy,
    is_issuer_authorized_by_caa,
)
from core.cert_utils import cert_alt_names, cert_flag, cert_ip_names, cert_is_self_signed, publicly_trusted, weak_key_mask
from core.helpers import is_ip_address, md_escape
from core.intel_data import DUAL_USE_JA4X, KNOWN_JA4X
from core.self_signed import SEVERITIES, self_signed_certificates
from integrations.certificates import fetch_certsql
from views import navigation
from views.common import chart, explainer, table
from views.hunt_actions import certificate_actions
from views.query_editor import set_query
from visualizations.sankey import render_hostname_sankey_flow

CAA_BREACH_TYPES = {"Unauthorized CA Certificate Issuance (CAA Breach)", "Wildcard Issuance Forbidden by CAA Policy"}

OID_POLICY_MAP = {
    "2.23.140.1.2.1": "CA/B Forum DV (Domain Validated)",
    "2.23.140.1.2.2": "CA/B Forum OV (Organization Validated)",
    "2.23.140.1.2.3": "CA/B Forum IV (Individual Validated)",
    "2.23.140.1.1": "CA/B Forum EV (Extended Validation)",
    "2.23.140.1.3": "CA/B Forum EV Code Signing",
    "2.23.140.1.4.1": "CA/B Forum Code Signing",
    "2.23.140.1.4.2": "CA/B Forum Timestamping",
    "1.3.6.1.4.1.44947.1.1.1": "Let's Encrypt DV Policy",
    "2.16.840.1.114412.1.1": "DigiCert OV Server",
    "2.16.840.1.114412.1.2": "DigiCert DV Server",
    "2.16.840.1.114412.2.1": "DigiCert EV Server",
    "1.3.6.1.4.1.11129.2.5.1": "Google Trust Services EV",
    "1.3.6.1.4.1.11129.2.5.2": "Google Trust Services OV",
    "1.3.6.1.4.1.11129.2.5.3": "Google Trust Services DV",
    "1.3.6.1.4.1.6449.1.2.1.3.4": "Sectigo DV",
    "1.3.6.1.4.1.6449.1.2.1.3.2": "Sectigo OV",
    "1.3.6.1.4.1.6449.1.2.1.5.1": "Sectigo EV",
    "2.16.840.1.114413.1.7.23.1": "GoDaddy DV",
    "2.16.840.1.114413.1.7.23.2": "GoDaddy OV",
    "2.16.840.1.114413.1.7.23.3": "GoDaddy EV",
    "1.3.6.1.4.1.4146.1.10.10": "GlobalSign DV",
    "1.3.6.1.4.1.4146.1.20": "GlobalSign OV",
    "1.3.6.1.4.1.4146.1.1": "GlobalSign EV",
    "1.3.6.1.4.1.4788.2.201": "Amazon Trust Services DV",
    "1.3.6.1.4.1.4788.2.202": "Amazon Trust Services OV",
    "2.5.29.32.0": "anyPolicy (Universal Policy)",
}

PIVOT_OPTIONS = {
    "Public Key Hash (SHA256)": "Public Key SHA256",
    "Subject Key ID (SKID)": "Subject Key ID",
    "Certificate Hash (SHA256)": "Hash",
    "Certificate Hash (SHA1)": "SHA1",
    "Certificate Hash (MD5)": "MD5",
}


CERT_FOCUS_KEY = "cert_focus"   # a certificate or JA4X the page is narrowed to (set by an indicator's details)
CERT_TAB_KEY = "cert_tab"   # the selected tab; other pages open one with navigation.open_tab
SELF_SIGNED_TAB = "Self-Signed"
JA4X_TAB = "JA4X"
CERT_TABS = ["Executive Health", SELF_SIGNED_TAB, "Validity & Lifelines", "Cipher & Keys", "Key Reuse Matrix",
             JA4X_TAB, "Geo & Org Profiling", "EKU & Capabilities", "Policies & OIDs", "CAA Record", "CT Log Telemetry", "IP & C2"]


TREEMAP_CERTS = 15   # certificates drawn per target domain in the SAN treemap; the rest are one box
TREEMAP_SANS = 12    # SANs drawn per certificate; the rest are one box


def san_treemap_records(unique_certs, max_certs=TREEMAP_CERTS, max_sans=TREEMAP_SANS):
    """
    (rows, capped) for the SAN treemap: per target domain its `max_certs` certificates with the most SANs, each with
    its first `max_sans` SANs; the remaining SANs and certificates are single "+N more" boxes of the same total size,
    so the map stays readable (and quick to draw) for domains with hundreds of certificates.
    """
    certs = {}
    for _, cert in unique_certs.iterrows():
        sans = list(dict.fromkeys(s.replace("*.", "") for s in cert_alt_names(cert))) or [cert["Domain"]]
        certs.setdefault(cert["Domain"], []).append((f"{cert.get('Source', 'Unknown')} | {str(cert['Hash'])[:12]}...",
                                                     sans))
    rows, capped = [], False
    for domain, items in certs.items():
        items.sort(key=lambda item: -len(item[1]))
        for label, sans in items[:max_certs]:
            rows.extend({"Target Domain": domain, "Certificate": label, "SAN Domain": s, "Count": 1}
                        for s in sans[:max_sans])
            if len(sans) > max_sans:
                capped = True
                rows.append({"Target Domain": domain, "Certificate": label,
                             "SAN Domain": f"+{len(sans) - max_sans:,} more SANs", "Count": len(sans) - max_sans})
        rest = items[max_certs:]
        if rest:
            capped = True
            label = f"+{len(rest):,} more certificates"
            rows.append({"Target Domain": domain, "Certificate": label,
                         "SAN Domain": f"{sum(len(sans) for _, sans in rest):,} SANs",
                         "Count": sum(len(sans) for _, sans in rest)})
    return rows, capped


def _render_overview(ds, unique_certs):
    san_records, capped = san_treemap_records(unique_certs)
    if san_records:
        st.markdown("#### SAN Sprawl Hierarchy (Treemap)",
                    help="Target domains ➔ certificate hashes ➔ bundled SANs. Box size is the number of SANs. Per "
                         f"domain, the {TREEMAP_CERTS} certificates with the most SANs are drawn, each with up to "
                         f"{TREEMAP_SANS} SANs; the rest are grouped into one \"+N more\" box each.")
        if capped:
            st.caption(f"Grouped to keep the map readable: up to {TREEMAP_CERTS} certificates per domain and "
                       f"{TREEMAP_SANS} SANs per certificate, the rest in \"+N more\" boxes of the same size.")
        fig = px.treemap(pd.DataFrame(san_records), path=["Target Domain", "Certificate", "SAN Domain"], values="Count",
                         color="Certificate", color_discrete_sequence=px.colors.qualitative.Prism, title="Certificate Infrastructure Map")
        fig.update_traces(root_color="lightgrey")
        fig.update_layout(margin=dict(t=30, l=10, r=10, b=10))
        chart(fig, height=450)

    st.divider()
    st.markdown("#### Hostname ➔ Cert ➔ IP Infrastructure Flow",
                help="Observed hostnames ➔ certificate SHA256 fingerprints ➔ IP nodes, with step navigation.")
    if ds.cert_hostnames.empty:
        st.info("No Hostname Event telemetry available for selected domains.")
    else:
        render_hostname_sankey_flow(ds.cert_hostnames, target_tz=ds.timezone)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### Certificate Authority (CA) Distribution", help="Issuing CAs across historical and active certificates.")
        counts = unique_certs["Issuer"].fillna("Unknown").value_counts().reset_index()
        counts.columns = ["Issuer", "Count"]
        chart(px.pie(counts, names="Issuer", values="Count", hole=0.4, title="Issuing CAs"), height=320)
    with col2:
        st.markdown("#### Data Source Coverage", help="Certificates retrieved from the Cert API, Iris Investigate, and Domain History.")
        counts = unique_certs["Source"].value_counts().reset_index()
        counts.columns = ["Source", "Count"]
        chart(px.pie(counts, names="Source", values="Count", hole=0.4, title="Certificates by Data Source"), height=320)
    _render_wildcards(unique_certs)
    st.divider()


def _render_wildcards(unique_certs):
    st.markdown("#### Wildcard Certificates",
                help="Certificates whose Common Name or SANs include a wildcard (*.domain), covering any subdomain without per-host issuance.")
    rows = [{
        "Domain": cert.get("Domain"),
        "Common Name": cert.get("Common Name", "N/A"),
        "Wildcard Names": ", ".join(s for s in cert_alt_names(cert) if s.startswith("*.")) or cert.get("Common Name", "N/A"),
        "SAN Count": cert.get("SAN Count"),
        "Issuer": cert.get("Issuer", "Unknown"),
        "Validation Level": str(cert.get("Validation Level") or "unknown").upper(),
        "Source": cert.get("Source"),
        "Hash": cert.get("Hash", "N/A"),
    } for _, cert in unique_certs.iterrows() if cert_is_wildcard(cert)]
    if not rows:
        st.success("No wildcard certificates observed.")
        return
    st.caption(f"{len(rows)} of {len(unique_certs)} certificate(s) cover wildcard names.")
    table(pd.DataFrame(rows))


def _render_health(ds, unique_certs, threats):
    st.markdown("#### Executive Security & Hygiene Summary",
                help="Key reuse, self-signed instances, weak keys, CT compliance, and CAA authorization.")
    explainer("Understanding Cryptographic Hygiene & Health Metrics", """
* **Total Certificates vs. Unique Public Keys:** fewer unique keys than certificates means key reuse across hosts or domains.
* **Self-Signed Certificates:** Subject matches Issuer without a public CA root; common on C2 panels and staging servers.
* **Weak Keys:** RSA/DSA below 2048 bits or EC below 224 bits (NIST SP 800-57, CA/B Forum).
* **Missing CT SCTs:** only counted when the source explicitly reports no embedded SCTs (Certificate API data).
* **CAA Policy Status (RFC 8659):** whether observed certificates come from CAs permitted by the domain's CAA records.
""")
    total = len(unique_certs)
    uniq_keys = unique_certs["Public Key SHA256"].replace("", pd.NA).nunique() if "Public Key SHA256" in unique_certs.columns else 0
    self_signed = sum(cert_is_self_signed(c) for _, c in unique_certs.iterrows())
    weak = int(weak_key_mask(unique_certs).sum())
    missing_scts = sum(cert_flag(c, "Has Embedded SCTs") is False for _, c in unique_certs.iterrows())

    alerts = threats.alerts
    has_breach = not alerts.empty and alerts["Threat Type"].isin(CAA_BREACH_TYPES).any()
    has_caa = any(extract_domain_caa_policy(ds.events_utc, dom).has_policy for dom in ds.selected_domains)
    coverage_incomplete = any(
        caa_coverage_status(ds.pdns_coverage, dom) == "incomplete" and not extract_domain_caa_policy(ds.events_utc, dom).has_policy
        for dom in ds.selected_domains
    )
    if has_breach:
        caa_label, caa_delta, caa_color = "Policy Breach", "Critical", "inverse"
    elif has_caa:
        caa_label, caa_delta, caa_color = "Enforced & Compliant", "Clean", "normal"
    elif coverage_incomplete:
        caa_label, caa_delta, caa_color = "CAA Unknown", "pDNS incomplete", "off"
    else:
        caa_label, caa_delta, caa_color = "No CAA Policy", "Unprotected", "off"

    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Total Certificates", total)
    m2.metric("Unique Public Keys", uniq_keys)
    m3.metric("Self-Signed Certs", self_signed, delta="Warning" if self_signed else "Clean", delta_color="inverse")
    m4.metric("Weak Keys", weak, delta="Critical" if weak else "Clean", delta_color="inverse")
    m5.metric("Missing CT SCTs", missing_scts, delta="Non-Compliant" if missing_scts else "Clean", delta_color="inverse")
    m6.metric("CAA Compliance", caa_label, delta=caa_delta, delta_color=caa_color)


def _render_validity(unique_certs, short_lived_days):
    st.markdown("#### Certificate Validity Lifelines & History",
                help="Validity timeline per certificate lane: rotation velocity, renewal cadence, and ephemeral deployment.")
    explainer("Understanding Certificate Lifespans", f"""
* **Lifetimes are shrinking by design:** the CA/B Forum maximum for public certificates is 200 days from March 2026,
  100 days from March 2027 and 47 days from March 2029. Let's Encrypt defaults to 90 days (moving to 45) and offers an
  opt-in 6-day (160-hour) *shortlived* profile, which is also the only option for IP-address certificates.
* **Short-lived certificates (<= {int(short_lived_days)} days)** are flagged as *Short-Lived Certificate* for context only:
  short lifetimes are a sign of good automation, so they do not raise risk scores or change DIF fingerprints.
* **What is suspicious is the rotation pattern:** *Certificate Churn* fires on early replacements, when a certificate is
  reissued for the same names while the previous one still had over half its validity left.
* **Analyst Insight:** compare validity dates with the first passive DNS timestamp to identify rapid weaponization gaps.
""")
    gantt = unique_certs.dropna(subset=["Not Before Date", "Not After Date"]).copy()
    if gantt.empty:
        st.info("Insufficient timestamp data to render lifelines.")
        return
    now_utc = pd.Timestamp.now(tz="UTC").tz_localize(None)
    gantt["Validation Level"] = gantt["Validation Level"].fillna("Unknown") if "Validation Level" in gantt.columns else "Unknown"
    if "Duration" not in gantt.columns:
        gantt["Duration"] = None
    gantt = gantt.sort_values(["Domain", "Not Before Date"])
    gantt["Days Remaining"] = (gantt["Not After Date"] - now_utc).dt.days
    gantt["Duration_Display"] = pd.to_numeric(gantt["Duration"], errors="coerce").fillna(
        (gantt["Not After Date"] - gantt["Not Before Date"]).dt.days)
    gantt["Cert_Lane"] = gantt["Domain"] + " | " + gantt["Common Name"].fillna("N/A").astype(str) + " (" + gantt["Hash"].astype(str) + ")"
    gantt["Valid From"] = gantt["Not Before Date"].dt.strftime("%Y-%m-%d")
    gantt["Valid To"] = gantt["Not After Date"].dt.strftime("%Y-%m-%d")
    gantt["Wildcard"] = ["Yes" if cert_is_wildcard(cert) else "No" for _, cert in gantt.iterrows()]

    fig = px.timeline(
        gantt, x_start="Not Before Date", x_end="Not After Date", y="Cert_Lane", color="Source", hover_name="Common Name",
        hover_data={"Domain": True, "Common Name": True, "Issuer": True, "Duration_Display": True, "Days Remaining": True,
                    "Valid From": True, "Valid To": True, "Validation Level": True, "Wildcard": True, "Source": True, "Hash": True, "Cert_Lane": False},
        title="SSL Certificate Operational Lifespans",
    )
    fig.add_vline(x=now_utc, line_width=2, line_dash="dash", line_color=DT_ORANGE, annotation_text="Today", annotation_position="top right")
    lanes = gantt["Cert_Lane"].unique().tolist()
    fig.update_yaxes(autorange="reversed", title="Domain | Common Name (Full Hash)", categoryorder="array", categoryarray=lanes)
    fig.update_layout(xaxis_title="Validity Timeline")
    chart(fig, height=max(400, len(lanes) * 35 + 100))

    st.divider()
    st.markdown(f"#### Short-Lived Certificates (Duration <= {int(short_lived_days)} Days)",
                help="Informational: short lifetimes are normal for automated renewal and are not used in risk scores or DIF.")
    short_lived = gantt[pd.to_numeric(gantt["Duration_Display"], errors="coerce") <= short_lived_days]
    if short_lived.empty:
        st.caption("No short-lived certificates in the current window.")
        return
    st.info(f"{len(short_lived)} short-lived certificate(s). Informational only; check *Certificate Churn* for abnormal rotation.")
    cols = ["Domain", "Common Name", "Issuer", "Duration_Display", "Days Remaining", "Valid From", "Valid To", "Validation Level",
            "Wildcard", "Source", "Hash"]
    table(short_lived[[c for c in cols if c in short_lived.columns]].rename(columns={"Duration_Display": "Duration (Days)"}))


def _render_keys(unique_certs):
    st.markdown("#### Cryptographic Cipher Suite & Key Topography")
    explainer("Understanding SSL Validation Levels (DV vs. OV vs. EV)", """
* **DV (Domain Validation):** domain control only, fully automated; the most abused tier for phishing and disposable endpoints.
* **OV (Organization Validation):** domain control plus verification of the operating organization.
* **EV (Extended Validation):** rigorous legal, physical, and operational checks.

**Analyst Insight:** flag domains that unexpectedly downgrade from EV/OV to DV.
""")
    col1, col2 = st.columns(2)
    with col1:
        if "Validation Level" in unique_certs.columns:
            counts = unique_certs["Validation Level"].fillna("unknown").astype(str).str.upper().value_counts().reset_index()
            counts.columns = ["Validation Level", "Count"]
            fig = px.pie(counts, names="Validation Level", values="Count", hole=0.5, title="Trust Validation Breakdown",
                         color="Validation Level", color_discrete_map={"EV": DT_GREEN, "OV": DT_BLUE, "DV": DT_ORANGE, "UNKNOWN": DT_SLATE})
            chart(fig, height=380)
    with col2:
        if "Public Key Bits" in unique_certs.columns:
            keys = unique_certs.dropna(subset=["Public Key Bits"]).copy()
            if not keys.empty:
                algos = keys["Public Key Algo"].fillna("").astype(str).str.upper() if "Public Key Algo" in keys.columns else ""
                keys["Key"] = algos + " " + pd.to_numeric(keys["Public Key Bits"], errors="coerce").fillna(0).astype(int).astype(str) + " Bits"
                counts = keys.groupby(["Domain", "Key"]).size().reset_index(name="Count")
                fig = px.bar(counts, x="Domain", y="Count", color="Key", title="Public Key Types per Domain", barmode="group")
                fig.update_layout(yaxis_title="Number of Certificates")
                chart(fig, height=380)


def _render_key_reuse(unique_certs):
    st.markdown("#### Cryptographic Attribution & Reuse Matrix",
                help="Shared public key hashes, Subject Key IDs, or certificate hashes across distinct domains.")
    explainer("Understanding Cryptographic Attribution & Key Reuse", """
* **Public Key Hash (SHA-256):** two domains sharing a public key hash were signed with the same private key — strong evidence of common management.
* **Subject Key Identifier (SKID):** shared SKIDs across unrelated registrations link infrastructure to the same operator.
* **Certificate Hash Pivot:** the same certificate deployed across different IPs, VPS providers, or reverse proxies.
""")
    available = {k: v for k, v in PIVOT_OPTIONS.items() if v in unique_certs.columns}
    if not available:
        st.info("No cryptographic hash data present.")
        return
    label = st.selectbox("Select Cryptographic Pivot:", options=list(available))
    col = available[label]
    reuse = unique_certs.dropna(subset=[col])
    reuse = reuse[reuse[col].astype(str).str.strip() != ""]
    if reuse.empty:
        st.info(f"No valid data available for `{label}`.")
        return
    key_reuse = reuse.groupby(col).agg(
        Associated_Domains=("Domain", lambda x: ", ".join(sorted(set(x)))),
        Domain_Count=("Domain", "nunique"),
        Cert_Count=("Hash", "count"),
        Issuers=("Issuer", lambda x: ", ".join(sorted(set(map(str, x))))),
    ).reset_index()
    shared = key_reuse[key_reuse["Domain_Count"] > 1].copy()
    if shared.empty:
        st.success(f"Clean: No cross-domain reuse detected using `{label}`.")
        return
    st.error(f"**Attribution Warning:** Detected {len(shared)} `{label}`(s) shared across domains.")
    shared["Display_ID"] = shared[col].astype(str).map(lambda x: x[:16] + "..." if len(x) > 16 else x)
    fig = px.bar(shared, x="Display_ID", y="Domain_Count", color="Associated_Domains", title=f"Cross-Domain Reuse: {label}")
    fig.update_layout(xaxis_title=label)
    chart(fig, height=380)
    table(shared.drop(columns=["Display_ID"]))


JA4X_RARITY_KEY = "ja4x_rarity"   # {ja4x: (total, relation)} from Certificate Search counts, kept for the session
JA4X_CHECK_MAX = 10              # values counted per click (the Certificates API allows 20 requests a minute)


def _open_ja4x_search(value):
    set_query("certsql_query", f"{certsql.HEADER}\n{ja4x.search_query(value)}")
    navigation.go("certsql")


def _check_rarity(values):
    counts = st.session_state.setdefault(JA4X_RARITY_KEY, {})
    errors = []
    for value in values:
        result = fetch_certsql(certsql.normalize(ja4x.search_query(value)), 1)
        if result.error:
            errors.append(result.error)
            break
        counts[value] = (int(result.extras.get("total") or 0), result.extras.get("relation", "eq"))
    return errors


def _render_ja4x(unique_certs):
    st.markdown("#### JA4X: how the certificates were generated",
                help="JA4X fingerprints the layout of a certificate (issuer and subject attribute types, extensions), "
                     "not its names or key. The same JA4X means the same tool or template made the certificates.")
    explainer("Reading JA4X", f"""
* **Three parts `a_b_c`:** a hash of the issuer's attribute types, of the subject's, and of the extensions. `000000000000` means that part is empty.
* **Known tools:** {len(KNOWN_JA4X)} C2 and malware fingerprints and {len(DUAL_USE_JA4X)} dual-use tool fingerprint(s) are built in (Reference → Built-in lists); a match raises an alert.
* **Common vs rare:** certificates from public CAs share a few very common values, so a JA4X shared by two domains only links them when it is **rare**. *Check how common* counts each value in the Certificates API ({ja4x.RARE_MAX} certificates or fewer is rare).
* **Pivot:** *Find certificates with this JA4X* opens CertsQL with `ja4x equals "…"`.
""")
    frame = ja4x.summary(unique_certs)
    if frame.empty:
        st.info("No JA4X in this run's certificates. The Certificates API adds `ja4x` with the latest CertsQL release; "
                "certificates collected once it is live carry it, and this tab and the JA4X alerts use it then.",
                icon=":material/info:")
    else:
        known = frame[frame["Known As"] != ""]
        if not known.empty:
            st.error(f"**{len(known)} JA4X value(s) match a known tool:** "
                     + "; ".join(f"{name} on {domains}" for name, domains in zip(known["Known As"], known["Domains"])))
        counts = st.session_state.get(JA4X_RARITY_KEY, {})
        frame["In Certificates API"] = frame["JA4X"].map(lambda v: counts[v][0] if v in counts else None)
        frame["Rarity"] = frame["JA4X"].map(lambda v: ja4x.rarity(*counts[v]) if v in counts else "")
        shared_rare = frame[(frame["Domain Count"] > 1) & (frame["Rarity"].isin(["Rare", "Uncommon"]))]
        if not shared_rare.empty:
            st.warning(f"**{len(shared_rare)} rare or uncommon JA4X value(s) shared across domains:** the same "
                       "tool or template made their certificates. " + "; ".join(shared_rare["Domains"]))
        table(frame, column_config={
            "In Certificates API": st.column_config.NumberColumn(
                "In Certificates API", format="%d", help="Certificates with this JA4X in the Certificates API "
                                                          "(exact up to 10,000), after Check how common"),
            "Self-signed": st.column_config.CheckboxColumn("Self-signed")})
        unchecked = [v for v in frame["JA4X"] if v not in counts][:JA4X_CHECK_MAX]
        c_check, c_pick, c_find = st.columns([1.2, 2, 1.2], vertical_alignment="bottom")
        if unchecked and c_check.button(
                f"Check how common ({len(unchecked)})", icon=":material/query_stats:", key="ja4x_check",
                help=f"One Certificate Search request (1 result) per value not checked yet, at most "
                     f"{JA4X_CHECK_MAX} per click; repeats within the cache lifetime cost none."):
            with st.spinner("Counting certificates per JA4X..."):
                errors = _check_rarity(unchecked)
            if errors:
                st.error(f"Certificate Search: {errors[0]}")
                if hint := certsql.error_hint(errors[0], ja4x.search_query(unchecked[0])):
                    st.info(hint, icon=":material/tips_and_updates:")
            else:
                st.rerun()
        value = c_pick.selectbox("JA4X to pivot on", list(frame["JA4X"]), key="ja4x_pivot",
                                 format_func=lambda v: v + (f" ({ja4x.known_ja4x(v)[0]})" if ja4x.known_ja4x(v) else ""))
        if c_find.button("Find certificates with this JA4X", icon=":material/badge:", key="ja4x_find",
                         width="stretch", help="Opens CertsQL with `ja4x equals` and this value; search from there."):
            _open_ja4x_search(value)
    with st.expander("Hunt for a known tool's certificates", icon=":material/travel_explore:"):
        st.caption("Opens CertsQL with the tool's JA4X, to find its certificates anywhere, not only in this run.")
        listed = {**{v: n for v, n in KNOWN_JA4X.items()}, **{v: f"{n} (dual-use)" for v, n in DUAL_USE_JA4X.items()}}
        c_tool, c_go = st.columns([3, 1.2], vertical_alignment="bottom")
        tool = c_tool.selectbox("Known fingerprint", list(listed), key="ja4x_known",
                                format_func=lambda v: f"{listed[v]}: {v}")
        if c_go.button("Find certificates", icon=":material/badge:", key="ja4x_known_find", width="stretch"):
            _open_ja4x_search(tool)


def _render_geo(unique_certs):
    st.markdown("#### Subject vs. Issuer Geographic Profiling",
                help="Certificate Subject country vs. issuing CA country, to spot jurisdictional evasion.")
    explainer("Understanding Geographic & Organizational Profiling", """
* **Subject Country:** declared jurisdiction of the certificate owner.
* **Issuer Country:** jurisdiction of the issuing Certificate Authority.
* **Jurisdictional Mismatch:** bulletproof hosting and illegal streaming portals often register in non-cooperative jurisdictions to obstruct takedowns.
""")
    if "Subject Country" not in unique_certs.columns or "Issuer Country" not in unique_certs.columns:
        st.info("Geographic parameters not present.")
        return
    geo = unique_certs.dropna(subset=["Subject Country", "Issuer Country"])
    geo = geo[(geo["Subject Country"].astype(str) != "") & (geo["Issuer Country"].astype(str) != "")]
    if geo.empty:
        st.info("Country metadata redacted or unavailable.")
        return
    col1, col2 = st.columns(2)
    with col1:
        chart(px.pie(geo, names="Subject Country", title="Subject Registered Countries", hole=0.4), height=350)
    with col2:
        chart(px.pie(geo, names="Issuer Country", title="Issuer Operating Countries", hole=0.4), height=350)


def _render_eku(unique_certs):
    st.markdown("#### Extended Key Usage (EKU) & Functional Capabilities",
                help="Server Auth, Client Auth, Code Signing, and S/MIME roles that reveal non-standard capabilities.")
    explainer("Understanding Extended Key Usage (EKU) Roles", """
* **Server Authentication (1.3.6.1.5.5.7.3.1):** identifies an HTTPS server to clients.
* **Client Authentication (1.3.6.1.5.5.7.3.2):** on public threat infrastructure, suggests admin panels, C2 listeners, or mTLS tunneling.
* **Code Signing (1.3.6.1.5.5.7.3.3):** abnormal on web hosting certificates; may indicate payload staging.
* **Secure Email / S/MIME (1.3.6.1.5.5.7.3.4):** email signing and encryption.
""")
    if "Extended Key Usage" not in unique_certs.columns:
        st.info("Extended Key Usage extensions not present.")
        return
    rows = [{"Domain": row["Domain"], "EKU Role": str(eku).replace("_", " ").title()}
            for _, row in unique_certs.iterrows() if isinstance(row.get("Extended Key Usage"), list)
            for eku in row["Extended Key Usage"]]
    if not rows:
        st.info("No Extended Key Usage extensions found.")
        return
    counts = pd.DataFrame(rows).groupby(["EKU Role", "Domain"]).size().reset_index(name="Count")
    chart(px.bar(counts, x="Count", y="EKU Role", color="Domain", orientation="h", title="Certificate Capability Roles"), height=380)


def _render_policies(unique_certs):
    st.markdown("#### Certificate Policy OIDs & CA Compliance",
                help="Certificate Policy OIDs and CPS URIs indicating validation rigor.")
    explainer("Decoding Certificate Policy OIDs (CA/B Forum & Major CAs)",
              "| Policy OID | Meaning |\n| :--- | :--- |\n" + "\n".join(f"| `{oid}` | {name} |" for oid, name in OID_POLICY_MAP.items()))
    if "Certificate Policy" not in unique_certs.columns:
        st.info("Certificate policy extensions not present.")
        return
    rows = []
    for _, row in unique_certs.iterrows():
        policies = row.get("Certificate Policy")
        for pol in policies if isinstance(policies, list) else []:
            if isinstance(pol, dict):
                oid = str(pol.get("policy_oid", "Unknown")).strip()
                rows.append({"Domain": row["Domain"], "Policy OID": oid,
                             "Policy Name": OID_POLICY_MAP.get(oid, "Custom / Private CA Policy"),
                             "CPS URI": ", ".join(pol.get("cps_uris") or []) or "None"})
    if not rows:
        st.info("No certificate policy OIDs found.")
        return
    counts = pd.DataFrame(rows).groupby(["Policy Name", "Domain"]).size().reset_index(name="Cert Count")
    chart(px.bar(counts, x="Cert Count", y="Policy Name", orientation="h", color="Domain", title="Observed Policy OIDs"), height=350)


def _caa_status_style(val):
    val = str(val)
    if "POLICY BREACH" in val:
        return "background-color: #5c1414; color: #ff8888; font-weight: bold;"
    if "Non-Public" in val or "Unverified" in val or "Incomplete" in val:
        return "background-color: #2a3040; color: #c8d0dc;"
    if "Authorized" in val:
        return "background-color: #143d22; color: #88ffaa;"
    if "Unprotected" in val:
        return "background-color: #3b3517; color: #ffea88;"
    return ""


def _render_caa(ds, unique_certs):
    st.markdown("#### Certification Authority Authorization (CAA) Audit Matrix",
                help="CAA policies from passive DNS / Domain History compared against observed certificate issuers.")
    explainer("Understanding CAA Records & Policy Enforcement (RFC 8659)", """
* **Purpose:** CAA records list the CAs allowed to issue for a domain (e.g. `0 issue "digicert.com"`).
* **Enforcement:** public CAs must check CAA before issuing.
* **Unauthorized issuance:** a certificate from a CA outside the list indicates DNS compromise, a challenge bypass, or a rogue certificate.
* **`issue ";"` / `issuewild ";"`:** an empty value forbids all (wildcard) issuance.
* **`iodef`:** where compliant CAs report blocked issuance attempts.
* Only CAA records on the domain name itself are used; subdomain CAA records do not change the apex policy.
* **CAA binds publicly trusted CAs only.** Certificates from private / non-public CAs (no embedded SCTs, no CA/B Forum
  policy, unrecognized issuer) are shown as *Non-Public CA (CAA N/A)* rather than as a breach.
* **Coverage matters:** "no CAA observed" only means "unprotected" when the CAA record was queried directly or the passive
  DNS results were complete. Truncated results are shown as *No CAA Observed (pDNS Incomplete)*.
""")
    rows = []
    for dom in ds.selected_domains:
        policy = extract_domain_caa_policy(ds.events_utc, dom)
        coverage = caa_coverage_status(ds.pdns_coverage, dom)
        for _, cert in unique_certs[unique_certs["Domain"] == dom].iterrows():
            trust = publicly_trusted(cert)
            if cert_is_self_signed(cert):
                status, reason = "Self-Signed (Bypasses CA)", "Self-signed certificates are not issued by a CA."
            elif policy.has_policy:
                is_auth, reason, _ = is_issuer_authorized_by_caa(cert, policy)
                if is_auth:
                    status = "Authorized"
                elif trust is True:
                    status = "POLICY BREACH"
                elif trust is False:
                    status, reason = "Non-Public CA (CAA N/A)", f"CAA only binds publicly trusted CAs. {reason}"
                else:
                    status, reason = "Mismatch (CA Trust Unverified)", f"Cannot confirm the CA is publicly trusted. {reason}"
            elif coverage == "incomplete":
                status = "No CAA Observed (pDNS Incomplete)"
                reason = ("No CAA record in the returned passive DNS sample, but the query was truncated and no dedicated CAA "
                          "lookup ran; enable *CAA lookup* or raise the result limit.")
            else:
                status, reason = "Unprotected (No CAA)", "Domain has no CAA DNS records; any public CA can issue."
            rows.append({
                "Domain": dom,
                "Issuer": cert.get("Issuer", "Unknown"),
                "Common Name": cert.get("Common Name", "N/A"),
                "Has Wildcard": "Yes" if cert_is_wildcard(cert) else "No",
                "Public CA": {True: "Yes", False: "No", None: "Unknown"}[trust],
                "Compliance Status": status,
                "Matched Policy / Reason": reason,
                "CAA Data Coverage": CAA_COVERAGE_LABELS[coverage],
                "Reporting Contact (iodef)": ", ".join(policy.iodef_contacts) or "None Declared",
                "Cert Hash": cert.get("Hash", "N/A"),
            })
    if not rows:
        st.info("No certificate records available to evaluate against CAA policy.")
        return
    caa_df = pd.DataFrame(rows)
    table(caa_df.style.map(_caa_status_style, subset=["Compliance Status"]))


def _render_ct_logs(ds, unique_certs):
    st.markdown("#### Live Certificate Transparency (CTL) Telemetry",
                help="CT log ingestion timestamps, log hosts, and submission working hours.")
    explainer("Understanding Certificate Transparency (CT) Telemetry", """
* **Public CT Logs:** CAs submit every publicly trusted TLS certificate to append-only logs (Google, Cloudflare, DigiCert, and others).
* **Submission Working Hours:** submission times in your selected timezone can reveal operator working hours or automation schedules.
""")
    if ds.ctl.empty:
        st.info("No CT log telemetry collected (disabled, capped, or no Cert API certificates).")
        return
    ctl = ds.ctl.merge(unique_certs[["Hash", "Domain"]].drop_duplicates(), on="Hash", how="inner")
    if ctl.empty:
        st.info("No CT log telemetry for the selected domains.")
        return
    ctl["Timestamp"] = pd.to_datetime(ctl["Timestamp"], errors="coerce", utc=True).dt.tz_convert(ds.timezone).dt.tz_localize(None)
    ctl["Hour"] = ctl["Timestamp"].dt.hour
    col1, col2 = st.columns(2)
    with col1:
        chart(px.histogram(ctl, x="Hour", color="Domain", nbins=24, title=f"CT Submission Working Hours ({ds.timezone})"), height=350)
    with col2:
        counts = ctl["Log Host"].value_counts().reset_index()
        counts.columns = ["Log Host", "Count"]
        chart(px.pie(counts, names="Log Host", values="Count", title="CT Log Host Distribution", hole=0.4), height=350)
    table(ctl.sort_values("Timestamp", ascending=False))


def _render_bare_ip(unique_certs):
    st.markdown("#### IP Certificates & Command/Control (C2) Indicators",
                help="Certificates issued to raw IPv4/IPv6 addresses instead of domain names.")
    explainer("Understanding Bare-IP Certificates (C2 Indicators)", """
* **Why it's abnormal:** public websites almost always use certificates for domain names.
* **Bypassing DNS monitoring:** C2 frameworks (Cobalt Strike, Sliver, Havoc, Mythic) often use IP certificates so agents talk to the IP directly, avoiding DNS-layer controls.
* When the target itself is an IP, certificates naming that IP are expected; see the threat engine for certificates that also cover other IPs.
""")
    rows = []
    for _, cert in unique_certs.iterrows():
        ip_names = cert_ip_names(cert)
        if ip_names:
            cn = str(cert.get("Common Name") or "").strip()
            rows.append({
                "Target": cert["Domain"],
                "Target Is IP": "Yes" if is_ip_address(cert["Domain"]) else "No",
                "Common Name": cn,
                "IP Names (CN/SAN)": ", ".join(ip_names),
                "Issuer": cert.get("Issuer", "Unknown"),
                "Hash": str(cert.get("Hash", "")),
            })
    if not rows:
        st.success("Clean: No Bare-IP certificates detected.")
        return
    bare = pd.DataFrame(rows)
    st.error(f"**C2 Alert:** Found {len(bare)} cert(s) using raw IP addresses.")
    table(bare)


SEVERITY_BADGES = {"Critical": "red", "High": "orange", "Medium": "violet", "Low": "gray"}
SELF_SIGNED_CARDS = 15   # certificates shown as cards; all of them are in the table below


def _when(value):
    return f"{value:%Y-%m-%d}" if pd.notna(value) else "?"


def _self_signed_card(row):
    with st.container(border=True):
        status = {"Expired": ":gray[expired]", "Not yet valid": ":orange[not yet valid]"}.get(row["Status"], ":green[valid]")
        st.markdown(f":{SEVERITY_BADGES[row['Severity']]}-badge[{row['Severity']}] **{md_escape(row['Common Name'])}** · "
                    f"{status} · {_when(row['Not Before'])} → {_when(row['Not After'])}")
        c1, c2, c3 = st.columns(3)
        c1.markdown(f"**Domain(s):** {md_escape(row['Domains'])}  \n**Seen in:** {md_escape(row['Sources'])}")
        days = row["Validity (days)"]
        c2.markdown(f"**Key:** {row['Key'] or 'not reported'}  \n**Signature:** {row['Signature'] or 'not reported'}")
        c3.markdown(f"**Validity:** {f'{days:,.0f} days' if pd.notna(days) else 'not reported'}  \n"
                    f"**Last seen:** {_when(row['Last Seen'])}")
        st.markdown("**Why it matters**\n" + "\n".join(f"- {md_escape(reason)}" for reason in row["Reasons"]))
        st.markdown(f"**What to do:** {row['Action']}")
        details = [("Subject", row["Subject"]), ("Issuer", row["Issuer"]), ("Names (SAN)", row["Names"]),
                   ("SHA-256" if len(row["Hash"]) == 64 else "Hash", row["Hash"]), ("SHA-1", row["SHA-1"])]
        st.caption("  \n".join(f"{label}: `{value}`" for label, value in details if value))
        certificate_actions(row["Hash"], row["SHA-1"], row["Common Name"], key=row["Hash"] or row["Common Name"])


def _render_self_signed(ds, unique_certs):
    st.markdown("#### Self-Signed Certificates",
                help="Certificates whose subject is their own issuer: no public CA vouches for them.")
    explainer("Understanding self-signed certificates and their severity", """
A self-signed certificate is signed by its own key instead of a public Certificate Authority, so browsers do not trust
it. Internal services, appliances and development servers use them legitimately; C2 servers, malware panels and
quickly built phishing hosts use them because they cost nothing and leave no record at a CA.

* **Critical:** served on the analyzed domain right now (Iris Investigate sees it), or the default certificate of a
  C2 / exploitation framework (Cobalt Strike, Sliver, Metasploit).
* **High:** served right now on another name, names a bare IP address, has a weak key, claims a public CA's name
  (e.g. *Google Trust Services*) while naming the analyzed domain, or carries OpenSSL's default organization
  (*Internet Widgits Pty Ltd*).
* **Medium:** a private CA root, a multi-year lifetime, or the default certificate of a proxy, hosting panel or
  appliance (Kubernetes ingress, Traefik, Plesk, cPanel, Fortinet, localhost): usually a misconfiguration.
* **Low:** expired and no longer served. An expired certificate is one step less severe, except a C2 default.

Each certificate also raises the *Self-Signed Certificate Detected* alert (High) on the Alerts page.
""")
    certs = self_signed_certificates(unique_certs, ds.selected_domains)
    if certs.empty:
        st.success("Clean: no self-signed certificates among the certificates of the selected domains.")
        return
    counts = certs["Severity"].value_counts()
    for column, severity in zip(st.columns(len(SEVERITIES)), SEVERITIES):
        column.metric(severity, int(counts.get(severity, 0)))
    for _, row in certs.head(SELF_SIGNED_CARDS).iterrows():
        _self_signed_card(row)
    if len(certs) > SELF_SIGNED_CARDS:
        st.caption(f"The {SELF_SIGNED_CARDS} most severe are shown above; all {len(certs)} are in the table.")
    with st.expander(f"All {len(certs)} self-signed certificate(s) as a table"):
        table(certs.assign(Reasons=certs["Reasons"].map("; ".join)), column_config={
            "Not Before": st.column_config.DatetimeColumn(format="YYYY-MM-DD"),
            "Not After": st.column_config.DatetimeColumn(format="YYYY-MM-DD"),
            "Last Seen": st.column_config.DatetimeColumn(format="YYYY-MM-DD"),
            "Validity (days)": st.column_config.NumberColumn(format="%d")})


def _clear_focus():
    st.session_state.pop(CERT_FOCUS_KEY, None)


def _focused(ds):
    """
    The dataset narrowed to the certificate (SHA-256 / SHA-1) or JA4X a suggestion opened the page on, with a banner
    to show every certificate again; `ds` itself when there is no focus or nothing matches it.
    """
    focus = str(st.session_state.get(CERT_FOCUS_KEY) or "").lower()
    if not focus:
        return ds
    mask = pd.Series(False, index=ds.ssl.index)
    for column in ("Hash", "SHA1", "JA4X"):
        if column in ds.ssl.columns:
            mask |= ds.ssl[column].astype(str).str.lower() == focus
    with st.container(horizontal=True, vertical_alignment="center"):
        if mask.any():
            domains = sorted(ds.ssl.loc[mask, "Domain"].astype(str).unique())
            st.info(f"Showing only `{focus}`: {int(mask.sum())} record(s) on {', '.join(domains[:5])}"
                    + (f" +{len(domains) - 5}" if len(domains) > 5 else ""), icon=":material/filter_alt:")
        else:
            st.warning(f"`{focus}` is not among this run's certificates; showing them all.")
        st.button("Show every certificate", key="cert_focus_clear", on_click=_clear_focus, icon=":material/close:")
    if not mask.any():
        return ds
    focused = copy.copy(ds)
    focused.ssl = ds.ssl[mask]
    focused.derived = {}   # tables built from the full certificates must not be reused for the narrowed ones
    return focused


def render_ssl_lens(ds, threats, thresholds):
    if ds.ssl.empty:
        st.info("No certificate data available for the selected domains.")
        st.divider()
        return
    st.subheader("SSL/TLS Certificate Intelligence",
                 help="Cryptographic and X.509 telemetry across active and historical certificates.")
    ds = _focused(ds)
    unique_certs = ds.ssl.drop_duplicates(subset=["Domain", "Hash", "Source"]).copy()
    _render_overview(ds, unique_certs)

    st.markdown("### Deep Certificate Telemetry & Cryptographic Analysis",
                help="Cryptographic strength, key reuse, lifespans, policy compliance, and C2 indicators.")
    tabs = st.tabs(CERT_TABS, key=CERT_TAB_KEY, on_change="rerun")
    navigation.scroll_to_tab()
    with tabs[0]:
        _render_health(ds, unique_certs, threats)
    with tabs[1]:
        _render_self_signed(ds, unique_certs)
    with tabs[2]:
        _render_validity(unique_certs, thresholds["short_lived_days"])
    with tabs[3]:
        _render_keys(unique_certs)
    with tabs[4]:
        _render_key_reuse(unique_certs)
    with tabs[5]:
        _render_ja4x(unique_certs)
    with tabs[6]:
        _render_geo(unique_certs)
    with tabs[7]:
        _render_eku(unique_certs)
    with tabs[8]:
        _render_policies(unique_certs)
    with tabs[9]:
        _render_caa(ds, unique_certs)
    with tabs[10]:
        _render_ct_logs(ds, unique_certs)
    with tabs[11]:
        _render_bare_ip(unique_certs)
    st.divider()
