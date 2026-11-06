"""Domain profile page: everything about one domain on one screen, with links to the pages that go deeper."""
import pandas as pd
import streamlit as st

from core.anonymizers import ANONYMIZER_CATEGORIES, for_domains, shared_exit
from core.cname import dataset_cname_map
from core.helpers import md_escape
from core.idn import unicode_label
from core.network_intel import explode_ip_events
from core.next_steps import SEVERITY_RANK
from core.risk_profile import drivers_text, score_drivers
from core.triage import DOMAIN, STATUS_HELP, STATUSES, load_triage, set_status, status_of
from integrations.enrichment import extract_iris_profile
from views import navigation
from views.anonymizer_view import CATEGORY_BADGES, alerts_button, selectable_table

LATEST_PER_TYPE = 5


def latest_dns(pdns, domain, per_type=LATEST_PER_TYPE):
    """The most recently seen passive DNS values of `domain`, a few per record type."""
    if pdns is None or pdns.empty:
        return pd.DataFrame(columns=["Type", "Name", "Value", "Last Seen"])
    rows = pdns[pdns["Domain"] == domain]
    if rows.empty:
        return pd.DataFrame(columns=["Type", "Name", "Value", "Last Seen"])
    rows = rows.sort_values("Last Seen", ascending=False).drop_duplicates(["Field", "RRName", "Value"])
    rows = rows.groupby("Field", sort=False).head(per_type)
    return rows.rename(columns={"Field": "Type", "RRName": "Name"})[["Type", "Name", "Value", "Last Seen"]] \
        .sort_values(["Type", "Last Seen"], ascending=[True, False]).reset_index(drop=True)


def _local(series, tz):
    return pd.to_datetime(series, errors="coerce").dt.tz_localize("UTC").dt.tz_convert(tz).dt.tz_localize(None)


def _render_verdict(domain):
    """The analyst's verdict on the whole domain, kept between runs (dt_triage.json)."""
    status, note = status_of(load_triage(), domain)
    with st.form(f"verdict_{domain}", border=True):
        c_status, c_note, c_save = st.columns([1.2, 3, 1], vertical_alignment="bottom")
        choice = c_status.selectbox("Verdict on this domain", STATUSES, index=STATUSES.index(status),
                                    key=f"verdict_status_{domain}", help=STATUS_HELP)
        text = c_note.text_input("Note", value=note, key=f"verdict_note_{domain}",
                                 placeholder="Why: e.g. registered by the same actor as …, ticket number")
        if c_save.form_submit_button("Save verdict", width="stretch"):
            set_status([(domain, DOMAIN)], choice, text)
            st.toast(f"{domain} marked {choice}.")
            st.rerun()


VPNDB_COLUMNS = ["IP", "Seen In", "Category", "Provider", "Confidence", "Sharing", "IOC Value", "Tor", "Infrastructure",
                 "ASN", "AS Organization", "Country", "Last Seen", "Geo Mismatch", "Basis", "Note"]


def domain_vpndb(table, domain, current_ips, window_ips):
    """The VPNDB rows of the domain's IPs, anonymizer exits first, with where the domain used each IP."""
    rows = for_domains(table, [domain])
    if rows.empty:
        return pd.DataFrame(columns=VPNDB_COLUMNS)

    def seen_in(ip):
        return " + ".join(name for name, ips in (("Iris (now)", current_ips), ("passive DNS", window_ips))
                          if ip in ips) or "passive DNS (before the window)"

    rows = rows.assign(**{"Seen In": rows["IP"].map(seen_in),
                          "_order": (~rows["Category"].isin(ANONYMIZER_CATEGORIES)).astype(int)})
    return rows.sort_values(["_order", "IP"], kind="stable")[VPNDB_COLUMNS].reset_index(drop=True)


def _render_vpndb(ds, domain, current_ips, window_ips):
    """VPNDB's verdict on each IP the domain resolves to (now in Iris, or in the window's passive DNS)."""
    with st.container(border=True):
        st.markdown("**VPNDB** · which VPN or proxy provider operates behind each IP",
                    help="Each public IPv4 address the domain resolves to, now (Iris Investigate) or in the analysis "
                         "window (passive DNS), checked in VPNDB. Not observed is not an all-clear: VPNDB only knows "
                         "the exits it measured or that public lists name.")
        rows = domain_vpndb(ds.anonymizers, domain, current_ips, window_ips)
        if rows.empty:
            st.caption("No VPNDB verdicts for this domain: turn on *Check hosting IPs for VPN, residential proxy and "
                       "Tor* (Settings → Collection options) with a VPNDB key, then analyze again."
                       if ds.anonymizers is None or ds.anonymizers.empty else
                       "None of the domain's IPs was checked in VPNDB (IPv6, private, CDN or over the per-domain limit).")
            return
        flagged = rows[rows["Category"].isin(ANONYMIZER_CATEGORIES)]
        if flagged.empty:
            st.success(f"VPNDB attributes none of the domain's {len(rows)} checked IP(s) to a VPN, proxy or Tor.")
        else:
            shared = int(flagged.apply(shared_exit, axis=1).sum())
            st.markdown(f"**{len(flagged)} of {len(rows)}** checked IP(s) are anonymizer exits: "
                        + " ".join(f":{CATEGORY_BADGES.get(name, 'violet')}-badge[{count} {name}]"
                                   for name, count in flagged["Category"].value_counts().items())
                        + (f" · {shared} shared exit(s): they identify the service, not the actor" if shared else ""))
        selectable_table(rows, f"profile_vpndb_{domain}", ds.anonymizers, ds=ds, column_config={
            "Seen In": st.column_config.Column("Seen in", help="Iris (now): a current IP of the domain; passive DNS: "
                                                               "used in the analysis window, or before it")})
        c_alerts, c_dns = st.columns(2)
        alerts_button(f"profile_vpndb_{domain}", c_alerts)
        navigation.link("vpndb", label="Every checked IP (VPNDB page)", container=c_dns)


def render_profile(ctx):
    ds, view, profiles = ctx.ds, ctx.view, ctx.profiles
    domains = list(ds.selected_domains)
    st.header("Domain profile", help="One domain: risk, registration, hosting, DNS, CNAMEs, certificates, history and "
                                     "alerts. Each section links to the page with the full detail.")
    if not domains:
        st.info("No domain is selected in the sidebar's view filters.")
        return
    if st.session_state.get("profile_domain") not in domains:
        st.session_state["profile_domain"] = domains[0]
    domain = st.selectbox("Domain", domains, key="profile_domain", format_func=unicode_label)

    profile = profiles[profiles["Domain"] == domain].iloc[0] if not profiles.empty and domain in set(profiles["Domain"]) else None
    alerts = view.active[view.active["Domain"] == domain] if not view.active.empty else view.active
    ranked = alerts.assign(_r=alerts["Severity"].map(SEVERITY_RANK).fillna(9)).sort_values("_r") if not alerts.empty else alerts
    cmap = dataset_cname_map(ds)
    mine = cmap[cmap["Domain"] == domain] if not cmap.empty else cmap
    certs = ds.ssl[ds.ssl["Domain"] == domain] if not ds.ssl.empty else ds.ssl
    metrics = [
        ("Unified risk", f"{profile['Unified Risk']:.0f} / 100" if profile is not None else "–",
         "DomainTools risk score plus the telemetry penalty vectors"),
        ("DomainTools risk", f"{profile['Domain Risk Score']:.0f}" if profile is not None else "–",
         "Risk score from DomainTools"),
        ("Alerts", f"{len(alerts):,}" + (f" · worst {ranked.iloc[0]['Severity']}" if not ranked.empty else ""),
         "Active alerts in the analysis window"),
        ("Hostnames with a CNAME", f"{mine['Hostname'].nunique():,}" if not mine.empty else "0", "In the analysis window"),
        ("Certificates", f"{certs['Hash'].nunique() if 'Hash' in certs else len(certs):,}", "In the analysis window"),
    ]
    for col, (label, value, help_text) in zip(st.columns(len(metrics)), metrics):
        col.metric(label, value, help=help_text)
    if profile is not None and profile.get("DIF Breakdown"):
        st.caption(f"**DIF** `{profile['DIF Fingerprint']}` — {profile['DIF Breakdown']}")
    if profile is not None:
        drivers = score_drivers(profile, view.active)
        if drivers:
            st.caption("**Why this score:** " + md_escape(drivers_text(drivers)))
    _render_verdict(domain)

    iris = extract_iris_profile(ds.enrichment.get(domain, {}))
    c_reg, c_host = st.columns(2)
    with c_reg.container(border=True):
        st.markdown("**Registration** (Iris Investigate)")
        facts = {"Registrar": iris["registrar"], "Created": iris["create_date"], "Expires": iris["expiration_date"],
                 "First seen": iris["first_seen"], "Web server": iris["server_type"],
                 "Redirects to": iris["redirect_domain"] or iris["redirect"]}
        st.dataframe(pd.DataFrame([{"Field": k, "Value": "" if v is None or pd.isna(v) else str(v)[:80]}
                                   for k, v in facts.items()]), hide_index=True, width="stretch")
    with c_host.container(border=True):
        st.markdown("**Hosting** (Iris Investigate)")
        ips = pd.DataFrame(iris["ips"]).rename(columns={"ip": "IP", "asn": "ASN", "isp": "ISP", "country": "Country"})
        if ips.empty:
            st.caption("No current IP address.")
        else:
            st.dataframe(ips, hide_index=True, width="stretch")
        st.caption("**Name servers:** " + (", ".join(iris["name_servers"]) or "none"))
        navigation.link("dns", label="Hosting and DNS of every domain")
    window_ips = set(explode_ip_events(ds.pdns_utc[ds.pdns_utc["Domain"] == domain])["IP"].astype(str)) \
        if not ds.pdns_utc.empty else set()
    _render_vpndb(ds, domain, set(ips["IP"].astype(str)) if not ips.empty else set(), window_ips)

    st.subheader("Alerts")
    if ranked.empty:
        st.caption("No active alerts for this domain in the analysis window.")
    else:
        st.dataframe(ranked[[c for c in ("Threat Type", "Severity", "Confidence", "Status", "Category", "Threat Logic")
                             if c in ranked.columns]], hide_index=True,
                     width="stretch", column_config={"Threat Logic": st.column_config.TextColumn("Why", width="large")})
        navigation.link("alerts", label="Alerts with their evidence")

    c_dns, c_cname = st.columns(2)
    with c_dns:
        st.subheader("Latest DNS records", help=f"The {LATEST_PER_TYPE} most recently seen values per record type, "
                                                "from the passive DNS of the analysis window")
        dns = latest_dns(ds.pdns_utc, domain)
        if dns.empty:
            st.caption("No passive DNS records in the analysis window.")
        else:
            st.dataframe(dns.assign(**{"Last Seen": _local(dns["Last Seen"], ds.timezone)}), hide_index=True,
                         width="stretch", height=280,
                         column_config={"Last Seen": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm")})
    with c_cname:
        st.subheader("CNAME chains")
        if mine.empty:
            st.caption("No CNAME records in the analysis window.")
        else:
            current = mine[mine["Current"]]
            st.markdown(f"{mine['Hostname'].nunique():,} hostname(s) with a CNAME, "
                        f"{int(current['External'].sum()):,} current external, "
                        f"{int((current['Outcome'] == 'Dead end').sum()):,} dead end(s), "
                        f"{int((current['Outcome'] == 'Not chased').sum()):,} not chased yet.")
            top = mine.groupby("Target")["Hostname"].nunique().sort_values(ascending=False).head(5)
            st.dataframe(top.rename("Hostnames").reset_index(), hide_index=True, width="stretch")
            navigation.jump_button("cname", "Open this domain's CNAME chains", {"cname_domains": [domain]},
                                   button_key="profile_cname", icon=":material/route:")

    c_cert, c_hist = st.columns(2)
    with c_cert:
        st.subheader("Newest certificates")
        if certs.empty:
            st.caption("No certificates in the analysis window.")
        else:
            cols = [c for c in ("Common Name", "Issuer", "Not Before", "Not After", "Source") if c in certs]
            newest = certs.assign(_nb=pd.to_datetime(certs.get("Not Before"), errors="coerce", utc=True)) \
                .sort_values("_nb", ascending=False, na_position="last")
            st.dataframe(newest.drop_duplicates("Hash" if "Hash" in certs else cols).head(8)[cols].astype(str),
                         hide_index=True, width="stretch")
            navigation.link("certs", label="Every certificate")
    with c_hist:
        st.subheader("Latest Domain History changes")
        history = ds.dh[ds.dh["Domain"] == domain] if not ds.dh.empty else ds.dh
        if history.empty:
            st.caption("No Domain History changes in the analysis window.")
        else:
            cols = [c for c in ("Timestamp", "Field", "Before", "After") if c in history]
            latest = history.assign(_ts=pd.to_datetime(history.get("Timestamp"), errors="coerce", utc=True)) \
                .sort_values("_ts", ascending=False, na_position="last")
            st.dataframe(latest.head(10)[cols].astype(str), hide_index=True, width="stretch")
            navigation.link("raw", label="Every record")
