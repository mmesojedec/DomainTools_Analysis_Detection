"""Domain profile page: everything about one domain on one screen, with links to the pages that go deeper."""
import pandas as pd
import streamlit as st

from core import bgp
from core.anonymizers import ANONYMIZER_CATEGORIES, for_domains, shared_exit
from core.certsql import certificates_query
from core.cname import dataset_cname_map
from core.helpers import is_cidr, is_ip_address, md_escape
from core.idn import unicode_label
from core.irisql import similar_query
from core.ja4x import note as ja4x_note
from core.network_intel import explode_ip_events
from core.next_steps import SEVERITY_RANK
from core.risk_profile import drivers_text, score_drivers
from core.threat_detection.risk_rules import risk_pattern
from core.triage import DOMAIN, STATUS_HELP, STATUSES, load_triage, set_status, status_of
from integrations.enrichment import extract_iris_profile
from integrations.risk import risk_components
from views import navigation
from views.anonymizer_view import CATEGORY_BADGES, alerts_button, selectable_table
from views.common import metric, metric_slots
from views.history_cap import render_history_cap_notice
from views.query_editor import set_query

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


BGP_IP_COLUMNS = ["IP", "Prefix", "Origin", "AS Name", "Status", "Origins", "Announced Since", "Collectors", "RIR Country",
                  "Iris Country", "Upstream", "Findings"]


def _render_bgp(ds, domain):
    """BGPDB: who announces the domain's hosting IPs, whether the registries allow it, and the routing findings."""
    from views.bgp_page import STATUS_BADGES, badges
    from views.bgp_page import alerts_button as bgp_alerts_button
    with st.container(border=True):
        st.markdown("**BGP routing** · who announces each hosting IP on the internet (BGPDB)",
                    help="Each public hosting IP of the domain (no CDN addresses) looked up in BGPDB, about the last "
                         "30 days of the global routing table: the prefix it is announced in, the network (origin AS) "
                         "that announces it, whether RPKI / IRR authorize that network, and the routing findings.")
        origins = getattr(ds, "bgp_origins", None)
        if origins is None or origins.empty:
            st.caption("No BGPDB data in this run: add a BGPDB host (Settings → API credentials, or ~/.bgpdbq.conf) "
                       "and keep *Look up BGP routing of the hosting IPs* on (Settings → Collection options), then analyze again.")
            return
        mine = bgp.for_domain(origins, domain)
        if mine.empty:
            st.caption("None of the domain's IPs was looked up in BGPDB (CDN, private, or over the per-run limit), "
                       "or BGPDB knows no announcement for them.")
            return
        found = bgp.for_domain(bgp.findings(origins, ds.bgp_asns, ds.bgp_routes), domain)
        usual = bgp.main_origins(mine)
        networks = usual.drop_duplicates("Origin")
        named = ", ".join(f"{row['Origin']} {row['AS Name']}".strip()
                          + f" :{STATUS_BADGES.get(row['Status'], 'gray')}-badge[{row['Status']}]"
                          for _, row in networks.head(4).iterrows())
        st.markdown(f"**{mine['IP'].nunique()}** IP(s) in **{mine['Prefix'].nunique()}** prefix(es), announced by "
                    f"{named}" + (f" and {len(networks) - 4} more" if len(networks) > 4 else "") + "  \n" + badges(found))
        asns = getattr(ds, "bgp_asns", None)
        if asns is not None and not asns.empty:
            ages = asns[asns["ASN"].isin(set(usual["Origin"]))].dropna(subset=["Registered"])
            if not ages.empty:
                st.caption("Origin networks registered: " + ", ".join(
                    f"{row['ASN']} {pd.Timestamp(row['Registered']):%Y-%m-%d} ({row['RIR'] or '?'}"
                    f"{', ' + row['RIR Country'] if row['RIR Country'] else ''})" for _, row in ages.iterrows()))
        ips = bgp.ip_table(mine, ds.bgp_routes, found=found, enrichment=ds.enrichment)
        st.dataframe(ips[[c for c in BGP_IP_COLUMNS if c in ips.columns]], hide_index=True, width="stretch",
                     column_config={"Announced Since": st.column_config.DatetimeColumn(format="YYYY-MM-DD"),
                                    "Origins": st.column_config.NumberColumn(
                                        "Origins", help="Networks that announced the prefix in the last ~30 days; "
                                                        "more than 1: see the BGP page's Origin timeline"),
                                    "Findings": st.column_config.TextColumn(width="medium")})
        if not found.empty:
            st.dataframe(found[["Finding", "Severity", "Prefix", "ASN", "Detail"]], hide_index=True, width="stretch",
                         column_config={"Detail": st.column_config.TextColumn(width="large")})
        c_alerts, c_page = st.columns(2)
        bgp_alerts_button(f"profile_bgp_{domain}", c_alerts)
        navigation.link("bgp", label="Routing map and timeline (BGP page)", container=c_page)


def _render_similar(ctx, domain):
    """The run's domains built most like this one, and look-alikes in earlier saved runs (no API query)."""
    from core import similarity as sim
    from views.similarity_view import THRESHOLD_KEY, current_weights, scored, similar_earlier
    with st.container(border=True):
        st.markdown("**Similar domains** · built like this one (hosting, DNS, certificates, registration, naming)",
                    help="Infrastructure similarity, not attribution: read the shared values. Hunt → Domain "
                         "similarity has every pair, the clusters and the weights.")
        if "/" in domain:
            st.caption("Not for CIDR targets.")
            return
        feats, counts, pairs = scored(ctx, current_weights())
        threshold = st.session_state.get(THRESHOLD_KEY, sim.DEFAULT_THRESHOLD)
        mine = pairs[(pairs["Domain A"] == domain) | (pairs["Domain B"] == domain)] if not pairs.empty else pairs
        mine = mine[mine["Similarity %"] >= threshold] if not mine.empty else mine
        if mine.empty:
            st.caption(f"No domain of this run is {threshold} % similar or more.")
        else:
            other = mine.apply(lambda r: r["Domain B"] if r["Domain A"] == domain else r["Domain A"], axis=1)
            st.dataframe(mine.assign(Domain=other.map(unicode_label))[["Domain", "Similarity %", "Rare Shared",
                                                                       "Shared Values"]].head(8),
                         hide_index=True, width="stretch", column_config={
                             "Similarity %": st.column_config.ProgressColumn("Similarity", format="%.0f %%",
                                                                             min_value=0, max_value=100)})
        if domain in feats:
            earlier = similar_earlier(domain, feats[domain], counts, st.session_state.get("run_created"))
            if not earlier.empty:
                st.markdown("**In earlier runs**")
                st.dataframe(earlier.head(5), hide_index=True, width="stretch", column_config={
                    "Similarity %": st.column_config.ProgressColumn("Similarity", format="%.0f %%", min_value=0,
                                                                    max_value=100)})
        navigation.link("similarity", label="Every pair, clusters and weights (Domain similarity)")


RISK_SCORES = ("Proximity", "Malware", "Phishing", "Spam")


def _render_risk(ds, domain, thresholds):
    """The DomainTools risk score's components as numbers, like the metrics above; the threat profile last, with the
    threats it predicts and the evidence it is based on."""
    found = risk_components(ds.risk).get(domain) if not ds.risk.empty else None
    st.markdown("**DomainTools risk score**")
    if not found:
        st.caption("Iris Investigate gave no risk score for this domain.")
        return
    row = st.container(horizontal=True, wrap=True, gap="medium")
    for name in RISK_SCORES:
        score = (found.get(name) or {}).get("Score")
        metric(row.container(width=190), name, "–" if score is None else f"{score:.0f}")
    profile = found.get("Threat profile") or {}
    details = [f"**{label}:** {md_escape(text)}" for label, text in (("Threats", profile.get("Threats")),
                                                                     ("Evidence", profile.get("Evidence"))) if text]
    score = profile.get("Score")
    metric(row.container(width=380), "Threat profile", "–" if score is None else f"{score:.0f}",
           note="  \n".join(details) or None)
    pattern = risk_pattern(found, thresholds["proximity_min"], thresholds["threat_profile_max"])
    if pattern:
        st.warning(f"**Proximity {pattern[0]:g}** while Malware, Phishing and Spam are all "
                   f"{thresholds['threat_profile_max']:g} or less: a harmless-looking domain next to known bad "
                   "infrastructure. On an established domain that recently moved its hosting, name servers, "
                   "registrar or registrant, that is how a hijack looks (*Possible Domain Hijack*); otherwise "
                   "shared hosting or a new actor domain (*Benign-Looking Domain in Malicious Neighborhood*). "
                   "See the Alerts below.", icon=":material/travel_explore:")


def _render_actions(domain):
    """One row of next moves for the domain: where else it was seen, IrisQL / CertsQL searches, a copyable name."""
    from views.certsql_view import QUERY_KEY as CERTSQL_KEY  # the query pages import this page's helpers
    from views.irisql_view import QUERY_KEY as IRISQL_KEY
    from views.recent_view import open_sightings
    with st.container(horizontal=True, vertical_alignment="center"):
        if st.button("Where else seen", key="profile_seen", icon=":material/visibility:", type="tertiary",
                     help="Runs → Indicator Sightings for this domain (local files, no API query)"):
            open_sightings(domain)
        if st.button("Similar domains / IPs in IrisQL", key="profile_irisql", icon=":material/manage_search:",
                     type="tertiary",
                     help="Opens IrisQL with a query for domains hosted on this IP (or range), or for a domain, domains "
                          "whose name contains its name; edit it, then Search (one Iris Investigate query)"):
            set_query(IRISQL_KEY, similar_query(domain))
            navigation.go("irisql")
        if st.button("Search in DNSDB", key="profile_dnsdb", icon=":material/saved_search:", type="tertiary",
                     help="Opens the DNSDB page with *.domain (every name under it); edit it there (a regex, a "
                          "record type, a time window), then Search (one DNSDB query)"):
            from views.dnsdb_view import open_search
            open_search(domain if is_ip_address(domain) or is_cidr(domain) else f"*.{domain}")
        if st.button("Its certificates in CertsQL", key="profile_certsql", icon=":material/badge:", type="tertiary",
                     help="Opens CertsQL with a query for certificates naming this IP (or an address in the range), "
                          "or this domain or its subdomains; Search there runs it"):
            set_query(CERTSQL_KEY, certificates_query(domain))
            navigation.go("certsql")
        with st.popover("Copy", icon=":material/content_copy:"):
            st.code(domain, language="text")


def render_profile(ctx):
    ds, view, profiles = ctx.ds, ctx.view, ctx.profiles
    domains = [d for d in ds.selected_domains if not is_ip_address(d) and not is_cidr(d)]   # IPs: the IP profile
    st.header("Domain profile", help="One domain: risk, registration, hosting, VPNDB, BGP routing, DNS, CNAMEs, "
                                     "certificates, history and alerts. Each section links to the page with the full detail.")
    if not domains:
        st.info("No domain is selected in the toolbar's *Domains* filter."
                + (" IP addresses and CIDR ranges are on the **IP profile**." if ds.selected_domains else ""))
        if ds.selected_domains:
            navigation.link("ip_profile", label="Open the IP profile")
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
        ("Alerts", f"{len(alerts):,}", "Active alerts in the analysis window; below, the highest severity among them",
         f"Highest severity: {ranked.iloc[0]['Severity']}" if not ranked.empty else None),
        ("Hostnames with a CNAME", f"{mine['Hostname'].nunique():,}" if not mine.empty else "0", "In the analysis window"),
        ("Certificates", f"{certs['Hash'].nunique() if 'Hash' in certs else len(certs):,}", "In the analysis window"),
    ]
    for col, (label, value, help_text, *delta) in zip(metric_slots(len(metrics)), metrics):
        metric(col, label, value, note=delta[0] if delta else None, help=help_text)
    _render_risk(ds, domain, ctx.thresholds)
    if profile is not None and profile.get("DIF Breakdown"):
        st.caption(f"**DIF** `{profile['DIF Fingerprint']}` — {profile['DIF Breakdown']}")
    if profile is not None:
        drivers = score_drivers(profile, view.active)
        if drivers:
            st.caption("**Why this score:** " + md_escape(drivers_text(drivers)))
    _render_verdict(domain)
    _render_actions(domain)

    iris = extract_iris_profile(ds.enrichment.get(domain, {}))
    c_reg, c_host = st.columns(2)
    with c_reg.container(border=True):
        st.markdown("**Registration** (Iris Investigate)")
        facts = {"Registrar": iris["registrar"], "Created": iris["create_date"], "Expires": iris["expiration_date"],
                 "First seen": iris["first_seen"], "Web server": iris["server_type"],
                 "Website response": iris["website_response"],
                 "Popularity rank": f"{iris['popularity_rank']:,}" if iris["popularity_rank"] else "not ranked",
                 "Redirects to": iris["redirect_domain"] or iris["redirect"],
                 "Email domains": ", ".join(iris["email_domains"])}
        st.dataframe(pd.DataFrame([{"Field": k, "Value": "" if v is None or pd.isna(v) else str(v)[:80]}
                                   for k, v in facts.items()]), hide_index=True, width="stretch")
    with c_host.container(border=True):
        st.markdown("**Hosting** (Iris Investigate)")
        ips = pd.DataFrame(iris["ips"]).rename(columns={"ip": "IP", "asn": "ASN", "isp": "ISP", "country": "Country"})
        if ips.empty:
            st.caption("No current IP address.")
        else:
            picked = st.dataframe(ips, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
                                  key=f"profile_hosting_ips::{domain}")
            rows = picked.selection.rows if picked and picked.selection else []
            from views.ip_profile_view import open_button as open_ip
            open_ip(ips.iloc[rows[0]]["IP"] if rows else ips.iloc[0]["IP"],
                    label=f"Open {ips.iloc[rows[0]]['IP'] if rows else ips.iloc[0]['IP']} in IP profile",
                    key="profile_ip_open")
        st.caption("**Name servers:** " + (", ".join(iris["name_servers"]) or "none"))
        st.caption("**Mail (MX):** " + (", ".join(iris["mx_hosts"]) or "none")
                   + (f"  \n**SPF:** `{iris['spf'][:200]}`" if iris["spf"] else ""))
        navigation.link("dns", label="Hosting and DNS of every domain")
    window_ips = set(explode_ip_events(ds.pdns_utc[ds.pdns_utc["Domain"] == domain])["IP"].astype(str)) \
        if not ds.pdns_utc.empty else set()
    _render_vpndb(ds, domain, set(ips["IP"].astype(str)) if not ips.empty else set(), window_ips)
    _render_bgp(ds, domain)
    _render_similar(ctx, domain)

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
            cols = [c for c in ("Common Name", "Issuer", "Not Before", "Not After", "JA4X", "Source") if c in certs]
            from core.cert_profile import most_relevant, when
            newest = certs.assign(_nb=certs["Not Before"].map(when) if "Not Before" in certs else pd.NaT) \
                .sort_values("_nb", ascending=False, na_position="last")
            shown = newest.drop_duplicates("Hash" if "Hash" in certs else cols).head(8)[cols].astype(str)
            if "JA4X" in shown:
                shown = shown.assign(JA4X=[f"{value} · {note}" if note else value for value, note in
                                           zip(shown["JA4X"].replace("nan", ""), shown["JA4X"].map(ja4x_note))])
            st.dataframe(shown, hide_index=True, width="stretch")
            c_every, c_open = st.columns(2)
            with c_every:
                navigation.link("certs", label="Every certificate")
            if "Hash" in newest:
                from core.cert_profile import certificates
                from views.cert_profile_view import open_button
                best = most_relevant(certificates(certs), domain)
                if best:
                    open_button(best, label="Domain's certificate in Certificate profile",
                                key="profile_cert_open", container=c_open, domain=domain)
        every = ds.ssl_all_utc[ds.ssl_all_utc["Domain"] == domain] if not ds.ssl_all_utc.empty else certs
        if not every.empty:
            from views.ssl_view import render_ja4x_notes  # the Certificates page imports this page's helpers
            render_ja4x_notes(every, f"profile_ja4x_{domain}", title="**JA4X of this domain's certificates**",
                              empty="{count} JA4X value(s), none on a built-in list or unusual.", window_ssl=certs)
    with c_hist:
        st.subheader("Latest Domain History changes")
        history = ds.dh[ds.dh["Domain"] == domain] if not ds.dh.empty else ds.dh
        render_history_cap_notice([domain], key="profile_history_rest")
        if history.empty:
            st.caption("No Domain History changes in the analysis window.")
        else:
            cols = [c for c in ("Timestamp", "Field", "Before", "After") if c in history]
            latest = history.assign(_ts=pd.to_datetime(history.get("Timestamp"), errors="coerce", utc=True)) \
                .sort_values("_ts", ascending=False, na_position="last")
            st.dataframe(latest.head(10)[cols].astype(str), hide_index=True, width="stretch")
            navigation.link("raw", label="Every record")
