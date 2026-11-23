"""Builds the filtered, normalized, and timezone-shifted frames consumed by the dashboard views."""
from dataclasses import dataclass, field

import pandas as pd

from config import HOSTNAME_NEW_DAYS
from core.anonymizers import for_domains
from core.correlation import build_ip_observations
from core.hostnames import apply_certificate_focus, apply_focus, build_hostname_certificates, build_hostname_inventory
from core.network_intel import build_ip_intel
from core.pdns_features import add_event_gaps
from core.threat_detection import analyze_txt_fingerprints
from core.timezone import apply_tz_shift
from core.window import AnalysisWindow, filter_cert_events, filter_certificates, filter_pdns, filter_point_events

SSL_SOURCE_PRIORITY = {"DomainTools Cert API": 1, "CertsQL search": 1, "Iris Investigate API": 2, "Domain History": 3}


@dataclass
class Dataset:
    selected_domains: list
    timezone: str
    pdns_provider: str
    risk: pd.DataFrame = field(default_factory=pd.DataFrame)
    enrichment: dict = field(default_factory=dict)
    # UTC frames (threat engine input)
    dh_utc: pd.DataFrame = field(default_factory=pd.DataFrame)
    pdns_utc: pd.DataFrame = field(default_factory=pd.DataFrame)
    ssl_utc: pd.DataFrame = field(default_factory=pd.DataFrame)
    events_utc: pd.DataFrame = field(default_factory=pd.DataFrame)
    # Timezone-shifted display frames
    dh: pd.DataFrame = field(default_factory=pd.DataFrame)
    pdns: pd.DataFrame = field(default_factory=pd.DataFrame)
    ssl: pd.DataFrame = field(default_factory=pd.DataFrame)
    dh_norm: pd.DataFrame = field(default_factory=pd.DataFrame)
    pdns_norm: pd.DataFrame = field(default_factory=pd.DataFrame)
    combined: pd.DataFrame = field(default_factory=pd.DataFrame)
    txt_apps: pd.DataFrame = field(default_factory=pd.DataFrame)
    cert_hostnames: pd.DataFrame = field(default_factory=pd.DataFrame)
    ctl: pd.DataFrame = field(default_factory=pd.DataFrame)
    cert_observations: pd.DataFrame = field(default_factory=pd.DataFrame)
    ip_observations: pd.DataFrame = field(default_factory=pd.DataFrame)
    ip_intel: dict = field(default_factory=dict)
    pdns_coverage: dict = field(default_factory=dict)
    cname_chases: pd.DataFrame = field(default_factory=pd.DataFrame)   # DNSDB CNAME chases (run + CNAME Chains lens)
    resolutions: pd.DataFrame = field(default_factory=pd.DataFrame)    # DNSDB lookups of the DNS tree (DNS resolution)
    resolution_routing: pd.DataFrame = field(default_factory=pd.DataFrame)   # BGPDB origins of its addresses
    cname_rdata: pd.DataFrame = field(default_factory=pd.DataFrame)    # reverse CNAME lookups (CNAME Chains lens)
    anonymizers: pd.DataFrame = field(default_factory=pd.DataFrame)    # VPNDB verdict per hosting IP (core.anonymizers)
    prefixes: pd.DataFrame = field(default_factory=pd.DataFrame)       # VPNDB verdict per CIDR target
    prefix_addresses: pd.DataFrame = field(default_factory=pd.DataFrame)   # addresses VPNDB reached in each CIDR
    range_ips: pd.DataFrame = field(default_factory=pd.DataFrame)      # every address of a CIDR target (VPNDB bulk)
    exit_weeks: pd.DataFrame = field(default_factory=pd.DataFrame)     # VPNDB weekly history of the exits
    neighbour_ranges: pd.DataFrame = field(default_factory=pd.DataFrame)   # /24s around the hosting IPs (VPNDB)
    hosting_asns: pd.DataFrame = field(default_factory=pd.DataFrame)   # VPNDB providers on the Iris ASNs
    exit_neighbours: pd.DataFrame = field(default_factory=pd.DataFrame)    # other names on dedicated exits (DNSDB)
    vpndb_raw: pd.DataFrame = field(default_factory=pd.DataFrame)      # every VPNDB answer as received
    tor_overview: dict = field(default_factory=dict)                  # VPNDB /tor overview of the Tor network
    bgp_origins: pd.DataFrame = field(default_factory=pd.DataFrame)    # BGPDB: prefix and origin per hosting IP
    bgp_asns: pd.DataFrame = field(default_factory=pd.DataFrame)       # BGPDB: origin and upstream networks
    bgp_routes: pd.DataFrame = field(default_factory=pd.DataFrame)     # BGPDB: AS paths towards the prefixes
    bgp_neighbours: pd.DataFrame = field(default_factory=pd.DataFrame)   # BGPDB: prefixes announced around them
    bgp_raw: pd.DataFrame = field(default_factory=pd.DataFrame)        # every BGPDB answer as received
    host_focus: dict = field(default_factory=dict)                      # apex -> hostnames the views are focused on
    hostname_inventory: pd.DataFrame = field(default_factory=pd.DataFrame)   # every hostname, full history, unfocused
    hostname_certificates: pd.DataFrame = field(default_factory=pd.DataFrame)   # inventory hostname -> certificate links
    # Analysis window and the full-history engine inputs (used to count alerts outside the window)
    window: AnalysisWindow = field(default_factory=AnalysisWindow)
    window_stats: dict = field(default_factory=dict)
    events_all_utc: pd.DataFrame = field(default_factory=pd.DataFrame)
    ssl_all_utc: pd.DataFrame = field(default_factory=pd.DataFrame)
    cert_hostnames_all: pd.DataFrame = field(default_factory=pd.DataFrame)
    derived: dict = field(default_factory=dict)   # tables built from this dataset on first use (e.g. IOCs), kept with it


def _concat(frames):
    frames = [f for f in frames if f is not None and not f.empty]
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def dedupe_certificates(ssl_df):
    """Keeps one row per (Domain, Hash), preferring the richest source (Cert API > Iris > Domain History)."""
    if ssl_df.empty or "Source" not in ssl_df.columns or "Hash" not in ssl_df.columns:
        return ssl_df
    ranked = ssl_df.assign(_rank=ssl_df["Source"].map(SSL_SOURCE_PRIORITY).fillna(4))
    ranked = ranked.sort_values(["Domain", "Hash", "_rank"], kind="stable")
    return ranked.drop_duplicates(subset=["Domain", "Hash"], keep="first").drop(columns="_rank").reset_index(drop=True)


def _filter(df, domains, fields=None):
    if df is None or df.empty:
        return pd.DataFrame()
    mask = df["Domain"].isin(domains)
    if fields is not None and "Field" in df.columns:
        mask &= df["Field"].isin(fields)
    return df[mask].copy()


def _merged_events_with_history(dh, pdns):
    """DH + pDNS events with dormancy gaps computed on the FULL history, so windowed rules keep their context."""
    events = _concat([dh, pdns])
    if events.empty or "Date" not in events.columns:
        return events
    events["Date"] = pd.to_datetime(events["Date"], errors="coerce")
    return add_event_gaps(events.dropna(subset=["Date"]))


def build_dataset(collected, selected_domains, dh_fields, pdns_fields, timezone, window=None, host_focus=None):
    """
    Applies domain/field filters, the hostname focus and the analysis window, merges SSL sources, normalizes event
    frames, and shifts timezones. Event gaps are computed on full history before windowing. `host_focus`
    ({apex: [hostnames]}) keeps only the passive DNS names, certificates and certificate events of those hostnames for
    the focused domains; the hostname inventory is built before the focus so it lists every hostname.
    """
    window = window or AnalysisWindow()
    ds = Dataset(selected_domains=list(selected_domains), timezone=timezone, pdns_provider=collected.pdns_provider, window=window)
    ds.risk = _filter(collected.risk, selected_domains)
    ds.enrichment = {k: v for k, v in collected.enrichment.items() if k in selected_domains}

    dh_all = _filter(collected.dh, selected_domains, dh_fields)
    if not dh_all.empty:
        dh_all["Value"] = dh_all["After"]
    pdns_all = _filter(collected.pdns, selected_domains, pdns_fields)
    ssl_all = dedupe_certificates(_concat([_filter(collected.ssl, selected_domains), _filter(collected.ssl_active, selected_domains)]))
    hostnames_all = _filter(collected.cert_hostnames, selected_domains)

    ds.host_focus = {apex: hosts for apex, hosts in (host_focus or {}).items() if apex in selected_domains and hosts}
    ds.hostname_inventory = build_hostname_inventory(pdns_all, ssl_all, hostnames_all, selected_domains, ds.host_focus,
                                                     getattr(collected, "pdns_coverage", {}) or {}, new_days=HOSTNAME_NEW_DAYS)
    ds.hostname_certificates = build_hostname_certificates(ssl_all, ds.hostname_inventory["Hostname"])
    pdns_all = apply_focus(pdns_all, ds.host_focus, "RRName")
    ssl_all = apply_certificate_focus(ssl_all, ds.host_focus)
    hostnames_all = apply_focus(hostnames_all, ds.host_focus, "Hostname")

    ds.events_all_utc = _merged_events_with_history(dh_all, pdns_all)
    ds.ssl_all_utc = ssl_all
    ds.cert_hostnames_all = hostnames_all

    ds.dh_utc = filter_point_events(dh_all, window)
    ds.pdns_utc = filter_pdns(pdns_all, window)
    ds.events_utc = filter_pdns(ds.events_all_utc, window)
    ds.ssl_utc = filter_certificates(ssl_all, window)
    ds.cert_hostnames = filter_cert_events(hostnames_all, window)
    ds.window_stats = {
        "Passive DNS": (len(ds.pdns_utc), len(pdns_all)),
        "Domain History": (len(ds.dh_utc), len(dh_all)),
        "Certificates": (len(ds.ssl_utc), len(ssl_all)),
        "Cert Events": (len(ds.cert_hostnames), len(hostnames_all)),
    }

    ds.dh = apply_tz_shift(ds.dh_utc, ["Date"], timezone)
    ds.pdns = apply_tz_shift(ds.pdns_utc, ["Date", "First Seen", "Last Seen", "Start", "End"], timezone)
    ds.ssl = apply_tz_shift(ds.ssl_utc, ["Date", "Not Before Date", "Not After Date"], timezone)

    if not ds.dh.empty:
        dh_norm = ds.dh.copy()
        dh_norm["RRName"] = dh_norm["Domain"]
        dh_norm["Count"] = 1
        dh_norm["Data Source"] = "Domain History"
        dh_norm["Field"] = "DH: " + dh_norm["Field"].astype(str)
        ds.dh_norm = dh_norm
    if not ds.pdns.empty:
        pdns_norm = ds.pdns.copy()
        pdns_norm["Data Source"] = f"Passive DNS ({collected.pdns_provider})"
        pdns_norm["Field"] = "pDNS: " + pdns_norm["Field"].astype(str)
        ds.pdns_norm = pdns_norm
    ds.combined = _concat([ds.pdns_norm, ds.dh_norm])
    ds.txt_apps = analyze_txt_fingerprints(ds.combined)

    ds.ctl = filter_point_events(collected.ctl, window, "Timestamp")
    ds.cert_observations = filter_point_events(collected.cert_observations, window, "Timestamp")
    ds.ip_intel = build_ip_intel(ds.enrichment)
    ds.pdns_coverage = getattr(collected, "pdns_coverage", {}) or {}
    chases = getattr(collected, "cname_chases", None)
    ds.cname_chases = chases if chases is not None else pd.DataFrame()
    rdata = getattr(collected, "cname_rdata", None)
    ds.cname_rdata = rdata if rdata is not None else pd.DataFrame()
    resolutions = getattr(collected, "resolutions", None)
    ds.resolutions = resolutions if resolutions is not None else pd.DataFrame()
    routing = getattr(collected, "resolution_routing", None)
    ds.resolution_routing = routing if routing is not None else pd.DataFrame()
    ds.anonymizers = for_domains(getattr(collected, "anonymizers", None), selected_domains).reset_index(drop=True)
    raw = getattr(collected, "vpndb_raw", None)   # the run's answers, whatever the view filter (like Data sources)
    ds.vpndb_raw = raw if raw is not None else pd.DataFrame()
    ds.tor_overview = getattr(collected, "tor_overview", None) or {}
    ips = set(ds.anonymizers["IP"]) if not ds.anonymizers.empty else set()
    for name, column in (("exit_weeks", "IP"), ("exit_neighbours", "IP"), ("neighbour_ranges", "Domains"),
                         ("hosting_asns", "Domains")):   # the parts of the selected domains
        frame = getattr(collected, name, None)
        if frame is None or frame.empty:
            setattr(ds, name, pd.DataFrame())
            continue
        keep = frame[column].isin(ips) if column == "IP" else frame[column].astype(str).map(
            lambda d: bool(set(selected_domains) & {x.strip() for x in d.split(",")}))
        setattr(ds, name, frame[keep].reset_index(drop=True))
    for name in ("prefixes", "prefix_addresses", "range_ips"):   # CIDR targets are filtered like domains
        frame = getattr(collected, name, None)
        setattr(ds, name, frame[frame["CIDR"].isin(selected_domains)].reset_index(drop=True)
                if frame is not None and not frame.empty else pd.DataFrame())

    _bgp_frames(ds, collected, selected_domains)

    pivots = getattr(collected, "ip_pivots", pd.DataFrame())
    if pivots is not None and not pivots.empty:
        selected = set(selected_domains)
        pivots = pivots[pivots["Related"].astype(str).map(lambda r: bool(selected & {x.strip() for x in r.split(",")}))]
    # Full history: hop detection needs the domains that used an IP before the window; hops are windowed by the engine
    ds.ip_observations = build_ip_observations(pdns_all, pivots)
    return ds


def _bgp_frames(ds, collected, selected_domains):
    """The BGPDB frames of the selected domains: their IPs' origins, the routes and neighbours of those prefixes, and
    the networks on them (a run saved before BGPDB existed has none)."""
    origins = getattr(collected, "bgp_origins", None)
    if origins is None or origins.empty:
        for name in ("bgp_origins", "bgp_asns", "bgp_routes", "bgp_neighbours"):
            setattr(ds, name, pd.DataFrame())
    else:
        selected = set(selected_domains)
        keep = origins["Domains"].astype(str).map(lambda v: bool(selected & {d.strip() for d in v.split(",")}))
        ds.bgp_origins = origins[keep].reset_index(drop=True)
        prefixes = set(ds.bgp_origins["Prefix"])
        routes = getattr(collected, "bgp_routes", None)
        ds.bgp_routes = routes[routes["Prefix"].isin(prefixes)].reset_index(drop=True) \
            if routes is not None and not routes.empty else pd.DataFrame()
        networks = set(ds.bgp_origins["Origin"]) | (set(ds.bgp_routes["Upstream"]) if not ds.bgp_routes.empty else set())
        asns = getattr(collected, "bgp_asns", None)
        ds.bgp_asns = asns[asns["ASN"].isin(networks)].reset_index(drop=True) \
            if asns is not None and not asns.empty else pd.DataFrame()
        near = getattr(collected, "bgp_neighbours", None)
        ds.bgp_neighbours = near[near["Run Prefix"].astype(str).map(
            lambda v: bool(prefixes & {p.strip() for p in v.split(",")}))].reset_index(drop=True) \
            if near is not None and not near.empty else pd.DataFrame()
    raw = getattr(collected, "bgp_raw", None)
    ds.bgp_raw = raw if raw is not None else pd.DataFrame()


def expand_multiline_rows(df, split_cols, blank_cols):
    """
    Splits newline-separated values in `split_cols` into one row per line (columns padded to equal length)
    and blanks `blank_cols` on continuation rows. Vectorized replacement for per-row copying.
    """
    if df.empty:
        return df
    out = df.copy()
    for col in split_cols:
        out[col] = out[col].astype(str).str.split("\n")
    lengths = out[split_cols].apply(lambda col: col.str.len()).max(axis=1)
    for col in split_cols:
        out[col] = [vals + [""] * (n - len(vals)) for vals, n in zip(out[col], lengths)]
    out = out.explode(split_cols, ignore_index=False)
    continuation = out.groupby(level=0).cumcount() > 0
    for col in blank_cols:
        if col in out.columns:
            out[col] = out[col].astype(object)
            out.loc[continuation.to_numpy(), col] = ""
    return out.reset_index(drop=True)
