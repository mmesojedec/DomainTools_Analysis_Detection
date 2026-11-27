"""
IP profile: one IP address or CIDR range of the run, the way the Domain and Certificate profiles show a domain or a
certificate. Everything comes from the loaded data (no request): which addresses there are (the IP and CIDR targets,
the domains' hosting IPs, the addresses the DNS resolution reached), and for one of them its hosting, BGP routing,
VPNDB verdict, the names and domains seen on it, the certificates naming it or served on it, and the alerts naming it.
"""
import ipaddress

import pandas as pd

from core.address_targets import address_targets, names_on
from core.helpers import extract_ip_addresses, is_cidr, is_ip_address, registrable_domain
from core.network_intel import cdn_for_ip, explode_ip_events, is_public_ip

KINDS = ("IP target", "Range target", "Hosting", "Resolved")
CANDIDATE_COLUMNS = ["Address", "Kind", "Domains", "Alerts", "Routing", "VPNDB", "Notes"]
USE_COLUMNS = ["Domain", "Analyzed", "Names", "Records", "First Seen", "Last Seen"]
SERVED_COLUMNS = ["SHA-256", "Hostname", "Common Name", "Issuer", "JA4X", "First Seen", "Last Seen"]
NAMED_COLUMNS = ["SHA-256", "Common Name", "Issuer", "Not Before", "Not After", "JA4X", "SANs"]
RANGE_COLUMNS = ["Address", "Names", "Domains", "VPNDB", "Alerts"]
EXIT_CATEGORIES = ("VPN", "Residential proxy", "Tor", "Proxy")


def _frame(ds, name):
    frame = getattr(ds, name, None)
    return frame if frame is not None and not frame.empty else pd.DataFrame()


def kind_of(address, targets=()):
    if is_cidr(address):
        return "Range target"
    return "IP target" if address in set(targets or ()) else "Hosting"


def alert_ips(alerts):
    """[(alert index, {IPs it names})]: the addresses in each alert's text, read once for every candidate."""
    if alerts is None or alerts.empty:
        return []
    return [(i, set(extract_ip_addresses(" ".join(str(v) for v in row.values()))))
            for i, row in zip(alerts.index, alerts.to_dict("records"))]


def alerts_naming(alerts, address, named=None):
    """The alerts whose text names the address (or an address in the range)."""
    if alerts is None or alerts.empty:
        return pd.DataFrame()
    named = named if named is not None else alert_ips(alerts)
    if is_cidr(address):
        network = ipaddress.ip_network(address, strict=False)
        hits = [i for i, ips in named if any(_in(ip, network) for ip in ips)]
    else:
        hits = [i for i, ips in named if address in ips]
    if "Domain" in alerts:   # an alert raised on the target itself
        hits += list(alerts.index[alerts["Domain"].astype(str) == address])
    return alerts.loc[list(dict.fromkeys(hits))]


def _in(ip, network):
    try:
        return ipaddress.ip_address(ip) in network
    except ValueError:
        return False


def _ip_uses(ds):
    """explode_ip_events of the full history (every A / AAAA record, the IP and CIDR targets' reverse lookups too)."""
    events = _frame(ds, "events_all_utc")
    if events.empty:
        events = _frame(ds, "pdns")
    return explode_ip_events(events) if not events.empty else pd.DataFrame(columns=["Domain", "RRName", "IP"])


def routing_status(ds):
    """{IP: status of its usual origin} from the BGPDB origins."""
    origins = _frame(ds, "bgp_origins")
    if origins.empty:
        return {}
    ranked = origins.sort_values("Updates", ascending=False).drop_duplicates("IP")
    return dict(zip(ranked["IP"].astype(str), ranked["Status"]))


def vpndb_label(ds, ip):
    table = _frame(ds, "anonymizers")
    if table.empty:
        return ""
    row = table[table["IP"].astype(str) == ip]
    if row.empty:
        return ""
    row = row.iloc[0]
    return " · ".join(str(v) for v in (row.get("Category"), row.get("Provider")) if v and str(v) != "nan")


def candidates(ds, targets, alerts=None):
    """
    CANDIDATE_COLUMNS: every address the profile can show, the targets first, then the hosting and resolved addresses
    by what there is to see (alerts, an unauthorized route, an anonymizer exit, how many domains use it).
    """
    targets = list(targets or [])
    found = {}

    def add(address, kind):
        if address and address not in found:
            found[address] = kind

    for target in address_targets(targets):
        add(target, kind_of(target, targets))
    uses = _ip_uses(ds)
    domain_uses = uses[~uses["Domain"].astype(str).map(lambda d: is_ip_address(d) or is_cidr(d))] \
        if not uses.empty else uses
    for ip in domain_uses["IP"].astype(str) if not domain_uses.empty else []:
        add(ip, "Hosting")
    for ip in (getattr(ds, "ip_intel", None) or {}):
        add(str(ip), "Hosting")
    for name in ("bgp_origins", "anonymizers"):
        frame = _frame(ds, name)
        if "Domains" in frame:   # not the address a CIDR target is looked up by: that is the range's own row
            frame = frame[~frame["Domains"].astype(str).map(
                lambda v: all(is_cidr(d.strip()) for d in v.split(",") if d.strip()) and bool(v.strip()))]
        for ip in frame["IP"].astype(str) if "IP" in frame else []:
            add(ip, "Hosting")
    routing = _frame(ds, "resolution_routing")
    for ip in routing["IP"].astype(str) if "IP" in routing else []:
        add(ip, "Resolved")
    found = {a: k for a, k in found.items() if is_cidr(a) or is_ip_address(a)}
    named = alert_ips(alerts)
    counts = domain_uses.groupby(domain_uses["IP"].astype(str))["Domain"].nunique().to_dict() \
        if not domain_uses.empty else {}
    status = routing_status(ds)
    rows = []
    for address, kind in found.items():
        hits = alerts_naming(alerts, address, named) if named else pd.DataFrame()
        iris = (getattr(ds, "ip_intel", None) or {}).get(address) or {}
        domains = counts.get(address, 0) or len(iris.get("domains") or ())
        notes = []
        if is_ip_address(address):
            if not is_public_ip(address):
                notes.append("private / reserved")
            elif cdn_for_ip(address):
                notes.append(f"CDN: {cdn_for_ip(address)}")
        rows.append({"Address": address, "Kind": kind, "Domains": int(domains), "Alerts": len(hits),
                     "Routing": status.get(address, ""), "VPNDB": vpndb_label(ds, address), "Notes": ", ".join(notes)})
    table = pd.DataFrame(rows, columns=CANDIDATE_COLUMNS)
    if table.empty:
        return table
    interest = (table["Alerts"] * 10 + (table["Routing"] == "Unauthorized") * 8
                + table["VPNDB"].str.contains("|".join(EXIT_CATEGORIES), case=False) * 6 + table["Domains"].clip(upper=20))
    order = table["Kind"].map({k: i for i, k in enumerate(KINDS)})
    return table.assign(_o=order, _i=interest).sort_values(["_o", "_i"], ascending=[True, False]) \
        .drop(columns=["_o", "_i"]).reset_index(drop=True)


def domains_using(ds, address):
    """
    USE_COLUMNS: the domains whose names resolved to the address (or into the range), from the run's passive DNS and
    Domain History and the targets' reverse lookups, plus the run's domains Iris has on it now. Analyzed = one of the
    run's own domains.
    """
    uses = _ip_uses(ds)
    analyzed = set(getattr(ds, "selected_domains", None) or [])
    if not uses.empty:
        if is_cidr(address):
            network = ipaddress.ip_network(address, strict=False)
            uses = uses[uses["IP"].astype(str).map(lambda ip: _in(ip, network))]
        else:
            uses = uses[uses["IP"].astype(str) == address]
    rows = []
    if not uses.empty:
        names = uses["RRName"].fillna("").astype(str).str.rstrip(".")   # pandas keeps NaN through astype(str)
        owner = uses["Domain"].fillna("").astype(str)
        domain = [o if o in analyzed and not (is_ip_address(o) or is_cidr(o)) else (registrable_domain(n) or n or o)
                  for o, n in zip(owner, names)]   # a row without a record name keeps its domain
        seen = uses.assign(_domain=domain, _name=names,
                           _last=pd.to_datetime(uses["Last Seen"], errors="coerce").fillna(
                               pd.to_datetime(uses.get("Date"), errors="coerce")))
        for name, group in seen.groupby("_domain"):
            rows.append({"Domain": name, "Analyzed": name in analyzed, "Names": ", ".join(sorted({n for n in group["_name"] if n})[:5]),
                         "Records": len(group), "First Seen": pd.to_datetime(group.get("Date"), errors="coerce").min(),
                         "Last Seen": group["_last"].max()})
    iris = (getattr(ds, "ip_intel", None) or {}).get(address) or {}
    listed = {r["Domain"] for r in rows}
    rows += [{"Domain": d, "Analyzed": d in analyzed, "Names": "(Iris: current IP)", "Records": 0,
              "First Seen": pd.NaT, "Last Seen": pd.NaT} for d in sorted(iris.get("domains") or ()) if d not in listed]
    table = pd.DataFrame(rows, columns=USE_COLUMNS)
    return table.sort_values(["Analyzed", "Last Seen"], ascending=[False, False], na_position="last") \
        .reset_index(drop=True)


def certificates_served(ds, address):
    """SERVED_COLUMNS: certificates the Certificate API saw served on the address (or an address in the range)."""
    events = _frame(ds, "cert_hostnames")
    if events.empty or "IP" not in events:
        return pd.DataFrame(columns=SERVED_COLUMNS)
    if is_cidr(address):
        network = ipaddress.ip_network(address, strict=False)
        rows = events[events["IP"].astype(str).map(lambda ip: _in(ip, network))]
    else:
        rows = events[events["IP"].astype(str) == address]
    if rows.empty:
        return pd.DataFrame(columns=SERVED_COLUMNS)
    ssl = _frame(ds, "ssl")
    by_hash = ssl.drop_duplicates("Hash").set_index("Hash") if "Hash" in ssl else pd.DataFrame()

    def cert(sha, column):
        return str(by_hash.at[sha, column]) if not by_hash.empty and sha in by_hash.index and column in by_hash else ""

    table = pd.DataFrame({
        "SHA-256": rows["Cert_SHA256"].astype(str), "Hostname": rows["Hostname"].astype(str),
        "First Seen": pd.to_datetime(rows["First Seen"], errors="coerce", utc=True),
        "Last Seen": pd.to_datetime(rows["Last Seen"], errors="coerce", utc=True)})
    table["Common Name"] = table["SHA-256"].map(lambda s: cert(s, "Common Name"))
    table["Issuer"] = table["SHA-256"].map(lambda s: cert(s, "Issuer"))
    table["JA4X"] = table["SHA-256"].map(lambda s: cert(s, "JA4X"))
    return table.drop_duplicates(["SHA-256", "Hostname"]).sort_values("Last Seen", ascending=False,
                                                                       na_position="last")[SERVED_COLUMNS]


def certificates_naming(ds, address):
    """NAMED_COLUMNS: certificates with the address (or an address in the range) among their SAN IPs."""
    ssl = _frame(ds, "ssl")
    if ssl.empty:
        return pd.DataFrame(columns=NAMED_COLUMNS)
    network = ipaddress.ip_network(address, strict=False) if is_cidr(address) else None

    def names_it(row):
        if str(row.get("Domain")) == address:
            return True
        ips = [p.strip() for col in ("SAN IPv4", "SAN IPv6") for p in str(row.get(col) or "").split(",") if p.strip()]
        return any(_in(ip, network) for ip in ips) if network is not None else address in ips

    rows = ssl[[names_it(r) for r in ssl.to_dict("records")]]
    if rows.empty:
        return pd.DataFrame(columns=NAMED_COLUMNS)
    sans = rows.apply(lambda r: ", ".join(p for p in (str(r.get("SAN IPv4") or ""), str(r.get("SAN DNS") or ""))
                                          if p and p != "nan")[:120], axis=1)
    table = pd.DataFrame({"SHA-256": rows.get("Hash"), "Common Name": rows.get("Common Name"),
                          "Issuer": rows.get("Issuer"), "Not Before": rows.get("Not Before"),
                          "Not After": rows.get("Not After"), "JA4X": rows.get("JA4X"), "SANs": sans})
    return table.drop_duplicates("SHA-256").reset_index(drop=True)[NAMED_COLUMNS]


def routing(ds, address):
    """The BGPDB view of one address or range: its origin rows, the usual one, every upstream, the more-specifics
    inside its prefixes (or the range), and the AS paths."""
    from core import bgp
    origins = _frame(ds, "bgp_origins")
    if not origins.empty:
        if is_cidr(address):
            mine = origins["Domains"].astype(str).map(lambda v: address in {d.strip() for d in v.split(",")})
        else:
            mine = origins["IP"].astype(str) == address
        origins = origins[mine]
    resolved = _frame(ds, "resolution_routing")
    main = bgp.main_origins(origins).sort_values("Updates", ascending=False).iloc[0] if not origins.empty else None
    prefixes = set(origins["Prefix"].astype(str).str.rstrip("+")) if not origins.empty else set()
    routes = _frame(ds, "bgp_routes")
    routes = routes[routes["Prefix"].isin(prefixes)] if not routes.empty else routes
    upstreams = [u for ups in bgp.prefix_upstreams(routes).values() for u in ups]
    near = _frame(ds, "bgp_neighbours")
    if not near.empty:
        near = near[near["Covering Range"].isin(prefixes | ({address} if is_cidr(address) else set()))]
    asns = _frame(ds, "bgp_asns")
    networks = asns[asns["ASN"].isin(set(origins["Origin"]) | set(upstreams))] if not asns.empty and not origins.empty \
        else pd.DataFrame()
    resolved_row = resolved[resolved["IP"].astype(str) == address] if "IP" in resolved else pd.DataFrame()
    return {"origins": origins, "main": main, "upstreams": list(dict.fromkeys(upstreams)), "routes": routes,
            "more_specifics": near, "networks": networks, "resolved": resolved_row}


def badges(ds, address, alerts_count=0):
    """[(text, colour)] for the header: routing status, VPNDB verdict, Tor, CDN / private, alerts."""
    out = []
    route = routing(ds, address)
    if route["main"] is not None:
        status = route["main"]["Status"]
        out.append((f"Routing: {status}", {"Valid": "green", "Unauthorized": "red"}.get(status, "gray")))
    elif not route["resolved"].empty:
        status = route["resolved"].iloc[0].get("Status", "")
        out.append((f"Routing: {status}", {"Valid": "green", "Unauthorized": "red"}.get(status, "gray")))
    if is_ip_address(address):
        label = vpndb_label(ds, address)
        if label:
            exit_ = any(c.lower() in label.lower() for c in EXIT_CATEGORIES)
            out.append((f"VPNDB: {label}", "orange" if exit_ else "blue"))
        table = _frame(ds, "anonymizers")
        row = table[table["IP"].astype(str) == address] if not table.empty else table
        if not row.empty and str(row.iloc[0].get("Tor") or "") not in ("", "nan", "None"):
            out.append((f"Tor: {row.iloc[0]['Tor']}", "violet"))
        if not is_public_ip(address):
            out.append(("Private / reserved", "gray"))
        elif cdn_for_ip(address):
            out.append((f"CDN: {cdn_for_ip(address)}", "blue"))
    else:
        prefixes = _frame(ds, "prefixes")
        row = prefixes[prefixes["CIDR"] == address] if not prefixes.empty else prefixes
        if not row.empty and row.iloc[0].get("Top Provider"):
            out.append((f"VPNDB: {row.iloc[0]['Top Provider']} ({row.iloc[0]['Known Exits']} known exits)", "orange"))
    if alerts_count:
        out.append((f"{alerts_count} alert(s)", "red"))
    return out


def why(ds, address, alerts):
    """One plain sentence on what stands out about the address, or ''."""
    parts = []
    if alerts is not None and not alerts.empty and "Threat Type" in alerts:
        top = alerts["Threat Type"].value_counts().index[:2]
        parts.append(f"named by {len(alerts)} alert(s) ({', '.join(top)})")
    route = routing(ds, address)
    if route["main"] is not None and route["main"]["Status"] == "Unauthorized":
        parts.append(f"announced by {route['main']['Origin']} without RPKI / IRR authorization")
    label = vpndb_label(ds, address) if is_ip_address(address) else ""
    if label and any(c.lower() in label.lower() for c in EXIT_CATEGORIES):
        parts.append(f"a {label} exit in VPNDB")
    domains = domains_using(ds, address)
    if len(domains) > 1:
        parts.append(f"{len(domains)} domains seen on it ({int(domains['Analyzed'].sum())} of the run's)")
    return ("It is " if parts and parts[0].startswith(("a ", "announced")) else "") + "; ".join(parts) + "." \
        if parts else ""


def range_addresses(ds, cidr, alerts=None):
    """RANGE_COLUMNS: the addresses of a range the run has something on, busiest first."""
    network = ipaddress.ip_network(cidr, strict=False)
    uses = _ip_uses(ds)
    rows = {}
    if not uses.empty:
        inside = uses[uses["IP"].astype(str).map(lambda ip: _in(ip, network))]
        for ip, group in inside.groupby(inside["IP"].astype(str)):
            rows[ip] = {"Address": ip, "Names": group["RRName"].nunique(),
                        "Domains": group["RRName"].astype(str).map(lambda n: registrable_domain(n.rstrip(".")) or n)
                        .nunique()}
    vpn = _frame(ds, "range_ips")
    if not vpn.empty:
        for row in vpn[vpn["CIDR"] == cidr].to_dict("records"):
            entry = rows.setdefault(str(row["IP"]), {"Address": str(row["IP"]), "Names": 0, "Domains": 0})
            entry["VPNDB"] = " · ".join(str(v) for v in (row.get("Category"), row.get("Top Provider") or
                                                          row.get("Provider")) if v and str(v) != "nan")
    named = alert_ips(alerts)
    for entry in rows.values():
        entry.setdefault("VPNDB", "")
        entry["Alerts"] = sum(1 for _, ips in named if entry["Address"] in ips)
    table = pd.DataFrame(list(rows.values()), columns=RANGE_COLUMNS)
    return table.sort_values(["Alerts", "Names", "Domains"], ascending=False).reset_index(drop=True)


__all__ = ["candidates", "domains_using", "certificates_served", "certificates_naming", "routing", "badges", "why",
           "range_addresses", "alerts_naming", "names_on", "kind_of"]
