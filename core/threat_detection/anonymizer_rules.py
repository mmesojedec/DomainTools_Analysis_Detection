"""
Anonymizer rules (VPNDB): the domain resolves, in the analysis window or now (Iris), to a Tor relay or exit, a
residential proxy exit, or a VPN / proxy exit. Rules read ctx.anonymizers ({ip: core.anonymizers row}).

Following VPNDB's own guidance, a shared exit (many customers leave through it) identifies the service, not the actor:
it still alerts, but only a dedicated exit, or one several analyzed domains use, is treated as an actor indicator. The
compound rules weigh what an exit means for the domain: a new registration behind one, hosting that moved onto one,
or rotation across several exits and providers.

With VPNDB's weekly history of an exit (ctx.exit_weeks), an exit only counts when it was one while the domain used it
(passive DNS first / last seen, or now for a current Iris IP): an address that became a VPN exit after the domain left
it is reused hosting, not an anonymizer the domain chose.
"""
import ipaddress

import pandas as pd

from core.anonymizers import (
    ANONYMIZER_CATEGORIES,
    PROXY,
    RESIDENTIAL,
    TOR,
    VPN,
    dedicated_exit,
    exit_during_use,
    neighbour_cidr,
    shared_exit,
    tor_window,
    use_intervals,
)
from core.network_intel import explode_ip_events
from core.threat_detection.context import MAX_IOC_LINES, evidence_record, fmt_ts

MIN_NETWORK_EXITS = 25   # known exits before a single-tenant ASN counts as one VPN provider's network
CONFIDENCE = {"High": "High", "Medium": "Medium"}   # VPNDB's confidence; Low and Very low stay Low


def _domain_ips(ctx):
    """The IPs the domain used in the analysis window, its current Iris IPs, or the IP target itself."""
    if ctx.is_ip:
        return {ctx.domain}
    ips = {entry["ip"] for entry in ctx.profile.get("ips", [])}
    if not ctx.events.empty:
        ips |= set(explode_ip_events(ctx.events)["IP"].astype(str))
    return ips


def _exit(row):
    return row["Category"] in ANONYMIZER_CATEGORIES


def _exposure(ctx, ip):
    """The exit weeks that overlap the domain's use of `ip`; None when VPNDB's history of it is not known."""
    weeks = ctx.exit_weeks.get(ip)
    if not weeks or ctx.is_ip:
        return None
    current = ip in {entry["ip"] for entry in ctx.profile.get("ips", [])}
    return exit_during_use(use_intervals(ctx.events, ip, current=current, now=ctx.now), weeks)


def _exposed_rows(ctx):
    """{ip: row} of the domain's anonymizer exits that were exits while it used them, each with its overlap weeks
    (`_weeks`) and Iris domain count (`_iris`)."""
    if not ctx.anonymizers:
        return {}
    rows = {}
    for ip in sorted(_domain_ips(ctx)):
        row = ctx.anonymizers.get(ip)
        if row is None or not _exit(row):
            continue
        weeks = _exposure(ctx, ip)
        if weeks == []:   # known history, but not an exit while the domain used it
            continue
        if row["Category"] == TOR and not _tor_overlap(ctx, ip, row):   # a Tor exit before or after the domain
            continue
        rows[ip] = {**row, "_weeks": weeks or [], "_iris": (ctx.ip_intel.get(ip) or {}).get("count")}
    return rows


def _tor_overlap(ctx, ip, row):
    """False when the Tor exit lists date the IP's exit days and none falls in the domain's use of it."""
    window = tor_window(row, ctx.now)
    if window is None or ctx.is_ip:
        return True
    current = ip in {entry["ip"] for entry in ctx.profile.get("ips", [])}
    spans = use_intervals(ctx.events, ip, current=current, now=ctx.now)
    start, end = window
    return not spans or any(s < end and e >= start for s, e in spans)


def _rows(ctx, categories):
    return [row for row in _exposed_rows(ctx).values() if row["Category"] in categories]


def _line(row):
    details = [row["Provider"] or "unknown provider", row["Infrastructure"], row["Tor"],
               f"VPNDB confidence {row['Confidence']}" if row["Confidence"] else "",
               "shared exit: identifies the service, not the actor" if shared_exit(row) else
               "dedicated exit: few users" if dedicated_exit(row) else "",
               f"geo mismatch: {row['Geo Mismatch']}" if row.get("Geo Mismatch") else "",
               f"AS{row['ASN']} {row['AS Organization']}".strip() if row["ASN"] else "", row["Country"],
               f"exit while the domain used it: {_week_span(row['_weeks'])}" if row.get("_weeks") else "",
               f"{row['_iris']:,} domains on it in Iris" if row.get("_iris") else "",
               f"Tor relays: {row['Tor Relays']}" if _has(row, "Tor Relays") else "",
               f"Tor exit {row['Tor Exit First Seen']} to "
               + ("now" if row.get("Tor Exit Current") is True else
                  str(row["Tor Exit Last Seen"]) if _has(row, "Tor Exit Last Seen") else "?")
               if _has(row, "Tor Exit First Seen") else "",
               f"{row['Tor Exit Probability']:.3%} of Tor exit traffic" if _has(row, "Tor Exit Probability") else "",
               f"operator family of {int(row['Tor Family'])} relays" if _has(row, "Tor Family") else "",
               f"Tor reached via {row['Tor Reached Via']}" if _has(row, "Tor Reached Via") else ""]
    return f"{row['IP']} - " + ", ".join(d for d in details if d)


def _has(row, name):
    """A filled cell: not missing, NaN or empty (table rows hold NaN where a verdict had no value)."""
    value = row.get(name)
    return value is not None and value != "" and not (isinstance(value, float) and pd.isna(value)) and value != 0


def _week_span(weeks):
    weeks = sorted(weeks)
    return f"{len(weeks)} week(s), {fmt_ts(weeks[0], '%Y-%m-%d')} to {fmt_ts(weeks[-1], '%Y-%m-%d')}"


def _report(rows):
    """(IOC text, confidence, evidence) of the matching rows; the confidence is VPNDB's best for them."""
    best = max((row["Confidence"] for row in rows), key=["Very low", "", "Low", "Medium", "High"].index, default="")
    lines = [_line(row) for row in rows[:MAX_IOC_LINES]]
    if len(rows) > MAX_IOC_LINES:
        lines.append(f"... {len(rows) - MAX_IOC_LINES} more")
    evidence = [evidence_record(row["Last Seen"] or None, f"VPNDB: {row['Category']}", _line(row), artifact=row["IP"])
                for row in rows]
    return "\n".join(lines), CONFIDENCE.get(best, "Low"), evidence


NEW_TOR_EXIT_DAYS = 30   # a Tor exit first seen this recently was set up next to the domain


def _is_tor_exit(row):
    return _has(row, "Tor Exit First Seen") or str(row.get("Tor") or "").startswith("Exit") or \
        "(exit" in str(row.get("Tor Relays") if _has(row, "Tor Relays") else "")


def rule_tor_node(ctx):
    """The domain resolves to a Tor exit (High) or a relay that does not exit traffic (Medium-High), while the Tor
    Project's lists show it in that role (exit dates checked against the domain's use when known)."""
    rows = _rows(ctx, {TOR})
    if not rows:
        return
    exits = [row for row in rows if _is_tor_exit(row)]
    new = [row for row in exits if _has(row, "Tor Exit First Seen") and (ctx.now - pd.to_datetime(
        row["Tor Exit First Seen"], errors="coerce")).days <= NEW_TOR_EXIT_DAYS]
    iocs, _, evidence = _report(rows)
    what = (f"{len(exits)} IP(s) the domain resolves to exit Tor traffic to the internet" if exits else
            f"{len(rows)} IP(s) the domain resolves to run a Tor relay (guard or middle, not an exit)")
    ctx.add(
        "Domain on Tor Relay / Exit Node", "High" if exits else "Medium-High", "T1090.003 (Proxy: Multi-hop Proxy)",
        what + " (Tor Project data via VPNDB): the host is shared with anonymized traffic, and services on it are "
        "often run by operators who want to stay unattributed."
        + (f" {len(new)} of the exits started in the last {NEW_TOR_EXIT_DAYS} days: set up next to the domain."
           if new else ""),
        iocs, flag="anonymizer", confidence="High", evidence=evidence,
    )


TOR_NETWORK_SHARE = 0.005   # a network carrying 0.5 % of all Tor exit traffic or more is a Tor exit network
TOR_NETWORK_EXITS = 10      # ... or holding this many Tor exit addresses


def rule_hosted_among_tor_exits(ctx):
    """The domain's own IPs are not Tor relays, but they sit in a Tor exit prefix or on a network that carries a
    real share of Tor exit traffic (VPNDB /tor overview): hosting next to Tor exits."""
    if ctx.is_ip or not (ctx.tor_networks or ctx.tor_prefixes):
        return
    tor_ips = {ip for ip, row in (ctx.anonymizers or {}).items() if row["Category"] == TOR}
    asns = {entry["ip"]: entry["asn"] for entry in ctx.profile.get("ips", []) if entry.get("asn")}
    lines, evidence, in_prefix = [], [], False
    for ip in sorted(_domain_ips(ctx) - tor_ips):
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        prefix = next(((net, e) for net, e in ctx.tor_prefixes if address.version == net.version and address in net),
                      None)
        if prefix:
            net, entry = prefix
            lines.append(f"{ip} in Tor exit prefix {net}: {entry.get('exitAddresses', 0)} exit address(es), "
                         f"{entry.get('exitShare', 0):.2%} of Tor exit traffic ({entry.get('organization', '')})")
            evidence.append(evidence_record(None, "Tor exit prefix", str(net), artifact=ip))
            in_prefix = True
            continue
        row = (ctx.anonymizers or {}).get(ip) or {}
        asn = asns.get(ip) or (int(row["ASN"]) if row.get("ASN") is not None and not pd.isna(row["ASN"]) else None)
        entry = ctx.tor_networks.get(asn) if asn else None
        if entry and (entry.get("exitShare", 0) >= TOR_NETWORK_SHARE or entry.get("exitAddresses", 0) >= TOR_NETWORK_EXITS):
            lines.append(f"{ip} on AS{asn} {entry.get('organization', '')}: {entry.get('exitAddresses', 0)} Tor exit "
                         f"address(es), {entry.get('exitShare', 0):.2%} of all Tor exit traffic")
            evidence.append(evidence_record(None, "Tor exit network", f"AS{asn} {entry.get('organization', '')}",
                                            artifact=ip))
    if lines:
        ctx.add(
            "Hosted Among Tor Exits", "Medium", "T1090.003 (Proxy: Multi-hop Proxy)",
            "The domain's own IPs are not Tor relays, but they sit in a prefix with Tor exits or on a network that "
            "carries a real share of Tor exit traffic (VPNDB Tor overview): a hoster that welcomes Tor exits, often "
            "a privacy or bulletproof-style provider, or a server next to the operator's own exits.",
            "\n".join(lines[:MAX_IOC_LINES]), flag="tor_network", confidence="Medium" if in_prefix else "Low",
            evidence=evidence,
        )


def rule_residential_proxy(ctx):
    rows = _rows(ctx, {RESIDENTIAL})
    if rows:
        iocs, confidence, evidence = _report(rows)
        ctx.add(
            "Domain on Residential Proxy Exit", "High", "T1090.002 (Proxy: External Proxy)",
            f"{len(rows)} IP(s) the domain resolves to are residential or mobile proxy exits (VPNDB): home "
            "connections rented out, often without their owners knowing, that hide where the real server is and "
            "evade IP reputation. A legitimate site rarely points its DNS at one.",
            iocs, flag="anonymizer", confidence=confidence, evidence=evidence,
        )


def rule_vpn_exit(ctx):
    rows = _rows(ctx, {VPN, PROXY, "Relay"})
    if rows:
        iocs, confidence, evidence = _report(rows)
        providers = sorted({row["Provider"] for row in rows if row["Provider"]})
        ctx.add(
            "Domain on VPN / Proxy Exit", "Medium-High", "T1090.002 (Proxy: External Proxy)",
            f"{len(rows)} IP(s) the domain resolves to are exits of a commercial VPN or proxy service"
            + (f" ({', '.join(providers)})" if providers else "") + " (VPNDB). Pointing a domain at an anonymizer exit "
            "is unusual: it can mark infrastructure meant to be hard to attribute. A shared exit identifies the "
            "service, not the actor, so do not block it as an indicator on its own.",
            iocs, flag="anonymizer", confidence=confidence, evidence=evidence,
        )


def rule_dedicated_exit(ctx):
    rows = [row for row in _rows(ctx, set(ANONYMIZER_CATEGORIES) - {TOR}) if dedicated_exit(row)]
    if rows:
        iocs, confidence, evidence = _report(rows)
        ctx.add(
            "Domain on Dedicated Anonymizer Exit", "High", "T1090.002 (Proxy: External Proxy)",
            f"{len(rows)} IP(s) the domain resolves to are VPN or proxy exits that few customers share (VPNDB "
            "sharing LOW or IOC value HIGH), such as a dedicated or static VPN IP: unlike a shared exit, the address "
            "points to one customer, so it is worth pivoting on and blocking.",
            iocs, flag="anonymizer_dedicated", confidence=confidence, evidence=evidence,
        )


def _ip_timeline(ctx):
    """{ip: first seen} of the domain's IPs in the analysis window (passive DNS)."""
    if ctx.events.empty:
        return {}
    ips = explode_ip_events(ctx.events)
    if ips.empty:
        return {}
    first = pd.to_datetime(ips["Date"], errors="coerce")
    return first.groupby(ips["IP"].astype(str)).min().dropna().to_dict()


def rule_moved_onto_exit(ctx):
    """The domain used ordinary hosting first and its newest addresses are anonymizer exits."""
    if ctx.is_ip or not ctx.anonymizers:
        return
    timeline = {ip: seen for ip, seen in _ip_timeline(ctx).items() if ip in ctx.anonymizers}
    exposed = _exposed_rows(ctx)
    exits = {ip: seen for ip, seen in timeline.items() if ip in exposed}
    earlier = {ip: seen for ip, seen in timeline.items() if ip not in exits}
    if not exits or not earlier or min(exits.values()) <= min(earlier.values()) \
            or max(timeline, key=timeline.get) not in exits:
        return
    moved = min(exits.values())
    rows = [exposed[ip] for ip in sorted(exits, key=exits.get)]
    iocs, confidence, evidence = _report(rows)
    before = ", ".join(sorted(earlier, key=earlier.get)[:5])
    ctx.add(
        "Hosting Moved onto Anonymizer Exit", "Medium-High", "T1090.002 (Proxy: External Proxy)",
        f"The domain resolved to ordinary hosting first ({before}) and, from {fmt_ts(moved, '%Y-%m-%d')}, to "
        f"{len(rows)} VPN, proxy or Tor exit(s) (VPNDB): the operator moved it behind an anonymizer, often to hide "
        "the real server after it was reported or blocked.",
        f"Before: {before}\n" + iocs, flag="anonymizer_move", confidence=confidence,
        evidence=evidence + [evidence_record(seen, "Earlier hosting", ip, artifact=ip) for ip, seen in earlier.items()],
    )


def rule_exit_rotation(ctx):
    """Several exits, or exits of several providers: rotating anonymized hosting."""
    rows = _rows(ctx, set(ANONYMIZER_CATEGORIES))
    providers = sorted({row["Provider"] for row in rows if row["Provider"]})
    if len(rows) < 3 and len(providers) < 2:
        return
    iocs, _, evidence = _report(rows)
    ctx.add(
        "Domain Rotates Across Anonymizer Exits", "Medium-High", "T1090.002 (Proxy: External Proxy)",
        f"The domain resolves to {len(rows)} anonymizer exits" + (f" of {len(providers)} providers "
                                                                   f"({', '.join(providers[:5])})" if providers else "")
        + " (VPNDB): rotating exits keeps the hosting moving ahead of IP blocks and reputation lists.",
        iocs, flag="anonymizer_rotation", confidence="High" if len(rows) >= 3 and len(providers) >= 2 else "Medium",
        evidence=evidence,
    )


def rule_new_domain_on_exit(ctx):
    """Compound: a newly registered domain (rule_newly_registered) that already points at an anonymizer exit."""
    if not {"nrd", "anonymizer"} <= ctx.flags:
        return
    rows = _rows(ctx, set(ANONYMIZER_CATEGORIES))
    created = ctx.profile.get("create_date")
    iocs, _, evidence = _report(rows)
    ctx.add(
        "Newly Registered Domain on Anonymizer Exit", "High", "T1583.001 (Acquire Infrastructure: Domains)",
        f"Registered on {fmt_ts(created, '%Y-%m-%d')} and already resolving to {len(rows)} VPN, proxy or Tor exit(s) "
        "(VPNDB): a fresh domain hidden behind an anonymizer from the start is a common pattern of phishing and C2 "
        "set-ups.",
        f"Created: {fmt_ts(created, '%Y-%m-%d')}\n" + iocs, flag="anonymizer_nrd", confidence="High",
        evidence=evidence,
    )


def shared_exit_alerts(contexts):
    """
    Cross-domain: one alert per analyzed domain that shares an anonymizer exit with other analyzed domains. Shared
    exits (IOC value LOW or sharing HIGH) are left out: unrelated customers of the service use them too.
    """
    users = {}
    for domain, ctx in contexts.items():
        if ctx.is_ip or not ctx.anonymizers:
            continue
        for ip, row in _exposed_rows(ctx).items():
            if not shared_exit(row):
                users.setdefault(ip, set()).add(domain)
    for domain, ctx in contexts.items():
        shared = {ip: sorted(doms - {domain}) for ip, doms in users.items() if domain in doms and len(doms) > 1}
        if not shared:
            continue
        others = sorted({d for doms in shared.values() for d in doms})
        exposed = _exposed_rows(ctx)
        rows = [exposed[ip] for ip in sorted(shared)]
        lines = [f"{_line(row)} ⇐ also {', '.join(shared[row['IP']][:5])}" for row in rows[:MAX_IOC_LINES]]
        ctx.add(
            "Anonymizer Exit Shared by Analyzed Domains", "Medium-High",
            "T1583.003 (Acquire Infrastructure: Virtual Private Server)",
            f"{len(shared)} anonymizer exit(s) of this domain are also used by {len(others)} other analyzed domain(s) "
            f"({', '.join(others[:10])}{' ...' if len(others) > 10 else ''}). The exits are not ones many customers "
            "share, so the domains are probably run by the same operator.",
            "\n".join(lines), flag="cluster",
            confidence="High" if any(dedicated_exit(row) for row in rows) else "Medium",
            evidence=[evidence_record(row["Last Seen"] or None, "Shared exit", ", ".join(shared[row["IP"]]),
                                      artifact=row["IP"]) for row in rows],
        )


def rule_hosted_among_exits(ctx):
    """The domain's own IPs are not exits, but their /24 holds known VPN / proxy exits, or the network is a VPN
    provider's own (one provider holds 95 % of the ASN's exits, and VPNDB knows at least MIN_NETWORK_EXITS there):
    hosted on an anonymizer operator's servers."""
    if ctx.is_ip or not (ctx.neighbours or ctx.asn_verdicts):
        return
    exits = set(_exposed_rows(ctx))
    lines, evidence, strong = [], [], False
    for ip in sorted(_domain_ips(ctx) - exits):
        cidr = neighbour_cidr(ip)
        row = ctx.neighbours.get(cidr) if cidr else None
        if row and row["Known Exits"]:
            share = row["Coverage"] or "?"
            lines.append(f"{ip} in {cidr}: {row['Known Exits']} known exit(s) ({share}) of {row['Providers'] or 'VPNDB'}")
            evidence.append(evidence_record(None, "Exit range", f"{cidr}: {row['Providers']}", artifact=ip))
            strong |= bool(row["Single Tenant"])
    for entry in ctx.profile.get("ips", []):
        verdict = ctx.asn_verdicts.get(entry["asn"])
        if entry["ip"] not in exits and verdict and verdict["Single Tenant"] \
                and verdict["Known Exits"] >= MIN_NETWORK_EXITS:   # one exit on a hoster is not a VPN's network
            lines.append(f"{entry['ip']} on AS{entry['asn']} {verdict['AS Organization']}: a network of "
                         f"{verdict['Top Provider'] or 'one VPN provider'} ({verdict['Known Exits']} known exits)")
            evidence.append(evidence_record(None, "Exit network", f"AS{entry['asn']} {verdict['Top Provider']}",
                                            artifact=entry["ip"]))
            strong = True
    if lines:
        ctx.add(
            "Hosted Among Anonymizer Exits", "Medium", "T1090.002 (Proxy: External Proxy)",
            "The domain's own IPs are not known exits, but they sit in /24 ranges where VPNDB knows VPN or proxy exits, "
            "or on a network one VPN provider runs: the domain is probably hosted on an anonymizer operator's "
            "servers, or next to them on bulletproof-style hosting.",
            "\n".join(lines[:MAX_IOC_LINES]), flag="anonymizer_range", confidence="Medium" if strong else "Low",
            evidence=evidence,
        )


THREAT_TYPES = ("Domain on Tor Relay / Exit Node", "Domain on Residential Proxy Exit", "Domain on VPN / Proxy Exit",
                "Domain on Dedicated Anonymizer Exit", "Hosting Moved onto Anonymizer Exit",
                "Domain Rotates Across Anonymizer Exits", "Newly Registered Domain on Anonymizer Exit",
                "Anonymizer Exit Shared by Analyzed Domains", "Hosted Among Anonymizer Exits",
                "Hosted Among Tor Exits")

ANONYMIZER_RULES = (rule_tor_node, rule_residential_proxy, rule_vpn_exit, rule_dedicated_exit, rule_moved_onto_exit,
                    rule_exit_rotation, rule_new_domain_on_exit, rule_hosted_among_exits,
                    rule_hosted_among_tor_exits)
