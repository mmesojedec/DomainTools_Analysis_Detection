"""CNAME detection rules: dangling and takeover-prone CNAMEs, dynamic DNS / tunnel and free hosting targets, retargeted
CNAMEs, and long chains. Rules read the domain's slice of the CNAME map (core.cname.build_cname_map)."""
from core.cname import NOT_CHASED, SHARED_SERVICE_TYPES, cname_links
from core.subdomain_triage import STRONG_SIGNALS, name_signals
from core.threat_detection.context import MAX_IOC_LINES, evidence_record, fmt_ts


def _lines(rows, text):
    lines = [text(r) for r in rows.head(MAX_IOC_LINES).to_dict("records")]
    if len(rows) > MAX_IOC_LINES:
        lines.append(f"... {len(rows) - MAX_IOC_LINES} more")
    return "\n".join(lines)


def _evidence(rows, value=lambda r: r["Chain"]):
    return [evidence_record(r["Last Seen"], f"CNAME ({r['Outcome']})", value(r), artifact=r["Hostname"])
            for r in rows.to_dict("records")]


def _current(ctx):
    cmap = ctx.cname_map
    return cmap[cmap["Current"]] if not cmap.empty else cmap


def rule_dangling_cname(ctx):
    rows = _current(ctx)
    rows = rows[rows["Outcome"] == "Dead end"] if not rows.empty else rows
    if rows.empty:
        return
    takeover = rows[rows["Service Type"] == "Takeover-prone"]
    services = ", ".join(sorted(set(takeover["Service"])))
    ctx.add(
        "Dangling CNAME (Subdomain Takeover Risk)", "Critical" if not takeover.empty else "High",
        "T1584.001 (Compromise Infrastructure: Domains)",
        f"{len(rows)} hostname(s) still point by CNAME to a chain that ends without any A, AAAA or CNAME record in "
        "DNSDB" + (f"; {len(takeover)} on takeover-prone services ({services}), where anyone can claim the name"
                   if not takeover.empty else "") + ".",
        _lines(rows, lambda r: f"{r['Chain']} ✕ ({r['Service'] or 'no known service'}; {r['Note']})"),
        flag="dangling_cname", confidence="High" if not takeover.empty else "Medium", evidence=_evidence(rows),
    )


def rule_unverified_takeover_prone(ctx):
    rows = _current(ctx)
    if rows.empty:
        return
    rows = rows[(rows["Service Type"] == "Takeover-prone") & rows["Outcome"].isin([NOT_CHASED, "Lookup failed"])]
    if rows.empty:
        return
    ctx.add(
        "Unverified CNAME to Takeover-Prone Service", "Medium", "T1584.001 (Compromise Infrastructure: Domains)",
        f"{len(rows)} hostname(s) point to services where a deleted resource can be claimed by anyone "
        f"({', '.join(sorted(set(rows['Service'])))}); the chain was not chased, so it is unknown whether it still "
        "resolves. Chase it in the CNAME Chains lens.",
        _lines(rows, lambda r: f"{r['Hostname']} ➔ {r['Target']} ({r['Service']})"),
        evidence=_evidence(rows, lambda r: f"{r['Hostname']} ➔ {r['Target']}"),
    )


def rule_dynamic_dns_cname(ctx):
    cmap = ctx.cname_map
    rows = cmap[cmap["Service Type"] == "Dynamic DNS / tunnel"] if not cmap.empty else cmap
    if rows.empty:
        return
    ctx.add(
        "CNAME to Dynamic DNS / Tunnel Service", "High", "T1568 (Dynamic Resolution)",
        f"{rows['Hostname'].nunique()} hostname(s) point by CNAME to dynamic DNS or tunnel services "
        f"({', '.join(sorted(set(rows['Service'])))}): the name follows a home or attacker machine, or exposes a "
        "local service, a common setup for C2 and short-lived phishing.",
        _lines(rows, lambda r: f"[{fmt_ts(r['Last Seen'])}] {r['Hostname']} ➔ {r['Target']} ({r['Service']}"
                               f"{', current' if r['Current'] else ''})"),
        flag="dynamic_dns_cname", evidence=_evidence(rows, lambda r: f"{r['Hostname']} ➔ {r['Target']}"),
    )


def rule_free_hosting_cname(ctx):
    rows = _current(ctx)
    if rows.empty:
        return
    rows = rows[(rows["Service Type"] == "Free hosting") & rows["External"]]
    if rows.empty:
        return
    lures = rows[[any(s in STRONG_SIGNALS for s in name_signals(h, d)[0])
                  for h, d in zip(rows["Hostname"], rows["Domain"])]]
    ctx.add(
        "CNAME to Free Hosting Platform", "High" if not lures.empty else "Medium",
        "T1583.006 (Acquire Infrastructure: Web Services)",
        f"{len(rows)} hostname(s) of this domain are served from free hosting platforms anyone can publish on "
        f"({', '.join(sorted(set(rows['Service'])))})" + (f"; {len(lures)} carry phishing words, brands or embedded "
                                                           "domains in the name" if not lures.empty else "") + ".",
        _lines(lures if not lures.empty else rows, lambda r: f"{r['Hostname']} ➔ {r['Target']}"),
        confidence="Medium" if not lures.empty else None,
        evidence=_evidence(rows, lambda r: f"{r['Hostname']} ➔ {r['Target']}"),
    )


def rule_cname_retarget(ctx):
    cmap = ctx.cname_map
    if cmap.empty:
        return
    hits = []
    for hostname, group in cmap.groupby("Hostname"):
        if group["Target Domain"].nunique() < 2:
            continue
        ordered = group.sort_values("First Seen", kind="stable")
        new = ordered.iloc[-1]
        previous = ordered[ordered["Target Domain"] != new["Target Domain"]]
        if previous.empty or not new["Current"] or not new["External"] or new["Service Type"] in SHARED_SERVICE_TYPES:
            continue
        old = previous.iloc[-1]
        hits.append((hostname, old, new))
    if not hits:
        return
    ctx.add(
        "CNAME Retargeted to Another Provider", "Medium", "T1584.001 (Compromise Infrastructure: Domains)",
        f"{len(hits)} hostname(s) moved their CNAME to a different provider; a takeover or a compromised DNS account "
        "often shows as a subdomain repointed to new, attacker-controlled hosting.",
        "\n".join(f"{h}: {o['Target']} (last {fmt_ts(o['Last Seen'], '%Y-%m-%d')}) ➔ {n['Target']} "
                  f"(first {fmt_ts(n['First Seen'], '%Y-%m-%d')}{', ' + n['Service'] if n['Service'] else ''})"
                  for h, o, n in hits[:MAX_IOC_LINES]),
        evidence=[evidence_record(n["First Seen"], "CNAME Retarget", f"{o['Target']} ➔ {n['Target']}", artifact=h)
                  for h, o, n in hits],
    )


def rule_long_cname_chain(ctx):
    rows = _current(ctx)
    if rows.empty:
        return
    rows = rows[(rows["Hops"] >= ctx.thresholds["cname_hops"]) | rows["Outcome"].isin(["Loop", "Step limit"])]
    if rows.empty:
        return
    loops = rows[rows["Outcome"] == "Loop"]
    ctx.add(
        "Long CNAME Chain / Loop", "Medium-High" if not loops.empty else "Medium", "T1090 (Proxy)",
        f"{len(rows)} hostname(s) pass through {int(rows['Hops'].max())} or more CNAMEs"
        + (f", {len(loops)} in a loop" if not loops.empty else "") + ": layered redirects hide the final hosting "
        "and let operators swap it without touching the visible name.",
        _lines(rows, lambda r: f"{r['Chain']} ({r['Hops']} hops, {r['Outcome']})"),
        evidence=_evidence(rows),
    )


def shared_cname_alerts(contexts, cname_map, rdata=None):
    """One alert per analyzed domain linked to other analyzed domains through its CNAME chains (core.cname.cname_links):
    a CNAME into another analyzed domain, or a name outside them all that several reach. CDNs, parking and shared final
    addresses are left out (unrelated customers share those)."""
    links = cname_links(cname_map, contexts, rdata)
    if links.empty:
        return
    links = links[(links["Kind"] != "Shared final address") & ~links["Service Type"].isin(SHARED_SERVICE_TYPES)]
    for domain, ctx in contexts.items():
        mine = links[[domain in d.split(", ") for d in links["Domains"]]]
        if mine.empty:
            continue
        others = sorted({d for doms in mine["Domains"] for d in doms.split(", ") if d != domain})
        direct = mine[mine["Kind"] == "CNAME into analyzed domain"]
        known = mine["Service Type"].ne("").all()
        names = set(mine["Link"])
        rows = ctx.cname_map[[any(n in names for n in str(chain).split(" → ")[1:]) for chain in ctx.cname_map["Chain"]]]
        ctx.add(
            "CNAME Link Between Analyzed Domains", "Medium-High", "T1583.001 (Acquire Infrastructure: Domains)",
            f"CNAME chains connect this domain to {len(others)} other analyzed domain(s) ({', '.join(others[:10])}"
            f"{' ...' if len(others) > 10 else ''})"
            + (f"; {len(direct)} name(s) of one analyzed domain alias into another" if not direct.empty else "")
            + ": one operator fronting several domains with the same proxy or host.",
            "\n".join(f"{r['Link']} ({r['Kind']}) ⇐ {r['Domains']}" for r in mine.head(MAX_IOC_LINES).to_dict("records")),
            flag="shared_cname", confidence="High" if not direct.empty else ("Low" if known else "Medium"),
            evidence=[evidence_record(r["Last Seen"], "CNAME Link", r["Chain"], artifact=r["Hostname"])
                      for r in rows.to_dict("records")],
        )


CNAME_RULES = (
    rule_dangling_cname,
    rule_unverified_takeover_prone,
    rule_dynamic_dns_cname,
    rule_free_hosting_cname,
    rule_cname_retarget,
    rule_long_cname_chain,
)
