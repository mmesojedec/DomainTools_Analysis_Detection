"""DNS resolution rules: dangling NS, MX and SPF records, CNAMEs to lapsed domains and internal IPs in public DNS.
Rules read the domain's rows of the resolution tree (core.resolver.build_tree)."""
from core.resolver import DANGLING
from core.threat_detection.context import MAX_IOC_LINES, evidence_record


def _rows(ctx, kind):
    tree = ctx.resolution
    if tree is None or tree.empty:
        return tree
    return tree[(tree["Status"] == DANGLING) & (tree["Type"] == kind)]   # claimable only (stale records are not)


def _lines(rows):
    lines = [f"{r['Name']} {r['Type']} → {', '.join(r['Dangling'])} ✕ ({r['Reason'][0]})"
             for r in rows.head(MAX_IOC_LINES).to_dict("records")]
    if len(rows) > MAX_IOC_LINES:
        lines.append(f"... {len(rows) - MAX_IOC_LINES} more")
    return "\n".join(lines)


def _evidence(rows):
    return [evidence_record(r["Last Seen"], f"{r['Type']} (dangling)", f"{r['Name']} → {target}", artifact=target)
            for r in rows.to_dict("records") for target in r["Dangling"]]


def _lapsed(rows):
    return rows["Reason"].map(lambda reasons: any("no current DNS record" in r for r in reasons))


def rule_dangling_ns(ctx):
    rows = _rows(ctx, "NS")
    if rows is None or rows.empty:
        return
    lapsed = bool(_lapsed(rows).any())
    ctx.add(
        "Dangling NS Record (Zone Takeover Risk)", "Critical" if lapsed else "High",
        "T1584.002 (Compromise Infrastructure: DNS Server)",
        f"{len(rows)} NS record(s) delegate to name servers that resolve nowhere in DNSDB"
        + ("; the name server's own domain has no current DNS record, so anyone may register it and answer for the "
           "whole zone" if lapsed else "") + ".",
        _lines(rows), flag="dangling_dns", confidence="High" if lapsed else "Medium", evidence=_evidence(rows),
    )


def rule_dangling_mx(ctx):
    rows = _rows(ctx, "MX")
    if rows is None or rows.empty:
        return
    lapsed = bool(_lapsed(rows).any())
    ctx.add(
        "Dangling MX Record (Mail Interception Risk)", "Critical" if lapsed else "High",
        "T1584.001 (Compromise Infrastructure: Domains)",
        f"{len(rows)} MX record(s) name mail servers that resolve nowhere in DNSDB"
        + ("; the mail server's domain has no current DNS record, so whoever registers it receives the domain's mail"
           if lapsed else "") + ".",
        _lines(rows), flag="dangling_dns", confidence="High" if lapsed else "Medium", evidence=_evidence(rows),
    )


def rule_dangling_spf(ctx):
    rows = _rows(ctx, "TXT")
    if rows is None or rows.empty:
        return
    lapsed = bool(_lapsed(rows).any())
    ctx.add(
        "Dangling SPF Include (Mail Spoofing Risk)", "High" if lapsed else "Medium",
        "T1584.001 (Compromise Infrastructure: Domains)",
        f"{len(rows)} SPF record(s) include a domain that has no SPF record in DNSDB"
        + ("; the included domain has no current DNS record, so whoever registers it may send mail as this domain"
           if lapsed else "") + ".",
        _lines(rows), flag="dangling_dns", evidence=_evidence(rows),
    )


def rule_cname_lapsed_domain(ctx):
    rows = _rows(ctx, "CNAME")
    rows = rows[_lapsed(rows)] if rows is not None and not rows.empty else rows
    if rows is None or rows.empty:
        return
    ctx.add(
        "CNAME to Lapsed Domain (Takeover Risk)", "Critical", "T1584.001 (Compromise Infrastructure: Domains)",
        f"{len(rows)} hostname(s) point by CNAME to a name whose domain has no current DNS record in DNSDB: it may be "
        "unregistered or lapsed, and whoever registers it serves the hostname.",
        _lines(rows), flag="dangling_dns", confidence="High", evidence=_evidence(rows),
    )


def rule_internal_ip(ctx):
    tree = ctx.resolution
    if tree is None or tree.empty:
        return
    rows = tree[tree["Type"].isin(["A", "AAAA"]) & tree["Warnings"].map(
        lambda warnings: any(w.startswith(("Internal IP", "Bogon address")) for w in warnings))]
    if rows.empty:
        return
    lines = [f"{r['Name']} {r['Type']} {', '.join(r['IPv4'] + r['IPv6'])}" for r in rows.head(MAX_IOC_LINES).to_dict("records")]
    ctx.add(
        "Internal IP Address in Public DNS", "Low", "T1590.002 (Gather Victim Network Information: DNS)",
        f"{len(rows)} public name(s) resolve to internal addresses (RFC 1918, loopback, link-local, ...) or bogons "
        "(reserved space not routable on the internet): they map the internal network for anyone who looks, and can "
        "be used in DNS rebinding.",
        "\n".join(lines),
        evidence=[evidence_record(r["Last Seen"], f"{r['Type']} (internal)", ", ".join(r["IPv4"] + r["IPv6"]),
                                  artifact=r["Name"]) for r in rows.to_dict("records")],
    )


RESOLVER_RULES = (rule_dangling_ns, rule_dangling_mx, rule_dangling_spf, rule_cname_lapsed_domain, rule_internal_ip)
