"""
IP and CIDR targets at a glance: what each source returned for an address or a range entered as a target (names in
passive DNS, domains in Iris, certificates naming it, its BGP routing, its VPNDB verdict). Built from the loaded data,
no request.
"""
import ipaddress

import pandas as pd

from core.helpers import is_cidr, is_ip_address, normalize_cidr, registrable_domain

TABLE_COLUMNS = ["Target", "Kind", "Names in passive DNS", "Last Seen", "Domains in Iris", "High-risk in Iris",
                 "Certificates", "Prefix", "Origin", "Routing", "Prefixes inside", "VPNDB"]
NAME_COLUMNS = ["Name", "Domain", "Type", "Value", "First Seen", "Last Seen", "Count"]


def address_targets(targets):
    """The IP and CIDR targets among `targets`, in order (a range as looked up: `104.21.59.7/24` is `104.21.59.0/24`)."""
    return list(dict.fromkeys(normalize_cidr(t) or t for t in (str(t).strip() for t in targets or [])
                              if is_ip_address(t) or is_cidr(t)))


def kind(target):
    if is_cidr(target):
        return f"IPv{ipaddress.ip_network(target, strict=False).version} range"
    return f"IPv{ipaddress.ip_address(target).version}"


def _rows(frame, column, target):
    if frame is None or frame.empty or column not in frame.columns:
        return pd.DataFrame()
    return frame[frame[column].astype(str) == target]


def names_on(pdns, target):
    """NAME_COLUMNS: the names passive DNS saw resolving to the address or into the range, latest first."""
    rows = _rows(pdns, "Domain", target)
    if rows.empty:
        return pd.DataFrame(columns=NAME_COLUMNS)
    names = rows["RRName"].astype(str).str.rstrip(".")
    table = pd.DataFrame({"Name": names, "Domain": names.map(lambda n: registrable_domain(n) or n),
                          "Type": rows["Field"], "Value": rows["Value"], "First Seen": rows["First Seen"],
                          "Last Seen": rows["Last Seen"], "Count": rows["Count"]})
    return table.sort_values("Last Seen", ascending=False, na_position="last").reset_index(drop=True)


def _routing(origins, neighbours, target):
    """(prefix, origin, status, prefixes announced inside) of a target from the BGPDB frames."""
    found = pd.DataFrame()
    if origins is not None and not origins.empty:
        mine = origins["Domains"].astype(str).map(lambda v: target in {d.strip() for d in v.split(",")})
        found = origins[mine].sort_values("Updates", ascending=False)
    inside = 0
    if is_cidr(target) and neighbours is not None and not neighbours.empty:
        inside = int((neighbours["Covering Range"] == target).sum())
    if found.empty:
        return "", "", "", inside
    top = found.iloc[0]
    origin = f"{top['Origin']} {top.get('AS Name', '') or ''}".strip()
    return top["Prefix"], origin, top["Status"], inside


def _vpndb(anonymizers, prefixes, target):
    if is_cidr(target):
        row = _rows(prefixes, "CIDR", target)
        if row.empty:
            return ""
        row = row.iloc[0]
        return (f"{row['Top Provider']} ({row['Known Exits']} known exits)" if row.get("Top Provider")
                else str(row.get("Category") or ""))
    row = _rows(anonymizers, "IP", target)
    if row.empty:
        return ""
    row = row.iloc[0]
    return " · ".join(str(v) for v in (row.get("Category"), row.get("Provider")) if v)


def target_table(ds, targets, high_risk=70):
    """TABLE_COLUMNS: one row per IP or CIDR target with what each source returned for it."""
    rows = []
    for target in address_targets(targets):
        names = names_on(ds.pdns, target)
        on = _rows(ds.target_domains, "Target", target)
        risk = pd.to_numeric(on["Risk Score"], errors="coerce") if not on.empty else pd.Series(dtype=float)
        certs = _rows(ds.ssl, "Domain", target)
        prefix, origin, status, inside = _routing(ds.bgp_origins, ds.bgp_neighbours, target)
        rows.append({
            "Target": target, "Kind": kind(target), "Names in passive DNS": names["Name"].nunique(),
            "Last Seen": names["Last Seen"].max() if not names.empty else pd.NaT,
            "Domains in Iris": len(on), "High-risk in Iris": int((risk >= high_risk).sum()),
            "Certificates": certs["Hash"].nunique() if "Hash" in certs else len(certs),
            "Prefix": prefix, "Origin": origin, "Routing": status, "Prefixes inside": inside or None,
            "VPNDB": _vpndb(ds.anonymizers, ds.prefixes, target)})
    table = pd.DataFrame(rows, columns=TABLE_COLUMNS)
    table["Prefixes inside"] = pd.to_numeric(table["Prefixes inside"], errors="coerce").astype("Int64")
    return table


def related_domains(ds, target, high_risk=70, limit=25):
    """The registrable domains seen on a target, riskiest Iris domains first, then passive DNS names: to analyze."""
    on = _rows(ds.target_domains, "Target", target)
    picked = []
    if not on.empty:
        picked += list(on.sort_values("Risk Score", ascending=False, na_position="last")["Domain"])
    names = names_on(ds.pdns, target)
    picked += [d for d in names["Domain"] if d and not is_ip_address(d)]
    return list(dict.fromkeys(picked))[:limit]
