"""
Hostname focus and inventory. Domains are always collected in full (every subdomain); the focus narrows the views to
chosen hostnames afterwards, and the inventory lists every hostname a run's certificates and passive DNS mention.
"""
import pandas as pd

from core.helpers import is_ip_address, registrable_domain

INVENTORY_COLUMNS = [
    "Hostname", "Apex", "Focus", "Flags", "Certificates", "First Certificate", "Latest Certificate", "Latest Certificate Hash",
    "Certificate Expires",
    "pDNS First Seen", "pDNS Last Seen", "pDNS Records", "Record Types", "Current Values", "Cert Events",
]
# Name labels attackers like for credential phishing and remote access; matched against whole labels or label parts
SENSITIVE_WORDS = ("login", "signin", "logon", "secure", "account", "auth", "sso", "vpn", "webmail", "mail", "admin",
                   "portal", "pay", "billing", "verify", "update", "wallet", "support", "remote", "citrix", "owa", "okta",
                   "password", "reset", "invoice", "bank")
FLAG_HELP = {
    "Certificate, never resolved": "Named in a certificate but never seen in passive DNS: possibly prepared for later use",
    "Resolves, no certificate": "Seen resolving (A / AAAA / CNAME) but no certificate collected names or covers it",
    "New": "First seen (certificate or passive DNS) within the last N days",
    "Sensitive name": "Contains a word often used for phishing or remote access (login, vpn, secure, ...)",
    "Wildcard": "A wildcard certificate name: covers any one-label subdomain",
}
RESOLVING_TYPES = ("A", "AAAA", "CNAME")
CERTIFICATE_LINK_COLUMNS = ["Hostname", "Apex", "Match", "Certificate Hash", "Hash Type", "Common Name", "Issuer",
                            "Not Before", "Not After", "Source"]


def clean_hostname(name):
    return str(name or "").strip().lower().rstrip(".")


def apex_of(name):
    return registrable_domain(clean_hostname(name).removeprefix("*.")) or ""


def focus_from_hostnames(hostnames):
    """{apex: [hostnames]} from a flat list of hostnames."""
    focus = {}
    for name in sorted({clean_hostname(h) for h in hostnames or [] if clean_hostname(h)}):
        apex = apex_of(name)
        if apex:
            focus.setdefault(apex, []).append(name)
    return focus


def name_in_focus(name, hosts):
    """
    True when a DNS name belongs to one of the focus hostnames: the hostname itself or a name under it
    (`_acme-challenge.api.example.com` for `api.example.com`); a wildcard `*.example.com` covers every name under
    example.com except the apex itself.
    """
    name = clean_hostname(name)
    for host in hosts:
        base = host[2:] if host.startswith("*.") else host
        if (name == host or name.endswith("." + base)) or (not host.startswith("*.") and name == base):
            return True
    return False


def certificate_in_focus(names, hosts):
    """
    True when a certificate naming `names` (SANs and CN) covers a focus hostname: names it, names something under it,
    or carries the wildcard covering it (`*.example.com` covers `api.example.com`). A certificate for the apex alone
    does not cover `api.example.com`.
    """
    for raw in names:
        name = clean_hostname(raw)
        if not name:
            continue
        for host in hosts:
            if name == host or name_in_focus(name, [host]):
                return True
            if name.startswith("*.") and not host.startswith("*.") and "." in host and host.split(".", 1)[1] == name[2:]:
                return True
    return False


def certificate_names(row):
    """SAN DNS names plus the common name of a certificate row (SAN DNS may be a list or a comma-separated string)."""
    sans = row.get("SAN DNS") if hasattr(row, "get") else None
    if isinstance(sans, str):
        sans = [s.strip() for s in sans.split(",")]
    elif sans is None or (not isinstance(sans, (list, tuple)) and pd.isna(sans)):
        sans = []
    names = [s for s in sans if s]
    common = row.get("Common Name") if hasattr(row, "get") else None
    if isinstance(common, str) and common.strip():
        names.append(common)
    return names


def apply_focus(frame, focus, name_column):
    """Rows of focused domains whose `name_column` belongs to a focus hostname; other domains' rows are kept."""
    if not focus or frame is None or frame.empty or name_column not in frame.columns:
        return frame
    keep = [dom not in focus or name_in_focus(name, focus[dom]) for dom, name in zip(frame["Domain"], frame[name_column])]
    return frame[keep].copy()


def apply_certificate_focus(frame, focus):
    """Certificate rows of focused domains that cover a focus hostname; rows without any name are kept."""
    if not focus or frame is None or frame.empty:
        return frame
    keep = []
    for _, row in frame.iterrows():
        hosts = focus.get(row.get("Domain"))
        names = certificate_names(row)
        keep.append(not hosts or not names or certificate_in_focus(names, hosts))
    return frame[keep].copy()


def _valid_name(name, domains):
    name = clean_hostname(name)
    if not name or " " in name or is_ip_address(name) or "." not in name:
        return ""
    if any(label.startswith("_") for label in name.split(".")):   # service labels (_dmarc, _acme-challenge)
        return ""
    return name if apex_of(name) in domains else ""


def candidate_hostnames(pdns, ssl, cert_events, domains, extra=()):
    """Every hostname under `domains` that passive DNS, certificates or certificate events mention, sorted."""
    domains = set(domains)
    names = set()
    if pdns is not None and not pdns.empty and "RRName" in pdns.columns:
        names.update(pdns["RRName"].dropna().astype(str).unique())
    if ssl is not None and not ssl.empty:
        for _, row in ssl.iterrows():
            names.update(certificate_names(row))
    if cert_events is not None and not cert_events.empty and "Hostname" in cert_events.columns:
        names.update(cert_events["Hostname"].dropna().astype(str).unique())
    names.update(extra)
    return sorted({n for n in (_valid_name(name, domains) for name in names) if n})


def sensitive_words(name):
    """SENSITIVE_WORDS found in the labels below the registered domain (`secure-login.example.com` -> secure, login)."""
    name = clean_hostname(name).removeprefix("*.")
    apex = apex_of(name)
    labels = name[:-len(apex) - 1].split(".") if apex and name.endswith("." + apex) else []
    parts = {p for label in labels for p in label.replace("_", "-").split("-")}
    return [word for word in SENSITIVE_WORDS if word in parts or any(label.startswith(word) for label in labels)]


def is_sensitive(name):
    """True when a label below the registered domain contains a SENSITIVE_WORDS word."""
    return bool(sensitive_words(name))


def _certificates(ssl):
    """One entry per certificate (by hash) with the names it covers, its validity and its identifiers."""
    certs, seen = [], set()
    if ssl is None or ssl.empty:
        return certs
    for _, row in ssl.iterrows():
        cert_hash = str(row.get("Hash") or "").strip().lower()
        key = cert_hash or id(row)
        if key in seen:
            continue
        seen.add(key)
        certs.append({"names": [clean_hostname(n) for n in certificate_names(row)], "hash": cert_hash,
                      "not_before": pd.to_datetime(row.get("Not Before Date"), errors="coerce"),
                      "not_after": pd.to_datetime(row.get("Not After Date"), errors="coerce"),
                      "common_name": row.get("Common Name") or "", "issuer": row.get("Issuer") or "",
                      "source": row.get("Source") or ""})
    return certs


def _covered_names(certs):
    """
    Lookup sets for certificate coverage, the same rule as certificate_in_focus() but without a pass over every
    certificate per hostname: (every certificate name, every parent of a certificate name).
    """
    names = {n for c in certs for n in c["names"] if n}
    parents = {n.split(".", i)[i] for n in names for i in range(1, n.count(".") + 1)}
    return names, parents


def _is_covered(host, names, parents):
    """True when a certificate names `host`, names something under it, or carries the wildcard covering it."""
    if host.startswith("*."):
        return host in names or host[2:] in parents
    parent = host.split(".", 1)[1] if "." in host else ""
    return host in names or host in parents or bool(parent and f"*.{parent}" in names)


def hash_type(value):
    return {64: "SHA-256", 40: "SHA-1", 32: "MD5"}.get(len(value or ""), "")


def build_hostname_certificates(ssl, hostnames):
    """
    Hostname -> certificate links (CERTIFICATE_LINK_COLUMNS): every certificate with a hash that names a hostname
    ("Named") or carries the wildcard one level above it ("Wildcard"), newest first per hostname.
    """
    certs = [c for c in _certificates(ssl) if c["hash"]]
    rows = []
    for name in hostnames:
        parent = name.split(".", 1)[1] if "." in name and not name.startswith("*.") else ""
        for cert in certs:
            match = "Named" if name in cert["names"] else "Wildcard" if parent and f"*.{parent}" in cert["names"] else ""
            if match:
                rows.append({"Hostname": name, "Apex": apex_of(name), "Match": match, "Certificate Hash": cert["hash"],
                             "Hash Type": hash_type(cert["hash"]), "Common Name": cert["common_name"],
                             "Issuer": cert["issuer"], "Not Before": cert["not_before"], "Not After": cert["not_after"],
                             "Source": cert["source"]})
    if not rows:
        return pd.DataFrame(columns=CERTIFICATE_LINK_COLUMNS)
    frame = pd.DataFrame(rows, columns=CERTIFICATE_LINK_COLUMNS)
    return frame.sort_values(["Apex", "Hostname", "Not Before"], ascending=[True, True, False], kind="stable") \
        .reset_index(drop=True)


def build_hostname_inventory(pdns, ssl, cert_events, domains, focus=None, coverage=None, now=None, new_days=30):
    """
    One row per hostname (INVENTORY_COLUMNS) from full-history passive DNS, certificates and certificate events.
    `coverage` (domain -> {"truncated"}) suppresses the "never resolved" flag where passive DNS was capped.
    """
    focus, coverage = focus or {}, coverage or {}
    now = pd.Timestamp(now) if now is not None else pd.Timestamp.now(tz="UTC").tz_localize(None)
    names = candidate_hostnames(pdns, ssl, cert_events, domains, [h for hosts in focus.values() for h in hosts])
    if not names:
        return pd.DataFrame(columns=INVENTORY_COLUMNS)

    certs = _certificates(ssl)
    by_cert_name = {}
    for cert in certs:
        for cert_name in dict.fromkeys(cert["names"]):
            by_cert_name.setdefault(cert_name, []).append(cert)
    cert_names, cert_parents = _covered_names(certs)
    dns = pd.DataFrame()
    if pdns is not None and not pdns.empty and "RRName" in pdns.columns:
        dns = pdns.assign(_name=pdns["RRName"].astype(str).str.lower().str.rstrip("."),
                          _first=pd.to_datetime(pdns["First Seen"], errors="coerce"),
                          _last=pd.to_datetime(pdns["Last Seen"], errors="coerce"))
    by_name = dict(tuple(dns.groupby("_name"))) if not dns.empty else {}
    events = {}
    if cert_events is not None and not cert_events.empty and "Hostname" in cert_events.columns:
        events = cert_events["Hostname"].astype(str).str.lower().str.rstrip(".").value_counts().to_dict()

    rows = []
    for name in names:
        apex = apex_of(name)
        exact = by_cert_name.get(name, [])
        covering = bool(exact) or _is_covered(name, cert_names, cert_parents)
        records = by_name.get(name, pd.DataFrame())
        resolving = records[records["Field"].astype(str).str.upper().isin(RESOLVING_TYPES)] if not records.empty else records
        current = ""
        if not resolving.empty:
            latest = resolving["_last"].max()
            recent = resolving[resolving["_last"] >= latest - pd.Timedelta(days=1)] if pd.notna(latest) else resolving
            current = ", ".join(dict.fromkeys(v for value in recent["Value"].astype(str) for v in value.split("\n") if v))
        first_cert = min((c["not_before"] for c in exact if pd.notna(c["not_before"])), default=pd.NaT)
        newest_cert = max((c for c in exact if pd.notna(c["not_before"])), key=lambda c: c["not_before"], default=None)
        first_dns = records["_first"].min() if not records.empty else pd.NaT
        first_seen = min((t for t in (first_cert, first_dns) if pd.notna(t)), default=pd.NaT)
        flags = []
        if exact and records.empty and not coverage.get(apex, {}).get("truncated"):
            flags.append("Certificate, never resolved")
        if not resolving.empty and not covering:
            flags.append("Resolves, no certificate")
        if pd.notna(first_seen) and first_seen >= now - pd.Timedelta(days=new_days):
            flags.append("New")
        if is_sensitive(name):
            flags.append("Sensitive name")
        if name.startswith("*."):
            flags.append("Wildcard")
        rows.append({
            "Hostname": name, "Apex": apex, "Focus": name in focus.get(apex, []), "Flags": ", ".join(flags),
            "Certificates": len(exact), "First Certificate": first_cert,
            "Latest Certificate": newest_cert["not_before"] if newest_cert else pd.NaT,
            "Latest Certificate Hash": newest_cert["hash"] if newest_cert else "",
            "Certificate Expires": max((c["not_after"] for c in exact if pd.notna(c["not_after"])), default=pd.NaT),
            "pDNS First Seen": first_dns, "pDNS Last Seen": records["_last"].max() if not records.empty else pd.NaT,
            "pDNS Records": len(records),
            "Record Types": ", ".join(sorted(records["Field"].astype(str).str.upper().unique())) if not records.empty else "",
            "Current Values": current, "Cert Events": int(events.get(name, 0)),
        })
    frame = pd.DataFrame(rows, columns=INVENTORY_COLUMNS)
    return frame.sort_values(["Apex", "Hostname"], kind="stable").reset_index(drop=True)
