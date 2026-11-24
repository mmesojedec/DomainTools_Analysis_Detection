"""
Certificate anomalies across the run: what a certificate does differently from its issuer's other certificates, from
how Certificate Transparency logging normally goes, and a few patterns of tool-made or bulk certificates.

- Issuer baseline: the run's own certificates of an issuer set what is normal for it (each trait counted once per
  issuance, a precertificate and its final certificate together). The signing key and the validity are compared
  across the issuer; the other traits within its validity profile (the issuer's certificates of the same validity
  band), since a CA's 6-day and 90-day profiles differ in their extensions by design. A value is anomalous when at most 10% of the
  issuer's issuances (and at least one) have it, against a dominant value on 70% or more, with BASELINE_MIN issuances
  knowing the trait. A different Authority Key ID under one issuer name is the strongest: a CA impersonated by name or
  made by hand. A few built-in norms of large CAs fill in where the run is too small (KNOWN_ISSUERS).
- Certificate Transparency: precertificates are paired with their final certificate (issuer and serial); the first
  log time (embedded SCTs of either, or the run's CT log entries) more than LATE_LOG_HOURS after Not Before; fewer
  SCTs than Chrome's CT policy asks for; a publicly trusted certificate with no trace of logging; a precertificate
  whose final certificate is not in the run.
- Other: issuance bursts across analyzed domains; a Not Before at a round time from an issuer that normally uses real
  seconds; tool-style validity (365, 730 ... days) on a self-signed or unknown issuer; names that follow one template
  (the analyzed domains' own names left out: the DGA rules judge those).

anomalies() returns ANOMALY_COLUMNS rows; against_issuer() the comparison of one certificate with its issuer's norm.
Pure: no API call, no Streamlit.
"""
import re
from collections import Counter, OrderedDict, defaultdict

import pandas as pd

from core.cert_profile import _bool, _empty, _values, frame_key, text, when
from core.cert_shape import distinct, policies, precise, scts, trait_text, traits
from core.cert_utils import publicly_trusted
from core.helpers import calculate_shannon_entropy, registrable_domain

ANOMALY_COLUMNS = ["Hash", "Check", "Code", "Severity", "Field", "Finding"]
CHECKS = ("Issuer baseline", "Certificate Transparency", "Other")
BASELINE_MIN = 5            # issuances of an issuer that know a trait before the run sets its norm
RARE_SHARE = 0.10           # at most this share of the issuer's issuances (and at least one) ...
DOMINANT_SHARE = 0.70       # ... against a value on at least this share
LATE_LOG_HOURS = 48         # CAs backdate Not Before by an hour or so; logging this much later is backdating
SCT_POLICY = ((180, 2),)    # Chrome / Apple CT policy: up to 180 days 2 SCTs, longer 3
SCT_POLICY_LONG = 3
BURST_MINUTES = 10
BURST_MIN = 5               # issuances of one issuer within BURST_MINUTES ...
BURST_DOMAINS = 2           # ... for at least this many analyzed domains
TOOL_DAYS = {365, 730, 1095, 1825, 3650, 7300}
TEMPLATE_MIN = 3            # distinct names following one template
TEMPLATE_LENGTH = 6
RANDOM_LENGTH = 12
RANDOM_ENTROPY = 3.5
DV_POLICY = "2.23.140.1.2.1"
OV_EV_POLICIES = {"2.23.140.1.2.2": "OV", "2.23.140.1.2.3": "IV", "2.23.140.1.1": "EV"}
# Norms of large CAs, from their published practice: used where the run has too few of their certificates
KNOWN_ISSUERS = {
    "let's encrypt": {"name": "Let's Encrypt", "max_days": 100, "dv_only": True,      # 90-day and 6-day profiles
                      "validity": {"≤7 d", "48–100 d"}},
    "zerossl": {"name": "ZeroSSL", "dv_only": True},
    "google trust services": {"name": "Google Trust Services", "dv_only": True},
}
# Baseline traits: (key, field the finding goes under, severity, how to say it)
BASELINE = (("aki", "Authority Key ID", "High", "signing key (Authority Key ID)"),
            ("key", "Public Key Algo", "Medium", "key"),
            ("validity", "Duration", "Medium", "validity"),
            ("serial", "Serial Number", "Medium", "serial length"),
            ("signature", "Signature Algo", "Medium", "signature algorithm"),
            ("policy", "Certificate Policy", "Medium", "policy"),
            ("extensions", "Extension OIDs", "Low", "extension layout"),
            ("eku", "Extended Key Usage", "Low", "extended key usage"),
            ("round", "Not Before", "Low", "issue time"))
ISSUER_WIDE = {"aki", "validity"}     # compared across the issuer; the rest within its validity profile
BASELINE_LABELS = {"aki": "Signing key (AKI)", "key": "Key", "validity": "Validity", "serial": "Serial length",
                   "signature": "Signature", "policy": "Policy", "extensions": "Extension layout",
                   "eku": "Extended key usage", "round": "Issue time"}


def _issuer_name(cert):
    return text(cert.get("Issuer")) or text(cert.get("Issuer Org"))


def _known_issuer(cert, run=None):
    """The KNOWN_ISSUERS norm of the certificate's CA; an issuer name without its organization (Domain History) takes
    the organization the run's other records give that name."""
    org = text(cert.get("Issuer Org")) or (run.issuer_orgs.get(_issuer_name(cert).lower(), "") if run else "")
    blob = f"{org} {text(cert.get('Issuer DN'))}".lower()
    return next((norm for marker, norm in KNOWN_ISSUERS.items() if marker in blob), None)


def _serial(cert):
    return re.sub(r"[^0-9a-f]", "", text(cert.get("Serial Number")).lower()).lstrip("0")


def issuance(cert):
    """One issuance per (issuer, serial): a precertificate and its final certificate share it."""
    serial = _serial(cert)
    return (_issuer_name(cert).lower(), serial) if serial else ("", str(cert.get("Hash")))


def _round_time(cert):
    start = when(cert.get("Not Before"))
    if not precise(cert) or pd.isna(start):
        return None
    return "round (hh:mm:00)" if start.second == 0 else "to the second"


def _baseline_traits(cert):
    found = traits(cert)
    aki = text(cert.get("Authority Key ID")).lower().replace(":", "")
    return {"aki": aki or None, "key": found["key"], "validity": found["validity"], "serial": found["serial"],
            "signature": found["signature"], "policy": found["policy"], "extensions": found["extensions"],
            "eku": found["eku"], "round": _round_time(cert), "days": found["days"]}


def _value_text(key, value, exact_days=None):
    if value is None:
        return "–"
    if key == "aki":
        return value[:16] + "…"
    if key == "round":
        return value
    return trait_text(key, value, exact_days)


def _rare(counter, value):
    """(rare?, dominant value, its count, total) of `value` among the issuer's issuances."""
    total = sum(counter.values())
    if not total or value is None:
        return False, None, 0, total
    dominant, top = counter.most_common(1)[0]
    rare = (total >= BASELINE_MIN and value != dominant and counter[value] <= max(1, int(RARE_SHARE * total))
            and top / total >= DOMINANT_SHARE)
    return rare, dominant, top, total


class Run:
    """The run's certificates prepared once: issuances, issuer baselines, precertificate pairs and CT log times."""

    def __init__(self, certs, ctl=None, now=None):
        self.now = now or pd.Timestamp.now(tz="UTC").tz_localize(None)
        self.certs = distinct(certs) if certs is not None and not certs.empty else pd.DataFrame()
        self.rows = self.certs.to_dict("records") if not self.certs.empty else []
        self.by_hash = {row["Hash"]: row for row in self.rows}
        self.traits = {row["Hash"]: _baseline_traits(row) for row in self.rows}
        self.issuances = defaultdict(list)                  # issuance -> hashes
        for row in self.rows:
            self.issuances[issuance(row)].append(row["Hash"])
        # (issuer, None) -> issuer-wide traits; (issuer, validity band) -> the profile's traits; Counters over issuances
        self.baselines = defaultdict(lambda: defaultdict(Counter))
        for key, hashes in self.issuances.items():
            if not key[0]:
                continue
            final = next((h for h in hashes if not _bool(self.by_hash[h].get("Is Precertificate"))), hashes[0])
            found = self.traits[final]
            for trait, value in found.items():
                if trait == "days" or value is None:
                    continue
                if trait in ISSUER_WIDE:
                    self.baselines[(key[0], None)][trait][value] += 1
                elif found["validity"] is not None:
                    self.baselines[(key[0], found["validity"])][trait][value] += 1
        self.logged = defaultdict(list)                     # hash -> CT log entry times
        if ctl is not None and not ctl.empty and {"Hash", "Timestamp"} <= set(ctl.columns):
            for digest, stamp in zip(ctl["Hash"], ctl["Timestamp"]):
                stamp = when(stamp)
                if pd.notna(stamp):
                    self.logged[str(digest)].append(stamp)
        self.issuer_orgs = {text(r.get("Issuer")).lower(): text(r.get("Issuer Org")) for r in self.rows
                            if text(r.get("Issuer")) and text(r.get("Issuer Org"))}
        self.analyzed = {d.lower() for row in self.rows for d in _values(row.get("Domains"))}
        self.ja4x = Counter(text(r.get("JA4X")) for r in self.rows if text(r.get("JA4X")))
        self._templates = None
        self._bursts = None
        self._anomalies = None
        self._shapes = None
        self._sct_times = {}
        self._labels = {}
        self.source = certs

    def sct_times(self, digest):
        """The certificate's embedded SCT times, parsed once per run."""
        if digest not in self._sct_times:
            stamps = scts(self.by_hash.get(digest, {}))
            self._sct_times[digest] = [s["timestamp"] for s in stamps if pd.notna(s["timestamp"])]
        return self._sct_times[digest]

    def labels(self, cert):
        """_labels of the certificate, worked out once per run."""
        digest = cert.get("Hash")
        if digest not in self._labels:
            self._labels[digest] = _labels(cert, self.analyzed)
        return self._labels[digest]

    def anomalies(self):
        """anomalies() of the run, worked out once."""
        if self._anomalies is None:
            self._anomalies = anomalies(None, run=self)
        return self._anomalies

    def shapes(self):
        """cert_shape.shapes() of the run's certificates, worked out once."""
        if self._shapes is None:
            from core.cert_shape import shapes
            self._shapes = shapes(self.certs)
        return self._shapes

    def bursts(self):
        if self._bursts is None:
            self._bursts = _bursts(self)
        return self._bursts

    def findings(self, cert):
        """ANOMALY_COLUMNS rows of one certificate."""
        found = []
        cert = self.by_hash.get(cert.get("Hash"), cert)
        _issuer_checks(cert, self, found)
        _ct_checks(cert, self, found)
        _other_checks(cert, self, found, self.bursts())
        return pd.DataFrame(found, columns=ANOMALY_COLUMNS)

    def partners(self, digest):
        """The other certificates of the same issuance (a precertificate's final certificate, or the reverse)."""
        cert = self.by_hash.get(digest)
        return [h for h in self.issuances.get(issuance(cert), []) if h != digest] if cert else []

    def counter(self, cert, trait, mine=None):
        """The issuer's Counter of `trait` (issuer-wide, or within the certificate's validity profile)."""
        issuer = _issuer_name(cert).lower()
        if trait in ISSUER_WIDE:
            return self.baselines.get((issuer, None), {}).get(trait, Counter())
        band = (mine or self.traits.get(cert["Hash"]) or _baseline_traits(cert)).get("validity")
        return self.baselines.get((issuer, band), {}).get(trait, Counter()) if band else Counter()

    def templates(self):
        """{template: distinct labels} of the run's name labels that mix letters and digits."""
        if self._templates is None:
            found = defaultdict(set)
            for row in self.rows:
                for label in self.labels(row):
                    found[_template(label)].add(label)
            self._templates = {t: labels for t, labels in found.items() if len(labels) >= TEMPLATE_MIN}
        return self._templates


def _labels(cert, analyzed=()):
    """The labels of the certificate's names that mix letters and digits (the registrable name and subdomains, not
    the public suffix), at least TEMPLATE_LENGTH long; an analyzed domain's own label is left out."""
    labels = set()
    for name in _values(cert.get("SAN DNS")) or _values(cert.get("Alt Names List")) or [text(cert.get("Common Name"))]:
        name = str(name).lower().strip().removeprefix("*.").rstrip(".")
        if not name:
            continue
        base = registrable_domain(name)
        parts = name[:-len(base)].rstrip(".").split(".") if base and name.endswith(base) else []
        parts = [p for p in parts if p] + ([base.split(".")[0]] if base and base not in analyzed else [])
        labels.update(p for p in parts if len(p) >= TEMPLATE_LENGTH and re.search(r"\d", p) and re.search(r"[a-z]", p))
    return labels


def _template(label):
    return re.sub(r"[a-z]", "a", re.sub(r"\d", "9", label))


def _add(found, cert, check, code, severity, field, finding):
    found.append({"Hash": cert["Hash"], "Check": check, "Code": code, "Severity": severity, "Field": field,
                  "Finding": finding})


def _issuer_checks(cert, run, found):
    issuer = _issuer_name(cert)
    mine = run.traits.get(cert["Hash"]) or _baseline_traits(cert)
    norm = _known_issuer(cert, run)
    for key, field, severity, noun in BASELINE:
        value = mine.get(key)
        rare, dominant, top, total = _rare(run.counter(cert, key, mine), value)
        if not rare or key == "round" and not value.startswith("round") or value in (norm or {}).get(key, ()):
            continue
        scope = "" if key in ISSUER_WIDE else f" with {mine['validity']} validity"
        this = _value_text(key, value, mine.get("days") if key == "validity" else None)
        usual = _value_text(key, dominant)
        if key == "aki":
            finding = (f"Signed by a different key ({this}) than the issuer's other {top} of {total} certificates "
                       f"({usual}): a CA impersonated by name or made by hand, unless {issuer} rotated or "
                       "cross-signed its key")
        elif key == "round":
            finding = (f"Issued at a round time ({when(cert.get('Not Before')):%Y-%m-%d %H:%M:%S}) while {top} of "
                       f"{issuer}'s {total} certificates{scope} are timed to the second: often a hand-set date")
        else:
            finding = f"Unusual {noun} for {issuer}: {this}, while {top} of its {total} certificates{scope} have {usual}"
        if key == "extensions":
            ja4x = text(cert.get("JA4X"))
            shared = run.ja4x.get(ja4x, 0) if ja4x else 0
            if ja4x and shared <= 1:
                severity, finding = "Medium", finding + "; its JA4X is the only one of its kind in the run"
        _add(found, cert, CHECKS[0], f"issuer_{key}", severity, field, finding)
    level = text(cert.get("Validation Level")).lower()
    oids = set(policies(cert))
    if norm and norm.get("max_days") and mine.get("days") is not None and mine["days"] > norm["max_days"]:
        _add(found, cert, CHECKS[0], "issuer_norm_days", "Medium", "Duration",
             f"Valid {mine['days']} days: {norm['name']} never issues certificates this long")
    if norm and norm.get("dv_only"):
        higher = sorted({OV_EV_POLICIES[o] for o in oids if o in OV_EV_POLICIES} | ({level.upper()} & {"OV", "EV", "IV"}))
        if higher:
            _add(found, cert, CHECKS[0], "issuer_norm_level", "Medium", "Certificate Policy",
                 f"{'/'.join(higher)} validation claimed under {norm['name']}, which only issues domain-validated "
                 "certificates")
    org = text(cert.get("Subject Org"))
    if org and (level == "dv" or DV_POLICY in oids) and not (oids & set(OV_EV_POLICIES)):
        _add(found, cert, CHECKS[0], "dv_subject_org", "Medium", "Subject Org",
             f"Organization “{org}” on a domain-validated certificate: DV certificates carry no organization (the "
             "CA never checked one), so whoever made it put it there")


def _ct_checks(cert, run, found):
    digest = cert["Hash"]
    start = when(cert.get("Not Before"))
    pre = _bool(cert.get("Is Precertificate"))
    partners = run.partners(digest)
    own = scts(cert)
    times = run.sct_times(digest) + run.logged.get(digest, [])
    for other in partners:
        times += run.sct_times(other) + run.logged.get(other, [])
    if times and pd.notna(start):
        first = min(times)
        hours = (first - start).total_seconds() / 3600
        if hours > LATE_LOG_HOURS:
            _add(found, cert, CHECKS[1], "ct_late", "Medium", "Signed Certificate Timestamps",
                 f"First logged in CT {hours / 24:.1f} days after its Not Before ({first:%Y-%m-%d %H:%M} vs "
                 f"{start:%Y-%m-%d %H:%M}): backdated, or logged late (CAs backdate by an hour or so)")
    valid_for = run.traits.get(digest, {}).get("days")
    if not pre and own and valid_for is not None:
        needed = next((n for limit, n in SCT_POLICY if valid_for <= limit), SCT_POLICY_LONG)
        logs = len({s["log_id"] for s in own})
        if logs < needed:
            _add(found, cert, CHECKS[1], "sct_count", "Medium", "Signed Certificate Timestamps",
                 f"{logs} SCT log(s) for a {valid_for}-day certificate: Chrome and Apple ask for {needed}, so browsers "
                 "would reject it")
    trusted = publicly_trusted(cert)
    if trusted and not pre and not _empty(cert.get("Has Embedded SCTs")) and not _bool(cert.get("Has Embedded SCTs")) \
            and not any(_bool(run.by_hash[p].get("Is Precertificate")) for p in partners) \
            and not run.logged.get(digest):
        _add(found, cert, CHECKS[1], "ct_never", "Low", "Has Embedded SCTs",
             "No trace of CT logging: no embedded SCTs, no precertificate and no CT log entry in the run")
    if pre and precise(cert) and not partners:
        _add(found, cert, CHECKS[1], "ct_orphan_pre", "Low", "Is Precertificate",
             "Precertificate whose final certificate is not in the run: not deployed yet, or not collected")


def _bursts(run):
    """{hash: (issuances in the burst, analyzed domains, issuer)}: BURST_MIN issuances or more of one issuer within
    BURST_MINUTES for BURST_DOMAINS analyzed domains or more (Certificate API times only)."""
    by_issuer = defaultdict(list)
    for key, hashes in run.issuances.items():
        rows = [run.by_hash[h] for h in hashes if precise(run.by_hash[h])]
        stamps = [when(r.get("Not Before")) for r in rows]
        stamps = [s for s in stamps if pd.notna(s)]
        if rows and stamps and key[0]:
            domains = {d for r in rows for d in _values(r.get("Domains"))}
            by_issuer[key[0]].append((min(stamps), hashes, domains))
    found = {}
    window = pd.Timedelta(minutes=BURST_MINUTES)
    for issuer, items in by_issuer.items():
        items.sort(key=lambda item: item[0])
        for i, (start, _, _) in enumerate(items):
            group = []
            for item in items[i:]:
                if item[0] > start + window:
                    break
                group.append(item)
            domains = set().union(*(item[2] for item in group))
            if len(group) >= BURST_MIN and len(domains) >= BURST_DOMAINS:
                for _, hashes, _ in group:
                    for h in hashes:
                        if h not in found or found[h][0] < len(group):
                            found[h] = (len(group), sorted(domains), issuer, start)
    return found


def _other_checks(cert, run, found, bursts):
    digest = cert["Hash"]
    if digest in bursts:
        count, domains, issuer, start = bursts[digest]
        _add(found, cert, CHECKS[2], "burst", "Medium", "Not Before",
             f"One of {count} certificates {_issuer_name(cert) or issuer} issued within {BURST_MINUTES} minutes "
             f"(from {start:%Y-%m-%d %H:%M}) for {len(domains)} analyzed domains ({', '.join(domains[:4])}"
             f"{'…' if len(domains) > 4 else ''}): set up in one go")
    valid_for = run.traits.get(digest, {}).get("days")
    if valid_for in TOOL_DAYS and publicly_trusted(cert) is not True:
        _add(found, cert, CHECKS[2], "tool_days", "Low", "Duration",
             f"Valid exactly {valid_for} days on a {'self-signed' if _bool(cert.get('Is Self Signed')) else 'non-public'} "
             "certificate: the round number certificate tools (OpenSSL -days) are given")
    templates = run.templates()
    mine, hits = defaultdict(list), []
    for label in sorted(run.labels(cert)):
        template = _template(label)
        if template in templates:
            mine[template].append(label)
        elif len(label) >= RANDOM_LENGTH and calculate_shannon_entropy(label) >= RANDOM_ENTROPY:
            hits.append(f"{label} looks random (entropy {calculate_shannon_entropy(label):.1f})")
    for template, labels in sorted(mine.items(), key=lambda item: -len(item[1])):
        hits.insert(0, f"Names follow one template ({template}: {', '.join(labels[:3])}{'…' if len(labels) > 3 else ''}"
                       f"), shared by {len(templates[template])} names of the run: generated in bulk")
    if hits:
        _add(found, cert, CHECKS[2], "name_template", "Low", "SAN DNS", "; ".join(hits[:2]))


_RUNS = OrderedDict()       # run_key -> Run, the few most recent (pages rerun on every click)
_RUNS_KEPT = 4


def _run_key(certs, ctl):
    logged = () if ctl is None or ctl.empty else frame_key(ctl, ("Hash", "Timestamp"))
    return frame_key(certs), logged


def cached_run(certs, ctl=None):
    """
    Run(certs, ctl), reused while the certificates and CT log entries stay the same: the Certificate profile and the
    Certificates page rerun on every click, and a large run's anomalies take seconds. The Run also keeps its
    anomalies() and shapes() once worked out.
    """
    if certs is None or certs.empty:
        return Run(certs, ctl)
    key = _run_key(certs, ctl)
    run = _RUNS.get(key)
    if run is None:
        run = _RUNS[key] = Run(certs, ctl)
        while len(_RUNS) > _RUNS_KEPT:
            _RUNS.popitem(last=False)
    else:
        _RUNS.move_to_end(key)
    return run


def anomalies(certs, ctl=None, now=None, run=None):
    """ANOMALY_COLUMNS for every distinct certificate of the run, most severe first."""
    run = run or Run(certs, ctl, now)
    found = []
    for cert in run.rows:
        _issuer_checks(cert, run, found)
        _ct_checks(cert, run, found)
        _other_checks(cert, run, found, run.bursts())
    return _by_severity(pd.DataFrame(found, columns=ANOMALY_COLUMNS))


def _by_severity(frame):
    from core.intel_data import SEVERITY_RANK
    if frame.empty:
        return frame
    return frame.assign(_r=frame["Severity"].map(SEVERITY_RANK).fillna(9)).sort_values("_r", kind="stable") \
        .drop(columns="_r").reset_index(drop=True)


def for_certificate(digest, table, sha1=None):
    """The anomalies of one certificate (also under its SHA-1, the hash Domain History lists it by)."""
    if table is None or table.empty:
        return pd.DataFrame(columns=ANOMALY_COLUMNS)
    keys = {str(digest)} | ({str(sha1).lower()} if sha1 else set())
    return table[table["Hash"].astype(str).isin(keys)].reset_index(drop=True)


AGAINST_COLUMNS = ["Trait", "This certificate", "Issuer's usual", "Verdict"]


def against_issuer(cert, run):
    """
    AGAINST_COLUMNS: the certificate's traits next to what its issuer usually has in the run. Verdict: "usual",
    "differs" (another value is usual, but this one is not rare enough to flag), "rare" (flagged), or "too few" when
    fewer than BASELINE_MIN of the issuer's issuances know the trait.
    """
    mine = _baseline_traits(cert)
    norm = _known_issuer(cert, run) or {}
    rows = []
    for key, _, _, _ in BASELINE:
        value = mine.get(key)
        if value is None:
            continue
        rare, dominant, top, total = _rare(run.counter(cert, key, mine), value)
        if value in norm.get(key, ()):
            verdict = "usual"
        elif total < BASELINE_MIN:
            verdict = "too few"
        elif rare and not (key == "round" and not value.startswith("round")):
            verdict = "rare"
        elif value == dominant:
            verdict = "usual"
        else:
            verdict = "differs"
        rows.append({"Trait": BASELINE_LABELS[key] + ("" if key in ISSUER_WIDE or not mine.get("validity")
                                                      else f" ({mine['validity']} profile)"),
                     "This certificate": _value_text(key, value, mine.get("days") if key == "validity" else None),
                     "Issuer's usual": f"{_value_text(key, dominant)} ({top} of {total})" if total else "–",
                     "Verdict": verdict})
    return pd.DataFrame(rows, columns=AGAINST_COLUMNS)


def profile(cert, certs, run=None, ctl=None):
    """
    What the Certificate profile shows next to the certificate's own fields, in one place:
    "related" (cert_profile.related_certificates plus the same and near shapes), "found" (cert_profile.flags plus
    the anomalies, FLAG_COLUMNS with Check), "anomalies" (ANOMALY_COLUMNS), "family" (shape ID, label, members'
    hashes), "against" (against_issuer) and "query" (a CertsQL query for its shape).
    """
    from core import cert_profile as cp
    from core.cert_shape import family_of, shape_query, shape_relations
    run = run or Run(certs, ctl)
    related = cp.related_certificates(cert, certs)
    table = run.shapes()
    shaped = shape_relations(cert, certs, table=table)
    if not shaped.empty:
        related = pd.concat([related, shaped.drop(columns="Score")], ignore_index=True) if not related.empty \
            else shaped.drop(columns="Score")
    own = run.findings(cert)
    flags = cp.flags(cert, related=related).assign(Check="Certificate")
    found = _by_severity(pd.concat([flags, own[["Check", "Severity", "Field", "Finding"]]], ignore_index=True)
                         if not own.empty else flags)
    shape, label, members = family_of(cert.get("Hash"), certs, table)
    domains = sorted({d for h in members for d in _values(run.by_hash.get(h, {}).get("Domains"))})
    return {"related": related, "found": found, "anomalies": own, "against": against_issuer(cert, run),
            "family": {"id": shape, "label": label, "members": members, "domains": domains},
            "query": shape_query(cert)}
