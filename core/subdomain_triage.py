"""
Subdomain triage: ranks the hostnames of the Hostname Inventory by name and lifecycle signals that phishing and
malware subdomains tend to show (phishing words, brand names, punycode, random-looking labels, bursts of new names).
Built for shared platforms (pages.dev, workers.dev, free subdomain registries) where the domain's own risk says nothing
about what its subdomains host, but works for any domain.
"""
import math
import re
from collections import Counter

import pandas as pd

from config import TRIAGE_BURST_MIN
from core.hostnames import apex_of, clean_hostname, sensitive_words
from core.intel_data import IMPERSONATED_BRANDS, SHARED_PLATFORMS

# signal -> (weight, explanation); the score is the sum of the weights of a hostname's signals
TRIAGE_SIGNALS = {
    "Phishing word": (3, "A label contains a word used for credential phishing or remote access (login, verify, "
                         "wallet, vpn, ...)"),
    "Brand name": (3, "A label contains a brand phishing kits often impersonate (paypal, microsoft, dhl, ...) and the "
                      "domain itself is not that brand"),
    "Embedded domain": (3, "Another domain is written into the name (`zoom.us.example.eu.cc`, `paypal-com-verify`): "
                           "the real domain is pushed out of view"),
    "Punycode": (3, "A label is internationalized (xn--): may imitate another name with look-alike characters"),
    "Random-looking": (2, "A name part of 8+ characters that mixes letters and digits, has a long consonant run or "
                          "no structure, typical of generated names (also of some deploy previews)"),
    "New": (1, "First seen (certificate or passive DNS) within the last N days"),
    "Burst": (1, f"First seen in the same hour as at least {TRIAGE_BURST_MIN - 1} other hostnames of the same domain: "
                 "names created together, often one campaign or one automated deployment"),
    "Never resolved": (1, "Named in a certificate but never seen in passive DNS: possibly prepared for "
                                       "later use"),
    "Long or deep name": (1, "Three or more labels below the domain, or 40+ characters before it: hides the real "
                             "domain on small screens"),
}
# Name signals that point at abuse on their own; without one, lifecycle and random-name signals stay Low unless they add up
STRONG_SIGNALS = ("Phishing word", "Brand name", "Embedded domain", "Punycode")
HIGH_SCORE, MEDIUM_SCORE = 6, 4
# Top-level domains whose appearance inside a subdomain (`zoom.us.`, `paypal-com-`) usually means an embedded domain;
# word-like TLDs (app, site, online) are left out because they are ordinary words in names
EMBEDDED_TLDS = frozenset({"com", "net", "org", "us", "io", "co", "uk", "de", "fr", "ru", "cn", "gov", "edu"})
EMBEDDED_TLDS_IN_WORDS = frozenset({"com", "net", "org", "gov"})   # `paypal-com-login`, `irs-gov-refund`
LEVELS = ["High", "Medium", "Low"]
TRIAGE_COLUMNS = ["Score", "Level", "Hostname", "Apex", "Signals", "Matched", "First Seen", "Certificates",
                  "pDNS Records", "Current Values", "Latest Certificate Hash", "Platform"]
VOWELS = set("aeiouy")
CONSONANT_RUN = re.compile(r"[b-df-hj-np-tv-xz]{5,}")


def level_of(score, signals):
    """High: score 6+ with a strong name signal; Medium: a strong name signal or score 4+; Low: any other signal."""
    strong = any(s in STRONG_SIGNALS for s in signals)
    if strong and score >= HIGH_SCORE:
        return "High"
    if strong or score >= MEDIUM_SCORE:
        return "Medium"
    return "Low" if score else ""


def shared_platform(apex):
    """The shared-platform suffix the domain belongs to ("" when it is an ordinary domain)."""
    apex = clean_hostname(apex)
    return next((p for p in SHARED_PLATFORMS if apex == p or apex.endswith("." + p)), "")


def _labels_below(name, apex):
    return name[:-len(apex) - 1].split(".") if apex and name.endswith("." + apex) else []


def _entropy(text):
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def looks_random(label):
    """True when a hyphen-separated part of the label looks generated rather than made of words."""
    if label.startswith("xn--"):
        return False
    for part in re.split(r"[-_]", label):
        if len(part) < 8:
            continue
        letters, digits = sum(c.isalpha() for c in part), sum(c.isdigit() for c in part)
        if letters and digits and min(letters, digits) / len(part) >= 0.25:
            return True
        vowels = sum(c in VOWELS for c in part) / len(part)
        if CONSONANT_RUN.search(part) or (len(part) >= 12 and vowels < 0.25 and _entropy(part) >= 3.5):
            return True
    return False


def embedded_domains(labels):
    """Domains written into the labels: `zoom.us` from zoom.us.vip1, `paypal.com` from paypal-com-login."""
    found = [f"{labels[i]}.{labels[i + 1]}" for i in range(len(labels) - 1)
             if labels[i + 1] in EMBEDDED_TLDS and labels[i] and labels[i] not in EMBEDDED_TLDS]
    for label in labels:
        parts = label.split("-")
        found += [f"{parts[i - 1]}.{parts[i]}" for i in range(1, len(parts))
                  if parts[i] in EMBEDDED_TLDS_IN_WORDS and len(parts[i - 1]) >= 3 and parts[i - 1] not in EMBEDDED_TLDS]
    return list(dict.fromkeys(found))


def brands_in(labels, apex):
    """IMPERSONATED_BRANDS found in the labels, unless the domain itself carries the brand (login.paypal.com)."""
    own = apex.split(".")[0]
    joined = ".".join(labels)
    words = {w for w in re.split(r"[-_.\d]+", joined) if w}
    return [b for b in IMPERSONATED_BRANDS if b not in own and (b in words or (len(b) >= 6 and b in joined))]


def name_signals(name, apex):
    """(signals, matched words) from the hostname alone."""
    labels = _labels_below(name, apex)
    signals, matched = [], []
    words = sensitive_words(name)
    if words:
        signals.append("Phishing word")
        matched += words
    brands = brands_in(labels, apex)
    if brands:
        signals.append("Brand name")
        matched += brands
    embedded = embedded_domains(labels)
    if embedded:
        signals.append("Embedded domain")
        matched += embedded
    if any(label.startswith("xn--") for label in labels):
        signals.append("Punycode")
    if any(looks_random(label) for label in labels):
        signals.append("Random-looking")
    if len(labels) >= 3 or len(name) - len(apex) - 1 >= 40:
        signals.append("Long or deep name")
    return signals, list(dict.fromkeys(matched))


def build_subdomain_triage(inventory):
    """
    One row (TRIAGE_COLUMNS) per hostname below its domain (the domain itself and wildcard names are left out), with
    its signals and score, highest score first. `inventory` is the Hostname Inventory frame.
    """
    if inventory is None or inventory.empty:
        return pd.DataFrame(columns=TRIAGE_COLUMNS)
    hosts = inventory[~inventory["Hostname"].str.startswith("*.") & (inventory["Hostname"] != inventory["Apex"])]
    if hosts.empty:
        return pd.DataFrame(columns=TRIAGE_COLUMNS)
    first_seen = pd.concat([pd.to_datetime(hosts["First Certificate"], errors="coerce"),
                            pd.to_datetime(hosts["pDNS First Seen"], errors="coerce")], axis=1).min(axis=1)
    hour = first_seen.dt.floor("h")
    burst_size = hosts.assign(_hour=hour).groupby(["Apex", "_hour"])["Hostname"].transform("size")
    platforms = {apex: shared_platform(apex) for apex in hosts["Apex"].unique()}

    rows = []
    for idx, row in hosts.iterrows():
        name, apex = row["Hostname"], row["Apex"] or apex_of(row["Hostname"])
        signals, matched = name_signals(name, apex)
        flags = str(row.get("Flags") or "")
        if "New" in flags.split(", "):
            signals.append("New")
        if pd.notna(hour.loc[idx]) and burst_size.loc[idx] >= TRIAGE_BURST_MIN:
            signals.append("Burst")
        if "Certificate, never resolved" in flags:
            signals.append("Never resolved")
        score = sum(TRIAGE_SIGNALS[s][0] for s in signals)
        rows.append({
            "Score": score, "Level": level_of(score, signals), "Hostname": name, "Apex": apex, "Signals": ", ".join(signals),
            "Matched": ", ".join(matched), "First Seen": first_seen.loc[idx], "Certificates": row["Certificates"],
            "pDNS Records": row["pDNS Records"], "Current Values": row["Current Values"],
            "Latest Certificate Hash": row["Latest Certificate Hash"], "Platform": platforms.get(apex, ""),
        })
    frame = pd.DataFrame(rows, columns=TRIAGE_COLUMNS)
    return frame.sort_values(["Score", "First Seen", "Hostname"], ascending=[False, False, True], na_position="last",
                             kind="stable").reset_index(drop=True)
