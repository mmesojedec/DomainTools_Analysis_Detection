"""Brand lookalike analysis: typosquatting, homoglyph/IDN impersonation, combosquatting, and brand-in-subdomain."""
import re
import unicodedata

from core.helpers import is_ip_address, registrable_domain
from core.intel_data import HOMOGLYPHS, MULTI_CHAR_HOMOGLYPHS, PHISHING_KEYWORDS

MIN_BRAND_LENGTH = 4


def parse_brand_list(raw):
    """Parses a comma/newline-separated brand list into unique lowercase labels (e.g. 'PayPal, acme.com' -> paypal, acme)."""
    brands = []
    for item in re.split(r"[\s,;]+", raw or ""):
        label = item.strip().lower()
        if "." in label:
            label = registrable_domain(label).split(".")[0]
        label = re.sub(r"[^a-z0-9-]", "", label)
        if len(label) >= MIN_BRAND_LENGTH and label not in brands:
            brands.append(label)
    return tuple(brands)


def parse_official_domains(raw):
    """Entries given as domains (e.g. 'acme.co.uk') are treated as the brand's own, never-flagged domains."""
    return tuple(dict.fromkeys(registrable_domain(item.strip().lower()) for item in re.split(r"[\s,;]+", raw or "")
                               if "." in item and not is_ip_address(item.strip())))


def decode_idn(label):
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except UnicodeError:
            return label
    return label


def skeleton(text):
    """Visual skeleton: decoded IDN, accents stripped, confusables mapped to ASCII look-alikes."""
    decoded = ".".join(decode_idn(part) for part in str(text).lower().split("."))
    stripped = "".join(c for c in unicodedata.normalize("NFKD", decoded) if not unicodedata.combining(c))
    mapped = "".join(HOMOGLYPHS.get(c, c) for c in stripped)
    for source, target in MULTI_CHAR_HOMOGLYPHS:
        mapped = mapped.replace(source, target)
    return mapped


def edit_distance(a, b):
    """Optimal-string-alignment (Damerau-Levenshtein) distance: insertions, deletions, substitutions, transpositions."""
    if a == b:
        return 0
    rows, cols = len(a) + 1, len(b) + 1
    dist = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        dist[i][0] = i
    for j in range(cols):
        dist[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dist[i][j] = min(dist[i - 1][j] + 1, dist[i][j - 1] + 1, dist[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                dist[i][j] = min(dist[i][j], dist[i - 2][j - 2] + 1)
    return dist[-1][-1]


def _max_typo_distance(brand):
    return 1 if len(brand) <= 7 else 2


def analyze_lookalike(hostname, brands, official_domains=()):
    """Returns findings [{type, brand, detail}] for one hostname. IDN findings are reported even without brands."""
    host = str(hostname or "").strip().lower().rstrip(".")
    if not host or is_ip_address(host):
        return []
    official = set(official_domains)
    if registrable_domain(host) in official:
        return []
    findings = []
    labels = host.split(".")
    if any(label.startswith("xn--") for label in labels):
        findings.append({"type": "IDN / Punycode Domain", "brand": "", "detail": f"Decoded: {'.'.join(decode_idn(x) for x in labels)}"})

    reg = registrable_domain(host)
    reg_label = reg.split(".")[0] if reg else host
    subdomain_part = host[: -len(reg)].rstrip(".") if reg and host.endswith(reg) and host != reg else ""
    decoded_label = decode_idn(reg_label)
    label_skeleton = skeleton(decoded_label)
    tokens = [t for t in re.split(r"[-_]", label_skeleton) if t]

    for brand in brands:
        if reg_label == brand:
            brand_official = {d for d in official if d.split(".")[0] == brand}
            if (brand_official and reg not in brand_official) or (not brand_official and reg.split(".", 1)[-1] != "com"):
                findings.append({"type": "Brand Name on Alternate TLD", "brand": brand, "detail": f"{reg} uses the exact brand label"})
            continue
        if label_skeleton == brand:
            findings.append({"type": "Homoglyph / IDN Brand Impersonation", "brand": brand,
                             "detail": f"'{decoded_label}' renders like '{brand}'"})
            continue
        distance = edit_distance(decoded_label, brand)
        if 0 < distance <= _max_typo_distance(brand) and abs(len(decoded_label) - len(brand)) <= 2:
            findings.append({"type": "Typosquatting Lookalike", "brand": brand, "detail": f"Edit distance {distance} from '{brand}'"})
            continue
        if brand in label_skeleton:
            keywords = [k for k in PHISHING_KEYWORDS if k in label_skeleton.replace(brand, " ")]
            findings.append({"type": "Combosquatting (Brand + Keyword)", "brand": brand,
                             "detail": f"Label '{decoded_label}' embeds '{brand}'" + (f" with keywords: {', '.join(keywords)}" if keywords else ""),
                             "keywords": keywords})
            continue
        if any(edit_distance(token, brand) == 1 for token in tokens if len(token) >= MIN_BRAND_LENGTH):
            findings.append({"type": "Typosquatting Lookalike", "brand": brand, "detail": f"Label token is one edit from '{brand}'"})
            continue
        if subdomain_part and brand in skeleton(subdomain_part).replace("-", ".").split("."):
            findings.append({"type": "Brand in Subdomain", "brand": brand, "detail": f"Subdomain '{subdomain_part}' carries the brand on {reg}"})
    return findings
