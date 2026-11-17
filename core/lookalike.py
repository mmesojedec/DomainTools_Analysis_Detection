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


# Words that commonly wrap a brand inside one token (`mypaypal`, `paypalhelp`): a brand embedded in any other word
# (`chase` in `purchase`) is a coincidence, not combosquatting
COMBO_AFFIXES = ("my", "the", "online", "app", "web", "help", "mail", "id", "official", "center", "team", "cs", "care")
_AFFIX_RE = re.compile("^(?:" + "|".join(sorted({re.escape(k.replace("-", "")) for k in PHISHING_KEYWORDS + COMBO_AFFIXES},
                                                 key=len, reverse=True)) + r"|\d+)+$")


def _combosquat(tokens, brand):
    """True when the brand is a whole hyphen-separated token, or a token is the brand plus keywords / digits."""
    for token in tokens:
        if brand not in token:
            continue
        left, _, right = token.partition(brand)
        if all(not part or _AFFIX_RE.match(part) for part in (left, right)):
            return True
    return False


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
        if _combosquat(tokens, brand) or _combosquat(re.split(r"[-_]", decoded_label), brand):
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


# --- Candidate generation: names a lookalike hunt searches for (Settings → Brands & allowlist → Hunt lookalikes) ---
KEYBOARD = {"q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok", "o": "ipl",
            "p": "ol", "a": "qsz", "s": "awdz", "d": "sefx", "f": "drgc", "g": "fthv", "h": "gyjb", "j": "hukn",
            "k": "jilm", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm",
            "m": "njk"}
LOOKALIKE_SWAPS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "m": "rn", "w": "vv"}
CANDIDATE_TLDS = ("com", "net", "org", "co", "io", "info", "online", "site", "xyz", "top", "shop", "app")
CANDIDATE_WORDS = ("login", "secure", "verify", "account", "support", "billing", "update", "help", "auth", "online")
MAX_CANDIDATES = 500


def _typos(brand):
    found = set()
    for i in range(len(brand)):
        found.add(brand[:i] + brand[i + 1:])                                   # omission
        found.add(brand[:i] + brand[i] + brand[i:])                            # repetition
        if i < len(brand) - 1:
            found.add(brand[:i] + brand[i + 1] + brand[i] + brand[i + 2:])     # transposition
        for near in KEYBOARD.get(brand[i], ""):
            found.add(brand[:i] + near + brand[i + 1:])                        # neighbouring key
        if brand[i] in LOOKALIKE_SWAPS:
            found.add(brand[:i] + LOOKALIKE_SWAPS[brand[i]] + brand[i + 1:])   # look-alike character
        if 0 < i < len(brand):
            found.add(brand[:i] + "-" + brand[i:])                             # hyphenation
    found.discard(brand)
    return {name for name in found if len(name) >= 3}


def lookalike_candidates(brands, official_domains=(), tlds=CANDIDATE_TLDS, limit=MAX_CANDIDATES):
    """
    Domains a lookalike of `brands` would register: typos on the brand's own TLDs, the exact brand on other TLDs,
    and brand + phishing word combinations; the official domains left out. The most likely first, up to `limit`.
    """
    official = {str(d).lower() for d in official_domains}
    candidates = []
    for brand in brands:
        own_tlds = [d.split(".", 1)[1] for d in official if d.split(".", 1)[0] == brand] or ["com"]
        candidates += [f"{brand}.{tld}" for tld in tlds if tld not in own_tlds]
        candidates += [f"{brand}-{word}.{own_tlds[0]}" for word in CANDIDATE_WORDS]
        candidates += [f"{word}-{brand}.{own_tlds[0]}" for word in CANDIDATE_WORDS[:4]]
        candidates += [f"{name}.{tld}" for name in sorted(_typos(brand)) for tld in own_tlds]
    return [c for c in dict.fromkeys(candidates) if c not in official][:limit]


def lookalike_query(candidates, header="# IrisQL-1.0"):
    """An IrisQL query for the candidate domains that exist (registered), newest first in the results."""
    names = ", ".join(f'"{name}"' for name in candidates)
    return f"{header}\nDOMAIN EXACTLY_IN [{names}]"
