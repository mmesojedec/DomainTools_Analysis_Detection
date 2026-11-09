"""
Regenerates the reference tables in docs/USER_GUIDE.md (rule catalogue, ATT&CK mapping, thresholds, DIF codes) and
docs/REFERENCE.md (collection limits, use case options, built-in lists) from the code. Run after changing a rule,
threshold, DIF code, limit, use case or list:  python scripts/generate_docs_tables.py
tests/test_docs.py fails when a guide is out of date.
"""
import ast
import importlib
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import config  # noqa: E402
from config import THRESHOLD_SPECS  # noqa: E402
from core.intel_data import MITRE_TACTICS, RULE_METADATA, TACTIC_ORDER  # noqa: E402
from core.risk_profile import DIF_SEGMENTS  # noqa: E402
from core.rule_catalog import RULE_CATALOG  # noqa: E402
from core.use_cases import GLOBAL_DEFAULTS, OPTION_LABELS, PROFILE_KEYS, USE_CASES, builtin_settings  # noqa: E402
from core.window import WINDOW_PRESETS  # noqa: E402

GUIDE = ROOT / "docs" / "USER_GUIDE.md"
REFERENCE = ROOT / "docs" / "REFERENCE.md"


def _cell(text):
    return str(text).replace("|", "\\|")


def _number(value):
    return int(value) if float(value).is_integer() else value


def rules_table():
    by_category = defaultdict(list)
    for name, (severity, mitre, trigger, why) in RULE_CATALOG.items():
        category, confidence = RULE_METADATA[name]
        by_category[category].append((name, severity, confidence, mitre, trigger, why))
    blocks = []
    for category in sorted(by_category):
        rows = ["| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |",
                "| --- | --- | --- | --- | --- | --- |"]
        rows += ["| " + " | ".join(_cell(x) for x in row) + " |" for row in by_category[category]]
        blocks.append(f"#### {category}\n\n" + "\n".join(rows))
    return "\n\n".join(blocks)


def tactics_table():
    names, counts = defaultdict(set), defaultdict(int)
    for _, mitre, _, _ in RULE_CATALOG.values():
        technique = mitre.split(" ")[0]
        names[technique].add(mitre[len(technique):].strip(" ()"))
        counts[technique] += 1
    rows = []
    for technique in names:
        tactic = MITRE_TACTICS.get(technique.split(".")[0], "Other")
        order = TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else len(TACTIC_ORDER)
        rows.append((order, tactic, technique, "; ".join(sorted(names[technique])), counts[technique]))
    lines = ["| Tactic | Technique | Name(s) used by rules | Rules |", "| --- | --- | --- | --- |"]
    lines += [f"| {tactic} | {technique} | {_cell(n)} | {count} |" for _, tactic, technique, n, count in sorted(rows)]
    return "\n".join(lines)


def thresholds_table():
    lines = ["| Threshold | Default | Range | Section | What it controls |", "| --- | --- | --- | --- | --- |"]
    lines += [f"| {s.label} | {_number(s.default)} | {_number(s.min_value)}–{_number(s.max_value)} | {s.section} | {_cell(s.help)} |"
              for s in THRESHOLD_SPECS]
    return "\n".join(lines)


def dif_table():
    lines = ["| Segment | Code | Meaning | Derived from |", "| --- | --- | --- | --- |"]
    lines += [f"| {segment} | `{code}` | {_cell(meaning)} | {_cell(source)} |" for segment, _, code, meaning, source in DIF_SEGMENTS]
    return "\n".join(lines)


def _comments(path):
    """{constant name: its comment} of a module: the comment at the end of the assignment's first line, or the
    comment lines right above it."""
    lines = path.read_text().splitlines()
    found = {}
    for node in ast.parse("\n".join(lines)).body:
        if not isinstance(node, ast.Assign) or not isinstance(node.targets[0], ast.Name):
            continue
        first = lines[node.lineno - 1]
        text = first.split("  # ", 1)[1] if "  # " in first else ""
        above, row = [], node.lineno - 2
        while row >= 0 and lines[row].startswith("# ") and not lines[row].startswith("# ---"):
            above.insert(0, lines[row][2:])
            row -= 1
        found[node.targets[0].id] = (text or " ".join(above)).strip()
    return found


def _section_names(path, start, end):
    """Constant names assigned between the `# --- start` and `# --- end` header comments of a module."""
    names, inside = [], False
    for line in path.read_text().splitlines():
        if line.startswith("# ---"):
            inside = start in line if not inside else end not in line
            continue
        if inside and line[:1].isupper() and " = " in line:
            names.append(line.split(" = ", 1)[0])
    return names


def _value(value):
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, (list, tuple)):
        return ", ".join(_value(v) for v in value)
    if isinstance(value, dict):
        return ", ".join(f"{k}: {_value(v)}" for k, v in value.items())
    return str(value)


def limits_table():
    comments = _comments(ROOT / "config.py")
    lines = ["| Setting in config.py | Value | What it limits |", "| --- | --- | --- |"]
    lines += [f"| `{name}` | {_cell(_value(getattr(config, name)))} | {_cell(comments.get(name, ''))} |"
              for name in _section_names(ROOT / "config.py", "COLLECTION LIMITS", "DISPLAY LIMITS")]
    return "\n".join(lines)


def use_case_table():
    header = ["Option", "Global default", *(case.title for case in USE_CASES)]
    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
    for key in PROFILE_KEYS:
        default = GLOBAL_DEFAULTS[key]
        cells = [_value(builtin_settings(case)[key]) if builtin_settings(case)[key] != default else "·"
                 for case in USE_CASES]
        lines.append(f"| {OPTION_LABELS[key]} | {_value(default)} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def other_values_table():
    rows = [
        ("Severity weights (risk vectors and Unified Risk)", _value(config.SEVERITY_WEIGHTS)),
        ("Analysis window choices", ", ".join(WINDOW_PRESETS)),
        ("Cache lifetime choices", ", ".join(config.CACHE_LIFETIMES)),
        ("Default cache lifetime", f"{config.FETCH_CACHE_TTL_SECONDS // 3600} hours"),
        ("Hostname counted as New (Hostname Inventory)", f"first seen within {config.HOSTNAME_NEW_DAYS} days"),
        ("Pivot strength (Pivot Ranking)", f"strong: shared by 2–{config.PIVOT_STRONG_MAX:,} domains in Iris; useful: "
                                           f"up to {config.PIVOT_USEFUL_MAX:,}; weak: more"),
        ("Burst of new subdomains (Subdomain Triage)", f"{config.TRIAGE_BURST_MIN}+ first seen in the same hour"),
        ("Offline datasets kept (default; change on Offline Datasets)", f"{config.MAX_OFFLINE_DATASETS} newest"),
        ("Run snapshots kept per target set (default; change on Runs & Diffs)", f"{config.MAX_RUN_SNAPSHOTS} newest"),
        ("Rows shown in raw tables", f"{config.MAX_RAW_DISPLAY_ROWS:,}"),
        ("Quota banner (products this app uses, DNSDB key)", f"yellow from {config.QUOTA_WARN_PERCENT}% of the quota "
                                                             f"used or {config.EXPIRY_WARN_DAYS} days before expiry; "
                                                             "red when used up or expired"),
    ]
    lines = ["| What | Value |", "| --- | --- |"]
    lines += [f"| {what} | {_cell(value)} |" for what, value in rows]
    return "\n".join(lines)


# built-in lists: (module, constant, title, used by)
LISTS = [
    ("core.intel_data", "HOSTING_WATCHLIST", "Hosting watchlist",
     "*Hosting Watchlist* alert, the Watchlist column on DNS & Hosting"),
    ("core.intel_data", "IMPERSONATED_BRANDS", "Impersonated brands",
     "Subdomain Triage (*Brand name* signal), CNAME rules (lure names on free hosting)"),
    ("core.intel_data", "PHISHING_KEYWORDS", "Phishing keywords", "Lookalike rules (combosquats of your brands)"),
    ("core.hostnames", "SENSITIVE_WORDS", "Sensitive hostname words", "Hostname Inventory (*Sensitive name* flag)"),
    ("core.intel_data", "SHARED_PLATFORMS", "Shared platforms",
     "Subdomain Triage (platform domains), CNAME Chains (*Free hosting* service type)"),
    ("core.intel_data", "TAKEOVER_CNAME_SUFFIXES", "Takeover-prone services",
     "CNAME Chains (*Takeover-prone*), *Dangling CNAME* alerts"),
    ("core.intel_data", "DYNAMIC_DNS_CNAME_SUFFIXES", "Dynamic DNS and tunnel services",
     "CNAME Chains (*Dynamic DNS / tunnel*), CNAME alerts"),
    ("core.intel_data", "PARKING_CNAME_SUFFIXES", "Parking CNAME targets",
     "CNAME Chains (*Parking*; never counted as a link between domains)"),
    ("core.intel_data", "PARKING_NS_MARKERS", "Parking name servers", "Parked-domain detections, campaign correlation"),
    ("core.intel_data", "CDN_CNAME_SUFFIXES", "CDN CNAME targets", "CDN fronting, CNAME Chains (*CDN*)"),
    ("core.intel_data", "CDN_ISP_MARKERS", "CDN networks (ISP names)", "CDN attribution of IPs, origin discovery"),
    ("core.intel_data", "CDN_IP_RANGES", "CDN IP ranges", "CDN attribution of IPs: hosting alerts, DNS & Hosting, IP pivots (CDN IPs are skipped), exports"),
    ("core.intel_data", "LARGE_DNS_PROVIDER_MARKERS", "Large DNS providers",
     "Campaign correlation: shared name servers here do not link domains"),
    ("core.cert_inputs", "SHARED_SAN_SUFFIXES", "Shared certificate names",
     "Certificate inputs: their SANs are never turned into targets"),
    ("core.intel_data", "HOMOGLYPHS", "Homoglyphs", "Lookalike rules"),
    ("core.intel_data", "MULTI_CHAR_HOMOGLYPHS", "Multi-letter homoglyphs", "Lookalike rules"),
]


def _list_values(value):
    if isinstance(value, dict) and all(isinstance(v, (list, tuple)) for v in value.values()):
        return "; ".join(f"{name}: {len(cidrs)} ranges" for name, cidrs in value.items())
    if isinstance(value, dict):
        return ", ".join(f"`{k}` → {v}" for k, v in value.items())
    return ", ".join(f"`{a}` → {b}" if isinstance(item, tuple) else f"`{item}`"
                     for item in value for a, b in [item if isinstance(item, tuple) else (None, None)])


def lists_section():
    blocks = []
    for module, name, title, used_by in LISTS:
        value = getattr(importlib.import_module(module), name)
        path = ROOT / (module.replace(".", "/") + ".py")
        comment = _comments(path).get(name, "")
        count = sum(len(v) for v in value.values()) if isinstance(value, dict) and name == "CDN_IP_RANGES" else len(value)
        blocks.append(f"### {title}\n\n`{name}` in `{path.relative_to(ROOT)}`, {count} entries. {comment.rstrip('.')}."
                      f"\n\n**Used by:** {used_by}\n\n{_list_values(value)}")
    return "\n\n".join(blocks)


SECTIONS = {   # name -> (start marker, end marker, generator); the text between the markers is replaced
    "rules": ("current run.\n\n", "\n\n**Notes**", rules_table),
    "tactics": ("alert counts for the current run.\n\n",
                "\n\nMost domain-infrastructure", tactics_table),
    "thresholds": ("engine on data already collected, with no new API calls.\n\n", "\n\n## Run history", thresholds_table),
    "dif": ("### DIF codes\n\n", "\n\n### Reading a DIF", dif_table),
}


REFERENCE_SECTIONS = {   # the text up to the next heading is replaced
    "use cases": ("Options per use case (generated from `core/use_cases.py`):\n\n", "A dot (·)", use_case_table),
    "limits": ("Limits (generated from `config.py`):\n\n", "## Other built-in values", limits_table),
    "other": ("Values (generated from `config.py` and `core/window.py`):\n\n", "## Built-in lists", other_values_table),
    "lists": ("The lists (generated from the modules named under each one):\n\n", "## Files the app keeps", lists_section),
}
REFERENCE_SECTIONS = {name: (start, end, lambda generate=generate: generate() + "\n\n")
                      for name, (start, end, generate) in REFERENCE_SECTIONS.items()}
GENERATED = {GUIDE: SECTIONS, REFERENCE: REFERENCE_SECTIONS}


def render(text, sections=SECTIONS, path=GUIDE):
    for name, (start, end, generate) in sections.items():
        head, found, rest = text.partition(start)
        _, found_end, tail = rest.partition(end)
        if not (found and found_end):
            raise ValueError(f"Markers for the {name} section not found in {path}")
        text = head + start + generate() + end + tail
    return text


if __name__ == "__main__":
    for path, sections in GENERATED.items():
        path.write_text(render(path.read_text(), sections, path))
        print(f"Updated {path.relative_to(ROOT)}")
