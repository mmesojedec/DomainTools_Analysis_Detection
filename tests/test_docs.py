import re
from pathlib import Path

from config import THRESHOLD_SPECS
from core.risk_profile import DIF_SEGMENTS
from core.rule_catalog import RULE_CATALOG
from integrations.credentials import DOMAINTOOLS_ENV_PAIRS

ROOT = Path(__file__).resolve().parent.parent
DOCS = {path.name: path.read_text() for path in [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]}


def anchor(heading):
    """GitHub-style heading anchor."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def test_user_guide_lists_every_rule_threshold_and_dif_code():
    guide = DOCS["USER_GUIDE.md"]
    for threat_type, (_, mitre, _, _) in RULE_CATALOG.items():
        assert f"| {threat_type} |" in guide, threat_type
        assert mitre.split(" ")[0] in guide, mitre
    for spec in THRESHOLD_SPECS:
        assert f"| {spec.label} |" in guide, spec.label
    for _, _, code, _, _ in DIF_SEGMENTS:
        assert f"`{code}`" in guide, code


def test_installation_guide_lists_every_credential_variable():
    install = DOCS["INSTALLATION.md"]
    names = [name for pair in DOMAINTOOLS_ENV_PAIRS for name in pair] + ["DNSDB_API_KEY", "DT_CERT_API_KEY", "DT_CREDENTIALS_FILE"]
    for name in names:
        assert f"`{name}`" in install, name


def test_internal_links_resolve():
    anchors = {name: {anchor(h) for h in re.findall(r"^#+ (.+)$", text, re.M)} for name, text in DOCS.items()}
    for name, text in DOCS.items():
        for target in re.findall(r"\]\(([^)\s]+)\)", text):
            if target.startswith("http"):
                continue
            path, _, fragment = target.partition("#")
            doc = Path(path).name if path else name
            if path and not path.endswith(".md"):
                assert (ROOT / path).exists() or (ROOT / "docs" / path).exists(), (name, target)
                continue
            assert doc in DOCS, (name, target)
            if fragment:
                assert fragment in anchors[doc], (name, target)


def test_thresholds_are_grouped_by_data_source():
    sections = [spec.section for spec in THRESHOLD_SPECS]
    order = list(dict.fromkeys(sections))
    assert order == ["DomainTools Risk", "Passive DNS & Domain History", "Iris Investigate & Domain Name", "Certificate API"]
    assert sections == sorted(sections, key=order.index)   # each section is contiguous in the sidebar


def test_generated_tables_are_current():
    import importlib.util
    spec = importlib.util.spec_from_file_location("generate_docs_tables", ROOT / "scripts" / "generate_docs_tables.py")
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    for path, sections in generator.GENERATED.items():
        text = path.read_text()
        assert generator.render(text, sections, path) == text, f"{path.name}: run python scripts/generate_docs_tables.py"
