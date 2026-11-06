from views.docs_view import (
    DOCS_DIR,
    GUIDES,
    count_matches,
    doc_url,
    find_topic,
    load_guides,
    parse_guide,
    rewrite_links,
    slugify,
    split_markdown,
)

GUIDE = """# Usage

Intro text.

## Contents

- [Running](#running-an-analysis)

## Running an analysis

Run it.

### 1. Lookups

Look things up.

#### Lookup Queries

Copy queries.

```bash
# not a heading
```

### 2. Analysis Window

Pick a window.

## Troubleshooting

Fix it. Run it again.
"""


def test_every_guide_file_exists():
    for key, (_, file) in GUIDES.items():
        assert (DOCS_DIR / file).exists(), key


def test_links_open_topics_in_the_app():
    text = ("See [Usage](USAGE.md#certificate-inputs), [guide](USER_GUIDE.md), [readme](docs/WORKFLOWS.md), "
            "[cases](USE_CASES.md), [site](https://example.com/USAGE.md), [code](app.py) and [here](#contents).")
    assert rewrite_links(text, "usage") == (
        "See [Usage](/docs?doc=usage&topic=certificate-inputs), [guide](/docs?doc=user-guide), [readme](/docs?doc=workflows), "
        "[cases](/docs?doc=use-cases), [site](https://example.com/USAGE.md), [code](app.py) and "
        "[here](/docs?doc=usage&topic=contents).")
    assert doc_url() == "/docs?doc=workflows"


def test_slugs_match_github_anchors():
    assert slugify("Step 0: reading the target box") == "step-0-reading-the-target-box"
    assert slugify("MITRE ATT&CK mapping") == "mitre-attck-mapping"
    assert slugify("Monitoring, re-use and sharing") == "monitoring-re-use-and-sharing"


def test_a_guide_splits_into_a_topic_tree():
    topics = parse_guide("usage", GUIDE)
    assert [(t.slug, t.level, t.parent) for t in topics] == [
        ("", 1, ""), ("running-an-analysis", 2, ""), ("1-lookups", 3, "running-an-analysis"),
        ("2-analysis-window", 3, "running-an-analysis"), ("troubleshooting", 2, "")]   # Contents is left out
    overview, section, lookups = topics[:3]
    assert overview.title == "Usage" and overview.body == "# Usage\n\nIntro text."
    assert "### 2. Analysis Window" in section.body and "## Troubleshooting" not in section.body
    assert "#### Lookup Queries" in lookups.body and "# not a heading" in lookups.body
    assert "2. Analysis Window" not in lookups.body


def test_links_to_deeper_headings_find_their_topic():
    guides = {"usage": parse_guide("usage", GUIDE)}
    assert find_topic(guides, "usage", "lookup-queries").slug == "1-lookups"
    assert find_topic(guides, "usage", "troubleshooting").slug == "troubleshooting"
    assert find_topic(guides, "usage", "missing").level == 1
    assert find_topic(guides, "unknown").guide == "usage"


def test_search_counts_case_insensitive_matches():
    troubleshooting = parse_guide("usage", GUIDE)[-1]
    assert count_matches(troubleshooting.body, "it") == 2 and count_matches(troubleshooting.body, "RUN") == 1
    assert count_matches(troubleshooting.body, "") == 0


def test_mermaid_blocks_are_split_out_in_order():
    parts = split_markdown("# Title\n\n```mermaid\nflowchart TD\n  A --> B\n```\n\nAfter.\n")
    assert [kind for kind, _ in parts] == ["markdown", "mermaid", "markdown"]
    assert parts[1][1] == "flowchart TD\n  A --> B\n"


def test_real_guides_keep_every_section_and_diagram():
    guides = load_guides()
    workflow = "\n".join(t.body for t in guides["workflows"] if t.level < 3)
    assert sum(1 for kind, _ in split_markdown(workflow) if kind == "mermaid") == 8   # VPNDB logic and IrisQL search added
    assert [t.title for t in guides["use-cases"] if t.level == 2] == [
        "Triage and threat hunting", "Certificates and attack surface", "Infrastructure and hosting",
        "Monitoring, re-use and sharing"]
    for key, topics in guides.items():
        assert len({t.slug for t in topics}) == len(topics), key
