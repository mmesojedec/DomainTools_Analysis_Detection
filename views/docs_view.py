"""In-app documentation (`?doc=<guide>&topic=<section>`): a topic tree and search over the guides in docs/ on the
left, the selected topic on the right with its Mermaid diagrams drawn."""
import html
import re
from dataclasses import dataclass

import streamlit as st
import streamlit.components.v1 as components

from config import BASE_DIR

DOCS_DIR = BASE_DIR / "docs"
DOCS_PATH = "docs"   # the documentation page's URL path
GUIDES = {   # key -> (title, file); the key is the `?doc=` value, in tree order
    "workflows": ("Workflows", "WORKFLOWS.md"),
    "use-cases": ("Use Cases", "USE_CASES.md"),
    "usage": ("Usage", "USAGE.md"),
    "user-guide": ("User Guide", "USER_GUIDE.md"),
    "reference": ("Reference", "REFERENCE.md"),
    "installation": ("Installation", "INSTALLATION.md"),
}
DOCS_HOME = "workflows"
HIDDEN_TOPICS = {"contents"}   # the tree replaces each guide's table of contents
TREE_DEPTH = 3   # '##' sections and their '###' subsections are topics; deeper headings stay inside them
MERMAID = re.compile(r"```mermaid\n(.*?)```", re.S)
HEADING = re.compile(r"^(#{1,6}) +(.+?) *#*$")
DOC_LINK = re.compile(r"\]\((?:docs/)?([A-Z_]+\.md)?(#[^)\s]*)?\)")
MERMAID_JS = "https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.esm.min.mjs"
TREE_CSS = """<style>   /* topic buttons sit close together, like a file tree */
  [data-testid="stSidebar"] [data-testid="stExpander"] [data-testid="stVerticalBlock"] { gap: 0.15rem; }
  [data-testid="stSidebar"] [data-testid="stExpander"] button { min-height: 0; padding: 0.1rem 0; justify-content: flex-start; }
</style>"""


@dataclass(frozen=True)
class Topic:
    guide: str
    slug: str      # "" for the guide's overview (the text before its first section)
    title: str
    level: int     # 1 overview, 2 section, 3 subsection
    parent: str    # slug of the section a subsection belongs to
    body: str      # markdown from the topic's heading up to the next topic
    anchors: frozenset   # slugs of every heading in the body, so links to deeper headings find their topic


def doc_url(key=DOCS_HOME, topic=""):
    """
    Link that opens the documentation (Streamlit opens markdown links in a new tab). It points at the docs page's own
    path, so it works from every page of the top navigation (a bare `?doc=` would keep the current page's path).
    """
    return f"/{DOCS_PATH}?doc={key}" + (f"&topic={topic}" if topic else "")


def slugify(title):
    """GitHub-style heading anchor, so links written for GitHub find the same topic here."""
    return re.sub(r"[^\w\- ]", "", title.strip().lower()).replace(" ", "-")


def rewrite_links(text, key):
    """Links to a guide or to a heading open that topic in the app; other links are left alone."""
    by_file = {file: guide for guide, (_, file) in GUIDES.items()}

    def swap(match):
        file, anchor = match.group(1), (match.group(2) or "#")[1:]
        guide = by_file.get(file) if file else key
        return f"]({doc_url(guide, anchor)})" if guide and (file or anchor) else match.group(0)
    return DOC_LINK.sub(swap, text)


def parse_guide(key, text):
    """Splits a guide into topics in document order: its overview, then each '##' and '###' heading."""
    lines, headings, fenced = text.splitlines(), [], False
    for number, line in enumerate(lines):
        if line.startswith("```"):
            fenced = not fenced
        elif not fenced and (match := HEADING.match(line)):
            headings.append((number, len(match.group(1)), match.group(2)))
    seen, slugs = {}, []
    for _, _, title in headings:   # repeated headings get -1, -2, ... like on GitHub
        base = slugify(title)
        slugs.append(f"{base}-{seen[base]}" if base in seen else base)
        seen[base] = seen.get(base, 0) + 1
    starts = [(i, number, level) for i, (number, level, _) in enumerate(headings) if level <= TREE_DEPTH]
    topics, parent = [], ""
    for position, (i, number, level) in enumerate(starts):
        end = next((n for _, n, lvl in starts[position + 1:] if lvl <= max(level, 2) or level == 1), len(lines))
        inside = [slugs[j] for j, (n, _, _) in enumerate(headings) if number <= n < end]
        if level == 2:
            parent = slugs[i]
        title = GUIDES[key][0] if level == 1 else headings[i][2]
        topics.append(Topic(key, "" if level == 1 else slugs[i], title, level, parent if level == 3 else "",
                            "\n".join(lines[number:end]).strip(), frozenset(inside)))
    hidden = {t.slug for t in topics if t.slug in HIDDEN_TOPICS} | {t.slug for t in topics if t.parent in HIDDEN_TOPICS}
    return [t for t in topics if t.slug not in hidden]


def load_guides():
    guides = {}
    for key, (_, file) in GUIDES.items():
        path = DOCS_DIR / file
        guides[key] = parse_guide(key, path.read_text(encoding="utf-8")) if path.exists() else []
    return guides


def find_topic(guides, key, slug=""):
    """The topic a link names: its own slug, or the most specific topic holding that heading; else the overview."""
    topics = guides.get(key) or guides.get(DOCS_HOME) or next(iter(guides.values()))
    exact = [t for t in topics if t.slug == slug]
    holding = sorted((t for t in topics if slug in t.anchors), key=lambda t: -t.level)
    return (exact or holding or topics)[0] if topics else None


def count_matches(text, query):
    return text.casefold().count(query.casefold()) if query else 0


def _open(key, slug):
    st.query_params.from_dict({"doc": key, "topic": slug} if slug else {"doc": key})


def _label(topic, branch, hits, current):
    title = "Overview" if topic.level == 1 else re.sub(r"^(\d+)\.", r"\1\\.", topic.title)
    title = f"**{title}**" if topic == current else title
    return f"{branch}{title}" + (f" · {hits}" if hits else "")


def render_tree(guides, current, query):
    """One expander per guide; its topics as a tree, filtered to the ones mentioning the search text."""
    shown = 0
    for key, (title, _) in GUIDES.items():
        topics = [t for t in guides[key] if not query or count_matches(t.body, query)]
        if not topics:
            continue
        shown += 1
        hits = sum(count_matches(t.body, query) for t in topics if t.level < 3)
        with st.sidebar.expander(f"{title} · {hits}" if query else title, expanded=bool(query) or key == current.guide):
            for position, topic in enumerate(topics):
                branch = ""
                if topic.level == 3:
                    following = topics[position + 1] if position + 1 < len(topics) else None
                    branch = "├─ " if following and following.level == 3 else "└─ "
                st.button(_label(topic, branch, count_matches(topic.body, query), current),
                          key=f"topic:{key}:{topic.slug}", type="tertiary", on_click=_open, args=(key, topic.slug))
    if query and not shown:
        st.sidebar.caption(f"No guide mentions “{query}”.")


def split_markdown(text):
    """[("markdown", text) | ("mermaid", source), ...] in document order."""
    parts, pos = [], 0
    for match in MERMAID.finditer(text):
        parts.append(("markdown", text[pos:match.start()]))
        parts.append(("mermaid", match.group(1)))
        pos = match.end()
    parts.append(("markdown", text[pos:]))
    return [(kind, body) for kind, body in parts if body.strip()]


def _diagram_height(source):
    """Starting height; the frame resizes itself to the drawn diagram (this applies when Mermaid cannot load)."""
    lines = [line for line in source.splitlines() if line.strip()]
    decisions = sum(1 for line in lines if "{" in line)
    return min(1600, 80 + 55 * len(lines) + 50 * decisions)


def render_mermaid(source):
    """Draws one diagram with Mermaid from the CDN; without internet access the diagram's text is shown instead."""
    components.html(f"""
        <pre class="mermaid" style="color:#DFE5EF;font-size:12px">{html.escape(source)}</pre>
        <script type="module">
          import mermaid from "{MERMAID_JS}";
          mermaid.initialize({{startOnLoad: false, theme: "dark", flowchart: {{useMaxWidth: true}}}});
          await mermaid.run({{querySelector: ".mermaid"}});
          const fit = () => {{   // the frame is same-origin: grow or shrink it to the drawn diagram
            const svg = document.querySelector(".mermaid svg");
            const frame = window.frameElement;
            if (!svg || !frame) return;
            const height = Math.ceil(svg.getBoundingClientRect().height + 24) + "px";
            frame.style.height = height;
            if (frame.parentElement) {{   // Streamlit's wrapper is sized by flex-basis from the starting height
              frame.parentElement.style.height = height;
              frame.parentElement.style.flexBasis = height;
            }}
          }};
          fit();
          window.addEventListener("resize", fit);
        </script>""", height=_diagram_height(source), scrolling=True)


def _render_neighbours(order, topic):
    position = order.index(topic)
    back, ahead = st.columns(2)
    for column, step, arrow in ((back, -1, "← "), (ahead, 1, "")):
        if 0 <= position + step < len(order):
            other = order[position + step]
            name = f"{GUIDES[other.guide][0]}: Overview" if other.level == 1 else other.title
            column.button(f"{arrow}{name}" + (" →" if step > 0 else ""), key=f"step:{step}", type="tertiary",
                          on_click=_open, args=(other.guide, other.slug))


SHOWN_TOPIC_KEY = "docs_shown_topic"


def scroll_to_top(marker):
    """
    Scrolls the page back to its top. Streamlit keeps the scroll position when a button reruns the page, so a topic
    picked far down a long one would otherwise open in the middle. The frame is same-origin, so it can reach the page;
    `marker` (the topic) makes each frame new, so its script runs again for every topic.
    """
    components.html(f"<!-- {html.escape(marker)} -->" + """<script>
      const page = window.parent.document;
      for (const element of page.querySelectorAll('[data-testid="stMain"], [data-testid="stAppViewContainer"], section.main')) {
        element.scrollTo({top: 0});
      }
      window.parent.scrollTo({top: 0});
    </script>""", height=0)


def render_doc_page(key, slug=""):
    guides = load_guides()
    st.html(TREE_CSS)
    st.sidebar.subheader("Documentation")
    query = st.sidebar.text_input("Search all guides", key="docs_search",
                                  placeholder="e.g. CAA, fast-flux, credentials").strip()
    topic = find_topic(guides, key, slug)
    if topic is None:
        st.error(f"No guides were found in {DOCS_DIR}.")
        return
    render_tree(guides, topic, query)
    shown = (topic.guide, topic.slug)
    if st.session_state.get(SHOWN_TOPIC_KEY) != shown:   # a new topic opens at its beginning
        st.session_state[SHOWN_TOPIC_KEY] = shown
        scroll_to_top(f"{topic.guide}#{topic.slug}")
    parent = next((t for t in guides[topic.guide] if t.slug == topic.parent), None) if topic.parent else None
    st.caption(" › ".join(["Documentation", GUIDES[topic.guide][0]] + ([parent.title] if parent else [])
                          + ([topic.title] if topic.level > 1 else [])))
    if query and (hits := count_matches(topic.body, query)):
        st.caption(f"“{query}” appears {hits} time(s) in this topic.")
    for kind, body in split_markdown(rewrite_links(topic.body, topic.guide)):
        if kind == "mermaid":
            render_mermaid(body)
        else:
            st.markdown(body)
    st.divider()
    _render_neighbours([t for key in GUIDES for t in guides[key]], topic)
