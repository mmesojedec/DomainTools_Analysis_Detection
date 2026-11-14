// IrisQL / CertsQL query editor (views/query_editor.py): CodeMirror 5 with suggestions driven by the field catalog the
// page passes in `data.catalog` (core/query_assist.py). Loaded after the bundled CodeMirror, which sets window.CodeMirror.
const CM = window.CodeMirror;

function indexCatalog(catalog) {
  const fields = new Map();
  for (const field of catalog.fields) {
    const ops = new Map(field.operators.map((op) => [catalog.ignoreCase ? op.name.toUpperCase() : op.name, op]));
    fields.set(catalog.ignoreCase ? field.name.toUpperCase() : field.name, { ...field, ops });
  }
  return { ...catalog, byName: fields, operatorSet: new Set(catalog.operators.map((o) => catalog.ignoreCase ? o.toUpperCase() : o)) };
}

function key(index, word) {
  let name = index.ignoreCase ? word.toUpperCase() : word;
  if (index.fieldPrefix && name.includes(index.fieldPrefix)) name = name.split(index.fieldPrefix).pop();
  return name;
}

const isComment = (text) => /^\s*(#|\/\/)/.test(text);

// What the cursor is on: a field (first word), an operator (second word) or the value (after the operator).
function context(cm) {
  const cur = cm.getCursor();
  const line = cm.getLine(cur.line);
  const before = line.slice(0, cur.ch);
  const after = line.slice(cur.ch);
  if (isComment(before)) return null;
  let m = before.match(/^(\s*)([\w.:]*)$/);
  if (m && !/^[\w.:]/.test(after)) return { stage: "field", word: m[2], from: CM.Pos(cur.line, m[1].length), to: cur };
  m = before.match(/^\s*([\w.:]+)\s+(\w*)$/);
  if (m && !/^\w/.test(after)) return { stage: "operator", field: m[1], word: m[2], from: CM.Pos(cur.line, cur.ch - m[2].length), to: cur };
  m = before.match(/^\s*([\w.:]+)\s+(\w+)\s+(\w*)$/);
  if (m && after.trim() === "") return { stage: "value", field: m[1], operator: m[2], word: m[3], from: CM.Pos(cur.line, cur.ch - m[3].length), to: cur };
  return null;
}

// Prefix matches first, then names that contain what was typed.
function rank(items, word, name, ignoreCase) {
  const typed = ignoreCase ? word.toUpperCase() : word.toLowerCase();
  const norm = (s) => (ignoreCase ? s.toUpperCase() : s.toLowerCase());
  if (!typed) return items;
  const starts = items.filter((i) => norm(name(i)).startsWith(typed));
  const contains = items.filter((i) => !norm(name(i)).startsWith(typed) && norm(name(i)).includes(typed));
  return starts.concat(contains);
}

function render(kind) {
  return (el, _self, item) => {
    const name = document.createElement("span");
    name.className = "dtq-name";
    name.textContent = item.displayText;
    el.appendChild(name);
    if (kind || item.kind) {
      const tag = document.createElement("span");
      tag.className = "dtq-kind";
      tag.textContent = item.kind || kind;
      el.appendChild(tag);
    }
  };
}

function insertValue(cm, from, template) {
  cm.replaceRange(template.text, from, cm.getCursor());
  cm.setCursor(cm.posFromIndex(cm.indexFromPos(from) + template.cursor));   // a template may span lines
}

function reopen(cm) {
  setTimeout(() => cm.showHint({ completeSingle: false }), 0);
}

function hints(cm) {
  const index = cm.state.dtqIndex;
  const ctx = context(cm);
  if (!index || !ctx) return null;
  let list = [];
  if (ctx.stage === "field") {
    const fields = rank([...index.byName.values()], ctx.word, (f) => f.name, index.ignoreCase).map((f) => ({
      text: f.name + " ", displayText: f.name, kind: f.kind, render: render(),
      hint: (cm2, data, item) => { cm2.replaceRange(item.text, data.from, data.to); reopen(cm2); },
    }));
    const lineNo = ctx.from.line;
    const previous = lineNo > 0 ? cm.getLine(lineNo - 1).trim() : "";
    const andItem = { text: "AND", displayText: "AND", kind: "next clause", render: render(),
      hint: (cm2, data) => { cm2.replaceRange("AND\n", data.from, data.to); reopen(cm2); } };
    const canAnd = previous && previous.toUpperCase() !== "AND" && !isComment(previous) && previous !== index.header;
    if (canAnd && "AND".startsWith(ctx.word.toUpperCase())) list.push(andItem);
    list = list.concat(fields);
  } else if (ctx.stage === "operator") {
    const field = index.byName.get(key(index, ctx.field));
    if (!field && ctx.field.toUpperCase() === "AND") return null;
    const ops = field ? [...field.ops.values()] : index.operators.map((name) => ({ name, template: { text: "", cursor: 0 }, values: [] }));
    list = rank(ops, ctx.word, (o) => o.name, index.ignoreCase).map((op) => ({
      text: op.name, displayText: op.name, render: render(),
      hint: (cm2, data) => {
        cm2.replaceRange(op.name + " ", data.from, data.to);
        if (op.values && op.values.length) reopen(cm2);   // a short list of values to pick from
        else if (op.template.text) insertValue(cm2, cm2.getCursor(), op.template);
      },
    }));
  } else {
    const field = index.byName.get(key(index, ctx.field));
    const op = field && field.ops.get(index.ignoreCase ? ctx.operator.toUpperCase() : ctx.operator);
    if (!op) return null;
    if (!op.values.length) return null;   // a value you type: nothing to suggest
    const values = op.values.map((v) => {
      const text = /^(true|false)$/.test(v) ? v : `"${v}"`;
      return { text, template: { text, cursor: text.length } };
    });
    list = rank(values, ctx.word, (v) => v.text, true).map((v) => ({
      text: v.template.text, displayText: v.template.text, kind: field.kind, render: render(),
      hint: (cm2, data) => {
        cm2.replaceRange("", data.from, data.to);
        insertValue(cm2, data.from, v.template);
      },
    }));
  }
  if (!list.length) return null;
  return { list, from: ctx.from, to: ctx.to };
}

// Colours: field / operator known to the catalog, values, AND lines, comments; unknown names once the word is done.
function defineMode(name, index) {
  CM.defineMode(name, () => ({
    startState: () => ({ pos: 0, field: null }),
    token(stream, state) {
      if (stream.sol()) { state.pos = 0; state.field = null; }
      if (stream.eatSpace()) return null;
      if (state.pos === 0 && stream.match(/^(#|\/\/)/)) { stream.skipToEnd(); return "comment"; }
      if (state.pos === 0 && stream.match(/^AND\s*$/i)) return "keyword";
      if (state.pos === 0) {
        const word = stream.match(/^[^\s]+/)[0];
        state.pos = 1;
        state.field = index.byName.get(key(index, word));
        if (state.field) return "variable";
        return stream.eol() ? "variable" : "error";
      }
      if (state.pos === 1) {
        const word = stream.match(/^[^\s]+/)[0];
        state.pos = 2;
        const op = index.ignoreCase ? word.toUpperCase() : word;
        const known = state.field ? state.field.ops.has(op) : index.operatorSet.has(op);
        return known || stream.eol() ? "operator" : "error";
      }
      if (stream.match(/^"(?:[^"\\]|\\.)*"?/)) return "string";
      if (stream.match(/^-?\d+(\.\d+)?/)) return "number";
      if (stream.match(/^(true|false)\b/)) return "atom";
      if (stream.match(/^\(/) || stream.match(/^\)/)) return "bracket";
      stream.next();
      return null;
    },
  }));
}

function setMarks(cm, marks) {
  cm.clearGutter("dtq-marks");
  for (const handle of cm.state.dtqMarked || []) cm.removeLineClass(handle, "background", "dtq-problem");
  cm.state.dtqMarked = [];
  for (const [line, message] of Object.entries(marks || {})) {
    const n = Number(line);
    if (n >= cm.lineCount()) continue;
    const dot = document.createElement("div");
    dot.className = "dtq-mark";
    dot.title = message.replace(/`/g, "");
    dot.textContent = "●";
    cm.setGutterMarker(n, "dtq-marks", dot);
    cm.state.dtqMarked.push(cm.addLineClass(n, "background", "dtq-problem"));
  }
}

// Dark theme: pick the lighter syntax colours; hand the theme colours to the suggestion list (it lives on <body>).
function applyTheme(box) {
  const style = getComputedStyle(box);
  const root = document.documentElement.style;
  const pairs = { text: "color", bg: "background-color" };
  const editorStyle = getComputedStyle(box.querySelector(".CodeMirror") || box);
  for (const [name, prop] of Object.entries(pairs)) root.setProperty(`--dtq-hint-${name}`, editorStyle.getPropertyValue(prop));
  root.setProperty("--dtq-hint-border", style.getPropertyValue("--dtq-border"));
  root.setProperty("--dtq-hint-accent", style.getPropertyValue("--dtq-accent"));
  root.setProperty("--dtq-hint-font", editorStyle.getPropertyValue("font-family"));
  const rgb = (editorStyle.getPropertyValue("background-color").match(/\d+(\.\d+)?/g) || [255, 255, 255]).map(Number);
  box.classList.toggle("dtq-dark", 0.299 * rgb[0] + 0.587 * rgb[1] + 0.114 * rgb[2] < 128);
}

export default function (component) {
  const { data, parentElement, setTriggerValue } = component;
  let box = parentElement.querySelector(".dtq-editor");
  if (!box) {
    box = document.createElement("div");
    box.className = "dtq-editor";
    parentElement.appendChild(box);
  }
  let cm = box.dtqEditor;
  if (!cm) {
    cm = CM(box, {
      value: data.value || "", lineNumbers: true, lineWrapping: true, gutters: ["dtq-marks", "CodeMirror-linenumbers"],
      extraKeys: {
        "Ctrl-Space": (c) => c.showHint({ completeSingle: false }),
        "Ctrl-Enter": (c) => commit(c), "Cmd-Enter": (c) => commit(c),
        Tab: (c) => {   // inside the closing quotes / brackets of a value: jump past them
          const cur = c.getCursor(), rest = c.getLine(cur.line).slice(cur.ch);
          if (rest && /^["\]\s,]*$/.test(rest)) c.setCursor(cur.line, cur.ch + rest.length);
          else c.execCommand("insertSoftTab");
        },
      },
      hintOptions: { hint: hints, completeSingle: false, closeCharacters: /[\s()\[\]{};>,"]/ },
    });
    box.dtqEditor = cm;
    cm.state.dtqCommitted = data.value || "";
    cm.state.dtqRevision = data.revision;
    const commit = (c) => {
      const text = c.getValue();
      if (text === c.state.dtqCommitted) return;
      c.state.dtqCommitted = text;
      c.state.dtqSend(text);
    };
    box.dtqCommit = commit;
    cm.on("blur", (c) => { if (!c.state.completionActive) commit(c); });
    cm.on("change", (c, change) => { if (change.origin !== "setValue") setMarks(c, {}); });
    cm.on("inputRead", (c, change) => {
      if (c.state.completionActive || change.origin === "paste") return;
      const typed = change.text.join("");
      if (/^[\w.: ]+$/.test(typed) && context(c)) c.showHint({ completeSingle: false });
    });
    cm.on("keyup", (c, event) => {
      if (event.key === "Enter" && !c.state.completionActive && context(c)) c.showHint({ completeSingle: false });
    });
  }
  cm.state.dtqSend = (text) => setTriggerValue("commit", text);
  if (cm.state.dtqLanguage !== data.catalog.language) {
    cm.state.dtqLanguage = data.catalog.language;
    cm.state.dtqIndex = indexCatalog(data.catalog);
    const mode = `dtq-${data.catalog.language}`;
    defineMode(mode, cm.state.dtqIndex);
    cm.setOption("mode", mode);
  }
  if (data.revision !== cm.state.dtqRevision) {   // the page replaced the query (an example): take it over the typed text
    cm.state.dtqRevision = data.revision;
    cm.state.dtqCommitted = data.value || "";
    cm.setValue(data.value || "");
  }
  box.style.setProperty("--dtq-height", `${data.height || 170}px`);
  applyTheme(box);
  cm.refresh();
  setMarks(cm, data.marks);
}
