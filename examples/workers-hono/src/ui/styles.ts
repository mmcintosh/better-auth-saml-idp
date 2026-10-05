// The example's stylesheet, served as /assets/app.css (same origin, so the pages' CSP needs no
// inline styles). Adapted from the CharDB example's: light and dark, cards, tables, pills, forms.
export const CSS = `:root {
  --bg: #f5f6f8;
  --panel: #ffffff;
  --line: #e3e6eb;
  --line-soft: #eef0f3;
  --text: #1a1d24;
  --muted: #5d6472;
  --accent: #2b5fd9;
  --accent-soft: #e8efff;
  --ok: #067647;
  --ok-soft: #dcfae6;
  --warn: #b54708;
  --warn-soft: #fef0c7;
  --bad: #b42318;
  --bad-soft: #fee4e2;
  --code: #f1f3f6;
  color: var(--text);
  background: var(--bg);
  font: 15px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  color-scheme: light dark;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1115;
    --panel: #171a21;
    --line: #2a2f3a;
    --line-soft: #222733;
    --text: #e6e8ee;
    --muted: #9aa3b2;
    --accent: #7aa2ff;
    --accent-soft: #1d2740;
    --ok: #4ade80;
    --ok-soft: #12301f;
    --warn: #fbbf24;
    --warn-soft: #33260b;
    --bad: #f87171;
    --bad-soft: #3a1414;
    --code: #1f2430;
  }
}

* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); }
h1, h2, h3 { margin: 0; line-height: 1.25; }
h1 { font-size: 1.6rem; font-weight: 650; letter-spacing: -0.01em; }
h2 { font-size: 1.05rem; font-weight: 600; }
h3 { font-size: 0.95rem; font-weight: 600; margin: 1.25rem 0 0.5rem; }
p { margin: 0.4rem 0; }
a { color: var(--accent); }
code { font: 12.5px ui-monospace, SFMono-Regular, Menlo, monospace; background: var(--code); padding: 0.1rem 0.35rem; border-radius: 5px; }
.muted { color: var(--muted); }
.small { font-size: 0.85rem; }
.error { color: var(--bad); }
.right { text-align: right; }
.nowrap { white-space: nowrap; }
.break { word-break: break-all; }

/* Layout */
.layout { display: grid; grid-template-columns: 240px 1fr; min-height: 100vh; }
.sidebar { position: sticky; top: 0; height: 100vh; display: flex; flex-direction: column; gap: 1.5rem; padding: 1.25rem 1rem; border-right: 1px solid var(--line); background: var(--panel); }
.brand { display: flex; gap: 0.65rem; align-items: center; }
.brand strong { display: block; font-size: 0.95rem; }
.brand small { display: block; font-size: 0.75rem; }
.logo { display: grid; place-items: center; width: 34px; height: 34px; border-radius: 9px; background: var(--accent); color: #fff; font-size: 1rem; }
nav { display: grid; gap: 2px; }
nav a { padding: 0.5rem 0.7rem; border-radius: 8px; color: var(--text); text-decoration: none; font-size: 0.93rem; }
nav a:hover { background: var(--line-soft); }
nav a.active { background: var(--accent-soft); color: var(--accent); font-weight: 600; }
.whoami { margin-top: auto; display: grid; gap: 0.35rem; justify-items: start; padding-top: 1rem; border-top: 1px solid var(--line); }
.whoami .email { font-weight: 600; word-break: break-all; }
.content { padding: 2rem 2.5rem 4rem; max-width: 1100px; width: 100%; }
.page-head { margin-bottom: 1.25rem; }
.page-head p { max-width: 62rem; }

/* Cards and tiles */
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 1.1rem 1.25rem; margin: 0 0 1rem; }
.card-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; margin-bottom: 0.75rem; }
.tiles { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 0.75rem; }
.tile { display: grid; gap: 0.3rem; padding: 0.85rem; border: 1px solid var(--line); border-radius: 10px; }
.split { display: grid; grid-template-columns: 300px 1fr; gap: 1rem; align-items: start; }
.notice { padding: 0.85rem 1rem; border-radius: 10px; background: var(--accent-soft); border: 1px solid var(--line); display: grid; gap: 0.5rem; }
.empty { color: var(--muted); padding: 0.75rem 0; }
.steps { margin: 0; padding-left: 1.2rem; display: grid; gap: 0.45rem; }
.warnings { color: var(--warn); margin: 0.5rem 0; padding-left: 1.2rem; }

/* Rows, lists, tables */
.row { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
.row.between { justify-content: space-between; }
.top { margin-top: 0.85rem; }
.stack { display: grid; gap: 0.6rem; }
.list { list-style: none; margin: 0; padding: 0; display: grid; gap: 4px; }
.item { width: 100%; display: grid; text-align: left; gap: 0; padding: 0.55rem 0.7rem; border-radius: 8px; background: transparent; border: 1px solid transparent; color: var(--text); }
.item:hover { background: var(--line-soft); }
.item.active { background: var(--accent-soft); border-color: var(--line); }
.table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
.table th { text-align: left; font-weight: 500; color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.03em; padding: 0.4rem 0.5rem; }
.table td { padding: 0.55rem 0.5rem; border-top: 1px solid var(--line-soft); vertical-align: top; }
.kv { display: grid; gap: 0; margin: 0; }
.kv > div { display: grid; grid-template-columns: 190px 1fr; gap: 1rem; padding: 0.5rem 0; border-top: 1px solid var(--line-soft); }
.kv > div:first-child { border-top: 0; }
.kv dt { color: var(--muted); font-size: 0.88rem; }
.kv dd { margin: 0; min-width: 0; }
.copy { display: inline-flex; gap: 0.4rem; align-items: center; max-width: 100%; }
.copy code { word-break: break-all; }
.note { font-size: 0.82rem; margin-top: 0.25rem; }
.note.bad { color: var(--bad); }
.note.warn { color: var(--warn); }

/* Pills and tabs */
.pill { display: inline-block; font-size: 0.75rem; font-weight: 600; padding: 0.1rem 0.55rem; border-radius: 99px; background: var(--line-soft); color: var(--muted); white-space: nowrap; }
.pill.ok { background: var(--ok-soft); color: var(--ok); }
.pill.warn { background: var(--warn-soft); color: var(--warn); }
.pill.bad { background: var(--bad-soft); color: var(--bad); }
.pill.info { background: var(--accent-soft); color: var(--accent); }
.tabs { display: flex; gap: 0.35rem; flex-wrap: wrap; margin-bottom: 1rem; }
.tab { background: var(--panel); color: var(--text); border: 1px solid var(--line); }
.tab.active { background: var(--accent); color: #fff; border-color: var(--accent); }

/* Forms and buttons */
input, select, textarea { font: inherit; color: var(--text); background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 0.5rem 0.65rem; min-width: 0; }
input:focus, select:focus, textarea:focus { outline: 2px solid var(--accent-soft); border-color: var(--accent); }
textarea.code { width: 100%; min-height: 16rem; font: 12.5px ui-monospace, Menlo, monospace; }
textarea.code.short { min-height: 7rem; }
pre.code { white-space: pre-wrap; font-size: 12px; background: var(--code); padding: 0.75rem; border-radius: 8px; }
.field { display: grid; gap: 0.3rem; margin-bottom: 0.6rem; }
.field > span { font-weight: 600; font-size: 0.88rem; }
.inline { display: flex; gap: 0.6rem; align-items: flex-start; flex-wrap: wrap; }
/* A button beside labelled fields sits on the inputs' line (below the label). */
.inline > button, .inline > .button { margin-top: 1.55rem; }
.inline .field { margin: 0; flex: 1 1 200px; }
.check { display: flex; gap: 0.5rem; align-items: center; margin: 0.6rem 0; }
button, .button { font: inherit; font-weight: 550; font-size: 0.9rem; padding: 0.5rem 0.9rem; border-radius: 8px; border: 1px solid var(--accent); background: var(--accent); color: #fff; cursor: pointer; text-decoration: none; display: inline-block; line-height: 1.3; }
button:disabled, .button.disabled { opacity: 0.5; cursor: default; pointer-events: none; }
button.ghost, .button.ghost { background: transparent; color: var(--text); border-color: var(--line); }
button.ghost:hover, .button.ghost:hover { background: var(--line-soft); }
button.danger { background: transparent; color: var(--bad); border-color: var(--bad-soft); }
button.danger-text { color: var(--bad); }
button.small, .button.small { padding: 0.25rem 0.55rem; font-size: 0.8rem; }
button.link { background: none; border: 0; padding: 0; color: var(--accent); font-weight: 600; }
.try { display: grid; gap: 0.6rem; justify-items: start; margin-top: 0.75rem; }

/* Sign-in */
.auth { min-height: 100vh; display: grid; place-items: center; padding: 1rem; }
.auth-card { width: min(420px, 100%); background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 1.75rem; display: grid; gap: 1.25rem; }
.auth-card h1 { font-size: 1.3rem; }

.toast { position: fixed; bottom: 1.25rem; right: 1.25rem; max-width: 30rem; padding: 0.75rem 1rem; border-radius: 10px; background: var(--ok-soft); color: var(--ok); border: 1px solid var(--line); box-shadow: 0 6px 24px rgb(0 0 0 / 0.12); font-weight: 550; z-index: 10; }
.toast.err { background: var(--bad-soft); color: var(--bad); }

@media (max-width: 860px) {
  .layout { grid-template-columns: 1fr; }
  .sidebar { position: static; height: auto; flex-direction: row; flex-wrap: wrap; align-items: center; }
  nav { display: flex; flex-wrap: wrap; }
  .whoami { margin: 0; border: 0; padding: 0; }
  .content { padding: 1.25rem 1rem 3rem; }
  .split { grid-template-columns: 1fr; }
  .kv > div { grid-template-columns: 1fr; gap: 0.2rem; }
}

/* Server-rendered pages: a nav section label, flash messages, page actions, file links. */
.nav-label { font-size: 0.72rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); padding: 0.75rem 0.7rem 0.25rem; }
.flash { padding: 0.7rem 1rem; border-radius: 10px; margin-bottom: 1rem; border: 1px solid var(--line); }
.flash.ok { background: var(--ok-soft); color: var(--ok); }
.flash.err { background: var(--bad-soft); color: var(--bad); }
.actions { display: flex; gap: 0.4rem; flex-wrap: wrap; justify-content: flex-end; }
.stat { font-size: 1.6rem; font-weight: 650; line-height: 1.1; }
.issues { margin: 0.3rem 0 0; padding-left: 1.1rem; font-size: 0.85rem; }
.issues .bad, .bad { color: var(--bad); }
.issues .warn, .warn { color: var(--warn); }
[hidden] { display: none !important; }
.brand { color: var(--text); text-decoration: none; }
.brand small { color: var(--muted); }
.tile .button, .tile button { justify-self: start; }
.table-wrap { overflow-x: auto; }
.targets-cell { display: grid; gap: 0.25rem; }
.targets-cell .err { font-size: 0.8rem; color: var(--bad); max-width: 28rem; }
`;
