#!/usr/bin/env python3
"""loggifi.tasks — A columnar task management app with SQLite backend."""

import sqlite3
import json
import ssl
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

DATA_PATH_BASE_DIR = "/var/lib/loggifi"
os.makedirs(DATA_PATH_BASE_DIR, exist_ok=True)

CERT_PATH_BASE_DIR = "/opt/loggifi/certs/tasks/"
os.makedirs(CERT_PATH_BASE_DIR, exist_ok=True)

DB_PATH   = os.path.join(DATA_PATH_BASE_DIR, "loggifi_tasks.db")
CERT_FILE = os.path.join(CERT_PATH_BASE_DIR, "cert.pem")
KEY_FILE  = os.path.join(CERT_PATH_BASE_DIR, "key.pem")

# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS columns (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                title      TEXT    NOT NULL DEFAULT 'New Column',
                color      TEXT    NOT NULL DEFAULT '#6366f1',
                pos        INTEGER NOT NULL DEFAULT 0,
                collapsed  INTEGER NOT NULL DEFAULT 0,
                col_width  INTEGER NOT NULL DEFAULT 280,
                col_height INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS tasks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                column_id   INTEGER NOT NULL REFERENCES columns(id) ON DELETE CASCADE,
                content     TEXT    NOT NULL DEFAULT '',
                done        INTEGER NOT NULL DEFAULT 0,
                pos         INTEGER NOT NULL DEFAULT 0,
                modified_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );
        """)
        # Migrate: add new columns to existing DBs that pre-date these fields
        for ddl in [
            "ALTER TABLE columns ADD COLUMN collapsed  INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE columns ADD COLUMN col_width  INTEGER NOT NULL DEFAULT 280",
            "ALTER TABLE columns ADD COLUMN col_height INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE tasks   ADD COLUMN modified_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
        ]:
            try:
                conn.execute(ddl)
                conn.commit()
            except Exception:
                pass  # column already exists — fine

        # Back-fill any existing tasks that have no modified_at value
        try:
            conn.execute(
                "UPDATE tasks SET modified_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') "
                "WHERE modified_at IS NULL OR modified_at = ''"
            )
            conn.commit()
        except Exception:
            pass

        cur = conn.execute("SELECT COUNT(*) FROM columns")
        if cur.fetchone()[0] == 0:
            conn.execute("INSERT INTO columns (title, color, pos, collapsed) VALUES ('Tasks', '#6366f1', 0, 0)")
            conn.commit()

# ── API helpers ───────────────────────────────────────────────────────────────

def all_columns():
    with get_db() as conn:
        cols = conn.execute("SELECT * FROM columns ORDER BY pos, id").fetchall()
        result = []
        for c in cols:
            tasks = conn.execute(
                "SELECT * FROM tasks WHERE column_id=? ORDER BY pos, id", (c["id"],)
            ).fetchall()
            result.append({
                "id": c["id"], "title": c["title"],
                "color": c["color"], "pos": c["pos"],
                "collapsed": bool(c["collapsed"]),
                "col_width": c["col_width"] or 280,
                "col_height": c["col_height"] or 0,
                "tasks": [{"id": t["id"], "content": t["content"],
                           "done": bool(t["done"]), "pos": t["pos"],
                           "modified_at": dict(t).get("modified_at", "")} for t in tasks]
            })
        return result

def add_column(title="New Column", color="#6366f1"):
    with get_db() as conn:
        cur = conn.execute("SELECT COALESCE(MAX(pos),0)+1 FROM columns")
        pos = cur.fetchone()[0]
        cur = conn.execute(
            "INSERT INTO columns (title, color, pos, collapsed) VALUES (?,?,?,0)", (title, color, pos)
        )
        conn.commit()
        return conn.execute("SELECT * FROM columns WHERE id=?", (cur.lastrowid,)).fetchone()

def update_column(col_id, title=None, color=None, collapsed=None, col_width=None, col_height=None):
    with get_db() as conn:
        if title is not None:
            conn.execute("UPDATE columns SET title=? WHERE id=?", (title, col_id))
        if color is not None:
            conn.execute("UPDATE columns SET color=? WHERE id=?", (color, col_id))
        if collapsed is not None:
            conn.execute("UPDATE columns SET collapsed=? WHERE id=?", (1 if collapsed else 0, col_id))
        if col_width is not None:
            conn.execute("UPDATE columns SET col_width=? WHERE id=?", (int(col_width), col_id))
        if col_height is not None:
            conn.execute("UPDATE columns SET col_height=? WHERE id=?", (int(col_height), col_id))
        conn.commit()

def delete_column(col_id):
    with get_db() as conn:
        conn.execute("DELETE FROM tasks WHERE column_id=?", (col_id,))
        conn.execute("DELETE FROM columns WHERE id=?", (col_id,))
        conn.commit()

def add_task(column_id, content=""):
    with get_db() as conn:
        cur = conn.execute("SELECT COALESCE(MAX(pos),0)+1 FROM tasks WHERE column_id=?", (column_id,))
        pos = cur.fetchone()[0]
        try:
            cur = conn.execute(
                "INSERT INTO tasks (column_id, content, done, pos, modified_at) VALUES (?,?,0,?,strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
                (column_id, content, pos)
            )
        except sqlite3.OperationalError:
            # modified_at column not yet migrated — insert without it
            cur = conn.execute(
                "INSERT INTO tasks (column_id, content, done, pos) VALUES (?,?,0,?)",
                (column_id, content, pos)
            )
        conn.commit()
        t = dict(conn.execute("SELECT * FROM tasks WHERE id=?", (cur.lastrowid,)).fetchone())
        return {"id": t["id"], "content": t["content"], "done": bool(t["done"]), "pos": t["pos"],
                "modified_at": t.get("modified_at", "")}

def update_task(task_id, content=None, done=None, column_id=None, pos=None):
    with get_db() as conn:
        def set_field(sql_with_ts, sql_without, params):
            try:
                conn.execute(sql_with_ts, params)
            except sqlite3.OperationalError:
                conn.execute(sql_without, params)
        if content is not None:
            set_field(
                "UPDATE tasks SET content=?, modified_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?",
                "UPDATE tasks SET content=? WHERE id=?",
                (content, task_id)
            )
        if done is not None:
            set_field(
                "UPDATE tasks SET done=?, modified_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?",
                "UPDATE tasks SET done=? WHERE id=?",
                (1 if done else 0, task_id)
            )
        if column_id is not None:
            set_field(
                "UPDATE tasks SET column_id=?, modified_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?",
                "UPDATE tasks SET column_id=? WHERE id=?",
                (column_id, task_id)
            )
        if pos is not None:
            conn.execute("UPDATE tasks SET pos=? WHERE id=?", (pos, task_id))
        conn.commit()

def delete_task(task_id):
    with get_db() as conn:
        conn.execute("DELETE FROM tasks WHERE id=?", (task_id,))
        conn.commit()

def reorder_columns(order):
    with get_db() as conn:
        for i, col_id in enumerate(order):
            conn.execute("UPDATE columns SET pos=? WHERE id=?", (i, col_id))
        conn.commit()

# ── Self-signed certificate ───────────────────────────────────────────────────

def ensure_certificates():
    """Generate a self-signed cert+key if not already present. Returns True on success."""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return True
    print("  Generating self-signed TLS certificate…")
    try:
        import subprocess
        result = subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", KEY_FILE, "-out", CERT_FILE,
            "-days", "3650", "-nodes",
            "-subj", "/CN=loggifi.tasks/O=loggifi/C=US",
            "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"
        ], check=True, capture_output=True)
        os.chmod(KEY_FILE, 0o600)
        print("  Certificate created.")
        return True
    except Exception as e:
        print(f"  WARNING: Could not generate certificate via openssl: {e}")
        print("  Falling back to plain HTTP.")
        return False

# ── HTML / Frontend ───────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>loggifi.tasks</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  /* ── DARK theme (default) ── */
  :root {
    --bg: #0d0e12;
    --surface: #15161c;
    --surface2: #1c1d26;
    --border: #2a2b38;
    --text: #e8e9f0;
    --version: #818cf8;
    --muted: #6b6d82;
    --accent: #6366f1;
    --danger: #ef4444;
    --success: #22c55e;
    --radius: 10px;
    --col-width: 280px;
    --col-collapsed-width: 48px;
  }

  /* ── LIGHT theme ── */
  :root.light {
    --bg: #f0f1f7;
    --surface: #ffffff;
    --surface2: #e8eaf2;
    --border: #d0d3e8;
    --text: #1a1b2e;
    --muted: #8487a3;
    --accent: #6366f1;
    --danger: #ef4444;
    --success: #22c55e;
  }

  html, body {
    height: 100%;
    background: var(--bg);
    color: var(--text);
    font-family: 'Syne', sans-serif;
    overflow: hidden;
    transition: background .25s, color .25s;
  }

  /* ── Header ── */
  header {
    display: flex; align-items: center; gap: 12px;
    padding: 0 24px; height: 56px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    position: relative; z-index: 10;
    flex-shrink: 0;
    transition: background .25s, border-color .25s;
  }
  .logo {
    font-size: 1.15rem; font-weight: 800; letter-spacing: -0.5px;
    background: linear-gradient(135deg, #818cf8, #a78bfa);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  }
  .logo span { font-weight: 400; opacity: .6; }
  .logo-meta {
    font-size: .50rem; font-family: 'JetBrains Mono', monospace;
    font-weight: 400; color: var(--version);
    letter-spacing: .04em; line-height: 1;
    margin-top: 0px; margin-left: 60px;
  }
  .logo-wrap {
    display: flex; flex-direction: column; align-items: flex-start; gap: 0;
  }
  header .spacer { flex: 1; }
  .btn-add-col {
    display: flex; align-items: center; gap: 6px;
    background: var(--accent); color: #fff;
    border: none; border-radius: 7px;
    padding: 7px 14px; font-family: inherit; font-size: .8rem; font-weight: 600;
    cursor: pointer; transition: opacity .15s;
  }
  .btn-add-col:hover { opacity: .85; }

  /* ── Theme toggle ── */
  .theme-toggle {
    background: var(--surface2); border: 1px solid var(--border);
    border-radius: 20px; width: 52px; height: 28px;
    cursor: pointer; position: relative;
    transition: background .25s, border-color .25s;
    flex-shrink: 0; display: flex; align-items: center; padding: 0 4px;
  }
  .theme-toggle-thumb {
    width: 20px; height: 20px; border-radius: 50%;
    background: var(--accent); position: absolute; left: 4px;
    transition: transform .25s cubic-bezier(.4,0,.2,1), background .25s;
  }
  :root.light .theme-toggle-thumb { transform: translateX(24px); }
  .theme-toggle-icon {
    position: absolute; font-size: 11px;
    pointer-events: none; transition: opacity .2s;
  }
  .icon-moon { left: 6px; opacity: 1; }
  .icon-sun  { right: 6px; opacity: .4; }
  :root.light .icon-moon { opacity: .4; }
  :root.light .icon-sun  { opacity: 1; }

  /* ── Board ── */
  #board-wrap {
    display: flex; flex-direction: column;
    height: calc(100vh - 56px);
    overflow-y: auto; overflow-x: hidden;
  }
  #board-wrap::-webkit-scrollbar { width: 8px; }
  #board-wrap::-webkit-scrollbar-track { background: var(--bg); }
  #board-wrap::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
  #board {
    display: flex; flex-wrap: wrap; gap: 14px;
    padding: 20px 24px;
    align-items: flex-start; align-content: flex-start;
  }

  /* ── Column (expanded) ── */
  .col {
    flex-shrink: 0;
    width: var(--col-width);
    background: var(--surface);
    border-radius: var(--radius);
    border: 1px solid var(--border);
    display: flex; flex-direction: column;
    max-height: calc(100vh - 120px);
    overflow: hidden;
    position: relative;
    transition: box-shadow .2s, background .25s, border-color .25s;
    cursor: grab;
  }
  .col:hover { box-shadow: 0 0 0 1px var(--border); }
  .col.dragging { opacity: .4; cursor: grabbing; box-shadow: 0 8px 32px rgba(0,0,0,.35); }
  .col.drag-over { box-shadow: 0 0 0 2px var(--accent); }
  .col.resizing { user-select: none; cursor: se-resize; transition: none; }

  /* ── Resize handles ── */
  .resize-e {
    position: absolute; top: 0; right: 0;
    width: 6px; height: 100%;
    cursor: ew-resize; z-index: 5;
    border-radius: 0 var(--radius) var(--radius) 0;
  }
  .resize-e:hover, .col.resizing .resize-e { background: var(--accent); opacity: .5; }
  .resize-s {
    position: absolute; bottom: 0; left: 0;
    width: 100%; height: 6px;
    cursor: ns-resize; z-index: 5;
    border-radius: 0 0 var(--radius) var(--radius);
  }
  .resize-s:hover, .col.resizing-s .resize-s { background: var(--accent); opacity: .5; }
  .resize-se {
    position: absolute; bottom: 0; right: 0;
    width: 14px; height: 14px;
    cursor: se-resize; z-index: 6;
    border-radius: 0 0 var(--radius) 0;
    display: flex; align-items: flex-end; justify-content: flex-end;
    padding: 2px;
    opacity: 0; transition: opacity .15s;
  }
  .col:hover .resize-se { opacity: 1; }
  .resize-se svg { color: var(--muted); }

  /* ── Column (collapsed) ── */
  .col.collapsed {
    width: var(--col-collapsed-width) !important;
    max-height: calc(100vh - 120px) !important;
    cursor: pointer;
    transition: width .3s cubic-bezier(.4,0,.2,1), box-shadow .2s, background .25s, border-color .25s;
  }
  .col.collapsed .col-body,
  .col.collapsed .color-row { display: none; }
  .col.collapsed .resize-e,
  .col.collapsed .resize-s,
  .col.collapsed .resize-se { display: none; }

  /* Collapsed header becomes a vertical strip */
  .col.collapsed .col-header {
    flex-direction: column;
    align-items: center;
    justify-content: flex-start;
    padding: 10px 0 8px;
    gap: 8px;
    height: 100%;
    border-bottom: none;
    border-left: 3px solid var(--col-accent, #6366f1);
    cursor: pointer;
  }
  .col.collapsed .col-count,
  .col.collapsed .col-actions { display: none; }

  /* Rotated title in collapsed state */
  .col.collapsed .col-title-wrap {
    flex: 1; display: flex; align-items: center; justify-content: center;
    overflow: hidden;
  }
  .col.collapsed .col-title {
    writing-mode: vertical-rl;
    text-orientation: mixed;
    transform: rotate(180deg);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-height: 180px;
    pointer-events: none;
    font-size: .82rem;
  }

  /* Chevron flips when collapsed */
  .collapse-btn {
    background: none; border: none; color: var(--muted);
    cursor: pointer; padding: 3px 4px; border-radius: 5px;
    display: flex; align-items: center; justify-content: center;
    transition: color .15s, background .15s, transform .3s;
    flex-shrink: 0;
  }
  .collapse-btn:hover { color: var(--text); background: var(--surface2); }
  .col.collapsed .collapse-btn {
    transform: rotate(180deg);
    margin-top: auto;
    margin-bottom: 2px;
  }

  /* ── Col header (expanded) ── */
  .col-header {
    display: flex; align-items: center; gap: 8px;
    padding: 12px 12px 10px;
    border-bottom: 2px solid var(--col-accent, #6366f1);
    flex-shrink: 0; user-select: none;
  }
  .col-dot {
    width: 10px; height: 10px; border-radius: 50%;
    background: var(--col-accent, #6366f1);
    flex-shrink: 0; cursor: grab;
  }
  .col-title-wrap { flex: 1; min-width: 0; display: flex; align-items: center; }
  .col-title {
    width: 100%; font-size: .9rem; font-weight: 700;
    background: transparent; border: none; color: var(--text);
    font-family: inherit; outline: none; min-width: 0; cursor: text;
  }
  .col-title:focus { background: var(--surface2); border-radius: 4px; padding: 2px 6px; }
  .col-actions { display: flex; gap: 4px; }
  .icon-btn {
    background: none; border: none; color: var(--muted);
    cursor: pointer; padding: 4px; border-radius: 5px;
    display: flex; align-items: center; justify-content: center;
    transition: color .15s, background .15s; font-size: .75rem;
  }
  .icon-btn:hover { color: var(--text); background: var(--surface2); }
  .icon-btn.danger:hover { color: var(--danger); }
  .col-count {
    font-size: .72rem; color: var(--muted); font-weight: 600;
    background: var(--surface2); border-radius: 20px;
    padding: 1px 7px; flex-shrink: 0; transition: background .25s;
  }

  /* ── Color picker ── */
  .color-row {
    display: none; flex-wrap: wrap; gap: 6px;
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    background: var(--surface2); transition: background .25s;
  }
  .color-row.open { display: flex; }
  .color-swatch {
    width: 20px; height: 20px; border-radius: 50%;
    cursor: pointer; border: 2px solid transparent;
    transition: transform .15s, border-color .15s;
  }
  .color-swatch:hover { transform: scale(1.2); }
  .color-swatch.active { border-color: #fff; }
  .color-custom { display: flex; align-items: center; gap: 4px; }
  .color-custom input[type=color] {
    width: 20px; height: 20px; border: none; background: none;
    cursor: pointer; padding: 0;
  }

  /* ── Column body (tasks + add btn) ── */
  .col-body { display: flex; flex-direction: column; flex: 1; overflow: hidden; }

  /* ── Task list ── */
  .task-list { overflow-y: auto; flex: 1; padding: 8px; }
  .task-list::-webkit-scrollbar { width: 5px; }
  .task-list::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

  .task-item {
    display: flex; align-items: flex-start; gap: 8px;
    background: var(--surface2); border-radius: 7px;
    padding: 18px 10px 9px; margin-bottom: 6px;
    border: 1px solid transparent;
    transition: border-color .15s, background .25s; position: relative;
  }
  .task-item:hover { border-color: var(--border); }
  .task-item.done .task-text { text-decoration: line-through; color: var(--muted); }
  .task-check {
    width: 16px; height: 16px; flex-shrink: 0;
    accent-color: var(--col-accent, #6366f1);
    cursor: pointer; margin-top: 2px;
  }
  .task-text {
    flex: 1; font-size: .82rem; font-family: 'JetBrains Mono', monospace;
    font-weight: 400; line-height: 1.5;
    background: transparent; border: none; color: var(--text);
    resize: none; outline: none; min-height: 20px; word-break: break-word;
  }
  .task-del { opacity: 0; transition: opacity .15s; flex-shrink: 0; }
  .task-item:hover .task-del { opacity: 1; }
  .task-save {
    display: none; align-items: center; gap: 4px;
    background: var(--col-accent, #6366f1); color: #fff;
    border: none; border-radius: 5px;
    padding: 3px 9px; font-family: 'Syne', sans-serif; font-size: .72rem;
    font-weight: 600; cursor: pointer; flex-shrink: 0; transition: opacity .15s;
  }
  .task-save:hover { opacity: .85; }
  .task-item.editing .task-save { display: flex; }
  .task-item.editing .task-del  { display: none; }

  /* ── Task modified timestamp ── */
  .task-modified {
    position: absolute; top: 5px; right: 8px;
    font-size: .62rem; font-family: 'JetBrains Mono', monospace;
    color: var(--muted); opacity: .65;
    pointer-events: none; white-space: nowrap;
    line-height: 1;
  }
  .task-item.editing .task-modified { opacity: .3; }

  /* ── Add task btn ── */
  .add-task-btn {
    display: flex; align-items: center; gap: 7px;
    width: 100%; padding: 9px 12px;
    background: none; border: none; border-top: 1px solid var(--border);
    color: var(--muted); font-family: 'Syne', sans-serif; font-size: .82rem;
    font-weight: 600; cursor: pointer; transition: color .15s, background .15s;
    flex-shrink: 0;
  }
  .add-task-btn:hover { color: var(--text); background: var(--surface2); }

  /* ── Empty state ── */
  .empty-state {
    text-align: center; padding: 24px 12px;
    color: var(--muted); font-size: .78rem; line-height: 1.6;
  }
  .empty-icon { font-size: 1.6rem; margin-bottom: 8px; }

  /* ── Toast ── */
  #toast {
    position: fixed; bottom: 28px; left: 50%; transform: translateX(-50%) translateY(20px);
    background: var(--surface); border: 1px solid var(--border);
    color: var(--text); padding: 10px 20px; border-radius: 8px;
    font-size: .82rem; font-weight: 600; opacity: 0;
    transition: opacity .2s, transform .2s; pointer-events: none; z-index: 100;
  }
  #toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }

  /* ── Confirm modal ── */
  #modal-overlay {
    display: none; position: fixed; inset: 0;
    background: rgba(0,0,0,.6); z-index: 200;
    align-items: center; justify-content: center;
  }
  #modal-overlay.open { display: flex; }
  .modal-box {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 12px; padding: 28px 32px; max-width: 360px; width: 90%;
    text-align: center; transition: background .25s;
  }
  .modal-box h3 { font-size: 1rem; font-weight: 700; margin-bottom: 10px; }
  .modal-box p  { font-size: .83rem; color: var(--muted); margin-bottom: 22px; line-height: 1.5; }
  .modal-actions { display: flex; gap: 10px; justify-content: center; }
  .modal-actions button {
    padding: 8px 20px; border-radius: 7px; border: none;
    font-family: inherit; font-size: .85rem; font-weight: 600; cursor: pointer;
  }
  .btn-cancel  { background: var(--surface2); color: var(--text); }
  .btn-confirm { background: var(--danger); color: #fff; }

  svg { display: block; }
</style>
</head>
<body>

<header>
  <div class="logo-wrap">
    <div class="logo">loggifi<span>.tasks</span></div>
    <div class="logo-meta">version: 01.00.13.08</div>
  </div>
  <div class="spacer"></div>
  <button class="theme-toggle" onclick="toggleTheme()" title="Toggle light/dark mode" aria-label="Toggle theme">
    <span class="theme-toggle-icon icon-moon">🌙</span>
    <span class="theme-toggle-icon icon-sun">☀</span>
    <span class="theme-toggle-thumb"></span>
  </button>
  <button class="btn-add-col" onclick="addColumn()">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <path d="M7 1v12M1 7h12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
    </svg>
    Add Column
  </button>
</header>

<div id="board-wrap">
  <div id="board"></div>
</div>

<div id="toast"></div>

<div id="modal-overlay">
  <div class="modal-box">
    <h3 id="modal-title">Delete Column?</h3>
    <p id="modal-body">This will permanently delete the column and all its tasks.</p>
    <div class="modal-actions">
      <button class="btn-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-confirm" id="modal-confirm-btn">Delete</button>
    </div>
  </div>
</div>

<script>
const SWATCHES = [
  '#6366f1','#8b5cf6','#ec4899','#ef4444',
  '#f97316','#eab308','#22c55e','#14b8a6',
  '#06b6d4','#3b82f6','#e2e8f0','#64748b'
];

let state = { columns: [] };
let modalCallback = null;

// ── Theme ─────────────────────────────────────────────────────────────────────

function toggleTheme() {
  const isLight = document.documentElement.classList.toggle('light');
  localStorage.setItem('loggifi-theme', isLight ? 'light' : 'dark');
}
(function initTheme() {
  if (localStorage.getItem('loggifi-theme') === 'light')
    document.documentElement.classList.add('light');
})();

// ── API ───────────────────────────────────────────────────────────────────────

async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const r = await fetch('/api' + path, opts);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

// ── Timestamp cache (localStorage fallback) ───────────────────────────────────

function tsKey(taskId) { return 'loggifi-ts-' + taskId; }

function saveTs(taskId, iso) {
  try { localStorage.setItem(tsKey(taskId), iso); } catch {}
}

function loadTs(taskId) {
  try { return localStorage.getItem(tsKey(taskId)) || ''; } catch { return ''; }
}

function purgeTsCache(allTaskIds) {
  try {
    const keep = new Set(allTaskIds.map(id => tsKey(id)));
    Object.keys(localStorage)
      .filter(k => k.startsWith('loggifi-ts-') && !keep.has(k))
      .forEach(k => localStorage.removeItem(k));
  } catch {}
}

async function loadState() {
  state.columns = await api('GET', '/columns');
  // Merge any cached timestamps for tasks whose server value is missing
  const allIds = [];
  for (const col of state.columns) {
    for (const t of col.tasks) {
      allIds.push(t.id);
      if (!t.modified_at) t.modified_at = loadTs(t.id);
    }
  }
  purgeTsCache(allIds);
  render();
}

// ── Column actions ────────────────────────────────────────────────────────────

async function addColumn() {
  const col = await api('POST', '/columns', { title: 'New Column', color: '#6366f1' });
  state.columns.push({ ...col, tasks: [], collapsed: false, col_width: 280, col_height: 0 });
  render();
  setTimeout(() => {
    const el = document.querySelector(`[data-col-id="${col.id}"] .col-title`);
    if (el) el.select();
  }, 50);
}

async function updateColumnTitle(id, title) {
  await api('PATCH', `/columns/${id}`, { title });
  const c = state.columns.find(c => c.id === id);
  if (c) c.title = title;
  toast('Column renamed');
}

async function updateColumnColor(id, color) {
  await api('PATCH', `/columns/${id}`, { color });
  const c = state.columns.find(c => c.id === id);
  if (c) { c.color = color; render(); }
}

async function toggleCollapse(id) {
  const c = state.columns.find(c => c.id === id);
  if (!c) return;
  c.collapsed = !c.collapsed;
  await api('PATCH', `/columns/${id}`, { collapsed: c.collapsed });
  render();
}

function confirmDeleteColumn(id) {
  const c = state.columns.find(c => c.id === id);
  document.getElementById('modal-title').textContent = 'Delete Column?';
  document.getElementById('modal-body').textContent =
    `"${c.title}" and its ${c.tasks.length} task(s) will be permanently deleted.`;
  document.getElementById('modal-confirm-btn').textContent = 'Delete Column';
  modalCallback = () => deleteColumn(id);
  document.getElementById('modal-overlay').classList.add('open');
}
function closeModal() {
  document.getElementById('modal-overlay').classList.remove('open');
  modalCallback = null;
}
document.getElementById('modal-confirm-btn').onclick = () => {
  if (modalCallback) modalCallback();
  closeModal();
};
document.getElementById('modal-overlay').addEventListener('click', e => {
  if (e.target === document.getElementById('modal-overlay')) closeModal();
});

async function deleteColumn(id) {
  await api('DELETE', `/columns/${id}`);
  state.columns = state.columns.filter(c => c.id !== id);
  render(); toast('Column deleted');
}

// ── Task actions ──────────────────────────────────────────────────────────────

async function addTask(colId) {
  const task = await api('POST', `/columns/${colId}/tasks`, { content: '' });
  if (!task.modified_at) { task.modified_at = new Date().toISOString(); }
  saveTs(task.id, task.modified_at);
  const c = state.columns.find(c => c.id === colId);
  if (c) c.tasks.push(task);
  render();
  setTimeout(() => {
    const el = document.querySelector(`[data-task-id="${task.id}"] .task-text`);
    if (el) el.focus();
  }, 40);
}

async function updateTask(taskId, data) {
  await api('PATCH', `/tasks/${taskId}`, data);
  const now = new Date().toISOString();
  for (const c of state.columns) {
    const t = c.tasks.find(t => t.id === taskId);
    if (t) {
      Object.assign(t, data);
      if (data.content !== undefined || data.done !== undefined || data.column_id !== undefined) {
        t.modified_at = now;
        saveTs(taskId, now);
        const itemEl = document.querySelector(`[data-task-id="${taskId}"]`);
        if (itemEl) {
          const lbl = itemEl.querySelector('.task-modified');
          if (lbl) lbl.textContent = fmtModified(now);
        }
      }
    }
  }
}

async function deleteTask(taskId) {
  await api('DELETE', `/tasks/${taskId}`);
  for (const c of state.columns) { c.tasks = c.tasks.filter(t => t.id !== taskId); }
  render();
}

// ── Column drag-to-reorder ────────────────────────────────────────────────────

let dragSrcId = null;

function initColDrag(colEl, colId) {
  colEl.setAttribute('draggable', 'true');
  colEl.addEventListener('dragstart', e => {
    dragSrcId = colId; colEl.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', String(colId));
  });
  colEl.addEventListener('dragend', () => {
    colEl.classList.remove('dragging');
    document.querySelectorAll('.col.drag-over').forEach(el => el.classList.remove('drag-over'));
  });
  colEl.addEventListener('dragover', e => {
    e.preventDefault(); e.dataTransfer.dropEffect = 'move';
    if (dragSrcId !== colId) colEl.classList.add('drag-over');
  });
  colEl.addEventListener('dragleave', () => colEl.classList.remove('drag-over'));
  colEl.addEventListener('drop', async e => {
    e.preventDefault(); colEl.classList.remove('drag-over');
    if (dragSrcId === null || dragSrcId === colId) return;
    const srcIdx = state.columns.findIndex(c => c.id === dragSrcId);
    const tgtIdx = state.columns.findIndex(c => c.id === colId);
    if (srcIdx === -1 || tgtIdx === -1) return;
    const [moved] = state.columns.splice(srcIdx, 1);
    state.columns.splice(tgtIdx, 0, moved);
    await api('POST', '/columns/reorder', { order: state.columns.map(c => c.id) });
    render(); dragSrcId = null;
  });
  // Don't start drag from interactive children
  colEl.querySelectorAll('input, textarea, button').forEach(el => {
    el.addEventListener('mousedown', e => e.stopPropagation());
  });
}

// ── Column resize ─────────────────────────────────────────────────────────────

const MIN_COL_W = 180;
const MIN_COL_H = 120;

// Debounce helper
function debounce(fn, ms) {
  let t; return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

function initColResize(colEl, colId) {
  const saveSize = debounce(async (w, h) => {
    const c = state.columns.find(c => c.id === colId);
    if (!c) return;
    c.col_width  = w;
    c.col_height = h;
    await api('PATCH', `/columns/${colId}`, { col_width: w, col_height: h });
  }, 400);

  function startResize(e, mode) {
    e.preventDefault();
    e.stopPropagation();
    const startX   = e.clientX;
    const startY   = e.clientY;
    const startW   = colEl.offsetWidth;
    const startH   = colEl.offsetHeight;

    colEl.classList.add('resizing');
    document.body.style.cursor = mode === 'e' ? 'ew-resize' : mode === 's' ? 'ns-resize' : 'se-resize';
    document.body.style.userSelect = 'none';

    function onMove(ev) {
      let newW = startW, newH = startH;
      if (mode === 'e' || mode === 'se') {
        newW = Math.max(MIN_COL_W, startW + (ev.clientX - startX));
        colEl.style.width = newW + 'px';
      }
      if (mode === 's' || mode === 'se') {
        newH = Math.max(MIN_COL_H, startH + (ev.clientY - startY));
        colEl.style.maxHeight = newH + 'px';
      }
      saveSize(
        mode === 's' ? startW : newW,
        mode === 'e' ? startH : newH
      );
    }

    function onUp() {
      colEl.classList.remove('resizing');
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup',   onUp);
    }

    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup',   onUp);
  }

  colEl.querySelector('.resize-e') .addEventListener('mousedown', e => startResize(e, 'e'));
  colEl.querySelector('.resize-s') .addEventListener('mousedown', e => startResize(e, 's'));
  colEl.querySelector('.resize-se').addEventListener('mousedown', e => startResize(e, 'se'));
}

// ── Render ────────────────────────────────────────────────────────────────────

function render() {
  const board = document.getElementById('board');
  board.innerHTML = '';
  for (const col of state.columns) {
    const colEl = buildColumn(col);
    board.appendChild(colEl);
    initColDrag(colEl, col.id);
    initColResize(colEl, col.id);
  }
}

function buildColumn(col) {
  const div = document.createElement('div');
  div.className = 'col' + (col.collapsed ? ' collapsed' : '');
  div.setAttribute('data-col-id', col.id);
  div.style.setProperty('--col-accent', col.color);

  // Apply persisted size (ignored when collapsed via CSS !important)
  if (col.col_width && col.col_width !== 280) div.style.width = col.col_width + 'px';
  if (col.col_height && col.col_height > 0) div.style.maxHeight = col.col_height + 'px';

  // Click collapsed column to expand
  if (col.collapsed) {
    div.addEventListener('click', () => toggleCollapse(col.id));
  }

  // ── Header ──
  const header = document.createElement('div');
  header.className = 'col-header';
  if (!col.collapsed) header.style.borderBottomColor = col.color;

  const dot = document.createElement('div');
  dot.className = 'col-dot';
  dot.style.background = col.color;
  dot.title = 'Drag to reorder';

  const titleWrap = document.createElement('div');
  titleWrap.className = 'col-title-wrap';

  const titleInput = document.createElement('input');
  titleInput.className = 'col-title';
  titleInput.value = col.title;
  titleInput.type = 'text';
  titleInput.spellcheck = false;
  titleInput.readOnly = col.collapsed;
  if (!col.collapsed) {
    titleInput.addEventListener('blur', () => updateColumnTitle(col.id, titleInput.value));
    titleInput.addEventListener('keydown', e => { if (e.key === 'Enter') titleInput.blur(); });
  }
  titleWrap.appendChild(titleInput);

  // Chevron collapse button
  const collapseBtn = document.createElement('button');
  collapseBtn.className = 'collapse-btn';
  collapseBtn.title = col.collapsed ? 'Expand' : 'Collapse';
  collapseBtn.innerHTML = `<svg width="14" height="14" viewBox="0 0 14 14" fill="none">
    <path d="M9 11L5 7l4-4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;
  collapseBtn.addEventListener('click', e => { e.stopPropagation(); toggleCollapse(col.id); });

  if (col.collapsed) {
    header.append(dot, titleWrap, collapseBtn);
  } else {
    const count = document.createElement('span');
    count.className = 'col-count';
    count.textContent = col.tasks.length;

    const colorBtn = document.createElement('button');
    colorBtn.className = 'icon-btn';
    colorBtn.title = 'Pick color';
    colorBtn.innerHTML = `<svg width="14" height="14" viewBox="0 0 14 14"><circle cx="7" cy="7" r="5" fill="${col.color}"/></svg>`;
    colorBtn.addEventListener('click', () => toggleColorRow(col.id));

    const delBtn = document.createElement('button');
    delBtn.className = 'icon-btn danger';
    delBtn.title = 'Delete column';
    delBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M1 1l11 11M12 1L1 12" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>`;
    delBtn.addEventListener('click', () => confirmDeleteColumn(col.id));

    const actions = document.createElement('div');
    actions.className = 'col-actions';
    actions.append(colorBtn, delBtn);

    header.append(dot, titleWrap, count, collapseBtn, actions);
  }

  // ── Color row ──
  const colorRow = document.createElement('div');
  colorRow.className = 'color-row';
  colorRow.id = `color-row-${col.id}`;
  for (const sw of SWATCHES) {
    const s = document.createElement('div');
    s.className = 'color-swatch' + (sw === col.color ? ' active' : '');
    s.style.background = sw; s.title = sw;
    s.addEventListener('click', () => { updateColumnColor(col.id, sw); closeColorRows(); });
    colorRow.appendChild(s);
  }
  const custom = document.createElement('div');
  custom.className = 'color-custom';
  const picker = document.createElement('input');
  picker.type = 'color'; picker.value = col.color; picker.title = 'Custom color';
  picker.addEventListener('input', e => updateColumnColor(col.id, e.target.value));
  custom.appendChild(picker);
  colorRow.appendChild(custom);

  // ── Body (task list + add btn) ──
  const body = document.createElement('div');
  body.className = 'col-body';

  const taskList = document.createElement('div');
  taskList.className = 'task-list';
  if (col.tasks.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.innerHTML = `<div class="empty-icon">📋</div>No tasks yet.<br>Add one below.`;
    taskList.appendChild(empty);
  } else {
    for (const task of col.tasks) taskList.appendChild(buildTask(task, col.color));
  }

  const addBtn = document.createElement('button');
  addBtn.className = 'add-task-btn';
  addBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 12 12" fill="none">
    <path d="M6 1v10M1 6h10" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
  </svg>Add task`;
  addBtn.addEventListener('click', () => addTask(col.id));

  body.append(taskList, addBtn);

  // ── Resize handles ──
  const resizeE  = document.createElement('div'); resizeE.className  = 'resize-e';
  const resizeS  = document.createElement('div'); resizeS.className  = 'resize-s';
  const resizeSE = document.createElement('div'); resizeSE.className = 'resize-se';
  resizeSE.innerHTML = `<svg width="8" height="8" viewBox="0 0 8 8" fill="none">
    <path d="M1 7l6-6M4 7l3-3M7 4l0 3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
  </svg>`;

  div.append(header, colorRow, body, resizeE, resizeS, resizeSE);
  return div;
}

// ── Timestamp formatter ───────────────────────────────────────────────────────

function fmtModified(iso) {
  if (!iso) return '';
  try {
    const d = new Date(iso.endsWith('Z') ? iso : iso + 'Z');
    if (isNaN(d.getTime())) return '';
    const date = d.toLocaleDateString(undefined, { day: '2-digit', month: '2-digit', year: '2-digit' });
    const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false });
    return `${date} ${time}`;
  } catch { return ''; }
}

// Refresh all timestamp labels every 60 s
setInterval(() => {
  document.querySelectorAll('.task-modified').forEach(el => {
    const taskEl = el.closest('[data-task-id]');
    if (!taskEl) return;
    const id = parseInt(taskEl.getAttribute('data-task-id'));
    for (const c of state.columns) {
      const t = c.tasks.find(t => t.id === id);
      if (t && t.modified_at) { el.textContent = fmtModified(t.modified_at); break; }
    }
  });
}, 60000);

function buildTask(task, accentColor) {
  const item = document.createElement('div');
  item.className = 'task-item' + (task.done ? ' done' : '');
  item.setAttribute('data-task-id', task.id);

  // Timestamp label (top-right corner)
  const modLabel = document.createElement('span');
  modLabel.className = 'task-modified';
  modLabel.textContent = fmtModified(task.modified_at);
  item.appendChild(modLabel);

  const check = document.createElement('input');
  check.type = 'checkbox'; check.className = 'task-check';
  check.checked = task.done; check.style.accentColor = accentColor;
  check.addEventListener('change', async () => {
    task.done = check.checked;
    item.classList.toggle('done', task.done);
    await updateTask(task.id, { done: task.done });
  });

  const textarea = document.createElement('textarea');
  textarea.className = 'task-text'; textarea.value = task.content;
  textarea.rows = 1; textarea.placeholder = 'Type a task…';

  // Auto-resize without touching the cursor position
  function autoResize() {
    const selStart = textarea.selectionStart;
    const selEnd   = textarea.selectionEnd;
    textarea.style.height = 'auto';
    textarea.style.height = textarea.scrollHeight + 'px';
    // Restore cursor position after height recalc (Firefox may move it)
    try { textarea.setSelectionRange(selStart, selEnd); } catch {}
  }

  textarea.addEventListener('input', autoResize);

  const saveTask = async () => {
    await updateTask(task.id, { content: textarea.value });
    item.classList.remove('editing'); toast('Task saved');
  };
  textarea.addEventListener('focus', () => item.classList.add('editing'));
  textarea.addEventListener('blur', () => {
    setTimeout(() => {
      if (!item.contains(document.activeElement)) item.classList.remove('editing');
    }, 150);
    updateTask(task.id, { content: textarea.value });
  });
  textarea.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) return;
    if (e.key === 'Enter' && e.shiftKey) {
      e.preventDefault(); textarea.blur();
      const colEl = item.closest('[data-col-id]');
      if (colEl) addTask(parseInt(colEl.getAttribute('data-col-id')));
    }
    if (e.key === 'Backspace' && textarea.value === '') {
      e.preventDefault(); deleteTask(task.id);
    }
  });

  // Initial height — defer so layout is ready, but do NOT move the cursor
  setTimeout(autoResize, 0);

  const saveBtn = document.createElement('button');
  saveBtn.className = 'task-save'; saveBtn.textContent = 'Save';
  saveBtn.addEventListener('mousedown', e => e.preventDefault());
  saveBtn.addEventListener('click', saveTask);

  const delBtn = document.createElement('button');
  delBtn.className = 'icon-btn danger task-del'; delBtn.title = 'Delete task';
  delBtn.innerHTML = `<svg width="11" height="11" viewBox="0 0 11 11" fill="none">
    <path d="M1 1l9 9M10 1L1 10" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
  </svg>`;
  delBtn.addEventListener('click', () => deleteTask(task.id));

  item.append(check, textarea, saveBtn, delBtn);
  return item;
}

// ── Color rows ────────────────────────────────────────────────────────────────

function toggleColorRow(colId) {
  const row = document.getElementById(`color-row-${colId}`);
  const isOpen = row.classList.contains('open');
  closeColorRows();
  if (!isOpen) row.classList.add('open');
}
function closeColorRows() {
  document.querySelectorAll('.color-row.open').forEach(r => r.classList.remove('open'));
}

// ── Toast ─────────────────────────────────────────────────────────────────────

let toastTimer;
function toast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg; el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 2000);
}

// ── Init ──────────────────────────────────────────────────────────────────────
loadState();
</script>
</body>
</html>
"""

# ── HTTP Handler ──────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress default request logging

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", ""):
            body = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path == "/api/columns":
            self.send_json(all_columns())
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        body = self.read_body()

        if parsed.path == "/api/columns":
            col = add_column(body.get("title", "New Column"), body.get("color", "#6366f1"))
            self.send_json({"id": col["id"], "title": col["title"],
                            "color": col["color"], "pos": col["pos"],
                            "collapsed": False}, 201)

        elif parsed.path == "/api/columns/reorder":
            reorder_columns(body.get("order", []))
            self.send_json({"ok": True})

        elif parsed.path.startswith("/api/columns/") and parsed.path.endswith("/tasks"):
            col_id = int(parsed.path.split("/")[3])
            task = add_task(col_id, body.get("content", ""))
            self.send_json(task, 201)
        else:
            self.send_response(404); self.end_headers()

    def do_PATCH(self):
        parsed = urlparse(self.path)
        body = self.read_body()
        parts = parsed.path.strip("/").split("/")

        if len(parts) == 3 and parts[0] == "api" and parts[1] == "columns":
            col_id = int(parts[2])
            update_column(col_id,
                          title=body.get("title"),
                          color=body.get("color"),
                          collapsed=body.get("collapsed"),
                          col_width=body.get("col_width"),
                          col_height=body.get("col_height"))
            self.send_json({"ok": True})

        elif len(parts) == 3 and parts[0] == "api" and parts[1] == "tasks":
            task_id = int(parts[2])
            update_task(task_id, content=body.get("content"),
                        done=body.get("done"), column_id=body.get("column_id"),
                        pos=body.get("pos"))
            self.send_json({"ok": True})
        else:
            self.send_response(404); self.end_headers()

    def do_DELETE(self):
        parsed = urlparse(self.path)
        parts = parsed.path.strip("/").split("/")

        if len(parts) == 3 and parts[0] == "api" and parts[1] == "columns":
            delete_column(int(parts[2])); self.send_json({"ok": True})

        elif len(parts) == 3 and parts[0] == "api" and parts[1] == "tasks":
            delete_task(int(parts[2])); self.send_json({"ok": True})
        else:
            self.send_response(404); self.end_headers()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    init_db()
    port = 8443
    use_tls = ensure_certificates()

    server = HTTPServer(("0.0.0.0", port), Handler)

    if use_tls and os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        proto = "https"
    else:
        proto = "http"

    print(f"\n  loggifi.tasks running at  {proto}://localhost:{port}\n")
    if proto == "https":
        print("  (Self-signed cert — accept the browser security warning on first visit)\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down. Goodbye!\n")


if __name__ == "__main__":
    main()
