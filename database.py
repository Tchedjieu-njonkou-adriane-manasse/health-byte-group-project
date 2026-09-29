import os 
import sqlite3
import click
from flask import current_app, g


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DATABASE"],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db
    

def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,                      -- NULL for Google-only accounts
    google_id TEXT UNIQUE,
    role TEXT NOT NULL CHECK(role IN ('doctor', 'patient')),
    reset_token TEXT,
    reset_token_expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', '+1 hours'))
);
"""