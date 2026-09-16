from functools import wraps
from flask import session, redirect, url_for, flash, g
from database import get_db

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def role_required(role):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                flash("Please log in to continue.", "error")
                return redirect(url_for("login"))
            if g.user["role"] != role:
                flash("You don't have access to that page.", "error")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapped
    return decorator

def next_code(db, table, column, prefix):
    """Generate the next human-friendly code, e.g. HB-PT-0001, HB-PT-0002 ..."""
    row = db.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
    next_number = row["n"] + 1
    return f"{prefix}-{next_number:04d}"
