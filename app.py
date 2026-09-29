from flask import Flask, render_template, request, redirect, url_for, flash, g, session
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime, timedelta

import database
import blockchain
import mailer
import config
from auth import login_required, role_required, next_code

app = Flask(__name__)
app.config.from_object(config.Config)
app.secret_key = config.SECRET_KEY
database.init_app(app)

try:
    from authlib.integrations.flask_client import OAuth
    oauth = OAuth(app)
    if app.config.get("GOOGLE_CLIENT_ID") and app.config.get("GOOGLE_CLIENT_SECRET"):
        google_oauth = oauth.register(
            name="google",
            client_id=app.config["GOOGLE_CLIENT_ID"],
            client_secret=app.config["GOOGLE_CLIENT_SECRET"],
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )
    else:
        google_oauth = None
except ImportError:
    google_oauth = None


@app.before_request
def load_logged_in_user():
    user_id = session.get("user_id")
    if user_id is None:
        g.user = None
        g.profile = None
    else:
        db = database.get_db()
        g.user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        g.profile = None
        if g.user:
            if g.user["role"] == "patient":
                g.profile = db.execute(
                    "SELECT * FROM patients WHERE user_id = ?", (g.user["id"],)
                ).fetchone()
            else:
                g.profile = db.execute(
                    "SELECT * FROM doctors WHERE user_id = ?", (g.user["id"],)
                ).fetchone()


@app.context_processor
def inject_user():
    return {"current_user": g.get("user"), "current_profile": g.get("profile")}


def _access_status(db, doctor_id, patient_id):
    """Returns 'pending' / 'approved' / 'denied' / 'revoked' / None."""
    row = db.execute(
        "SELECT status FROM access_requests WHERE doctor_id = ? AND patient_id = ?",
        (doctor_id, patient_id)
    ).fetchone()
    return row["status"] if row else None


def _require_patient_access(db, patient):
    """Call at the top of any doctor route that touches a specific patient's
    record. Returns True if allowed to proceed; flashes a message and
    returns False otherwise."""
    if _access_status(db, g.profile["id"], patient["id"]) != "approved":
        flash("You need this patient's approval before you can view or update their record.", "error")
        return False
    return True