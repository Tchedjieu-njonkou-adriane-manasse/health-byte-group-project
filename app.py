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



@app.route("/")
def index():
    if g.user:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/signup", methods=("GET", "POST"))
def signup():
    if g.user:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        role = request.form.get("role")
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        full_name = request.form.get("full_name", "").strip()

        db = database.get_db()
        error = None

        if role not in ("doctor", "patient"):
            error = "Choose whether you're signing up as a doctor or a patient."
        elif not email or not password or not full_name:
            error = "Email, full name and password are required."
        elif "@" not in email or "." not in email.split("@")[-1]:
            error = "Enter a valid email address."
        elif password != confirm:
            error = "Passwords don't match."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            error = "An account with that email already exists."

        if error is None:
            cursor = db.execute(
                "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
                (email, generate_password_hash(password), role)
            )
            user_id = cursor.lastrowid
            _create_profile_for_new_user(db, user_id, role, full_name, request.form)
            code_col = "patient_code" if role == "patient" else "doctor_code"
            table = "patients" if role == "patient" else "doctors"
            code = db.execute(f"SELECT {code_col} FROM {table} WHERE user_id = ?", (user_id,)).fetchone()[code_col]
            flash(f"Account created! Your {'Patient' if role == 'patient' else 'Doctor'} ID is {code}. Please log in.", "success")
            return redirect(url_for("login"))

        flash(error, "error")

    return render_template("signup.html", google_enabled=google_oauth is not None)


def _create_profile_for_new_user(db, user_id, role, full_name, form):
    """Shared by the normal signup form and the post-Google onboarding form."""
    if role == "patient":
        code = next_code(db, "patients", "patient_code", "HB-PT")
        db.execute(
            """INSERT INTO patients
               (user_id, patient_code, full_name, date_of_birth, sex,
                contact_info, address, blood_group, genotype,
                emergency_contact_name, emergency_contact_phone,
                medical_history, allergies, chronic_conditions)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (user_id, code, full_name,
             form.get("date_of_birth") or None,
             form.get("sex") or None,
             form.get("contact_info") or None,
             form.get("address") or None,
             form.get("blood_group") or None,
             form.get("genotype") or None,
             form.get("emergency_contact_name") or None,
             form.get("emergency_contact_phone") or None,
             form.get("medical_history") or None,
             form.get("allergies") or None,
             form.get("chronic_conditions") or None)
        )
        new_id = db.execute("SELECT id FROM patients WHERE user_id = ?", (user_id,)).fetchone()["id"]
        db.commit()
        blockchain.add_block(
            db, patient_id=new_id, actor_id=user_id, actor_role="patient",
            action_type="CREATE", record_type="patient_profile", record_id=new_id,
            data=dict(form)
        )
    else:
        code = next_code(db, "doctors", "doctor_code", "HB-DR")
        db.execute(
            """INSERT INTO doctors
               (user_id, doctor_code, full_name, specialization, license_number, contact_info)
               VALUES (?,?,?,?,?,?)""",
            (user_id, code, full_name,
             form.get("specialization") or None,
             form.get("license_number") or None,
             form.get("contact_info") or None)
        )
        db.commit()


@app.route("/login", methods=("GET", "POST"))
def login():
    if g.user:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        db = database.get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user is None:
            flash("Incorrect email or password.", "error")
        elif user["password_hash"] is None:
            flash("This account uses Google Sign-In. Use the 'Continue with Google' button below.", "error")
        elif not check_password_hash(user["password_hash"], password):
            flash("Incorrect email or password.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))

    return render_template("login.html", google_enabled=google_oauth is not None)


@app.route("/forgot-password", methods=("GET", "POST"))
def forgot_password():
    if g.user:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        db = database.get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user is not None and user["password_hash"] is not None:
            code = f"{secrets.randbelow(1000000):06d}"
            expires_at = (datetime.utcnow() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
            db.execute(
                "UPDATE users SET reset_token = ?, reset_token_expires_at = ? WHERE id = ?",
                (code, expires_at, user["id"])
            )
            db.commit()

            if mailer.send_reset_email(app, email, code):
                flash(f"We've sent a 6-digit code to {email}. Enter it below.", "success")
            else:
                flash(f"Email sending isn't set up yet, so here's your code directly: {code}", "success")
        else:
            flash("If that email has an account, we've sent a 6-digit code to it. Enter it below.", "success")

        session["reset_email"] = email
        return redirect(url_for("reset_password"))

    return render_template("forgot_password.html")


@app.route("/reset-password", methods=("GET", "POST"))
def reset_password():
    email = session.get("reset_email")
    if not email:
        flash("Please request a reset code first.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        db = database.get_db()
        user = db.execute("SELECT * FROM users WHERE email = ? AND reset_token = ?", (email, code)).fetchone()