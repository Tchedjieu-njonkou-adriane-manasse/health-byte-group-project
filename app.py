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

        if user is None:
            flash("That code is incorrect. Please check it and try again.", "error")
        else:
            expires_at = datetime.strptime(user["reset_token_expires_at"], "%Y-%m-%d %H:%M:%S")
            if datetime.utcnow() > expires_at:
                flash("That code has expired. Please request a new one.", "error")
                session.pop("reset_email", None)
                return redirect(url_for("forgot_password"))
            elif len(password) < 6:
                flash("Password must be at least 6 characters.", "error")
            elif password != confirm:
                flash("Passwords don't match.", "error")
            else:
                db.execute(
                    "UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires_at = NULL WHERE id = ?",
                    (generate_password_hash(password), user["id"])
                )
                db.commit()
                session.pop("reset_email", None)
                flash("Password updated. Please log in.", "success")
                return redirect(url_for("login"))

    return render_template("reset_password.html", email=email)


@app.route("/login/google")
def login_google():
    if google_oauth is None:
        flash("Google Sign-In isn't configured on this server yet.", "error")
        return redirect(url_for("login"))
    redirect_uri = url_for("google_callback", _external=True)
    return google_oauth.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def google_callback():
    if google_oauth is None:
        flash("Google Sign-In isn't configured on this server yet.", "error")
        return redirect(url_for("login"))

    token = google_oauth.authorize_access_token()
    profile = token.get("userinfo")
    if not profile:
        resp = google_oauth.get("https://www.googleapis.com/oauth2/v3/userinfo", token=token)
        profile = resp.json()

    email = (profile.get("email") or "").strip().lower()
    google_id = profile.get("sub")
    name = profile.get("name", "")

    if not email or not google_id:
        flash("Couldn't get your Google account details. Please try again.", "error")
        return redirect(url_for("login"))

    db = database.get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if user is None:
        session["google_pending"] = {"email": email, "google_id": google_id, "name": name}
        return redirect(url_for("complete_google_signup"))

    if user["google_id"] is None:
        db.execute("UPDATE users SET google_id = ? WHERE id = ?", (google_id, user["id"]))
        db.commit()

    session.clear()
    session["user_id"] = user["id"]
    return redirect(url_for("dashboard"))


@app.route("/signup/complete-google", methods=("GET", "POST"))
def complete_google_signup():
    pending = session.get("google_pending")
    if not pending:
        flash("Please sign in with Google again to continue.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        role = request.form.get("role")
        full_name = request.form.get("full_name", "").strip() or pending["name"]

        if role not in ("doctor", "patient"):
            flash("Choose whether you're signing up as a doctor or a patient.", "error")
        else:
            db = database.get_db()
            cursor = db.execute(
                "INSERT INTO users (email, password_hash, google_id, role) VALUES (?, NULL, ?, ?)",
                (pending["email"], pending["google_id"], role)
            )
            user_id = cursor.lastrowid
            _create_profile_for_new_user(db, user_id, role, full_name, request.form)
            session.pop("google_pending", None)
            session.clear()
            session["user_id"] = user_id
            flash("Account created with Google. Welcome to HealthByte!", "success")
            return redirect(url_for("dashboard"))

    return render_template("complete_google_signup.html", pending=pending)


@app.route("/logout")
def logout():
    session.clear()
    flash("You've been logged out.", "success")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    if g.user["role"] == "patient":
        return redirect(url_for("patient_dashboard"))
    return redirect(url_for("doctor_dashboard"))


@app.route("/patient/dashboard")
@role_required("patient")
def patient_dashboard():
    db = database.get_db()
    patient = g.profile
    consultations = db.execute(
        "SELECT c.*, d.full_name AS doctor_name FROM consultations c "
        "JOIN doctors d ON d.id = c.doctor_id "
        "WHERE c.patient_id = ? ORDER BY c.visit_date DESC", (patient["id"],)
    ).fetchall()
    prescriptions = db.execute(
    "SELECT p.*, d.full_name AS doctor_name, "
    "c.visit_date AS linked_visit_date, c.reason AS linked_reason "
    "FROM prescriptions p "
    "JOIN doctors d ON d.id = p.doctor_id "
    "LEFT JOIN consultations c ON c.id = p.consultation_id "
    "WHERE p.patient_id = ? ORDER BY p.date_prescribed DESC", (patient["id"],)
    ).fetchall()
    labs = db.execute(
        "SELECT l.*, d.full_name AS doctor_name FROM lab_results l "
        "JOIN doctors d ON d.id = l.doctor_id "
        "WHERE l.patient_id = ? ORDER BY l.test_date DESC", (patient["id"],)
    ).fetchall()

    pending_requests = db.execute(
        "SELECT ar.*, d.full_name AS doctor_name, d.specialization, d.doctor_code "
        "FROM access_requests ar JOIN doctors d ON d.id = ar.doctor_id "
        "WHERE ar.patient_id = ? AND ar.status = 'pending' ORDER BY ar.requested_at DESC",
        (patient["id"],)
    ).fetchall()
    approved_doctors = db.execute(
        "SELECT ar.*, d.full_name AS doctor_name, d.specialization, d.doctor_code "
        "FROM access_requests ar JOIN doctors d ON d.id = ar.doctor_id "
        "WHERE ar.patient_id = ? AND ar.status = 'approved' ORDER BY d.full_name",
        (patient["id"],)
    ).fetchall()

    return render_template(
        "patient_dashboard.html", patient=patient,
        consultations=consultations, prescriptions=prescriptions, labs=labs,
        pending_requests=pending_requests, approved_doctors=approved_doctors
    )


@app.route("/patient/access/<int:request_id>/approve", methods=("POST",))
@role_required("patient")
def approve_access(request_id):
    db = database.get_db()
    req = db.execute(
        "SELECT ar.*, u.email AS doctor_email, d.full_name AS doctor_name "
        "FROM access_requests ar "
        "JOIN doctors d ON d.id = ar.doctor_id "
        "JOIN users u ON u.id = d.user_id "
        "WHERE ar.id = ? AND ar.patient_id = ?",
        (request_id, g.profile["id"])
    ).fetchone()
    if req is None:
        flash("Request not found.", "error")
    else:
        db.execute(
            "UPDATE access_requests SET status='approved', responded_at=datetime('now') WHERE id = ?",
            (request_id,)
        )
        db.commit()
        mailer.send_access_decision_email(app, req["doctor_email"], g.profile["full_name"], "approved")
        flash("Access approved.", "success")
    return redirect(url_for("patient_dashboard"))


@app.route("/patient/access/<int:request_id>/deny", methods=("POST",))
@role_required("patient")
def deny_access(request_id):
    db = database.get_db()
    req = db.execute(
        "SELECT ar.*, u.email AS doctor_email, d.full_name AS doctor_name "
        "FROM access_requests ar "
        "JOIN doctors d ON d.id = ar.doctor_id "
        "JOIN users u ON u.id = d.user_id "
        "WHERE ar.id = ? AND ar.patient_id = ?",
        (request_id, g.profile["id"])
    ).fetchone()
    if req is None:
        flash("Request not found.", "error")
    else:
        db.execute(
            "UPDATE access_requests SET status='denied', responded_at=datetime('now') WHERE id = ?",
            (request_id,)
        )
        db.commit()
        mailer.send_access_decision_email(app, req["doctor_email"], g.profile["full_name"], "denied")
        flash("Access denied.", "success")
    return redirect(url_for("patient_dashboard"))

@app.route("/access-requests/<token>/<decision>")
def respond_to_request_via_email(token, decision):
    if decision not in ("approve", "deny"):
        return "Invalid link.", 400

    db = database.get_db()
    req = db.execute("SELECT * FROM access_requests WHERE token = ?", (token,)).fetchone()
    if req is None:
        return "This link is invalid or has already been used.", 404

    new_status = "approved" if decision == "approve" else "denied"
    db.execute(
        "UPDATE access_requests SET status = ?, responded_at = datetime('now'), token = NULL WHERE id = ?",
        (new_status, req["id"])
    )
    db.commit()

    doctor = db.execute(
        "SELECT u.email AS doctor_email, d.full_name AS doctor_name FROM doctors d "
        "JOIN users u ON u.id = d.user_id WHERE d.id = ?", (req["doctor_id"],)
    ).fetchone()
    patient = db.execute("SELECT full_name FROM patients WHERE id = ?", (req["patient_id"],)).fetchone()
    mailer.send_access_decision_email(app, doctor["doctor_email"], patient["full_name"], new_status)

    return render_template("access_decision.html", decision=new_status)


@app.route("/patient/access/<int:request_id>/revoke", methods=("POST",))
@role_required("patient")
def revoke_access(request_id):
    db = database.get_db()
    req = db.execute(
        "SELECT * FROM access_requests WHERE id = ? AND patient_id = ?",
        (request_id, g.profile["id"])
    ).fetchone()
    if req is None:
        flash("Request not found.", "error")
    else:
        db.execute(
            "UPDATE access_requests SET status='revoked', responded_at=datetime('now') WHERE id = ?",
            (request_id,)
        )
        db.commit()
        flash("Access revoked.", "success")
    return redirect(url_for("patient_dashboard"))


@app.route("/patient/profile/edit", methods=("GET", "POST"))
@role_required("patient")
def patient_edit_profile():
    db = database.get_db()
    patient = g.profile

    if request.method == "POST":
        fields = ("full_name", "date_of_birth", "sex", "contact_info", "address",
                  "blood_group", "genotype", "emergency_contact_name",
                  "emergency_contact_phone", "medical_history", "allergies",
                  "chronic_conditions")
        values = {f: (request.form.get(f) or None) for f in fields}

        db.execute(
            """UPDATE patients SET full_name=:full_name, date_of_birth=:date_of_birth,
               sex=:sex, contact_info=:contact_info, address=:address,
               blood_group=:blood_group, genotype=:genotype,
               emergency_contact_name=:emergency_contact_name,
               emergency_contact_phone=:emergency_contact_phone,
               medical_history=:medical_history, allergies=:allergies,
               chronic_conditions=:chronic_conditions
               WHERE id = :id""",
            {**values, "id": patient["id"]}
        )
        db.commit()
        blockchain.add_block(
            db, patient_id=patient["id"], actor_id=g.user["id"], actor_role="patient",
            action_type="UPDATE", record_type="patient_profile", record_id=patient["id"],
            data=values
        )
        flash("Profile updated.", "success")
        return redirect(url_for("patient_dashboard"))

    return render_template("edit_patient.html", patient=patient, for_doctor=False)


@app.route("/doctor/dashboard")
@role_required("doctor")
def doctor_dashboard():
    db = database.get_db()
    query = request.args.get("q", "").strip()
    results = []
    if query:
        like = f"%{query}%"
        rows = db.execute(
            "SELECT * FROM patients WHERE patient_code LIKE ? OR full_name LIKE ? "
            "ORDER BY full_name LIMIT 25",
            (like, like)
        ).fetchall()
        for p in rows:
            results.append({
                "patient": p,
                "access_status": _access_status(db, g.profile["id"], p["id"])
            })

    my_patients = db.execute(
        "SELECT p.* FROM access_requests ar JOIN patients p ON p.id = ar.patient_id "
        "WHERE ar.doctor_id = ? AND ar.status = 'approved' ORDER BY p.full_name",
        (g.profile["id"],)
    ).fetchall()

    recent = db.execute(
        "SELECT l.*, p.full_name, p.patient_code FROM ledger l "
        "JOIN patients p ON p.id = l.patient_id "
        "WHERE l.actor_id = ? ORDER BY l.id DESC LIMIT 8", (g.user["id"],)
    ).fetchall()

    return render_template(
        "doctor_dashboard.html", query=query, results=results,
        recent=recent, my_patients=my_patients
    )


def _get_patient_or_404(patient_code):
    db = database.get_db()
    patient = db.execute(
        "SELECT patients.*, users.email AS email FROM patients "
        "JOIN users ON users.id = patients.user_id "
        "WHERE patient_code = ?", (patient_code,)
    ).fetchone()
    if patient is None:
        flash("Patient not found.", "error")
        return None
    return patient


@app.route("/doctor/patient/<patient_code>/request-access", methods=("POST",))
@role_required("doctor")
def request_access(patient_code):
    db = database.get_db()
    patient = _get_patient_or_404(patient_code)
    if patient is None:
        return redirect(url_for("doctor_dashboard"))

    existing = db.execute(
        "SELECT * FROM access_requests WHERE doctor_id = ? AND patient_id = ?",
        (g.profile["id"], patient["id"])
    ).fetchone()

    if existing is None:
        db.execute(
            "INSERT INTO access_requests (doctor_id, patient_id, status) VALUES (?, ?, 'pending')",
            (g.profile["id"], patient["id"])
        )
        db.commit()
        token = secrets.token_urlsafe(32)
        db.execute("UPDATE access_requests SET token = ? WHERE doctor_id = ? AND patient_id = ?",
                   (token, g.profile["id"], patient["id"]))
        db.commit()
        approve_url = url_for("respond_to_request_via_email", token=token, decision="approve", _external=True)
        deny_url = url_for("respond_to_request_via_email", token=token, decision="deny", _external=True)
        mailer.send_access_request_email(app, patient["email"], g.profile["full_name"], approve_url, deny_url)
        flash(f"Access request sent to {patient['full_name']}.", "success")

    elif existing["status"] in ("denied", "revoked"):
        db.execute(
            "UPDATE access_requests SET status='pending', requested_at=datetime('now'), responded_at=NULL WHERE id = ?",
            (existing["id"],)
        )
        db.commit()
        token = secrets.token_urlsafe(32)
        db.execute("UPDATE access_requests SET token = ? WHERE doctor_id = ? AND patient_id = ?",
                   (token, g.profile["id"], patient["id"]))
        db.commit()
        approve_url = url_for("respond_to_request_via_email", token=token, decision="approve", _external=True)
        deny_url = url_for("respond_to_request_via_email", token=token, decision="deny", _external=True)
        mailer.send_access_request_email(app, patient["email"], g.profile["full_name"], approve_url, deny_url)
        flash(f"Access request sent to {patient['full_name']}.", "success")

    elif existing["status"] == "pending":
        flash("You already have a pending request for this patient.", "error")
    else:
        flash("You already have access to this patient's record.", "success")

    return redirect(url_for("doctor_dashboard", q=request.form.get("q", "")))


@app.route("/doctor/patient/<patient_code>")
@role_required("doctor")
def view_patient(patient_code):
    db = database.get_db()
    patient = _get_patient_or_404(patient_code)
    if patient is None:
        return redirect(url_for("doctor_dashboard"))
    if not _require_patient_access(db, patient):
        return redirect(url_for("doctor_dashboard"))

    consultations = db.execute(
        "SELECT c.*, d.full_name AS doctor_name FROM consultations c "
        "JOIN doctors d ON d.id = c.doctor_id "
        "WHERE c.patient_id = ? ORDER BY c.visit_date DESC", (patient["id"],)
    ).fetchall()
    prescriptions = db.execute(
    "SELECT p.*, d.full_name AS doctor_name, "
    "c.visit_date AS linked_visit_date, c.reason AS linked_reason "
    "FROM prescriptions p "
    "JOIN doctors d ON d.id = p.doctor_id "
    "LEFT JOIN consultations c ON c.id = p.consultation_id "
    "WHERE p.patient_id = ? ORDER BY p.date_prescribed DESC", (patient["id"],)
    ).fetchall()
    labs = db.execute(
        "SELECT l.*, d.full_name AS doctor_name FROM lab_results l "
        "JOIN doctors d ON d.id = l.doctor_id "
        "WHERE l.patient_id = ? ORDER BY l.test_date DESC", (patient["id"],)
    ).fetchall()

    return render_template(
        "patient_records.html", patient=patient,
        consultations=consultations, prescriptions=prescriptions, labs=labs
    )


@app.route("/doctor/patient/<patient_code>/edit", methods=("GET", "POST"))
@role_required("doctor")
def edit_patient(patient_code):
    db = database.get_db()
    patient = _get_patient_or_404(patient_code)
    if patient is None:
        return redirect(url_for("doctor_dashboard"))
    if not _require_patient_access(db, patient):
        return redirect(url_for("doctor_dashboard"))

    if request.method == "POST":

        fields = ("blood_group", "genotype", "medical_history", "allergies",
                  "chronic_conditions")
        values = {f: (request.form.get(f) or None) for f in fields}

        db.execute(
            """UPDATE patients SET blood_group=:blood_group, genotype=:genotype,
               medical_history=:medical_history, allergies=:allergies,
               chronic_conditions=:chronic_conditions
               WHERE id = :id""",
            {**values, "id": patient["id"]}
        )
        db.commit()
        blockchain.add_block(
            db, patient_id=patient["id"], actor_id=g.user["id"], actor_role="doctor",
            action_type="UPDATE", record_type="patient_profile", record_id=patient["id"],
            data=values
        )
        flash("Patient record updated.", "success")
        return redirect(url_for("view_patient", patient_code=patient["patient_code"]))

    return render_template("edit_patient.html", patient=patient, for_doctor=True)


@app.route("/doctor/patient/<patient_code>/consultation/add", methods=("GET", "POST"))
@role_required("doctor")
def add_consultation(patient_code):
    db = database.get_db()
    patient = _get_patient_or_404(patient_code)
    if patient is None:
        return redirect(url_for("doctor_dashboard"))
    if not _require_patient_access(db, patient):
        return redirect(url_for("doctor_dashboard"))

    if request.method == "POST":
        visit_date = request.form.get("visit_date")
        reason = request.form.get("reason")
        diagnosis = request.form.get("diagnosis")
        notes = request.form.get("notes")

        if not visit_date or not reason:
            flash("Visit date and reason are required.", "error")
        else:
            cursor = db.execute(
                """INSERT INTO consultations (patient_id, doctor_id, visit_date, reason, diagnosis, notes)
                   VALUES (?,?,?,?,?,?)""",
                (patient["id"], g.profile["id"], visit_date, reason, diagnosis, notes)
            )
            db.commit()
            record_id = cursor.lastrowid
            blockchain.add_block(
                db, patient_id=patient["id"], actor_id=g.user["id"], actor_role="doctor",
                action_type="CREATE", record_type="consultation", record_id=record_id,
                data={"visit_date": visit_date, "reason": reason, "diagnosis": diagnosis, "notes": notes}
            )
            flash("Consultation added.", "success")
            return redirect(url_for("view_patient", patient_code=patient["patient_code"]))

    return render_template("add_consultation.html", patient=patient)


@app.route("/doctor/patient/<patient_code>/prescription/add", methods=("GET", "POST"))
@role_required("doctor")
def add_prescription(patient_code):
    db = database.get_db()
    patient = _get_patient_or_404(patient_code)
    if patient is None:
        return redirect(url_for("doctor_dashboard"))
    if not _require_patient_access(db, patient):
        return redirect(url_for("doctor_dashboard"))

    consultations = db.execute(
        "SELECT id, visit_date, reason FROM consultations WHERE patient_id = ? ORDER BY visit_date DESC",
        (patient["id"],)
    ).fetchall()

    if request.method == "POST":
        medication = request.form.get("medication")
        date_prescribed = request.form.get("date_prescribed")

        if not medication or not date_prescribed:
            flash("Medication and date are required.", "error")
        else:
            consultation_id = request.form.get("consultation_id") or None
            data = {
                "medication": medication,
                "dosage": request.form.get("dosage"),
                "frequency": request.form.get("frequency"),
                "duration": request.form.get("duration"),
                "instructions": request.form.get("instructions"),
                "date_prescribed": date_prescribed,
            }
            cursor = db.execute(
                """INSERT INTO prescriptions
                   (patient_id, doctor_id, consultation_id, medication, dosage,
                    frequency, duration, instructions, date_prescribed)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (patient["id"], g.profile["id"], consultation_id, data["medication"],
                 data["dosage"], data["frequency"], data["duration"],
                 data["instructions"], data["date_prescribed"])
            )
            db.commit()
            record_id = cursor.lastrowid
            blockchain.add_block(
                db, patient_id=patient["id"], actor_id=g.user["id"], actor_role="doctor",
                action_type="CREATE", record_type="prescription", record_id=record_id, data=data
            )
            flash("Prescription added.", "success")
            return redirect(url_for("view_patient", patient_code=patient["patient_code"]))

    return render_template("add_prescription.html", patient=patient, consultations=consultations)


@app.route("/doctor/patient/<patient_code>/lab/add", methods=("GET", "POST"))
@role_required("doctor")
def add_lab_result(patient_code):
    db = database.get_db()
    patient = _get_patient_or_404(patient_code)
    if patient is None:
        return redirect(url_for("doctor_dashboard"))
    if not _require_patient_access(db, patient):
        return redirect(url_for("doctor_dashboard"))

    if request.method == "POST":
        test_name = request.form.get("test_name")
        test_date = request.form.get("test_date")

        if not test_name or not test_date:
            flash("Test name and date are required.", "error")
        else:
            data = {
                "test_name": test_name,
                "result_value": request.form.get("result_value"),
                "reference_range": request.form.get("reference_range"),
                "lab_notes": request.form.get("lab_notes"),
                "test_date": test_date,
            }
            cursor = db.execute(
                """INSERT INTO lab_results
                   (patient_id, doctor_id, test_name, result_value, reference_range, lab_notes, test_date)
                   VALUES (?,?,?,?,?,?,?)""",
                (patient["id"], g.profile["id"], data["test_name"], data["result_value"],
                 data["reference_range"], data["lab_notes"], data["test_date"])
            )
            db.commit()
            record_id = cursor.lastrowid
            blockchain.add_block(
                db, patient_id=patient["id"], actor_id=g.user["id"], actor_role="doctor",
                action_type="CREATE", record_type="lab_result", record_id=record_id, data=data
            )
            flash("Lab result added.", "success")
            return redirect(url_for("view_patient", patient_code=patient["patient_code"]))

    return render_template("add_lab_result.html", patient=patient)

