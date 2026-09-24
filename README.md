# HealthByte

HealthByte is a digital medical record platform where each patient keeps **one lifelong record** instead of scattered paper files at every hospital they visit. Doctors can search for any patient, but a record only becomes visible once the patient explicitly approves that doctor's access — and can revoke it at any time.

Built as a team course project. This repository covers the full-stack app; the doctor dashboard module was built by Ramson.

## Key Features

- **Consent-based access control** — a doctor must request access to a patient's record; the patient approves, denies, or revokes it from their own dashboard. No record is visible without explicit consent.
- **Tamper-evident ledger** — every create/update action (a new consultation, an edited profile) is hashed with SHA-256 and linked to the previous hash, forming a blockchain-style chain. The **Verify Integrity** page re-walks the chain and flags any record altered outside the app.
- **Role-based dashboards** — separate views and permissions for doctors and patients. Doctors can only edit clinical fields (diagnosis, allergies, history) — never a patient's identity or contact details.
- **Flexible authentication** — sign up and log in with email/password, or with **Google OAuth** for one-click sign-in.
- **Email-based password reset** — a random 6-digit code is generated, emailed via Gmail SMTP, and expires after 05 minutes.
- **Admin tools** — a single admin account (set via `ADMIN_EMAIL`) can view site-wide visit stats (`/stats`) and every registered user (`/admin/users`); invisible to everyone else.

## Tech Stack

- **Backend:** Python, Flask
- **Database:** SQLite
- **Frontend:** Server-rendered HTML with Jinja2, plain CSS (no frontend framework)
- **Auth:** Werkzeug password hashing, Authlib for Google OAuth
- **Email:** Gmail SMTP via Python's `smtplib`

## Project Structure

| File | Purpose |
|---|---|
| `app.py` | Flask routes — signup, login, dashboards, consent requests, admin pages |
| `database.py` | Database schema (`SCHEMA`) and connection helpers (`get_db`, `init_db`) |
| `blockchain.py` | Hash-chain logic for the tamper-evident ledger |
| `auth.py` | Login/role-required decorators and ID-generation helpers (e.g. `HB-PT-0001`) |
| `mailer.py` | Sends password reset codes via Gmail SMTP |
| `config.py` | App configuration — database path, mail settings, admin email, secret key |
| `templates/` | Jinja2 HTML templates for every page |
| `static/css/` | Stylesheet — forest green (`#146C43`) and white design system, IBM Plex Sans/Mono |

## Setup

1. **Clone the repository and create a virtual environment**
   ```bash
   git clone <repo-url>
   cd healthbyte
   python -m venv venv
   venv\Scripts\activate      # Windows
   source venv/bin/activate   # macOS/Linux
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**

   Copy `.env.example` to `.env` and fill in your own values:
   ```
   SECRET_KEY=
   GOOGLE_CLIENT_ID=
   GOOGLE_CLIENT_SECRET=
   MAIL_SERVER=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USE_TLS=true
   MAIL_USERNAME=
   MAIL_PASSWORD=
   MAIL_DEFAULT_SENDER=
   ```
   - Google OAuth and email settings are optional — the app degrades gracefully (hides the Google button, shows the reset code on-screen) if left unset.
   - For Gmail, use an **App Password**, not your regular password (requires 2-Step Verification enabled on the Google account).

4. **Initialize the database**
   ```bash
   flask --app app init-db
   ```
   This creates a fresh SQLite database with all required tables. Re-run this command any time the database file is deleted or missing.

5. **Run the app**
   ```bash
   python app.py
   ```
   Visit `http://127.0.0.1:5000` in your browser.

## Notes

- The Flask development server (`python app.py`) is for local testing only — not intended for production traffic.
- `.env` is excluded from version control; never commit real credentials. Only `.env.example` (placeholder values) is tracked.

## Setting up password reset emails (optional)

Without this set up, "Forgot password?" still works — it just shows the
reset link directly on screen instead of emailing it, which is fine for
testing on your own machine.

To actually send real emails, the easiest option is a free Gmail account:

1. Turn on 2-Step Verification on the Gmail account you want to send from
   (**Google Account → Security → 2-Step Verification**).
2. Go to **Google Account → Security → App passwords**, create one (name it
   anything, e.g. "HealthByte"), and copy the 16-character password it gives you.
   (Regular Gmail passwords don't work for this — it has to be an App Password.)
3. Add these to your `.env` file:
   ```
   MAIL_SERVER=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USE_TLS=true
   MAIL_USERNAME=youraddress@gmail.com
   MAIL_PASSWORD=your-16-character-app-password
   MAIL_DEFAULT_SENDER=youraddress@gmail.com
   ```
4. Restart the app. "Forgot password?" will now actually email the reset code or link.

Any other SMTP provider (Outlook, a school/work email, SendGrid, etc.) works
the same way — just swap in that provider's SMTP server, port, and credentials.

## Setting up Google Sign-In (optional)

"Continue with Google" needs your own free OAuth credentials — Anthropic/Claude
can't generate these for you since they're tied to your own Google account.

1. Go to [Google Cloud Console](https://console.cloud.google.com/) and create
   a new project (or use an existing one).
2. Go to **APIs & Services → OAuth consent screen**. Choose "External", fill
   in an app name and your email, and save (you can leave it in "Testing"
   mode — just add your own Google account under "Test users").
3. Go to **APIs & Services → Credentials → Create Credentials → OAuth client ID**.
   - Application type: **Web application**
   - Authorized redirect URIs: add exactly
     ```
     http://127.0.0.1:5000/auth/google/callback
     ```
4. Copy the generated **Client ID** and **Client Secret** into your `.env` file:
   ```
   GOOGLE_CLIENT_ID=your-client-id-here
   GOOGLE_CLIENT_SECRET=your-client-secret-here
   ```
5. Restart the app (`python app.py`). The "Continue with Google" button will
   now appear on the login and signup pages.

The first time someone signs in with a new Google account, they'll land on a
short one-time screen to choose Doctor or Patient and fill in the rest of
their profile — after that, it's one-click sign-in.
