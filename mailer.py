"""
mailer.py
---------
Sends the "reset your password" email over SMTP. If no mail server is
configured (MAIL_SERVER unset), send_reset_email() returns False instead of
raising, and the caller falls back to showing the reset link directly on
screen -- handy for local development and for anyone who hasn't set up
SMTP credentials yet. See README.md for how to configure a real mail
provider (Gmail app password works well for this).
"""

import smtplib
from email.mime.text import MIMEText


def mail_is_configured(app):
    return bool(app.config.get("MAIL_SERVER") and app.config.get("MAIL_USERNAME"))


def send_reset_email(app, to_email, code):
    if not mail_is_configured(app):
        return False

    subject = "Your HealthByte password reset code"
    body = (
        "We received a request to reset your HealthByte password.\n\n"
        f"Your verification code is: {code}\n\n"
        "Enter this code in the app to create a new password.\n\n"
        "This code will expire in 5 minutes.\n\n"
        "If you didn't request this, you can safely ignore this email."
    )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = app.config["MAIL_DEFAULT_SENDER"]
    msg["To"] = to_email

    try:
        with smtplib.SMTP(app.config["MAIL_SERVER"], app.config["MAIL_PORT"], timeout=10) as server:
            if app.config.get("MAIL_USE_TLS"):
                server.starttls()
            server.login(app.config["MAIL_USERNAME"], app.config["MAIL_PASSWORD"])
            server.sendmail(app.config["MAIL_DEFAULT_SENDER"], [to_email], msg.as_string())
        return True
    except Exception:
        return False

def send_access_request_email(app, to_email, doctor_name, approve_url, deny_url):
    if not mail_is_configured(app):
        return False

    subject = "A doctor is requesting access to your HealthByte record"

    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto;">
      <h2 style="color: #146C43;">HealthByte</h2>
      <p>Dr. {doctor_name} has requested access to your medical record.</p>
      <div style="margin: 24px 0;">
        <a href="{approve_url}" style="background: #146C43; color: #ffffff; padding: 12px 24px;
           border-radius: 6px; text-decoration: none; font-weight: bold; margin-right: 12px; display: inline-block;">
          Approve
        </a>
        <a href="{deny_url}" style="background: #D64545; color: #ffffff; padding: 12px 24px;
           border-radius: 6px; text-decoration: none; font-weight: bold; display: inline-block;">
          Deny
        </a>
      </div>
      <p style="color: #888; font-size: 13px;">
        If you don't recognize this doctor, click Deny or simply ignore this email.
      </p>
    </div>
    """

    msg = MIMEText(html_body, "html")
    msg["Subject"] = subject
    msg["From"] = app.config["MAIL_DEFAULT_SENDER"]
    msg["To"] = to_email

    try:
        with smtplib.SMTP(app.config["MAIL_SERVER"], app.config["MAIL_PORT"], timeout=10) as server:
            if app.config.get("MAIL_USE_TLS"):
                server.starttls()
            server.login(app.config["MAIL_USERNAME"], app.config["MAIL_PASSWORD"])
            server.sendmail(app.config["MAIL_DEFAULT_SENDER"], [to_email], msg.as_string())
        return True
    except Exception:
        return False


def send_access_decision_email(app, to_email, patient_name, decision):
    if not mail_is_configured(app):
        return False

    subject = f"Access request {decision} — HealthByte"
    body = f"Your request to access {patient_name}'s record has been {decision}."

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = app.config["MAIL_DEFAULT_SENDER"]
    msg["To"] = to_email

    try:
        with smtplib.SMTP(app.config["MAIL_SERVER"], app.config["MAIL_PORT"], timeout=10) as server:
            if app.config.get("MAIL_USE_TLS"):
                server.starttls()
            server.login(app.config["MAIL_USERNAME"], app.config["MAIL_PASSWORD"])
            server.sendmail(app.config["MAIL_DEFAULT_SENDER"], [to_email], msg.as_string())
        return True
    except Exception:
        return False
