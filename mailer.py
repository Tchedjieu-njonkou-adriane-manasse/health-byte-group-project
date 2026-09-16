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
        "Enter this code in the app to choose a new password.\n\n"
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
        #It Doesn't crash the request if the mail server rejects us; the route
        # falls back to showing us the link on screen.
        return False
