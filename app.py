import hashlib
import logging
import os
import re
import secrets
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from crypto_utils import encrypt_text, decrypt_text

app = Flask(__name__)

secret_key = os.environ.get("FLASK_SECRET_KEY")

if not secret_key:
    if os.environ.get("RENDER"):
        raise RuntimeError("FLASK_SECRET_KEY must be set in production.")
    secret_key = secrets.token_hex(32)

app.config["SECRET_KEY"] = secret_key

csrf = CSRFProtect(app)

database_url = os.environ.get("DATABASE_URL")

if database_url:
    if database_url.startswith("postgres://"):
        database_url = database_url.replace(
            "postgres://",
            "postgresql+psycopg://",
            1
        )
    elif database_url.startswith("postgresql://"):
        database_url = database_url.replace(
            "postgresql://",
            "postgresql+psycopg://",
            1
        )

    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

security_logger = logging.getLogger("security_events")
security_logger.setLevel(logging.INFO)
security_logger.propagate = False

if not security_logger.handlers:
    handler = logging.FileHandler("security_events.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    security_logger.addHandler(handler)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class SecureNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class CapabilityCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    scope = db.Column(db.String(40), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)


@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return redirect(url_for("register"))

        if len(username) > 80 or len(password) < 8:
            flash("Username must be at most 80 characters; password must be at least 8 characters.", "error")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("That username is already registered.", "error")
            return redirect(url_for("register"))

        user = User(
            username=username,
            password_hash=generate_password_hash(password),
        )
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            return redirect(url_for("dashboard"))

        security_logger.info("LOGIN_FAILURE")
        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        flash("Please log in first.", "error")
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session.get("username"))


@app.route("/secure-data", methods=["GET", "POST"])
def secure_data():
    if not session.get("user_id"):
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        content = request.form.get("content", "").strip()

        if not content:
            flash("Please enter some information.", "error")
        elif len(content) > 5000:
            flash("Information must be 5000 characters or fewer.", "error")
        else:
            note = SecureNote(
                user_id=session["user_id"],
                encrypted_content=encrypt_text(content),
            )
            db.session.add(note)
            db.session.commit()
            flash("Sensitive information saved in encrypted form.", "success")
            return redirect(url_for("secure_data"))

    notes = SecureNote.query.filter_by(
        user_id=session["user_id"]
    ).order_by(SecureNote.id.desc()).all()

    for note in notes:
        try:
            note.display_content = decrypt_text(note.encrypted_content)
        except Exception:
            note.display_content = "[Unable to decrypt: check encryption key or data integrity]"

    return render_template("secure_data.html", notes=notes)


@app.route("/security-test", methods=["GET", "POST"])
def security_test():
    if not session.get("user_id"):
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    result = None
    test_input = ""

    if request.method == "POST":
        test_input = request.form.get("test_input", "")[:500]
        patterns = [
            r"\bunion\s+select\b",
            r"\b(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
            r"(--|/\*|\*/)",
            r";\s*(drop|delete|insert|update|alter)\b",
        ]
        suspicious = any(
            re.search(pattern, test_input, re.IGNORECASE)
            for pattern in patterns
        )

        if suspicious:
            security_logger.warning(
                "SQL_INJECTION_PATTERN_DETECTED user_id=%s",
                session.get("user_id"),
            )
            result = (
                "Potentially suspicious SQL injection pattern detected. "
                "This is a warning, not proof of an attack."
            )
        else:
            result = (
                "No known suspicious pattern detected. "
                "This does not guarantee the input is safe."
            )

    return render_template(
        "security_test.html",
        result=result,
        test_input=test_input,
    )


@app.route("/capability", methods=["GET", "POST"])
def capability():
    message = None
    one_time_code = None

    if request.method == "POST":
        action = request.form.get("action", "").strip()

        if action == "generate":
            if "user_id" not in session:
                flash("Please log in before generating a capability code.")
                return redirect(url_for("login"))

            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

            record = CapabilityCode(
                token_hash=token_hash,
                user_id=session["user_id"],
                scope="create_note",
                expires_at=datetime.utcnow() + timedelta(minutes=10),
            )
            db.session.add(record)
            db.session.commit()

            one_time_code = token
            message = "Code created. Copy it now; it will not be shown again."

        elif action == "redeem":
            token = request.form.get("token", "").strip()
            content = request.form.get("content", "").strip()

            if not token or not content:
                message = "Enter both the capability code and the information."
            elif len(content) > 5000:
                message = "Information must be 5000 characters or fewer."
            else:
                now = datetime.utcnow()
                token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

                record = CapabilityCode.query.filter_by(
                    token_hash=token_hash,
                    scope="create_note",
                    used_at=None,
                ).filter(CapabilityCode.expires_at > now).first()

                if record is None:
                    message = "Invalid, expired, or already-used capability code."
                else:
                    # Claim the code only if it remains unused and unexpired.
                    claimed = CapabilityCode.query.filter_by(
                        id=record.id,
                        used_at=None,
                    ).filter(
                        CapabilityCode.expires_at > now
                    ).update(
                        {"used_at": now},
                        synchronize_session=False,
                    )

                    if claimed != 1:
                        db.session.rollback()
                        message = "This code is no longer available."
                    else:
                        db.session.add(SecureNote(
                            user_id=record.user_id,
                            encrypted_content=encrypt_text(content),
                        ))
                        db.session.commit()
                        message = "Success: encrypted information saved for the code owner."

        else:
            message = "Unknown action."

    return render_template(
        "capability.html",
        message=message,
        one_time_code=one_time_code,
    )


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=False)
