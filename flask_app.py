import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
from datetime import datetime, timedelta, time
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import case
from werkzeug.security import generate_password_hash, check_password_hash

# WebAuthn for Face ID / Biometric support
import webauthn # This line was likely 'from webauthn import webauthn' which caused the error
from webauthn.helpers.structs import RegistrationCredential, AuthenticationCredential, AuthenticatorSelectionCriteria, UserVerificationRequirement, PublicKeyCredentialDescriptor, PublicKeyCredentialType
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, options_to_json

# Initialize the Flask application
app = Flask(__name__)

# --- Database Configuration ---
# Get the absolute path for the database file
basedir = os.path.abspath(os.path.dirname(__file__))
# Set the database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'todo.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# A secret key is required to use sessions, which we need for PIN authentication.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-super-secret-key-you-should-change')

# Initialize the database with the app
db = SQLAlchemy(app)

# --- WebAuthn (Face ID) Configuration ---
# These will be set dynamically per request to handle both 'localhost' and '127.0.0.1'
RP_ID = None
RP_NAME = 'My Notebook'
ORIGIN = None

# --- Database Models ---
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    reminder_at = db.Column(db.DateTime, nullable=True) # New column for reminders
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Todo {self.id}>'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    todos = db.relationship('Todo', backref='author', lazy=True, cascade="all, delete-orphan")
    webauthn_credentials = db.relationship('WebAuthnCredential', backref='user', lazy=True, cascade="all, delete-orphan")

class WebAuthnCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    credential_id = db.Column(db.LargeBinary, nullable=False, unique=True)
    public_key = db.Column(db.LargeBinary, nullable=False)
    sign_count = db.Column(db.Integer, nullable=False, default=0)
    transports = db.Column(db.String(255), nullable=True)

# --- Create the database ---
# This ensures the database tables are created based on your models
with app.app_context():
    db.create_all()

# --- Routes ---

@app.route("/login", methods=["GET", "POST"])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            flash("Invalid email or password. Please try again.")
            return redirect(url_for('login'))

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        
        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists.")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully! Please log in.")
        return redirect(url_for('login'))

    return render_template("register.html")

@app.route("/logout")
def logout():
    session.pop('user_id', None) # Clear the user from the session
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route("/settings")
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = db.get_or_404(User, session['user_id'])
    return render_template("settings.html", credentials=user.webauthn_credentials)

@app.route("/webauthn/register/begin", methods=["POST"])
def webauthn_register_begin():
    if 'user_id' not in session:
        return jsonify({"error": "Not authenticated"}), 401

    user = db.get_or_404(User, session['user_id'])

    # Dynamically set RP_ID and ORIGIN based on the request for robustness
    # This handles cases where the user accesses via `localhost` or `127.0.0.1`
    RP_ID = request.host.split(':')[0]
    ORIGIN = f"https://{request.host}"

    # Find existing credentials to prevent re-registration of the same authenticator
    exclude_credentials = [
        {"id": cred.credential_id, "type": "public-key"} for cred in user.webauthn_credentials
    ]

    registration_options = webauthn.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=str(user.id).encode("utf-8"), # The library expects bytes, not a base64url string
        user_name=user.email,
        exclude_credentials=exclude_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED
        )
    )

    # Store the challenge in the session to verify it later
    session['webauthn_challenge'] = bytes_to_base64url(registration_options.challenge)
    
    # The options_to_json helper correctly serializes the options object to a JSON response.
    json_response = options_to_json(registration_options)
    return Response(json_response, mimetype="application/json")

@app.route("/webauthn/register/complete", methods=["POST"])
def webauthn_register_complete():
    if 'user_id' not in session:
        return jsonify({"error": "Not authenticated"}), 401

    user = db.get_or_404(User, session['user_id'])
    challenge_from_session = session.get('webauthn_challenge')

    # Dynamically set RP_ID and ORIGIN to match the registration context
    # This must be consistent between the /begin and /complete steps.
    RP_ID = request.host.split(':')[0]
    ORIGIN = f"https://{request.host}"

    try:
        # A simple helper class to allow attribute access on a dictionary
        class DictObject:
            def __init__(self, d):
                self.__dict__ = d

        body = request.get_json()

        # The library expects a nested `response` object that allows attribute access.
        # We create a dictionary with the required byte-decoded fields...
        response_dict = {
            "client_data_json": base64url_to_bytes(body["response"]["client_data_json"]),
            "attestation_object": base64url_to_bytes(body["response"]["attestation_object"]),
        }
        # ...and then wrap it in our helper class.
        credential = RegistrationCredential(
            id=body["id"],
            raw_id=base64url_to_bytes(body["raw_id"]),
            type=body["type"],
            response=DictObject(response_dict),
        )
        # The transports are part of the response from the client
        transports = body["response"].get("transports", [])

        # The core of WebAuthn: verify that the credential is valid and was created for our site.
        verification = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge_from_session),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            require_user_verification=True
        )

        # Store the new, verified credential in the database, associated with the current user.
        new_credential = WebAuthnCredential(
            user_id=user.id,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            transports=",".join(transports or []),
        )
        db.session.add(new_credential)
        db.session.commit()

        session.pop('webauthn_challenge', None) # Clean up challenge
        return jsonify({"success": True, "message": "Device registered successfully!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Registration failed: {e}"}), 400

@app.route("/webauthn/login/begin", methods=["POST"])
def webauthn_login_begin():
    # Dynamically set RP_ID for this request
    RP_ID = request.host.split(':')[0]

    # Find all possible credentials for this user session.
    # In a real app, you might ask for an email first to narrow this down.
    # For simplicity, we'll allow any registered credential.
    all_credentials = WebAuthnCredential.query.all()
    if not all_credentials:
        return jsonify({"error": "No biometric credentials registered in the system."}), 404

    allow_credentials = [PublicKeyCredentialDescriptor(id=cred.credential_id, type=PublicKeyCredentialType.PUBLIC_KEY) for cred in all_credentials]

    auth_options = webauthn.generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    session['webauthn_challenge'] = bytes_to_base64url(auth_options.challenge)

    json_response = options_to_json(auth_options)
    return Response(json_response, mimetype="application/json")

@app.route("/webauthn/login/complete", methods=["POST"])
def webauthn_login_complete():
    challenge_from_session = session.get('webauthn_challenge')
    RP_ID = request.host.split(':')[0]
    ORIGIN = f"https://{request.host}"

    try:
        # A simple helper class to allow attribute access on a dictionary
        class DictObject:
            def __init__(self, d):
                self.__dict__ = d

        body = request.get_json()
        credential_id = base64url_to_bytes(body["raw_id"])

        # Find the credential in the database
        db_credential = WebAuthnCredential.query.filter_by(credential_id=credential_id).first()
        if not db_credential:
            return jsonify({"success": False, "message": "This device is not registered."}), 400

        # The library expects a nested `response` object that allows attribute access.
        response_dict = {
            "client_data_json": base64url_to_bytes(body["response"]["client_data_json"]),
            "authenticator_data": base64url_to_bytes(body["response"]["authenticator_data"]),
            "signature": base64url_to_bytes(body["response"]["signature"]),
            "user_handle": base64url_to_bytes(body["response"]["user_handle"]) if body["response"]["user_handle"] else None,
        }
        auth_credential = AuthenticationCredential(
            id=body["id"],
            raw_id=credential_id,
            type=body["type"],
            response=DictObject(response_dict),
        )

        verification = webauthn.verify_authentication_response(
            credential=auth_credential,
            expected_challenge=base64url_to_bytes(challenge_from_session),
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=db_credential.public_key,
            credential_current_sign_count=db_credential.sign_count,
            require_user_verification=True,
        )

        # Update the sign count in the database
        db_credential.sign_count = verification.new_sign_count
        db.session.commit()

        # Log the user in
        session['user_id'] = db_credential.user_id
        session.pop('webauthn_challenge', None)

        return jsonify({"success": True, "redirect_url": url_for('index')})

    except Exception as e:
        return jsonify({"success": False, "message": f"Authentication failed: {e}"}), 400

@app.route("/", methods=["GET", "POST"])
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == "POST":
        todo_content = request.form.get("content")
        reminder_due = request.form.get("reminder_due")

        if todo_content:
            reminder_datetime = None
            if reminder_due:
                today = datetime.utcnow().date()
                reminder_time = time(8, 0) # 08:00 AM UTC
                
                if reminder_due == "today":
                    reminder_date = today
                elif reminder_due == "tomorrow":
                    reminder_date = today + timedelta(days=1)
                elif reminder_due == "week":
                    reminder_date = today + timedelta(weeks=1)
                elif reminder_due == "month":
                    # A simple approximation for a month
                    reminder_date = today + timedelta(days=30)
                else:
                    reminder_date = None
                
                if reminder_date:
                    reminder_datetime = datetime.combine(reminder_date, reminder_time)

            new_todo = Todo(content=todo_content, reminder_at=reminder_datetime, user_id=session['user_id'])
            db.session.add(new_todo)
            db.session.commit()
        else:
            flash("Task content cannot be empty.")
        return redirect(url_for("index"))

    # Sort by completion status, then by reminder date (nulls last), then by creation order
    todos = Todo.query.filter_by(user_id=session['user_id']).order_by(Todo.completed, db.nullslast(Todo.reminder_at.asc()), Todo.created_at.desc()).all()
    return render_template("index.html", todos=todos, now=datetime.utcnow())

@app.route("/complete/<int:todo_id>")
def complete(todo_id):
    """
    Toggles the completed status of a task.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))

    todo_to_complete = db.get_or_404(Todo, todo_id)
    if todo_to_complete.user_id != session['user_id']:
        return "Unauthorized", 403 # Prevent users from completing others' tasks
    todo_to_complete.completed = not todo_to_complete.completed
    db.session.commit()
    return redirect(url_for("index"))