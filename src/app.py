# src/app.py (Final Integrated Structure with DB, Login, Dashboard, and History)

import os
import json
# Import the model and the global timezone placeholder
from .models import URLLog, User, Base
import pandas as pd # Still useful for pandas operations if needed


import random
import smtplib
from email.message import EmailMessage
from werkzeug.security import generate_password_hash
from .models import User

# Flask Core Imports
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from werkzeug.security import generate_password_hash

# ML/Data Imports
from joblib import load
from .extract_features import extract_features

# Database and Auth Imports
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from flask_login import (
    LoginManager, 
    login_user, 
    logout_user, 
    login_required, 
    current_user, 
    UserMixin
)
# Assuming you have a models.py file with Base, User, and URLLog classes
import pytz
from datetime import datetime, timezone, timedelta # இது ஏற்கனவே இருக்கலாம்

# Asia/Kolkata நேர மண்டல மாறிலியை வரையறுக்கிறோம்
IST_TIMEZONE = pytz.timezone('Asia/Kolkata')

# -------------------------- APPLICATION SETUP --------------------------

# Basic App Configuration
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.environ.get("FLASK_SECRET", "A-SECURE-DEFAULT-SECRET-KEY")
os.makedirs("data", exist_ok=True) # Ensure data folder for SQLite DB exists
os.makedirs("models", exist_ok=True) # Ensure models folder exists

# Database Setup (SQLite)
DB_PATH = "sqlite:///data/app.db"
engine = create_engine(DB_PATH, connect_args={"check_same_thread": False})
Base.metadata.create_all(engine) # Create tables if they don't exist
Session = scoped_session(sessionmaker(bind=engine))

# Flask-Login Setup
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# -------------------------- ML/MODEL LOADING --------------------------
try:
    scaler = load("models/scaler.joblib")
    encoder = load("models/label_encoder.joblib")
    model = load("models/ensemble_model.joblib")
    print("ML Models loaded successfully.")
except FileNotFoundError as e:
    print(f"ERROR: Could not load model component: {e}")
    # Handle the error gracefully if required

# -------------------------- HELPER FUNCTIONS --------------------------
# Helper: User adapter for Flask-Login
class FlaskUser(UserMixin):
    def __init__(self, user_row):
        self.id = user_row.id
        self.username = user_row.username
        self.is_admin = user_row.is_admin
        self.email = user_row.email

@login_manager.user_loader
def load_user(user_id):
    db = Session()
    u = db.query(User).get(int(user_id))
    db.close()
    return FlaskUser(u) if u else None

def compute_safety_score(probs):
    """Calculates safety score and phishing probability from model predictions."""
    phishing_idx = list(encoder.classes_).index("phishing")
    p_phish = float(probs[phishing_idx])
    safety = max(0.0, min(100.0, (1.0 - p_phish) * 100.0))
    return safety, p_phish

def require_admin():
    """Checks if the current logged-in user is an administrator."""
    return current_user.is_authenticated and getattr(current_user, "is_admin", False)

@app.teardown_appcontext
def shutdown_session(exception=None):
    """Remove SQLAlchemy session at the end of the request."""
    Session.remove()

# -------------------------- AUTHENTICATION ROUTES --------------------------

@app.route("/register", methods=["GET","POST"])
def register():
    if current_user.is_authenticated: return redirect(url_for("index")) 
    if request.method == "POST":
        db = Session()
        username = request.form.get("username").strip()
        email = request.form.get("email").strip().lower()
        password = request.form.get("password")
        if db.query(User).filter((User.username==username)|(User.email==email)).first():
            print("Username or email already exists")
            flash("Username or email already exists", "error")
            db.close()
            return redirect(url_for("register"))
        is_first_user = db.query(User).count() == 0
        user = User(username=username, email=email, is_admin=is_first_user)
        user.set_password(password)
        db.add(user); db.commit(); db.close()
        print("Account created. Please login.")
        flash("Account created. Please login.", "success")
        return redirect(url_for("login"))
    return render_template("auth/register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if current_user.is_authenticated: return redirect(url_for("index"))
    if request.method == "POST":
        db = Session()
        identifier = request.form.get("identifier").strip()
        password = request.form.get("password")
        user = db.query(User).filter((User.username==identifier)|(User.email==identifier)).first()
        if user and user.check_password(password):
            login_user(FlaskUser(user))
            db.close()
            flash("Welcome...! ", "success")
            return redirect(url_for("index"))
        print("Invalid credentials")
        flash("Invalid credentials", "error")
        db.close()
    return render_template("auth/login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    print("User logged out.")
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))

def send_otp_email(to_email, otp):
    EMAIL = "srms1161@gmail.com"
    PASSWORD = "hvgmnxvmbqkuqhda"

    msg = EmailMessage()
    msg["Subject"] = "Your Password Reset OTP"
    msg["From"] = EMAIL
    msg["To"] = to_email
    msg.set_content(f"Your OTP for resetting password is: {otp}")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(EMAIL, PASSWORD)
        smtp.send_message(msg)
        
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email")

        db = Session()
        user = db.query(User).filter_by(email=email).first()

        if not user:
            flash("Email not found!", "error")
            db.close()
        else:
            otp = str(random.randint(100000, 999999))
            user.reset_otp = otp
            user.otp_expiry = datetime.now() + timedelta(minutes=5)

            db.commit()
            db.close()

            send_otp_email(email, otp)
            return redirect(url_for("reset_password", email=email))

    return render_template("auth/forgot.html")

@app.route("/reset/<email>", methods=["GET", "POST"])
def reset_password(email):
    db = Session()
    user = db.query(User).filter_by(email=email).first()

    if request.method == "POST":
        otp = request.form.get("otp")
        new_pass = request.form.get("password")

        if not user or user.reset_otp != otp:
            flash("Invalid OTP!","error")
        elif datetime.now() > user.otp_expiry:
            flash("OTP expired!","error")
        else:
            user.password_hash = generate_password_hash(new_pass)
            user.reset_otp = None
            user.otp_expiry = None
            flash("Your Password has been changed!","success")
            db.commit()
            db.close()
            return redirect(url_for("login"))

    db.close()
    return render_template("auth/reset.html",)

# -------------------------- CORE APPLICATION ROUTES --------------------------

@app.route("/", methods=["GET", "POST"])
def index():
    """Main URL scanning page."""
    prediction = None; probability = None; safety_score = None
    
    if request.method == "POST":
        url = request.form.get("url","").strip()
        if url:
            features = extract_features(url)
            # CRITICAL FIX: Ensure feature ordering matches the scaler
            features = features[[f for f in scaler.feature_names_in_ if f in features.columns]] 
            
            scaled = scaler.transform(features)
            pred_enc = int(model.predict(scaled)[0])
            probs = model.predict_proba(scaled)[0]
            prediction = encoder.inverse_transform([pred_enc])[0]
            safety_score, p_phish = compute_safety_score(probs)
            probability = float(p_phish)
            # Save log to DB
            db = Session()
            uid = current_user.id if current_user.is_authenticated else None
            rec = URLLog(user_id=uid, url=url, prediction=prediction,
                        prob_phishing=probability, safety_score=safety_score,
                        features=json.dumps(features.iloc[0].to_dict()))
            db.add(rec); db.commit(); db.close()
    return render_template("index.html",
                        prediction=prediction,
                        probability=probability,
                        safety_score=safety_score)



@app.template_filter('ist_time')
def format_datetime_to_ist(utc_dt):
    if utc_dt is None:
        return ""
    if utc_dt.tzinfo is None:
        utc_dt = utc_dt.replace(tzinfo=timezone.utc)
    ist_dt = utc_dt.astimezone(IST_TIMEZONE)
    return ist_dt.strftime('%b %d, %Y - %I:%M:%S %p IST')
# -------------------------- DASHBOARD AND HISTORY ROUTES --------------------------

@app.route("/dashboard")
@login_required # Only logged-in users can see the dashboard
def dashboard():
    metrics = {}
    metrics_file = "models/ensemble_metrics.json" 
    # 1. Load Metrics from JSON (Site-wide)
    if os.path.exists(metrics_file):
        try:
            with open(metrics_file, 'r') as f:
                metrics = json.load(f)
        except json.JSONDecodeError:
            pass # Ignore if file is empty/corrupt
            
    db = Session()
    
    # 2. Fetch recent scans for the CURRENT USER ONLY (last 10 - this part is correct)
    last_scans = db.query(URLLog)\
                .filter(URLLog.user_id == current_user.id)\
                .order_by(URLLog.timestamp.desc())\
                .limit(10)\
                .all()
    
    # 3. MODIFIED: Fetch data for Safety Series Chart for the CURRENT USER ONLY (last 100 scans)
    # The chart will now display the trend of the logged-in user's activity.
    safety_series_data = db.query(URLLog.timestamp, URLLog.safety_score)\
                        .filter(URLLog.safety_score != None)\
                        .filter(URLLog.user_id == current_user.id) \
                        .order_by(URLLog.timestamp.asc())\
                        .limit(100)\
                        .all()
    
    safety_series = []
    for timestamp, safety_score in safety_series_data:
        if timestamp is not None:
            # Handle timezone: Ensure the timestamp is timezone-aware before isoformat()
            if timestamp.tzinfo is None:
                # Assuming stored timestamps are UTC if not specified
                timestamp = timestamp.replace(tzinfo=timezone.utc)
        
        # Convert to ISO format string for easy parsing by JavaScript
        iso_timestamp = timestamp.isoformat()
        
        safety_series.append({
            "timestamp": iso_timestamp,
            "safety_score": safety_score
        })  
        
    db.close()
    
    return render_template("dashboard.html",
                        metrics=metrics,
                        last_scans=last_scans, 
                        safety_series=safety_series)

@app.route("/history")
@login_required
def history():
    """Shows the current user's full scan history (renamed from /my-logs)."""
    db = Session()
    logs = db.query(URLLog).filter(URLLog.user_id==current_user.id).order_by(URLLog.timestamp.desc()).all()
    db.close()
    return render_template("history.html", logs=logs)

# -------------------------- API ROUTES --------------------------

@app.route("/api/predict", methods=["POST"])
def api_predict():
    """API endpoint for AJAX requests from the frontend."""
    data = request.get_json() or {}
    url = (data.get("url") or "").strip()
    
    if not url:
        return jsonify({"error":"No URL provided"}), 400
    
    try:
        features = extract_features(url)
        features_df = features[[f for f in scaler.feature_names_in_ if f in features.columns]] 
        scaled = scaler.transform(features_df)
        pred_enc = int(model.predict(scaled)[0])
        probs = model.predict_proba(scaled)[0]
        safety_score, p_phish = compute_safety_score(probs)
        
    except Exception as e:
        print(f"Prediction Error: {e}")
        return jsonify({"error": "Prediction failed due to model error."}), 500

    # Save to DB (user-aware)
    db = Session()
    uid = current_user.id if current_user.is_authenticated else None
    rec = URLLog(user_id=uid, url=url, prediction=encoder.inverse_transform([pred_enc])[0],
                prob_phishing=float(p_phish), safety_score=float(safety_score),
                features=json.dumps(features_df.iloc[0].to_dict()))
    db.add(rec); db.commit(); db.close()

    resp = {
        "url": url,
        "prediction": encoder.inverse_transform([pred_enc])[0],
        "prob_phishing": float(p_phish),
        "safety_score": float(safety_score)
    }
    return jsonify(resp)

# -------------------------- ADMIN ROUTES --------------------------

@app.route("/admin/users")
@login_required
def admin_users():
    db = Session()
    users = db.query(User).all()
    db.close()
    return render_template("admin/users.html", users=users)

@app.route("/admin/user/<int:user_id>/logs")
@login_required
def admin_user_logs(user_id):
    db = Session()
    logs = db.query(URLLog).filter(URLLog.user_id==user_id).order_by(URLLog.timestamp.desc()).all()
    user = db.query(User).get(user_id)
    db.close()
    return render_template("admin/user_logs.html", logs=logs, user=user)

# -------------------------- STATIC FILES & RUN --------------------------

@app.route("/static/<path:filename>")
def static_files(filename):
    """Serve static files (CSS, JS, images)."""
    return app.send_static_file(filename) 

if __name__ == "__main__":
    app.run(debug=True)
    






