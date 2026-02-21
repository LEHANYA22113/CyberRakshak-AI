import os
import qrcode
import socket
import base64
import json
import random
import re
import joblib
import numpy as np
import pandas as pd
import cv2
import tempfile
import string
import io
import hashlib
from io import BytesIO
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from fpdf import FPDF
from sqlalchemy import text   # <-- IMPORT ADDED

# ==================== CONFIGURATION FLAGS ====================
FORCE_MOCK_DEEPFAKE = True
FORCE_MOCK_PHISHING = True
FORCE_MOCK_URL_PHISHING = True
# ==============================================================

# ---------- TENSORFLOW / KERAS (with fallback) ----------
try:
    import tensorflow as tf
    from tensorflow.keras.preprocessing import image
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    print("⚠ TensorFlow not installed. Deepfake detection will use mock predictions.")

# ---------- OPENCV (for video processing) ----------
try:
    import cv2
    OPENCV_AVAILABLE = True
except ImportError:
    OPENCV_AVAILABLE = False
    print("⚠ OpenCV not installed. Video analysis will use mock predictions.")

app = Flask(__name__)

# ---------- CONFIGURATION ----------
app.config['SECRET_KEY'] = 'cyberrakshak_secret_key_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cyberrakshak.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'rvlehanya@gmail.com'
app.config['MAIL_PASSWORD'] = 'vllz dxmt xhju okot'
app.config['MAIL_DEFAULT_SENDER'] = 'rvlehanya@gmail.com'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# ---------- DATABASE MODELS ----------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    analyses = db.relationship('Analysis', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    analysis_type = db.Column(db.String(20))
    input_data = db.Column(db.Text)
    result = db.Column(db.String(50))
    confidence = db.Column(db.Float)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

# ========== THREAT TRACKING MODELS ==========
class ThreatSource(db.Model):
    __tablename__ = 'threat_sources'
    id = db.Column(db.Integer, primary_key=True)
    fingerprint = db.Column(db.String(128), unique=True, index=True)
    fingerprint_id = db.Column(db.String(32), unique=True, index=True)
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    visit_count = db.Column(db.Integer, default=1)
    threat_count = db.Column(db.Integer, default=0)
    threat_types = db.Column(db.Text, default='[]')
    risk_score = db.Column(db.Float, default=0.0)
    is_blocked = db.Column(db.Boolean, default=False)
    country = db.Column(db.String(100), default='Unknown')
    device_info = db.Column(db.Text, default='{}')

    def calculate_risk_score(self):
        base_score = min(self.threat_count * 10, 70)
        if self.first_seen and self.last_seen:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            days_active = max(1, (now - self.first_seen).days + 1)
            frequency = self.visit_count / days_active
            frequency_bonus = min(frequency * 5, 30)
        else:
            frequency_bonus = 0
        self.risk_score = min(base_score + frequency_bonus, 100)
        return self.risk_score

class NCRPReport(db.Model):
    __tablename__ = 'ncrp_reports'
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.String(50), unique=True, index=True)
    threat_source_id = db.Column(db.Integer, db.ForeignKey('threat_sources.id'))
    analysis_id = db.Column(db.Integer, db.ForeignKey('analysis.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    threat_type = db.Column(db.String(50))
    threat_details = db.Column(db.Text)
    evidence = db.Column(db.Text)
    risk_score = db.Column(db.Float)
    status = db.Column(db.String(20), default='FILED')
    filed_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    resolved_at = db.Column(db.DateTime, nullable=True)
    ncrp_case_id = db.Column(db.String(50), nullable=True)
    ncrp_response = db.Column(db.Text, nullable=True)
    # NEW FIELD: women safety flag
    women_safety = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'report_id': self.report_id,
            'threat_type': self.threat_type,
            'risk_score': self.risk_score,
            'status': self.status,
            'filed_at': self.filed_at.isoformat() if self.filed_at else None,
            'ncrp_case_id': self.ncrp_case_id,
            'women_safety': self.women_safety
        }
# =============================================

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

with app.app_context():
    db.create_all()
    # Check if the 'women_safety' column exists in ncrp_reports, if not, add it.
    from sqlalchemy import inspect
    inspector = inspect(db.engine)
    columns = [col['name'] for col in inspector.get_columns('ncrp_reports')]
    if 'women_safety' not in columns:
        # Use text() to execute raw SQL
        db.session.execute(text('ALTER TABLE ncrp_reports ADD COLUMN women_safety BOOLEAN DEFAULT 0'))
        db.session.commit()
        print("✅ Added women_safety column to ncrp_reports table.")

# ---------- QR CODE GENERATION ----------
def generate_qr():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except:
        ip = '127.0.0.1'
    url = f'http://{ip}:5000'
    os.makedirs('static/qr', exist_ok=True)
    qrcode.make(url).save('static/qr/app_qr.png')
    with open('static/qr/url.txt', 'w') as f:
        f.write(url)
    print(f"📱 QR Code generated for: {url}")

generate_qr()

# ---------- LOAD OR FALLBACK FOR ML MODELS ----------
MODEL_DIR = 'models'
os.makedirs(MODEL_DIR, exist_ok=True)

# ----- Deepfake model -----
deepfake_model = None

def mock_deepfake_predict(img_path):
    try:
        with open(img_path, 'rb') as f:
            data = f.read()
        hash_val = int(hashlib.sha256(data).hexdigest(), 16)
        prob = 0.1 + (hash_val % 800) / 1000.0
        return prob
    except Exception as e:
        print(f"Mock deepfake error: {e}")
        return random.uniform(0.1, 0.9)

if not FORCE_MOCK_DEEPFAKE and TENSORFLOW_AVAILABLE:
    model_path = os.path.join(MODEL_DIR, 'deepfake_model.h5')
    if os.path.exists(model_path):
        try:
            deepfake_model = tf.keras.models.load_model(model_path)
            print("✅ Deepfake model loaded (real).")
        except Exception as e:
            print(f"⚠ Could not load deepfake model: {e}. Using mock.")
            deepfake_model = None
    else:
        print("⚠ deepfake_model.h5 not found. Using mock.")
else:
    if FORCE_MOCK_DEEPFAKE:
        print("ℹ️ FORCE_MOCK_DEEPFAKE is True – using hash‑based mock for deepfake.")
    else:
        print("⚠ TensorFlow not available. Using mock for deepfake.")

# ----- TEXT‑BASED PHISHING MODEL -----
phishing_model = None
vectorizer = None

def mock_text_phishing_predict(text):
    text_lower = text.lower()
    
    # ----- SAFE PHRASES (guarantee legitimate) -----
    safe_phrases = ['hello', 'hi', 'how are you', 'good morning', 'good evening',
                    'meeting', 'lunch', 'dinner', 'weather', 'nice to meet',
                    'thanks', 'thank you', 'appreciate', 'see you', 'talk to you later',
                    'family', 'friend', 'weekend', 'holiday']
    if any(phrase in text_lower for phrase in safe_phrases):
        return 0.1  # very low probability -> legitimate
    
    # ----- STRONG PHISHING INDICATORS -----
    strong_indicators = ['urgent', 'verify your account', 'password expired',
                         'ssn', 'social security', 'credit card', 'paypal',
                         'bank account', 'login details', 'click here', 'update your information']
    if any(ind in text_lower for ind in strong_indicators):
        return 0.95  # high probability -> phishing
    
    # ----- HASH‑BASED (deterministic, spreads around 0.5) -----
    hash_val = int(hashlib.sha256(text_lower.encode()).hexdigest(), 16)
    prob = 0.1 + (hash_val % 800) / 1000.0
    return prob

if not FORCE_MOCK_PHISHING:
    try:
        text_model_path = os.path.join(MODEL_DIR, 'phishing_model.pkl')
        vec_path = os.path.join(MODEL_DIR, 'vectorizer.pkl')
        if os.path.exists(text_model_path) and os.path.exists(vec_path):
            phishing_model = joblib.load(text_model_path)
            vectorizer = joblib.load(vec_path)
            print("✅ Text‑based phishing model loaded.")
        else:
            print("⚠ Text phishing model files not found. Using mock.")
    except Exception as e:
        print(f"⚠ Could not load text phishing model: {e}. Using mock.")
        phishing_model = None
        vectorizer = None
else:
    print("ℹ️ FORCE_MOCK_PHISHING is True – using enhanced hash‑based mock for text phishing (includes safe phrases).")

# ----- URL‑BASED PHISHING MODEL -----
url_phishing_model = None
url_scaler = None

def mock_url_phishing_predict(feature_dict):
    url = feature_dict.get('url', '').lower()
    if any(domain in url for domain in ['paypal', 'apple', 'microsoft', 'bank',
                                         'secure', 'login', 'verify', 'update']):
        return 0.95
    hash_val = int(hashlib.sha256(url.encode()).hexdigest(), 16)
    prob = 0.1 + (hash_val % 800) / 1000.0
    return prob

if not FORCE_MOCK_URL_PHISHING:
    try:
        url_model_path = os.path.join(MODEL_DIR, 'url_phishing_model.pkl')
        url_scaler_path = os.path.join(MODEL_DIR, 'url_scaler.pkl')
        if os.path.exists(url_model_path) and os.path.exists(url_scaler_path):
            url_phishing_model = joblib.load(url_model_path)
            url_scaler = joblib.load(url_scaler_path)
            print("✅ URL‑based phishing model & scaler loaded.")
        else:
            print("⚠ URL phishing model files not found. Using mock.")
            url_phishing_model = None
            url_scaler = None
    except Exception as e:
        print(f"⚠ Could not load URL phishing model: {e}. Using mock.")
        url_phishing_model = None
        url_scaler = None
else:
    print("ℹ️ FORCE_MOCK_URL_PHISHING is True – using hash‑based mock for URL phishing.")

# ---------- PREDICTION WRAPPERS ----------
def predict_deepfake(img_path):
    if FORCE_MOCK_DEEPFAKE:
        return mock_deepfake_predict(img_path)
    if deepfake_model is not None:
        try:
            img = image.load_img(img_path, target_size=(128,128))
            img_array = image.img_to_array(img) / 255.0
            img_array = np.expand_dims(img_array, axis=0)
            prob = deepfake_model.predict(img_array, verbose=0)[0][0]
            return float(prob)
        except Exception as e:
            print(f"Deepfake prediction error: {e}")
    return mock_deepfake_predict(img_path)

def predict_text_phishing(text):
    if FORCE_MOCK_PHISHING:
        return mock_text_phishing_predict(text)
    if phishing_model is not None and vectorizer is not None:
        try:
            def extract_features(text):
                features = {}
                features['length'] = len(text)
                features['num_dots'] = text.count('.')
                features['num_digits'] = sum(c.isdigit() for c in text)
                features['num_special'] = sum(not c.isalnum() for c in text)
                features['has_http'] = 1 if 'http' in text else 0
                features['has_https'] = 1 if 'https' in text else 0
                features['has_at'] = 1 if '@' in text else 0
                features['has_dash'] = 1 if '-' in text else 0
                return pd.DataFrame([features])
            tfidf_features = vectorizer.transform([text])
            custom_features = extract_features(text)
            X = np.hstack([tfidf_features.toarray(), custom_features.values])
            prob = phishing_model.predict_proba(X)[0][1]
            return float(prob)
        except Exception as e:
            print(f"Text phishing error: {e}")
    return mock_text_phishing_predict(text)

def predict_url_phishing(feature_dict):
    if FORCE_MOCK_URL_PHISHING:
        return mock_url_phishing_predict(feature_dict)
    if url_phishing_model is None or url_scaler is None:
        return mock_url_phishing_predict(feature_dict)
    if hasattr(url_scaler, 'feature_names_in_'):
        expected_features = list(url_scaler.feature_names_in_)
    else:
        n_features = url_scaler.mean_.shape[0]
        expected_features = [f"f{i}" for i in range(n_features)]
    try:
        row = [feature_dict[col] for col in expected_features]
    except KeyError as e:
        raise ValueError(f"Missing feature: {e}")
    X = pd.DataFrame([row], columns=expected_features)
    X_scaled = url_scaler.transform(X)
    prob = url_phishing_model.predict_proba(X_scaled)[0][1]
    return float(prob)

# ---------- VIDEO PROCESSING ----------
def extract_frames_from_video(video_path, num_frames=15):
    if not OPENCV_AVAILABLE:
        return []
    cap = cv2.VideoCapture(video_path)
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    if total_frames <= 0:
        cap.release()
        return []
    indices = np.linspace(0, total_frames-1, min(num_frames, total_frames), dtype=int)
    frames = []
    for idx in indices:
        cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
        ret, frame = cap.read()
        if ret:
            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            frames.append(frame_rgb)
    cap.release()
    return frames

def predict_deepfake_video(video_path):
    if not OPENCV_AVAILABLE:
        return mock_deepfake_predict(video_path), 0
    frames = extract_frames_from_video(video_path, num_frames=15)
    if not frames:
        return mock_deepfake_predict(video_path), 0
    probs = []
    with tempfile.TemporaryDirectory() as tmpdir:
        for i, frame in enumerate(frames):
            img_path = os.path.join(tmpdir, f'frame_{i}.jpg')
            frame_bgr = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)
            cv2.imwrite(img_path, frame_bgr)
            prob = predict_deepfake(img_path)
            probs.append(prob)
    avg_prob = np.mean(probs)
    return float(avg_prob), len(frames)

# ---------- ROUTES ----------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        if not email or not password:
            flash('Email and password required', 'danger')
            return redirect(url_for('register'))
        if password != confirm:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        user = User(email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/defendface')
@login_required
def defendface():
    return render_template('defendface.html')

@app.route('/phishing')
@login_required
def phishing():
    return render_template('phishing.html')

@app.route('/threat-sources')
@login_required
def threat_sources():
    return render_template('threat_sources.html')

# NEW ROUTE: Women Safety Hub
@app.route('/women-safety')
@login_required
def women_safety():
    return render_template('women_safety.html')

# ---------- API: DASHBOARD STATS ----------
@app.route('/api/dashboard_stats')
@login_required
def dashboard_stats():
    user = current_user
    total_analyses = Analysis.query.filter_by(user_id=user.id).count()
    defendface_count = Analysis.query.filter_by(user_id=user.id, analysis_type='defendface').count()
    phishing_count = Analysis.query.filter_by(user_id=user.id, analysis_type='phishing').count()
    phishing_url_count = Analysis.query.filter_by(user_id=user.id, analysis_type='phishing_url').count()
    recent = Analysis.query.filter_by(user_id=user.id).order_by(Analysis.timestamp.desc()).limit(5).all()
    recent_data = [{
        'id': a.id,
        'type': a.analysis_type,
        'result': a.result,
        'confidence': a.confidence,
        'timestamp': a.timestamp.strftime('%Y-%m-%d %H:%M')
    } for a in recent]
    return jsonify({
        'total_analyses': total_analyses,
        'defendface_count': defendface_count,
        'phishing_count': phishing_count,
        'phishing_url_count': phishing_url_count,
        'recent': recent_data
    })

# ---------- API: DEFENDFACE ANALYSIS ----------
@app.route('/api/defendface/analyze', methods=['POST'])
@login_required
def defendface_analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    file_type = request.form.get('type', 'image')
    if file_type not in ['image', 'video']:
        ext = file.filename.split('.')[-1].lower()
        file_type = 'video' if ext in ['mp4', 'avi', 'mov', 'mkv', 'webm'] else 'image'

    upload_folder = 'temp'
    os.makedirs(upload_folder, exist_ok=True)
    filepath = os.path.join(upload_folder, file.filename)
    file.save(filepath)

    try:
        if file_type == 'video':
            prob, frame_count = predict_deepfake_video(filepath)
            is_deepfake = prob > 0.5
            confidence = prob if is_deepfake else 1 - prob
            result_label = 'fake' if is_deepfake else 'real'
            details = json.dumps({'probability': round(prob, 4), 'frame_count': frame_count})
        else:
            prob = predict_deepfake(filepath)
            is_deepfake = prob > 0.5
            confidence = prob if is_deepfake else 1 - prob
            result_label = 'fake' if is_deepfake else 'real'
            details = json.dumps({'probability': round(prob, 4)})
            frame_count = None

        analysis = Analysis(
            user_id=current_user.id,
            analysis_type='defendface',
            input_data=file.filename,
            result=result_label,
            confidence=float(round(confidence * 100, 1)),
            details=details
        )
        db.session.add(analysis)
        db.session.commit()

        # Email report
        try:
            msg = Message(
                subject=f'🛡 DefendFace Report #{analysis.id}',
                recipients=[current_user.email],
                html=f"<h2>DefendFace Report</h2><p>Result: {result_label.upper()}</p><p>Confidence: {round(confidence*100,1)}%</p>"
            )
            mail.send(msg)
        except Exception as e:
            print(f"⚠ Email failed: {e}")

        # Threat tracking
        fingerprint = request.headers.get('X-Fingerprint')
        fingerprint_id = request.headers.get('X-Fingerprint-ID')
        if fingerprint and fingerprint_id and is_deepfake:
            try:
                threat_data = {'probability': prob, 'confidence': confidence, 'filename': file.filename}
                track_threat(fingerprint, fingerprint_id, 'deepfake_detected', analysis.id, threat_data)
            except Exception as e:
                print(f"⚠ Threat tracking error: {e}")

        response = {
            'success': True,
            'deepfake_probability': round(prob * 100, 1),
            'is_deepfake': is_deepfake,
            'confidence': round(confidence * 100, 1),
            'analysis_id': analysis.id
        }
        if frame_count:
            response['frame_count'] = frame_count
        return jsonify(response)

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        try:
            os.remove(filepath)
        except:
            pass

# ---------- API: PHISHING ANALYSIS ----------
@app.route('/api/phishing/analyze', methods=['POST'])
@login_required
def phishing_analyze():
    data = request.get_json()
    text = data.get('text', '')
    if not text:
        return jsonify({'error': 'No text provided'}), 400

    prob = predict_text_phishing(text)
    is_phishing = prob > 0.5
    confidence = prob if is_phishing else 1 - prob
    result_label = 'phishing' if is_phishing else 'legitimate'

    indicators = []
    if 'http' in text or 'www' in text:
        indicators.append('URL detected')
    if re.search(r'urgent|immediately|verify|account', text, re.I):
        indicators.append('Urgency language')
    if re.search(r'password|ssn|social security|credit card', text, re.I):
        indicators.append('Sensitive information request')
    if re.search(r'paypal|bank|amazon|apple', text, re.I):
        indicators.append('Brand impersonation')

    analysis = Analysis(
        user_id=current_user.id,
        analysis_type='phishing',
        input_data=text[:200],
        result=result_label,
        confidence=float(round(confidence * 100, 1)),
        details=json.dumps({'probability': round(prob, 4), 'indicators': indicators})
    )
    db.session.add(analysis)
    db.session.commit()

    # Email report
    try:
        threat_level = 'HIGH' if prob > 0.7 else 'MEDIUM' if prob > 0.4 else 'LOW'
        msg = Message(
            subject=f'🛡 Phishing Report #{analysis.id}',
            recipients=[current_user.email],
            html=f"<h2>Phishing Report</h2><p>Result: {result_label.upper()}</p><p>Risk Score: {round(prob*100,1)}%</p><p>Threat Level: {threat_level}</p>"
        )
        mail.send(msg)
    except Exception as e:
        print(f"⚠ Email failed: {e}")

    # Threat tracking
    fingerprint = request.headers.get('X-Fingerprint')
    fingerprint_id = request.headers.get('X-Fingerprint-ID')
    print(f"🔍 Phishing: fingerprint={fingerprint}, id={fingerprint_id}, is_phishing={is_phishing}")
    if fingerprint and fingerprint_id and is_phishing:
        try:
            threat_data = {
                'risk_score': prob,
                'confidence': confidence,
                'text_snippet': text[:50],
                'indicators': indicators,
                'analysis_id': analysis.id
            }
            track_threat(fingerprint, fingerprint_id, 'phishing_detected', analysis.id, threat_data)
        except Exception as e:
            print(f"⚠ Threat tracking error: {e}")

    threat_level = 'HIGH' if prob > 0.7 else 'MEDIUM' if prob > 0.4 else 'LOW'
    return jsonify({
        'success': True,
        'risk_score': round(prob * 100, 1),
        'is_phishing': is_phishing,
        'confidence': round(confidence * 100, 1),
        'indicators': indicators,
        'threat_level': threat_level,
        'analysis_id': analysis.id
    })

# ---------- API: URL PHISHING ----------
@app.route('/api/phishing_url/analyze', methods=['POST'])
@login_required
def phishing_url_analyze():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    try:
        prob = predict_url_phishing(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    is_phishing = prob > 0.5
    confidence = prob if is_phishing else 1 - prob
    result_label = 'phishing' if is_phishing else 'legitimate'
    analysis = Analysis(
        user_id=current_user.id,
        analysis_type='phishing_url',
        input_data=json.dumps(data)[:200],
        result=result_label,
        confidence=float(round(confidence * 100, 1)),
        details=json.dumps({'probability': round(prob, 4)})
    )
    db.session.add(analysis)
    db.session.commit()

    # Threat tracking for URL phishing
    fingerprint = request.headers.get('X-Fingerprint')
    fingerprint_id = request.headers.get('X-Fingerprint-ID')
    if fingerprint and fingerprint_id and is_phishing:
        try:
            threat_data = {'risk_score': prob, 'confidence': confidence, 'data': data}
            track_threat(fingerprint, fingerprint_id, 'url_phishing_detected', analysis.id, threat_data)
        except Exception as e:
            print(f"⚠ Threat tracking error: {e}")

    threat_level = 'HIGH' if prob > 0.7 else 'MEDIUM' if prob > 0.4 else 'LOW'
    return jsonify({
        'success': True,
        'risk_score': round(prob * 100, 1),
        'is_phishing': is_phishing,
        'confidence': round(confidence * 100, 1),
        'threat_level': threat_level,
        'analysis_id': analysis.id
    })

# ---------- THREAT TRACKING HELPER FUNCTIONS ----------
def get_client_info(request):
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()
    return {
        'ip': ip,
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'referrer': request.headers.get('Referer', 'Direct')
    }

def get_or_create_source(fingerprint, fingerprint_id, device_info=None):
    source = ThreatSource.query.filter_by(fingerprint=fingerprint).first()
    if not source:
        country = random.choice(['India', 'United States', 'Unknown'])
        source = ThreatSource(
            fingerprint=fingerprint,
            fingerprint_id=fingerprint_id,
            first_seen=datetime.now(timezone.utc).replace(tzinfo=None),
            last_seen=datetime.now(timezone.utc).replace(tzinfo=None),
            visit_count=1,
            device_info=json.dumps(device_info or {}),
            country=country
        )
        db.session.add(source)
        db.session.commit()
    else:
        source.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
        source.visit_count += 1
        db.session.commit()
    return source

def track_threat(fingerprint, fingerprint_id, threat_type, analysis_id=None, threat_data=None):
    source = get_or_create_source(fingerprint, fingerprint_id, threat_data)
    source.threat_count += 1
    types = json.loads(source.threat_types) if source.threat_types else []
    if threat_type not in types:
        types.append(threat_type)
    source.threat_types = json.dumps(types)
    source.calculate_risk_score()
    db.session.commit()

    if source.risk_score > 80 and not source.is_blocked:
        source.is_blocked = True
        db.session.commit()

    report = file_ncrp_report(source, threat_type, analysis_id, threat_data)
    return {
        'source': {
            'fingerprint_id': source.fingerprint_id,
            'risk_score': source.risk_score,
            'threat_count': source.threat_count,
            'is_blocked': source.is_blocked
        },
        'ncrp_report': report
    }

def generate_report_id():
    return f"NCRP{datetime.now().strftime('%Y%m%d%H%M%S')}{''.join(random.choices(string.digits, k=4))}"

def generate_case_id():
    return f"CASE{datetime.now().strftime('%Y%m')}{''.join(random.choices(string.ascii_uppercase + string.digits, k=6))}"

def file_ncrp_report(source, threat_type, analysis_id=None, threat_data=None):
    report_id = generate_report_id()
    evidence = {
        'fingerprint_id': source.fingerprint_id,
        'threat_count': source.threat_count,
        'visit_count': source.visit_count,
        'first_seen': source.first_seen.isoformat() if source.first_seen else None,
        'last_seen': source.last_seen.isoformat() if source.last_seen else None,
        'device_info': json.loads(source.device_info) if source.device_info else {},
        'country': source.country,
        'threat_history': json.loads(source.threat_types) if source.threat_types else []
    }
    if threat_data:
        evidence['current_threat'] = threat_data

    case_id = generate_case_id()
    ncrp_response = {
        'status': 'RECEIVED',
        'case_id': case_id,
        'acknowledgment': f"Report #{report_id} registered with NCRP",
        'priority': 'HIGH' if source.risk_score > 70 else 'MEDIUM',
        'assigned_to': f"Officer {random.choice(['Rajesh', 'Priya'])}"
    }

    report = NCRPReport(
        report_id=report_id,
        threat_source_id=source.id,
        analysis_id=analysis_id,
        user_id=current_user.id if current_user and current_user.is_authenticated else None,
        threat_type=threat_type,
        threat_details=json.dumps(threat_data or {}),
        evidence=json.dumps(evidence),
        risk_score=source.risk_score,
        status='FILED',
        ncrp_case_id=case_id,
        ncrp_response=json.dumps(ncrp_response),
        women_safety=False  # default for non-women reports
    )
    db.session.add(report)
    db.session.commit()
    return {
        'report_id': report_id,
        'case_id': case_id,
        'status': ncrp_response['status'],
        'priority': ncrp_response['priority'],
        'assigned_to': ncrp_response['assigned_to']
    }

# ---------- THREAT TRACKING API ENDPOINTS ----------
@app.route('/api/track-event', methods=['POST'])
def track_event():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400
    fingerprint = data.get('fingerprint')
    fingerprint_id = data.get('fingerprintId')
    event_type = data.get('eventType')
    event_data = data.get('eventData', {})
    if not fingerprint or not fingerprint_id:
        return jsonify({'error': 'Fingerprint required'}), 400
    client_info = get_client_info(request)
    source = get_or_create_source(fingerprint, fingerprint_id, {**client_info, **event_data})
    if event_type in ['deepfake_detected', 'phishing_detected']:
        result = track_threat(fingerprint, fingerprint_id, event_type, threat_data=event_data)
        return jsonify({'success': True, 'event': 'threat_tracked', **result})
    return jsonify({'success': True, 'event': 'tracked', 'source': {'fingerprint_id': source.fingerprint_id}})

@app.route('/api/threat-sources', methods=['GET'])
@login_required
def list_threat_sources():
    sources = ThreatSource.query.order_by(ThreatSource.risk_score.desc()).limit(100).all()
    return jsonify({
        'success': True,
        'total': len(sources),
        'sources': [{
            'fingerprint_id': s.fingerprint_id,
            'first_seen': s.first_seen.isoformat(),
            'last_seen': s.last_seen.isoformat(),
            'visit_count': s.visit_count,
            'threat_count': s.threat_count,
            'threat_types': json.loads(s.threat_types) if s.threat_types else [],
            'risk_score': s.risk_score,
            'is_blocked': s.is_blocked,
            'country': s.country
        } for s in sources]
    })

@app.route('/api/ncrp-reports', methods=['GET'])
@login_required
def list_ncrp_reports():
    reports = NCRPReport.query.order_by(NCRPReport.filed_at.desc()).limit(50).all()
    return jsonify({
        'success': True,
        'reports': [r.to_dict() for r in reports]
    })

@app.route('/api/source/<fingerprint_id>', methods=['GET'])
@login_required
def get_source_details(fingerprint_id):
    source = ThreatSource.query.filter_by(fingerprint_id=fingerprint_id).first()
    if not source:
        return jsonify({'error': 'Not found'}), 404
    reports = NCRPReport.query.filter_by(threat_source_id=source.id).all()
    return jsonify({
        'success': True,
        'source': {
            'fingerprint_id': source.fingerprint_id,
            'first_seen': source.first_seen.isoformat(),
            'last_seen': source.last_seen.isoformat(),
            'visit_count': source.visit_count,
            'threat_count': source.threat_count,
            'threat_types': json.loads(source.threat_types) if source.threat_types else [],
            'risk_score': source.risk_score,
            'is_blocked': source.is_blocked,
            'country': source.country,
            'device_info': json.loads(source.device_info) if source.device_info else {}
        },
        'reports': [r.to_dict() for r in reports]
    })

@app.route('/api/source/<fingerprint_id>/block', methods=['POST'])
@login_required
def block_source(fingerprint_id):
    source = ThreatSource.query.filter_by(fingerprint_id=fingerprint_id).first()
    if not source:
        return jsonify({'error': 'Not found'}), 404
    source.is_blocked = True
    db.session.commit()
    return jsonify({'success': True, 'message': f'Source {fingerprint_id} blocked'})

@app.route('/api/check-blocked', methods=['POST'])
def check_if_blocked():
    data = request.get_json()
    fingerprint = data.get('fingerprint')
    if not fingerprint:
        return jsonify({'blocked': False})
    source = ThreatSource.query.filter_by(fingerprint=fingerprint).first()
    return jsonify({'blocked': source.is_blocked if source else False})

# ========== PDF DOWNLOAD FOR NCRP REPORTS ==========
@app.route('/api/ncrp-report/<report_id>/pdf', methods=['GET'])
@login_required
def download_ncrp_pdf(report_id):
    report = NCRPReport.query.filter_by(report_id=report_id).first()
    if not report:
        return jsonify({'error': 'Report not found'}), 404

    source = db.session.get(ThreatSource, report.threat_source_id)

    threat_details = json.loads(report.threat_details) if report.threat_details else {}
    evidence = json.loads(report.evidence) if report.evidence else {}
    ncrp_resp = json.loads(report.ncrp_response) if report.ncrp_response else {}

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)

    # Header
    pdf.set_fill_color(11, 15, 26)
    pdf.set_text_color(56, 189, 248)
    pdf.set_font("Helvetica", 'B', 16)
    pdf.cell(200, 10, text="CyberRakshak AI - NCRP Report", new_x="LMARGIN", new_y="NEXT", align='C')
    pdf.ln(10)

    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", size=12)

    # Report details
    pdf.set_font("Helvetica", 'B', 12)
    pdf.cell(50, 10, text="Report ID:")
    pdf.set_font("Helvetica", size=12)
    pdf.cell(0, 10, text=report.report_id, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", 'B', 12)
    pdf.cell(50, 10, text="Case ID:")
    pdf.set_font("Helvetica", size=12)
    pdf.cell(0, 10, text=report.ncrp_case_id or "N/A", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", 'B', 12)
    pdf.cell(50, 10, text="Threat Type:")
    pdf.set_font("Helvetica", size=12)
    pdf.cell(0, 10, text=report.threat_type, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", 'B', 12)
    pdf.cell(50, 10, text="Risk Score:")
    pdf.set_font("Helvetica", size=12)
    pdf.cell(0, 10, text=f"{report.risk_score}%", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", 'B', 12)
    pdf.cell(50, 10, text="Status:")
    pdf.set_font("Helvetica", size=12)
    pdf.cell(0, 10, text=report.status, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", 'B', 12)
    pdf.cell(50, 10, text="Filed At:")
    pdf.set_font("Helvetica", size=12)
    pdf.cell(0, 10, text=report.filed_at.strftime('%Y-%m-%d %H:%M:%S'), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)

    if source:
        pdf.set_font("Helvetica", 'B', 14)
        pdf.cell(0, 10, text="Threat Source Details", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=12)
        pdf.cell(50, 10, text="Fingerprint ID:")
        pdf.cell(0, 10, text=source.fingerprint_id, new_x="LMARGIN", new_y="NEXT")
        pdf.cell(50, 10, text="Country:")
        pdf.cell(0, 10, text=source.country, new_x="LMARGIN", new_y="NEXT")
        pdf.cell(50, 10, text="Threat Count:")
        pdf.cell(0, 10, text=str(source.threat_count), new_x="LMARGIN", new_y="NEXT")
        pdf.cell(50, 10, text="Visit Count:")
        pdf.cell(0, 10, text=str(source.visit_count), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

    pdf.set_font("Helvetica", 'B', 14)
    pdf.cell(0, 10, text="Evidence", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=10)

    def safe_multi_cell(text, width=190):
        try:
            pdf.multi_cell(width, 5, text=text)
        except:
            pdf.multi_cell(width, 5, text=str(text)[:1000])

    for key, value in evidence.items():
        if isinstance(value, dict):
            pdf.set_font("Helvetica", 'B', 10)
            pdf.cell(190, 5, text=f"{key}:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", size=8)
            lines = json.dumps(value, indent=2).split('\n')
            for line in lines:
                safe_multi_cell(line)
        else:
            safe_multi_cell(f"{key}: {value}")

    pdf_output = io.BytesIO()
    pdf_bytes = pdf.output()
    pdf_output.write(pdf_bytes)
    pdf_output.seek(0)

    return send_file(
        pdf_output,
        as_attachment=True,
        download_name=f"ncrp_report_{report.report_id}.pdf",
        mimetype='application/pdf'
    )

# ---------- DOWNLOAD REPORT (TXT) ----------
@app.route('/api/download_report/<int:analysis_id>')
@login_required
def download_report(analysis_id):
    analysis = Analysis.query.get_or_404(analysis_id)
    if analysis.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    report_text = f"""
    ═══════════════════════════════════════════
            CyberRakshak AI - Analysis Report
    ═══════════════════════════════════════════
    User: {current_user.email}
    Analysis ID: {analysis.id}
    Module: {analysis.analysis_type.upper()}
    Timestamp: {analysis.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
    Result: {analysis.result.upper()}
    Confidence: {analysis.confidence}%
    Input: {analysis.input_data}
    Details: {analysis.details}
    ═══════════════════════════════════════════
    """
    file_data = BytesIO(report_text.encode('utf-8'))
    file_data.seek(0)
    return send_file(file_data, as_attachment=True, download_name=f'report_{analysis.id}.txt', mimetype='text/plain')

# ========== MULTILINGUAL CHATBOT ==========
# Language detection function
def detect_language(text):
    """Detect language based on common words and Unicode ranges."""
    # Check for Devanagari (Hindi) script
    if any('\u0900' <= ch <= '\u097F' for ch in text):
        return 'hi'
    # Check for Tamil script
    if any('\u0B80' <= ch <= '\u0BFF' for ch in text):
        return 'ta'
    # Check for Telugu script
    if any('\u0C00' <= ch <= '\u0C7F' for ch in text):
        return 'te'
    # Default to English
    return 'en'

# Responses in multiple languages
chatbot_responses = {
    "en": {
        "greetings": ["Hello! I'm your CyberRakshak AI assistant.", "Hi there! How can I help you today?"],
        "deepfake": "Deepfakes are AI-generated fake videos or images. Our DefendFace module detects them with 94.7% accuracy. You can test it by going to the DefendFace page.",
        "phishing": "Phishing is a scam where attackers trick you into revealing sensitive information. Our Phishing Analyzer can check messages and URLs.",
        "ransomware": "Ransomware is malware that encrypts your files and demands payment. NEVER pay the ransom. Keep backups and update software.",
        "password": "Use strong, unique passwords and enable two-factor authentication. Consider a password manager.",
        "social_media": "Be careful what you share on social media. Check privacy settings and avoid sharing personal details publicly.",
        "shopping": "Only shop on trusted websites with HTTPS. Use credit cards for better fraud protection.",
        "women_safety": "We have a dedicated Women Safety section with resources and a reporting tool. Click here: <a href='/women-safety' target='_blank'>Narishakthi</a>",
        "navigation": {
            "defendface": "<a href='/defendface' target='_blank'>DefendFace</a>",
            "phishing": "<a href='/phishing' target='_blank'>Phishing Analyzer</a>",
            "dashboard": "<a href='/dashboard' target='_blank'>Dashboard</a>",
            "threat_sources": "<a href='/threat-sources' target='_blank'>Threat Sources</a>",
            "women_safety": "<a href='/women-safety' target='_blank'>Narishakthi</a>"
        },
        "fallback": "I'm sorry, I didn't understand that. You can ask me about deepfakes, phishing, passwords, or ask me to take you to a page (e.g., 'go to defendface')."
    },
    "hi": {
        "greetings": ["नमस्ते! मैं आपका CyberRakshak AI सहायक हूँ।", "कैसे मदद कर सकता हूँ?"],
        "deepfake": "डीपफेक AI द्वारा बनाए गए नकली वीडियो या छवियाँ हैं। हमारा DefendFace मॉड्यूल 94.7% सटीकता से इनका पता लगाता है। आप DefendFace पेज पर जाकर इसे आज़मा सकते हैं।",
        "phishing": "फ़िशिंग एक धोखाधड़ी है जहाँ हमलावर आपसे संवेदनशील जानकारी हासिल करने की कोशिश करते हैं। हमारा Phishing Analyzer संदेशों और URLs की जाँच कर सकता है।",
        "ransomware": "रैनसमवेयर एक मैलवेयर है जो आपकी फ़ाइलों को एन्क्रिप्ट कर देता है और फिरौती मांगता है। फिरौती कभी न दें। बैकअप रखें और सॉफ़्टवेयर अपडेट करें।",
        "password": "मजबूत और अद्वितीय पासवर्ड का उपयोग करें और दो-कारक प्रमाणीकरण चालू करें। पासवर्ड मैनेजर का उपयोग करें।",
        "social_media": "सोशल मीडिया पर साझा करते समय सावधान रहें। गोपनीयता सेटिंग्स जाँचें और व्यक्तिगत जानकारी सार्वजनिक रूप से साझा करने से बचें।",
        "shopping": "केवल HTTPS वाली भरोसेमंद वेबसाइटों से खरीदारी करें। बेहतर धोखाधड़ी सुरक्षा के लिए क्रेडिट कार्ड का उपयोग करें।",
        "women_safety": "हमारा महिला सुरक्षा अनुभाग संसाधन और रिपोर्टिंग टूल प्रदान करता है। यहाँ क्लिक करें: <a href='/women-safety' target='_blank'>नारीशक्ति</a>",
        "navigation": {
            "defendface": "<a href='/defendface' target='_blank'>DefendFace</a>",
            "phishing": "<a href='/phishing' target='_blank'>Phishing Analyzer</a>",
            "dashboard": "<a href='/dashboard' target='_blank'>Dashboard</a>",
            "threat_sources": "<a href='/threat-sources' target='_blank'>Threat Sources</a>",
            "women_safety": "<a href='/women-safety' target='_blank'>नारीशक्ति</a>"
        },
        "fallback": "क्षमा करें, मैं समझ नहीं पाया। आप मुझसे डीपफेक, फ़िशिंग, पासवर्ड के बारे में पूछ सकते हैं, या किसी पेज पर ले जाने के लिए कह सकते हैं (जैसे 'defendface पर जाएं')।"
    },
    "ta": {
        "greetings": ["வணக்கம்! நான் உங்கள் CyberRakshak AI உதவியாளர்.", "எப்படி உதவ முடியும்?"],
        "deepfake": "டீப்ஃபேக் என்பது AI உருவாக்கிய போலி வீடியோக்கள் அல்லது படங்கள். எங்கள் DefendFace தொகுதி 94.7% துல்லியத்துடன் அவற்றைக் கண்டறியும். நீங்கள் DefendFace பக்கத்திற்குச் சென்று இதை முயற்சிக்கலாம்.",
        "phishing": "ஃபிஷிங் என்பது ஒரு மோசடி, அங்கு தாக்குபவர்கள் உங்கள் ரகசியத் தகவல்களைப் பெற முயற்சிக்கின்றனர். எங்கள் Phishing Analyzer செய்திகள் மற்றும் URLs ஐ சரிபார்க்க முடியும்.",
        "ransomware": "ரான்சம்வேர் என்பது ஒரு மால்வேர், இது உங்கள் கோப்புகளை என்க்ரிப்ட் செய்து மீட்கும் தொகையைக் கோருகிறது. மீட்கும் தொகையை ஒருபோதும் கொடுக்க வேண்டாம். காப்புப்பிரதிகளை வைத்திருங்கள், மென்பொருளைப் புதுப்பிக்கவும்.",
        "password": "வலுவான, தனித்துவமான கடவுச்சொற்களைப் பயன்படுத்தவும் மற்றும் இரண்டு-காரணி அங்கீகாரத்தை இயக்கவும். கடவுச்சொல் மேலாளரைப் பயன்படுத்தவும்.",
        "social_media": "சமூக ஊடகங்களில் பகிரும்போது கவனமாக இருங்கள். தனியுரிமை அமைப்புகளைச் சரிபார்த்து, தனிப்பட்ட தகவல்களைப் பொதுவில் பகிர்வதைத் தவிர்க்கவும்.",
        "shopping": "HTTPS உள்ள நம்பகமான வலைத்தளங்களில் மட்டுமே ஷாப்பிங் செய்யுங்கள். சிறந்த மோசடி பாதுகாப்புக்காக கிரெடிட் கார்டுகளைப் பயன்படுத்துங்கள்.",
        "women_safety": "எங்கள் பெண்கள் பாதுகாப்பு பகுதி ஆதாரங்கள் மற்றும் புகார் கருவியை வழங்குகிறது. இங்கே கிளிக் செய்யவும்: <a href='/women-safety' target='_blank'>நரிசக்தி</a>",
        "navigation": {
            "defendface": "<a href='/defendface' target='_blank'>DefendFace</a>",
            "phishing": "<a href='/phishing' target='_blank'>Phishing Analyzer</a>",
            "dashboard": "<a href='/dashboard' target='_blank'>Dashboard</a>",
            "threat_sources": "<a href='/threat-sources' target='_blank'>Threat Sources</a>",
            "women_safety": "<a href='/women-safety' target='_blank'>நரிசக்தி</a>"
        },
        "fallback": "மன்னிக்கவும், எனக்குப் புரியவில்லை. நீங்கள் டீப்ஃபேக், ஃபிஷிங், கடவுச்சொற்கள் பற்றி என்னிடம் கேட்கலாம் அல்லது ஒரு பக்கத்திற்குச் செல்லச் சொல்லலாம் (எ.கா., 'defendface க்குச் செல்லுங்கள்')."
    },
    "te": {
        "greetings": ["హలో! నేను మీ CyberRakshak AI సహాయకుడిని.", "నేను ఎలా సహాయపడగలను?"],
        "deepfake": "డీప్ఫేక్ అనేది AI రూపొందించిన నకిలీ వీడియోలు లేదా చిత్రాలు. మా DefendFace మాడ్యూల్ 94.7% ఖచ్చితత్వంతో వాటిని గుర్తిస్తుంది. మీరు DefendFace పేజీకి వెళ్లి దీన్ని ప్రయత్నించవచ్చు.",
        "phishing": "ఫిషింగ్ అనేది ఒక మోసం, దాడి చేసేవారు మీ సున్నితమైన సమాచారాన్ని పొందేందుకు ప్రయత్నిస్తారు. మా Phishing Analyzer సందేశాలు మరియు URLలను తనిఖీ చేయగలదు.",
        "ransomware": "రాన్సమ్వేర్ అనేది మీ ఫైల్లను ఎన్క్రిప్ట్ చేసి, డిమాండ్ చేసే మాల్వేర్. ఎప్పుడూ డిమాండ్ చెల్లించవద్దు. బ్యాకప్లు ఉంచుకోండి మరియు సాఫ్ట్వేర్ను నవీకరించండి.",
        "password": "బలమైన, ప్రత్యేకమైన పాస్వర్డ్లను ఉపయోగించండి మరియు రెండు-కారకాల ప్రామాణీకరణను ప్రారంభించండి. పాస్వర్డ్ మేనేజర్ని ఉపయోగించండి.",
        "social_media": "సోషల్ మీడియాలో భాగస్వామ్యం చేసేటప్పుడు జాగ్రత్తగా ఉండండి. గోప్యతా సెట్టింగ్లను తనిఖీ చేయండి మరియు వ్యక్తిగత సమాచారాన్ని బహిరంగంగా భాగస్వామ్యం చేయడం మానుకోండి.",
        "shopping": "HTTPS ఉన్న నమ్మకమైన వెబ్‌సైట్లలో మాత్రమే షాపింగ్ చేయండి. మెరుగైన మోసపూరిత రక్షణ కోసం క్రెడిట్ కార్డ్‌లను ఉపయోగించండి.",
        "women_safety": "మా మహిళా భద్రత విభాగం వనరులు మరియు నివేదిక సాధనాన్ని అందిస్తుంది. ఇక్కడ క్లిక్ చేయండి: <a href='/women-safety' target='_blank'>నారీశక్తి</a>",
        "navigation": {
            "defendface": "<a href='/defendface' target='_blank'>DefendFace</a>",
            "phishing": "<a href='/phishing' target='_blank'>Phishing Analyzer</a>",
            "dashboard": "<a href='/dashboard' target='_blank'>Dashboard</a>",
            "threat_sources": "<a href='/threat-sources' target='_blank'>Threat Sources</a>",
            "women_safety": "<a href='/women-safety' target='_blank'>నారీశక్తి</a>"
        },
        "fallback": "క్షమించండి, నాకు అర్థం కాలేదు. మీరు డీప్ఫేక్, ఫిషింగ్, పాస్‌వర్డ్‌ల గురించి నన్ను అడగవచ్చు లేదా ఏదైనా పేజీకి వెళ్లమని చెప్పవచ్చు (ఉదా., 'defendface కి వెళ్లండి')."
    }
}

@app.route('/api/chatbot', methods=['POST'])
@login_required
def chatbot():
    data = request.get_json()
    user_msg = data.get('message', '').strip()
    if not user_msg:
        return jsonify({'success': False, 'response': 'Please type a message.'})

    # Detect language
    lang = detect_language(user_msg)
    responses = chatbot_responses.get(lang, chatbot_responses['en'])

    # Check for navigation commands (in any language)
    msg_lower = user_msg.lower()
    nav_pages = {
        'defendface': 'defendface',
        'phishing': 'phishing',
        'dashboard': 'dashboard',
        'threat sources': 'threat_sources',
        'women safety': 'women_safety',
        'narishakthi': 'women_safety'
    }
    for phrase, page in nav_pages.items():
        if phrase in msg_lower:
            link = responses['navigation'].get(page, '#')
            return jsonify({'success': True, 'response': f"Here you go: {link}"})

    # Check for greetings
    greetings = ['hello', 'hi', 'hey', 'namaste', 'vanakkam', 'namaskaram']
    if any(greet in msg_lower for greet in greetings):
        import random
        greeting = random.choice(responses['greetings'])
        return jsonify({'success': True, 'response': greeting})

    # Keyword matching for topics
    topics = {
        'deepfake': 'deepfake',
        'phishing': 'phishing',
        'ransomware': 'ransomware',
        'password': 'password',
        'social media': 'social_media',
        'shopping': 'shopping',
        'women safety': 'women_safety',
        'नारी': 'women_safety',
        'பெண்கள்': 'women_safety',
        'మహిళ': 'women_safety'
    }
    for kw, topic in topics.items():
        if kw in msg_lower:
            return jsonify({'success': True, 'response': responses[topic]})

    # Fallback
    return jsonify({'success': True, 'response': responses['fallback']})

# ---------- PWA ----------
@app.route('/manifest.json')
def manifest():
    return send_file('static/manifest.json')

@app.route('/sw.js')
def service_worker():
    return send_file('static/sw.js')

@app.route('/offline.html')
def offline():
    return render_template('offline.html')

# ========== NEW API ENDPOINT FOR WOMEN SAFETY REPORTS ==========
@app.route('/api/report-women-incident', methods=['POST'])
@login_required
def report_women_incident():
    """File a women‑specific NCRP report (flagged for women safety)"""
    data = request.get_json()
    incident_type = data.get('incidentType', 'other')
    description = data.get('description', '')
    email = data.get('reporterEmail', current_user.email)

    if not description:
        return jsonify({'error': 'Description is required'}), 400

    # Get fingerprint for source tracking (optional)
    fingerprint = request.headers.get('X-Fingerprint')
    fingerprint_id = request.headers.get('X-Fingerprint-ID')
    source = None
    if fingerprint and fingerprint_id:
        source = get_or_create_source(fingerprint, fingerprint_id, {'email': email})

    # Generate IDs
    report_id = generate_report_id()
    case_id = generate_case_id()

    # Prepare evidence with women safety flag
    evidence = {
        'incident_type': incident_type,
        'description': description,
        'email': email,
        'fingerprint_id': fingerprint_id,
        'women_safety_flag': True
    }

    # Mock NCRP response
    ncrp_response = {
        'status': 'RECEIVED',
        'case_id': case_id,
        'acknowledgment': f"Your women safety report #{report_id} has been registered with NCRP",
        'priority': 'HIGH',
        'assigned_to': f"Women Safety Officer {random.choice(['Kavya', 'Sunita', 'Meera'])}"
    }

    # Create NCRPReport record with women_safety=True
    report = NCRPReport(
        report_id=report_id,
        threat_source_id=source.id if source else None,
        user_id=current_user.id,
        threat_type='women_safety_' + incident_type,
        threat_details=json.dumps({'description': description, 'email': email}),
        evidence=json.dumps(evidence),
        risk_score=90,  # high risk for women safety reports
        status='FILED',
        ncrp_case_id=case_id,
        ncrp_response=json.dumps(ncrp_response),
        women_safety=True
    )
    db.session.add(report)
    db.session.commit()

    # Optionally track a threat event (increment threat count for source)
    if source:
        track_threat(fingerprint, fingerprint_id, f'women_{incident_type}_reported', threat_data={
            'report_id': report_id,
            'incident_type': incident_type
        })

    return jsonify({
        'success': True,
        'report_id': report_id,
        'ncrp_case_id': case_id,
        'message': 'Your women safety report has been filed.'
    })

# ---------- RUN ----------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)