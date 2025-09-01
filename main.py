import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'global-clinic-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///global_clinic.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Enable CORS for all routes
CORS(app, origins="*")

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mobile_number = db.Column(db.String(20), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False)  # patient, doctor, admin
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, assigned, completed
    audio_transcript_en = db.Column(db.Text)
    doctor_report = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# JWT Token decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# API Routes
@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({"status": "ok", "message": "Global Clinic API is running"})

@app.route('/api/auth/register/patient/start', methods=['POST'])
def register_patient_start():
    data = request.get_json()
    mobile_number = data.get('mobile_number')
    
    if not mobile_number:
        return jsonify({'message': 'Mobile number is required'}), 400
    
    # Generate OTP (for demo, we'll use a fixed OTP)
    otp = '123456'
    
    # Check if user already exists
    existing_user = User.query.filter_by(mobile_number=mobile_number).first()
    if existing_user:
        return jsonify({'message': 'User already exists', 'otp_sent': True}), 200
    
    return jsonify({'message': 'OTP sent successfully', 'otp_sent': True}), 200

@app.route('/api/auth/register/patient/verify', methods=['POST'])
def register_patient_verify():
    data = request.get_json()
    mobile_number = data.get('mobile_number')
    otp = data.get('otp')
    
    if not mobile_number or not otp:
        return jsonify({'message': 'Mobile number and OTP are required'}), 400
    
    # For demo, accept any OTP
    if otp != '123456':
        return jsonify({'message': 'Invalid OTP'}), 400
    
    # Create or get user
    user = User.query.filter_by(mobile_number=mobile_number).first()
    if not user:
        user = User(mobile_number=mobile_number, role='patient', is_verified=True)
        db.session.add(user)
        db.session.commit()
    
    # Generate JWT token
    token = jwt.encode({
        'user_id': user.id,
        'role': user.role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({
        'message': 'Registration successful',
        'access_token': token,
        'token_type': 'bearer',
        'user_id': user.id,
        'role': user.role
    }), 200

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400
    
    # Find user by email
    user = User.query.filter_by(email=email).first()
    
    # For demo purposes, create accounts if they don't exist
    if not user:
        if email == 'doctor@globalclinic.com':
            password_hash = generate_password_hash('password123')
            user = User(email=email, password_hash=password_hash, role='doctor', is_verified=True)
        elif email == 'admin@globalclinic.com':
            password_hash = generate_password_hash('AdminGlobal2024!')
            user = User(email=email, password_hash=password_hash, role='admin', is_verified=True)
        
        if user:
            db.session.add(user)
            db.session.commit()
    
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    # Generate JWT token
    token = jwt.encode({
        'user_id': user.id,
        'role': user.role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({
        'message': 'Login successful',
        'access_token': token,
        'token_type': 'bearer',
        'user_id': user.id,
        'role': user.role
    }), 200

@app.route('/api/patient/cases', methods=['GET'])
@token_required
def get_patient_cases(current_user):
    if current_user.role != 'patient':
        return jsonify({'message': 'Access denied'}), 403
    
    cases = Case.query.filter_by(patient_id=current_user.id).all()
    
    cases_data = []
    for case in cases:
        cases_data.append({
            'id': case.id,
            'status': case.status,
            'audio_transcript_en': case.audio_transcript_en,
            'doctor_report': case.doctor_report,
            'created_at': case.created_at.isoformat()
        })
    
    return jsonify(cases_data), 200

@app.route('/api/patient/cases', methods=['POST'])
@token_required
def submit_case(current_user):
    if current_user.role != 'patient':
        return jsonify({'message': 'Access denied'}), 403
    
    # For demo, create a case with sample data
    case = Case(
        patient_id=current_user.id,
        status='pending',
        audio_transcript_en='Patient describes pain in lower back, difficulty walking, symptoms started 3 days ago.'
    )
    db.session.add(case)
    db.session.commit()
    
    return jsonify({
        'message': 'Case submitted successfully',
        'case_id': case.id
    }), 201

@app.route('/api/doctor/cases', methods=['GET'])
@token_required
def get_doctor_cases(current_user):
    if current_user.role != 'doctor':
        return jsonify({'message': 'Access denied'}), 403
    
    # For demo, return all pending cases
    cases = Case.query.filter_by(status='pending').all()
    
    cases_data = []
    for case in cases:
        patient = User.query.get(case.patient_id)
        cases_data.append({
            'id': case.id,
            'patient_id': case.patient_id,
            'patient_mobile': patient.mobile_number if patient else 'Unknown',
            'status': case.status,
            'audio_transcript_en': case.audio_transcript_en,
            'created_at': case.created_at.isoformat()
        })
    
    return jsonify(cases_data), 200

@app.route('/api/doctor/cases/<int:case_id>', methods=['GET'])
@token_required
def get_case_detail(current_user, case_id):
    if current_user.role != 'doctor':
        return jsonify({'message': 'Access denied'}), 403
    
    case = Case.query.get_or_404(case_id)
    patient = User.query.get(case.patient_id)
    
    return jsonify({
        'id': case.id,
        'patient_id': case.patient_id,
        'patient_mobile': patient.mobile_number if patient else 'Unknown',
        'status': case.status,
        'audio_transcript_en': case.audio_transcript_en,
        'doctor_report': case.doctor_report,
        'created_at': case.created_at.isoformat()
    }), 200

@app.route('/api/doctor/cases/<int:case_id>/report', methods=['POST'])
@token_required
def submit_report(current_user, case_id):
    if current_user.role != 'doctor':
        return jsonify({'message': 'Access denied'}), 403
    
    data = request.get_json()
    report = data.get('report')
    
    if not report:
        return jsonify({'message': 'Report is required'}), 400
    
    case = Case.query.get_or_404(case_id)
    case.doctor_report = report
    case.doctor_id = current_user.id
    case.status = 'completed'
    db.session.commit()
    
    return jsonify({'message': 'Report submitted successfully'}), 200

@app.route('/api/admin/users', methods=['GET'])
@token_required
def get_all_users(current_user):
    if current_user.role != 'admin':
        return jsonify({'message': 'Access denied'}), 403
    
    users = User.query.all()
    users_data = []
    for user in users:
        users_data.append({
            'id': user.id,
            'mobile_number': user.mobile_number,
            'email': user.email,
            'role': user.role,
            'is_verified': user.is_verified,
            'created_at': user.created_at.isoformat()
        })
    
    return jsonify(users_data), 200

@app.route('/api/admin/cases', methods=['GET'])
@token_required
def get_all_cases(current_user):
    if current_user.role != 'admin':
        return jsonify({'message': 'Access denied'}), 403
    
    cases = Case.query.all()
    cases_data = []
    for case in cases:
        patient = User.query.get(case.patient_id)
        doctor = User.query.get(case.doctor_id) if case.doctor_id else None
        
        cases_data.append({
            'id': case.id,
            'patient_id': case.patient_id,
            'patient_mobile': patient.mobile_number if patient else 'Unknown',
            'doctor_id': case.doctor_id,
            'doctor_email': doctor.email if doctor else 'Unassigned',
            'status': case.status,
            'created_at': case.created_at.isoformat()
        })
    
    return jsonify(cases_data), 200

# Initialize database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

