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

# Routes
@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({"status": "ok", "message": "Global Clinic API is running"})

@app.route('/api/patients/register', methods=['POST'])
def register_patient():
    data = request.get_json()
    mobile_number = data.get('mobile_number')
    otp = data.get('otp')
    
    if not mobile_number:
        return jsonify({'message': 'Mobile number is required'}), 400
    
    # For demo purposes, accept any OTP as 123456
    if otp and otp != '123456':
        return jsonify({'message': 'Invalid OTP'}), 400
    
    # Check if user already exists
    existing_user = User.query.filter_by(mobile_number=mobile_number).first()
    if existing_user:
        if not otp:
            return jsonify({'message': 'OTP sent', 'requires_otp': True}), 200
        else:
            existing_user.is_verified = True
            db.session.commit()
            
            token = jwt.encode({
                'user_id': existing_user.id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, app.config['SECRET_KEY'])
            
            return jsonify({
                'message': 'Login successful',
                'token': token,
                'user': {
                    'id': existing_user.id,
                    'mobile_number': existing_user.mobile_number,
                    'role': existing_user.role
                }
            }), 200
    
    if not otp:
        return jsonify({'message': 'OTP sent', 'requires_otp': True}), 200
    
    # Create new user
    new_user = User(
        mobile_number=mobile_number,
        role='patient',
        is_verified=True
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    token = jwt.encode({
        'user_id': new_user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'])
    
    return jsonify({
        'message': 'Registration successful',
        'token': token,
        'user': {
            'id': new_user.id,
            'mobile_number': new_user.mobile_number,
            'role': new_user.role
        }
    }), 201

@app.route('/api/patients/cases', methods=['POST'])
@token_required
def submit_case(current_user):
    if current_user.role != 'patient':
        return jsonify({'message': 'Access denied'}), 403
    
    data = request.get_json()
    audio_transcript = data.get('audio_transcript_en', '')
    
    new_case = Case(
        patient_id=current_user.id,
        audio_transcript_en=audio_transcript,
        status='pending',
        created_at=datetime.datetime.utcnow()
    )
    
    db.session.add(new_case)
    db.session.commit()
    
    return jsonify({
        'message': 'Case submitted successfully',
        'case_id': new_case.id
    }), 201

@app.route('/api/patients/cases', methods=['GET'])
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

@app.route('/api/doctors/login', methods=['POST'])
def doctor_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400
    
    # For demo purposes, accept doctor@globalclinic.com with password123
    if email == 'doctor@globalclinic.com' and password == 'password123':
        # Check if doctor user exists, create if not
        doctor = User.query.filter_by(email=email).first()
        if not doctor:
            doctor = User(
                email=email,
                password_hash=generate_password_hash(password),
                role='doctor',
                is_verified=True
            )
            db.session.add(doctor)
            db.session.commit()
        
        token = jwt.encode({
            'user_id': doctor.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': doctor.id,
                'email': doctor.email,
                'role': doctor.role
            }
        }), 200
    
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/doctors/cases', methods=['GET'])
@token_required
def get_pending_cases(current_user):
    if current_user.role != 'doctor':
        return jsonify({'message': 'Access denied'}), 403
    
    cases = Case.query.filter_by(status='pending').all()
    cases_data = []
    
    for case in cases:
        patient = User.query.get(case.patient_id)
        cases_data.append({
            'id': case.id,
            'patient_id': case.patient_id,
            'patient_mobile': patient.mobile_number if patient else 'Unknown',
            'audio_transcript_en': case.audio_transcript_en,
            'status': case.status,
            'created_at': case.created_at.isoformat()
        })
    
    return jsonify(cases_data), 200

@app.route('/api/doctors/cases/<int:case_id>/report', methods=['POST'])
@token_required
def submit_report(current_user, case_id):
    if current_user.role != 'doctor':
        return jsonify({'message': 'Access denied'}), 403
    
    data = request.get_json()
    report = data.get('report')
    
    if not report:
        return jsonify({'message': 'Report is required'}), 400
    
    case = Case.query.get(case_id)
    if not case:
        return jsonify({'message': 'Case not found'}), 404
    
    case.doctor_id = current_user.id
    case.doctor_report = report
    case.status = 'completed'
    
    db.session.commit()
    
    return jsonify({'message': 'Report submitted successfully'}), 200

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    admin_key = data.get('admin_key')
    
    if not all([email, password, admin_key]):
        return jsonify({'message': 'Email, password, and admin key are required'}), 400
    
    # For demo purposes
    if (email == 'admin@globalclinic.com' and 
        password == 'AdminGlobal2024!' and 
        admin_key == 'GLOBAL_CLINIC_ADMIN_2024_SECURE_KEY'):
        
        # Check if admin user exists, create if not
        admin = User.query.filter_by(email=email).first()
        if not admin:
            admin = User(
                email=email,
                password_hash=generate_password_hash(password),
                role='admin',
                is_verified=True
            )
            db.session.add(admin)
            db.session.commit()
        
        token = jwt.encode({
            'user_id': admin.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': admin.id,
                'email': admin.email,
                'role': admin.role
            }
        }), 200
    
    return jsonify({'message': 'Invalid credentials'}), 401

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

# Vercel handler
def handler(request):
    return app(request.environ, lambda status, headers: None)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

