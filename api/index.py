import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'global-clinic-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///global_clinic.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Enable CORS for all routes
CORS(app, origins="*")

# Initialize database
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mobile_number = db.Column(db.String(20), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    status = db.Column(db.String(20), default='pending')
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
    return jsonify({"status": "healthy", "message": "Global Clinic API is running"})

@app.route('/api/patients/register', methods=['POST'])
def register_patient():
    data = request.get_json()
    mobile_number = data.get('mobile_number')
    otp = data.get('otp')
    
    if not mobile_number:
        return jsonify({'message': 'Mobile number is required'}), 400
    
    if otp and otp != '123456':
        return jsonify({'message': 'Invalid OTP'}), 400
    
    user = User.query.filter_by(mobile_number=mobile_number).first()
    if not user:
        user = User(
            mobile_number=mobile_number,
            role='patient',
            is_verified=True
        )
        db.session.add(user)
        db.session.commit()
    
    token = jwt.encode({
        'user_id': user.id,
        'role': user.role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({
        'message': 'Registration successful',
        'token': token,
        'user': {
            'id': user.id,
            'mobile_number': user.mobile_number,
            'role': user.role
        }
    }), 200

@app.route('/api/doctors/login', methods=['POST'])
def doctor_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400
    
    if email == 'doctor@globalclinic.com' and password == 'password123':
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
            'role': doctor.role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
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

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    admin_key = data.get('admin_key')
    
    if not email or not password or not admin_key:
        return jsonify({'message': 'Email, password, and admin key are required'}), 400
    
    if (email == 'admin@globalclinic.com' and 
        password == 'AdminGlobal2024!' and 
        admin_key == 'GLOBAL_CLINIC_ADMIN_2024_SECURE_KEY'):
        
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
            'role': admin.role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'message': 'Admin login successful',
            'token': token,
            'user': {
                'id': admin.id,
                'email': admin.email,
                'role': admin.role
            }
        }), 200
    
    return jsonify({'message': 'Invalid credentials'}), 401

# Initialize database
with app.app_context():
    db.create_all()

# Vercel handler
def handler(request):
    return app(request.environ, lambda status, headers: None)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
