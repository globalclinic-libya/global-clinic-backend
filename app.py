from flask import Flask, jsonify, request
from flask_cors import CORS
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'global-clinic-secret-key-2024'


# 🔹 for deploy on  Railway
CORS(app, origins=[
    "https://global-clinic-patients-production.up.railway.app",
    "https://global-clinic-doctors-production.up.railway.app",
    "https://global-clinic-admin-production.up.railway.app",
    "http://localhost:3000",  # patients
    "http://localhost:3001",  # doctors
    "http://localhost:3002",  # admin
])


#-----------------------------------------------------
# Enable CORS for Vercel frontend domains
# CORS(app, origins=[
#     "https://global-clinic-patients.vercel.app",
#     "https://global-clinic-doctors.vercel.app",
#     "https://global-clinic-admin.vercel.app",
#     "http://localhost:3000",  # For local development
#     "http://localhost:3001",
#     "http://localhost:3002"
# ])
#------------------------------------------------------


# In-memory storage (for demo)
users = {}
cases = {}
user_counter = 1
case_counter = 1


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
            current_user = users.get(data['user_id'])
        except Exception:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)
    return decorated


@app.route('/')
def home():
    return jsonify({"status": "healthy", "message": "Global Clinic API running on Railway"})


@app.route('/api/status')
def status():
    return jsonify({"status": "healthy", "message": "Global Clinic API running on Railway"})


@app.route('/api/auth/register/api/patient/start', methods=['POST'])
def patient_register():
    global user_counter
    data = request.get_json()
    mobile_number = data.get('mobile_number')

    if not mobile_number:
        return jsonify({'message': 'Mobile number is required'}), 400

    # Check if user already exists
    existing_user = None
    for user_id, user in users.items():
        if user.get('mobile_number') == mobile_number:
            existing_user = user
            break

    if not existing_user:
        # Create new user
        user_id = user_counter
        users[user_id] = {
            'id': user_id,
            'mobile_number': mobile_number,
            'role': 'patient',
            'is_verified': False
        }
        user_counter += 1

    # Return demo OTP
    return jsonify({
        'message': 'OTP sent successfully',
        'debug_otp': '123456',  # Demo OTP
        'mobile_number': mobile_number
    }), 200


@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    mobile_number = data.get('mobile_number')
    otp = data.get('otp')

    if not mobile_number or not otp:
        return jsonify({'message': 'Mobile number and OTP are required'}), 400

    # Demo OTP verification
    if otp != '123456':
        return jsonify({'message': 'Invalid OTP'}), 400

    # Find user
    user_id = None
    for uid, user in users.items():
        if user.get('mobile_number') == mobile_number:
            user_id = uid
            users[uid]['is_verified'] = True
            break

    if not user_id:
        return jsonify({'message': 'User not found'}), 404

    # Generate JWT token
    token = jwt.encode({
        'user_id': user_id,
        'role': 'patient',
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({
        'message': 'OTP verified successfully',
        'access_token': token,
        'user_id': user_id,
        'role': 'patient'
    }), 200


@app.route('/api/doctors/login', methods=['POST'])
def doctor_login():
    global user_counter
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Demo doctor credentials
    if email == 'doctor@globalclinic.com' and password == 'password123':
        user_id = 999  # Fixed doctor ID
        users[user_id] = {
            'id': user_id,
            'email': email,
            'role': 'doctor'
        }

        token = jwt.encode({
            'user_id': user_id,
            'role': 'doctor',
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({
            'message': 'Doctor login successful',
            'token': token,
            'user': users[user_id]
        }), 200

    return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    global user_counter
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    admin_key = data.get('admin_key')

    if (
        email == 'admin@globalclinic.com'
        and password == 'AdminGlobal2024!'
        and admin_key == 'GLOBAL_CLINIC_ADMIN_2024_SECURE_KEY'
      ):

        user_id = 998  # Fixed admin ID
        users[user_id] = {
            'id': user_id,
            'email': email,
            'role': 'admin'
        }

        token = jwt.encode({
            'user_id': user_id,
            'role': 'admin',
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({
            'message': 'Admin login successful',
            'token': token,
            'user': users[user_id]
        }), 200

    return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/api/patients/cases', methods=['GET'])
@token_required
def get_patient_cases(current_user):
    if current_user['role'] != 'patient':
        return jsonify({'message': 'Access denied'}), 403

    patient_cases = [case for case in cases.values() if case['patient_id'] == current_user['id']]
    return jsonify({'cases': patient_cases}), 200


@app.route('/api/patients/cases', methods=['POST'])
@token_required
def submit_case(current_user):
    global case_counter
    if current_user['role'] != 'patient':
        return jsonify({'message': 'Access denied'}), 403

    data = request.get_json()
    case_id = case_counter
    cases[case_id] = {
        'id': case_id,
        'patient_id': current_user['id'],
        'description': data.get('description', ''),
        'audio_transcript': data.get('audio_transcript', ''),
        'status': 'pending',
        'created_at': datetime.datetime.utcnow().isoformat()
    }
    case_counter += 1

    return jsonify({
        'message': 'Case submitted successfully',
        'case_id': case_id
    }), 201

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
