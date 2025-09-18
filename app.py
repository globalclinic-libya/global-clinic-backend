from flask import Flask, jsonify, request
from flask_cors import CORS
import jwt
import datetime
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'global-clinic-secret-key-2024'

# ✅ تم إصلاح المسافات الزائدة في origins

# قائمة النطاقات المسموحة
ALLOWED_ORIGINS = [
    "https://global-clinic-patients-production.up.railway.app",
    "https://global-clinic-doctors-production.up.railway.app",
    "https://global-clinic-admin-production.up.railway.app"
]

CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)


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
            
            # ✅ تأكد أن المستخدم موجود
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
                
        except Exception as e:
            print("Token error:", str(e))  # للتنقيح فقط
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
        user_id = user_counter
        users[user_id] = {
            'id': user_id,
            'mobile_number': mobile_number,
            'role': 'patient',
            'is_verified': False
        }
        user_counter += 1
    
    return jsonify({
        'message': 'OTP sent successfully',
        'debug_otp': '123456',
        'mobile_number': mobile_number
    }), 200


@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    mobile_number = data.get('mobile_number')
    otp = data.get('otp')
    
    if not mobile_number or not otp:
        return jsonify({'message': 'Mobile number and OTP are required'}), 400
    
    if otp != '123456':
        return jsonify({'message': 'Invalid OTP'}), 400
    
    user_id = None
    for uid, user in users.items():
        if user.get('mobile_number') == mobile_number:
            user_id = uid
            users[uid]['is_verified'] = True
            break
    
    if not user_id:
        return jsonify({'message': 'User not found'}), 404
    
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
    
    if email == 'doctor@globalclinic.com' and password == 'password123':
        user_id = 999
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
    
    if (email == 'admin@globalclinic.com' and 
        password == 'AdminGlobal2024!' and 
        admin_key == 'GLOBAL_CLINIC_ADMIN_2024_SECURE_KEY'):
        
        user_id = 998
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
            'access_token': token,           # ← تم التغيير من 'token' إلى 'access_token'
            'user_id': user_id,
            'role': 'admin',
            'admin_key': admin_key
        }), 200
    
    return jsonify({'message': 'Invalid credentials'}), 401


# ✅ دعم JSON و FormData بشكل آمن
@app.route('/api/patients/cases', methods=['GET'])
@token_required
def get_patient_cases(current_user):
    if current_user['role'] not in ['patient', 'doctor']:
        return jsonify({'message': 'Access denied'}), 403

    # تحويل الحالات إلى قائمة نظيفة
    result_cases = []
    for case in cases.values():
        result_cases.append({
            'id': int(case['id']),
            'patient_id': int(case['patient_id']),
            'description': case['description'],
            'status': case['status'],
            'created_at': case['created_at'],
            'audio_file_path': case.get('audio_file_path'),
            'document_file_paths': case.get('document_file_paths'),
            'diagnosis': case.get('diagnosis'),
            'report_text': case.get('report_text'),
            'reported_at': case.get('reported_at')
        })

    if current_user['role'] == 'patient':
        filtered = [c for c in result_cases if c['patient_id'] == current_user['id']]
        return jsonify({'cases': filtered}), 200

    return jsonify({'cases': result_cases}), 200

# ✅ دعم JSON فقط (آمن - لا يكسر أي تطبيق حالي)
@app.route('/api/patients/cases', methods=['POST'])
@token_required
def submit_case(current_user):
    global case_counter
    if not current_user or current_user['role'] != 'patient':
        return jsonify({'message': 'Access denied'}), 403

    # دعم JSON و FormData
    if request.is_json:
        data = request.get_json()
        description = data.get('description')
    else:
        description = request.form.get('description')

    if not description:
        return jsonify({'message': 'Description is required'}), 400

    # التعامل مع الملف الصوتي (اختياري)
    audio_filename = None
    audio_file = request.files.get('audio_file')
    if audio_file:
        audio_filename = f"audio_{case_counter}_{audio_file.filename}"

    # التعامل مع المستندات (اختياري)
    document_filenames = []
    document_files = request.files.getlist('document_files')
    for doc in document_files:
        document_filenames.append(f"doc_{case_counter}_{doc.filename}")

    # حفظ الحالة
    case_id = case_counter
    cases[case_id] = {
        'id': case_id,
        'patient_id': current_user['id'],
        'description': description,
        'status': 'pending',
        'created_at': datetime.datetime.utcnow().isoformat(),
        'audio_file_path': audio_filename,
        'document_file_paths': document_filenames if document_filenames else None
    }
    case_counter += 1

    return jsonify({
        'message': 'Case submitted successfully',
        'case_id': case_id
    }), 201



@app.route('/api/doctors/case/<int:case_id>/report', methods=['POST'])
@token_required
def submit_report(current_user, case_id):
    if not current_user or current_user['role'] != 'doctor':
        return jsonify({'message': 'Access denied'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'message': 'No report data provided'}), 400

    # تأكد من أن الحالة موجودة
    if case_id not in cases:
        return jsonify({'message': 'Case not found'}), 404

    # تحديث الحالة بالتقرير
    cases[case_id]['diagnosis'] = data.get('diagnosis')
    cases[case_id]['report_text'] = data.get('report_text', '')
    cases[case_id]['reported_at'] = datetime.datetime.utcnow().isoformat()
    cases[case_id]['status'] = 'completed'

    return jsonify({'message': 'Report submitted successfully'}), 200


# --- Admin Routes ---
@app.route('/api/admin/dashboard/stats', methods=['GET'])
@token_required
def admin_dashboard_stats(current_user):
    if current_user['role'] != 'admin':
        return jsonify({'message': 'Access denied'}), 403

    total_patients = sum(1 for u in users.values() if u['role'] == 'patient')
    total_doctors = sum(1 for u in users.values() if u['role'] == 'doctor')
    total_cases = len(cases)
    total_revenue = total_cases * 200  # $200 per case

    return jsonify({
        'total_users': total_patients + total_doctors,
        'total_patients': total_patients,
        'total_doctors': total_doctors,
        'total_cases': total_cases,
        'total_revenue': total_revenue,
        'system_health': 'excellent'
    }), 200


@app.route('/api/admin/cases', methods=['GET'])
@token_required
def admin_get_all_cases(current_user):
    if current_user['role'] != 'admin':
        return jsonify({'message': 'Access denied'}), 403

    return jsonify(list(cases.values())), 200


@app.route('/api/admin/users', methods=['GET'])
@token_required
def admin_get_all_users(current_user):
    if current_user['role'] != 'admin':
        return jsonify({'message': 'Access denied'}), 403

    result = []
    for uid, user in users.items():
        result.append({
            'id': uid,
            'role': user['role'],
            'email': user.get('email'),
            'mobile_number': user.get('mobile_number'),
            'is_active': True,
            'created_at': datetime.datetime.utcnow().isoformat(),
            'last_login': datetime.datetime.utcnow().isoformat()
        })
    return jsonify(result), 200


@app.route('/api/admin/transactions', methods=['GET'])
@token_required
def admin_get_transactions(current_user):
    if current_user['role'] != 'admin':
        return jsonify({'message': 'Access denied'}), 403

    transactions = []
    for cid, case in cases.items():
        if case['status'] == 'completed':
            transactions.append({
                'id': cid,
                'type': 'payment',
                'case_id': cid,
                'patient_id': case['patient_id'],
                'doctor_id': 2,
                'amount': 200,
                'platform_share': 120,
                'status': 'completed',
                'created_at': case['created_at'],
                'payment_method': 'Plutu'
            })
            transactions.append({
                'id': f"p{cid}",
                'type': 'payout',
                'case_id': cid,
                'patient_id': case['patient_id'],
                'doctor_id': 2,
                'amount': 80,
                'platform_share': None,
                'status': 'completed',
                'created_at': case['created_at'],
                'payment_method': 'Bank Transfer'
            })
    return jsonify(transactions), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
