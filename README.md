# Global Clinic Backend API - Vercel Compatible

## 🏥 **Global Clinic Telemedicine Platform Backend**

A comprehensive Flask-based API for the Global Clinic telemedicine platform, optimized for Vercel serverless deployment.

## 🚀 **Features**

### **Patient Management**
- Mobile number registration with OTP verification
- Case submission with audio transcription
- Case status tracking and history

### **Doctor Portal**
- Email/password authentication
- Pending case management
- Medical report submission
- Case assignment and completion

### **Admin Dashboard**
- Three-factor authentication (email, password, admin key)
- Complete platform oversight
- User and case management
- System analytics and monitoring

## 📋 **API Endpoints**

### **System**
- `GET /api/status` - Health check

### **Patient Endpoints**
- `POST /api/patients/register` - Register/login with mobile + OTP
- `POST /api/patients/cases` - Submit new case
- `GET /api/patients/cases` - Get patient's cases

### **Doctor Endpoints**
- `POST /api/doctors/login` - Doctor authentication
- `GET /api/doctors/cases` - Get pending cases
- `POST /api/doctors/cases/{id}/report` - Submit medical report

### **Admin Endpoints**
- `POST /api/admin/login` - Admin authentication
- `GET /api/admin/cases` - Get all cases

## 🔐 **Demo Credentials**

### **Doctor Login**
- **Email:** `doctor@globalclinic.com`
- **Password:** `password123`

### **Admin Login**
- **Email:** `admin@globalclinic.com`
- **Password:** `AdminGlobal2024!`
- **Admin Key:** `GLOBAL_CLINIC_ADMIN_2024_SECURE_KEY`

### **Patient Registration**
- **Mobile:** Any Libyan number (e.g., `+218912345678`)
- **OTP:** `123456` (demo OTP)

## 🛠 **Technology Stack**

- **Framework:** Flask 2.3.3
- **Database:** SQLite (with SQLAlchemy ORM)
- **Authentication:** JWT tokens
- **CORS:** Enabled for all origins
- **Deployment:** Vercel serverless functions

## 🌍 **Deployment**

This backend is optimized for Vercel deployment with:
- Serverless function architecture
- Automatic scaling
- Global CDN distribution
- HTTPS/SSL encryption

## 📊 **Database Schema**

### **Users Table**
- ID, mobile_number, email, password_hash
- Role (patient/doctor/admin)
- Verification status and timestamps

### **Cases Table**
- ID, patient_id, doctor_id
- Status (pending/assigned/completed)
- Audio transcript and doctor report
- Creation timestamps

## 🔒 **Security Features**

- JWT token authentication
- Password hashing with Werkzeug
- Role-based access control
- CORS protection
- Admin key verification

---

**Developed for Global Clinic - Telemedicine Platform**
**Optimized for Vercel Serverless Deployment**

