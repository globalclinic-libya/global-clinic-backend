# Global Clinic Backend API

🏥 **Professional Telemedicine Platform Backend**

A Flask-based API for the Global Clinic telemedicine platform.

## 🚀 **Quick Deploy to Railway**

This repository is configured for one-click deployment to Railway.

## 🌟 **Features**

- ✅ **JWT Authentication** for secure API access
- ✅ **Patient Registration** with OTP verification
- ✅ **Doctor Portal** with case management
- ✅ **Admin Dashboard** with user oversight
- ✅ **SQLite Database** with automatic setup

## 🔑 **Demo Credentials**

### **Admin Portal**
- **Email:** `admin@globalclinic.com`
- **Password:** `AdminGlobal2024!`

### **Doctor Portal**
- **Email:** `doctor@globalclinic.com`
- **Password:** `password123`

### **Patient Portal**
- **Mobile:** Any number (e.g., `+218912345678`)
- **OTP:** `123456`

## 📋 **API Endpoints**

- `GET /api/status` - Health check
- `POST /api/auth/register/patient/start` - Start patient registration
- `POST /api/auth/register/patient/verify` - Verify OTP
- `POST /api/auth/login` - Doctor/Admin login
- `GET /api/patient/cases` - Get patient cases
- `POST /api/patient/cases` - Submit new case
- `GET /api/doctor/cases` - Get doctor cases
- `POST /api/doctor/cases/{id}/report` - Submit medical report
- `GET /api/admin/users` - Get all users (admin only)
- `GET /api/admin/cases` - Get all cases (admin only)

## 🛠 **Technology Stack**

- **Framework:** Flask (Python)
- **Database:** SQLite with SQLAlchemy
- **Authentication:** JWT tokens
- **Deployment:** Railway.app ready

---

**Developed by Dr. Adnan Alganimi for global healthcare** 🌍

