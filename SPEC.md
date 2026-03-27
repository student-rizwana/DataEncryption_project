# Cloud Data Encryption System - Specification Document

## 1. Project Overview

**Project Name:** Cloud Data Encryption System  
**Project Type:** Full-stack Web Application  
**Core Functionality:** A secure cloud-based storage system where users can register, login, upload files that are encrypted client-side using AES-256, with AES keys encrypted using RSA-2048 for secure key exchange. Only authorized users can decrypt and download their files.  
**Target Users:** Individuals and organizations requiring secure cloud storage for sensitive data.

---

## 2. Technical Stack

### Backend
- **Framework:** Django 4.x with Django REST Framework
- **Language:** Python 3.x
- **Database:** MySQL (with SQLite fallback for development)
- **Cryptography:** cryptography library, PyCryptodome

### Frontend
- **HTML5** for structure
- **CSS3** with Bootstrap 5 for styling
- **JavaScript** for client-side encryption/decryption
- **Bootstrap 5** for responsive UI

### Security
- AES-256-CBC for file encryption
- RSA-2048 for AES key encryption
- PBKDF2 for password hashing
- CSRF protection
- Session-based authentication

---

## 3. UI/UX Specification

### Color Palette
- **Primary:** #1a1a2e (Deep Navy)
- **Secondary:** #16213e (Dark Blue)
- **Accent:** #0f3460 (Medium Blue)
- **Highlight:** #e94560 (Coral Red)
- **Success:** #00d9a5 (Teal Green)
- **Warning:** #ffc107 (Amber)
- **Background:** #0f0f1a (Near Black)
- **Card Background:** #1a1a2e
- **Text Primary:** #ffffff
- **Text Secondary:** #a0a0a0

### Typography
- **Headings:** 'Orbitron', sans-serif (futuristic/tech feel)
- **Body:** 'Rajdhani', sans-serif
- **Monospace:** 'Fira Code', monospace (for keys/codes)

### Layout Structure
- **Navigation:** Fixed top navbar with brand logo, nav links, user menu
- **Hero Section:** Full-width banner with animated background
- **Content:** Centered container with max-width 1200px
- **Cards:** Glassmorphism effect with subtle transparency
- **Footer:** Dark footer with links and copyright

### Responsive Breakpoints
- Mobile: < 576px
- Tablet: 576px - 992px
- Desktop: > 992px

### Visual Effects
- Smooth fade-in animations on page load
- Hover effects on buttons and cards (scale + glow)
- Progress bars for upload/download
- Password strength indicator
- Encryption status badges

---

## 4. Page Specifications

### 4.1 Home Page (index.html)
- Hero section with system introduction
- Features grid (Encryption, Security, Cloud Storage)
- Call-to-action buttons (Register, Login)
- Animated background with floating particles

### 4.2 Register Page (register.html)
- Username field
- Email field
- Password field with strength indicator
- Confirm password field
- Register button
- Link to login page

### 4.3 Login Page (login.html)
- Username/Email field
- Password field
- Remember me checkbox
- Login button
- Link to register page

### 4.4 Dashboard (dashboard.html)
- Welcome message with username
- Quick stats cards (Total Files, Encrypted, Storage Used)
- Recent files table with actions
- Upload button
- Search/filter functionality

### 4.5 Upload Page (upload.html)
- Drag-and-drop file upload area
- File browser button
- File info display (name, size, type)
- Progress bar during encryption/upload
- Encryption status indicator
- Cancel/Upload buttons

### 4.6 Files List Page (files.html)
- Table with columns: Name, Size, Upload Date, Status, Actions
- Search bar
- Filter dropdown (All, Encrypted, Decrypted)
- Action buttons (Download, Delete, Share)

### 4.7 Download Page (download.html)
- File information display
- Decryption progress indicator
- Download button
- Return to files link

---

## 5. Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(150) UNIQUE NOT NULL,
    email VARCHAR(254) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    public_key TEXT,
    private_key_encrypted TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
);
```

### Files Table
```sql
CREATE TABLE files (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    original_name VARCHAR(255) NOT NULL,
    file_size BIGINT,
    encrypted_file_path VARCHAR(500),
    encrypted_aes_key TEXT,
    iv TEXT,
    upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### Encryption Keys Table
```sql
CREATE TABLE encryption_keys (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    private_key_encrypted TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

---

## 6. Security Features

### 6.1 Client-Side Encryption Flow
1. User selects file to upload
2. JavaScript generates random AES-256 key
3. File is encrypted using AES-256-CBC
4. AES key is encrypted using RSA public key
5. Encrypted file + encrypted AES key + IV sent to server

### 6.2 Decryption Flow
1. User requests file download
2. Server returns encrypted file + encrypted AES key + IV
3. JavaScript decrypts AES key using RSA private key
4. File is decrypted using decrypted AES key
5. Original file is downloaded

### 6.3 Authentication
- PBKDF2 password hashing with salt
- Session-based authentication
- CSRF token protection
- Secure password requirements (min 8 chars, mixed case, numbers)

---

## 7. API Endpoints

### Authentication
- `POST /api/register/` - User registration
- `POST /api/login/` - User login
- `POST /api/logout/` - User logout
- `GET /api/user/` - Get current user

### Files
- `POST /api/files/upload/` - Upload encrypted file
- `GET /api/files/` - List user's files
- `GET /api/files/<id>/` - Get file details
- `GET /api/files/<id>/download/` - Download file (returns encrypted data)
- `DELETE /api/files/<id>/` - Delete file

### Keys
- `GET /api/keys/generate/` - Generate RSA key pair for user

---

## 8. Acceptance Criteria

### Authentication
- [ ] User can register with valid credentials
- [ ] User can login with correct username/password
- [ ] Invalid credentials show appropriate errors
- [ ] Password is securely hashed

### File Upload
- [ ] User can select file via drag-drop or file browser
- [ ] File is encrypted client-side before upload
- [ ] Progress indicator shows during upload
- [ ] Success message after upload completes
- [ ] File metadata stored in database

### File Download
- [ ] User can view list of their files
- [ ] User can download their encrypted files
- [ ] File is decrypted client-side
- [ ] Original file is restored correctly

### Security
- [ ] AES-256 encryption is used for files
- [ ] RSA-2048 is used for key exchange
- [ ] Only file owner can access their files
- [ ] Passwords are hashed not stored in plain text

### UI/UX
- [ ] All pages are responsive
- [ ] Loading states are displayed
- [ ] Error messages are user-friendly
- [ ] Animations are smooth

---

## 9. Project Structure

```
CloudDataEncryption/
├── manage.py
├── requirements.txt
├── CloudDataEncryption/
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   ├── wsgi.py
├── encryption/
│   ├── __init__.py
│   ├── models.py
│   ├── views.py
│   ├── urls.py
│   ├── serializers.py
│   ├── encryption_utils.py
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── register.html
│   ├── login.html
│   ├── dashboard.html
│   ├── upload.html
│   ├── files.html
│   ├── download.html
├── static/
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   ├── encryption.js
│   │   ├── auth.js
│   │   └── main.js
├── media/
│   └── encrypted_files/
└── SPEC.md
```

