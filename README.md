# SecureVoteX™ — Complete Election Management Platform

SecureVoteX™ is a secure, networked college smart voting system integrating IoT hardware (ESP32) and modern web-based monitoring. It combines biometrics (fingerprint templates) and RFID cards for state-of-the-art electronic voter validation and real-time cryptography.

## 🚀 Key Features

* **Voter & Candidate Management (CRUD)**: Complete database panel to enroll, edit, delete, and monitor voters and candidates.
* **Biometric & RFID Authentication**: Stateless `/api/verify-rfid` and `/api/verify-fingerprint` endpoints with secure backend database lookups.
* **Security Operations Center (SOC)**:
  * **Live Authentication Monitor**: Real-time event log for sensor states, authentication successes, and rejections.
  * **Cryptographic Policy Grade**: Dashboard indicators tracking TLS status, HMAC-SHA256 payload validation, and anti-replay sequence verification.
  * **Intrusion Detection**: Logs and graphs tracking tampered packets, sequence violations, and double voting attempts.
* **Hardware Status Panel**: Dynamic sensor status, active booth counts, and heartbeats driven by active ESP32 booths or built-in software simulators.
* **Interactive Live Workflow Simulator**: A step-by-step graphical flowchart with manual or auto-pilot runner modes to trace votes from RFID scan to database sync.
* **Admin Role-Based Access Control (RBAC)**: Distinct permissions for `SUPER_ADMIN`, `ELECTION_OFFICER`, `AUDITOR`, and `VIEWER` roles.
* **Security Hardening**: Exclusively salted bcrypt hashing for passwords, CSRF protection bypass exemption rules for stateless API routes, and XSS defensive filters.

---

## 🛠️ Technology Stack

* **Backend**: Python, Flask, Flask-SocketIO, SQLite3
* **Frontend**: HTML5, Vanilla CSS (Premium Glassmorphism Design), JavaScript (Socket.IO client, Chart.js)
* **Firmware**: C++, PlatformIO, Espressif ESP32 dev framework, `marcoschwartz/LiquidCrystal_I2C` LCD library (Address `0x27`)

---

## ⚡ Quick Start Guide (Windows PowerShell)

1. **Activate Virtual Environment**:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
2. **Configure Python module path**:
   ```powershell
   $env:PYTHONPATH="voting_system"
   ```
3. **Start the server**:
   ```powershell
   python voting_system/start_system.py
   ```
4. **Access the platform**:
   * **Dashboard**: [http://127.0.0.1:5000/](http://127.0.0.1:5000/)
   * **Public Results View**: [http://127.0.0.1:5000/public-results](http://127.0.0.1:5000/public-results)
   * **Hardware Ping**: [http://127.0.0.1:5000/api/ping](http://127.0.0.1:5000/api/ping)
