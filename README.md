# SecureVoteX™ — Complete Election Management Platform

SecureVoteX™ is a cryptographically secured, networked electronic voting platform designed to integrate Internet of Things (IoT) hardware booths with a central monitoring server. It leverages multi-factor authentication (RFID + Biometrics), timing-safe HMAC message signatures, and live Socket.IO diagnostics to protect against double-voting, replay attacks, and packet tampering.

---

## 📐 Project Architecture

```text
                                  +-----------------------------+
                                  |     Central Flask Server     |
                                  |  (SocketIO + SQLite DB +    |
                                  |   HMAC-SHA256 Verifier)     |
                                  +--------------+--------------+
                                                 |
                       +-------------------------+-------------------------+
                       | HTTP / Websocket (JSON)                           | MQTT / TLS (Legacy / Simulator)
                       v                                                   v
       +---------------+---------------+                   +---------------+---------------+
       |       Web Dashboard           |                   |    ESP32 Hardware Booth      |
       |  - SOC Analytics Panel        |                   |  - I2C 16x2 LCD Display (0x27)|
       |  - Candidate Management CRUD  |                   |  - AS608 Fingerprint Reader   |
       |  - Voter Management CRUD      |                   |  - MFRC522 RFID Card Scanner  |
       |  - Live Workflow Simulator    |                   |  - Status LEDs & Buzzer Beep  |
       +-------------------------------+                   +-------------------------------+
```

---

## 📂 Project Structure

```text
VOTING SYSTEM/
├── firmware/                        # ESP32 C++ PlatformIO Project
│   ├── include/                     # Header files (.h)
│   │   ├── config.h                 # Pins, WiFi credentials, topics, and constants
│   │   ├── lcd_manager.h            # Class for 16x2 I2C LCD control
│   │   ├── fingerprint_manager.h    # Class for AS608 fingerprint validation
│   │   └── security_manager.h       # SHA256 HMAC payload signing engine
│   └── src/                         # Implementation source files (.cpp)
│       ├── main.cpp                 # Finite State Machine (FSM) main loops
│       └── lcd_manager.cpp          # LCD character layouts and backlight methods
│
├── voting_system/                   # Central Flask Server & Dashboard Web Application
│   ├── config/
│   │   └── config.py                # Database paths, cryptographic keys, and options
│   ├── database/
│   │   ├── schema.sql               # SQLite DDL schema creation script
│   │   ├── seed_data.py             # Pre-registers candidates, admins, and 100 voters
│   │   └── voting.db                # Active SQLite database file
│   ├── server/
│   │   ├── app.py                   # Flask server initialization and extension setup
│   │   ├── routes.py                # REST Endpoints (verify-rfid, verify-fingerprint, vote, ping)
│   │   ├── database.py              # SQLite helper functions
│   │   ├── vote_verifier.py         # Signature audit, anti-replay sequence checks, and database commits
│   │   └── socketio_handler.py      # Real-time dashboard broadcast events wrapper
│   └── dashboard/
│       ├── templates/
│       │   ├── index.html           # Main Admin dashboard & Live Simulator template
│       │   └── public_results.html  # Guest results board (auth-free)
│       └── static/
│           ├── css/style.css        # Premium custom Glassmorphic dark styling
│           └── js/dashboard.js      # Dynamic chart renderer, simulators, and websocket feeds
│
└── README.md                        # Master technical documentation
```

---

## 🔒 Security & Cryptographic Protocols

1. **Multi-Factor Authentication (MFA)**:
   * **Factor 1 (Possession)**: RFID Card (scanned UID queried against registered voters).
   * **Factor 2 (Inherence)**: Biometric Fingerprint (template slot match corresponding to the cardholder).
2. **Timing-Safe HMAC-SHA256 Payload Signature**:
   * Machine-to-machine vote submissions carry an HMAC signature.
   * Signature is computed as: `HMAC-SHA256(SecretKey, RFID + Candidate + BoothID + SequenceNumber + Uptime)`.
   * The server runs a timing-safe comparative check (`hmac.compare_digest`) to prevent timing side-channel attacks.
3. **Replay Attack Protection**:
   * The database maintains a `vote_sequence` table for each voter.
   * Every cast ballot must carry a sequence number strictly greater than the last recorded number.
   * Duplicate or decremented sequence payloads are flagged as intrusion threats and rejected.
4. **Session-Exempt & CSRF-Exempt Hardware APIs**:
   * Browser requests require full CSRF validation and session cookies.
   * Microcontroller routes (`/api/verify-rfid`, `/api/verify-fingerprint`, `/api/vote`, `/api/ping`) bypass CSRF checks to allow direct POST requests from embedded controllers.

---

## 🗄️ Database Schema Design

* **`voters`**: Stores RFID ID (Primary Key), voter name, fingerprint template slot number, voted status, and timestamp.
* **`votes`**: Encodes cast ballots containing the voter ID, candidate choice, booth source ID, timestamp, and verification hash.
* **`vote_sequence`**: Tracks the last sequence number per voter for anti-replay verification.
* **`audit_log`**: Records all access requests, authentications, rejections, and intrusion alerts with IP and severity.
* **`booths`**: Registers hardware IDs, descriptions, locations, and active status.
* **`admins`**: Stores administrative credentials with secure bcrypt hashing.

---

## 🖥️ ESP32 Hardware Wiring Reference

| Component | Pin (ESP32 DevKit) | Description |
| :--- | :--- | :--- |
| **I2C LCD SDA** | `GPIO 21` | Data line for 16x2 Character Display (I2C Address `0x27`) |
| **I2C LCD SCL** | `GPIO 22` | Clock line for 16x2 Character Display |
| **RFID SDA (SS)**| `GPIO 21` / `GPIO 5` | SPI Chip Select for MFRC522 |
| **RFID SCK** | `GPIO 18` | SPI Clock |
| **RFID MOSI** | `GPIO 23` | SPI MOSI |
| **RFID MISO** | `GPIO 19` | SPI MISO |
| **RFID RST** | `GPIO 22` / `GPIO 0` | Reset Line |
| **Fingerprint TX**| `GPIO 16` (RX2) | UART Data line from AS608 to ESP32 |
| **Fingerprint RX**| `GPIO 17` (TX2) | UART Data line from ESP32 to AS608 |
| **Status LED Green**| `GPIO 12` | High output on successful auth/vote recorded |
| **Status LED Red**| `GPIO 14` | High output (pulsed) on auth failure or invalid state |
| **Buzzer** | `GPIO 15` | Acoustic confirmation beeps |

---

## 📡 API Specifications

### 1. `GET /api/ping`
Tests hardware connection to the server.
* **Response (HTTP 200)**:
  ```json
  {
    "status": "online",
    "message": "SecureVoteX Server Running"
  }
  ```

### 2. `POST /api/verify-rfid`
Verifies if an RFID UID card is enrolled in the central database.
* **Request Payload**:
  ```json
  { "rfid_uid": "57 92 27 64" }
  ```
* **Success Response (HTTP 200)**:
  ```json
  {
    "status": "success",
    "registered": true,
    "name": "S Mohith Aradhya",
    "fingerprint_id": 1
  }
  ```

### 3. `POST /api/verify-fingerprint`
Compares scanned template index against cardholder biometric slot record.
* **Request Payload**:
  ```json
  {
    "rfid_uid": "57 92 27 64",
    "fingerprint_id": 1
  }
  ```
* **Success Response (HTTP 200)**:
  ```json
  {
    "status": "success",
    "verified": true
  }
  ```

### 4. `POST /api/vote`
Records a cryptographically secured vote. If no signature is provided, the API automatically signs the payload for debugging/testing.
* **Request Payload**:
  ```json
  {
    "rfid_uid": "57 92 27 64",
    "candidate": "A"
  }
  ```
* **Success Response (HTTP 200)**:
  ```json
  {
    "status": "accepted",
    "message": "Vote processed successfully",
    "vote_id": 48
  }
  ```

---

## 🧪 Simulation Tools (Hardware-Free Testing)

If you don't have physical ESP32 hardware connected, you can run the full system using the built-in simulators:

1. **Demo Mode Workflow**: Navigate to the **Demo Mode Workflow** tab in the browser dashboard. Use the step-by-step flowchart tool (**Scan RFID** ➔ **Verify RFID** ➔ **Verify Finger** ➔ **Cast Ballot**) or click **Start Auto-Pilot** to watch the telemetry, logging, and LCD status sync live.
2. **Demo Safety Mode**: Open the **Demo Center** modal on the top header and enable **Demo Safety Mode**. The system will feed automatic heartbeats and votes for 4 simulated booths in the background.

---

## ⚙️ How to Run the Platform

### Windows PowerShell Startup
```powershell
# 1. Open PowerShell and navigate to the project root:
cd "C:\Users\S Mohith\Desktop\VOTING SYSTEM"

# 2. Activate the virtual environment:
.\.venv\Scripts\Activate.ps1

# 3. Configure the Python module path:
$env:PYTHONPATH="voting_system"

# 4. Run the startup script:
python voting_system/start_system.py
```

### URL Navigation
* **Admin Center Dashboard**: [http://127.0.0.1:5000/](http://127.0.0.1:5000/)
* **Public Guest Results Board**: [http://127.0.0.1:5000/public-results](http://127.0.0.1:5000/public-results)
