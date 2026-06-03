# IoT Secure Smart Voting System

A college project that combines IoT and computer networks to simulate a secure voting booth built around an ESP32-style booth device and a Raspberry Pi or laptop backend.

## Architecture

```text
+----------------------+        MQTT         +------------------------+
|  Booth Simulator     |  votes/booth01 ---> |  Flask + MQTT Server   |
|  ESP32-style logic   | <--- response ----- |  SQLite + Audit Log    |
|  RFID + Fingerprint |                     |  Hash Verification     |
+----------------------+                     +-----------+------------+
                                                            |
                                                            v
                                                   +------------------+
                                                   |  SQLite Database  |
                                                   |  voters / votes   |
                                                   |  audit_log        |
                                                   +------------------+
```

## Technology Stack

- Python 3
- Flask
- SQLite3
- MQTT with Mosquitto
- paho-mqtt
- hashlib SHA-256
- HTML, CSS, JavaScript
- Windows / VS Code

## Folder Structure

- `booth/` contains the ESP32 booth simulator, RFID simulator, fingerprint simulator, and vote sender.
- `server/` contains the Flask app, MQTT handler, vote verification, and all database operations.
- `database/` contains the SQL schema, seed script, and generated SQLite database.
- `security/` contains hashing helpers and TLS configuration placeholders.
- `dashboard/` contains the later-phase web dashboard.
- `tests/` contains unit and integration tests.
- `config/` contains all project constants in one place.
- `logs/` stores the application log file.

## Setup

1. Open the project folder in VS Code.
2. Run the setup script:

```bash
python setup.py
```

3. If the setup script completes, the database will be created and seeded with 10 voters.
4. Start the MQTT broker locally with Mosquitto.
5. Start the Flask server.
6. Start the booth simulator.

## Run Components

Start the broker:

```bash
mosquitto
```

Start the server:

```bash
python server/app.py
```

Start the simulator:

```bash
python booth/simulator.py
```

Open the dashboard in a browser after the server starts:

```text
http://127.0.0.1:5000/
```

## Tests

Run the automated test suite:

```bash
python -m unittest discover -s tests
```

## Notes

- The simulator works without physical ESP32 hardware.
- If Mosquitto is not running, the simulator uses the local database fallback so vote logic can still be tested.
- All SQL queries use parameterized statements.
- All configuration values are centralized in `config/config.py`.

## Security Architecture

- Message authentication uses HMAC-SHA256 with a secret key stored in `config/config.py` (`SECRET_KEY`).
- Payloads include a `sequence_number` and `signature` to prevent tampering and replay attacks.
- The server verifies signatures using a timing-safe comparison and logs every verification attempt.

## Replay Protection

- The server maintains a `vote_sequence` table recording the last sequence number per voter.
- Votes with duplicate or lower sequence numbers are rejected and logged as `REPLAY_ATTACK` with `CRITICAL` severity.

## Offline Buffering

- Booths buffer votes to `booth/buffered_votes.json` if the MQTT broker is unavailable.
- Buffered votes are retried automatically every 10 seconds until delivery.
- The simulator provides a Network Online/Offline toggle to exercise buffering modes.

## Admin System

- Admin users are stored in the `admins` table. Default admin `admin` / password `admin123` is created during seeding (password stored as SHA-256 hash).
- Helper functions exist to `authenticate_admin`, `create_admin`, and `change_admin` passwords.

## Booth Management

- Booths are registered in the `booths` table. A default booth `BOOTH001` (Main Voting Booth) is created during seeding.
- Every vote must reference a valid booth.

## System Health Monitoring

- A `system_health` table tracks component status for `ESP32 Booth`, `MQTT Broker`, `Database`, and `Dashboard`.
- Helper functions update and query component health.

## Future WebSocket Expansion

- Flask-SocketIO has been added as an infrastructure dependency.
- `server/socketio_handler.py` contains minimal wiring to emit `new_vote`, `dashboard_update`, and `system_health_update` events in future phases.

## Migration Notes

- New tables and columns were added to support replay protection, booths, admins, election configuration, and system health. The database initialization applies `CREATE TABLE IF NOT EXISTS` statements so existing data is preserved.

## Phase 2 MQTT Architecture

Topics used by Phase 2:

- `voting/auth/request`
- `voting/auth/response`
- `voting/vote/submit`
- `voting/vote/response`
- `voting/system/health`
- `voting/admin/events`

Flow:

```text
Simulator -> MQTT/TLS -> Mosquitto -> server/mqtt_handler.py -> vote_verifier -> SQLite
                                                                                                                     -> SocketIO dashboard emits
```

## TLS Architecture

- Certificates are generated by `security/certificate_generator.py`.
- Generated files:
    - `security/certificates/ca.crt`
    - `security/certificates/ca.key`
    - `security/certificates/server.crt`
    - `security/certificates/server.key`
    - `security/certificates/client.crt`
    - `security/certificates/client.key`
- TLS helpers:
    - `load_tls_configuration()`
    - `validate_certificates()`

Generate certificates:

```bash
python -m security.certificate_generator
```

## Authentication Flow

1. Booth publishes RFID (and fingerprint) to `voting/auth/request`.
2. Server validates voter and publishes to `voting/auth/response`.
3. Booth proceeds only when `registered=true` and `verified=true`.

## Vote Flow

1. Booth creates payload with HMAC signature and sequence number.
2. Booth publishes vote to `voting/vote/submit`.
3. Server validates signature, replay rules, booth, and election status.
4. Server stores the vote and publishes result to `voting/vote/response`.
5. Server emits `new_vote` and `dashboard_update` via SocketIO.

## Health Monitoring

- Booth publishes heartbeat every 30 seconds to `voting/system/health`.
- Server updates `system_health` and emits `system_health_update`.
- Components are marked `OFFLINE` when heartbeat is absent for 90 seconds.

## Network Mode

`config/config.py` exposes `NETWORK_MODE`:

- `SIMULATION`: direct local processing (Phase 1 behavior).
- `MQTT`: full MQTT request/response behavior.

## Startup

Start all services with prerequisite checks:

```bash
python start_system.py
```

Graceful stop helper:

```bash
python stop_system.py
```

## Wireshark Demonstration

See `docs/wireshark_demo.md` for capture steps, filters, and screenshot checklist.
