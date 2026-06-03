# Wireshark Demo: MQTT Traffic (TLS vs non-TLS)

## Goal
Show that MQTT payloads are readable on port 1883 and encrypted on port 8883.

## Prerequisites
- Mosquitto broker running using `mqtt/mosquitto.conf`
- Voting server running (`python server/app.py`)
- Booth simulator sending auth and vote traffic

## Capture Steps
1. Open Wireshark.
2. Select the active network interface.
3. Start capture.
4. Trigger booth auth and vote flows.

## Display Filters
- `mqtt`
- `tcp.port == 1883`
- `tcp.port == 8883`

## Expected Observations
### Without TLS (`1883`)
- MQTT frames decode directly.
- JSON payloads are readable in packet bytes.
- Topics visible: `voting/auth/request`, `voting/vote/submit`, etc.

### With TLS (`8883`)
- Packet payload is encrypted TLS application data.
- MQTT JSON body is not readable.
- TLS handshake is visible before encrypted traffic.

## Screenshot Guide
Capture and include these screenshots in your demo report:
1. Packet list filtered with `tcp.port == 1883` showing readable MQTT payload.
2. Packet bytes pane highlighting plain JSON payload.
3. Packet list filtered with `tcp.port == 8883` showing TLS handshake and app data.
4. Packet bytes pane showing encrypted payload for TLS session.
