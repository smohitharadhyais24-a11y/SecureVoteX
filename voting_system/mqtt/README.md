# Mosquitto Integration (Windows)

## Install Mosquitto
1. Download Mosquitto for Windows from the Eclipse Mosquitto releases page.
2. Install it with default options.
3. Ensure `mosquitto.exe` is available in PATH, or run scripts from Mosquitto install directory.

## Project Broker Configuration
- Config file: `mqtt/mosquitto.conf`
- Plain MQTT: port `1883`
- MQTT over TLS: port `8883`
- Persistence: enabled
- Logs: enabled (`mqtt/log/mosquitto.log`)
- Retained messages: disabled

## Start Broker
```bat
mqtt\start_broker.bat
```

## Stop Broker
```bat
mqtt\stop_broker.bat
```

## TLS Certificate Prerequisite
Generate certificates before starting TLS listener:
```bash
python -m security.certificate_generator
```
