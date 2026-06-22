#ifndef CONFIG_H
#define CONFIG_H

#include <Arduino.h>

// Firmware Version
#define FIRMWARE_VERSION "v1.0.0"

// Network Configuration
#define WIFI_SSID "SmartVotingWiFi"
#define WIFI_PASSWORD "voting1234"

#define MQTT_BROKER_HOST "192.168.1.100" // Replace with the actual IP address of the server hosting Mosquitto
#define MQTT_PORT 1883                  // Default TCP Port. Set to 8883 if using TLS.
#define MQTT_USE_TLS false              // Set to true to enable TLS certificate authentication

// Device Configuration
#define BOOTH_ID "booth01"
#define SECRET_KEY "iot_secure_voting_2026" // Must match Flask server config
#define ADMIN_RFID "ADMIN001"              // Special card UID for admin menu

// Pin Mappings (Boot-Safe Pins)
#define RFID_SS_PIN 5
#define RFID_RST_PIN 4

#define FP_RX_PIN 16
#define FP_TX_PIN 17

#define LCD_SDA_PIN 21
#define LCD_SCL_PIN 22

#define BUTTON_A_PIN 32
#define BUTTON_B_PIN 33
#define BUTTON_C_PIN 25

#define GREEN_LED_PIN 26
#define RED_LED_PIN 27
#define BUZZER_PIN 14

// System Settings
#define HEARTBEAT_INTERVAL_MS 30000
#define RESPONSE_TIMEOUT_MS 5000
#define VOTE_TIMEOUT_MS 30000
#define DEBOUNCE_DELAY_MS 50

#endif // CONFIG_H
