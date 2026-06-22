#include <Arduino.h>
#include "config.h"
#include "certificates.h"
#include "button_manager.h"
#include "lcd_manager.h"
#include "rfid_manager.h"
#include "fingerprint_manager.h"
#include "security_manager.h"
#include "offline_buffer.h"
#include "mqtt_manager.h"

// FSM States
enum SystemState {
    STATE_WIFI_CONNECTING,
    STATE_MQTT_CONNECTING,
    STATE_IDLE,
    STATE_WAITING_RFID_VALIDATION,
    STATE_PROMPT_FINGERPRINT,
    STATE_WAITING_FINGERPRINT,
    STATE_PROMPT_CANDIDATE,
    STATE_WAITING_CANDIDATE,
    STATE_SUBMITTING_VOTE,
    STATE_VOTE_CONFIRMED,
    STATE_VOTE_FAILED,
    STATE_REJECTED,
    STATE_ADMIN_MENU
};

// Global Manager Instances
ButtonManager buttonMgr;
LCDManager lcdMgr;
RFIDManager rfidMgr;
FingerprintManager fpMgr;
OfflineBuffer bufferMgr;
MQTTManager mqttMgr;

// State Variables
SystemState currentState = STATE_WIFI_CONNECTING;
unsigned long stateTimer = 0;
unsigned long lastHeartbeatTime = 0;
unsigned long lastQueueCheckTime = 0;

// Current transaction data
String currentVoterRFID = "";
String currentVoterName = "";
int expectedFingerprintId = -1;
int fingerprintAttempts = 0;
char selectedCandidate = '\0';
uint64_t sequenceNumber = 1; // Monotonic sequence

// Admin Menu variables
int currentAdminItem = 0;
const int totalAdminItems = 4;
const char* adminItemTitles[] = {
    "Election Status",
    "Booth Health",
    "MQTT Status",
    "Buffered Count"
};

// Alert Helper Functions
void triggerSuccessAlert() {
    digitalWrite(GREEN_LED_PIN, HIGH);
    digitalWrite(RED_LED_PIN, LOW);
    digitalWrite(BUZZER_PIN, HIGH);
    delay(200); // Beep
    digitalWrite(BUZZER_PIN, LOW);
    delay(600); // Total 800ms LED on
    digitalWrite(GREEN_LED_PIN, LOW);
}

void triggerFailureAlert() {
    digitalWrite(GREEN_LED_PIN, LOW);
    for (int i = 0; i < 3; i++) {
        digitalWrite(RED_LED_PIN, HIGH);
        digitalWrite(BUZZER_PIN, HIGH);
        delay(120);
        digitalWrite(BUZZER_PIN, LOW);
        digitalWrite(RED_LED_PIN, LOW);
        delay(120);
    }
}

// Translate and publish FSM state information to MQTT heartbeat
void publishLiveStatus() {
    if (!mqttMgr.isConnected()) {
        return;
    }
    
    String fsmStateStr = "";
    switch (currentState) {
        case STATE_WIFI_CONNECTING: fsmStateStr = "WIFI_CONNECTING"; break;
        case STATE_MQTT_CONNECTING: fsmStateStr = "MQTT_CONNECTING"; break;
        case STATE_IDLE: fsmStateStr = "IDLE"; break;
        case STATE_WAITING_RFID_VALIDATION: fsmStateStr = "WAITING_RFID_VALIDATION"; break;
        case STATE_PROMPT_FINGERPRINT: fsmStateStr = "PROMPT_FINGERPRINT"; break;
        case STATE_WAITING_FINGERPRINT: fsmStateStr = "WAITING_FINGERPRINT"; break;
        case STATE_PROMPT_CANDIDATE: fsmStateStr = "PROMPT_CANDIDATE"; break;
        case STATE_WAITING_CANDIDATE: fsmStateStr = "WAITING_CANDIDATE"; break;
        case STATE_SUBMITTING_VOTE: fsmStateStr = "SUBMITTING_VOTE"; break;
        case STATE_VOTE_CONFIRMED: fsmStateStr = "VOTE_CONFIRMED"; break;
        case STATE_VOTE_FAILED: fsmStateStr = "VOTE_FAILED"; break;
        case STATE_REJECTED: fsmStateStr = "REJECTED"; break;
        case STATE_ADMIN_MENU: fsmStateStr = "ADMIN_MENU"; break;
        default: fsmStateStr = "UNKNOWN"; break;
    }
    
    String rfidStatusStr = "IDLE";
    if (currentState == STATE_WAITING_RFID_VALIDATION) {
        rfidStatusStr = "VALIDATING";
    } else if (currentVoterRFID.length() > 0) {
        rfidStatusStr = "SCANNED";
    }
    
    String fingerprintStatusStr = "IDLE";
    if (currentState == STATE_WAITING_FINGERPRINT) {
        fingerprintStatusStr = "SCANNING";
    } else if (expectedFingerprintId >= 0 && currentState > STATE_WAITING_FINGERPRINT) {
        fingerprintStatusStr = "VERIFIED";
    }
    
    String lcdStatusStr = "Online";
    switch (currentState) {
        case STATE_WIFI_CONNECTING: lcdStatusStr = "Connecting WiFi"; break;
        case STATE_MQTT_CONNECTING: lcdStatusStr = "Connecting MQTT"; break;
        case STATE_IDLE: lcdStatusStr = "Scan RFID"; break;
        case STATE_WAITING_RFID_VALIDATION: lcdStatusStr = "Checking Voter"; break;
        case STATE_PROMPT_FINGERPRINT: lcdStatusStr = "Scan Finger"; break;
        case STATE_WAITING_FINGERPRINT: lcdStatusStr = "Scan Finger"; break;
        case STATE_PROMPT_CANDIDATE: lcdStatusStr = "Select Candidate"; break;
        case STATE_WAITING_CANDIDATE: lcdStatusStr = "Select Candidate"; break;
        case STATE_SUBMITTING_VOTE: lcdStatusStr = "Sending Vote"; break;
        case STATE_VOTE_CONFIRMED: lcdStatusStr = "Vote Recorded"; break;
        case STATE_VOTE_FAILED: lcdStatusStr = "System Error"; break;
        case STATE_REJECTED: lcdStatusStr = "Access Denied"; break;
        case STATE_ADMIN_MENU: lcdStatusStr = "Admin Menu"; break;
    }
    
    mqttMgr.publishHeartbeat(
        bufferMgr.getBufferedCount(),
        fsmStateStr,
        currentVoterRFID,
        rfidStatusStr,
        fingerprintStatusStr,
        lcdStatusStr
    );
}

// Function to update LCD and Serial logs on FSM transitions
void transitionTo(SystemState newState) {
    currentState = newState;
    stateTimer = millis();
    
    // Broadcast live transition updates immediately
    publishLiveStatus();
    
    switch (currentState) {
        case STATE_WIFI_CONNECTING:
            Serial.println("[FSM] State: WIFI_CONNECTING");
            lcdMgr.displayMessage("Connecting WiFi", WIFI_SSID);
            break;
            
        case STATE_MQTT_CONNECTING:
            Serial.println("[FSM] State: MQTT_CONNECTING");
            lcdMgr.displayMessage("Connecting MQTT", MQTT_BROKER_HOST);
            break;
            
        case STATE_IDLE:
            Serial.println("[FSM] State: IDLE - Waiting for voter card scan...");
            lcdMgr.displayScanRFID();
            digitalWrite(GREEN_LED_PIN, LOW);
            digitalWrite(RED_LED_PIN, LOW);
            // Clear transaction details
            currentVoterRFID = "";
            currentVoterName = "";
            expectedFingerprintId = -1;
            fingerprintAttempts = 0;
            selectedCandidate = '\0';
            break;
            
        case STATE_WAITING_RFID_VALIDATION:
            Serial.println("[FSM] State: WAITING_RFID_VALIDATION");
            lcdMgr.displayCheckingVoter();
            break;
            
        case STATE_PROMPT_FINGERPRINT:
            Serial.println("[FSM] State: PROMPT_FINGERPRINT");
            fingerprintAttempts = 0;
            transitionTo(STATE_WAITING_FINGERPRINT);
            break;
            
        case STATE_WAITING_FINGERPRINT:
            fingerprintAttempts++;
            Serial.print("[FSM] State: WAITING_FINGERPRINT - Attempt ");
            Serial.println(fingerprintAttempts);
            lcdMgr.displayScanFinger(fingerprintAttempts);
            break;
            
        case STATE_PROMPT_CANDIDATE:
            Serial.println("[FSM] State: PROMPT_CANDIDATE");
            lcdMgr.displaySelectCandidate();
            transitionTo(STATE_WAITING_CANDIDATE);
            break;
            
        case STATE_WAITING_CANDIDATE:
            Serial.println("[FSM] State: WAITING_CANDIDATE - Awaiting button press...");
            break;
            
        case STATE_SUBMITTING_VOTE:
            Serial.println("[FSM] State: SUBMITTING_VOTE");
            lcdMgr.displaySendingVote();
            break;
            
        case STATE_VOTE_CONFIRMED:
            Serial.println("[FSM] State: VOTE_CONFIRMED");
            lcdMgr.displayVoteRecorded(selectedCandidate);
            triggerSuccessAlert();
            transitionTo(STATE_IDLE);
            break;
            
        case STATE_VOTE_FAILED:
            Serial.println("[FSM] State: VOTE_FAILED");
            lcdMgr.displaySystemError();
            triggerFailureAlert();
            transitionTo(STATE_IDLE);
            break;
            
        case STATE_REJECTED:
            Serial.println("[FSM] State: REJECTED");
            triggerFailureAlert();
            transitionTo(STATE_IDLE);
            break;
            
        case STATE_ADMIN_MENU:
            Serial.println("[FSM] State: ADMIN_MENU");
            currentAdminItem = 0;
            lcdMgr.displayAdminItem(adminItemTitles[currentAdminItem], "Press B to View");
            break;
    }
}

// Admin menu navigation logic
void handleAdminMenu() {
    char pressed = buttonMgr.getPressedCandidate();
    
    if (pressed == 'A') { // Next Item
        currentAdminItem = (currentAdminItem + 1) % totalAdminItems;
        lcdMgr.displayAdminItem(adminItemTitles[currentAdminItem], "Press B to View");
    } 
    else if (pressed == 'B') { // Select / Refresh View
        String valueStr = "";
        
        switch (currentAdminItem) {
            case 0: // Election Status
                if (mqttMgr.isConnected()) {
                    valueStr = "ACTIVE";
                } else {
                    valueStr = "OFFLINE (UNKNOWN)";
                }
                break;
                
            case 1: // Booth Health
                valueStr = "Up:" + String(millis() / 1000) + "s H:" + String(ESP.getFreeHeap() / 1024) + "K";
                break;
                
            case 2: // MQTT Status
                if (mqttMgr.isConnected()) {
                    valueStr = "CONNECTED";
                } else {
                    valueStr = "DISCONNECTED";
                }
                break;
                
            case 3: // Buffered Count
                valueStr = "Buffered: " + String(bufferMgr.getBufferedCount()) + " v";
                break;
        }
        
        lcdMgr.displayAdminItem(adminItemTitles[currentAdminItem], valueStr);
    } 
    else if (pressed == 'C') { // Exit Admin Menu
        Serial.println("Exiting Admin Menu...");
        transitionTo(STATE_IDLE);
    }
}

void setup() {
    // Initialize Serial Debug
    Serial.begin(115200);
    Serial.println("\n--- IoT Secure Smart Voting Booth ---");
    Serial.print("Booting... Firmware Version: ");
    Serial.println(FIRMWARE_VERSION);
    
    // Initialize Hardware Indicators
    pinMode(GREEN_LED_PIN, OUTPUT);
    pinMode(RED_LED_PIN, OUTPUT);
    pinMode(BUZZER_PIN, OUTPUT);
    digitalWrite(GREEN_LED_PIN, LOW);
    digitalWrite(RED_LED_PIN, LOW);
    digitalWrite(BUZZER_PIN, LOW);
    
    // Test indicator buzzer on startup
    digitalWrite(BUZZER_PIN, HIGH);
    delay(100);
    digitalWrite(BUZZER_PIN, LOW);
    
    // Initialize Managers
    buttonMgr.init();
    lcdMgr.init();
    rfidMgr.init();
    fpMgr.init();
    bufferMgr.init();
    mqttMgr.init();
    
    // Initial transition to WiFi connecting
    transitionTo(STATE_WIFI_CONNECTING);
}

void loop() {
    // Keep MQTT client running and handle WiFi/MQTT reconnection checks
    mqttMgr.update();
    
    // Keep button debouncers updated
    buttonMgr.update();
    
    unsigned long now = millis();
    
    // Periodic MQTT Heartbeat topic: voting/booth/heartbeat
    if (now - lastHeartbeatTime >= HEARTBEAT_INTERVAL_MS) {
        lastHeartbeatTime = now;
        publishLiveStatus();
    }
    
    // Periodic Offline Buffer Queue processing (Retry cached votes when idle)
    if (currentState == STATE_IDLE && mqttMgr.isConnected()) {
        if (now - lastQueueCheckTime >= 10000) {
            lastQueueCheckTime = now;
            bufferMgr.processQueue(mqttMgr);
        }
    }
    
    // FSM State Loop
    switch (currentState) {
        case STATE_WIFI_CONNECTING:
            if (WiFi.status() == WL_CONNECTED) {
                transitionTo(STATE_MQTT_CONNECTING);
            } 
            else if (millis() - stateTimer > 10000) { // Timeout WiFi connection after 10s to allow offline idle scan
                Serial.println("WiFi connection timeout. Entering offline IDLE mode...");
                transitionTo(STATE_IDLE);
            }
            break;
            
        case STATE_MQTT_CONNECTING:
            if (mqttMgr.isConnected()) {
                transitionTo(STATE_IDLE);
            } 
            else if (millis() - stateTimer > 6000) { // Timeout MQTT broker after 6s to allow offline idle scan
                Serial.println("MQTT connection timeout. Entering offline IDLE mode...");
                transitionTo(STATE_IDLE);
            }
            break;
            
        case STATE_IDLE:
            // Check for RFID scans
            if (rfidMgr.isCardPresent()) {
                String uid = rfidMgr.readUID();
                rfidMgr.haltCard(); // Halts communication to prevent duplicate loops
                
                Serial.println("Card Scanned: UID: " + uid);
                
                // Check if it is the special Admin card
                if (uid == ADMIN_RFID) {
                    transitionTo(STATE_ADMIN_MENU);
                    break;
                }
                
                currentVoterRFID = uid;
                transitionTo(STATE_WAITING_RFID_VALIDATION);
            }
            break;
            
        case STATE_WAITING_RFID_VALIDATION: {
            if (!mqttMgr.isConnected()) {
                Serial.println("MQTT Offline. Cannot authenticate voter online. Access Denied.");
                lcdMgr.displayMessage("Network Offline", "Voter Rejected");
                mqttMgr.publishAuditEvent("MQTT_OFFLINE", currentVoterRFID, "MQTT offline during voter RFID validation attempt");
                transitionTo(STATE_REJECTED);
                break;
            }
            
            AuthResponse response;
            bool success = mqttMgr.requestAuthentication(currentVoterRFID, response);
            
            if (success) {
                if (!response.registered) {
                    Serial.println("Server returned: Voter Not Registered!");
                    lcdMgr.displayVoterNotFound();
                    mqttMgr.publishAuditEvent("RFID_FAIL", currentVoterRFID, "RFID scanned card is not registered in DB");
                    transitionTo(STATE_REJECTED);
                } 
                else if (response.hasVoted) {
                    Serial.println("Server returned: Voter has already voted!");
                    lcdMgr.displayAlreadyVoted();
                    mqttMgr.publishAuditEvent("DOUBLE_VOTE", currentVoterRFID, "Double vote attempt detected at auth stage");
                    transitionTo(STATE_REJECTED);
                } 
                else {
                    Serial.println("Voter registered. Welcome: " + response.name);
                    lcdMgr.displayMessage("Welcome,", response.name);
                    currentVoterName = response.name;
                    expectedFingerprintId = response.fingerprintId;
                    
                    delay(1500); // Welcome splash delay
                    transitionTo(STATE_PROMPT_FINGERPRINT);
                }
            } else {
                // Request timeout or server error
                Serial.println("Server verification failed or timed out.");
                lcdMgr.displaySystemError();
                transitionTo(STATE_REJECTED);
            }
            break;
        }
        
        case STATE_WAITING_FINGERPRINT: {
            // Check for timeout
            if (millis() - stateTimer > VOTE_TIMEOUT_MS) {
                Serial.println("Fingerprint scan timeout.");
                lcdMgr.displayMessage("Time Out", "Voter Rejected");
                mqttMgr.publishAuditEvent("FINGERPRINT_FAIL", currentVoterRFID, "Fingerprint timeout after 30 seconds");
                transitionTo(STATE_REJECTED);
                break;
            }
            
            int matchResult = fpMgr.scanAndMatch(expectedFingerprintId);
            
            if (matchResult >= 0) { // Success match
                Serial.println("Fingerprint match verified.");
                lcdMgr.displayMessage("Fingerprint OK", "Welcome!");
                delay(1200);
                transitionTo(STATE_PROMPT_CANDIDATE);
            } 
            else if (matchResult == -1) { // Mismatch or read error
                Serial.println("Fingerprint mismatch / read error.");
                lcdMgr.displayMessage("Match Failed!", "Try Again");
                delay(1200);
                
                if (fingerprintAttempts >= 3) {
                    Serial.println("Max fingerprint attempts reached. Voter Rejected.");
                    lcdMgr.displayFingerprintFailed();
                    mqttMgr.publishAuditEvent("FINGERPRINT_FAIL", currentVoterRFID, "Fingerprint mismatch. 3 failed attempts.");
                    transitionTo(STATE_REJECTED);
                } else {
                    // Retry scan (increment attempts and redraw screen)
                    transitionTo(STATE_WAITING_FINGERPRINT);
                }
            }
            // If matchResult == -2: No finger placed yet. Keep looping.
            break;
        }
        
        case STATE_WAITING_CANDIDATE: {
            // Check for timeout
            if (millis() - stateTimer > VOTE_TIMEOUT_MS) {
                Serial.println("Candidate selection timeout.");
                lcdMgr.displayMessage("Time Out", "Vote Cancelled");
                transitionTo(STATE_REJECTED);
                break;
            }
            
            char pressed = buttonMgr.getPressedCandidate();
            if (pressed == 'A' || pressed == 'B' || pressed == 'C') {
                selectedCandidate = pressed;
                Serial.print("Voter selected Candidate: ");
                Serial.println(selectedCandidate);
                
                // Play short beep for button confirmation
                digitalWrite(BUZZER_PIN, HIGH);
                delay(80);
                digitalWrite(BUZZER_PIN, LOW);
                
                transitionTo(STATE_SUBMITTING_VOTE);
            }
            break;
        }
        
        case STATE_SUBMITTING_VOTE: {
            // Increment local sequence number
            sequenceNumber++;
            
            // Build and sign the JSON vote payload using uptime and sequence number (No NTP)
            uint32_t uptime = millis() / 1000;
            String signature = "";
            String votePayload = SecurityManager::buildVotePayload(currentVoterRFID, selectedCandidate, expectedFingerprintId, sequenceNumber, uptime, signature);
            
            Serial.println("Prepared vote payload string: " + votePayload);
            Serial.println("HMAC-SHA256 Signature: " + signature);
            
            bool published = false;
            if (mqttMgr.isConnected()) {
                published = mqttMgr.submitVotePayload(votePayload);
            }
            
            if (published) {
                Serial.println("Vote payload processed and accepted by server.");
                transitionTo(STATE_VOTE_CONFIRMED);
            } else {
                // If connection is lost or publish fails, buffer vote locally to LittleFS
                Serial.println("Publish failed. Saving vote to offline buffer...");
                bool buffered = bufferMgr.bufferVote(votePayload);
                
                if (buffered) {
                    lcdMgr.displayMessage("Offline Mode", "Vote Saved");
                    mqttMgr.publishAuditEvent("MQTT_OFFLINE", currentVoterRFID, "Vote cached to offline buffer due to MQTT offline");
                    triggerSuccessAlert();
                    transitionTo(STATE_IDLE);
                } else {
                    // Buffer write failed (LittleFS full or unmounted)
                    transitionTo(STATE_VOTE_FAILED);
                }
            }
            break;
        }
        
        case STATE_ADMIN_MENU:
            handleAdminMenu();
            break;
            
        default:
            break;
    }
}
