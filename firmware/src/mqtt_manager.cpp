#include "mqtt_manager.h"
#include "security_manager.h"
#include <ArduinoJson.h>
#include "certificates.h"

// Callback bridge implementation
MQTTManager* globalMQTTManager = nullptr;

void callbackBridge(char* topic, byte* payload, unsigned int length) {
    if (globalMQTTManager != nullptr) {
        globalMQTTManager->messageCallback(topic, payload, length);
    }
}

MQTTManager::MQTTManager() : client() {
    lastReconnectAttempt = 0;
    lastHeartbeatTime = 0;
    
    currentAuthResp.isPopulated = false;
    currentVoteResp.isPopulated = false;
}

bool MQTTManager::init() {
    globalMQTTManager = this;
    
    // Set up secure or insecure client depending on TLS flag
    if (MQTT_USE_TLS) {
        secureClient.setCACert(ca_certificate);
        secureClient.setCertificate(client_certificate);
        secureClient.setPrivateKey(client_key);
        client.setClient(secureClient);
    } else {
        client.setClient(wifiClient);
    }
    
    client.setServer(MQTT_BROKER_HOST, MQTT_PORT);
    client.setCallback(callbackBridge);
    
    // Initial WiFi begin (will check status dynamically in FSM)
    Serial.print("Connecting to WiFi SSID: ");
    Serial.println(WIFI_SSID);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    
    return true;
}

void MQTTManager::update() {
    if (WiFi.status() == WL_CONNECTED) {
        if (!client.connected()) {
            unsigned long now = millis();
            if (now - lastReconnectAttempt > 5000) { // Retry every 5 seconds
                lastReconnectAttempt = now;
                Serial.println("Attempting MQTT connection...");
                if (connectMQTT()) {
                    lastReconnectAttempt = 0;
                    Serial.println("MQTT connected.");
                    
                    // Publish SYSTEM_RESTART audit event on first connection
                    publishAuditEvent("SYSTEM_RESTART", "", "ESP32 Voting Booth restarted. Firmware: v1.0.0");
                }
            }
        } else {
            client.loop();
        }
    }
}

bool MQTTManager::isConnected() {
    return WiFi.status() == WL_CONNECTED && client.connected();
}

bool MQTTManager::connectMQTT() {
    String clientId = "booth_" + String(BOOTH_ID) + "_" + String(random(1000, 9999));
    if (client.connect(clientId.c_str())) {
        client.subscribe("voting/auth/response");
        client.subscribe("voting/vote/response");
        return true;
    }
    Serial.print("MQTT connection failed, rc=");
    Serial.println(client.state());
    return false;
}

bool MQTTManager::requestAuthentication(const String& rfid, AuthResponse& outResponse) {
    if (!client.connected()) {
        return false;
    }
    
    String reqId = SecurityManager::generateUUID();
    currentAuthResp.isPopulated = false;
    currentAuthResp.requestId = "";
    
    StaticJsonDocument<256> doc;
    doc["request_id"] = reqId;
    doc["booth_id"] = BOOTH_ID;
    doc["rfid"] = rfid;
    
    String outbound;
    serializeJson(doc, outbound);
    
    Serial.println("Publishing auth request. Request ID: " + reqId);
    client.publish("voting/auth/request", outbound.c_str());
    
    unsigned long startWait = millis();
    while (millis() - startWait < RESPONSE_TIMEOUT_MS) {
        client.loop();
        if (currentAuthResp.isPopulated && currentAuthResp.requestId == reqId) {
            outResponse = currentAuthResp;
            return true;
        }
        delay(10);
    }
    
    Serial.println("Auth request timed out.");
    return false;
}

bool MQTTManager::submitVotePayload(const String& votePayload) {
    if (!client.connected()) {
        return false;
    }
    
    String reqId = SecurityManager::generateUUID();
    currentVoteResp.isPopulated = false;
    currentVoteResp.requestId = "";
    
    StaticJsonDocument<512> innerDoc;
    DeserializationError err = deserializeJson(innerDoc, votePayload);
    if (err) {
        Serial.println("submitVotePayload: failed to parse votePayload");
        return false;
    }
    
    StaticJsonDocument<1024> doc;
    doc["request_id"] = reqId;
    doc["booth_id"] = BOOTH_ID;
    doc["vote_payload"] = innerDoc;
    
    String outbound;
    serializeJson(doc, outbound);
    
    Serial.println("Publishing vote payload. Request ID: " + reqId);
    client.publish("voting/vote/submit", outbound.c_str());
    
    unsigned long startWait = millis();
    while (millis() - startWait < RESPONSE_TIMEOUT_MS) {
        client.loop();
        if (currentVoteResp.isPopulated && currentVoteResp.requestId == reqId) {
            return currentVoteResp.status == "accepted";
        }
        delay(10);
    }
    
    Serial.println("Vote submit timed out.");
    return false;
}

void MQTTManager::publishHeartbeat(int bufferedVotesCount, const String& fsmState, const String& currentVoter, const String& rfidStatus, const String& fingerprintStatus, const String& lcdStatus) {
    if (!client.connected()) {
        return;
    }
    
    StaticJsonDocument<512> doc;
    doc["booth_id"] = BOOTH_ID;
    doc["wifi_status"] = (WiFi.status() == WL_CONNECTED) ? "CONNECTED" : "DISCONNECTED";
    doc["mqtt_status"] = client.connected() ? "CONNECTED" : "DISCONNECTED";
    doc["buffered_votes"] = bufferedVotesCount;
    doc["free_heap"] = ESP.getFreeHeap();
    doc["firmware_version"] = FIRMWARE_VERSION;
    if (fsmState.length() > 0) doc["fsm_state"] = fsmState;
    if (currentVoter.length() > 0) doc["current_voter"] = currentVoter;
    if (rfidStatus.length() > 0) doc["rfid_status"] = rfidStatus;
    if (fingerprintStatus.length() > 0) doc["fingerprint_status"] = fingerprintStatus;
    if (lcdStatus.length() > 0) doc["lcd_status"] = lcdStatus;
    
    String payload;
    serializeJson(doc, payload);
    
    client.publish("voting/booth/heartbeat", payload.c_str());
}

void MQTTManager::publishAuditEvent(const String& event, const String& rfid, const String& details) {
    if (!client.connected()) {
        return;
    }
    
    StaticJsonDocument<256> doc;
    doc["event"] = event;
    doc["booth_id"] = BOOTH_ID;
    if (rfid.length() > 0) {
        doc["voter_id"] = rfid;
    }
    doc["details"] = details;
    doc["uptime_seconds"] = millis() / 1000;
    
    String payload;
    serializeJson(doc, payload);
    
    client.publish("voting/audit/events", payload.c_str());
}

void MQTTManager::messageCallback(char* topic, byte* payload, unsigned int length) {
    StaticJsonDocument<512> doc;
    DeserializationError error = deserializeJson(doc, payload, length);
    if (error) {
        Serial.println("messageCallback: Failed to deserialize JSON");
        return;
    }
    
    String topicStr = String(topic);
    if (topicStr == "voting/auth/response") {
        currentAuthResp.requestId = doc["request_id"].as<String>();
        currentAuthResp.registered = doc["registered"].as<bool>();
        currentAuthResp.verified = doc["verified"].as<bool>();
        currentAuthResp.hasVoted = doc["has_voted"].as<bool>();
        currentAuthResp.name = doc["name"].as<String>();
        currentAuthResp.fingerprintId = doc["fingerprint_id"].as<int>();
        currentAuthResp.isPopulated = true;
    } else if (topicStr == "voting/vote/response") {
        currentVoteResp.requestId = doc["request_id"].as<String>();
        currentVoteResp.status = doc["status"].as<String>();
        currentVoteResp.message = doc["message"].as<String>();
        currentVoteResp.voteId = doc["vote_id"].as<int>();
        currentVoteResp.isPopulated = true;
    }
}
