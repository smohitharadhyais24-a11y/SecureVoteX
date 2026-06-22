#ifndef MQTT_MANAGER_H
#define MQTT_MANAGER_H

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include "config.h"

// Structs to hold transaction responses
struct AuthResponse {
    String requestId;
    bool registered;
    bool verified;
    bool hasVoted;
    String name;
    int fingerprintId;
    bool isPopulated;
};

struct VoteResponse {
    String requestId;
    String status;
    String message;
    int voteId;
    bool isPopulated;
};

class MQTTManager {
public:
    MQTTManager();
    bool init();
    void update(); // Calls client.loop() and handles WiFi/MQTT reconnection checks
    
    bool isConnected();
    bool connectMQTT();
    
    // Auth Request-Response Transaction (blocking with timeout)
    bool requestAuthentication(const String& rfid, AuthResponse& outResponse);
    
    // Vote Submit Request-Response Transaction (blocking with timeout)
    bool submitVotePayload(const String& votePayload);
    
    // Publish Booth Heartbeat
    void publishHeartbeat(int bufferedVotesCount, const String& fsmState = "", const String& currentVoter = "", const String& rfidStatus = "", const String& fingerprintStatus = "", const String& lcdStatus = "");
    
    // Publish Audit Events
    void publishAuditEvent(const String& event, const String& rfid, const String& details);

    // Callbacks for incoming messages
    void messageCallback(char* topic, byte* payload, unsigned int length);

private:
    WiFiClient wifiClient;
    WiFiClientSecure secureClient;
    PubSubClient client;
    
    unsigned long lastReconnectAttempt;
    unsigned long lastHeartbeatTime;
    
    // Storage for transaction responses populated by callback
    AuthResponse currentAuthResp;
    VoteResponse currentVoteResp;
};

#endif // MQTT_MANAGER_H
