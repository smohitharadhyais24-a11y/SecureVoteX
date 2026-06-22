#ifndef SECURITY_MANAGER_H
#define SECURITY_MANAGER_H

#include <Arduino.h>
#include "config.h"

class SecurityManager {
public:
    SecurityManager();
    
    // Computes HMAC-SHA256 signature using native ESP32 mbedtls
    static String computeHMAC(const String& message, const String& key);
    
    // Generates a random UUIDv4 string using hardware esp_random()
    static String generateUUID();
    
    // Builds and signs the JSON payload for MQTT vote submission
    static String buildVotePayload(const String& rfid, char candidate, int fingerprintId, uint64_t seqNum, uint32_t uptimeSecs, String& outSignature);
};

#endif // SECURITY_MANAGER_H
