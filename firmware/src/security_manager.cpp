#include "security_manager.h"
#include <mbedtls/md.h>
#include <ArduinoJson.h>

SecurityManager::SecurityManager() {}

String SecurityManager::computeHMAC(const String& message, const String& key) {
    byte hmacResult[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
    
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx, (const unsigned char*) key.c_str(), key.length());
    mbedtls_md_hmac_update(&ctx, (const unsigned char*) message.c_str(), message.length());
    mbedtls_md_hmac_finish(&ctx, hmacResult);
    mbedtls_md_free(&ctx);
    
    String hashStr = "";
    for (int i = 0; i < 32; i++) {
        char buf[3];
        sprintf(buf, "%02x", hmacResult[i]);
        hashStr += buf;
    }
    return hashStr;
}

String SecurityManager::generateUUID() {
    // Generate 16 random bytes using ESP32 hardware RNG
    uint8_t uuidBytes[16];
    for (int i = 0; i < 16; i += 4) {
        uint32_t r = esp_random();
        memcpy(&uuidBytes[i], &r, 4);
    }
    
    // Set UUID v4 variant/version
    uuidBytes[6] = (uuidBytes[6] & 0x0F) | 0x40; // Version 4
    uuidBytes[8] = (uuidBytes[8] & 0x3F) | 0x80; // Variant 10xxxxxx
    
    // Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    char buffer[37];
    sprintf(buffer, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            uuidBytes[0], uuidBytes[1], uuidBytes[2], uuidBytes[3],
            uuidBytes[4], uuidBytes[5],
            uuidBytes[6], uuidBytes[7],
            uuidBytes[8], uuidBytes[9],
            uuidBytes[10], uuidBytes[11], uuidBytes[12], uuidBytes[13], uuidBytes[14], uuidBytes[15]);
            
    return String(buffer);
}

String SecurityManager::buildVotePayload(const String& rfid, char candidate, int fingerprintId, uint64_t seqNum, uint32_t uptimeSecs, String& outSignature) {
    // 1. Construct signature string
    String candidateStr = String(candidate);
    String message = rfid + "|" + candidateStr + "|" + BOOTH_ID + "|" + String(uptimeSecs) + "|" + String(seqNum);
    
    // 2. Compute HMAC signature
    outSignature = computeHMAC(message, SECRET_KEY);
    
    // 3. Construct JSON
    StaticJsonDocument<512> doc;
    doc["message_id"] = generateUUID();
    doc["voter_id"] = rfid;
    doc["candidate"] = candidateStr;
    doc["booth_id"] = BOOTH_ID;
    doc["uptime_seconds"] = uptimeSecs;
    doc["sequence_number"] = seqNum;
    doc["signature"] = outSignature;
    doc["hash"] = outSignature; // Backwards compatibility field
    
    String jsonStr;
    serializeJson(doc, jsonStr);
    return jsonStr;
}
