#include "offline_buffer.h"
#include "mqtt_manager.h"

OfflineBuffer::OfflineBuffer() : isMounted(false) {}

bool OfflineBuffer::init() {
    // Mount LittleFS, formatting it if it fails or is uninitialized
    if (LittleFS.begin(true)) {
        isMounted = true;
        Serial.println("LittleFS mounted successfully.");
        // Ensure /votes directory exists
        if (!LittleFS.exists("/votes")) {
            LittleFS.mkdir("/votes");
        }
        return true;
    } else {
        Serial.println("Failed to mount LittleFS.");
        return false;
    }
}

bool OfflineBuffer::bufferVote(const String& votePayload) {
    if (!isMounted) {
        return false;
    }
    
    // Create unique filename based on millis and a random number
    String filePath = "/votes/v_" + String(millis()) + "_" + String(random(1000, 9999)) + ".json";
    
    File file = LittleFS.open(filePath, FILE_WRITE);
    if (!file) {
        Serial.println("Failed to create buffered vote file: " + filePath);
        return false;
    }
    
    file.print(votePayload);
    file.close();
    
    Serial.println("Vote buffered locally to: " + filePath);
    return true;
}

int OfflineBuffer::getBufferedCount() {
    if (!isMounted) {
        return 0;
    }
    
    int count = 0;
    File root = LittleFS.open("/votes");
    if (!root || !root.isDirectory()) {
        return 0;
    }
    
    File file = root.openNextFile();
    while (file) {
        count++;
        file = root.openNextFile();
    }
    
    return count;
}

void OfflineBuffer::processQueue(MQTTManager& mqtt) {
    if (!isMounted) {
        return;
    }
    
    File root = LittleFS.open("/votes");
    if (!root || !root.isDirectory()) {
        return;
    }
    
    File file = root.openNextFile();
    while (file) {
        String filename = file.name();
        String filePath = filename;
        if (!filePath.startsWith("/votes/")) {
            filePath = "/votes/" + filename;
        }
        
        Serial.println("Processing cached vote file: " + filePath);
        
        // Read stored vote payload JSON
        String votePayload = file.readString();
        file.close();
        
        // Attempt to submit this vote via MQTT (with retry wait/timeout)
        bool success = mqtt.submitVotePayload(votePayload);
        if (success) {
            Serial.println("Cached vote delivered successfully. Removing file: " + filePath);
            LittleFS.remove(filePath);
        } else {
            Serial.println("Failed to deliver cached vote. Stopping queue processing.");
            // Stop processing queue if server is unreachable
            break;
        }
        
        file = root.openNextFile();
    }
}
