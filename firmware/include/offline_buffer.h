#ifndef OFFLINE_BUFFER_H
#define OFFLINE_BUFFER_H

#include <Arduino.h>
#include <LittleFS.h>
#include "config.h"

// Forward declaration to avoid circular dependency
class MQTTManager;

class OfflineBuffer {
public:
    OfflineBuffer();
    bool init();
    
    // Saves a vote JSON string to a file under /votes/
    bool bufferVote(const String& votePayload);
    
    // Returns the count of currently cached votes
    int getBufferedCount();
    
    // Processes the queue by reading each file, trying to publish it, and deleting on success
    void processQueue(MQTTManager& mqtt);

private:
    bool isMounted;
};

#endif // OFFLINE_BUFFER_H
