#ifndef FINGERPRINT_MANAGER_H
#define FINGERPRINT_MANAGER_H

#include <Adafruit_Fingerprint.h>
#include <Arduino.h>
#include "config.h"

// Define to enable hardware simulation for testing FSM without physical sensors
//#define DEBUG_HARDWARE_SIM

class FingerprintManager {
public:
    FingerprintManager();
    bool init();
    
    // Returns confidence score (>=0) on success,
    // -2 if no finger placed,
    // -1 on error or mismatch.
    int scanAndMatch(int expectedID);

private:
    Adafruit_Fingerprint finger;
    HardwareSerial mySerial;
};

#endif // FINGERPRINT_MANAGER_H
