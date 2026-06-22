#include "fingerprint_manager.h"

FingerprintManager::FingerprintManager() : mySerial(2), finger(&mySerial) {}

bool FingerprintManager::init() {
#ifdef DEBUG_HARDWARE_SIM
    Serial.println("[SIMULATION] Fingerprint Sensor initialized (Mock Mode)");
    return true;
#else
    // Default baud rate for R307 sensors is 57600
    mySerial.begin(57600, SERIAL_8N1, FP_RX_PIN, FP_TX_PIN);
    finger.begin(57600);

    if (finger.verifyPassword()) {
        Serial.println("Found R307 fingerprint sensor!");
        return true;
    } else {
        Serial.println("Did not find R307 fingerprint sensor :(");
        return false;
    }
#endif
}

int FingerprintManager::scanAndMatch(int expectedID) {
#ifdef DEBUG_HARDWARE_SIM
    static unsigned long startScanTime = 0;
    if (startScanTime == 0) {
        startScanTime = millis();
        Serial.println("[SIMULATION] Place finger on scanner...");
        return -2; // No finger
    }
    
    if (millis() - startScanTime < 2000) {
        // Return no finger for 2 seconds to simulate waiting
        return -2;
    }
    
    startScanTime = 0; // Reset for next scan
    Serial.print("[SIMULATION] Finger verified successfully for expected ID: ");
    Serial.println(expectedID);
    return 100; // Success confidence
#else
    uint8_t p = finger.getImage();
    if (p == FINGERPRINT_NOFINGER) {
        return -2; // No finger detected
    }
    if (p != FINGERPRINT_OK) {
        Serial.println("Fingerprint getImage error");
        return -1;
    }

    p = finger.image2Tz();
    if (p != FINGERPRINT_OK) {
        Serial.println("Fingerprint image2Tz error");
        return -1;
    }

    p = finger.fingerFastSearch();
    if (p != FINGERPRINT_OK) {
        Serial.println("Fingerprint match mismatch or not found");
        return -1; // Mismatch / search error
    }

    // Match found, now check if template ID matches voter's registered slot
    if (finger.fingerID == expectedID) {
        Serial.print("Fingerprint Match Success! ID: ");
        Serial.print(finger.fingerID);
        Serial.print(" | Confidence: ");
        Serial.println(finger.confidence);
        return finger.confidence;
    } else {
        Serial.print("Fingerprint matched ID: ");
        Serial.print(finger.fingerID);
        Serial.print(" but expected ID: ");
        Serial.println(expectedID);
        return -1; // Wrong finger
    }
#endif
}
