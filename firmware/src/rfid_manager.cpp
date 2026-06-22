#include "rfid_manager.h"

RFIDManager::RFIDManager() : mfrc522(RFID_SS_PIN, RFID_RST_PIN) {}

void RFIDManager::init() {
    SPI.begin();
    mfrc522.PCD_Init();
}

bool RFIDManager::isCardPresent() {
    // Reset the loop if no new card present on the sensor/reader. This saves power.
    if (!mfrc522.PICC_IsNewCardPresent()) {
        return false;
    }

    // Select one of the cards
    if (!mfrc522.PICC_ReadCardSerial()) {
        return false;
    }

    return true;
}

String RFIDManager::readUID() {
    String uidStr = "";
    for (byte i = 0; i < mfrc522.uid.size; i++) {
        if (i > 0) {
            uidStr += ":";
        }
        if (mfrc522.uid.uidByte[i] < 0x10) {
            uidStr += "0";
        }
        uidStr += String(mfrc522.uid.uidByte[i], HEX);
    }
    uidStr.toUpperCase();
    return uidStr;
}

void RFIDManager::haltCard() {
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
}
