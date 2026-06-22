#ifndef RFID_MANAGER_H
#define RFID_MANAGER_H

#include <MFRC522.h>
#include <SPI.h>
#include <Arduino.h>
#include "config.h"

class RFIDManager {
public:
    RFIDManager();
    void init();
    bool isCardPresent();
    String readUID();
    void haltCard();

private:
    MFRC522 mfrc522;
};

#endif // RFID_MANAGER_H
