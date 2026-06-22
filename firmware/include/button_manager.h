#ifndef BUTTON_MANAGER_H
#define BUTTON_MANAGER_H

#include "config.h"

class ButtonManager {
public:
    ButtonManager();
    void init();
    void update();
    char getPressedCandidate();
    bool isButtonPressed(int pin);

private:
    unsigned long lastDebounceTimeA;
    unsigned long lastDebounceTimeB;
    unsigned long lastDebounceTimeC;

    int lastButtonStateA;
    int lastButtonStateB;
    int lastButtonStateC;

    int buttonStateA;
    int buttonStateB;
    int buttonStateC;
};

#endif // BUTTON_MANAGER_H
