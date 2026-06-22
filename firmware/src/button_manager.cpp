#include "button_manager.h"

ButtonManager::ButtonManager() {
    lastDebounceTimeA = 0;
    lastDebounceTimeB = 0;
    lastDebounceTimeC = 0;

    lastButtonStateA = HIGH;
    lastButtonStateB = HIGH;
    lastButtonStateC = HIGH;

    buttonStateA = HIGH;
    buttonStateB = HIGH;
    buttonStateC = HIGH;
}

void ButtonManager::init() {
    pinMode(BUTTON_A_PIN, INPUT_PULLUP);
    pinMode(BUTTON_B_PIN, INPUT_PULLUP);
    pinMode(BUTTON_C_PIN, INPUT_PULLUP);
}

void ButtonManager::update() {
    int readingA = digitalRead(BUTTON_A_PIN);
    int readingB = digitalRead(BUTTON_B_PIN);
    int readingC = digitalRead(BUTTON_C_PIN);

    // Debounce Button A
    if (readingA != lastButtonStateA) {
        lastDebounceTimeA = millis();
    }
    if ((millis() - lastDebounceTimeA) > DEBOUNCE_DELAY_MS) {
        buttonStateA = readingA;
    }
    lastButtonStateA = readingA;

    // Debounce Button B
    if (readingB != lastButtonStateB) {
        lastDebounceTimeB = millis();
    }
    if ((millis() - lastDebounceTimeB) > DEBOUNCE_DELAY_MS) {
        buttonStateB = readingB;
    }
    lastButtonStateB = readingB;

    // Debounce Button C
    if (readingC != lastButtonStateC) {
        lastDebounceTimeC = millis();
    }
    if ((millis() - lastDebounceTimeC) > DEBOUNCE_DELAY_MS) {
        buttonStateC = readingC;
    }
    lastButtonStateC = readingC;
}

char ButtonManager::getPressedCandidate() {
    // Check for falling edge (active LOW)
    static int prevStableA = HIGH;
    static int prevStableB = HIGH;
    static int prevStableC = HIGH;

    char pressed = '\0';

    if (buttonStateA == LOW && prevStableA == HIGH) {
        pressed = 'A';
    } else if (buttonStateB == LOW && prevStableB == HIGH) {
        pressed = 'B';
    } else if (buttonStateC == LOW && prevStableC == HIGH) {
        pressed = 'C';
    }

    prevStableA = buttonStateA;
    prevStableB = buttonStateB;
    prevStableC = buttonStateC;

    return pressed;
}

bool ButtonManager::isButtonPressed(int pin) {
    if (pin == BUTTON_A_PIN) return buttonStateA == LOW;
    if (pin == BUTTON_B_PIN) return buttonStateB == LOW;
    if (pin == BUTTON_C_PIN) return buttonStateC == LOW;
    return false;
}
