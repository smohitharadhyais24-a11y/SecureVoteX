#include "lcd_manager.h"

LCDManager::LCDManager() : lcd(0x27, 16, 2) {}

void LCDManager::init() {
    lcd.init();
    lcd.backlight();
    lcd.clear();
}

void LCDManager::clear() {
    lcd.clear();
}

void LCDManager::displayMessage(const String& line1, const String& line2) {
    lcd.clear();
    lcd.setCursor(0, 0);
    // Print up to 16 characters for line 1
    lcd.print(line1.substring(0, 16));
    lcd.setCursor(0, 1);
    // Print up to 16 characters for line 2
    lcd.print(line2.substring(0, 16));
}

void LCDManager::displayScanRFID() {
    displayMessage("Ready For Voter", "Scan RFID Card");
}

void LCDManager::displayCheckingVoter() {
    displayMessage("Checking Voter...", "Please Wait");
}

void LCDManager::displayScanFinger(int attempt) {
    String attemptStr = "Attempt " + String(attempt) + "/3";
    displayMessage("Scan Finger", attemptStr);
}

void LCDManager::displaySelectCandidate() {
    displayMessage("Select Candidate", "A     B      C");
}

void LCDManager::displaySendingVote() {
    displayMessage("Sending Vote...", "Securing Payload");
}

void LCDManager::displayVoteRecorded(char candidate) {
    String msg = "Candidate ";
    msg += candidate;
    displayMessage("Vote Recorded!", msg);
}

void LCDManager::displayVoterNotFound() {
    displayMessage("Voter Not Found", "Access Denied");
}

void LCDManager::displayAlreadyVoted() {
    displayMessage("Already Voted", "Access Denied");
}

void LCDManager::displayAccessDenied() {
    displayMessage("Access Denied", "Voter Rejected");
}

void LCDManager::displayFingerprintFailed() {
    displayMessage("Fingerprint Fail", "Max Attempts");
}

void LCDManager::displayElectionInactive() {
    displayMessage("Election Closed", "No Voting Allowed");
}

void LCDManager::displaySystemError() {
    displayMessage("System Error", "Try Again Later");
}

void LCDManager::displayAdminMenuHeader() {
    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print("=== ADMIN MENU ===");
}

void LCDManager::displayAdminItem(const String& title, const String& val) {
    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print(title.substring(0, 16));
    lcd.setCursor(0, 1);
    lcd.print(val.substring(0, 16));
}
