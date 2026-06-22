#ifndef LCD_MANAGER_H
#define LCD_MANAGER_H

#include <LiquidCrystal_I2C.h>
#include <Arduino.h>

class LCDManager {
public:
    LCDManager();
    void init();
    void clear();
    void displayMessage(const String& line1, const String& line2);
    
    // Voting Workflow Displays
    void displayScanRFID();
    void displayCheckingVoter();
    void displayScanFinger(int attempt);
    void displaySelectCandidate();
    void displaySendingVote();
    void displayVoteRecorded(char candidate);
    
    // Error States
    void displayVoterNotFound();
    void displayAlreadyVoted();
    void displayAccessDenied();
    void displayFingerprintFailed();
    void displayElectionInactive();
    void displaySystemError();
    
    // Admin Menu Displays
    void displayAdminMenuHeader();
    void displayAdminItem(const String& title, const String& val);

private:
    LiquidCrystal_I2C lcd;
};

#endif // LCD_MANAGER_H
