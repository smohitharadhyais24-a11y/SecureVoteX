"""Interactive booth simulator for the IoT secure smart voting system."""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from colorama import Fore, Style, init as colorama_init
from tabulate import tabulate

from booth.fingerprint_simulator import simulate_fingerprint_attempt
from booth.rfid_simulator import format_voter_menu, get_voter_by_choice, list_registered_voters, simulate_rfid_scan
from booth.vote_sender import send_vote_payload
from booth.offline_buffer import get_offline_buffer
from config.config import BOOTH_ID, CANDIDATE_NAMES, DEFAULT_SOURCE_IP, MAX_FINGERPRINT_ATTEMPTS
from security.hashing import generate_payload
from server.database import get_voter_by_rfid, record_audit_log, set_voter_as_voted
from server.vote_verifier import process_vote

logger = logging.getLogger(__name__)
colorama_init(autoreset=True)

MENU_SEPARATOR = "=" * 42
NETWORK_ONLINE = True


def print_header() -> None:
    """Print the title banner for the booth simulator.

    Parameters:
        None.

    Returns:
        None.
    """
    print(MENU_SEPARATOR)
    print("IoT SECURE VOTING SYSTEM - BOOTH SIMULATOR")
    print(MENU_SEPARATOR)


def print_menu() -> None:
    """Display the main menu.

    Parameters:
        None.

    Returns:
        None.
    """
    print_header()
    print("1. Simulate valid voter voting")
    print("2. Simulate unregistered voter")
    print("3. Simulate already-voted voter")
    print("4. Simulate fingerprint failure")
    print("5. Simulate tampered packet attack")
    print("6. Run automated full demo (all scenarios)")
    print("7. Toggle network online/offline (current: {})".format("Online" if NETWORK_ONLINE else "Offline"))
    print("0. Exit")


def _print_led(color: str, state: str) -> None:
    """Print the simulated LED status.

    Parameters:
        color: The LED color label.
        state: The LED state label.

    Returns:
        None.
    """
    print(f"[LED] {color} - {state}")


def _print_buzzer(message: str) -> None:
    """Print the simulated buzzer status.

    Parameters:
        message: The buzzer message to display.

    Returns:
        None.
    """
    print(f"[BUZZER] {message}")


def _print_lcd(message: str) -> None:
    """Print a simulated LCD line.

    Parameters:
        message: The LCD message to display.

    Returns:
        None.
    """
    print(f"[LCD] {message}")


def _show_candidate_list() -> None:
    """Display the candidate list with readable names.

    Parameters:
        None.

    Returns:
        None.
    """
    candidate_rows = [[code, name] for code, name in CANDIDATE_NAMES.items()]
    print(tabulate(candidate_rows, headers=["Code", "Candidate"], tablefmt="grid"))


def _choose_voter(voters: list[dict[str, Any]]) -> dict[str, Any]:
    """Prompt the user to choose one registered voter.

    Parameters:
        voters: The registered voter list.

    Returns:
        The selected voter dictionary.
    """
    print(format_voter_menu(voters))
    while True:
        try:
            choice = int(input("Select voter number: ").strip())
            voter = get_voter_by_choice(voters, choice)
            return voter
        except (ValueError, IndexError):
            print("Invalid selection. Please enter a number from the table.")


def _choose_candidate() -> str:
    """Prompt the user to choose a candidate code.

    Parameters:
        None.

    Returns:
        The selected candidate code.
    """
    _show_candidate_list()
    while True:
        candidate = input("Choose candidate (A/B/C): ").strip().upper()
        if candidate in CANDIDATE_NAMES:
            return candidate
        print("Invalid candidate. Choose A, B, or C.")


def run_valid_voter_flow(db_path: str | None = None) -> None:
    """Simulate a complete valid-voter voting flow.

    Parameters:
        db_path: Optional database path override.

    Returns:
        None.
    """
    voters = list_registered_voters(db_path)
    voter = _choose_voter(voters)
    candidate = _choose_candidate()

    simulate_rfid_scan(str(voter["rfid_id"]))
    _lcd_welcome_sequence(voter, candidate)

    payload = generate_payload(str(voter["rfid_id"]), candidate, BOOTH_ID)
    print("[SYSTEM] Complete payload prepared:")
    print(payload)
    print(f"[SYSTEM] SHA-256 hash: {payload['hash']}")

    if NETWORK_ONLINE:
        result = send_vote_payload(payload, persist_locally_on_failure=True, db_path=db_path)
        if result.get("local_result"):
            print(f"[SERVER] {result['local_result'].get('message')}")
        else:
            print("[SERVER] Vote published to MQTT broker successfully")
    else:
        _print_lcd("Network unavailable")
        _print_lcd("Vote stored securely")
        buf = get_offline_buffer()
        buf.save_vote(payload)

    _print_led("GREEN", "ON")
    _print_buzzer("BEEP - accepted")
    print("[LCD] Vote recorded for Candidate " + candidate)
    print("[LCD] Thank you! Please collect your card.")


def _lcd_welcome_sequence(voter: dict[str, Any], candidate: str | None = None) -> None:
    """Print the LCD sequence for a successful vote.

    Parameters:
        voter: The selected voter dictionary.
        candidate: Optional candidate code to display later.

    Returns:
        None.
    """
    _lcd_check_registration(voter)
    _print_lcd(f"Welcome, {voter['name']}!")
    for attempt in range(1, MAX_FINGERPRINT_ATTEMPTS + 1):
        matched = simulate_fingerprint_attempt(str(voter["name"]), int(voter["fingerprint_id"]), matched=True)
        if matched:
            break
        if attempt == MAX_FINGERPRINT_ATTEMPTS:
            raise RuntimeError("Fingerprint verification unexpectedly failed")
    if candidate is not None:
        _print_lcd("Please vote: A / B / C")


def _lcd_check_registration(voter: dict[str, Any]) -> None:
    """Display the registration check lines.

    Parameters:
        voter: The selected voter dictionary.

    Returns:
        None.
    """
    _print_lcd("Checking registration...")
    _print_lcd(f"Card detected: {voter['rfid_id']}")


def run_unregistered_voter_flow(db_path: str | None = None) -> None:
    """Simulate the flow for an unregistered RFID card.

    Parameters:
        db_path: Optional database path override.

    Returns:
        None.
    """
    fake_rfid = "XX:XX:XX:XX"
    simulate_rfid_scan(fake_rfid)
    _print_lcd("Checking registration...")
    _print_lcd("Access denied: RFID not registered")
    _print_led("RED", "ON")
    _print_buzzer("3 beeps - rejected")
    record_audit_log(
        event_type="REJECTED_UNREGISTERED",
        rfid_id=fake_rfid,
        details="Simulated unregistered voter attempt",
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        ip_address=DEFAULT_SOURCE_IP,
        db_path=db_path,
    )


def run_already_voted_flow(db_path: str | None = None) -> None:
    """Simulate a voter attempting to vote a second time.

    Parameters:
        db_path: Optional database path override.

    Returns:
        None.
    """
    voters = list_registered_voters(db_path)
    voter = _choose_voter(voters)
    if int(voter["has_voted"]) == 0:
        print("[SYSTEM] Creating a prior vote for simulation so the next attempt is rejected.")
        payload = generate_payload(str(voter["rfid_id"]), "A", BOOTH_ID)
        process_vote(payload, ip_address=DEFAULT_SOURCE_IP, db_path=db_path)
    simulate_rfid_scan(str(voter["rfid_id"]))
    _print_lcd("Checking registration...")
    _print_lcd(f"Welcome back, {voter['name']}!")
    _print_led("RED", "ON")
    _print_buzzer("3 beeps - already voted")
    print("[LCD] This card has already been used.")
    process_vote(generate_payload(str(voter["rfid_id"]), "A", BOOTH_ID), ip_address=DEFAULT_SOURCE_IP, db_path=db_path)


def run_fingerprint_failure_flow(db_path: str | None = None) -> None:
    """Simulate a fingerprint verification failure.

    Parameters:
        db_path: Optional database path override.

    Returns:
        None.
    """
    voters = list_registered_voters(db_path)
    voter = _choose_voter(voters)
    simulate_rfid_scan(str(voter["rfid_id"]))
    _print_lcd("Checking registration...")
    _print_lcd(f"Welcome, {voter['name']}!")
    matched = simulate_fingerprint_attempt(str(voter["name"]), int(voter["fingerprint_id"]), matched=False)
    if not matched:
        _print_led("RED", "ON")
        _print_buzzer("3 beeps - fingerprint failed")
        record_audit_log(
            event_type="AUTH_FAILED",
            rfid_id=str(voter["rfid_id"]),
            details="Fingerprint verification failed in simulator",
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            ip_address=DEFAULT_SOURCE_IP,
            db_path=db_path,
        )


def run_tampered_packet_flow(db_path: str | None = None) -> None:
    """Simulate a tampered vote payload being rejected.

    Parameters:
        db_path: Optional database path override.

    Returns:
        None.
    """
    voters = list_registered_voters(db_path)
    voter = voters[0]
    candidate = "A"
    payload = generate_payload(str(voter["rfid_id"]), candidate, BOOTH_ID)
    payload["hash"] = "0" * 64
    print("[SYSTEM] Deliberately corrupted hash for tamper test")
    print(payload)
    result = process_vote(payload, ip_address=DEFAULT_SOURCE_IP, db_path=db_path)
    _print_led("RED", "ON")
    _print_buzzer("3 beeps - tamper detected")
    print(f"[SERVER] {result['message']}")


def run_full_demo(db_path: str | None = None) -> None:
    """Run all simulator scenarios automatically with delays between them.

    Parameters:
        db_path: Optional database path override.

    Returns:
        None.
    """
    scenarios = [
        ("VALID VOTER", run_valid_voter_flow),
        ("UNREGISTERED VOTER", run_unregistered_voter_flow),
        ("ALREADY VOTED", run_already_voted_flow),
        ("FINGERPRINT FAILURE", run_fingerprint_failure_flow),
        ("TAMPERED PACKET", run_tampered_packet_flow),
    ]
    for index, (title, scenario) in enumerate(scenarios, start=1):
        print("\n" + "-" * 60)
        print(f"DEMO SCENARIO {index}: {title}")
        print("-" * 60)
        scenario(db_path=db_path)
        if index != len(scenarios):
            time.sleep(2)


def main() -> None:
    """Run the interactive booth simulator menu.

    Parameters:
        None.

    Returns:
        None.
    """
    logging.basicConfig(level=logging.INFO)
    # Start offline buffer retry loop
    offline_buf = get_offline_buffer()
    offline_buf.start()

    while True:
        print_menu()
        choice = input("Enter your choice: ").strip()
        if choice == "1":
            run_valid_voter_flow()
        elif choice == "2":
            run_unregistered_voter_flow()
        elif choice == "3":
            run_already_voted_flow()
        elif choice == "4":
            run_fingerprint_failure_flow()
        elif choice == "5":
            run_tampered_packet_flow()
        elif choice == "6":
            run_full_demo()
        elif choice == "7":
            global NETWORK_ONLINE
            NETWORK_ONLINE = not NETWORK_ONLINE
            print("Network mode toggled. Now:", "Online" if NETWORK_ONLINE else "Offline")
        elif choice == "0":
            print("Exiting booth simulator.")
            break
        else:
            print("Invalid choice. Please select a number from the menu.")


if __name__ == "__main__":
    main()
