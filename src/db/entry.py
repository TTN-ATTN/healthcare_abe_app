#!/usr/bin/env python3.11
import sys
import os
import getpass

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from db.scripts import add_user, ROLES, DatabaseManager, DEFAULT_CONTACT_NUMBER, DEFAULT_EMAIL, DATABASE_FILE

def main():
    print("Healthcare System - User Data Entry Script")
    print("-----------------------------------------")

    print(DATABASE_FILE)
    db_manager = DatabaseManager(DATABASE_FILE)

    while True:
        username = input("Enter username (or type 'exit' to quit): ").strip()
        if username.lower() == 'exit':
            break
        if not username:
            print("Username cannot be empty.")
            continue

        password = getpass.getpass("Enter password: ").strip()
        if not password:
            print("Password cannot be empty.")
            continue
        password_confirm = getpass.getpass("Confirm password: ").strip()
        if password != password_confirm:
            print("Passwords do not match. Please try again.")
            continue

        print(f"Available roles: {', '.join(ROLES.keys())}")
        role = input(f"Enter role for {username}: ").strip()
        if role not in ROLES:
            print(f"Invalid role '{role}'. Please choose from the available roles.")
            continue

        contact_number = input(f"Enter contact number (default: {DEFAULT_CONTACT_NUMBER}): ").strip() or DEFAULT_CONTACT_NUMBER
        email = input(f"Enter email (default: {DEFAULT_EMAIL}): ").strip() or DEFAULT_EMAIL

        if add_user(username, password, role, contact_number, email):
            print(f"User '{username}' successfully added with role '{role}'.")
        else:
            print(f"Failed to add user '{username}'. See error above.")
        
        print("\n")

    print("Exiting data entry script.")

if __name__ == "__main__":
    main()