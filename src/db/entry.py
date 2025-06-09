#!/usr/bin/env python3.11
import sys
import os
import getpass

SRC_DIR = os.path.dirname(os.path.abspath(__file__)) 
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from db.scripts import add_user, ROLES, create_user_file_if_not_exists

DEFAULT_CONTACT_NUMBER = "0962425842"
DEFAULT_EMAIL = "23521090@gm.uit.edu.vn"

def main():
    print("Healthcare System - User Data Entry Script")
    print("-----------------------------------------")

    create_user_file_if_not_exists()

    while True:
        username = input("Enter username (or type 'exit' to quit): ")
        if username.lower() == 'exit':
            break
        if not username:
            print("Username cannot be empty.")
            continue

        password = getpass.getpass("Enter password: ")
        if not password:
            print("Password cannot be empty.")
            continue
        password_confirm = getpass.getpass("Confirm password: ")
        if password != password_confirm:
            print("Passwords do not match. Please try again.")
            continue

        print(f"Available roles: {', '.join(ROLES)}")
        role = input(f"Enter role for {username}: ")
        if role not in ROLES:
            print(f"Invalid role '{role}'. Please choose from the available roles.")
            continue

        first_name = input("Enter First Name: ") or "Unknown"
        last_name = input("Enter Last Name: ") or "Unknown"
        dob = input("Enter Date of Birth (YYYY-MM-DD): ") or "Unknown"
        gender = input("Enter Gender (M/F/O): ") or "O"
        contact_number = DEFAULT_CONTACT_NUMBER
        email = DEFAULT_EMAIL

        if add_user(username, password, role, first_name, last_name, dob, gender, contact_number, email):
            print(f"User '{username}' successfully added with role '{role}'.")
        else:
            print(f"Failed to add user '{username}'. See error above.")
        
        print("\n")

    print("Exiting data entry script.")

if __name__ == "__main__":
    main()
