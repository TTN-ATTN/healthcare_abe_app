#!/usr/bin/env python3.11
import csv
import hashlib
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
print(f"Base Directory: {BASE_DIR}")
USER_DATA_FILE = os.path.join(BASE_DIR, "data", "users.csv")
print(f"User Data File: {USER_DATA_FILE}")
os.makedirs(os.path.dirname(USER_DATA_FILE), exist_ok=True)

ROLES = ["Doctor", "Nurse", "Researcher", "Accountant", "Admin"]

DEFAULT_CONTACT_NUMBER = "0962425842"
DEFAULT_EMAIL = "23521090@gm.uit.edu.vn"

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    else:
        salt = bytes.fromhex(salt)
    salted_password = salt + password.encode("utf-8")
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password, salt.hex()

def create_user_file_if_not_exists():
    if not os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "first_name", "last_name", "dob", "gender", "contact_number", "email", "salt", "hashed_password", "role", "department", "clearance_level", "employee_id"])

def add_user(username, password, role, first_name="Unknown", last_name="Unknown", dob="Unknown", gender="Unknown", department="N/A", clearance_level="N/A", employee_id="N/A"):
    create_user_file_if_not_exists()
    if role not in ROLES:
        print(f"Error: Invalid role \'{role}\'. Must be one of {ROLES}")
        return False

    with open(USER_DATA_FILE, "r", newline="") as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            if row and row[0] == username:
                print(f"Error: Username \'{username}\' already exists.")
                return False

    hashed_pw, salt_hex = hash_password(password)
    with open(USER_DATA_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([username, first_name, last_name, dob, gender, DEFAULT_CONTACT_NUMBER, DEFAULT_EMAIL, salt_hex, hashed_pw, role, department, clearance_level, employee_id])
    print(f"User \'{username}\' added successfully with role \'{role}\'.")
    return True

def verify_user(username, password):
    create_user_file_if_not_exists()
    try:
        with open(USER_DATA_FILE, "r", newline="") as f:
            reader = csv.reader(f)
            header = next(reader)
            expected_header = ["username", "first_name", "last_name", "dob", "gender", "contact_number", "email", "salt", "hashed_password", "role", "department", "clearance_level", "employee_id"]
            if header != expected_header:
                print("Error: User data file has incorrect header. Expected: {expected_header}, Got: {header}")
                return None
            for row in reader:
                if row and row[0] == username:
                    stored_salt_hex = row[7]
                    stored_hashed_pw = row[8]
                    user_role = row[9]
                    hashed_attempt, _ = hash_password(password, stored_salt_hex)
                    if hashed_attempt == stored_hashed_pw:
                        print(f"User \'{username}\' verified successfully. Role: {user_role}")
                        return user_role
                    else:
                        print(f"Error: Invalid password for user \'{username}\'.")
                        return None
            print(f"Error: User \'{username}\' not found.")
            return None
    except FileNotFoundError:
        print("Error: User data file not found.")
        return None
    except Exception as e:
        print(f"An error occurred during user verification: {e}")
        return None

if __name__ == "__main__":
    # Ensure the user data file is clean for testing
    if os.path.exists(USER_DATA_FILE):
        os.remove(USER_DATA_FILE)

    create_user_file_if_not_exists()
    add_user("doctor_dave", "pass123", "Doctor", "Dave", "Smith", "1980-05-15", "Male", department="Cardiology", clearance_level="Level 3", employee_id="EMP001")
    add_user("nurse_nancy", "securePass!", "Nurse", "Nancy", "Jones", "1992-08-23", "Female", department="Pediatrics", clearance_level="Level 2", employee_id="EMP002")
    add_user("research_rob", "resPass456", "Researcher", "Rob", "Brown", "1985-03-12", "Male", department="Oncology Research", clearance_level="Level 2", employee_id="EMP003")
    add_user("admin_andy", "adminPass789", "Admin", "Andy", "White", "1975-12-09", "Male", department="IT", clearance_level="Level 4", employee_id="EMP004")
    add_user("account_anna", "accPass!@#", "Accountant", "Anna", "Davis", "1990-11-30", "Female", department="Finance", clearance_level="Level 1", employee_id="EMP005")

    print("\n--- Verifying Users ---")
    verify_user("doctor_dave", "pass123")
    verify_user("nurse_nancy", "securePass!")
    verify_user("research_rob", "wrongPass")
    verify_user("nonexistent_user", "anypass")
    verify_user("admin_andy", "adminPass789")
    verify_user("account_anna", "accPass!@#")


