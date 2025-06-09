import sqlite3
import hashlib
import os
import sys
import json
import base64
from typing import Dict, List, Optional, Tuple
from cryptography.hazmat.primitives import serialization
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
DATABASE_FILE = os.path.join(os.path.dirname(BASE_DIR), "data", "healthcare_system.db")
from utils.abe_core import SecureAES, ABESystem

print(f"Base Directory: {BASE_DIR}")
print(f"Database File: {DATABASE_FILE}")

# Ensure data directory exists
os.makedirs(os.path.dirname(DATABASE_FILE), exist_ok=True)

# Role definitions with ABE attributes
ROLES = {
    "Doctor": {"role": "doctor", "department": "cardiology", "clearance": "level3"},
    "Nurse": {"role": "nurse", "department": "cardiology", "clearance": "level2"},
    "Researcher": {"role": "researcher", "department": "oncology", "clearance": "level2"},
    "Accountant": {"role": "admin", "department": "oncology", "clearance": "level1"},
    "Admin": {"role": "admin", "department": "oncology", "clearance": "level3"}
}

DEFAULT_CONTACT_NUMBER = "0962425842"
DEFAULT_EMAIL = "23521090@gm.uit.edu.vn"

# Initialize ABE system
abe_system = ABESystem()

class DatabaseManager:
    """Handles all database operations with encryption"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.aes_cipher = SecureAES()
        self.init_database()
    
    def get_connection(self):
        """Get database connection"""
        return sqlite3.connect(self.db_path)
    
    def init_database(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Users table with encrypted fields
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL,
                    attributes TEXT NOT NULL,
                    contact_number TEXT,
                    email TEXT,
                    encrypted_profile TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            """)
            
            # ABE keys table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS abe_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    public_key TEXT NOT NULL,
                    private_key TEXT NOT NULL,
                    attributes TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """)
            
            # Audit log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """)
            
            conn.commit()

def hash_password(password: str, salt: str = None) -> Tuple[str, str]:
    """Hash password with salt"""
    if salt is None:
        salt = os.urandom(16)
    else:
        salt = bytes.fromhex(salt)
    
    salted_password = salt + password.encode("utf-8")
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password, salt.hex()

def encrypt_user_profile(profile_data: Dict, user_attributes: List[str]) -> str:
    """Encrypt user profile using ABE"""
    profile_json = json.dumps(profile_data)
    policy = " AND ".join(user_attributes)
    encrypted_data = abe_system.encrypt_data(profile_json.encode(), policy)
    return base64.b64encode(encrypted_data).decode()

def decrypt_user_profile(encrypted_profile: str, user_key) -> Dict:
    """Decrypt user profile using ABE"""
    try:
        encrypted_data = base64.b64decode(encrypted_profile.encode())
        decrypted_data = abe_system.decrypt_data(encrypted_data, user_key)
        return json.loads(decrypted_data.decode())
    except Exception as e:
        print(f"Decryption failed: {e}")
        return {}

def add_user(username: str, password: str, role: str, contact_number: str = None, email: str = None) -> bool:
    """Add a new user with ABE encryption"""
    if role not in ROLES:
        print(f"Invalid role: {role}")
        return False
    
    db_manager = DatabaseManager(DATABASE_FILE)
    
    try:
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            
            # Check if user already exists
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                print(f"User {username} already exists!")
                return False
            
            # Hash password
            password_hash, salt = hash_password(password)
            
            # Get role attributes
            role_attributes = ROLES[role]
            attributes_list = [f"{k}:{v}" for k, v in role_attributes.items()]
            
            # Generate ABE keys
            user_key = abe_system.generate_user_key(role_attributes)
            
            # Encrypt user profile
            profile_data = {
                "contact_number": contact_number or DEFAULT_CONTACT_NUMBER,
                "email": email or DEFAULT_EMAIL,
                "role": role,
                "security_level": role_attributes.get("level", "low")
            }
            encrypted_profile = encrypt_user_profile(profile_data, attributes_list)
            
            # Insert user
            cursor.execute("""
                INSERT INTO users (username, password_hash, salt, role, attributes, 
                                 contact_number, email, encrypted_profile)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (username, password_hash, salt, role, json.dumps(attributes_list),
                  contact_number, email, encrypted_profile))
            
            user_id = cursor.lastrowid
            
            # Store ABE keys
            cursor.execute("""
                INSERT INTO abe_keys (user_id, public_key, private_key, attributes)
                VALUES (?, ?, ?, ?)
            """, (user_id, base64.b64encode(abe_system.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode(),
                  base64.b64encode(user_key).decode(), json.dumps(attributes_list)))
            
            # Log the action
            cursor.execute("""
                INSERT INTO audit_log (user_id, action, details)
                VALUES (?, ?, ?)
            """, (user_id, "USER_CREATED", f"User {username} created with role {role}"))
            
            conn.commit()
            print(f"User {username} added successfully with ABE encryption!")
            return True
            
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    except Exception as e:
        print(f"Error adding user: {e}")
        return False

def authenticate_user(username: str, password: str) -> Optional[Dict]:
    """Authenticate user and return user data"""
    db_manager = DatabaseManager(DATABASE_FILE)
    
    try:
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT u.id, u.username, u.password_hash, u.salt, u.role, 
                       u.encrypted_profile, ak.private_key, ak.attributes
                FROM users u
                JOIN abe_keys ak ON u.id = ak.user_id
                WHERE u.username = ? AND u.is_active = 1
            """, (username,))
            
            user_data = cursor.fetchone()
            if not user_data:
                return None
            
            user_id, username, stored_hash, salt, role, encrypted_profile, private_key, attributes = user_data
            
            # Verify password
            password_hash, _ = hash_password(password, salt)
            if password_hash != stored_hash:
                return None
            
            # Decrypt profile
            user_key = base64.b64decode(private_key.encode())
            profile = decrypt_user_profile(encrypted_profile, user_key)
            
            # Update last login
            cursor.execute("""
                UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
            """, (user_id,))
            
            # Log login
            cursor.execute("""
                INSERT INTO audit_log (user_id, action, details)
                VALUES (?, ?, ?)
            """, (user_id, "USER_LOGIN", f"User {username} logged in"))
            
            conn.commit()
            
            return {
                "id": user_id,
                "username": username,
                "role": role,
                "attributes": json.loads(attributes),
                "profile": profile,
                "private_key": user_key
            }
            
    except Exception as e:
        print(f"Authentication error: {e}")
        return None

def list_users() -> List[Dict]:
    """List all users (admin function)"""
    db_manager = DatabaseManager(DATABASE_FILE)
    
    try:
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT username, role, contact_number, email, created_at, last_login, is_active
                FROM users
                ORDER BY created_at DESC
            """)
            
            users = []
            for row in cursor.fetchall():
                users.append({
                    "username": row[0],
                    "role": row[1],
                    "contact_number": row[2],
                    "email": row[3],
                    "created_at": row[4],
                    "last_login": row[5],
                    "is_active": bool(row[6])
                })
            
            return users
            
    except Exception as e:
        print(f"Error listing users: {e}")
        return []

def get_user_audit_log(user_id: int = None) -> List[Dict]:
    """Get audit log for specific user or all users"""
    db_manager = DatabaseManager(DATABASE_FILE)
    
    try:
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            
            if user_id:
                cursor.execute("""
                    SELECT al.action, al.details, al.timestamp, u.username
                    FROM audit_log al
                    JOIN users u ON al.user_id = u.id
                    WHERE al.user_id = ?
                    ORDER BY al.timestamp DESC
                    LIMIT 100
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT al.action, al.details, al.timestamp, u.username
                    FROM audit_log al
                    JOIN users u ON al.user_id = u.id
                    ORDER BY al.timestamp DESC
                    LIMIT 100
                """
            )
            
            logs = []
            for row in cursor.fetchall():
                logs.append({
                    "action": row[0],
                    "details": row[1],
                    "timestamp": row[2],
                    "username": row[3]
                })
            
            return logs
            
    except Exception as e:
        print(f"Error getting audit log: {e}")
        return []

if __name__ == "__main__":
    # Initialize database
    db_manager = DatabaseManager(DATABASE_FILE)
    print("Database initialized successfully!")
    
    # Test user creation
    test_users = [
        ("admin", "admin123", "Admin"),
        ("doctor1", "doctor123", "Doctor"),
        ("nurse1", "nurse123", "Nurse"),
        ("researcher1", "researcher123", "Researcher"),
        ("accountant1", "accountant123", "Accountant")
    ]
    
    for username, password, role in test_users:
        add_user(username, password, role)
