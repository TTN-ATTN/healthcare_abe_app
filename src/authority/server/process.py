from pymongo import MongoClient
import hashlib
import os

DB_URL = "mongodb://localhost:27017/"

client = MongoClient(DB_URL)
db = client['healthcare']
users_collection = db['users']

def create_sameple_user():
    if users_collection.count_documents({}) == 0:
        sample_users = [
            {
                "username": "doctor1",
                "password": hashlib.sha256("password123".encode()).hexdigest(),
                "ID": "1001",
                "attribute": ["doctor", "cardiology"]
            },
            {
                "username": "nurse1",
                "password": hashlib.sha256("password123".encode()).hexdigest(),
                "ID": "2001",
                "attribute": ["nurse", "emergency"]
            },
            {
                "username": "patient1",
                "password": hashlib.sha256("password123".encode()).hexdigest(),
                "ID": "3001",
                "attribute": ["patient"]
            },
            {
                "username": "researcher1",
                "password": hashlib.sha256("password123".encode()).hexdigest(),
                "ID": "4001",
                "attribute": ["researcher", "cardiology"]
            },
            {
                "username": "accountant1",
                "password": hashlib.sha256("password123".encode()).hexdigest(),
                "ID": "5001",
                "attribute": ["accountant"]
            },
            {
                "username": "pharmacist1",
                "password": hashlib.sha256("password123".encode()).hexdigest(),
                "ID": "6001",
                "attribute": ["pharmacist"]
            }
        ]
        users_collection.insert_many(sample_users)
        print("Sample users created successfully.")
    else:
        print("Sample users already exist in the database.")
        
def authenticate_user(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    user = users_collection.find_one({"username": username, "password": hashed_password})
    return user
