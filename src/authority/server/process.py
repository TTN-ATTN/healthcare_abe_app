# authority/server/process.py
from pymongo import MongoClient
import hashlib
import os

DB_URL = "mongodb://localhost:27017/"

client = MongoClient(DB_URL)
db = client['healthcare']
users_collection = db['users']

def create_sameple_user():
    if 'users' in db.list_collection_names():
        db['users'].drop()
        print("Users collection dropped successfully.")

    if users_collection.count_documents({}) == 0:
        sample_users = [
            {
                "username": "doctor1",
                "password": hashlib.sha256("password123".encode()).hexdigest(),
                "ID": "1001",
                "attributes": ["doctor", "cardiology"]
            },
            {
                "username": "neuro1",
                "password": hashlib.sha256("password123".encode()).hexdigest(),
                "ID": "1002",
                "attributes": ["neurology_doctor"]
            },
            {
                "username": "nurse1",
                "password": hashlib.sha256("password123".encode()).hexdigest(),
                "ID": "2001",
                "attributes": ["nurse", "emergency"]
            },
            {
                "username": "head_nurse1",
                "password": hashlib.sha256("password123".encode()).hexdigest(),
                "ID": "2002",
                "attributes": ["head_nurse"]
            },
            {
                "username": "patient1",
                "password": hashlib.sha256("password123".encode()).hexdigest(),
                "ID": "3001",
                "attributes": ["patient"]
            },
            {
                "username": "researcher1",
                "password": hashlib.sha256("password123".encode()).hexdigest(),
                "ID": "4001",
                "attributes": ["researcher", "cardiology"]
            },
            {
                "username": "accountant1",
                "password": hashlib.sha256("password123".encode()).hexdigest(),
                "ID": "5001",
                "attributes": ["accountant"]
            },
            {
                "username": "pharmacist1",
                "password": hashlib.sha256("password123".encode()).hexdigest(),
                "ID": "6001",
                "attributes": ["pharmacist"]
            },
            {
                "username": "admin",
                "password": hashlib.sha256("password123".encode()).hexdigest(),
                "ID": "0001",
                "attributes": ["admin"]
            }
        ]
        users_collection.insert_many(sample_users)
        print("Sample users created successfully.")
    else:
        print("Sample users already exist in the database.")
        
def authenticate_user(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    user = users_collection.find_one({"username": username.strip(), "password": hashed_password})
    return user
