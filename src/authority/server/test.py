#!/usr/bin/env python3
"""
Individual Component Tester
Test specific components separately for detailed debugging
"""

import requests
import jwt
import json
from datetime import datetime

AUTHORITY_SERVER = "http://127.0.0.1:5000"
STORAGE_SERVER = "http://127.0.0.1:8000"

def test_authority_endpoints():
    """Test all authority server endpoints"""
    print("🔍 Testing Authority Server Endpoints...")
    
    endpoints = [
        ("/login", "POST"),
        ("/logout", "POST"),
        ("/token", "POST"),
        ("/verify_token", "POST"),
        ("/get_keys", "POST")
    ]
    
    for endpoint, method in endpoints:
        try:
            if method == "GET":
                response = requests.get(f"{AUTHORITY_SERVER}{endpoint}", timeout=5)
            else:
                response = requests.post(f"{AUTHORITY_SERVER}{endpoint}", timeout=5)
            
            print(f"  {method} {endpoint}: {response.status_code}")
        except Exception as e:
            print(f"  {method} {endpoint}: ERROR - {str(e)}")

def test_storage_endpoints():
    """Test all storage server endpoints"""
    print("\n🔍 Testing Storage Server Endpoints...")
    
    endpoints = [
        ("/health", "GET"),
        ("/api/profile", "GET"),
        ("/api/users", "GET"),
        ("/api/health_records", "GET"),
        ("/api/medicine_records", "GET"),
        ("/api/research_records", "GET"),
    ]
    
    for endpoint, method in endpoints:
        try:
            if method == "GET":
                response = requests.get(f"{STORAGE_SERVER}{endpoint}", timeout=5)
            else:
                response = requests.post(f"{STORAGE_SERVER}{endpoint}", timeout=5)
            
            print(f"  {method} {endpoint}: {response.status_code}")
        except Exception as e:
            print(f"  {method} {endpoint}: ERROR - {str(e)}")

def test_complete_workflow():
    """Test complete workflow from login to data access"""
    print("\n🔄 Testing Complete Workflow...")
    
    # Step 1: Login
    print("  Step 1: Login to authority server")
    login_response = requests.post(
        f"{AUTHORITY_SERVER}/login",
        data={'username': 'doctor1', 'password': 'password123'}
    )
    print(f"    Login status: {login_response.status_code}")
    
    if login_response.status_code != 200:
        print(" ❌ Login failed - cannot continue workflow test")
        print(f"    Error: {login_response.text}")
        return
    
    user_data = login_response.json()
    print(f"    User ID: {user_data.get('user_id', 'Not found')}")
    print(f"    Attributes: {user_data.get('attributes', [])}")
    
    # Step 2: Get Token
    print("  Step 2: Get JWT token")
    token_response = requests.post(
        f"{AUTHORITY_SERVER}/token",
        json={
            'user_id': user_data.get('user_id'),
            'attributes': user_data.get('attributes', [])
        },
        headers={'Content-Type': 'application/json'}
    )
    print(f"    Token status: {token_response.status_code}")
    
    if token_response.status_code != 200:
        print("  ❌ Token generation failed - cannot continue workflow test")
        print(f"    Error: {token_response.text}")
        return
    
    token_data = token_response.json()
    token = token_data.get('token')
    print(f"    Token length: {len(token)} characters")
    
    # Step 3: Access Storage Server
    print("  Step 3: Access storage server with token")
    storage_response = requests.get(
        f"{STORAGE_SERVER}/api/health_records",
        headers={'Authorization': f'Bearer {token}'}
    )
    print(f"    Storage access status: {storage_response.status_code}")
    
    if storage_response.status_code == 200:
        print(" ✅ Complete workflow successful!")
        data = storage_response.json()
        print(f"    Retrieved {data.get('count', 0)} health records")
    else:
        print(f" ❌ Storage access failed: {storage_response.text[:200]}")

def test_individual_users():
    """Test login for different user types"""
    print("\n👥 Testing Different User Types...")
    
    test_users = [
        ('doctor1', 'password123'),
        ('nurse1', 'password123'), 
        ('patient1', 'password123'),
        ('researcher1', 'password123'),
        ('admin', 'password123')
    ]
    
    for username, password in test_users:
        print(f"  Testing {username}:")
        try:
            login_response = requests.post(
                f"{AUTHORITY_SERVER}/login",
                data={'username': username, 'password': password}
            )
            if login_response.status_code == 200:
                user_data = login_response.json()
                print(f"    ✅ Login successful - Attributes: {user_data.get('attributes', [])}")
            else:
                print(f"    ❌ Login failed: {login_response.status_code}")
        except Exception as e:
            print(f"    ❌ Error: {str(e)}")

if __name__ == "__main__":
    test_authority_endpoints()
    test_storage_endpoints() 
    test_complete_workflow()
    test_individual_users()