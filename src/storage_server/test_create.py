import requests
import jwt
import json
from datetime import datetime

AUTHORITY_SERVER = "http://127.0.0.1:5000"
STORAGE_SERVER = "http://127.0.0.1:8000"


def admin_create_users():
    """Test complete workflow from login to data access"""
    print("\n🔄 Testing Complete Workflow...")
    
    # Step 1: Login
    print("  Step 1: Login to authority server")
    login_response = requests.post(
        f"{AUTHORITY_SERVER}/login",
        data={'username': 'admin', 'password': 'admin123'}
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
    
    # Step 3: Access Storage Server - Get Users
    print("  Step 3: Access storage server with token (Get Users)")
    storage_response = requests.get(
        f"{STORAGE_SERVER}/api/users",
        headers={'Authorization': f'Bearer {token}'}
    )
    print(f"    Storage access status: {storage_response.status_code}")
    
    if storage_response.status_code == 200:
        print(" ✅ Storage server access successful!")
        data = storage_response.json()
        print(f"    Retrieved {data.get('count', 0)} users")
        users = data.get('users', [])
        for user in users:
            print(f"      User: {user.get('username')} (ID: {user.get('user_id')}, Attributes: {user.get('attributes')})")
    else:
        print(f" ❌ Storage access failed: {storage_response.text[:200]}")
        return
    
    # Step 4: Test Health Records Access
    print("  Step 4: Test health records access")
    health_response = requests.get(
        f"{STORAGE_SERVER}/api/health_records",
        headers={'Authorization': f'Bearer {token}'}
    )
    print(f"    Health records status: {health_response.status_code}")
    
    if health_response.status_code == 200:
        print(" ✅ Health records access successful!")
        health_data = health_response.json()
        print(f"    Retrieved {health_data.get('count', 0)} health records")
    else:
        print(f" ❌ Health records access failed: {health_response.text[:200]}")
    
    # Step 5: Create a new user
    print("  Step 5: Create a new user")
    new_user_data = {
        'user_id': '2001',
        'username': 'test_doctor',
        'password': 'password123',
        'attributes': ['doctor'],
        'role': 'doctor'
    }
    
    create_user_response = requests.post(
        f"{STORAGE_SERVER}/api/user",
        json=new_user_data,
        headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    )
    print(f"    Create user status: {create_user_response.status_code}")
    
    if create_user_response.status_code == 201:
        print(" ✅ User creation successful!")
        created_user = create_user_response.json()
        print(f"    Created user: {created_user.get('user', {}).get('username')}")
    else:
        print(f" ❌ User creation failed: {create_user_response.text[:200]}")
    
    # Step 6: Test Sample Data Creation
    print("  Step 6: Create sample health data")
    sample_data_response = requests.post(
        f"{STORAGE_SERVER}/api/create_sample_data",
        headers={'Authorization': f'Bearer {token}'}
    )
    print(f"    Sample data status: {sample_data_response.status_code}")
    
    if sample_data_response.status_code == 201:
        print(" ✅ Sample data creation successful!")
        sample_data = sample_data_response.json()
        print(f"    Created {sample_data.get('health_records', 0)} health records")
        print(f"    Created {sample_data.get('medicine_records', 0)} medicine records")
    else:
        print(f" ❌ Sample data creation failed: {sample_data_response.text[:200]}")

def test_token_decode():
    """Test JWT token decoding"""
    print("\n🔍 Testing JWT Token Decoding...")
    
    # First get a token
    login_response = requests.post(
        f"{AUTHORITY_SERVER}/login",
        data={'username': 'admin', 'password': 'admin123'}
    )
    
    if login_response.status_code != 200:
        print(" ❌ Cannot get token for testing")
        return
    
    user_data = login_response.json()
    token_response = requests.post(
        f"{AUTHORITY_SERVER}/token",
        json={
            'user_id': user_data.get('user_id'),
            'attributes': user_data.get('attributes', [])
        },
        headers={'Content-Type': 'application/json'}
    )
    
    if token_response.status_code != 200:
        print(" ❌ Cannot get token for testing")
        return
    
    token = token_response.json().get('token')
    
    try:
        # Decode without verification to see contents
        decoded = jwt.decode(token, options={"verify_signature": False})
        print(" ✅ Token decoded successfully!")
        print(f"    User ID: {decoded.get('user_id')}")
        print(f"    Attributes: {decoded.get('attributes')}")
        print(f"    Expires: {datetime.fromtimestamp(decoded.get('exp', 0))}")
    except Exception as e:
        print(f" ❌ Token decode failed: {e}")


if __name__ == "__main__":
    print("🚀 Healthcare Storage Server Test Suite")
    print("=" * 50)
    
    # Test different components
    test_token_decode()
    admin_create_users()
    
    print("\n" + "=" * 50)
    print("✅ Test suite completed!")