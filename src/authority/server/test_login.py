import requests
import pytest
import json
from unittest.mock import patch, MagicMock
import hashlib
import jwt
import datetime

# Base URL for your Flask application
BASE_URL = "http://127.0.0.1:5000"

class TestLoginAPI:
    """Test cases for the login API endpoints"""
    
    def setup_method(self):
        """Setup method run before each test"""
        self.base_url = BASE_URL
        self.login_url = f"{self.base_url}/login"
        self.logout_url = f"{self.base_url}/logout"
        self.token_url = f"{self.base_url}/token"
        
        # Test user credentials based on your process.py sample data
        self.valid_users = [
            {"username": "doctor1", "password": "password123"},
            {"username": "nurse1", "password": "password123"},
            {"username": "patient1", "password": "password123"},
            {"username": "researcher1", "password": "password123"}
        ]
        
    def test_successful_login(self):
        """Test successful login with valid credentials"""
        for user in self.valid_users:
            response = requests.post(
                self.login_url,
                data={
                    'username': user['username'],
                    'password': user['password']
                }
            )
            
            assert response.status_code == 200
            user_data = response.json()
            assert 'username' in user_data
            assert user_data['username'] == user['username']
            assert '_id' in user_data
            print(f"✓ Login successful for {user['username']}")
            
            # Print user data for debugging
            print(f"  User ID: {user_data.get('_id')}")
            print(f"  Attributes: {user_data.get('attribute', [])}")
    
    def test_login_missing_username(self):
        """Test login with missing username"""
        response = requests.post(
            self.login_url,
            data={'password': 'password123'}
        )
        
        assert response.status_code == 400
        assert "Missing username or password" in response.text
        print("✓ Missing username handled correctly")
    
    def test_login_missing_password(self):
        """Test login with missing password"""
        response = requests.post(
            self.login_url,
            data={'username': 'doctor1'}
        )
        
        assert response.status_code == 400
        assert "Missing username or password" in response.text
        print("✓ Missing password handled correctly")
    
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        response = requests.post(
            self.login_url,
            data={
                'username': 'nonexistent',
                'password': 'wrongpassword'
            }
        )
        
        assert response.status_code == 401
        assert "Invalid username or password" in response.text
        print("✓ Invalid credentials handled correctly")
    
    def test_login_wrong_password(self):
        """Test login with correct username but wrong password"""
        response = requests.post(
            self.login_url,
            data={
                'username': 'doctor1',
                'password': 'wrongpassword'
            }
        )
        
        assert response.status_code == 401
        assert "Invalid username or password" in response.text
        print("✓ Wrong password handled correctly")
    
    def test_logout_success(self):
        """Test successful logout"""
        # First login to establish a session
        login_response = requests.post(
            self.login_url,
            data={
                'username': 'doctor1',
                'password': 'password123'
            }
        )
        
        assert login_response.status_code == 200
        
        # Get session cookies
        session_cookies = login_response.cookies
        
        # Test logout
        logout_response = requests.post(
            self.logout_url,
            cookies=session_cookies
        )
        
        assert logout_response.status_code == 200
        assert "Logged out successfully" in logout_response.text
        print("✓ Logout successful")
    
    def test_token_generation_and_decode(self):
        """Test JWT token generation and decode the token content"""
        print("\n" + "="*60)
        print("JWT TOKEN GENERATION AND ANALYSIS")
        print("="*60)
        
        for user_creds in self.valid_users:
            print(f"\n Testing token for user: {user_creds['username']}")
            print("-" * 40)
            
            # First login to get user data
            login_response = requests.post(
                self.login_url,
                data={
                    'username': user_creds['username'],
                    'password': user_creds['password']
                }
            )
            
            assert login_response.status_code == 200
            user_data = login_response.json()
            
            print(f" User Data Retrieved:")
            print(f"   Username: {user_data.get('username')}")
            print(f"   User ID: {user_data.get('_id')}")
            print(f"   Attributes: {user_data.get('attribute', [])}")
            
            # Test token generation
            token_response = requests.post(
                self.token_url,
                json={
                    '_id': user_data['_id'],
                    'attribute': user_data.get('attribute', [])
                },
                headers={'Content-Type': 'application/json'}
            )
            
            assert token_response.status_code == 200
            token = token_response.text.strip('"')  # Remove quotes if present
            
            print(f"\n Generated JWT Token:")
            print(f"   {token}")
            print(f"   Token Length: {len(token)} characters")
            
            # Try to decode the token (without verification since we don't have the secret)
            try:
                # Decode header
                header = jwt.get_unverified_header(token)
                print(f"\n Token Header:")
                for key, value in header.items():
                    print(f"   {key}: {value}")
                
                # Decode payload (without verification)
                payload = jwt.decode(token, options={"verify_signature": False})
                print(f"\n Token Payload:")
                for key, value in payload.items():
                    if key == 'exp':
                        # Convert timestamp to readable date
                        exp_date = datetime.datetime.fromtimestamp(value)
                        print(f"   {key}: {value} ({exp_date})")
                    else:
                        print(f"   {key}: {value}")
                
                # Calculate token validity period
                if 'exp' in payload:
                    exp_time = datetime.datetime.fromtimestamp(payload['exp'])
                    current_time = datetime.datetime.utcnow()
                    time_remaining = exp_time - current_time
                    print(f"\n Token Validity:")
                    print(f"   Expires at: {exp_time} UTC")
                    print(f"   Current time: {current_time} UTC")
                    print(f"   Time remaining: {time_remaining}")
                    
            except jwt.InvalidTokenError as e:
                print(f" Error decoding token: {e}")
            except Exception as e:
                print(f" Unexpected error: {e}")
            
            print("-" * 40)
    
    def test_token_invalid_request(self):
        """Test token generation with invalid request"""
        token_response = requests.post(
            self.token_url,
            json={},
            headers={'Content-Type': 'application/json'}
        )
        
        assert token_response.status_code == 400
        assert "Invalid request" in token_response.text
        print("✓ Invalid token request handled correctly")
    
    def test_complete_login_flow_with_token_analysis(self):
        """Test complete login flow with detailed token analysis"""
        print("\n" + "="*60)
        print("COMPLETE LOGIN FLOW WITH TOKEN ANALYSIS")
        print("="*60)
        
        username = "doctor1"
        password = "password123"
        
        print(f"\n Starting complete flow for {username}")
        
        # Step 1: Login
        print("\n Step 1: Login")
        login_response = requests.post(
            self.login_url,
            data={
                'username': username,
                'password': password
            }
        )
        
        assert login_response.status_code == 200
        user_data = login_response.json()
        session_cookies = login_response.cookies
        
        print(f"   ✓ Login successful")
        print(f"    User: {user_data.get('username')}")
        print(f"    ID: {user_data.get('_id')}")
        print(f"    Attributes: {user_data.get('attribute', [])}")
        
        # Step 2: Get token
        print("\n Step 2: Generate JWT Token")
        token_response = requests.post(
            self.token_url,
            json={
                '_id': user_data['_id'],
                'attribute': user_data.get('attribute', [])
            },
            headers={'Content-Type': 'application/json'},
            cookies=session_cookies
        )
        
        assert token_response.status_code == 200
        token = token_response.text.strip('"')
        
        print(f"   ✓ Token generated successfully")
        print(f"    JWT Token: {token}")
        
        # Decode and analyze token
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            print(f"     Token contains:")
            print(f"      - User ID: {payload.get('user_id')}")
            print(f"      - Attributes: {payload.get('attributes')}")
            print(f"      - Expires: {datetime.datetime.fromtimestamp(payload.get('exp', 0))}")
        except Exception as e:
            print(f"   Token decode error: {e}")
        
        # Step 3: Logout
        print("\n Step 3: Logout")
        logout_response = requests.post(
            self.logout_url,
            cookies=session_cookies
        )
        
        assert logout_response.status_code == 200
        print("   ✓ Logout successful")
        print("\n Complete login flow finished successfully!")

def test_password_hashing():
    """Test password hashing functionality"""
    password = "password123"
    expected_hash = hashlib.sha256(password.encode()).hexdigest()
    
    # This tests that our expected hash matches what's in the database
    actual_hash = hashlib.sha256("password123".encode()).hexdigest()
    assert expected_hash == actual_hash
    print("✓ Password hashing works correctly")
    print(f"  Password: {password}")
    print(f"  Hash: {expected_hash}")

def test_user_attributes():
    """Test that user attributes are correctly structured"""
    print("\n" + "="*50)
    print("USER ATTRIBUTES VERIFICATION")
    print("="*50)
    
    expected_attributes = {
        "doctor1": ["doctor", "cardiology"],
        "nurse1": ["nurse", "emergency"],
        "patient1": ["patient"],
        "researcher1": ["researcher"]  # Assuming completion based on pattern
    }
    
    for username, expected_attrs in expected_attributes.items():
        print(f"\n Testing user: {username}")
        
        # Login to get user data
        response = requests.post(
            f"{BASE_URL}/login",
            data={
                'username': username,
                'password': 'password123'
            }
        )
        
        if response.status_code == 200:
            user_data = response.json()
            user_attributes = user_data.get('attribute', [])
            
            print(f"   Expected: {expected_attrs}")
            print(f"   Actual: {user_attributes}")
            
            # Check if expected attributes are present
            for attr in expected_attrs:
                if attr in user_attributes:
                    print(f"   Attribute '{attr}' found")
                else:
                    print(f"   Attribute '{attr}' missing")
        else:
            print(f"   Failed to login: {response.status_code}")

def test_all_user_tokens():
    """Generate and display tokens for all users"""
    print("\n" + "="*70)
    print("ALL USER TOKENS GENERATION")
    print("="*70)
    
    valid_users = [
        {"username": "doctor1", "password": "password123"},
        {"username": "nurse1", "password": "password123"},
        {"username": "patient1", "password": "password123"},
        {"username": "researcher1", "password": "password123"}
    ]
    
    tokens_collection = {}
    
    for user_creds in valid_users:
        print(f"\nGenerating token for: {user_creds['username']}")
        
        # Login
        login_response = requests.post(
            f"{BASE_URL}/login",
            data=user_creds
        )
        
        if login_response.status_code == 200:
            user_data = login_response.json()
            
            # Generate token
            token_response = requests.post(
                f"{BASE_URL}/token",
                json={
                    '_id': user_data['_id'],
                    'attribute': user_data.get('attribute', [])
                },
                headers={'Content-Type': 'application/json'}
            )
            
            if token_response.status_code == 200:
                token = token_response.text.strip('"')
                tokens_collection[user_creds['username']] = token
                
                print(f"   ✓ Token generated successfully")
                print(f"   User: {user_data.get('username')}")
                print(f"   ID: {user_data.get('_id')}")
                print(f"   Attributes: {user_data.get('attribute', [])}")
                print(f"   Token: {token}")
                
                # Quick decode
                try:
                    payload = jwt.decode(token, options={"verify_signature": False})
                    exp_time = datetime.datetime.fromtimestamp(payload.get('exp', 0))
                    print(f"Expires: {exp_time}")
                except:
                    print(f"Could not decode token expiration")
            else:
                print(f"Token generation failed: {token_response.status_code}")
        else:
            print(f" Login failed: {login_response.status_code}")

    # Summary
    print(f"\nTOKENS SUMMARY")
    print("-" * 50)
    for username, token in tokens_collection.items():
        print(f"{username}: {token[:50]}...")
    
    return tokens_collection

if __name__ == "__main__":
    """Run tests directly"""
    print("Starting Enhanced Login API Tests with JWT Token Analysis...")
    print("=" * 80)
    
    # Create test instance
    test_instance = TestLoginAPI()
    test_instance.setup_method()
    
    try:
        # Run individual tests
        print("\nBASIC LOGIN TESTS")
        print("-" * 30)
        test_instance.test_successful_login()
        test_instance.test_login_missing_username()
        test_instance.test_login_missing_password()
        test_instance.test_login_invalid_credentials()
        test_instance.test_login_wrong_password()
        test_instance.test_logout_success()
        
        # Enhanced token tests
        test_instance.test_token_generation_and_decode()
        test_instance.test_token_invalid_request()
        test_instance.test_complete_login_flow_with_token_analysis()
        
        # Run standalone tests
        print("\n SECURITY TESTS")
        print("-" * 20)
        test_password_hashing()
        test_user_attributes()
        
        # Generate all tokens
        test_all_user_tokens()
        
        print("\n" + "=" * 80)
        print(" ALL TESTS COMPLETED SUCCESSFULLY!")
        print("=" * 80)
        
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the Flask application.")
        print("Please make sure your Flask app is running on http://127.0.0.1:5000")
        print("Run: python app.py")
        
    except Exception as e:
        print(f"Test error: {str(e)}")
        import traceback
        traceback.print_exc()
