from flask import request, jsonify
from functools import wraps
import jwt
import os
from ast import literal_eval
import requests

# This should match the SECRET_KEY from your authority server's auth_api.py
# In production, this should be shared securely between services
SECRET_KEY = "shared_secret_key_between_authority_and_storage"
AUTHORITY_SERVER_URL = "http://127.0.0.1:5000"

def check_token(f):
    """
    Decorator to verify JWT tokens issued by the authority server
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Check for token in Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            # Handle "Bearer <token>" format
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
            else:
                token = auth_header
        
        # Check for token in request body (for compatibility)
        elif request.is_json and 'token' in request.json:
            token = request.json['token']

        if not token:
            return jsonify({
                'error': 'Token is missing!',
                'message': 'Please provide a valid JWT token in Authorization header or request body'
            }), 401

        try:
            # Decode token using the same secret key as authority server
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            
            # Extract user information from token
            current_user = {
                'user_id': data['user_id'],
                'attributes': literal_eval(data['attributes']) if isinstance(data['attributes'], str) else data['attributes'],
                'token': token
            }
            
            # Add current_user to kwargs for use in the decorated function
            kwargs['current_user'] = current_user
            
            return f(*args, **kwargs)
            
        except jwt.ExpiredSignatureError:
            return jsonify({
                'error': 'Token has expired!',
                'message': 'Please login again to get a new token'
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                'error': 'Token is invalid!',
                'message': 'Please provide a valid JWT token'
            }), 401
        except Exception as e:
            return jsonify({
                'error': 'Token verification failed!',
                'message': str(e)
            }), 401

    return decorated

def verify_token_with_authority(token):
    """
    Optional: Verify token with authority server directly
    This adds an extra layer of security but increases latency
    """
    try:
        response = requests.post(
            f"{AUTHORITY_SERVER_URL}/verify_token",
            json={'token': token},
            timeout=5
        )
        return response.status_code == 200
    except:
        return False

def extract_user_attributes(token):
    """
    Extract user attributes from JWT token without verification
    Useful for logging and debugging
    """
    try:
        data = jwt.decode(token, options={"verify_signature": False})
        return {
            'user_id': data.get('user_id'),
            'attributes': data.get('attributes', []),
            'exp': data.get('exp')
        }
    except:
        return None

def check_permission(required_attributes):
    """
    Decorator to check if user has required attributes for specific actions
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # This assumes check_token was already applied
            current_user = kwargs.get('current_user')
            if not current_user:
                return jsonify({'error': 'User information not found'}), 401
            
            user_attributes = current_user.get('attributes', [])
            
            # Check if user has any of the required attributes
            has_permission = any(attr in user_attributes for attr in required_attributes)
            
            if not has_permission:
                return jsonify({
                    'error': 'Access denied!',
                    'message': f'Required attributes: {required_attributes}',
                    'user_attributes': user_attributes
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator
