# storage_server/auth.py
from flask import request, jsonify
from functools import wraps
import jwt
import os
from ast import literal_eval
import requests

SECRET_KEY = "shared_secret_key_between_authority_and_storage"
AUTHORITY_SERVER_URL = "http://127.0.0.1:5000"

def get_expanded_attributes(user_attributes):
    """
    Expand specialized roles to include their parent roles
    This creates a hierarchical permission system
    """
    expanded = set(user_attributes.copy())
    
    # Define role hierarchies - specialized roles inherit from general roles
    role_hierarchy = {
        'neurology_doctor': ['doctor'],
        'cardiology_doctor': ['doctor'],
        'pediatric_doctor': ['doctor'],
        'surgery_doctor': ['doctor'],
        'oncology_doctor': ['doctor'],

        'head_nurse': ['nurse', 'administrator'],
        'surgical_nurse': ['nurse'],
        'pediatric_nurse': ['nurse'],
        
        'senior_pharmacist': ['pharmacist'],
        'clinical_pharmacist': ['pharmacist'],
        
        'lead_researcher': ['researcher', 'administrator'],
        'clinical_researcher': ['researcher'],
        
        'senior_accountant': ['accountant'],
        'financial_manager': ['accountant', 'administrator'],
        
        'system_admin': ['administrator'],
        'medical_admin': ['administrator'],
        
        # Add more specialized roles as needed
    }
    
    # Expand attributes based on hierarchy
    for attr in user_attributes:
        if attr in role_hierarchy:
            expanded.update(role_hierarchy[attr])
    
    return list(expanded)

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
            user_attributes = literal_eval(data['attributes']) if isinstance(data['attributes'], str) else data['attributes']
            
            # Expand attributes using hierarchical system
            expanded_attributes = get_expanded_attributes(user_attributes)
            
            current_user = {
                'user_id': data['user_id'],
                'attributes': user_attributes,  # Original attributes
                'expanded_attributes': expanded_attributes,  # Expanded attributes for permission checking
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
        user_attributes = data.get('attributes', [])
        return {
            'user_id': data.get('user_id'),
            'attributes': user_attributes,
            'expanded_attributes': get_expanded_attributes(user_attributes),
            'exp': data.get('exp')
        }
    except:
        return None

def check_permission(required_attributes):
    """
    Decorator to check if user has required attributes for specific actions
    Now uses expanded attributes for hierarchical permission checking
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            current_user = kwargs.get('current_user')
            if not current_user:
                return jsonify({'error': 'User information not found'}), 401
            
            # Use expanded attributes for permission checking
            user_expanded_attributes = current_user.get('expanded_attributes', [])
            print(f"\n\nChecking permissions for user: {current_user['user_id']}, required: {required_attributes}, expanded: {user_expanded_attributes}\n\n")
            user_original_attributes = current_user.get('attributes', [])
            
            # Check if user has any of the required attributes (using expanded attributes)
            has_permission = any(attr in user_expanded_attributes for attr in required_attributes)
            
            if not has_permission:
                return jsonify({
                    'error': 'Access denied!',
                    'message': f'Insufficient privileges for {f.__name__}',
                    'required_attributes': required_attributes,
                    'user_attributes': user_original_attributes,  # Show original for transparency
                    'expanded_attributes': user_expanded_attributes  # Show what permissions they actually have
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator

def get_user_permissions(user_attributes):
    """
    Utility function to get all permissions for a user
    Useful for debugging and user interface
    """
    return {
        'original_attributes': user_attributes,
        'expanded_attributes': get_expanded_attributes(user_attributes),
        'role_hierarchy_applied': True
    }