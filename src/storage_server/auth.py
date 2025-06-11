# storage_server/auth.py
from flask import request, jsonify
from functools import wraps
import jwt
import os
from ast import literal_eval
import requests

SECRET_KEY = "shared_secret_key_between_authority_and_storage"
AUTHORITY_SERVER_URL = "http://127.0.0.1:5000"

def check_token(f):
    """
    Decorator to verify JWT tokens issued by the authority server
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            # Handle "Bearer <token>" format
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
            else:
                token = auth_header
        
        elif request.is_json and 'token' in request.json:
            token = request.json['token']

        if not token:
            return jsonify({
                'error': 'Token is missing!',
                'message': 'Please provide a valid JWT token in Authorization header or request body'
            }), 401

        try:
            with open('./keystore/public_key.pem', 'rb') as f:
                public_key = f.read()
            data = jwt.decode(token, public_key, algorithms=['EdDSA'])

            user_attributes = literal_eval(data['attributes']) if isinstance(data['attributes'], str) else data['attributes']
            
            current_user = {
                'user_id': data['user_id'],
                'attributes': user_attributes,  # Original attributes
                'token': token
            }
            
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
            'exp': data.get('exp')
        }
    except:
        return None

def check_permission(required_attributes):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            current_user = kwargs.get('current_user')
            if not current_user:
                return jsonify({'error': 'User information not found'}), 401
            
            user_attributes = current_user.get('attributes', [])
  
            has_permission = any(attr in user_attributes for attr in required_attributes)
            
            if not has_permission:
                return jsonify({
                    'error': 'Access denied!',
                    'message': f'Insufficient privileges for {f.__name__}',
                    'required_attributes': required_attributes,
                    'attributes': user_attributes, 
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator