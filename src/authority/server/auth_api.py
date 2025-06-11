# authority/server/auth_api.py
from flask import Blueprint, request, jsonify, session
import jwt
import datetime
import os

auth_api = Blueprint('auth_api', __name__)

SECRET_KEY = "shared_secret_key_between_authority_and_storage"

@auth_api.route('/verify_token', methods=['POST'])
def verify_token():
    """Verify if a token is valid - for storage server"""
    data = request.json
    if not data or 'token' not in data:
        return "Invalid request", 400
    
    try:
        token = data['token']
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({'valid': True, 'user_data': decoded}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'valid': False, 'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'valid': False, 'error': 'Invalid token'}), 401

@auth_api.route('/token', methods=['POST'])
def get_token():
    data = request.json
    if not data:
        return "Invalid request", 400
    
    user_id = data.get('user_id')
    attributes = data.get('attributes')
    
    if not user_id:
        return "Missing user_id", 400
    if not attributes:
        return "Missing attributes", 400
    
    # Convert attributes to string format for JWT
    if isinstance(attributes, list):
        attributes_str = str(attributes)
    else:
        attributes_str = str(attributes)
    
    token = jwt.encode({
        'user_id': str(user_id),  # Ensure user_id is string
        'attributes': attributes_str,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, SECRET_KEY, algorithm='HS256')
    
    return jsonify({'token': token}), 200