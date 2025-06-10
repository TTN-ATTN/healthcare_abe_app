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
    if not data or '_id' not in data:
        return "Invalid request", 400
    
    token = jwt.encode({
        'user_id': data['_id'],
        'attributes': str(data.get('attribute')), # Nen có một giải pháp an toàn để lưu trữ attributes đó là enc nó lại
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, SECRET_KEY, algorithm='HS256')
    
    return token, 200
