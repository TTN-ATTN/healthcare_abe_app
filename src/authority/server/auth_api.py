from flask import Blueprint, request, jsonify, session
import jwt
import datetime
import os

auth_api = Blueprint('auth_api', __name__)

SECRET_KEY = os.urandom(24).hex() # Nen luu tru secret key nay trong mot file an toan

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

