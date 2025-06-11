# authority/server/login_api.py
from flask import Blueprint, request, jsonify, session
from process import authenticate_user
from bson import ObjectId

login_api = Blueprint('login_api', __name__)

def serialize_user(user):
    """Convert MongoDB user document to JSON-serializable format"""
    if user:
        serialized_user = {}
        for key, value in user.items():
            if isinstance(value, ObjectId):
                serialized_user[key] = str(value)
            else:
                serialized_user[key] = value
        return serialized_user
    return None

@login_api.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if (not username) or (not password):
        return "Missing username or password", 400
    
    user = authenticate_user(username, password)
    
    if user:
        # Serialize the user object to handle ObjectId
        serialized_user = serialize_user(user)
        session['user'] = serialized_user
        return jsonify(serialized_user), 200
    else:
        return "Invalid username or password", 401
    
@login_api.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return "Logged out successfully", 200