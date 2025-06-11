# authority/server/login_api.py
from flask import Blueprint, request, jsonify, session
from process import authenticate_user

login_api = Blueprint('login_api', __name__)

@login_api.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if (not username) or (not password):
        return "Missing username or password", 400
    
    user = authenticate_user(username, password)
    
    if user:
        user['user_id'] = str(user['user_id'])  # Convert ObjectId to string
        session['user'] = user
        return jsonify(user), 200
    else:
        return "Invalid username or password", 401
    
@login_api.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return "Logged out successfully", 200
