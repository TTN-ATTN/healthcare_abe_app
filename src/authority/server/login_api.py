from flask import Blueprint, request, jsonify, session, render_template, redirect
from process import Hash, MyAES
from urllib.parse import urljoin
import json
import requests
# Rehandle finish
CLOUD_STORAGE_URL = "http://127.0.0.1:8000"
login_api = Blueprint('login_api', __name__)

@login_api.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if (not username) or (not password):
        return "Missing username or password", 400
    
    response = requests.post(urljoin(CLOUD_STORAGE_URL, '/api/get_user_info'), params={'username': username})
    
    if (response.status_code != 200):
        return "User not found", 404
    
    user_info = response.json()
    
    if user_info["hash_password"] != Hash.hash_password(password):
        return "Invalid password", 401
    
    # Dang nhap thanh cong, thi lay thong tin attributes cua user de tao userkey (description key)
    session['user_id'] = user_info['user_id']
    session['username'] = username
    
    if session['username'] != 'admin':
        attributes = user_info['attributes']
        aes = MyAES()
        attributes = json.loads(aes.decrypt(attributes).decode())
    else:
        attributes = json.loads(user_info['attributes'])

    session['attributes'] = attributes['ATTR']
    
    if (session['attributes'] == 'admin'):
        session['username'] = 'admin'
    else:
        return jsonify({'user_id': session['user_id'], 'attributes': session['attributes']}), 200
        


@login_api.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return "Logged out successfully", 200
