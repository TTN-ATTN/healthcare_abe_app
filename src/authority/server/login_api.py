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
    
    response = request.get(urljoin(CLOUD_STORAGE_URL, '/api/get_user_info'), params={'username': username})
    
    if (response.status_code != 200):
        return "User not found", 404
    
    user_info = response.json()
    
    if user_info["hash_passwd"] != Hash.hash_password(password):
        return "Invalid password", 401
    
    # Dang nhap thanh cong, thi lay thong tin attribute cua user de tao userkey (description key)
    session['ID'] = user_info['ID']
    session['username'] = username
    
    if session['user'] != 'admin':
        attribute = user_info['attribute']
        aes = MyAES()
        attribute = json.loads(aes.decrypt(attribute).decode())
    else:
        attribute = json.loads(user_info['attribute'])

    session['attribute'] = attribute['ATTR']
    
    if (session['attribute'] == 'administrator'):
        session['user'] = 'admin'
    else:
        return jsonify({'ID': session['ID'], 'attribute': session['attribute']}), 200
        


@login_api.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return "Logged out successfully", 200
