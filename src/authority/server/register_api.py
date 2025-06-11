from flask import Blueprint, request, jsonify, session, render_template, redirect
from process import Hash, MyAES
from urllib.parse import urljoin
import json
import requests
# Rehandle finish
CLOUD_STORAGE_URL = "http://127.0.0.1:8000"
register_api = Blueprint('login_api', __name__)

        
@register_api.route('/register', methods=['POST'])
def register():
    if 'username' not in session['username']:
        return redirect('/login')  
    if 'admin' not in session['username'] and 'administrator' not in session['attribute']:
        return redirect('/login')
    
    username = request.form.get('username')
    password = request.form.get('password')
    attribute = request.form.get('attribute')
    
    if (not username) or (not password) or (not attribute):
        return "Missing username, password or attribute", 400
    
    aes = MyAES()
    attribute = '{{"ATTR": {}}}'.format(json.dumps([attr.strip() for attr in attribute.split(',')]))
    enc_attribute = aes.encrypt(attribute).hex()
    
    data = {
        'username': username,
        'password': Hash.hash_password(password),
        'enc_attribute': enc_attribute
    }
    
    response = requests.post(urljoin(CLOUD_STORAGE_URL, '/api/register_user'), json=data)

    if response.status_code == 200:
        return "User registered successfully", 201
    elif response.status_code == 400 and response.json().get('error') == 'User already exists':
        return "User already exists", 400
        