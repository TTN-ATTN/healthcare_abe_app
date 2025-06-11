# authority/server/auth_api.py
from flask import Blueprint, request, jsonify, session
import jwt
import datetime
import os
from process import MyAES, ABE, Hash, MyJWT
from ast import literal_eval

auth_api = Blueprint('auth_api', __name__)

@auth_api.route('/get_keys', methods=['POST'])
def get_keys():
    if 'user_id' not in session:
        return "Unauthorized", 401
    
    if "username" not in session:
        return "Unauthorized", 401
    
    post_data = request.json
    attributes = post_data['attributes']
    
    abe = ABE()
    pk = abe.getMasterPublickey()
    dk = abe.genDecryptionKey(literal_eval(attributes)).decode()
    
    reponse = {
        'pk_key': pk,
        'dk_key': dk,
    }
    return jsonify(reponse), 200


@auth_api.route('/token', methods=['POST'])
def get_token():
    # if 'user_id' not in session:
    #     return "Unauthorized", 401
    # if "username" not in session:
    #     return "Unauthorized", 401
    data = request.json
    if not data:
        return "Invalid request", 400
    
    user_id = data['user_id']
    attributes = str(data['attributes'])
    
    if not user_id:
        return "Missing user_id", 400
    if not attributes:
        return "Missing attributes", 400
   
    myjwt = MyJWT()
    token = myjwt.encode(attributes, user_id)
    
    return token, 200