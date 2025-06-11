from process import ABE, MyJWT
from flask import Blueprint, jsonify, request, session
from ast import literal_eval

auth_api = Blueprint('auth_api', __name__)

@auth_api.route('/get_keys', methods=['POST'])
def getKeys():
    if session.get("ID", "") != "" and session.get("username", "") != "":
        post_data = request.json
        attribute = post_data['attribute']
        
        abe = ABE()
        pk = abe.getMasterPublicKey().decode()
        dk = abe.genDecryptKey(literal_eval(attribute)).decode()
        
        server_response = {
            'pk_key': pk,
            'dk_key': dk
        }
        
        return jsonify(server_response), 200
    else:
        return "Please login first!", 404

@auth_api.route('/token', methods=['POST'])
def getToken():
    if session.get("ID", "") != "" and session.get("username", "") != "":
        post_data = request.json
        user_id = post_data['ID']
        attribute = str(post_data['attribute'])
        
        selfjwt = SelfJWT()
        token = selfjwt.encode(attribute, user_id)
        
        return token, 200
    else:
        return "Please login first!", 404