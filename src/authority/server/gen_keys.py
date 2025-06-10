# Buoc 1: cu authority server la setup key 

from flask import Blueprint, request, jsonify
from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes, bytesToObject
import json

gen_keys_api = Blueprint('gen_keys_api', __name__)

# Set up keys: tao master public key va master key cho CP-ABE
group = PairingGroup('SS512')
cpabe = CPabe_BSW07(group)
(master_public_key, master_secret_key) = cpabe.setup()

# Nhan vao public key va truong thuoc tinh 
@gen_keys_api.route('/get_keys', methods=['POST'])
def get_keys():
    data = request.json
    if not data or 'attributes' not in data:
        return "Invalid request", 400
    try:
        attributes = data['attributes']
        # Tao decryption key dua tren cac thuoc tinh cua nguoi dung va gui d    en nguoi dung
        dk_key = cpabe.keygen(master_public_key, master_secret_key, attributes)


        # chuyen doi cac keys thanh bytes de gui qua HTTP
        pk_bytes = objectToBytes(master_public_key, group)
        dk_bytess = objectToBytes(dk_key, group)
        
        return jsonify({
            'pk_bytes': pk_bytes.decode(),
            'dk_bytes': dk_bytess.decode()
        }), 200
    except Exception as e:
        return str(e), 500
        