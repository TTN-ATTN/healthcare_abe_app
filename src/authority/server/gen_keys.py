# authority/server/gen_keys.py

from flask import Blueprint, request, jsonify
from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes, bytesToObject
import json
import os
from process import MyAES, ABE
from Crypto.PublicKey import ECC

aes_key = os.urandom(32)

with open("./keystore/aes.key", "wb") as f:
    f.write(aes_key)

pairinggroup = PairingGroup('SS512')
abe = ABE()
pk, mk = abe.setup()

aes = MyAES()
with open("./keystore/pk.enc", "wb") as f:
    f.write(aes.encrypt(objectToBytes(pk, pairinggroup)))

with open("./keystore/mk.enc", "wb") as f:
    f.write(aes.encrypt(objectToBytes(mk, pairinggroup)))
    
private_key = ECC.generate(curve="ed25519")
public_key = private_key.public_key()

private_key_pem = private_key.export_key(format='PEM')
public_key_pem = public_key.export_key(format='PEM')

with open("./keystore/private_key.pem", "wb") as f:
    f.write(aes.encrypt(private_key_pem))
with open("./keystore/public_key.pem", "wb") as f:
    f.write(public_key_pem.encode())
