# authority/server/process.py
from pymongo import MongoClient
import hashlib
import os
import jwt
from Crypto.Cipher import AES
from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes, bytesToObject
import time
class Hash:
    def hash_password(password):
        """Hash a password using SHA-256"""
        if type(password) != type(b''):
            password = password.encode()
        return hashlib.sha256(password).hexdigest()
    
class MyAES:
    def __init__(self):
        self.key = open("./keystore/aes.key", "rb").read()
    
    def encrypt(self, data):
        if type(data) != type(b''):
            data = data.encode()
        
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce + tag + ciphertext
    
    def decrypt(self, data):
        ciphert = AES.new(self.key, AES.MODE_GCM, nonce=data[:16])
        tag = data[16:32]
        ciphertext = data[32:]
        
        return ciphert.decrypt_and_verify(ciphertext, tag)
    
class ABE:
    def __init__ (self):
        self.group = PairingGroup('SS512')
        self.cpabe = CPabe_BSW07(self.group)
    
    def setup(self):
        return self.cpabe.setup()
    # Lay masterpublic key
    def getMasterPublickey(self):
        aes = MyAES()
        with open("./opt/pk", "rb") as f:
            pk = aes.decrypt(f.read())
        return pk
    # Generate DecryptionKey for user
    def genDecryptionKey(self, attribute: list):
        aes = MyAES()
        self.pk = bytesToObject(self.getMasterPublickey(), self.group)
        with open("./opt/mk", "rb") as f:
            tmp = aes.decrypt(f.read())
            self.mk = bytesToObject(tmp, self.group)
        
        dk = self.cpabe.keygen(self.pk, self.mk, attribute)
        return objectToBytes(dk, self.group)
        
class MyJWT:
    def __init__(self):
        with open("./keystore/jwt.key", "rb") as f:
            encrypted_key = f.read()
            aes = MyAES()
            self.secret_key = aes.decrypt(encrypted_key).decode()
    def encode(self, attribute, user_id):
        exptime = str(round(time.time()) + 3600)
        payload = {
            'user_id': user_id,
            'attribute': attribute,
            'exp': exptime
        }
        enc_token = jwt.encode(payload, self.secret_key, algorithm='EdDSA')
        return enc_token
    
    
            