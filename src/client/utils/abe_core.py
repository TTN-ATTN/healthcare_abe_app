from charm.toolbox.pairinggroup import PairingGroup
from charm.adapters.abenc_adapt_hybrid import HybridABEnc
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes, bytesToObject
from Crypto.Cipher import AES
from Crypto.Util.Padding import *
import os

class SelfAES:
    def __init__(self):
        self.key = os.urandom(32)

    def encrypt(self, data):
        if type(data) != type(b''):
            data = data.encode()
        
        Cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = Cipher.encrypt_and_digest(data)
        
        return Cipher.nonce + ciphertext + tag
    
    def decrypt(self, data, key):
        Cipher = AES.new(key, AES.MODE_GCM, data[:16])
        
        return Cipher.decrypt_and_verify(data[16:-16], data[-16:])

    def getKey(self):
        return self.key

class ABE:
    def __init__(self):
        self.group = PairingGroup('SS512')
        self.cpabe = HybridABEnc(CPabe_BSW07(self.group), self.group)
        self.sign = b'NHANNHAN'

    def encrypt(self, pk, msg, policy):
        self.pk = bytesToObject(pk, self.group)
        data = self.cpabe.encrypt(self.pk, msg, policy)
        
        return data
    
    def decrypt(self, pk, dk, ct):
        self.pk = bytesToObject(pk, self.group)
        self.dk = bytesToObject(dk, self.group)
        data = self.cpabe.decrypt(self.pk, self.dk, ct)
        
        return data