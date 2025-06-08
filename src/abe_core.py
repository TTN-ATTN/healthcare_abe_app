from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import json
import base64
from typing import Dict, List, Any

class SelfAES:
    """Enhanced AES implementation with better key management"""
    
    def __init__(self, key: bytes = None):
        self.key = key if key else os.urandom(32)  # 256-bit key
    
    def encrypt(self, data: bytes) -> bytes:
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Generate a random IV
        iv = os.urandom(16)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Encrypt and get the tag
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Return IV + ciphertext + tag
        return iv + ciphertext + encryptor.tag
    
    def decrypt(self, encrypted_data: bytes, key: bytes = None) -> bytes:
        if key is None:
            key = self.key
            
        # Extract IV, ciphertext, and tag
        iv = encrypted_data[:16]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[16:-16]
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def get_key(self) -> bytes:
        return self.key

class AttributeBasedEncryption:
    """
    Simplified ABE implementation using attribute-based access control
    This is a basic implementation that mimics ABE functionality without complex pairing operations
    """
    
    def __init__(self):
        self.master_key = os.urandom(32)
        self.public_key = self._generate_public_key()
        self.attribute_keys = {}
        
    def _generate_public_key(self) -> Dict[str, Any]:
        """Generate a public key structure"""
        # In a real ABE system, this would involve pairing-based cryptography
        # Here we use a simplified approach with RSA keys
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        return {
            'public_key': public_key,
            'private_key': private_key,
            'master_key': self.master_key
        }
    
    def setup(self) -> bytes:
        """Setup the ABE system and return serialized public key"""
        public_key_bytes = self.public_key['public_key'].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key_bytes
    
    def key_generation(self, attributes: List[str]) -> bytes:
        """Generate a private key for a set of attributes"""
        # Create attribute-specific key derivation
        attribute_string = ','.join(sorted(attributes))
        
        # Derive key from master key and attributes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'abe_salt',  # In production, use random salt
            iterations=100000,
            backend=default_backend()
        )
        
        attribute_key = kdf.derive(self.master_key + attribute_string.encode())
        
        # Store for later use
        key_id = base64.b64encode(os.urandom(16)).decode()
        self.attribute_keys[key_id] = {
            'attributes': attributes,
            'key': attribute_key
        }
        
        # Return serialized key
        key_data = {
            'key_id': key_id,
            'attributes': attributes,
            'key': base64.b64encode(attribute_key).decode()
        }
        
        return json.dumps(key_data).encode()
    
    def encrypt(self, public_key_bytes: bytes, message: bytes, policy: str) -> bytes:
        """
        Encrypt message under a policy
        Policy format: simple boolean expressions like "attr1 AND attr2" or "attr1 OR attr2"
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Generate symmetric key for actual encryption
        aes = SelfAES()
        encrypted_message = aes.encrypt(message)
        
        # Parse policy (simplified - only supports AND/OR)
        required_attributes = self._parse_policy(policy)
        
        # Encrypt the AES key using attribute-based method
        policy_data = {
            'policy': policy,
            'required_attributes': required_attributes,
            'encrypted_key': base64.b64encode(aes.get_key()).decode()
        }
        
        # Encrypt policy data with public key
        public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())
        encrypted_policy = public_key.encrypt(
            json.dumps(policy_data).encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Combine encrypted message and encrypted policy
        ciphertext = {
            'encrypted_message': base64.b64encode(encrypted_message).decode(),
            'encrypted_policy': base64.b64encode(encrypted_policy).decode(),
            'policy': policy
        }
        
        return json.dumps(ciphertext).encode()
    
    def decrypt(self, public_key_bytes: bytes, private_key_bytes: bytes, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext using private key"""
        # Parse ciphertext
        ct_data = json.loads(ciphertext.decode())
        
        # Load private key
        private_key_data = json.loads(private_key_bytes.decode())
        user_attributes = private_key_data['attributes']
        symmetric_key = base64.b64decode(private_key_data['key'].encode())
        
        # Decrypt policy data
        private_key = self.public_key['private_key']  # In real implementation, this would be properly managed
        encrypted_policy = base64.b64decode(ct_data['encrypted_policy'].encode())
        
        try:
            policy_data_bytes = private_key.decrypt(
                encrypted_policy,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            policy_data = json.loads(policy_data_bytes.decode())
        except Exception:
            raise ValueError("Failed to decrypt policy data")
        
        # Check if user attributes satisfy the policy
        if not self._evaluate_policy(policy_data['policy'], user_attributes):
            raise ValueError("User attributes do not satisfy the access policy")
        
        # Decrypt the symmetric key and then the message
        encrypted_key = base64.b64decode(policy_data['encrypted_key'].encode())
        
        # Decrypt the actual message
        encrypted_message = base64.b64decode(ct_data['encrypted_message'].encode())
        
        aes = SelfAES(encrypted_key)
        return aes.decrypt(encrypted_message)
    
    def _parse_policy(self, policy: str) -> List[str]:
        """Parse a simple policy string and extract required attributes"""
        # Simple parser for "attr1 AND attr2" or "attr1 OR attr2" format
        policy = policy.replace('(', '').replace(')', '')
        
        if ' AND ' in policy:
            return [attr.strip() for attr in policy.split(' AND ')]
        elif ' OR ' in policy:
            return [attr.strip() for attr in policy.split(' OR ')]
        else:
            return [policy.strip()]
    
    def _evaluate_policy(self, policy: str, user_attributes: List[str]) -> bool:
        """Evaluate if user attributes satisfy the policy"""
        required_attributes = self._parse_policy(policy)
        
        if ' AND ' in policy:
            # All attributes must be present
            return all(attr in user_attributes for attr in required_attributes)
        elif ' OR ' in policy:
            # At least one attribute must be present
            return any(attr in user_attributes for attr in required_attributes)
        else:
            # Single attribute
            return required_attributes[0] in user_attributes

# Usage example and compatibility wrapper
class ABE:
    """Compatibility wrapper to match your original API"""
    
    def __init__(self):
        self.abe = AttributeBasedEncryption()
        self.sign = b'HEHEHEHE'  # Keeping your signature
        
    def setup(self):
        """Setup and return public and master keys"""
        pk = self.abe.setup()
        mk = self.abe.master_key
        return pk, mk
    
    def key_gen(self, mk: bytes, attributes: List[str]) -> bytes:
        """Generate key for attributes"""
        return self.abe.key_generation(attributes)
    
    def encrypt(self, pk: bytes, msg: bytes, policy: str) -> bytes:
        """Encrypt message under policy"""
        return self.abe.encrypt(pk, msg, policy)
    
    def decrypt(self, pk: bytes, dk: bytes, ct: bytes) -> bytes:
        """Decrypt ciphertext"""
        return self.abe.decrypt(pk, dk, ct)

# test
if __name__ == "__main__":
    abe = ABE()

    pk, mk = abe.setup()
    print("System setup complete")
    
    user_attributes = ["doctor", "hospital_a", "department_cardiology"]
    user_key = abe.key_gen(mk, user_attributes)
    print(f"Generated key for attributes: {user_attributes}")
    
    message = "Patient medical record - confidential data"
    policy = "doctor AND hospital_a" 
    
    ciphertext = abe.encrypt(pk, message.encode(), policy)
    print(f"Encrypted message under policy: {policy}")
    
    try:
        decrypted = abe.decrypt(pk, user_key, ciphertext)
        print(f"Decrypted message: {decrypted.decode()}")
    except ValueError as e:
        print(f"Decryption failed: {e}")
