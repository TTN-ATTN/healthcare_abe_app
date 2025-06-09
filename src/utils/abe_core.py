import os
import json
import base64
import re
from typing import Dict, List, Tuple, Union

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

class SecureAES:
    """Enhanced AES-GCM implementation with proper key management"""
    
    def __init__(self, key: bytes = None):
        """
        Initialize with optional key (generates random 256-bit key if not provided)
        
        Args:
            key: Optional 32-byte AES key. Must be kept secret.
        """
        if key:
            if len(key) != 32:
                raise ValueError("AES key must be 32 bytes (256 bits)")
            self.key = key
        else:
            self.key = os.urandom(32)
    
    def encrypt(self, plaintext: Union[str, bytes]) -> bytes:
        """
        Encrypt data using AES-GCM (authenticated encryption)
        
        Args:
            plaintext: Data to encrypt (str or bytes)
            
        Returns:
            bytes: Encrypted data in format: IV (16B) + ciphertext + tag (16B)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        
        # Generate random initialization vector
        iv = os.urandom(16)
        
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext + encryptor.tag
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt AES-GCM encrypted data
        
        Args:
            ciphertext: Encrypted data in format: IV (16B) + ciphertext + tag (16B)
            
        Returns:
            bytes: Decrypted plaintext
            
        Raises:
            InvalidTag: If authentication fails (tampered data)
        """
        if len(ciphertext) < 32:  # IV (16) + min 1 byte + tag (16)
            raise ValueError("Invalid ciphertext length")
            
        iv = ciphertext[:16]
        tag = ciphertext[-16:]
        encrypted_data = ciphertext[16:-16]
        
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        return decryptor.update(encrypted_data) + decryptor.finalize()
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate a new random 256-bit AES key"""
        return os.urandom(32)

class AttributeBasedEncryptionSystem:
    """
    Practical ABE implementation with healthcare-specific enhancements
    
    Note: This is a simplified version that simulates ABE concepts using
    hybrid encryption (AES for data + RSA for policy enforcement).
    A real ABE system would use pairing-based cryptography.
    """
    
    def __init__(self):
        """Initialize the ABE system with master parameters"""
        self.master_key = os.urandom(32)
        self._setup_crypto_material()
        self.attribute_universe = {
            "role": ["doctor", "nurse", "researcher", "admin"],
            "department": ["cardiology", "pediatrics", "oncology"],
            "clearance": ["level1", "level2", "level3"]
        }
    
    def _setup_crypto_material(self):
        """Generate cryptographic keys for the system"""
        # In real ABE, this would involve pairing parameters
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
    def get_public_parameters(self) -> bytes:
        """
        Get serialized public parameters for encryption
        
        Returns:
            bytes: Serialized public key in PEM format
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def generate_user_key(self, attributes: Dict[str, str]) -> bytes:
        """
        Generate a user secret key based on attributes
        
        Args:
            attributes: Dictionary of attribute types and values
                        e.g., {"role": "doctor", "department": "cardiology"}
                        
        Returns:
            bytes: Serialized key data containing derived key material
            
        Raises:
            ValueError: If invalid attributes are provided
        """
        # Validate attributes against universe
        for attr_type, attr_value in attributes.items():
            if attr_type not in self.attribute_universe:
                raise ValueError(f"Invalid attribute type: {attr_type}")
            if attr_value not in self.attribute_universe[attr_type]:
                raise ValueError(f"Invalid {attr_type} value: {attr_value}")
        
        # Create unique salt based on attributes
        attr_string = ",".join(f"{k}={v}" for k,v in sorted(attributes.items()))
        salt = hashes.Hash(hashes.SHA256(), backend=default_backend())
        salt.update(attr_string.encode())
        salt = salt.finalize()
        
        # Derive attribute-specific key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        user_key = kdf.derive(self.master_key + attr_string.encode())
        
        # Package key material securely
        key_package = {
            "version": "1.0",
            "attributes": attributes,
            "key": base64.b64encode(user_key).decode(),
            "salt": base64.b64encode(salt).decode()
        }
        
        # Sign the key package (in production, use proper PKI)
        signature = self._sign_data(json.dumps(key_package).encode())
        key_package["signature"] = base64.b64encode(signature).decode()
        
        return json.dumps(key_package).encode()
    
    def encrypt_data(self, plaintext: Union[str, bytes], policy: str) -> bytes:
        """
        Encrypt data under an attribute-based policy
        
        Args:
            plaintext: Data to encrypt (str or bytes)
            policy: Access policy in simple format
                    e.g., "role:doctor AND department:cardiology"
                    
        Returns:
            bytes: Serialized ciphertext package
            
        Raises:
            ValueError: For invalid policy format
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
            
        # 1. Encrypt data with random AES key
        aes_key_data = SecureAES.generate_key()
        aes_data = SecureAES(aes_key_data)
        encrypted_data = aes_data.encrypt(plaintext)
        
        # 2. Parse policy (simplified parser)
        policy_attributes = self._parse_policy(policy)
        
        # 3. Package policy and encrypted key
        policy_package = {
            "policy": policy,
            "policy_attributes": policy_attributes,
            "aes_key": base64.b64encode(aes_key_data).decode(),
            "encryption_time": int(os.times()[4])  # Simple timestamp
        }
        
        # Convert policy_package to bytes
        policy_package_bytes = json.dumps(policy_package).encode()
        
        # 4. Encrypt the policy package using AES (hybrid encryption)
        aes_key_policy = SecureAES.generate_key()
        aes_policy = SecureAES(aes_key_policy)
        encrypted_policy_package = aes_policy.encrypt(policy_package_bytes)
        
        # 5. Encrypt the AES key for the policy package with ABE public key (RSA)
        encrypted_aes_key_policy = self.public_key.encrypt(
            aes_key_policy,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 6. Create final ciphertext package
        ciphertext_package = {
            "version": "1.0",
            "encrypted_data": base64.b64encode(encrypted_data).decode(),
            "encrypted_policy_package": base64.b64encode(encrypted_policy_package).decode(),
            "encrypted_aes_key_policy": base64.b64encode(encrypted_aes_key_policy).decode(),
            "policy": policy
        }
        
        return json.dumps(ciphertext_package).encode()
    
    def decrypt_data(self, ciphertext: bytes, user_key: bytes) -> bytes:
        """
        Decrypt data if user attributes satisfy the policy
        
        Args:
            ciphertext: Encrypted data package from encrypt_data()
            user_key: User's secret key from generate_user_key()
            
        Returns:
            bytes: Decrypted plaintext
            
        Raises:
            ValueError: If decryption fails (policy not satisfied, tampered data, etc.)
        """
        try:
            # 1. Parse ciphertext package
            ct_pkg = json.loads(ciphertext.decode())
            if ct_pkg.get("version") != "1.0":
                raise ValueError("Unsupported ciphertext version")
                
            # 2. Parse and verify user key
            user_key_data = json.loads(user_key.decode())
            self._verify_key_signature(user_key_data)
            
            # 3. Decrypt the AES key for the policy package using RSA private key
            encrypted_aes_key_policy = base64.b64decode(ct_pkg["encrypted_aes_key_policy"])
            aes_key_policy = self.private_key.decrypt(
                encrypted_aes_key_policy,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # 4. Decrypt the policy package using the recovered AES key
            encrypted_policy_package = base64.b64decode(ct_pkg["encrypted_policy_package"])
            aes_policy = SecureAES(aes_key_policy)
            policy_package = json.loads(aes_policy.decrypt(encrypted_policy_package).decode())
            
            # 5. Check if user attributes satisfy policy
            if not self._check_policy_compliance(
                policy_package["policy"],
                user_key_data["attributes"]
            ):
                raise ValueError("User attributes don't satisfy policy")
            
            # 6. Get AES key for data and decrypt data
            aes_key_data = base64.b64decode(policy_package["aes_key"])
            encrypted_data = base64.b64decode(ct_pkg["encrypted_data"])
            
            aes_data = SecureAES(aes_key_data)
            return aes_data.decrypt(encrypted_data)
            
        except (json.JSONDecodeError, KeyError, InvalidTag) as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def _parse_policy(self, policy: str) -> List[Tuple[str, str]]:
        """
        Parse simple policy string into attribute requirements
        
        Supports:
        - Single attribute: "role:doctor"
        - AND conditions: "role:doctor AND department:cardiology"
        - OR conditions: "role:doctor OR role:researcher"
        
        Returns:
            List of (attribute_type, attribute_value) tuples
        """
        # Normalize policy string
        policy = re.sub(r"\s+", " ", policy.strip()).lower()
        
        # Handle AND/OR conditions
        if " and " in policy:
            clauses = policy.split(" and ")
            return [self._parse_attribute(clause) for clause in clauses]
        elif " or " in policy:
            clauses = policy.split(" or ")
            return [self._parse_attribute(clause) for clause in clauses]
        else:
            return [self._parse_attribute(policy)]
    
    def _parse_attribute(self, attribute_str: str) -> Tuple[str, str]:
        """Parse single attribute string like 'role:doctor'"""
        parts = attribute_str.split(":")
        if len(parts) != 2:
            raise ValueError(f"Invalid attribute format: {attribute_str}")
        return (parts[0].strip(), parts[1].strip())
    
    def _check_policy_compliance(self, policy: str, user_attrs: Dict[str, str]) -> bool:
        """
        Check if user attributes satisfy the policy
        
        Args:
            policy: Policy string
            user_attrs: Dictionary of user attributes
            
        Returns:
            bool: True if policy is satisfied
        """
        policy_attrs = self._parse_policy(policy)
        
        if " and " in policy.lower():
            # All attributes must match
            return all(
                user_attrs.get(attr_type) == attr_value
                for attr_type, attr_value in policy_attrs
            )
        elif " or " in policy.lower():
            # Any attribute must match
            return any(
                user_attrs.get(attr_type) == attr_value
                for attr_type, attr_value in policy_attrs
            )
        else:
            # Single attribute
            attr_type, attr_value = policy_attrs[0]
            return user_attrs.get(attr_type) == attr_value
    
    def _sign_data(self, data: bytes) -> bytes:
        """Sign data using system private key (simplified)"""
        return self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    def _verify_key_signature(self, key_data: Dict) -> None:
        """Verify key package signature"""
        signature = base64.b64decode(key_data["signature"])
        data = json.dumps({
            k: v for k, v in key_data.items()
            if k != "signature"
        }).encode()
        
        try:
            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as e:
            raise ValueError(f"Invalid key signature: {str(e)}")

# Example usage
if __name__ == "__main__":
    print("=== Healthcare ABE System Demo ===")
    
    abe = AttributeBasedEncryptionSystem()
    public_params = abe.get_public_parameters()
    print("System initialized with public parameters")
    
    doctor_attrs = {"role": "doctor", "department": "cardiology"}
    doctor_key = abe.generate_user_key(doctor_attrs)
    print(f"Generated doctor key for attributes: {doctor_attrs}")
    print(f"\n\nDoctor key: {doctor_key.decode()}\n\n")
    
    nurse_attrs = {"role": "nurse", "department": "cardiology"}
    nurse_key = abe.generate_user_key(nurse_attrs)
    print(f"Generated nurse key for attributes: {nurse_attrs}")
    print(f"\n\nNurse key: {nurse_key.decode()}\n\n")
  
    medical_record = "Patient X: Diagnosis - Hypertension, Treatment - Lisinopril 10mg daily"
    policy = "role:doctor AND department:cardiology"
    
    ciphertext = abe.encrypt_data(medical_record, policy)
    print(f"\nEncrypted record with policy: {policy}")

    print("\nAttempting decryption...")

    # Expect success
    try:
        decrypted = abe.decrypt_data(ciphertext, doctor_key)
        print("Doctor successfully decrypted record:")
        print(decrypted.decode())
    except ValueError as e:
        print(f"Doctor decryption failed: {e}")
    
    # Expect failure
    try:
        decrypted = abe.decrypt_data(ciphertext, nurse_key)
        print("Nurse successfully decrypted record:")
        print(decrypted.decode())
    except ValueError as e:
        print(f"Nurse decryption failed: {e}")


