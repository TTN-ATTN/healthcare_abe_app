import json
import base64
import re
from typing import Dict, List, Tuple, Union
from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth

class SecureAES:
    """Simplified AES-like interface for charm-crypto compatibility"""

    def __init__(self, key: bytes = None):
        # For compatibility - charm handles encryption differently
        self.key = key

    def encrypt(self, plaintext: Union[str, bytes]) -> bytes:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        return plaintext  # Placeholder - charm will handle actual encryption

    def decrypt(self, ciphertext: bytes) -> bytes:
        return ciphertext  # Placeholder - charm will handle actual decryption

    @staticmethod
    def generate_key() -> bytes:
        """Generate a placeholder key"""
        import os
        return os.urandom(32)

class ABESystem:
    """Charm-crypto based CP-ABE implementation"""

    def __init__(self):
        # Initialize pairing group for CP-ABE
        self.group = PairingGroup('SS512')
        self.cpabe = CPabe_BSW07(self.group)

        # Generate master keys
        (self.master_public_key, self.master_secret_key) = self.cpabe.setup()

        # Define attribute universe (same as original)
        self.attribute_universe = {
            "role": ["doctor", "nurse", "researcher", "admin", "patient"],
            "department": ["cardiology", "pediatrics", "oncology", "emergency"],
            "clearance": ["level1", "level2", "level3", "level4"]
        }

        # Initialize secret sharing utility
        self.util = SecretUtil(self.group, verbose=False)

    def get_public_parameters(self) -> bytes:
        """Return serialized public parameters"""
        return objectToBytes(self.master_public_key, self.group)

    def generate_user_key(self, attributes: Dict[str, str]) -> bytes:
        """Generate user secret key for given attributes using charm-crypto"""

        # Validate attributes against universe
        for attr_type, attr_value in attributes.items():
            if attr_type not in self.attribute_universe:
                raise ValueError(f"Invalid attribute type: {attr_type}")
            if attr_value not in self.attribute_universe[attr_type]:
                raise ValueError(f"Invalid {attr_type} value: {attr_value}")

        # Convert attributes to charm format (flat list of strings)
        charm_attributes = []
        for attr_type, attr_value in attributes.items():
            charm_attributes.append(f"{attr_type}:{attr_value}")

        # Generate secret key using charm CP-ABE
        secret_key = self.cpabe.keygen(self.master_public_key, self.master_secret_key, charm_attributes)

        # Package key with metadata for compatibility
        key_package = {
            "version": "2.0",  # Updated version for charm-crypto
            "attributes": attributes,
            "charm_attributes": charm_attributes,
            "secret_key": base64.b64encode(objectToBytes(secret_key, self.group)).decode(),
            "crypto_system": "charm-cp-abe"
        }

        return json.dumps(key_package).encode()

    def encrypt_data(self, plaintext: Union[str, bytes], policy: str) -> bytes:
        """Encrypt data using CP-ABE with charm-crypto"""

        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        # Convert policy to charm format
        charm_policy = self._convert_policy_to_charm_format(policy)

        # Encrypt using charm CP-ABE
        ciphertext = self.cpabe.encrypt(self.master_public_key, plaintext, charm_policy)

        # Package ciphertext with metadata
        ciphertext_package = {
            "version": "2.0",  # Updated version for charm-crypto
            "policy": policy,
            "charm_policy": charm_policy,
            "ciphertext": base64.b64encode(objectToBytes(ciphertext, self.group)).decode(),
            "crypto_system": "charm-cp-abe"
        }

        return json.dumps(ciphertext_package).encode()

    def decrypt_data(self, ciphertext: bytes, user_key: bytes) -> bytes:
        """Decrypt data using CP-ABE with charm-crypto"""

        try:
            # Parse ciphertext package
            ct_pkg = json.loads(ciphertext.decode())
            if ct_pkg.get("version") != "2.0":
                raise ValueError("Unsupported ciphertext version")

            # Parse user key
            user_key_data = json.loads(user_key.decode())
            if user_key_data.get("version") != "2.0":
                raise ValueError("Unsupported user key version")

            # Deserialize charm objects
            charm_ciphertext = bytesToObject(base64.b64decode(ct_pkg["ciphertext"]), self.group)
            charm_secret_key = bytesToObject(base64.b64decode(user_key_data["secret_key"]), self.group)

            # Decrypt using charm CP-ABE
            decrypted_data = self.cpabe.decrypt(self.master_public_key, charm_secret_key, charm_ciphertext)

            # Return decrypted bytes
            if isinstance(decrypted_data, bytes):
                return decrypted_data
            else:
                return str(decrypted_data).encode()

        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    def _convert_policy_to_charm_format(self, policy: str) -> str:
        """Convert policy string to charm-crypto format"""

        # Normalize policy string
        policy = re.sub(r"\s+", " ", policy.strip())

        # Convert to charm format (already compatible with most cases)
        # Charm uses format like: "role:doctor and department:cardiology"
        # which matches our input format

        # Replace logical operators to ensure compatibility
        charm_policy = policy.replace(" AND ", " and ").replace(" OR ", " or")

        return charm_policy

    def _parse_policy(self, policy: str) -> List[Tuple[str, str]]:
        """Parse policy string into attribute tuples (for compatibility)"""

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

# Example usage
if __name__ == "__main__":
    print("=== Healthcare ABE System Demo (Charm-Crypto) ===")

    abe = ABESystem()
    public_params = abe.get_public_parameters()
    print("System initialized with charm-crypto CP-ABE")

    # Generate user keys
    doctor_attrs = {"role": "doctor", "department": "cardiology"}
    doctor_key = abe.generate_user_key(doctor_attrs)
    print(f"Generated doctor key for attributes: {doctor_attrs}")

    nurse_attrs = {"role": "nurse", "department": "cardiology"}
    nurse_key = abe.generate_user_key(nurse_attrs)
    print(f"Generated nurse key for attributes: {nurse_attrs}")

    # Test encryption and decryption
    medical_record = "Patient X: Diagnosis - Hypertension, Treatment - Lisinopril 10mg daily"
    policy = "role:doctor and department:cardiology"

    print(f"\nEncrypting record with policy: {policy}")
    ciphertext = abe.encrypt_data(medical_record, policy)

    print("\nAttempting decryption...")

    # Test doctor access (should succeed)
    try:
        decrypted = abe.decrypt_data(ciphertext, doctor_key)
        print("Doctor successfully decrypted record:")
        print(decrypted.decode())
    except ValueError as e:
        print(f"Doctor decryption failed: {e}")

    # Test nurse access (should fail due to policy)
    try:
        decrypted = abe.decrypt_data(ciphertext, nurse_key)
        print("Nurse successfully decrypted record:")
        print(decrypted.decode())
    except ValueError as e:
        print(f"Nurse decryption failed: {e}")

    # Test with OR policy
    print("\n--- Testing OR Policy ---")
    or_policy = "role:doctor or role:nurse"
    print(f"Encrypting with OR policy: {or_policy}")
    or_ciphertext = abe.encrypt_data(medical_record, or_policy)

    try:
        decrypted = abe.decrypt_data(or_ciphertext, nurse_key)
        print("Nurse successfully decrypted record with OR policy:")
        print(decrypted.decode())
    except ValueError as e:
        print(f"Nurse decryption with OR policy failed: {e}")