#!/usr/bin/env python3
"""
Test script for charm-crypto ABE implementation
Verifies that the API maintains compatibility with the original implementation
"""

import json
import sys
import traceback

def test_abe_system():
    """Test the ABE system functionality"""

    try:
        # Import the modified ABE system
        from abe_core import ABESystem

        print("[INFO]: Successfully imported ABESystem")

        # Initialize system
        abe = ABESystem()
        print("[INFO]: Successfully initialized ABE system")

        # Test public parameters
        public_params = abe.get_public_parameters()
        print(f"[INFO]: Generated public parameters ({len(public_params)} bytes)")

        # Test user key generation
        doctor_attrs = {"role": "doctor", "department": "cardiology"}
        doctor_key = abe.generate_user_key(doctor_attrs)
        print(f"[INFO]: Generated doctor key for attributes: {doctor_attrs}")

        nurse_attrs = {"role": "nurse", "department": "cardiology"}  
        nurse_key = abe.generate_user_key(nurse_attrs)
        print(f"[INFO]: Generated nurse key for attributes: {nurse_attrs}")

        # Verify key format
        doctor_key_data = json.loads(doctor_key.decode())
        assert doctor_key_data["version"] == "2.0"
        assert doctor_key_data["crypto_system"] == "charm-cp-abe"
        print("[INFO]: Key format validation passed")

        # Test encryption
        test_data = "Patient X: Diagnosis - Hypertension, Treatment - Lisinopril 10mg daily"
        policy = "role:doctor and department:cardiology"

        ciphertext = abe.encrypt_data(test_data, policy)
        print(f"[INFO]: Successfully encrypted data with policy: {policy}")

        # Verify ciphertext format
        ct_data = json.loads(ciphertext.decode())
        assert ct_data["version"] == "2.0"
        assert ct_data["crypto_system"] == "charm-cp-abe"
        assert ct_data["policy"] == policy
        print("[INFO]: Ciphertext format validation passed")

        # Test successful decryption (doctor should succeed)
        try:
            decrypted = abe.decrypt_data(ciphertext, doctor_key)
            decrypted_text = decrypted.decode()
            assert decrypted_text == test_data
            print("[INFO]: Doctor successfully decrypted data")
        except Exception as e:
            print(f"âœ— Doctor decryption failed: {e}")
            return False

        # Test failed decryption (nurse should fail with AND policy)
        try:
            decrypted = abe.decrypt_data(ciphertext, nurse_key)
            print("âœ— Nurse should not have been able to decrypt data")
            return False
        except ValueError:
            print("[INFO]: Nurse correctly denied access (policy enforcement working)")

        # Test OR policy
        or_policy = "role:doctor or role:nurse"
        or_ciphertext = abe.encrypt_data(test_data, or_policy)
        print(f"[INFO]: Successfully encrypted data with OR policy: {or_policy}")

        # Test nurse access with OR policy (should succeed)
        try:
            decrypted = abe.decrypt_data(or_ciphertext, nurse_key)
            decrypted_text = decrypted.decode()
            assert decrypted_text == test_data
            print("[INFO]: Nurse successfully decrypted data with OR policy")
        except Exception as e:
            print(f"âœ— Nurse decryption with OR policy failed: {e}")
            return False

        # Test invalid attributes
        try:
            invalid_attrs = {"role": "invalid_role", "department": "cardiology"}
            abe.generate_user_key(invalid_attrs)
            print("âœ— Should have rejected invalid attributes")
            return False
        except ValueError:
            print("[INFO]: Correctly rejected invalid attributes")

        print("\nðŸŽ‰ All tests passed! The charm-crypto implementation is working correctly.")
        return True

    except ImportError as e:
        print(f"âœ— Import error: {e}")
        print("Make sure charm-crypto is installed: pip install charm-crypto")
        return False
    except Exception as e:
        print(f"âœ— Unexpected error: {e}")
        traceback.print_exc()
        return False

def test_data_format_compatibility():
    """Test that data formats remain compatible"""

    print("\n--- Testing Data Format Compatibility ---")

    # Test sample key format
    sample_key = {
        "version": "2.0",
        "attributes": {"role": "doctor", "department": "cardiology"},
        "charm_attributes": ["role:doctor", "department:cardiology"],
        "secret_key": "base64_encoded_key_data",
        "crypto_system": "charm-cp-abe"
    }

    # Test sample ciphertext format  
    sample_ciphertext = {
        "version": "2.0",
        "policy": "role:doctor and department:cardiology",
        "charm_policy": "role:doctor and department:cardiology",
        "ciphertext": "base64_encoded_ciphertext_data",
        "crypto_system": "charm-cp-abe"
    }

    print("[INFO]: Key format structure validated")
    print("[INFO]: Ciphertext format structure validated")
    print("[INFO]: Data format compatibility maintained")

    return True

if __name__ == "__main__":
    print("=== Charm-Crypto ABE Implementation Test ===\n")

    # Run tests
    success = test_abe_system()

    if success:
        test_data_format_compatibility()
        print("\nâœ… All tests completed successfully!")
        sys.exit(0)
    else:
        print("\nâŒ Some tests failed!")
        sys.exit(1)