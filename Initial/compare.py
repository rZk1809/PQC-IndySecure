

import time
import base64
from cryptography.hazmat.primitives import hashes, serialization # Added serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
import oqs  # Open Quantum Safe

# --- Configuration ---
PQC_ALG_NAME = "ML-DSA-44"
ECC_CURVE = ec.SECP256R1() # NIST P-256 curve
ECC_HASH = hashes.SHA256()

def format_duration(duration_sec):
    """Formats duration in seconds to ms or s."""
    if duration_sec < 1.0:
        return f"{duration_sec * 1000:.3f} ms"
    else:
        return f"{duration_sec:.4f} s"

print("--- Key Generation ---")
start_time = time.monotonic()

ecdsa_gen_start = time.monotonic()
ecdsa_private_key = ec.generate_private_key(ECC_CURVE)
ecdsa_public_key = ecdsa_private_key.public_key()
ecdsa_gen_duration = time.monotonic() - ecdsa_gen_start
print(f"Generated {ECC_CURVE.name} keys ({format_duration(ecdsa_gen_duration)}).")


try:
    pqc_gen_start = time.monotonic()
    dilithium_sig_instance = oqs.Signature(PQC_ALG_NAME)
    dilithium_public_key = dilithium_sig_instance.generate_keypair()
    pqc_gen_duration = time.monotonic() - pqc_gen_start
    print(f"Generated {PQC_ALG_NAME} keys ({format_duration(pqc_gen_duration)}).")
except oqs.MechanismNotSupportedError:
     print(f"ERROR: Algorithm '{PQC_ALG_NAME}' not supported by OQS build.")
     exit()
except Exception as e:
     print(f"ERROR: Failed OQS init for {PQC_ALG_NAME}: {e}")
     exit()

total_keygen_duration = time.monotonic() - start_time
print(f"Total key generation time: {format_duration(total_keygen_duration)}")

print("\n--- Public Keys ---")
try:
    ecdsa_pem = ecdsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(f"ECDSA ({ECC_CURVE.name}) Public Key (PEM):\n{ecdsa_pem.decode('utf-8')}")
    print(f"(PEM Length: {len(ecdsa_pem)} bytes)")
except Exception as e:
    print(f"Could not serialize ECDSA public key: {e}")

# ML-DSA Public Key (Base64 Encoded)
dilithium_public_key_b64 = base64.b64encode(dilithium_public_key).decode('ascii')
print(f"\nML-DSA ({PQC_ALG_NAME}) Public Key (Base64):\n{dilithium_public_key_b64}")
print(f"(Raw Length: {len(dilithium_public_key)} bytes)")


# 2. Sign a message with both algorithms
message = b"This is the data to be signed using a hybrid approach."
print(f"\n--- Signing ---")
print(f"Message: '{message.decode()}'")

start_time = time.monotonic()

# Sign with ECDSA
ecdsa_sign_start = time.monotonic()
ecdsa_signature = ecdsa_private_key.sign(
    message,
    ec.ECDSA(ECC_HASH)
)
ecdsa_sign_duration = time.monotonic() - ecdsa_sign_start
print(f"ECDSA signing took: {format_duration(ecdsa_sign_duration)}")

# Sign with ML-DSA
pqc_sign_start = time.monotonic()
dilithium_signature = dilithium_sig_instance.sign(message)
pqc_sign_duration = time.monotonic() - pqc_sign_start
print(f"ML-DSA signing took: {format_duration(pqc_sign_duration)}")

total_sign_duration = time.monotonic() - start_time
print(f"Total signing time: {format_duration(total_sign_duration)}")


# The hybrid signature
hybrid_signature_tuple = (ecdsa_signature, dilithium_signature)

print("\n--- Signature Details ---")
print(f"ECDSA ({ECC_CURVE.name}/{ECC_HASH.name}) signature length: {len(ecdsa_signature)} bytes")
print(f"ML-DSA ({PQC_ALG_NAME}) signature length: {len(dilithium_signature)} bytes")


# 3. Verify each signature individually using the public keys
print("\n--- Verification ---")
start_time = time.monotonic()
ecdsa_valid = False
dilithium_valid = False

# Verify ECDSA
ecdsa_verify_start = time.monotonic()
try:
    ecdsa_public_key.verify(
        ecdsa_signature,
        message,
        ec.ECDSA(ECC_HASH)
    )
    ecdsa_valid = True
except InvalidSignature:
    print("ECDSA verification: FAILED (Invalid Signature)")
except Exception as e:
    print(f"ECDSA verification: FAILED (Error: {e})")
ecdsa_verify_duration = time.monotonic() - ecdsa_verify_start
if ecdsa_valid: print(f"ECDSA verification: SUCCESS ({format_duration(ecdsa_verify_duration)})")


# Verify ML-DSA
pqc_verify_start = time.monotonic()
try:
    verifier = oqs.Signature(PQC_ALG_NAME)
    dilithium_valid = verifier.verify(message, dilithium_signature, dilithium_public_key)
except Exception as e:
    dilithium_valid = False # Ensure valid flag is false on error
    print(f"ML-DSA verification: FAILED (Error: {e})")
pqc_verify_duration = time.monotonic() - pqc_verify_start

if dilithium_valid:
    print(f"ML-DSA verification: SUCCESS ({format_duration(pqc_verify_duration)})")
else:
    # Print failure only if no exception occurred during verify attempt
    if 'e' not in locals(): # Check if exception 'e' exists in local scope
        print(f"ML-DSA verification: FAILED (Signature invalid) ({format_duration(pqc_verify_duration)})")


total_verify_duration = time.monotonic() - start_time
print(f"Total verification time: {format_duration(total_verify_duration)}")


# 4. Hybrid verification policy: Accept only if BOTH signatures are valid
print("\n--- Hybrid Verification Result ---")
if ecdsa_valid and dilithium_valid:
    print("Hybrid signature is VALID (both ECDSA and ML-DSA signatures verified successfully).")
else:
    print("Hybrid signature verification FAILED (one or both signatures failed).")
    if not ecdsa_valid: print(" -> ECDSA part failed.")
    if not dilithium_valid: print(" -> ML-DSA part failed.")
