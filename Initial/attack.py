import oqs
import base64
import logging
import sys

# --------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------
DEVICE_SIG_ALG = "ML-DSA-44"   # The algorithm used by the legitimate device
ATTACK_SIG_ALG = "ML-DSA-87"   # The algorithm used by the attacker for forgery

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger("Attacker")

# --------------------------------------------------------------------
# Simulated Device Key Generation
# --------------------------------------------------------------------
try:
    # Create a signing instance using the device's secure algorithm.
    device_signer = oqs.Signature(DEVICE_SIG_ALG)
    # Generate the device's key pair; only the public key is shared.
    arduino_public_key = device_signer.generate_keypair()
    # The private key is kept internal; we export it just for generating valid signatures.
    _ = device_signer.export_secret_key()
    log.info(f"Simulated device key pair generated using {DEVICE_SIG_ALG}.")
except Exception as e:
    log.critical(f"Failed to generate device keys: {e}")
    sys.exit(1)

def get_public_keys():
    """
    Returns a dictionary of simulated device public keys.
    In a real implementation, public keys might be loaded from a trusted source.
    """
    return {"Arduino": arduino_public_key}

# --------------------------------------------------------------------
# Attack Functions
# --------------------------------------------------------------------
def forge_signature(target_message: bytes, public_key: bytes) -> bytes:
    """
    Attempts to forge a signature for the given message using a different algorithm.
    Without the legitimate private key, this attempt should fail.
    """
    try:
        # The attacker uses a different algorithm (which is not compatible with the legitimate one).
        attacker = oqs.Signature(ATTACK_SIG_ALG)
        forged_signature = attacker.sign(target_message)
        log.info("Forgery attempt completed (for demonstration only).")
        return forged_signature
    except Exception as e:
        log.error(f"Forgery attempt failed: {e}")
        return b''

def replay_attack(original_message: bytes, original_signature: bytes, public_key: bytes) -> bool:
    """
    Demonstrates a replay attack by reusing a valid signature.
    This test shows that without protocol-level protections (nonces, timestamps), replayed signatures are valid.
    """
    try:
        # Use the legitimate algorithm for verification.
        verifier = oqs.Signature(DEVICE_SIG_ALG)
        is_valid = verifier.verify(original_message, original_signature, public_key)
        if is_valid:
            log.info("Replay attack successful (signature accepted).")
        else:
            log.error("Replay attack failed (signature rejected).")
        return is_valid
    except Exception as e:
        log.error(f"Replay attack failed: {e}")
        return False

def run_attack():
    log.info("Starting security test against the simulated device using public key of 'Arduino'...")
    
    # Load the public keys; here we pick the "Arduino" device.
    public_keys = get_public_keys()
    if not public_keys or "Arduino" not in public_keys:
        log.error("Failed to retrieve the public key for 'Arduino'.")
        return

    target_public_key = public_keys["Arduino"]
    log.info(f"Loaded 'Arduino' public key: {target_public_key.hex()}")

    # ----------- Test 1: Forgery Attack -----------
    test_message = b"Compromised data packet"
    forged_sig = forge_signature(test_message, target_public_key)

    # Verify the forged signature using the device's algorithm.
    verifier = oqs.Signature(DEVICE_SIG_ALG)
    is_forged_valid = verifier.verify(test_message, forged_sig, target_public_key)
    if is_forged_valid:
        log.warning("CRITICAL: Forgery attack succeeded! Cryptography is compromised.")
    else:
        log.info("Forgery attack failed as expected (cryptography secure against forgery).")

    # ----------- Test 2: Replay Attack -----------
    legitimate_message = b"Legitimate data packet"
    # Generate a valid signature using the device signer.
    legitimate_signature = device_signer.sign(legitimate_message)
    replay_success = replay_attack(legitimate_message, legitimate_signature, target_public_key)
    if replay_success:
        log.warning("Replay attack succeeded! The system is vulnerable to replay attacks.")
    else:
        log.info("Replay attack failed (replay protection is effective).")

    # ------- Final Assessment -------
    if not is_forged_valid and replay_success:
        log.info("Overall: The cryptography resists forgery, but the system may be vulnerable to replay attacks.")
    elif is_forged_valid:
        log.warning("Overall: The cryptography appears compromised by forgery!")
    else:
        log.info("Overall: The simulated device's cryptography appears secure.")

if __name__ == "__main__":
    try:
        run_attack()
    except KeyboardInterrupt:
        log.info("Attack simulation stopped manually.")

