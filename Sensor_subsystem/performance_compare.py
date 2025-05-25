
# File: performance_compare.py
import time
import os
import statistics
import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as crypto_utils # Renamed to avoid conflict
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding # Required for RSA, not ECDSA sign/verify directly

# --- Configuration ---
ML_DSA_ALG = "ML-DSA-44"
ECDSA_CURVE = ec.SECP256R1() # NIST P-256 curve
ECDSA_HASH = hashes.SHA256()
NUM_TRIALS = 1000 # Number of times to run timing tests for averaging
MESSAGE_SIZE_BYTES = 175# Size of the message to sign/verify

# --- Helper Function for Timing ---
def time_operation(func, *args, trials=NUM_TRIALS):
    """Times an operation multiple times and returns average duration in seconds."""
    timings = []
    for _ in range(trials):
        start_time = time.monotonic()
        func(*args)
        end_time = time.monotonic()
        timings.append(end_time - start_time)
    return statistics.mean(timings) if timings else 0

# --- ML-DSA Analysis ---
def analyze_mldsa():
    print(f"\n--- Analyzing {ML_DSA_ALG} ---")
    results = {}
    try:
        signer = oqs.Signature(ML_DSA_ALG)

        # Key Generation
        gen_start = time.monotonic()
        public_key_mldsa = signer.generate_keypair()
        secret_key_mldsa = signer.export_secret_key()
        gen_end = time.monotonic()
        results["key_gen_time_ms"] = (gen_end - gen_start) * 1000

        # Key Sizes
        results["public_key_size"] = len(public_key_mldsa)
        results["private_key_size"] = len(secret_key_mldsa)

        # Signing & Verification Time
        message = os.urandom(MESSAGE_SIZE_BYTES)

        # Need to wrap sign/verify for time_operation as they return values
        def sign_mldsa_op():
             return signer.sign(message)

        def verify_mldsa_op(sig):
             signer.verify(message, sig, public_key_mldsa)

        # Time signing (run once first to potentially warm up if needed)
        signature_mldsa = sign_mldsa_op()
        results["sign_time_ms"] = time_operation(sign_mldsa_op) * 1000

        # Time verification
        verify_mldsa_op(signature_mldsa) # Warm up
        results["verify_time_ms"] = time_operation(verify_mldsa_op, signature_mldsa) * 1000

        # Signature Size
        results["signature_size"] = len(signature_mldsa)

        print("ML-DSA Analysis Complete.")
        return results

    except Exception as e:
        print(f"ERROR analyzing ML-DSA: {e}")
        return None

# --- ECDSA Analysis ---
def analyze_ecdsa():
    print(f"\n--- Analyzing ECDSA ({ECDSA_CURVE.name} + {ECDSA_HASH.name}) ---")
    results = {}
    try:
        # Key Generation
        gen_start = time.monotonic()
        private_key_ecdsa = ec.generate_private_key(ECDSA_CURVE)
        public_key_ecdsa = private_key_ecdsa.public_key()
        gen_end = time.monotonic()
        results["key_gen_time_ms"] = (gen_end - gen_start) * 1000

        # Key Sizes (using standard encodings)
        # Public key: Uncompressed point format (common standard)
        public_key_bytes_ecdsa = public_key_ecdsa.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        results["public_key_size"] = len(public_key_bytes_ecdsa)

        # Private key: PKCS8 PEM format (common standard)
        private_key_bytes_ecdsa = private_key_ecdsa.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        results["private_key_size"] = len(private_key_bytes_ecdsa) # Note: PEM includes headers/newlines

        # Signing & Verification Time
        message = os.urandom(MESSAGE_SIZE_BYTES)

        # Wrap operations for timing
        def sign_ecdsa_op():
             # ECDSA signing returns DER-encoded signature by default
             return private_key_ecdsa.sign(message, ec.ECDSA(ECDSA_HASH))

        def verify_ecdsa_op(sig):
            # Verification takes the DER-encoded signature
             public_key_ecdsa.verify(sig, message, ec.ECDSA(ECDSA_HASH))

        # Time signing
        signature_ecdsa_der = sign_ecdsa_op() # Warm up
        results["sign_time_ms"] = time_operation(sign_ecdsa_op) * 1000

        # Time verification
        verify_ecdsa_op(signature_ecdsa_der) # Warm up
        results["verify_time_ms"] = time_operation(verify_ecdsa_op, signature_ecdsa_der) * 1000

        # Signature Size (DER encoded by default)
        results["signature_size"] = len(signature_ecdsa_der)
        # Note: ECDSA signatures can also be represented as raw (r, s) integers,
        # which for P-256 would be 2 * 32 = 64 bytes, but DER is common for interoperability.

        print("ECDSA Analysis Complete.")
        return results

    except Exception as e:
        print(f"ERROR analyzing ECDSA: {e}")
        return None

# --- Main Execution ---
if __name__ == "__main__":
    print(f"Starting performance comparison ({NUM_TRIALS} trials per timed operation)...")
    print(f"Message size for sign/verify: {MESSAGE_SIZE_BYTES} bytes")

    mldsa_results = analyze_mldsa()
    ecdsa_results = analyze_ecdsa()

    print("\n--- Comparison Summary ---")
    print(f"{'Metric':<25} | {'ML-DSA-44':<15} | {'ECDSA P-256':<15}")
    print("-" * (25 + 3 + 15 + 3 + 15))

    metrics = [
        ("Key Gen Time (ms)", "key_gen_time_ms", ".3f"),
        ("Sign Time (ms)", "sign_time_ms", ".3f"),
        ("Verify Time (ms)", "verify_time_ms", ".3f"),
        ("Public Key Size (B)", "public_key_size", "d"),
        ("Private Key Size (B)", "private_key_size", "d"), # ECDSA size is PEM format
        ("Signature Size (B)", "signature_size", "d")  # ECDSA size is DER format
    ]

    for label, key, fmt in metrics:
        mldsa_val = mldsa_results.get(key, 'N/A') if mldsa_results else 'ERROR'
        ecdsa_val = ecdsa_results.get(key, 'N/A') if ecdsa_results else 'ERROR'

        mldsa_str = f"{mldsa_val:{fmt}}" if isinstance(mldsa_val, (int, float)) else str(mldsa_val)
        ecdsa_str = f"{ecdsa_val:{fmt}}" if isinstance(ecdsa_val, (int, float)) else str(ecdsa_val)

        print(f"{label:<25} | {mldsa_str:<15} | {ecdsa_str:<15}")

    print("-" * (25 + 3 + 15 + 3 + 15))
