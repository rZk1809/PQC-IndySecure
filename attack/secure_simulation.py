# secure_simulation.py
import asyncio
import random
import time
import oqs
import base64
import logging
import copy # Needed for deep copying results before potential attack

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger("SecureSim")

PQC_SIG_ALG = "ML-DSA-87" # Make sure this matches your OQS build

try:
    oqs.Signature(PQC_SIG_ALG)
    log.info(f"OQS library check: {PQC_SIG_ALG} is supported.")
except oqs.MechanismNotSupportedError:
    log.critical(f"FATAL: PQC Algorithm '{PQC_SIG_ALG}' is not supported by your OQS build. Exiting.")
    exit(1)
except AttributeError:
    log.critical("FATAL: The 'oqs.Signature' class is missing. OQS Python installation is incomplete or faulty. Exiting.")
    exit(1)
except Exception as e:
    log.critical(f"FATAL: Failed to perform initial OQS check for '{PQC_SIG_ALG}': {e}. Exiting.")
    exit(1)


public_keys = {}
# ---

def verify_signature(message: bytes, signature: bytes, public_key: bytes, algorithm: str) -> bool:
    """Verifies a PQC signature using the provided public key."""
    if not all([message, signature, public_key, algorithm]):
        log.error("Verification error: Missing message, signature, public key, or algorithm.")
        return False
    if not isinstance(message, bytes) or not isinstance(signature, bytes) or not isinstance(public_key, bytes):
        log.error(f"Verification error: Inputs must be bytes. Got types: {type(message)}, {type(signature)}, {type(public_key)}")
        return False

    try:
        verifier = oqs.Signature(algorithm)
        # Verification timing can optionally be measured here
        # verify_start = time.monotonic()
        is_valid = verifier.verify(message, signature, public_key)
        # verify_end = time.monotonic()
        # log.debug(f"OQS verify took: {(verify_end - verify_start)*1000:.2f} ms")
        return is_valid
    except oqs.MechanismNotSupportedError:
        log.error(f"Verification error: Algorithm '{algorithm}' not supported by OQS during verification call.")
        return False
    except Exception as e:
        # Avoid logging potentially sensitive data from signature/message in case of errors
        log.error(f"Verification error: Unexpected exception during OQS verify: {e}")
        return False

class Device:
    def __init__(self, name, processing_time):
        """
        Initializes a device simulation instance.
        :param name: Identifier for the device.
        :param processing_time: Simulated non-crypto processing delay (in seconds).
        """
        self.name = name
        self.processing_time = processing_time # Simulate device-specific non-crypto work
        self.busy = False
        self.algorithm = PQC_SIG_ALG
        self.signer = None # Initialize signer to None
        self.public_key = None
        self._private_key = None # Use underscore to denote internal use

        try:
            log.debug(f"Initializing OQS signer for {self.name} ({self.algorithm})")
            # Create a new Signature instance for each device
            self.signer = oqs.Signature(self.algorithm)
            log.debug(f"Generating key pair for {self.name}")
            # generate_keypair() returns the public key and sets the private key internally
            self.public_key = self.signer.generate_keypair()
            # Keep the private key internal to the signer object (more encapsulated)
            # self._private_key = self.signer.export_secret_key() # Not strictly needed if only using self.signer.sign
            log.info(f"Device '{self.name}' initialized with {self.algorithm}. Public Key len: {len(self.public_key)} bytes.")

            # Store public key globally (for simulation verification access)
            if self.name in public_keys:
                 log.warning(f"Device name '{self.name}' collision in public_keys dictionary. Overwriting.")
            public_keys[self.name] = self.public_key

        except oqs.MechanismNotSupportedError:
             log.critical(f"Failed to initialize OQS keys for device {self.name}: Algorithm '{self.algorithm}' not supported.")
             raise RuntimeError(f"OQS Mechanism not supported for {name}") from None # Use 'from None' to break chain
        except Exception as e:
            log.critical(f"Failed to initialize OQS keys for device {self.name}: {e}")
            # Ensure signer is None if initialization fails
            self.signer = None
            raise RuntimeError(f"Failed key generation for {name}") from e

    async def sign_subpacket(self, subpacket_content: str, subpacket_index: int) -> tuple[str, int, bytes | None]:
        """
        Signs a subpacket including its index.
        Returns (device_name, subpacket_index, signature_bytes | None)
        """
        if not self.signer:
            log.error(f"Device {self.name} cannot sign, signer not initialized.")
            return self.name, subpacket_index, None

        # Construct the message to be signed: Include index for positional integrity
        message_to_sign = f"INDEX:{subpacket_index}|DATA:{subpacket_content}"
        message_bytes = message_to_sign.encode('utf-8')

        self.busy = True # Mark as busy *before* starting async operations
        log.info(f"{self.name} starts processing SubP#{subpacket_index}: '{subpacket_content[:30]}...'")

        # 1. Simulate non-cryptographic processing time
        await asyncio.sleep(self.processing_time)
        log.debug(f"{self.name} finished non-crypto processing for SubP#{subpacket_index}.")

        # 2. Perform cryptographic signing
        signature_bytes = None
        try:
            log.debug(f"{self.name} starting PQC signing for SubP#{subpacket_index} ({len(message_bytes)} bytes)...")
            sign_start_time = time.monotonic()

            # Run the potentially blocking OQS sign operation in a thread pool
            # to avoid blocking the asyncio event loop, especially if signing is slow.
            loop = asyncio.get_running_loop()
            signature_bytes = await loop.run_in_executor(
                None, # Uses the default ThreadPoolExecutor
                self.signer.sign, # The blocking function to call
                message_bytes    # Arguments for the function
            )
            # signature_bytes = self.signer.sign(message_bytes) # Direct call (if signing is fast enough)

            sign_duration = time.monotonic() - sign_start_time
            log.info(f"{self.name} finished PQC signing SubP#{subpacket_index}. Took {sign_duration:.4f}s. Sig len: {len(signature_bytes)} bytes.")
        except Exception as e:
            log.error(f"Error during signing for device {self.name}, SubP#{subpacket_index}: {e}")
            # Signature remains None

        # 3. Mark device as free *after* all operations are complete
        self.busy = False
        log.info(f"{self.name} finished task for SubP#{subpacket_index}: '{subpacket_content[:30]}...'")
        return self.name, subpacket_index, signature_bytes

# --- Device Instances ---
# Initialize devices pool. Order matters for scheduler preference (faster first).
device_pool = []
try:
    # Lower processing time means faster device preference
    fpga = Device("FPGA", 0.001) # Very fast non-crypto simulation
    raspberry_pi = Device("RaspberryPi", 0.05)
    arduino = Device("Arduino", 0.20) # Slower non-crypto simulation
    device_pool = [fpga, raspberry_pi, arduino] # Prioritized by speed for selection
    log.info(f"Initialized {len(device_pool)} devices successfully.")
except RuntimeError as e:
    log.critical(f"Failed to initialize one or more devices: {e}. Exiting simulation.")
    exit(1)
except Exception as e:
    log.critical(f"An unexpected error occurred during device initialization: {e}. Exiting.")
    exit(1)

# --- Dynamic Scheduler ---
# Using a lock to manage access to the shared device_pool state (busy flags)
scheduler_lock = asyncio.Lock()

async def dynamic_sign_subpacket(subpacket_content: str, subpacket_index: int) -> tuple[str, int, str, bytes | None]:
    """
    Dynamically selects the fastest available device to sign a given sub-packet.
    Returns a tuple: (device_name, subpacket_index, subpacket_content, signature_bytes | None).
    """
    chosen_device = None
    while not chosen_device:
        async with scheduler_lock: # Ensure atomic check-and-set for device busy status
            # Find devices that are not currently busy
            available_devices = [d for d in device_pool if not d.busy]

            if available_devices:
                # Choose the available device with the lowest non-crypto processing time base
                # (This assumes processing_time is a static indicator of preference)
                chosen_device = min(available_devices, key=lambda d: d.processing_time)
                chosen_device.busy = True # Mark busy immediately *inside the lock*
                log.debug(f"Scheduler selected {chosen_device.name} for SubP#{subpacket_index} ('{subpacket_content[:20]}...')")
            # else: # All devices are busy
                # Optional: log wait state if needed for debugging contention
                # log.debug(f"All devices busy, SubP#{subpacket_index} waiting...")
                # Pass releases the lock implicitly at end of 'with' block

        if not chosen_device:
            # If no device was available, wait a very short time before checking again
            # Avoids busy-waiting consuming 100% CPU if all devices are busy for a while
            await asyncio.sleep(0.005) # 5 milliseconds

    # Once a device is chosen and marked busy, call its sign method
    device_name, index, signature = await chosen_device.sign_subpacket(subpacket_content, subpacket_index)

    # Return all necessary info for verification and reconstruction
    return device_name, index, subpacket_content, signature

# --- Packet Handling ---

def split_packet(packet: str, num_splits: int) -> list[tuple[int, str]]:
    """
    Splits a packet into roughly equal parts, returning list of (index, content).
    Uses random split points for variability.
    """
    total_len = len(packet)
    if num_splits <= 0:
        log.warning(f"Invalid num_splits ({num_splits}). Defaulting to 1 split.")
        num_splits = 1
    if total_len == 0:
        log.warning("Packet is empty, cannot split.")
        return []
    if num_splits == 1:
        return [(0, packet)] # Return index 0 for single packet
    if num_splits > total_len:
        log.warning(f"num_splits ({num_splits}) > packet length ({total_len}). Splitting into {total_len} single characters.")
        num_splits = total_len # Split into individual characters if needed

    # Ensure split points are unique and within bounds
    k = num_splits - 1 # Need k split points for num_splits parts
    # Generate k distinct random indices between 1 and total_len-1
    # Using range(1, total_len) ensures splits happen *between* characters
    split_indices = sorted(random.sample(range(1, total_len), k))

    # Create the subpackets using the split indices
    subpackets = []
    start_index = 0
    for i, split_point in enumerate(split_indices):
        subpackets.append((i, packet[start_index:split_point])) # Add (index, content)
        start_index = split_point
    # Add the last part
    subpackets.append((len(subpackets), packet[start_index:])) # Index is the count so far

    # Verification log
    # reconstructed = "".join([content for idx, content in sorted(subpackets, key=lambda x: x[0])])
    # if reconstructed != packet:
    #    log.error(f"CRITICAL SPLIT ERROR: Reconstruction failed. Original len {len(packet)}, Reconstructed len {len(reconstructed)}")
    #    # Handle this error robustly, maybe raise exception
    # else:
    #    log.debug(f"Split successful into {len(subpackets)} parts.")


    return subpackets


def create_data_packet(packet_id: int) -> str:
    """Generates a sample data packet string."""
    timestamp = time.time() # High-resolution timestamp
    # Simulate some sensor data
    temp = round(random.uniform(18, 28), 2)
    pressure = round(random.uniform(0.95, 1.05), 3)
    vibration = random.random()
    # Create a structured packet string (e.g., key-value pairs or CSV)
    payload = f"Temp={temp:.2f}C,Press={pressure:.3f}atm,Vibe={vibration:.4f}"
    # Add a header with ID and timestamp
    header = f"ID:{packet_id:05d}|TS:{timestamp:.6f}|" # More precision for TS
    packet = header + payload
    log.debug(f"Created packet {packet_id}: {packet}")
    return packet

# --- Simulation Loop (with Enhanced Verification) ---
async def sensor_simulation(num_packets=10, interval=0.2):
    """
    Simulates generation, distributed signing, and central verification of data packets.
    """
    log.info(f"--- Starting Secure Sensor Simulation ---")
    log.info(f"Packets to generate: {num_packets}, Interval: {interval}s")
    log.info(f"Using PQC Algorithm: {PQC_SIG_ALG}")
    log.info(f"Devices in pool: {', '.join(d.name for d in device_pool)}")
    log.info(f"-----------------------------------------")

    simulation_summary = {
        "total_packets": num_packets,
        "verified_ok": 0,
        "verification_failed": 0,
        "signing_errors": 0, # Count cases where signing itself failed (sig is None)
        "reconstruction_errors": 0,
        "packets_details": []
    }

    start_time = time.monotonic()

    for i in range(num_packets):
        packet_id = i + 1
        log.info(f"========== Packet {packet_id}/{num_packets} ==========")
        original_packet = create_data_packet(packet_id)
        log.info(f"Generated Full Packet {packet_id} ({len(original_packet)} bytes)")

        # --- Splitting ---
        # Determine number of splits - ensure it's at least 2 if possible, up to number of devices
        max_splits = min(len(device_pool), len(original_packet)) # Can't split more than chars or devices
        num_splits = random.randint(min(2, max_splits), max_splits) if max_splits >= 2 else 1
        subpackets_with_indices = split_packet(original_packet, num_splits)
        log.info(f"Splitting into {len(subpackets_with_indices)} sub-packets.")
        for idx, sp_content in subpackets_with_indices:
            log.debug(f"  SubP #{idx} ({len(sp_content)}B): '{sp_content[:40]}...'")


        # --- Concurrent Signing ---
        signing_tasks = []
        for index, content in subpackets_with_indices:
            # Create a task for each subpacket using the dynamic scheduler
            task = asyncio.create_task(dynamic_sign_subpacket(content, index))
            signing_tasks.append(task)

        # Wait for all signing tasks to complete
        # Results contain: (device_name, subpacket_index, subpacket_content, signature_bytes | None)
        signing_results = await asyncio.gather(*signing_tasks)

        # Sort results by subpacket index to ensure correct order for reconstruction and verification
        signing_results.sort(key=lambda r: r[1]) # Sort by index (element 1)


        # --- Verification and Reconstruction ---
        log.info(f"--- Verifying Signatures for Packet {packet_id} ---")
        verified_subpackets_data = [] # Store details for logging/results
        packet_valid = True # Assume valid until proven otherwise
        reconstructed_parts = {} # Store content by index for reconstruction check

        for result in signing_results:
            device_name, sp_index, sp_content, sig_bytes = result
            log.debug(f"Verifying SubP #{sp_index} from {device_name}...")

            # Prepare the exact message that was signed (including index)
            message_to_verify = f"INDEX:{sp_index}|DATA:{sp_content}"
            sp_bytes_to_verify = message_to_verify.encode('utf-8')

            # Get the correct public key for the device that claimed to sign it
            public_key_bytes = public_keys.get(device_name)

            sub_packet_status = {
                "index": sp_index,
                "content": sp_content,
                "signer": device_name,
                "signature_b64": None,
                "verified_status": "FAILED", # Default to failed
                "reason": ""
            }

            verification_passed = False # Track verification outcome for this subpacket
            if sig_bytes is None:
                log.error(f"  Verification FAILED for SubP #{sp_index} (Device: {device_name}): Signing failed earlier (Signature is None).")
                packet_valid = False
                sub_packet_status["reason"] = "Signing process failed"
                simulation_summary["signing_errors"] += 1
            elif public_key_bytes is None:
                log.error(f"  Verification FAILED for SubP #{sp_index}: Public key for device '{device_name}' not found.")
                packet_valid = False
                sub_packet_status["reason"] = "Public key not found"
            else:
                # Perform the actual cryptographic verification
                is_valid = verify_signature(sp_bytes_to_verify, sig_bytes, public_key_bytes, PQC_SIG_ALG)
                sub_packet_status["signature_b64"] = base64.b64encode(sig_bytes).decode('ascii')

                if is_valid:
                    log.info(f"  Verification SUCCESS for SubP #{sp_index} from {device_name}.")
                    verification_passed = True
                    sub_packet_status["verified_status"] = "OK"
                    sub_packet_status["reason"] = "Signature matches message and key"
                    # Store content for reconstruction check only if verified
                    reconstructed_parts[sp_index] = sp_content
                else:
                    log.error(f"  Verification FAILED for SubP #{sp_index} from {device_name}: Invalid signature!")
                    packet_valid = False
                    sub_packet_status["reason"] = "Signature verification failed"

            verified_subpackets_data.append(sub_packet_status)

        # --- Post-Verification Checks ---
        # 1. Reconstruction Check (only if all individual parts were supposed to be valid)
        reconstruction_ok = False
        if packet_valid: # Only attempt reconstruction if no individual signature failed
             # Ensure all indices are present
             if len(reconstructed_parts) == len(subpackets_with_indices):
                reconstructed_packet = "".join(reconstructed_parts[i] for i in range(len(subpackets_with_indices)))
                if reconstructed_packet == original_packet:
                    log.info("Packet Reconstruction Successful: Content matches original.")
                    reconstruction_ok = True
                else:
                    log.error("Packet Reconstruction FAILED: Content mismatch after verification!")
                    log.debug(f"Original: '{original_packet}'")
                    log.debug(f"Reconstr: '{reconstructed_packet}'")
                    packet_valid = False # Mark entire packet as invalid due to reconstruction failure
                    simulation_summary["reconstruction_errors"] += 1
             else:
                 log.error(f"Packet Reconstruction FAILED: Missing verified subpackets. Expected {len(subpackets_with_indices)}, got {len(reconstructed_parts)}.")
                 packet_valid = False # Invalid if parts are missing
                 simulation_summary["reconstruction_errors"] += 1

        # 2. Final Packet Status
        if packet_valid and reconstruction_ok:
            log.info(f"--- Packet {packet_id} Verification Overall: SUCCESSFUL ---")
            simulation_summary["verified_ok"] += 1
            packet_status = "Verified"
        else:
            log.error(f"--- Packet {packet_id} Verification Overall: FAILED ---")
            simulation_summary["verification_failed"] += 1
            packet_status = "Failed Verification" # Generic failure status


        # --- Store Results ---
        packet_result_data = {
            "packet_id": f"Packet_{packet_id}",
            "original_packet_content": original_packet,
            "overall_status": packet_status,
            "subpackets_details": verified_subpackets_data # Already contains status/reason
        }
        simulation_summary["packets_details"].append(packet_result_data)

        log.info(f"========== End Packet {packet_id} ==========\n")
        # Wait before processing the next packet
        await asyncio.sleep(interval)

    # --- Simulation End Summary ---
    end_time = time.monotonic()
    total_duration = end_time - start_time
    log.info(f"========== Simulation Complete ==========")
    log.info(f"Total Time Elapsed: {total_duration:.3f} seconds")
    log.info(f"Packets Processed: {num_packets}")
    log.info(f"Successfully Verified & Reconstructed: {simulation_summary['verified_ok']}")
    log.info(f"Failed Verification (Sig/Recon): {simulation_summary['verification_failed']}")
    log.info(f"  (Breakdown: Signing Errors: {simulation_summary['signing_errors']}, Reconstruction Errors: {simulation_summary['reconstruction_errors']})")
    log.info(f"=========================================")

    # Optionally return the detailed results
    # return simulation_summary

async def run_simulation():
    log.info(f"Starting main simulation runner...")
    # Adjust num_packets and interval as needed
    await sensor_simulation(num_packets=5, interval=0.5)
    log.info("Simulation runner finished.")

if __name__ == "__main__":
    log.info("Script started.")
    try:
        asyncio.run(run_simulation())
    except KeyboardInterrupt:
        log.info("Simulation stopped manually by user (KeyboardInterrupt).")
    except Exception as main_e:
        log.critical(f"An uncaught exception occurred in main: {main_e}", exc_info=True)
    finally:
        log.info("Script finished.")
