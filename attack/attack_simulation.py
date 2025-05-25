import random
import time
import logging
import hashlib
import json
import os

# --- Configuration ---
LOG_LEVEL = logging.INFO
NUM_PACKETS = 10  # Increase for better statistics
SUBPACKETS_PER_PACKET = 3
ATTACK_PROBABILITY = 0.6  # 60% chance a packet is attacked
OUTPUT_DIR = "output_attack_sim"

# --- Logging Setup ---
logging.basicConfig(level=LOG_LEVEL, format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
logger = logging.getLogger("RealAttackSim")

# --- Helper Functions ---

# Simulated JSON-based sensor data
def generate_sample_data():
    """Generates random sensor data."""
    return {
        "timestamp": time.time(),
        "temperature": round(random.uniform(15.0, 35.0), 2),
        "humidity": round(random.uniform(30.0, 70.0), 2),
        "pressure": round(random.uniform(980.0, 1050.0), 2),
        "sensor_id": f"SN-{random.randint(1000, 9999)}"
    }

# Utility to simulate encryption (reversal here - simple placeholder)
def encrypt(data):
    """Simulates data encryption."""
    # In a real scenario, use a proper encryption library like cryptography
    return data[::-1]

# Utility to simulate decryption
def decrypt(data):
    """Simulates data decryption."""
    # Should mirror the encryption method
    return data[::-1]

# Utility to hash data for signing/verification
def hash_data(data):
    """Generates a SHA256 hash of the input data."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

# --- Classes ---

class Subpacket:
    """Represents a fragment of the original data packet."""
    def __init__(self, subpacket_id, original_content):
        self.id = subpacket_id
        self.original_content_fragment = original_content # Store for reference if needed
        self.encrypted_data = encrypt(original_content)
        # Signature is calculated ONCE on the original encrypted data
        self.signature = hash_data(self.encrypted_data)
        # These fields will be populated if tampering occurs on THIS subpacket
        self.tampered = False
        self.original_encrypted_data_before_tamper = None

    def tamper_data(self, tamper_string="<TAMPERED>"):
        """Simulates corruption of the encrypted data WITHOUT updating signature."""
        if not self.encrypted_data:
            logger.warning(f"Subpacket {self.id} has no data to tamper.")
            return False

        self.tampered = True
        self.original_encrypted_data_before_tamper = self.encrypted_data # Save original state

        # Inject tamper string somewhere in the middle
        insert_pos = len(self.encrypted_data) // 2
        self.encrypted_data = (
            self.encrypted_data[:insert_pos] +
            tamper_string +
            self.encrypted_data[insert_pos:]
        )
        logger.debug(f"Subpacket {self.id} data tampered.")
        return True

    def to_dict(self):
        """Returns a dictionary representation for saving."""
        return {
            "subpacket_id": self.id,
            # "original_content_fragment": self.original_content_fragment, # Optional: include for debugging
            "signature": self.signature,
            "encrypted_data": self.encrypted_data, # This is the potentially tampered data
            "tampered": self.tampered,
            "original_encrypted_data_before_tamper": self.original_encrypted_data_before_tamper # Shows original if tampered
        }

class Packet:
    """Represents a full data packet composed of subpackets."""
    def __init__(self, packet_id, raw_data_dict):
        self.id = packet_id
        self.subpackets = []
        self.raw_data = json.dumps(raw_data_dict, sort_keys=True) # Ensure consistent order for splitting

        # --- State Flags ---
        self.attack_simulated = False # Flag indicating if we *tried* to attack this packet
        self.attack_details = None    # Dictionary storing details if attack occurred

        self.create_subpackets()

    def create_subpackets(self):
        """Splits the raw data into parts and creates Subpacket objects."""
        data_len = len(self.raw_data)
        chunk_size = (data_len + SUBPACKETS_PER_PACKET - 1) // SUBPACKETS_PER_PACKET # Ceiling division

        parts = []
        for i in range(SUBPACKETS_PER_PACKET):
            start = i * chunk_size
            end = min((i + 1) * chunk_size, data_len)
            if start < data_len:
                 parts.append(self.raw_data[start:end])
            else:
                 parts.append("") # Handle cases where data splits unevenly

        # Ensure we have exactly SUBPACKETS_PER_PACKET, pad with empty if needed
        while len(parts) < SUBPACKETS_PER_PACKET:
            parts.append("")

        self.subpackets = [Subpacket(f"{self.id}-{i}", part) for i, part in enumerate(parts)]
        logger.debug(f"Packet {self.id}: Created {len(self.subpackets)} subpackets.")

    def simulate_attack(self):
        """
        Simulates an attack by tampering with one subpacket's encrypted data
        WITHOUT updating its signature.
        """
        if not self.subpackets:
            logger.warning(f"Packet {self.id} has no subpackets to attack.")
            return

        self.attack_simulated = True
        target_subpacket = random.choice(self.subpackets)

        logger.warning(f"!!! Simulating ATTACK on Packet {self.id} - Targeting Subpacket {target_subpacket.id}")

        original_encrypted = target_subpacket.encrypted_data
        success = target_subpacket.tamper_data() # Tamper the data

        if success:
            self.attack_details = {
                "attack_type": "Data Corruption",
                "targeted_subpacket_id": target_subpacket.id,
                "original_encrypted_fragment": original_encrypted,
                "tampered_encrypted_fragment": target_subpacket.encrypted_data
            }
        else:
             logger.error(f"Failed to tamper data for subpacket {target_subpacket.id}")
             self.attack_details = {
                "attack_type": "Data Corruption Attempt Failed",
                "targeted_subpacket_id": target_subpacket.id,
             }


    def verify(self):
        """
        Verifies the integrity of all subpackets by checking their signatures.
        This simulates what the receiver would do. It does NOT use the 'attack_simulated' flag.
        Returns: True if all signatures are valid, False otherwise.
        """
        for sub in self.subpackets:
            # Recalculate hash based on the *received* (potentially tampered) encrypted data
            current_data_hash = hash_data(sub.encrypted_data)
            if current_data_hash != sub.signature:
                logger.warning(f"Packet {self.id}: Verification FAILED for Subpacket {sub.id}. "
                             f"Expected Signature: {sub.signature}, Calculated Hash: {current_data_hash}")
                return False # Tampering detected (or data corruption)
        # If loop completes, all signatures matched
        return True

    def detailed_verify(self):
        """
        Performs verification and returns details about failed subpackets.
        Returns: Tuple (bool: overall_result, list: failed_subpacket_ids)
        """
        failed_subpackets = []
        overall_result = True
        for sub in self.subpackets:
            current_data_hash = hash_data(sub.encrypted_data)
            if current_data_hash != sub.signature:
                overall_result = False
                failed_subpackets.append(sub.id)
                logger.debug(f"Packet {self.id}: Detailed Verification FAILED for Subpacket {sub.id}.")

        return overall_result, failed_subpackets


    def reconstruct_payload(self):
        """
        Attempts to reconstruct the original data by decrypting and joining subpackets.
        Returns: The reconstructed string payload. Might be corrupted if tampering occurred.
        """
        decrypted_parts = []
        for sub in self.subpackets:
            try:
                decrypted_parts.append(decrypt(sub.encrypted_data))
            except Exception as e:
                logger.error(f"Packet {self.id}: Failed to decrypt subpacket {sub.id} - {e}")
                decrypted_parts.append(f"<DECRYPTION_ERROR:{sub.id}>")

        # Join the parts in the correct order
        # Note: The simple splitting logic might need adjustment for perfect reconstruction
        # depending on data length and number of subpackets.
        # This assumes the concatenation order matches the original split.
        payload = "".join(decrypted_parts)
        return payload

    def to_dict(self):
        """Returns a dictionary representation for saving the final state."""
        return {
            "packet_id": self.id,
            "attack_simulated": self.attack_simulated, # Record if attack was attempted
            "attack_details": self.attack_details,     # Record how it was attacked
            "subpackets": [sp.to_dict() for sp in self.subpackets] # Final state of subpackets
        }

# --- Main Simulation Logic ---

def run_real_attack_simulation():
    """Runs the full simulation."""
    logger.info("========== Starting Real Attack Simulation ==========")
    start_time = time.time()

    # Create output directory if it doesn't exist
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        logger.info(f"Created output directory: {OUTPUT_DIR}")

    # --- Step 1: Generate Original Data ---
    original_data_list = [generate_sample_data() for _ in range(NUM_PACKETS)]
    original_packets_path = os.path.join(OUTPUT_DIR, "original_sensor_data.json")
    try:
        with open(original_packets_path, "w") as f:
            json.dump(original_data_list, f, indent=2)
        logger.info(f"Original sensor data saved to {original_packets_path}")
    except IOError as e:
        logger.error(f"Failed to write original data: {e}")
        return # Stop if we can't save initial data

    # --- Step 2: Create Packets ---
    packets = [Packet(i, original_data_list[i]) for i in range(NUM_PACKETS)]
    logger.info(f"Created {len(packets)} packets from original data.")

    # --- Step 3: Simulate Transmission, Attacks, and Reception/Verification ---
    final_packet_states = []       # Store the final state of each packet after processing
    final_reconstructed_payloads = [] # Store the payloads as reconstructed by the receiver
    stats = {
        "total_packets": NUM_PACKETS,
        "attacks_simulated": 0,
        "attacks_detected": 0,
        "attacks_missed": 0,       # Attack happened, but verification passed (should be 0 now)
        "verified_ok_clean": 0,  # No attack simulated, verification passed
        "verified_failed_clean": 0 # No attack simulated, but verification failed (error/bug)
    }

    for packet in packets:
        logger.info(f"--- Processing Packet {packet.id} ---")

        # --- Simulate potential attack during transmission ---
        if random.random() < ATTACK_PROBABILITY:
            packet.simulate_attack()
            stats["attacks_simulated"] += 1

        # --- Simulate Receiver Side Verification ---
        logger.info(f"Packet {packet.id}: Receiver verifying integrity...")
        is_valid, failed_subs = packet.detailed_verify() # Verify based on received data

        if is_valid:
            logger.info(f"Packet {packet.id}: Verification PASSED ✅")
            if packet.attack_simulated:
                logger.error(f"Packet {packet.id}: Attack MISSED! Attack was simulated but verification passed.")
                stats["attacks_missed"] += 1
            else:
                logger.info(f"Packet {packet.id}: Verified OK (No attack simulated).")
                stats["verified_ok_clean"] += 1
        else:
            logger.warning(f"Packet {packet.id}: Verification FAILED! ❌ Tampering suspected in subpackets: {failed_subs}")
            if packet.attack_simulated:
                logger.info(f"Packet {packet.id}: Attack DETECTED successfully.")
                stats["attacks_detected"] += 1
            else:
                logger.error(f"Packet {packet.id}: False Positive! No attack simulated but verification failed.")
                stats["verified_failed_clean"] += 1

        # --- Attempt to Reconstruct Payload ---
        reconstructed_payload = packet.reconstruct_payload()
        logger.debug(f"Packet {packet.id}: Reconstructed payload: {reconstructed_payload}")

        # Attempt to parse the JSON payload (might fail if corrupted)
        try:
            parsed_payload = json.loads(reconstructed_payload)
            final_reconstructed_payloads.append({"packet_id": packet.id, "payload": parsed_payload, "status": "decoded"})
        except json.JSONDecodeError:
            logger.warning(f"Packet {packet.id}: Final reconstructed payload could not be decoded as JSON (likely corrupted).")
            final_reconstructed_payloads.append({"packet_id": packet.id, "payload": reconstructed_payload, "status": "corrupted/decoding_error"})

        # Store the final state of the packet (including attack details and potentially tampered data)
        final_packet_states.append(packet.to_dict())

        logger.info(f"--- Finished Processing Packet {packet.id} ---")


    # --- Step 4: Save Processed Data and Results ---

    # Save the final state of all packets
    processed_packets_path = os.path.join(OUTPUT_DIR, "processed_packets_log.json")
    try:
        with open(processed_packets_path, "w") as f:
            json.dump(final_packet_states, f, indent=2)
        logger.info(f"Final state of all processed packets saved to {processed_packets_path}")
    except IOError as e:
        logger.error(f"Failed to write processed packets log: {e}")

    # Save the final reconstructed payloads
    final_payloads_path = os.path.join(OUTPUT_DIR, "final_reconstructed_payloads.json")
    try:
        with open(final_payloads_path, "w") as f:
            json.dump(final_reconstructed_payloads, f, indent=2)
        logger.info(f"Final reconstructed payloads saved to {final_payloads_path}")
    except IOError as e:
        logger.error(f"Failed to write final payloads: {e}")


    # --- Step 5: Print Summary Statistics ---
    end_time = time.time()
    logger.info("========== Simulation Complete ==========")
    logger.info(f"Time Elapsed: {end_time - start_time:.2f} seconds")
    logger.info("----- Statistics -----")
    logger.info(f"Total Packets Processed: {stats['total_packets']}")
    logger.info(f"Attacks Simulated:       {stats['attacks_simulated']}")
    logger.info(f"Attacks Detected:        {stats['attacks_detected']} / {stats['attacks_simulated']}")
    logger.info(f"Attacks Missed:          {stats['attacks_missed']} / {stats['attacks_simulated']}")
    logger.info(f"Clean Packets Verified OK: {stats['verified_ok_clean']}")
    logger.info(f"Clean Packets Failed Verify: {stats['verified_failed_clean']} (Should be 0 ideally)")
    logger.info("----------------------")
    logger.info(f"Output files saved in: {OUTPUT_DIR}")

# --- Entry Point ---
if __name__ == "__main__":
    run_real_attack_simulation()
