
import asyncio
import random
import time
import oqs
import base64
import logging

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger("Simulation")

PQC_SIG_ALG = "ML-DSA-44"

try:
    oqs.Signature(PQC_SIG_ALG)
    log.info(f"OQS initialized successfully for {PQC_SIG_ALG}.")
except oqs.MechanismNotSupportedError:
    log.critical(f"PQC Algorithm '{PQC_SIG_ALG}' is not supported by your OQS build. Exiting.")
    exit()
except AttributeError:
    log.critical("The 'oqs.Signature' class is missing. OQS Python installation is incomplete or faulty. Exiting.")
    exit()
except Exception as e:
    log.critical(f"Failed to initialize OQS for '{PQC_SIG_ALG}': {e}. Exiting.")
    exit()

public_keys = {}

def verify_signature(message: bytes, signature: bytes, public_key: bytes, algorithm: str) -> bool:
    """Verifies a PQC signature."""
    try:
        verifier = oqs.Signature(algorithm)
        is_valid = verifier.verify(message, signature, public_key)
        return is_valid
    except Exception as e:
        log.error(f"Error during signature verification: {e}")
        return False

class Device:
    def __init__(self, name, processing_time):
        """
        :param name: Identifier for the device.
        :param processing_time: Simulated non-crypto processing delay (in seconds).
        """
        self.name = name
        self.processing_time = processing_time
        self.busy = False
        self.algorithm = PQC_SIG_ALG

        try:
            log.debug(f"Initializing OQS signer for {self.name} ({self.algorithm})")
            self.signer = oqs.Signature(self.algorithm)
            log.debug(f"Generating key pair for {self.name}")
            self.public_key = self.signer.generate_keypair()
            self.private_key = self.signer.export_secret_key() # Keep private key internal
            log.info(f"Device '{self.name}' initialized with {self.algorithm} keys.")
            public_keys[self.name] = self.public_key
        except Exception as e:
            log.critical(f"Failed to initialize OQS keys for device {self.name}: {e}")
            self.signer = None
            raise RuntimeError(f"Failed key generation for {name}") from e


    async def sign_subpacket(self, subpacket: str) -> tuple[str, bytes | None]:

        if not self.signer:
             log.error(f"Device {self.name} cannot sign, signer not initialized.")
             return self.name, None

        self.busy = True
        log.info(f"{self.name} starts processing sub-packet: '{subpacket[:30]}...'")

        await asyncio.sleep(self.processing_time)
        log.debug(f"{self.name} finished non-crypto processing.")

        signature_bytes = None
        try:
            message_bytes = subpacket.encode('utf-8') # Convert string to bytes
            log.debug(f"{self.name} starting PQC signing ({len(message_bytes)} bytes)...")
            sign_start_time = time.monotonic()
            # Note: oqs.sign is typically blocking. If very slow, use asyncio.to_thread
            signature_bytes = self.signer.sign(message_bytes) # Uses internal private key
            sign_duration = time.monotonic() - sign_start_time
            log.info(f"{self.name} finished PQC signing. Took {sign_duration:.4f}s.")
        except Exception as e:
            log.error(f"Error during signing for device {self.name}: {e}")

        self.busy = False
        log.info(f"{self.name} finished signing task for sub-packet: '{subpacket[:30]}...'")
        return self.name, signature_bytes

# --- Device Instances ---
# Initialize devices (this will also generate their keys)
try:
    arduino = Device("Arduino", 0.15) # Slightly reduced non-crypto time
    raspberry_pi = Device("RaspberryPi", 0.03)
    fpga = Device("FPGA", 0.0001)
    device_pool = [fpga, raspberry_pi, arduino] # Prioritized by speed for selection
    log.info("All devices initialized successfully.")
except RuntimeError as e:
    log.critical(f"Failed to initialize one or more devices: {e}. Exiting.")
    exit()

# --- Extract and Print Public Keys ---
# Access the public key from the public_keys dictionary
arduino_public_key = public_keys.get("Arduino")
raspberry_pi_public_key = public_keys.get("RaspberryPi")
fpga_public_key = public_keys.get("FPGA")

# Print the public key in bytes format
print("Arduino Public Key:", arduino_public_key)
print("Raspberry Pi Public Key:", raspberry_pi_public_key)
print("FPGA Public Key:", fpga_public_key)

# --- Dynamic Scheduler ---
async def dynamic_sign_subpacket(subpacket: str) -> tuple[str, str, bytes | None]:
    """
    Dynamically selects the fastest available device to sign a given sub-packet.
    Returns a tuple: (device_name, subpacket_string, signature_bytes | None).
    """
    chosen_device = None
    while not chosen_device:
        async with asyncio.Lock(): # Basic lock for selecting device state (though Device.busy is not strictly threadsafe)
            available_devices = [d for d in device_pool if not d.busy]
            if available_devices:
                # Choose the available device with the lowest non-crypto processing time base
                chosen_device = min(available_devices, key=lambda d: d.processing_time)
                chosen_device.busy = True # Mark busy immediately after selection
                log.debug(f"Scheduler selected {chosen_device.name} for subpacket '{subpacket[:20]}...'")
            else:
                # Optional: log wait state
                # log.debug("All devices busy, waiting...")
                pass # Release lock and sleep

        if not chosen_device:
            await asyncio.sleep(0.005)

    device_name, signature = await chosen_device.sign_subpacket(subpacket)
    return device_name, subpacket, signature

def split_packet(packet: str, num_splits: int) -> list[str]:
    total_len = len(packet)
    if num_splits <= 0 or total_len < num_splits :
         log.warning(f"Cannot split into {num_splits} parts, packet length {total_len}. Returning as 1 part.")
         return [packet]
    if num_splits == 1: return [packet]

    k = num_splits - 1
    n = total_len -1
    if k > n: k = n
    indices = sorted(random.sample(range(1, total_len), k)) # Sample k unique points
    indices = [0] + indices + [total_len]
    subpackets = [packet[indices[i]:indices[i+1]] for i in range(len(indices)-1)]
    return subpackets

def create_data_packet(packet_id: int) -> str:
    timestamp = time.time()
    payload = f"Temp={round(random.uniform(18, 28), 2)}C,Press={round(random.uniform(0.9, 1.1), 3)}atm,Vibe={random.random():.4f}"
    header = f"ID:{packet_id:04d}|TS:{timestamp:.3f}|"
    packet = header + payload
    return packet

# --- Simulation Loop (with Verification) ---
async def sensor_simulation(num_packets=10, interval=0.2):
    """
    Simulates generation, signing, and verification of data packets.
    """
    log.info(f"Starting simulation: {num_packets} packets, interval {interval}s.")
    simulation_results = []
    total_verified = 0
    total_failed = 0

    for i in range(num_packets):
        packet = create_data_packet(i + 1)
        log.info(f"--- Generated Full Packet {i+1} ({len(packet)} bytes) ---")
        log.debug(f"Packet Content: {packet}")

        num_splits = random.randint(2, max(2, len(device_pool))) # Split based on pool size, min 2
        subpackets = split_packet(packet, num_splits)
        log.info(f"Splitting into {len(subpackets)} sub-packets:")
        for idx, sp in enumerate(subpackets):
            log.debug(f"  SubP {idx+1} ({len(sp)}B): '{sp}'")

        tasks = [asyncio.create_task(dynamic_sign_subpacket(sp)) for sp in subpackets]
        signing_results = await asyncio.gather(*tasks)

        log.info(f"--- Verifying Signatures for Packet {i+1} ---")
        verified_signatures = []
        packet_valid = True
        for idx, result in enumerate(signing_results):
            device_name, sp_str, sig_bytes = result
            sp_bytes = sp_str.encode('utf-8')
            pub_key_bytes = public_keys.get(device_name)
            log.debug(f"Verifying SubP {idx+1} from {device_name}...")

            if sig_bytes is None:
                log.error(f"  Verification FAILED for SubP {idx+1}: Signing failed (Signature is None).")
                packet_valid = False
                verified_signatures.append((device_name, sp_str, None, False)) # Store failure
            elif pub_key_bytes is None:
                log.error(f"  Verification FAILED for SubP {idx+1}: Public key for {device_name} not found.")
                packet_valid = False
                verified_signatures.append((device_name, sp_str, sig_bytes, False))
            else:
                is_valid = verify_signature(sp_bytes, sig_bytes, pub_key_bytes, PQC_SIG_ALG)
                if is_valid:
                    log.info(f"  Verification SUCCESS for SubP {idx+1} from {device_name}.")
                    verified_signatures.append((device_name, sp_str, sig_bytes, True))
                else:
                    log.error(f"  Verification FAILED for SubP {idx+1} from {device.name}: Invalid signature!")
                    packet_valid = False
                    verified_signatures.append((device_name, sp_str, sig_bytes, False))

        if packet_valid:
             log.info(f"--- Packet {i+1} Verification: SUCCESSFUL ---")
             total_verified += 1
        else:
             log.error(f"--- Packet {i+1} Verification: FAILED (One or more subpackets invalid) ---")
             total_failed += 1

        # --- Aggregation & Reconstruction ---
        # Aggregate signatures (Base64 encoded for display/storage)
        aggregated_signature_display = "|".join([
            f"{name}:{base64.b64encode(sig).decode('ascii') if sig else 'SIGN_FAIL'}"
            for name, _, sig, _ in verified_signatures
        ])
        # Reassemble the original packet string
        reconstructed_packet = "".join([sp for _, sp, _, _ in verified_signatures])

        log.debug(f"Aggregated Signature Display:\n{aggregated_signature_display}\n")
        if reconstructed_packet == packet:
            log.debug("Reconstruction Successful: Packet content matches original.")
        else:
            log.error("Reconstruction Failed: Mismatch in packet content!") # Should not happen if split is correct

        # Store detailed result
        packet_result_data = {
            "packet_id": f"Packet_{i+1}",
            "original_packet": packet,
            "status": "Verified" if packet_valid else "Failed Verification",
            "subpackets_details": [
                {"subpacket": sp, "signer": name, "signature_b64": base64.b64encode(sig).decode('ascii') if sig else None, "verified": status}
                for name, sp, sig, status in verified_signatures
            ]
        }
        simulation_results.append(packet_result_data)

        await asyncio.sleep(interval)

    log.info(f"--- Simulation Summary ---")
    log.info(f"Total Packets Processed: {num_packets}")
    log.info(f"Successfully Verified: {total_verified}")
    log.info(f"Failed Verification: {total_failed}")
    log.info(f"-------------------------")
    return simulation_results

async def run_simulation():
    log.info(f"Starting simulation with actual OQS signing ({PQC_SIG_ALG})...\n")
    results = await sensor_simulation(num_packets=5, interval=0.5) # Fewer packets, longer interval

if __name__ == "__main__":
    try:
        asyncio.run(run_simulation())
    except KeyboardInterrupt:
        log.info("Simulation stopped manually.")
