# File: common.py
import asyncio
import json
import logging
import base64
import os
import time
import random # Added for split_packet

# --- Configuration ---
CONTROLLER_IP = '127.0.0.1' # Main controller IP
CONTROLLER_REGISTRATION_PORT = 5008 # Port for Signers to register with Controller
CONTROLLER_SENSOR_PORT = 5005 # Port for Sensor subsystems to submit data to Controller

# Local subsystem communication (Sensor <-> Local Signers)
# Assume very low latency / high bandwidth for local wired comms
LOCAL_IP = '127.0.0.1' # Sensor talks to signers on localhost
SIGNER_BASE_PORT = 6000 # Local signers will listen starting from this port

PQC_SIG_ALG = "ML-DSA-44"
LOG_LEVEL = logging.INFO

# --- Output Directory ---
OUTPUT_DIR = "simulation_data_subsystem" # Directory for this version
os.makedirs(OUTPUT_DIR, exist_ok=True)
GENERATED_PACKETS_FILE = os.path.join(OUTPUT_DIR, "generated_packets.json") # Logged by sensor
VERIFIED_PACKETS_FILE = os.path.join(OUTPUT_DIR, "verified_packets_log.json") # Logged by controller

# --- Simulated Bandwidth ---
# Separate bandwidths for main network and local network
MAIN_SIMULATED_BANDWIDTH_BPS = 100 * 1000 * 1000 # Default 100 Mbps (Sensor -> Controller)
LOCAL_SIMULATED_BANDWIDTH_BPS = 1000 * 1000 * 1000 # Default 1 Gbps (Sensor <-> Local Signers)

def set_main_simulated_bandwidth(bandwidth_mbps: float):
    """Sets the global simulated bandwidth for the main network."""
    global MAIN_SIMULATED_BANDWIDTH_BPS
    # (Same logic as before, but uses MAIN_SIMULATED_BANDWIDTH_BPS)
    if bandwidth_mbps <= 0:
        MAIN_SIMULATED_BANDWIDTH_BPS = 10 * 1000 * 1000 * 1000
        logging.warning(f"Main bandwidth invalid. Defaulting to high.")
    else:
        MAIN_SIMULATED_BANDWIDTH_BPS = bandwidth_mbps * 1000 * 1000
    logging.info(f"Main simulated bandwidth set to: {MAIN_SIMULATED_BANDWIDTH_BPS / 1e6:.2f} Mbps")

def set_local_simulated_bandwidth(bandwidth_mbps: float):
    """Sets the global simulated bandwidth for the local subsystem network."""
    global LOCAL_SIMULATED_BANDWIDTH_BPS
    # (Same logic as before, but uses LOCAL_SIMULATED_BANDWIDTH_BPS)
    if bandwidth_mbps <= 0:
        LOCAL_SIMULATED_BANDWIDTH_BPS = 10 * 1000 * 1000 * 1000
        logging.warning(f"Local bandwidth invalid. Defaulting to high.")
    else:
        LOCAL_SIMULATED_BANDWIDTH_BPS = bandwidth_mbps * 1000 * 1000
    logging.info(f"Local simulated bandwidth set to: {LOCAL_SIMULATED_BANDWIDTH_BPS / 1e6:.2f} Mbps")


def calculate_network_delay(data_size_bytes: int, is_local: bool = False) -> float:
    """Calculates simulated network delay based on global bandwidth."""
    bandwidth_bps = LOCAL_SIMULATED_BANDWIDTH_BPS if is_local else MAIN_SIMULATED_BANDWIDTH_BPS

    if bandwidth_bps <= 0 or data_size_bytes <= 0: return 0.0
    effective_size = data_size_bytes * 1.05 # Protocol overhead
    transmit_delay = (effective_size * 8) / bandwidth_bps
    base_latency = 0.00001 if is_local else 0.0001 # Smaller base latency for local
    total_delay = transmit_delay + base_latency
    return total_delay

# --- Basic Logging Setup ---
def setup_logging(name="Component"):
    # (Same as before)
    log_format = f'[%(asctime)s] [%(levelname)s] [{name}] %(message)s'
    logging.basicConfig(level=LOG_LEVEL, format=log_format, datefmt='%H:%M:%S')
    console_handler = logging.StreamHandler()
    console_handler.setLevel(LOG_LEVEL)
    formatter = logging.Formatter(log_format, datefmt='%H:%M:%S')
    root_logger = logging.getLogger()
    if not any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers):
         root_logger.addHandler(console_handler)
    return logging.getLogger(name)

# --- Network Utilities ---
async def send_json_with_latency(writer: asyncio.StreamWriter, data: dict, is_local: bool = False):
    """Sends JSON data and simulates network latency AFTER sending."""
    # (Same as before, but calls calculate_network_delay with is_local flag)
    message = json.dumps(data) + '\n'
    encoded_message = message.encode('utf-8')
    data_size_bytes = len(encoded_message)
    try:
        writer.write(encoded_message)
        await writer.drain()
        delay = calculate_network_delay(data_size_bytes, is_local=is_local) # Pass flag
        if delay > 0.000001: # Check against smaller threshold for local potentially
            log_level = logging.DEBUG if is_local else logging.DEBUG # Keep DEBUG for both maybe
            bandwidth_used = LOCAL_SIMULATED_BANDWIDTH_BPS if is_local else MAIN_SIMULATED_BANDWIDTH_BPS
            logging.log(log_level, f"Simulating {'local' if is_local else 'main'} network send delay: {delay*1000:.4f} ms for {data_size_bytes} bytes (@ {bandwidth_used / 1e6:.1f} Mbps)")
            await asyncio.sleep(delay)
    except ConnectionResetError:
        logging.error("Connection reset by peer during send.")
        raise
    except Exception as e:
        logging.error(f"Error during send_json_with_latency: {e}")
        raise

async def read_json(reader: asyncio.StreamReader) -> dict | None:
    """Reads newline-terminated JSON data from a StreamReader."""
    # (Same as before)
    try:
        message_bytes = await reader.readline()
        if not message_bytes: return None
        message = message_bytes.decode('utf-8').strip()
        if not message: return None
        return json.loads(message)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logging.error(f"Failed to decode received message: {message_bytes[:100]}... Error: {e}")
        return None
    except ConnectionResetError:
        logging.warning("Connection reset by peer during read.")
        return None
    except asyncio.IncompleteReadError:
        logging.warning("Incomplete read, connection likely closed.")
        return None
    except Exception as e:
        logging.error(f"Unexpected error during read_json: {e}")
        return None

# --- Data Handling ---
def b64_encode_bytes(data: bytes | None) -> str | None:
    # (Same as before)
    return base64.b64encode(data).decode('ascii') if data else None

def b64_decode_to_bytes(data: str | None) -> bytes | None:
    # (Same as before)
    if not data: return None
    try: return base64.b64decode(data)
    except Exception: logging.error(f"Failed to Base64 decode: {data[:30]}..."); return None

def store_json_log(filepath: str, data_to_append: dict):
    # (Same as before)
    os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
    try:
        try:
            with open(filepath, 'r') as f: log_list = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError): log_list = []
        log_list.append(data_to_append)
        with open(filepath, 'w') as f: json.dump(log_list, f, indent=4)
    except IOError as e: logging.error(f"Error writing to {filepath}: {e}")
    except Exception as e: logging.error(f"An unexpected error occurred during JSON logging: {e}")

# --- Packet Splitting Utility ---
# Moved here from original controller as Sensor now needs it
def split_packet(packet_str: str, num_splits: int) -> list[str]:
    """Splits a string into a specified number of non-empty sub-strings at random indices."""
    total_len = len(packet_str)
    if num_splits <= 0:
        logging.warning(f"Cannot split into {num_splits} parts. Returning as 1 part.")
        return [packet_str] if packet_str else []
    if num_splits == 1:
        return [packet_str] if packet_str else []
    if total_len < num_splits:
         logging.warning(f"Packet length ({total_len}) is less than desired splits ({num_splits}). Returning fewer parts.")
         # Split into total_len parts of size 1
         return [packet_str[i:i+1] for i in range(total_len)] if packet_str else []

    # Choose k unique split points (indices) *between* characters
    # We need num_splits - 1 points to get num_splits parts.
    k = num_splits - 1
    # Ensure indices are within the valid range (1 to total_len - 1)
    possible_indices = range(1, total_len)
    indices = sorted(random.sample(possible_indices, k))

    # Create the subpackets
    subpackets = []
    start_idx = 0
    for split_idx in indices:
        subpackets.append(packet_str[start_idx:split_idx])
        start_idx = split_idx
    subpackets.append(packet_str[start_idx:]) # Add the last part

    # Filter out any potentially empty strings if splitting was weird (shouldn't happen with above logic)
    subpackets = [sp for sp in subpackets if sp]
    if len(subpackets) != num_splits:
         logging.debug(f"Splitting resulted in {len(subpackets)} parts instead of desired {num_splits} (Length: {total_len})")

    return subpackets
