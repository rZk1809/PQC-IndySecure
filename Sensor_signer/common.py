# File: common.py
import asyncio
import json
import logging
import base64
import os
import time # Added for analyzer timestamping

# --- Configuration ---
CONTROLLER_IP = '127.0.0.1' # Localhost
CONTROLLER_PORT = 5004 # Single port for registration and data
PQC_SIG_ALG = "ML-DSA-44" # Using NIST standard name
LOG_LEVEL = logging.INFO # Change to logging.DEBUG for more detail

# --- Output Directory ---
OUTPUT_DIR = "simulation_data_sensor_signer" # New directory for this version
os.makedirs(OUTPUT_DIR, exist_ok=True)
GENERATED_PACKETS_FILE = os.path.join(OUTPUT_DIR, "generated_packets.json")
# SIGNED_PACKETS_FILE is removed as signing happens within the sensor
VERIFIED_PACKETS_FILE = os.path.join(OUTPUT_DIR, "verified_packets_log.json")

# --- Simulated Bandwidth (Set by main scripts via set_simulated_bandwidth) ---
SIMULATED_BANDWIDTH_BPS = 100 * 1000 * 1000 # Default to 100 Mbps

def set_simulated_bandwidth(bandwidth_mbps: float):
    """Sets the global simulated bandwidth."""
    global SIMULATED_BANDWIDTH_BPS
    if bandwidth_mbps <= 0:
        SIMULATED_BANDWIDTH_BPS = 10 * 1000 * 1000 * 1000 # Effectively disable latency
        logging.warning(f"Invalid bandwidth {bandwidth_mbps} Mbps. Defaulting to high bandwidth (latency effectively disabled).")
    else:
        SIMULATED_BANDWIDTH_BPS = bandwidth_mbps * 1000 * 1000 # Convert Mbps to bps
        logging.info(f"Simulated bandwidth set to: {SIMULATED_BANDWIDTH_BPS / 1e6:.2f} Mbps")

def calculate_network_delay(data_size_bytes: int) -> float:
    """Calculates simulated network delay based on global bandwidth."""
    if SIMULATED_BANDWIDTH_BPS <= 0 or data_size_bytes <= 0:
        return 0.0
    effective_size = data_size_bytes * 1.05 # Simplistic protocol overhead
    transmit_delay = (effective_size * 8) / SIMULATED_BANDWIDTH_BPS
    base_latency = 0.0001 # Small base latency
    total_delay = transmit_delay + base_latency
    return total_delay

# --- Basic Logging Setup ---
def setup_logging(name="Component"):
    log_format = f'[%(asctime)s] [%(levelname)s] [{name}] %(message)s'
    logging.basicConfig(level=LOG_LEVEL, format=log_format, datefmt='%H:%M:%S')
    # Ensure logs also go to console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(LOG_LEVEL)
    formatter = logging.Formatter(log_format, datefmt='%H:%M:%S')
    console_handler.setFormatter(formatter)
    # Avoid adding handler if it already exists (useful if called multiple times)
    root_logger = logging.getLogger()
    if not any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers):
         root_logger.addHandler(console_handler)

    return logging.getLogger(name)


# --- Network Utilities ---
async def send_json_with_latency(writer: asyncio.StreamWriter, data: dict):
    """Sends JSON data and simulates network latency AFTER sending."""
    message = json.dumps(data) + '\n'
    encoded_message = message.encode('utf-8')
    data_size_bytes = len(encoded_message)
    try:
        writer.write(encoded_message)
        await writer.drain()
        delay = calculate_network_delay(data_size_bytes)
        if delay > 0.00001:
            logging.debug(f"Simulating network send delay: {delay*1000:.3f} ms for {data_size_bytes} bytes (@ {SIMULATED_BANDWIDTH_BPS / 1e6:.1f} Mbps)")
            await asyncio.sleep(delay)
    except ConnectionResetError:
        logging.error("Connection reset by peer during send.")
        raise
    except Exception as e:
        logging.error(f"Error during send_json_with_latency: {e}")
        raise

async def read_json(reader: asyncio.StreamReader) -> dict | None:
    """Reads newline-terminated JSON data from a StreamReader."""
    try:
        message_bytes = await reader.readline()
        if not message_bytes:
            return None # Connection closed
        message = message_bytes.decode('utf-8').strip()
        if not message:
            return None # Empty line
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
    """Safely Base64 encode bytes, returning None if input is None."""
    return base64.b64encode(data).decode('ascii') if data else None

def b64_decode_to_bytes(data: str | None) -> bytes | None:
    """Safely Base64 decode string, returning None if input is None or invalid."""
    if not data: return None
    try:
        return base64.b64decode(data)
    except Exception:
        logging.error(f"Failed to Base64 decode: {data[:30]}...")
        return None

def store_json_log(filepath: str, data_to_append: dict):
    """Appends a dictionary entry to a JSON log file."""
    # Ensure directory exists
    os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
    try:
        try:
            with open(filepath, 'r') as f:
                log_list = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            log_list = [] # Start new list if file missing or empty/corrupt

        log_list.append(data_to_append)

        with open(filepath, 'w') as f:
            json.dump(log_list, f, indent=4) # Use indent for readability
    except IOError as e:
        logging.error(f"Error writing to {filepath}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during JSON logging: {e}")
