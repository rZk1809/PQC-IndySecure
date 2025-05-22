# File: sensor_main.py
import asyncio
import json
import time
import random
import argparse
import logging
import os
import oqs # Import OQS for signing

# Import from common.py
from common import (
    CONTROLLER_IP, CONTROLLER_PORT, PQC_SIG_ALG, LOG_LEVEL,
    setup_logging, send_json_with_latency, read_json,
    GENERATED_PACKETS_FILE, store_json_log,
    set_simulated_bandwidth,
    b64_encode_bytes, b64_decode_to_bytes # Need encoding
)

log = None # Will be set in main

# --- OQS Verification ---
try:
    oqs.Signature(PQC_SIG_ALG)
except (oqs.MechanismNotSupportedError, AttributeError) as e:
    logging.critical(f"OQS mechanism '{PQC_SIG_ALG}' not supported or OQS invalid: {e}. Exiting.")
    exit(1)
except Exception as e:
    logging.critical(f"Failed to initialize OQS for '{PQC_SIG_ALG}': {e}. Exiting.")
    exit(1)


# --- Configuration for Variable Packet Sizes ---
MIN_PAYLOAD_SIZE = 50   # Minimum bytes for the random payload
MAX_PAYLOAD_SIZE = 900  # Maximum bytes for the random payload

# Ensure output directory exists and clear log file
os.makedirs(os.path.dirname(GENERATED_PACKETS_FILE) or '.', exist_ok=True)
with open(GENERATED_PACKETS_FILE, 'w') as f:
    json.dump([], f)

class SensorSigner:
    def __init__(self, name: str, ctrl_host: str, ctrl_port: int):
        self.name = name
        self.ctrl_host = ctrl_host
        self.ctrl_port = ctrl_port
        self.log = setup_logging(f"Sensor-{self.name}")
        self.algorithm = PQC_SIG_ALG
        self.signer = None
        self.public_key = None
        self.private_key = None
        self.public_key_b64 = None
        self._generate_keys()

    def _generate_keys(self):
        """Generates PQC key pair."""
        try:
            self.log.info(f"Generating PQC key pair ({self.algorithm})...")
            self.signer = oqs.Signature(self.algorithm)
            self.public_key = self.signer.generate_keypair()
            self.private_key = self.signer.export_secret_key() # Keep private key internal
            self.public_key_b64 = b64_encode_bytes(self.public_key)
            self.log.info(f"Key pair generated. Public key size: {len(self.public_key)} bytes.")
        except Exception as e:
            self.log.critical(f"Failed to generate key pair: {e}")
            raise # Propagate exception to stop initialization

    def _sign_data(self, data: bytes) -> bytes | None:
        """Signs data using the private key."""
        if not self.signer or not self.private_key:
            self.log.error("Signer not initialized or private key missing.")
            return None
        try:
            sign_start_time = time.monotonic()
            signature = self.signer.sign(data)
            sign_duration = time.monotonic() - sign_start_time
            self.log.debug(f"PQC Signing took {sign_duration:.4f}s.")
            return signature
        except Exception as e:
            self.log.error(f"Error during signing: {e}")
            return None

    def create_sensor_packet(self, packet_id: int) -> dict:
        """Generates a sensor data packet as a dictionary with variable payload size."""
        timestamp = time.time()
        payload_size = random.randint(MIN_PAYLOAD_SIZE, MAX_PAYLOAD_SIZE)
        random_payload = os.urandom(payload_size // 2 + (payload_size % 2)).hex()[:payload_size]
        packet = {
            "packet_id": f"{self.name}_P_{packet_id:04d}", # Include sensor name
            "timestamp": timestamp,
            "sensor_name": self.name,
            "sensor_readings": {
                "temperature_c": round(random.uniform(18, 28), 2),
                "pressure_atm": round(random.uniform(0.9, 1.1), 3),
            },
            "status": random.choice(["Nominal", "Warning", "Critical", "Offline"]),
            "payload_data": random_payload
        }
        return packet

    async def run(self, num_packets: int, interval: float):
        """Connects, registers, generates/signs packets, and sends them."""
        self.log.info(f"Sensor node '{self.name}' starting. Will generate {num_packets} packets.")
        self.log.info(f"Connecting to controller at {self.ctrl_host}:{self.ctrl_port}")
        reader, writer = None, None
        try:
            # 1. Connect to Controller
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.ctrl_host, self.ctrl_port), timeout=10.0
            )
            peer = writer.get_extra_info('peername')
            self.log.info(f"Connected to controller at {peer}")

            # 2. Register with Controller
            registration_data = {
                "command": "REGISTER_SENSOR_SIGNER",
                "payload": {
                    "name": self.name,
                    "public_key_b64": self.public_key_b64,
                    "algorithm": self.algorithm
                }
            }
            self.log.info("Sending registration info...")
            await send_json_with_latency(writer, registration_data)
            response = await asyncio.wait_for(read_json(reader), timeout=5.0)
            if not response or response.get("status") != "OK":
                self.log.error(f"Registration failed or no valid ACK received: {response}")
                return # Stop if registration fails
            self.log.info("Registration acknowledged by controller.")

            # 3. Generate, Sign, and Send Packets
            for i in range(num_packets):
                # Generate
                packet_data = self.create_sensor_packet(i + 1)
                packet_json_string = json.dumps(packet_data)
                actual_size = len(packet_json_string.encode('utf-8'))
                store_json_log(GENERATED_PACKETS_FILE, packet_data) # Log original packet
                self.log.info(f"Generated Packet {packet_data['packet_id']} (JSON Size: {actual_size} B)")

                # Sign
                signature_bytes = self._sign_data(packet_json_string.encode('utf-8'))
                if signature_bytes is None:
                    self.log.error(f"Failed to sign packet {packet_data['packet_id']}. Skipping.")
                    continue # Skip sending if signing failed

                signature_b64 = b64_encode_bytes(signature_bytes)
                sig_size = len(signature_bytes)
                self.log.debug(f"Packet {packet_data['packet_id']} signed (Signature Size: {sig_size} B)")

                # Send Signed Packet
                message_to_send = {
                    "command": "SIGNED_PACKET_SUBMISSION",
                    "payload": {
                        "packet_id": packet_data['packet_id'],
                        "original_packet_json": packet_json_string, # Send original as string
                        "signature_b64": signature_b64
                    }
                }
                await send_json_with_latency(writer, message_to_send)
                self.log.debug(f"Signed packet {packet_data['packet_id']} sent to controller.")

                if interval > 0:
                    await asyncio.sleep(interval)

            # 4. Send Termination Signal
            self.log.info("Sending termination signal (SENSOR_DONE) to controller.")
            await send_json_with_latency(writer, {"command": "SENSOR_DONE", "payload": {"name": self.name}})

        except asyncio.TimeoutError:
            self.log.critical(f"Connection or communication timeout with controller at {self.ctrl_host}:{self.ctrl_port}. Exiting.")
        except ConnectionRefusedError:
            self.log.critical(f"Controller at {self.ctrl_host}:{self.ctrl_port} refused connection. Is it running? Exiting.")
        except Exception as e:
            self.log.critical(f"An error occurred: {e}", exc_info=True)
        finally:
            if writer:
                writer.close()
                try: await writer.wait_closed()
                except Exception: pass
            self.log.info(f"Sensor node '{self.name}' finished and connection closed.")


async def main(args):
    global log
    # Setup logging specific to this sensor instance name
    log = setup_logging(f"Sensor-{args.name}")
    log.info(f"--- Starting Sensor-Signer {args.name} ---")
    set_simulated_bandwidth(args.bandwidth)

    try:
        sensor_signer = SensorSigner(args.name, args.controller_host, args.controller_port)
        await sensor_signer.run(num_packets=args.num_packets, interval=args.interval)
    except Exception as e:
        log.critical(f"SensorSigner initialization or run failed: {e}", exc_info=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sensor Data Generator and Signer")
    parser.add_argument("--name", required=True, help="Unique name for this sensor instance")
    parser.add_argument("--controller-host", default=CONTROLLER_IP, help="Controller host address")
    parser.add_argument("--controller-port", type=int, default=CONTROLLER_PORT, help="Controller listening port")
    parser.add_argument("--num-packets", type=int, default=10, help="Number of packets to generate and send")
    parser.add_argument("--interval", type=float, default=0.1, help="Interval between sending packets (seconds)")
    parser.add_argument("--bandwidth", type=float, default=10.0, help="Simulated network bandwidth FROM this sensor (Mbps)")
    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        if log: log.info(f"Sensor {args.name} stopped manually.")
        else: print(f"Sensor {args.name} stopped manually.")
    except Exception as e:
        if log: log.exception("Sensor encountered critical error:")
        else: print(f"Sensor critical error: {e}")
