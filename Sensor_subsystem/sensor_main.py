# File: sensor_main.py
import asyncio
import json
import time
import random
import argparse
import logging
import os
import uuid
from collections import deque

# Import from common.py
from common import (
    CONTROLLER_IP, CONTROLLER_SENSOR_PORT, LOCAL_IP, SIGNER_BASE_PORT, # Use new ports
    PQC_SIG_ALG, LOG_LEVEL,
    setup_logging, send_json_with_latency, read_json, split_packet, # Need split_packet
    GENERATED_PACKETS_FILE, store_json_log,
    set_main_simulated_bandwidth, set_local_simulated_bandwidth
)

log = None # Will be set in main

# --- Configuration for Variable Packet Sizes ---
MIN_PAYLOAD_SIZE = 50
MAX_PAYLOAD_SIZE = 900

# Ensure output directory exists and clear log file
os.makedirs(os.path.dirname(GENERATED_PACKETS_FILE) or '.', exist_ok=True)
with open(GENERATED_PACKETS_FILE, 'w') as f:
    json.dump([], f)


class SensorCoordinator:
    def __init__(self, name: str, ctrl_host: str, ctrl_port: int, local_signer_ports: list[int]):
        self.name = name # ID of this sensor subsystem
        self.ctrl_host = ctrl_host
        self.ctrl_port = ctrl_port
        self.local_signer_addrs = [(LOCAL_IP, port) for port in local_signer_ports]
        self.log = setup_logging(f"SensorCoord-{self.name}")
        if not self.local_signer_addrs:
             self.log.critical("No local signer ports provided. Cannot operate.")
             raise ValueError("Must provide at least one local signer port.")
        self.log.info(f"Initialized Sensor Coordinator for {len(self.local_signer_addrs)} local signers: {self.local_signer_addrs}")
        # No keys needed for the coordinator itself in this model

    def create_sensor_packet(self, packet_id: int) -> dict:
        # (Same as before, maybe add subsystem ID to packet_id)
        timestamp = time.time()
        payload_size = random.randint(MIN_PAYLOAD_SIZE, MAX_PAYLOAD_SIZE)
        random_payload = os.urandom(payload_size // 2 + (payload_size % 2)).hex()[:payload_size]
        packet = {
            "packet_id": f"{self.name}_P_{packet_id:04d}", # Include sensor subsystem name
            "timestamp": timestamp,
            "sensor_subsystem_id": self.name,
            "sensor_readings": {
                "temperature_c": round(random.uniform(18, 28), 2),
                "pressure_atm": round(random.uniform(0.9, 1.1), 3),
            },
            "status": random.choice(["Nominal", "Warning", "Critical", "Offline"]),
            "payload_data": random_payload
        }
        return packet

    async def request_local_signature(self, job_id: str, subpacket: str, signer_addr: tuple[str, int]) -> dict:
        """Sends a signing request to a local signer and returns the result."""
        host, port = signer_addr
        result = {"job_id": job_id, "signer_addr": f"{host}:{port}", "signer_name": None, "signature_b64": None, "error": "Task initialization failed"}
        reader, writer = None, None
        try:
            self.log.debug(f"Connecting to local signer {host}:{port} for job {job_id}")
            # Short timeout for local connection
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2.0)

            request_payload = {"subpacket": subpacket, "job_id": job_id}
            request = {"command": "SIGN_REQUEST", "payload": request_payload}

            # Use LOCAL latency simulation for request
            await send_json_with_latency(writer, request, is_local=True)
            self.log.debug(f"Sent signing request {job_id} to local signer {host}:{port}")

            # Read response (use longer timeout for signing itself)
            response = await asyncio.wait_for(read_json(reader), timeout=15.0) # Allow time for signing

            if response and response.get("command") == "SIGN_RESULT":
                payload = response.get("payload", {})
                if payload.get("job_id") == job_id:
                    result["signature_b64"] = payload.get("signature_b64")
                    result["signer_name"] = payload.get("signer_name") # <<< Extract signer name
                    result["error"] = payload.get("error")
                    self.log.debug(f"Received result for {job_id} from signer '{result['signer_name']}' @ {host}:{port} (Error: {result['error']})")
                    if result["error"]: result["error"] = f"Local signer '{result['signer_name']}' error: {result['error']}" # Add context
                    if not result["signer_name"]: result["error"] = "Local signer did not return its name." # Add error if name missing
                else:
                    result["error"] = f"Local signer {host}:{port} returned result for wrong job ID: {payload.get('job_id')}"
                    self.log.error(result["error"])
            elif response is None:
                 result["error"] = f"Connection closed by local signer {host}:{port} before result."
                 self.log.error(result["error"])
            else:
                 result["error"] = f"Invalid response from local signer {host}:{port}: {str(response)[:100]}..."
                 self.log.error(result["error"])

        except asyncio.TimeoutError: result["error"] = f"Timeout connecting or getting response from local signer {host}:{port}"; self.log.error(result["error"])
        except ConnectionRefusedError: result["error"] = f"Connection refused by local signer {host}:{port}"; self.log.error(result["error"])
        except Exception as e: result["error"] = f"Communication error with local signer {host}:{port}: {e}"; self.log.exception(f"Error with local signer {host}:{port}:")
        finally:
            if writer:
                writer.close()
                try: await writer.wait_closed()
                except Exception: pass
        return result


    async def run(self, num_packets: int, interval: float, num_splits_per_packet: int):
        """Connects to controller, generates packets, coordinates local signing, sends final package."""
        self.log.info(f"Sensor Coordinator '{self.name}' starting.")
        self.log.info(f"Targeting Controller at {self.ctrl_host}:{self.ctrl_port}")
        ctrl_reader, ctrl_writer = None, None

        if num_splits_per_packet <= 0:
             self.log.error(f"Invalid number of splits requested: {num_splits_per_packet}. Must be > 0.")
             return
        if len(self.local_signer_addrs) == 0:
             self.log.error("No local signers configured. Cannot split or sign.")
             return
        if num_splits_per_packet > len(self.local_signer_addrs):
             self.log.warning(f"Requested {num_splits_per_packet} splits, but only {len(self.local_signer_addrs)} local signers available. Using {len(self.local_signer_addrs)} splits.")
             num_splits_per_packet = len(self.local_signer_addrs)


        try:
            # 1. Connect to Main Controller
            ctrl_reader, ctrl_writer = await asyncio.wait_for(
                asyncio.open_connection(self.ctrl_host, self.ctrl_port), timeout=10.0
            )
            peer = ctrl_writer.get_extra_info('peername')
            self.log.info(f"Connected to main controller at {peer}")
            # No registration needed from sensor in this model (signers register themselves)

            # 2. Generate, Split, Sign Locally, Send Final Package
            for i in range(num_packets):
                # Generate
                packet_data = self.create_sensor_packet(i + 1)
                packet_json_string = json.dumps(packet_data)
                actual_size = len(packet_json_string.encode('utf-8'))
                store_json_log(GENERATED_PACKETS_FILE, packet_data) # Log original
                self.log.info(f"Generated Packet {packet_data['packet_id']} (JSON Size: {actual_size} B)")

                # Split
                subpackets = split_packet(packet_json_string, num_splits_per_packet)
                if not subpackets or len(subpackets) != num_splits_per_packet : # Check if split worked as expected
                     self.log.error(f"Failed to split packet {packet_data['packet_id']} correctly into {num_splits_per_packet} parts (got {len(subpackets)}). Skipping.")
                     continue
                self.log.debug(f"Split packet {packet_data['packet_id']} into {len(subpackets)} parts.")

                # Assign to local signers and request signatures
                tasks = []
                # Track assignment by index to handle results easily
                signer_assignments_by_index = {} # {index: {"job_id": ..., "signer_addr": ...}}
                for idx, subpacket_str in enumerate(subpackets):
                    # Simple round-robin assignment to available local signers
                    signer_addr = self.local_signer_addrs[idx % len(self.local_signer_addrs)]
                    job_id = f"{packet_data['packet_id']}_sub{idx+1}_{uuid.uuid4().hex[:4]}"
                    self.log.debug(f"Assigning job {job_id} (SubP {idx+1}) to local signer {signer_addr[0]}:{signer_addr[1]}")
                    tasks.append(self.request_local_signature(job_id, subpacket_str, signer_addr))
                    signer_assignments_by_index[idx] = {"job_id": job_id, "signer_addr": signer_addr}

                # Gather results from local signers
                t_gather_start = time.monotonic()
                # Results list will correspond to tasks list order (implicitly by index)
                results_list = await asyncio.gather(*tasks, return_exceptions=True)
                t_gather_end = time.monotonic()
                self.log.debug(f"Gathered local signing results for {packet_data['packet_id']} in {t_gather_end-t_gather_start:.4f}s")

                # Process results and package for controller
                final_signatures = [] # Will be ordered by subpacket index
                all_signed_ok = True
                for idx, result in enumerate(results_list):
                    job_id = signer_assignments_by_index[idx]["job_id"] # Get job_id corresponding to this result index
                    signer_addr_str = f"{signer_assignments_by_index[idx]['signer_addr'][0]}:{signer_assignments_by_index[idx]['signer_addr'][1]}"

                    if isinstance(result, Exception):
                        self.log.error(f"Local signing task for job {job_id} failed with exception: {result}")
                        all_signed_ok = False; break
                    elif isinstance(result, dict):
                        if result.get("error"):
                             self.log.error(f"Local signing job {job_id} from {signer_addr_str} failed: {result['error']}")
                             all_signed_ok = False; break
                        elif not result.get("signature_b64"):
                             self.log.error(f"Local signing job {job_id} from {signer_addr_str} succeeded but returned no signature.")
                             all_signed_ok = False; break
                        elif not result.get("signer_name"): # Check if name was returned
                              self.log.error(f"Local signer at {signer_addr_str} did not return its name for job {job_id}.")
                              all_signed_ok = False; break
                        else:
                             # Add result to list, maintaining index order
                             final_signatures.append({
                                 "subpacket_index": idx,
                                 "signer_name": result["signer_name"], # Use the name from the result!
                                 "signature_b64": result["signature_b64"]
                             })
                    else:
                         self.log.error(f"Received unexpected result type for job {job_id}: {type(result)}")
                         all_signed_ok = False; break

                if not all_signed_ok:
                     self.log.error(f"Failed to get all valid signatures locally for {packet_data['packet_id']}. Skipping submission.")
                     continue

                # We already have signatures ordered by index implicitly from gather result order
                # final_signatures.sort(key=lambda x: x["subpacket_index"]) # Not strictly needed if processing in order

                # Send final package to controller
                message_to_send = {
                    "command": "SUBSYSTEM_PACKET_SUBMISSION",
                    "payload": {
                        "packet_id": packet_data['packet_id'],
                        "sensor_subsystem_id": self.name,
                        "original_packet_json": packet_json_string,
                        "subpacket_signatures": final_signatures # List of {index, signer_name, sig} ordered by index
                    }
                }
                # Use MAIN network latency
                await send_json_with_latency(ctrl_writer, message_to_send, is_local=False)
                self.log.info(f"Sent final package for {packet_data['packet_id']} to main controller.")

                if interval > 0:
                    await asyncio.sleep(interval)

            # 3. Send Termination Signal
            self.log.info("Sending termination signal (SENSOR_DONE) to main controller.")
            await send_json_with_latency(ctrl_writer, {"command": "SENSOR_DONE", "payload": {"name": self.name}}, is_local=False)

        except asyncio.TimeoutError:
            self.log.critical(f"Timeout connecting to main controller at {self.ctrl_host}:{self.ctrl_port}. Exiting.")
        except ConnectionRefusedError:
            self.log.critical(f"Main controller at {self.ctrl_host}:{self.ctrl_port} refused connection. Exiting.")
        except Exception as e:
            self.log.critical(f"An error occurred: {e}", exc_info=True)
        finally:
            if ctrl_writer:
                ctrl_writer.close()
                try: await ctrl_writer.wait_closed()
                except Exception: pass
            self.log.info(f"Sensor Coordinator '{self.name}' finished.")


async def main(args):
    global log
    log = setup_logging(f"SensorCoord-{args.name}")
    log.info(f"--- Starting Sensor Coordinator {args.name} ---")
    set_main_simulated_bandwidth(args.bandwidth) # Main network bandwidth
    set_local_simulated_bandwidth(10000) # Assume high local bandwidth default

    # Parse ports
    try:
        signer_ports = [int(p) for p in args.signer_ports]
        if not signer_ports: raise ValueError("No signer ports provided.")
    except Exception as e:
        log.critical(f"Invalid signer ports format: {args.signer_ports}. Error: {e}. Exiting.")
        return

    try:
        coordinator = SensorCoordinator(args.name, args.controller_host, args.controller_port, signer_ports)
        await coordinator.run(num_packets=args.num_packets, interval=args.interval, num_splits_per_packet=args.num_splits)
    except Exception as e:
        log.critical(f"SensorCoordinator initialization or run failed: {e}", exc_info=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sensor Data Coordinator")
    parser.add_argument("--name", required=True, help="Unique ID for this sensor subsystem")
    parser.add_argument("--controller-host", default=CONTROLLER_IP, help="Main Controller host address")
    parser.add_argument("--controller-port", type=int, default=CONTROLLER_SENSOR_PORT, help="Main Controller data submission port")
    parser.add_argument("--signer-ports", required=True, nargs='+', help="Ports of the local signers associated with this sensor (e.g., 6001 6002)")
    parser.add_argument("--num-packets", type=int, default=15, help="Number of packets to generate and process") # Default increased slightly
    parser.add_argument("--interval", type=float, default=0.05, help="Interval between processing packets (seconds)") # Default decreased slightly
    parser.add_argument("--num-splits", type=int, default=3, help="Number of sub-packets to split each packet into (<= number of signers)") # Default matches example run
    parser.add_argument("--bandwidth", type=float, default=100.0, help="Simulated MAIN network bandwidth FROM this sensor subsystem (Mbps)")
    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        # Ensure log exists before using it
        logger = logging.getLogger(f"SensorCoord-{args.name}")
        if logger.hasHandlers(): logger.info(f"Sensor Coordinator {args.name} stopped manually.")
        else: print(f"Sensor Coordinator {args.name} stopped manually.")
    except Exception as e:
        logger = logging.getLogger(f"SensorCoord-{args.name}")
        if logger.hasHandlers(): logger.exception("Sensor Coordinator encountered critical error:")
        else: print(f"Sensor Coordinator critical error: {e}")
