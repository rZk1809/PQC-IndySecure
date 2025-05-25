# File: controller_main.py
import asyncio
import json
import time
import oqs
import logging
import argparse
import statistics
import os
from collections import defaultdict

# Import from common.py
from common import (
    PQC_SIG_ALG, CONTROLLER_IP,
    CONTROLLER_REGISTRATION_PORT, CONTROLLER_SENSOR_PORT, # Using both ports now
    LOG_LEVEL, VERIFIED_PACKETS_FILE, OUTPUT_DIR,
    setup_logging, send_json_with_latency, read_json, split_packet, # Need split_packet
    b64_encode_bytes, b64_decode_to_bytes,
    store_json_log,
    set_main_simulated_bandwidth # Controller mainly experiences main bandwidth
)

log = setup_logging("Controller")

# --- OQS Verification Setup ---
try:
    oqs.Signature(PQC_SIG_ALG)
except Exception as e:
    log.critical(f"OQS mechanism '{PQC_SIG_ALG}' error: {e}. Exiting.")
    exit(1)

# Stores registered signers: { subsystem_id: { signer_name: { "public_key": bytes, "algorithm": str } } }
registered_signers = defaultdict(dict)
signer_keys_lock = asyncio.Lock()
active_sensors_writers = {} # Track sensor connections {writer: subsystem_id}
controller_shutdown_event = asyncio.Event()

# Statistics
total_packets_received = 0
total_packets_verified = 0
total_packets_failed = 0
verification_latencies = [] # Latency for verifying ALL sub-signatures for a packet

# --- Verification Function ---
# (Same as previous controller version)
def verify_pqc_signature(message: bytes, signature: bytes, public_key: bytes, algorithm: str) -> bool:
    if not public_key or not signature or not message:
        log.warning("Verification failed: Missing message, signature, or public key.")
        return False
    try:
        verifier = oqs.Signature(algorithm)
        return verifier.verify(message, signature, public_key)
    except oqs.MechanismNotSupportedError:
        log.error(f"Verification failed: Algorithm '{algorithm}' not supported by OQS.")
        return False
    except Exception as e:
        log.error(f"Error during signature verification: {e}")
        return False

# --- Registration Handler (for Signers) ---
async def handle_registration(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info('peername')
    log.info(f"Signer registration connection from {addr}")
    ack = {"status": "ERROR", "message": "Invalid registration data"}
    registered_name = None
    try:
        registration_data = await read_json(reader)
        if registration_data and registration_data.get("command") == "REGISTER_SIGNER":
            payload = registration_data.get("payload")
            # Check for required fields including sensor_subsystem_id
            if payload and all(k in payload for k in ["name", "public_key_b64", "sensor_subsystem_id"]):
                name = payload["name"]
                pk_b64 = payload["public_key_b64"]
                subsystem_id = payload["sensor_subsystem_id"]
                alg = payload.get("algorithm", PQC_SIG_ALG)
                pk_bytes = b64_decode_to_bytes(pk_b64)

                if pk_bytes:
                    # Verify OQS supports the algorithm
                    try: oqs.Signature(alg)
                    except Exception as e:
                        log.error(f"Signer '{name}' registration failed: Unsupported algorithm '{alg}': {e}")
                        ack = {"status": "ERROR", "message": f"Algorithm {alg} not supported"}
                    else:
                        async with signer_keys_lock:
                             # Use defaultdict structure: registered_signers[subsystem_id][name] = info
                            registered_signers[subsystem_id][name] = {"public_key": pk_bytes, "algorithm": alg}
                        registered_name = f"{name}@{subsystem_id}"
                        log.info(f"Registered signer: {name} for subsystem {subsystem_id} using {alg}")
                        ack = {"status": "OK", "message": f"Registered {name} for {subsystem_id}"}
                else:
                    ack["message"] = f"Invalid public key format for {name}"
            else:
                ack["message"] = "Missing fields in registration payload (name, public_key_b64, sensor_subsystem_id required)"
        else:
             log.warning(f"Received invalid registration command/data from {addr}")

        # Use main BW for ACK back to signer
        await send_json_with_latency(writer, ack, is_local=False)

    except Exception as e:
         log.error(f"Error during registration from {addr}: {e}", exc_info=True)
         try: # Try sending error back
              ack = {"status": "ERROR", "message": f"Server error during registration: {e}"}
              await send_json_with_latency(writer, ack, is_local=False)
         except: pass # Ignore if can't send error
    finally:
        log.info(f"Closing registration connection from {addr} (Signer: {registered_name or 'Unknown'})")
        writer.close()
        try:
            await writer.wait_closed()
        except Exception: pass


# --- Sensor Data Handler ---
async def handle_sensor_data(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    global total_packets_received, total_packets_verified, total_packets_failed, verification_latencies

    addr = writer.get_extra_info('peername')
    log.info(f"Sensor subsystem connection from {addr}")
    subsystem_id = None
    connection_active = True

    try:
        while connection_active:
            # Use MAIN network bandwidth simulation context for reads from sensor subsystem
            # (read_json itself doesn't simulate latency, it's assumed receiver-side)
            request_data = await read_json(reader)
            if request_data is None:
                log.warning(f"Connection from {addr} (Subsystem: {subsystem_id or 'Unknown'}) closed.")
                connection_active = False; break

            command = request_data.get("command")
            payload = request_data.get("payload")

            if command == "SUBSYSTEM_PACKET_SUBMISSION" and payload:
                packet_id = payload.get("packet_id", f"Unknown_{total_packets_received+1}")
                received_subsystem_id = payload.get("sensor_subsystem_id")
                original_packet_json = payload.get("original_packet_json")
                # Expecting list of {"subpacket_index": idx, "signer_name": name, "signature_b64": sig}
                subpacket_signatures = payload.get("subpacket_signatures")

                # Identify subsystem on first valid packet
                if not subsystem_id and received_subsystem_id:
                     subsystem_id = received_subsystem_id
                     active_sensors_writers[writer] = subsystem_id
                     log.info(f"Identified connection from {addr} as Sensor Subsystem '{subsystem_id}'")
                elif received_subsystem_id != subsystem_id:
                     log.error(f"Subsystem ID mismatch! Expected '{subsystem_id}', got '{received_subsystem_id}' from {addr}. Closing.")
                     connection_active = False; break

                # Basic validation of received payload structure
                if not subsystem_id or not original_packet_json or not isinstance(subpacket_signatures, list):
                    log.error(f"Invalid SUBSYSTEM_PACKET_SUBMISSION received from {subsystem_id or addr}. Missing/invalid fields.")
                    total_packets_failed += 1
                    continue # Skip processing this invalid packet

                log.debug(f"Received packet {packet_id} from subsystem {subsystem_id}")
                total_packets_received += 1

                # --- Verification Logic ---
                t_verify_start = time.monotonic()
                verification_status = "Verification Failed" # Default
                all_verified = False
                num_subpackets = len(subpacket_signatures)

                if num_subpackets == 0:
                     log.error(f"Packet {packet_id} from {subsystem_id} has no signatures.")
                     total_packets_failed += 1
                     verification_status = "Verification Failed - No Signatures"
                else:
                    # Re-split the original packet deterministically using the common function
                    recreated_subpackets = split_packet(original_packet_json, num_subpackets)

                    if len(recreated_subpackets) != num_subpackets:
                        log.error(f"Packet {packet_id}: Controller split ({len(recreated_subpackets)}) mismatch with received signatures ({num_subpackets}). Cannot verify.")
                        total_packets_failed += 1
                        verification_status = "Verification Failed - Split Mismatch"
                    else:
                        all_verified = True # Assume success unless one fails
                        async with signer_keys_lock:
                            # Get the dictionary of {signer_name: key_info} for this subsystem
                            subsystem_keys = registered_signers.get(subsystem_id, {})

                        if not subsystem_keys:
                            log.error(f"Packet {packet_id}: No registered signers found for subsystem '{subsystem_id}'.")
                            all_verified = False
                            verification_status = "Verification Failed - Subsystem Unknown"
                        else:
                            # Verify each sub-signature
                            for i in range(num_subpackets):
                                # Assume subpacket_signatures list is ordered by index 0 to N-1
                                sig_info = subpacket_signatures[i]
                                # *** Use the signer_name provided by the sensor coordinator ***
                                signer_name = sig_info.get("signer_name")
                                signature_b64 = sig_info.get("signature_b64")
                                subpacket_content = recreated_subpackets[i]

                                # Check if necessary info is present
                                if not signer_name:
                                    log.error(f"Packet {packet_id} SubP {i+1}: Signer name missing in payload from sensor subsystem '{subsystem_id}'.")
                                    all_verified = False; verification_status = "Verification Failed - Signer Name Missing"; break
                                if not signature_b64:
                                     log.error(f"Packet {packet_id} SubP {i+1}: Signature missing for signer '{signer_name}'.")
                                     all_verified = False; verification_status = "Verification Failed - Signature Missing"; break

                                sig_bytes = b64_decode_to_bytes(signature_b64)
                                # Look up the specific signer's key within the subsystem's dictionary
                                signer_key_info = subsystem_keys.get(signer_name)

                                if not signer_key_info:
                                    log.error(f"Packet {packet_id} SubP {i+1}: Signer '{signer_name}' not registered for subsystem '{subsystem_id}'.")
                                    all_verified = False; verification_status = "Verification Failed - Signer Unknown"; break
                                if not sig_bytes:
                                    log.error(f"Packet {packet_id} SubP {i+1}: Invalid signature encoding from signer '{signer_name}'.")
                                    all_verified = False; verification_status = "Verification Failed - Invalid Signature Encoding"; break

                                public_key = signer_key_info["public_key"]
                                algorithm = signer_key_info["algorithm"]
                                message_bytes = subpacket_content.encode('utf-8')

                                # Perform the actual verification
                                if not verify_pqc_signature(message_bytes, sig_bytes, public_key, algorithm):
                                    log.error(f"Packet {packet_id} SubP {i+1}: Invalid signature from signer '{signer_name}'.")
                                    all_verified = False; verification_status = "Verification Failed - Invalid Signature"; break
                                else:
                                    log.debug(f"Packet {packet_id} SubP {i+1}: Signature from '{signer_name}' verified.")

                        # After checking all sub-signatures
                        if all_verified:
                            log.info(f"Verification SUCCESS for packet {packet_id} from subsystem {subsystem_id}")
                            total_packets_verified += 1
                            verification_status = "Success"
                        else:
                            # Failed status already set inside loop or by earlier checks
                            total_packets_failed += 1

                t_verify_end = time.monotonic()
                verify_latency = t_verify_end - t_verify_start
                # Log latency only if verification was attempted and succeeded
                if all_verified : verification_latencies.append(verify_latency)
                log.debug(f"Packet {packet_id} verification processing took {verify_latency:.6f}s")

                # Log overall result for the packet
                log_entry = {
                    "packet_id": packet_id,
                    "sensor_subsystem_id": subsystem_id,
                    "num_subpackets": num_subpackets,
                    "verification_status": verification_status,
                    # Log latency for successful verifications, None otherwise
                    "controller_verification_latency_sec": round(verify_latency, 6) if all_verified else None,
                    "original_packet_preview": original_packet_json[:100]+"..." if not all_verified else None,
                    "timestamp": time.time()
                }
                store_json_log(VERIFIED_PACKETS_FILE, log_entry)


            elif command == "SENSOR_DONE" and payload:
                done_subsystem_id = payload.get("name")
                log.info(f"Received SENSOR_DONE signal from subsystem {done_subsystem_id} at {addr}.")
                # Set the subsystem_id if it wasn't set by a data packet (e.g., sensor sends 0 packets)
                if not subsystem_id: subsystem_id = done_subsystem_id
                connection_active = False
                # If expecting only one sensor, could trigger shutdown here:
                # controller_shutdown_event.set()
                break
            else:
                log.warning(f"Received unknown command '{command}' from {subsystem_id or addr}. Ignoring.")

    except ConnectionResetError: log.warning(f"Connection reset by peer {addr} (Subsystem: {subsystem_id or 'Unknown'})")
    except asyncio.IncompleteReadError: log.warning(f"Incomplete read from {addr} (Subsystem: {subsystem_id or 'Unknown'}), connection likely closed.")
    except Exception as e: log.error(f"Error handling connection from {addr} (Subsystem: {subsystem_id or 'Unknown'}): {e}", exc_info=True)
    finally:
        log.info(f"Closing connection from {addr} (Subsystem: {subsystem_id or 'Unknown'})")
        if writer in active_sensors_writers: del active_sensors_writers[writer]
        writer.close()
        try:
            await writer.wait_closed()
        except Exception: pass

async def main(args):
    set_main_simulated_bandwidth(args.bandwidth) # Controller uses main bandwidth setting
    os.makedirs(os.path.dirname(VERIFIED_PACKETS_FILE) or '.', exist_ok=True)
    with open(VERIFIED_PACKETS_FILE, 'w') as f: json.dump([], f)
    log.info(f"Initialized log files in {OUTPUT_DIR}")

    # Start servers for registration and sensor data
    try:
        registration_server = await asyncio.start_server(
            handle_registration, args.host, args.registration_port)
        sensor_data_server = await asyncio.start_server(
            handle_sensor_data, args.host, args.sensor_port)
    except OSError as e:
         log.critical(f"Failed to start server(s): {e}. Check if ports are already in use.")
         return
    except Exception as e:
         log.critical(f"Failed to start server(s): {e}")
         return


    reg_addr = registration_server.sockets[0].getsockname()
    sensor_addr = sensor_data_server.sockets[0].getsockname()
    log.info(f'Signer registration listening on {reg_addr}')
    log.info(f'Sensor data listening on {sensor_addr}')

    servers = [registration_server, sensor_data_server]

    # Keep servers running
    server_tasks = [asyncio.create_task(s.serve_forever()) for s in servers]
    log.info("Controller servers started. Press Ctrl+C to stop.")

    # Wait for tasks to complete (will only happen on cancellation/error)
    done, pending = await asyncio.wait(server_tasks, return_when=asyncio.FIRST_COMPLETED)

    # If a server task finishes unexpectedly, log it and cancel others
    for task in done:
        try:
            await task # Raise exception if server crashed
        except asyncio.CancelledError:
            pass # Expected on clean shutdown
        except Exception as e:
            log.error(f"A server task exited unexpectedly: {e}", exc_info=True)

    log.info("Attempting clean shutdown...")
    for task in pending: task.cancel() # Cancel remaining server tasks
    for server in servers: server.close(); await server.wait_closed() # Close server sockets
    await asyncio.gather(*pending, return_exceptions=True) # Wait for pending tasks to finish cancelling

    log.info("Controller servers stopped.")


    # --- Final Summary ---
    log.info("--- Controller Verification Summary ---")
    log.info(f"Simulated Bandwidth (Controller Perspective): {args.bandwidth:.2f} Mbps")
    log.info(f"Total Subsystem Packets Received: {total_packets_received}")
    log.info(f"Successfully Verified (All SubSigs): {total_packets_verified}")
    log.info(f"Failed Verification:                {total_packets_failed}")

    if verification_latencies:
        try: # Copied stats calculation block
            avg_latency = statistics.mean(verification_latencies)
            median_latency = statistics.median(verification_latencies)
            min_latency = min(verification_latencies)
            max_latency = max(verification_latencies)
            stdev_latency = statistics.stdev(verification_latencies) if len(verification_latencies) > 1 else 0.0
            log.info(f"Packet Verification Latency (Controller - All SubSigs):")
            log.info(f"  Avg:    {avg_latency:.6f} s")
            log.info(f"  Median: {median_latency:.6f} s")
            log.info(f"  StDev:  {stdev_latency:.6f} s")
            log.info(f"  Min:    {min_latency:.6f} s")
            log.info(f"  Max:    {max_latency:.6f} s")
        except statistics.StatisticsError as e: log.error(f"Could not calculate verification latency statistics: {e}")
        except Exception as e: log.error(f"Unexpected error calculating verification latency stats: {e}")
    else: log.info("Verification Latency: No packets verified.")
    log.info(f"-----------------------------------")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PQC Controller (Subsystem Verifier)")
    parser.add_argument("--host", default=CONTROLLER_IP, help="Host address for controller server")
    parser.add_argument("--registration-port", type=int, default=CONTROLLER_REGISTRATION_PORT, help="Port for signer registration")
    parser.add_argument("--sensor-port", type=int, default=CONTROLLER_SENSOR_PORT, help="Port for sensor data submission")
    parser.add_argument("--bandwidth", type=float, default=100.0, help="Simulated network bandwidth TO this controller (Mbps)") # Corrected default
    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        log.info("Controller stopped manually.")
    except Exception as e:
        # Ensure log exists if error happens early
        logger = logging.getLogger("Controller")
        if logger.hasHandlers(): logger.exception("Controller encountered critical error:")
        else: print(f"Controller critical error: {e}")
