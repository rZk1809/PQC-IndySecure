# File: controller_main.py
import asyncio
import json
import time
import oqs # Still needed for verification
import logging
import argparse
import statistics
import os

# Import from common.py
from common import (
    PQC_SIG_ALG, CONTROLLER_IP, CONTROLLER_PORT, LOG_LEVEL,
    VERIFIED_PACKETS_FILE, OUTPUT_DIR,
    setup_logging, send_json_with_latency, read_json,
    b64_encode_bytes, b64_decode_to_bytes,
    store_json_log,
    set_simulated_bandwidth
)

log = setup_logging("Controller")

# --- OQS Verification Setup ---
try:
    oqs.Signature(PQC_SIG_ALG) # Check if the default alg is supported
except (oqs.MechanismNotSupportedError, AttributeError) as e:
    log.critical(f"OQS mechanism '{PQC_SIG_ALG}' not supported or OQS invalid: {e}. Exiting.")
    exit(1)
except Exception as e:
    log.critical(f"Failed to initialize OQS for '{PQC_SIG_ALG}': {e}. Exiting.")
    exit(1)

# Stores registered public keys: { sensor_name: { "public_key": bytes, "algorithm": str } }
sensor_public_keys = {}
sensor_keys_lock = asyncio.Lock()
active_sensors = {} # Track active connections {writer: sensor_name}
controller_shutdown_event = asyncio.Event()

# Statistics
total_packets_received = 0
total_packets_verified = 0
total_packets_failed = 0
verification_latencies = []

# --- Verification Function ---
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

# --- Connection Handler ---
async def handle_sensor_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    global total_packets_received, total_packets_verified, total_packets_failed, verification_latencies

    addr = writer.get_extra_info('peername')
    log.info(f"Incoming connection from {addr}")
    sensor_name = None
    registered = False
    connection_active = True

    try:
        while connection_active:
            request_data = await read_json(reader)
            if request_data is None:
                log.warning(f"Connection from {addr} (Sensor: {sensor_name or 'Unknown'}) closed.")
                connection_active = False
                break

            command = request_data.get("command")
            payload = request_data.get("payload")

            if not registered:
                # Expect registration first
                if command == "REGISTER_SENSOR_SIGNER" and payload:
                    name = payload.get("name")
                    pk_b64 = payload.get("public_key_b64")
                    alg = payload.get("algorithm", PQC_SIG_ALG) # Use provided or default

                    if name and pk_b64:
                        pk_bytes = b64_decode_to_bytes(pk_b64)
                        if pk_bytes:
                            # Verify OQS supports the algorithm the sensor claims to use
                            try:
                                oqs.Signature(alg)
                            except Exception as e:
                                log.error(f"Sensor '{name}' registration failed: Unsupported algorithm '{alg}': {e}")
                                ack = {"status": "ERROR", "message": f"Algorithm {alg} not supported by controller"}
                                await send_json_with_latency(writer, ack)
                                connection_active = False; break

                            async with sensor_keys_lock:
                                if name in sensor_public_keys:
                                    log.warning(f"Sensor '{name}' re-registering. Updating public key.")
                                sensor_public_keys[name] = {"public_key": pk_bytes, "algorithm": alg}
                                sensor_name = name
                                active_sensors[writer] = name # Track connection
                                registered = True
                            log.info(f"Registered Sensor-Signer: {name} from {addr} using {alg}")
                            ack = {"status": "OK", "message": f"Registered {name}"}
                            await send_json_with_latency(writer, ack)
                        else:
                            log.error(f"Registration failed for '{name}': Invalid Base64 public key.")
                            ack = {"status": "ERROR", "message": "Invalid public key format"}
                            await send_json_with_latency(writer, ack)
                            connection_active = False; break
                    else:
                        log.error(f"Registration failed from {addr}: Missing name or public_key_b64.")
                        ack = {"status": "ERROR", "message": "Missing fields in registration payload"}
                        await send_json_with_latency(writer, ack)
                        connection_active = False; break
                else:
                    log.warning(f"Expected REGISTER_SENSOR_SIGNER command first from {addr}, got '{command}'. Closing.")
                    connection_active = False; break

            # Process subsequent commands after registration
            elif command == "SIGNED_PACKET_SUBMISSION" and payload:
                packet_id = payload.get("packet_id", f"{sensor_name}_Unknown_{total_packets_received+1}")
                log.debug(f"Received signed packet {packet_id} from {sensor_name}")
                total_packets_received += 1

                original_packet_json = payload.get("original_packet_json")
                signature_b64 = payload.get("signature_b64")

                verification_status = "Verification Failed - Missing Data"
                is_valid = False
                t_verify_start = 0.0
                verify_latency = 0.0

                if original_packet_json and signature_b64:
                    sig_bytes = b64_decode_to_bytes(signature_b64)
                    async with sensor_keys_lock: # Ensure key exists if sensor disconnects during verify
                        sensor_info = sensor_public_keys.get(sensor_name)

                    if sensor_info and sig_bytes:
                        public_key = sensor_info["public_key"]
                        algorithm = sensor_info["algorithm"]
                        message_bytes = original_packet_json.encode('utf-8')

                        t_verify_start = time.monotonic()
                        is_valid = verify_pqc_signature(message_bytes, sig_bytes, public_key, algorithm)
                        verify_latency = time.monotonic() - t_verify_start
                        verification_latencies.append(verify_latency)

                        if is_valid:
                            log.info(f"Verification SUCCESS for packet {packet_id} from {sensor_name} (Latency: {verify_latency:.6f}s)")
                            total_packets_verified += 1
                            verification_status = "Success"
                        else:
                            log.error(f"Verification FAILED for packet {packet_id} from {sensor_name}: Invalid signature.")
                            total_packets_failed += 1
                            verification_status = "Verification Failed - Invalid Signature"
                    elif not sensor_info:
                        log.error(f"Verification FAILED for packet {packet_id}: Public key for {sensor_name} not found (disconnected?).")
                        total_packets_failed += 1
                        verification_status = "Verification Failed - Public Key Not Found"
                    else: # sig_bytes is None
                         log.error(f"Verification FAILED for packet {packet_id} from {sensor_name}: Invalid Base64 signature.")
                         total_packets_failed += 1
                         verification_status = "Verification Failed - Invalid Signature Encoding"
                else:
                     log.error(f"Verification FAILED for packet {packet_id} from {sensor_name}: Missing original packet or signature in payload.")
                     total_packets_failed += 1

                # Log verification result
                log_entry = {
                    "packet_id": packet_id,
                    "sensor_name": sensor_name,
                    "verification_status": verification_status,
                    "controller_verification_latency_sec": round(verify_latency, 6) if is_valid else None,
                    "original_packet_preview": original_packet_json[:100]+"..." if not is_valid else None,
                    "timestamp": time.time()
                }
                store_json_log(VERIFIED_PACKETS_FILE, log_entry)

            elif command == "SENSOR_DONE" and payload:
                done_sensor_name = payload.get("name")
                log.info(f"Received SENSOR_DONE signal from {done_sensor_name} at {addr}.")
                connection_active = False # End loop for this sensor
                # Potentially signal main thread if this was the last expected sensor
                # For simplicity, we'll just let main run until Ctrl+C or manual stop
                # If running only one sensor, uncomment next line:
                # controller_shutdown_event.set()
                break # Exit loop

            else:
                log.warning(f"Received unknown or unexpected command '{command}' from {sensor_name}. Ignoring.")

    except ConnectionResetError:
        log.warning(f"Connection reset by peer {addr} (Sensor: {sensor_name or 'Unknown'})")
    except asyncio.IncompleteReadError:
        log.warning(f"Incomplete read from {addr} (Sensor: {sensor_name or 'Unknown'}), connection likely closed.")
    except Exception as e:
        log.error(f"Error handling connection from {addr} (Sensor: {sensor_name or 'Unknown'}): {e}", exc_info=True)
    finally:
        log.info(f"Closing connection from {addr} (Sensor: {sensor_name or 'Unknown'})")
        if writer in active_sensors:
            del active_sensors[writer]
        # Optionally remove sensor key on disconnect? Or keep it for potential reconnect?
        # Keeping it for now.
        # async with sensor_keys_lock:
        #    if sensor_name and sensor_name in sensor_public_keys:
        #        del sensor_public_keys[sensor_name]
        #        log.info(f"Removed public key for disconnected sensor {sensor_name}")
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def start_server(host, port):
    server = await asyncio.start_server(handle_sensor_connection, host, port)
    addr = server.sockets[0].getsockname()
    log.info(f'Controller listening on {addr}')
    return server


async def main(args):
    set_simulated_bandwidth(args.bandwidth)
    # Clear previous verification log
    os.makedirs(os.path.dirname(VERIFIED_PACKETS_FILE) or '.', exist_ok=True)
    with open(VERIFIED_PACKETS_FILE, 'w') as f: json.dump([], f)
    log.info(f"Initialized log files in {OUTPUT_DIR}")

    server = await start_server(args.host, args.port)

    async with server:
        # await controller_shutdown_event.wait() # Uncomment if using event for shutdown
        await server.serve_forever() # Runs until cancelled (e.g., Ctrl+C)

    log.info("Controller server stopped.")

    # --- Final Summary ---
    log.info("--- Controller Verification Summary ---")
    log.info(f"Simulated Bandwidth (Controller Perspective): {args.bandwidth:.2f} Mbps")
    log.info(f"Total Signed Packets Received: {total_packets_received}")
    log.info(f"Successfully Verified:         {total_packets_verified}")
    log.info(f"Failed Verification:           {total_packets_failed}")

    if verification_latencies:
        try:
            avg_latency = statistics.mean(verification_latencies)
            median_latency = statistics.median(verification_latencies)
            min_latency = min(verification_latencies)
            max_latency = max(verification_latencies)
            stdev_latency = statistics.stdev(verification_latencies) if len(verification_latencies) > 1 else 0.0
            log.info(f"Signature Verification Latency (Controller Only):")
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
    parser = argparse.ArgumentParser(description="PQC Controller (Verifier)")
    parser.add_argument("--host", default=CONTROLLER_IP, help="Host address for controller server")
    parser.add_argument("--port", type=int, default=CONTROLLER_PORT, help="Port for controller server")
    parser.add_argument("--bandwidth", type=float, default=1000.0, help="Simulated network bandwidth TO this controller (Mbps)")
    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        log.info("Controller stopped manually.")
    except Exception as e:
        log.exception("Controller encountered critical error:")
