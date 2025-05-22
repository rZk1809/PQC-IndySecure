# File: signer_main.py
import asyncio
import argparse
import time
import oqs
import logging
import base64 # Explicitly import base64 although b64 utils are used

# Import from common.py - NOTE the change here
from common import (
    PQC_SIG_ALG, CONTROLLER_IP, CONTROLLER_REGISTRATION_PORT,
    setup_logging, send_json_with_latency, read_json, # USE send_json_with_latency
    b64_encode_bytes, b64_decode_to_bytes,
    set_simulated_bandwidth # Import the setter
)

log = None # Will be set in main

# --- OQS Verification ---
try:
    oqs.Signature(PQC_SIG_ALG)
except (oqs.MechanismNotSupportedError, AttributeError) as e:
    logging.critical(f"OQS mechanism '{PQC_SIG_ALG}' not supported or OQS invalid: {e}. Install/build OQS correctly. Exiting.")
    exit(1)
except Exception as e:
    logging.critical(f"Failed to initialize OQS for '{PQC_SIG_ALG}': {e}. Exiting.")
    exit(1)

class SignerService:
    def __init__(self, name: str, host: str, port: int, processing_time: float):
        self.name = name
        self.host = host
        self.port = port
        self.processing_time = processing_time # Base non-crypto delay
        self.algorithm = PQC_SIG_ALG
        self.signer = oqs.Signature(self.algorithm)
        log.info("Generating PQC key pair...")
        self.public_key = self.signer.generate_keypair()
        self.private_key = self.signer.export_secret_key() # Keep private key internal
        self.public_key_b64 = b64_encode_bytes(self.public_key)
        log.info(f"Key pair generated. Public key size: {len(self.public_key)} bytes.")
        log.info(f"Signer '{self.name}' initialized.")

    async def register_with_controller(self, ctrl_host: str, ctrl_port: int):
        """Connects to the controller and sends registration info."""
        while True: # Keep retry logic
            reader, writer = None, None # Ensure defined for finally
            try:
                log.info(f"Attempting to register with controller at {ctrl_host}:{ctrl_port}...")
                reader, writer = await asyncio.open_connection(ctrl_host, ctrl_port)
                registration_data = {
                    "command": "REGISTER_SIGNER",
                    "payload": {
                        "name": self.name,
                        "host": self.host, # Host where this signer listens
                        "port": self.port, # Port where this signer listens
                        "public_key_b64": self.public_key_b64
                    }
                }
                # Use the latency-simulating send function
                await send_json_with_latency(writer, registration_data)
                log.info(f"Sent registration data: {registration_data['payload']}")

                # Wait for acknowledgment (optional but good practice)
                response = await read_json(reader)
                if response and response.get("status") == "OK":
                    log.info("Registration acknowledged by controller.")
                    return True # Success
                else:
                    log.warning(f"Registration failed or no valid ACK received: {response}")

            except ConnectionRefusedError:
                 log.warning(f"Controller at {ctrl_host}:{ctrl_port} refused connection. Retrying in 5 seconds...")
            except Exception as e:
                 log.error(f"Error during registration: {e}. Retrying in 5 seconds...")
            finally:
                if writer:
                    writer.close()
                    try: await writer.wait_closed()
                    except Exception: pass # Ignore close errors


            await asyncio.sleep(5) # Wait before retrying


    async def handle_signing_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handles an incoming signing request from the controller."""
        addr = writer.get_extra_info('peername')
        log.debug(f"Received connection from {addr}")
        request_data = await read_json(reader) # Read request first

        # Check request validity
        if not request_data or request_data.get("command") != "SIGN_REQUEST":
            log.warning(f"Invalid or missing request data from {addr}: {request_data}")
            response = {"command": "SIGN_RESULT", "payload": {"job_id": None, "signature_b64": None, "error": "Invalid request"}}
            # Send error response using latency sim send
            try:
                await send_json_with_latency(writer, response)
            except Exception as e_send:
                log.error(f"Failed to send invalid request error to {addr}: {e_send}")
            finally: # Ensure connection is closed
                 writer.close()
                 await writer.wait_closed()
            return

        payload = request_data.get("payload", {})
        subpacket = payload.get("subpacket")
        job_id = payload.get("job_id", "unknown_job")

        # Check if subpacket exists
        if not subpacket:
            log.error(f"Missing subpacket in request {job_id} from {addr}")
            response = {"command": "SIGN_RESULT", "payload": {"job_id": job_id, "signature_b64": None, "error": "Missing subpacket data"}}
            try:
                await send_json_with_latency(writer, response)
            except Exception as e_send:
                 log.error(f"Failed to send missing subpacket error to {addr}: {e_send}")
            finally:
                writer.close()
                await writer.wait_closed()
            return

        log.info(f"Received signing request {job_id} for subpacket: '{subpacket[:30]}...'")


        # 1. Simulate non-cryptographic processing time
        if self.processing_time > 0:
            await asyncio.sleep(self.processing_time)
            log.debug(f"Finished non-crypto processing for {job_id}.")

        # 2. Perform PQC Signing
        signature_bytes = None
        error_msg = None
        try:
            message_bytes = subpacket.encode('utf-8')
            log.debug(f"Starting PQC signing ({len(message_bytes)} bytes) for {job_id}...")
            sign_start_time = time.monotonic()
            signature_bytes = self.signer.sign(message_bytes) # Use internal private key
            sign_duration = time.monotonic() - sign_start_time
            log.info(f"Finished PQC signing for {job_id}. Took {sign_duration:.4f}s.")
        except Exception as e:
            log.error(f"Error during signing for job {job_id}: {e}")
            error_msg = f"Internal signing error: {e}"


        # 3. Send Result Back
        signature_b64 = b64_encode_bytes(signature_bytes)
        response_payload = {"job_id": job_id, "signature_b64": signature_b64, "error": error_msg}
        response = {"command": "SIGN_RESULT", "payload": response_payload}

        try:
            # Use the latency-simulating send function
            await send_json_with_latency(writer, response)
            log.info(f"Sent signing result for {job_id} back to controller.")
        except Exception as e:
            log.error(f"Failed to send signing result for {job_id} to {addr}: {e}")
        finally:
            # 4. Close connection (moved to finally)
            writer.close()
            await writer.wait_closed()
            log.debug(f"Connection with {addr} closed for {job_id}.")

    async def start_server(self):
        """Starts the TCP server to listen for signing requests."""
        server = await asyncio.start_server(
            self.handle_signing_request, self.host, self.port)

        addr = server.sockets[0].getsockname()
        log.info(f'Signer "{self.name}" listening on {addr}')

        async with server:
            await server.serve_forever()

async def main(args):
    global log
    log = setup_logging(f"Signer-{args.name}")

    # --- Set simulated bandwidth for this signer ---
    set_simulated_bandwidth(args.bandwidth)
    # ---------------------------------------------

    # Determine processing time based on name (example values)
    if args.name.lower() == "arduino":
        processing_time = 0.15
    elif args.name.lower() == "raspberrypi":
        processing_time = 0.03
    elif args.name.lower() == "fpga":
        processing_time = 0.001
    else:
        processing_time = 0.1 # Default
    log.info(f"Using base processing time: {processing_time}s")


    signer = SignerService(args.name, args.host, args.port, processing_time)

    # Register with controller in a separate task
    registration_task = asyncio.create_task(
        signer.register_with_controller(args.controller_host, args.controller_port)
    )
    # Start listening server
    server_task = asyncio.create_task(signer.start_server())
    # Keep running until tasks finish (or KeyboardInterrupt)
    await asyncio.gather(registration_task, server_task)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PQC Signing Device Simulator")
    parser.add_argument("--name", required=True, help="Name of the signer (e.g., Arduino, FPGA)")
    parser.add_argument("--host", default="127.0.0.1", help="Host address for this signer to listen on")
    parser.add_argument("--port", type=int, required=True, help="Port for this signer to listen on")
    parser.add_argument("--controller-host", default=CONTROLLER_IP, help="Controller host address")
    parser.add_argument("--controller-port", type=int, default=CONTROLLER_REGISTRATION_PORT, help="Controller registration port")
    parser.add_argument("--bandwidth", type=float, default=100.0, help="Simulated network bandwidth FROM this signer (Mbps)") # ADDED
    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        if log: log.info("Signer stopped manually.")
        else: print("Signer stopped manually.")
    except Exception as e:
        if log: log.exception("Signer encountered critical error:")
        else: print(f"Signer critical error: {e}")
