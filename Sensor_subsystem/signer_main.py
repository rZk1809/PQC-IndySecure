# File: signer_main.py
import asyncio
import argparse
import time
import oqs
import logging
import base64

# Import from common.py
from common import (
    PQC_SIG_ALG, CONTROLLER_IP, CONTROLLER_REGISTRATION_PORT, LOCAL_IP, # Use LOCAL_IP for listening
    setup_logging, send_json_with_latency, read_json,
    b64_encode_bytes, b64_decode_to_bytes,
    # Bandwidth simulation is less relevant for local signer, but keep setup consistent
    set_local_simulated_bandwidth
)

log = None # Will be set in main

# --- OQS Verification ---
try:
    oqs.Signature(PQC_SIG_ALG)
except Exception as e:
    # Use basic logging if setup_logging hasn't run yet
    logging.basicConfig(level=logging.INFO)
    logging.critical(f"OQS mechanism '{PQC_SIG_ALG}' error: {e}. Exiting.")
    exit(1)

class LocalSignerService:
    def __init__(self, name: str, host: str, port: int, subsystem_id: str):
        self.name = name
        self.host = host # Host THIS signer listens on (likely LOCAL_IP)
        self.port = port # Port THIS signer listens on
        self.subsystem_id = subsystem_id # ID of the sensor subsystem it belongs to
        self.algorithm = PQC_SIG_ALG
        self.signer = oqs.Signature(self.algorithm)
        # Logger setup moved after potential basicConfig call
        self.log = setup_logging(f"Signer-{self.name}@{self.subsystem_id}")

        self.log.info("Generating PQC key pair...")
        self.public_key = self.signer.generate_keypair()
        self.private_key = self.signer.export_secret_key() # Keep private key internal
        self.public_key_b64 = b64_encode_bytes(self.public_key)
        self.log.info(f"Key pair generated. Public key size: {len(self.public_key)} bytes.")
        self.log.info(f"Signer '{self.name}' for subsystem '{self.subsystem_id}' initialized.")

    async def register_with_controller(self, ctrl_host: str, ctrl_reg_port: int):
        """Connects to the MAIN controller and sends registration info."""
        while True: # Keep retry logic
            reader, writer = None, None
            try:
                self.log.info(f"Attempting to register with main controller at {ctrl_host}:{ctrl_reg_port}...")
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ctrl_host, ctrl_reg_port), timeout=10.0
                )
                registration_data = {
                    "command": "REGISTER_SIGNER",
                    "payload": {
                        "name": self.name, # Name of this specific signer
                        "host": self.host, # Where this signer listens (for info only, controller won't connect back)
                        "port": self.port, # Where this signer listens (for info only)
                        "public_key_b64": self.public_key_b64,
                        "algorithm": self.algorithm,
                        "sensor_subsystem_id": self.subsystem_id # Crucial link!
                    }
                }
                # Use MAIN network latency simulation for registration
                await send_json_with_latency(writer, registration_data, is_local=False)
                self.log.info(f"Sent registration data for subsystem {self.subsystem_id}")

                response = await asyncio.wait_for(read_json(reader), timeout=5.0)
                if response and response.get("status") == "OK":
                    self.log.info("Registration acknowledged by main controller.")
                    return True # Success
                else:
                    self.log.warning(f"Registration failed or no valid ACK received: {response}")

            except asyncio.TimeoutError:
                 self.log.warning(f"Timeout connecting/registering with controller {ctrl_host}:{ctrl_reg_port}. Retrying...")
            except ConnectionRefusedError:
                 self.log.warning(f"Controller at {ctrl_host}:{ctrl_reg_port} refused connection. Retrying...")
            except Exception as e:
                 self.log.error(f"Error during registration: {e}. Retrying...")
            finally:
                if writer:
                    writer.close()
                    try: await writer.wait_closed()
                    except Exception: pass
            await asyncio.sleep(5) # Wait before retrying

    async def handle_signing_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handles an incoming signing request from the LOCAL Sensor Coordinator."""
        addr = writer.get_extra_info('peername')
        self.log.debug(f"Received connection from local sensor coordinator {addr}")
        request_data = await read_json(reader)
        # Default error response, ensure job_id is included if available in request
        job_id_from_req = request_data.get("payload", {}).get("job_id") if request_data else None
        response = {"command": "SIGN_RESULT", "payload": {"job_id": job_id_from_req, "signature_b64": None, "signer_name": self.name, "error": "Invalid request"}}

        try:
            if request_data and request_data.get("command") == "SIGN_REQUEST":
                payload = request_data.get("payload", {})
                subpacket_str = payload.get("subpacket")
                job_id = payload.get("job_id", "unknown_job")
                response["payload"]["job_id"] = job_id # Update job_id in response

                if subpacket_str:
                    self.log.info(f"Received signing request {job_id} for subpacket: '{subpacket_str[:30]}...'")
                    # 1. Perform PQC Signing
                    signature_bytes = None
                    error_msg = None
                    try:
                        message_bytes = subpacket_str.encode('utf-8')
                        self.log.debug(f"Starting PQC signing ({len(message_bytes)} bytes) for {job_id}...")
                        sign_start_time = time.monotonic()
                        # Optional: Simulate tiny processing delay
                        # await asyncio.sleep(0.001)
                        signature_bytes = self.signer.sign(message_bytes)
                        sign_duration = time.monotonic() - sign_start_time
                        self.log.info(f"Finished PQC signing for {job_id}. Took {sign_duration:.4f}s.")
                    except Exception as e:
                        self.log.error(f"Error during signing for job {job_id}: {e}")
                        error_msg = f"Internal signing error: {e}"

                    # 2. Prepare Result Payload
                    signature_b64 = b64_encode_bytes(signature_bytes)
                    response["payload"]["signature_b64"] = signature_b64
                    response["payload"]["error"] = error_msg
                    # response["payload"]["signer_name"] = self.name # Already set in default
                else:
                    self.log.error(f"Missing subpacket in request {job_id} from {addr}")
                    response["payload"]["error"] = "Missing subpacket data"
            else:
                 self.log.warning(f"Invalid or missing request data from {addr}: {request_data}")
                 response["payload"]["error"] = f"Invalid command: {request_data.get('command')}" if request_data else "Empty request"


            # 3. Send Result Back to Sensor Coordinator (use LOCAL latency)
            await send_json_with_latency(writer, response, is_local=True)
            if response["payload"]["error"]:
                self.log.warning(f"Sent error response for {job_id or 'N/A'} back to sensor coordinator: {response['payload']['error']}")
            else:
                 self.log.info(f"Sent signing result for {job_id} back to sensor coordinator.")

        except Exception as e:
             log.error(f"Error processing request from {addr}: {e}", exc_info=True)
             # Try sending error back if possible
             try:
                 # Ensure payload exists before modifying
                 if "payload" not in response: response["payload"] = {}
                 response["payload"]["job_id"] = job_id_from_req # Try to preserve job_id
                 response["payload"]["error"] = f"Signer processing error: {e}"
                 response["payload"]["signer_name"] = self.name
                 await send_json_with_latency(writer, response, is_local=True)
             except: pass # Ignore errors during error reporting
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass # Ignore potential errors during close in error scenarios
            self.log.debug(f"Connection with {addr} closed for job {job_id_from_req or 'N/A'}.")


    async def start_server(self):
        """Starts the TCP server to listen for signing requests from the local sensor."""
        server = await asyncio.start_server(
            self.handle_signing_request, self.host, self.port)
        addr = server.sockets[0].getsockname()
        self.log.info(f'Signer "{self.name}" listening locally on {addr} for Sensor "{self.subsystem_id}"')
        async with server:
            await server.serve_forever()

async def main(args):
    global log
    # Setup logging after potential basicConfig call from OQS check
    log = setup_logging(f"Signer-{args.name}@{args.subsystem_id}")
    log.info(f"--- Starting Local Signer {args.name} for Subsystem {args.subsystem_id} ---")
    # Signers don't dictate network bandwidth in this model, use default local high BW
    set_local_simulated_bandwidth(10000) # Set high default local BW

    try:
        signer = LocalSignerService(args.name, args.host, args.port, args.subsystem_id)

        # Register with controller in a separate task
        registration_task = asyncio.create_task(
            signer.register_with_controller(args.controller_host, args.controller_reg_port)
        )
        # Start listening server
        server_task = asyncio.create_task(signer.start_server())

        # Wait for registration to succeed before fully operational? Or just run both?
        # Let's wait for registration first.
        reg_success = await registration_task
        if reg_success:
            log.info("Registration successful. Server running.")
            await server_task # Keep server running until cancelled
        else:
            log.error("Registration failed. Shutting down server task.")
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                log.info("Server task cancelled.")

    except Exception as e:
         log.critical(f"Signer initialization failed: {e}", exc_info=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PQC Local Signing Device")
    parser.add_argument("--name", required=True, help="Unique name of THIS signer (e.g., FPGA-01)")
    parser.add_argument("--host", default=LOCAL_IP, help="Host address for this signer to listen on")
    parser.add_argument("--port", type=int, required=True, help="Port for this signer to listen on")
    parser.add_argument("--subsystem-id", required=True, help="ID of the Sensor Subsystem this signer belongs to")
    parser.add_argument("--controller-host", default=CONTROLLER_IP, help="Main Controller host address")
    parser.add_argument("--controller-reg-port", type=int, default=CONTROLLER_REGISTRATION_PORT, help="Main Controller registration port")
    # Bandwidth arg removed - local communication uses high default

    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        # Ensure log exists before using it
        logger = logging.getLogger(f"Signer-{args.name}@{args.subsystem_id}")
        if logger.hasHandlers(): logger.info("Signer stopped manually.")
        else: print("Signer stopped manually.")
    except Exception as e:
        logger = logging.getLogger(f"Signer-{args.name}@{args.subsystem_id}")
        if logger.hasHandlers(): logger.exception("Signer encountered critical error:")
        else: print(f"Signer critical error: {e}")
