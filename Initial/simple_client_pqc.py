
import asyncio
import json
import time
import random
import sys
import oqs  # Requires PQC support for "ML-DSA-44"
import base64
from contextlib import suppress

# --- Configuration ---
SIG_ALG = "ML-DSA-44"

# --- Device Keys Management ---
class DeviceKeys:
    def __init__(self, algorithm):
        self.algorithm = algorithm
        self.public_key = None
        self.private_key = None
        self.signer = None
        self.generate()

    def generate(self):
        try:
            self.signer = oqs.Signature(self.algorithm)
            self.public_key = self.signer.generate_keypair()
            self.private_key = self.signer.export_secret_key()
            print(f"[Client] Generated keys: public ({len(self.public_key)}B), private ({len(self.private_key)}B)")
        except Exception as e:
            print(f"[Client] Key generation failed: {e}")
            raise

    def sign(self, message: bytes) -> bytes:
        try:
            return self.signer.sign(message)
        except Exception as e:
            print(f"[Client] Signing error: {e}")
            return None

# --- Network Message Helpers ---
async def send_message(writer: asyncio.StreamWriter, message: dict) -> bool:
    try:
        message_json = json.dumps(message, default=lambda obj: base64.b64encode(obj).decode('ascii') if isinstance(obj, bytes) else obj).encode('utf-8')
        writer.write(len(message_json).to_bytes(4, 'big'))
        writer.write(message_json)
        await writer.drain()
        return True
    except Exception as e:
        print(f"[Client] Error sending message: {e}")
        return False

async def read_message(reader: asyncio.StreamReader) -> dict or None:
    try:
        header = await reader.readexactly(4)
        msg_len = int.from_bytes(header, 'big')
        msg_json = await reader.readexactly(msg_len)
        return json.loads(msg_json.decode('utf-8'))
    except Exception as e:
        print(f"[Client] Error reading message: {e}")
        return None

# --- Main Client Logic ---
async def run_client(device_name: str, host: str, port: int):
    try:
        keys = DeviceKeys(SIG_ALG)
    except Exception as e:
        print(f"[Client] Exiting due to key error: {e}")
        return

    while True:
        try:
            print("[Client] Connecting to controller...")
            reader, writer = await asyncio.open_connection(host, port)
            print("[Client] Connected to controller.")

            # --- Registration ---
            reg_msg = {"type": "register_pqc", "name": device_name, "public_key": keys.public_key}
            if not await send_message(writer, reg_msg):
                print("[Client] Failed to send registration message.")
                continue
            ack = await asyncio.wait_for(read_message(reader), timeout=10)
            if ack and ack.get("status") == "OK":
                print("[Client] Registration successful.")
            else:
                print(f"[Client] Registration failed: {ack.get('detail', 'No detail provided') if ack else 'No response'}")
                raise Exception("Registration not OK")

            # --- Process Signing Requests ---
            while True:
                req = await read_message(reader)
                if req is None:
                    print("[Client] Connection closed by controller.")
                    break
                if req.get("type") == "sign_request_pqc":
                    task_id = req.get("task_id", "unknown")
                    subpacket_b64 = req.get("subpacket")
                    if not subpacket_b64:
                        print(f"[Client] Task {task_id}: Missing subpacket.")
                        continue
                    try:
                        subpacket = base64.b64decode(subpacket_b64)
                    except Exception as e:
                        print(f"[Client] Task {task_id}: Error decoding subpacket: {e}")
                        continue

                    print(f"[Client] Received sign request {task_id} ({len(subpacket)}B).")
                    # Simulate a tiny delay to mimic processing overhead.
                    time.sleep(random.uniform(0.001, 0.005))
                    signature = keys.sign(subpacket)
                    response = {"type": "sign_response_pqc", "task_id": task_id, "signature": signature}
                    if not await send_message(writer, response):
                        print(f"[Client] Task {task_id}: Failed to send response.")
                        break
                else:
                    print(f"[Client] Received unknown message type: {req.get('type')}")
        except Exception as e:
            print(f"[Client] Connection error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            wait_time = random.uniform(3, 7)
            print(f"[Client] Reconnecting in {wait_time:.1f} seconds...")
            await asyncio.sleep(wait_time)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python simple_client_pqc.py <DeviceName> <Host:Port>")
        print("Example: python simple_client_pqc.py Arduino 127.0.0.1:8891")
        sys.exit(1)
    device_name = sys.argv[1]
    try:
        host, port_str = sys.argv[2].split(':')
        port = int(port_str)
    except Exception as e:
        print(f"Error parsing host:port - {e}")
        sys.exit(1)
    asyncio.run(run_client(device_name, host, port))
