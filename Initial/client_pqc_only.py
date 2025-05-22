# client_pqc_only.py
import asyncio
import json
import time
import random
import sys
import oqs # PQC library
import base64
from contextlib import suppress

# --- Configuration ---
PQC_SIG_ALG = "ML-DSA-44" # Must match controller settings
SENSOR_DATA_INTERVAL_SECONDS = 8

# --- PQC Key Management & Signing ---
class DevicePqcKeys:
    def __init__(self, pqc_alg: str):
        self.pqc_alg = pqc_alg
        self.pqc_pub_key: bytes | None = None
        self.pqc_priv_key: bytes | None = None
        self.pqc_signer: oqs.Signature | None = None
        print("[Keys] Generating PQC key...")
        try:
            self.pqc_signer = oqs.Signature(self.pqc_alg)
            self.pqc_pub_key = self.pqc_signer.generate_keypair()
            self.pqc_priv_key = self.pqc_signer.export_secret_key()
            print("[Keys] PQC Key generation complete.")
        except Exception as e:
            print(f"[Keys] FATAL: PQC Key generation failed: {e}")
            raise

    def sign_pqc(self, msg: bytes) -> bytes | None:
        if not self.pqc_signer: print("[Sign] PQC signer N/A."); return None
        try: return self.pqc_signer.sign(msg)
        except Exception as e: print(f"[Sign] PQC sign error: {e}"); return None

    def get_pqc_pub_key(self) -> bytes | None: return self.pqc_pub_key

# --- Packet Handling ---
def create_sensor_data(node: str, num: int) -> dict:
    ts = time.time()
    status = random.choices(["PASS", "WARN"], weights=[95, 5], k=1)[0]
    return {
        "id": f"{node}-{num}", "ts": ts, "part": f"P{random.randint(100, 999)}",
        "stn": node, "stat": status, "val": round(random.uniform(1, 100), 1)
    }

def serialize_pkt(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True).encode('utf-8')

# --- Network Framing ---
async def send_msg(writer: asyncio.StreamWriter, msg_dict: dict) -> bool:
    peername = '?'
    try:
        peername = str(writer.get_extra_info('peername', '?'))
        def bytes_encoder(obj):
            if isinstance(obj, bytes): return base64.b64encode(obj).decode('ascii')
            raise TypeError(f"Type {obj.__class__.__name__} not JSON serializable")
        msg_json = json.dumps(msg_dict, default=bytes_encoder).encode('utf-8')
        msg_len_bytes = len(msg_json)
        writer.write(msg_len_bytes.to_bytes(4, 'big'))
        writer.write(msg_json)
        await writer.drain()
        return True
    except Exception as e:
        print(f"[Network] Send failed to {peername}: {e}")
        return False

async def read_msg(reader: asyncio.StreamReader) -> dict | None:
    try:
        hdr = await reader.readexactly(4)
        msg_len = int.from_bytes(hdr, 'big')
        limit = 25 * 1024 * 1024
        if msg_len > limit:
            print(f"[Network] Incoming message size {msg_len} exceeds limit {limit}.")
            raise asyncio.IncompleteReadError("Msg too large", None)
        msg_json_bytes = await reader.readexactly(msg_len)
        msg = json.loads(msg_json_bytes.decode('utf-8'))
        return msg
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError, OSError):
        return None
    except Exception as e:
        print(f"[Network] Read Error: {e}")
        return None

# --- Role-Specific Tasks (PQC Only) ---
async def sensor_loop(node: str, writer: asyncio.StreamWriter, keys: DevicePqcKeys, interval: float):
    print(f"[{node}] Starting sensor loop (Interval: {interval}s).")
    pkt_count = 0
    while True:
        try:
            await asyncio.sleep(interval)
            pkt_count += 1
            data_dict = create_sensor_data(node, pkt_count)
            data_bytes = serialize_pkt(data_dict)
            pqc_sig = keys.sign_pqc(data_bytes)
            if pqc_sig is None: print(f"[{node}] ERROR: PQC Sign failed pkt {pkt_count}!"); continue
            msg = {
                "type": "sensor_data_signed_pqc",
                "origin_node": node,
                "data_b64": data_bytes,
                "pqc_signature_b64": pqc_sig
            }
            if not await send_msg(writer, msg): print(f"[{node}] Failed send pkt {pkt_count}."); break
            else: print(f"[{node}] Sent packet {pkt_count}.")
        except asyncio.CancelledError: print(f"[{node}] Sensor loop cancelled."); break
        except Exception as e: print(f"[{node}] Sensor loop error: {e}."); break

async def signer_loop(node: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, keys: DevicePqcKeys):
    print(f"[{node}] Starting signer loop (PQC Only)...")
    while True:
        try:
            req = await read_msg(reader)
            if req is None: print(f"[{node}] Connection lost."); break

            if req.get("type") == "sign_request_pqc":
                task_id = req.get("task_id", "?")
                subpacket_b64_str = req.get("subpacket")

                if not subpacket_b64_str or not isinstance(subpacket_b64_str, str):
                    print(f"[{node}] Req {task_id} invalid subpacket field.")
                    fail_resp = {"type": "sign_response_pqc", "task_id": task_id, "error": "Invalid subpacket data"}
                    await send_msg(writer, fail_resp)
                    continue

                try:
                    subpacket_bytes = base64.b64decode(subpacket_b64_str)
                    print(f"[{node}] Received PQC sign req {task_id} ({len(subpacket_bytes)}B decoded). Signing...")
                    await asyncio.sleep(random.uniform(0.001, 0.005))

                    pqc_sig = keys.sign_pqc(subpacket_bytes)

                    resp = { "type": "sign_response_pqc", "task_id": task_id }
                    if pqc_sig:
                        resp["pqc_signature_b64"] = pqc_sig
                    else:
                        resp["error"] = "Internal PQC signing failed"
                        print(f"[{node}] Sending FAILURE resp {task_id} (Sign func failed).")

                    if not await send_msg(writer, resp): print(f"[{node}] Failed send resp {task_id}."); break

                except base64.binascii.Error as b64e:
                    print(f"[{node}] Error processing req {task_id}: Base64 decode failed - {b64e}")
                    fail_resp = {"type": "sign_response_pqc", "task_id": task_id, "error": "Subpacket base64 decode failed"}
                    await send_msg(writer, fail_resp)
                except Exception as e:
                    print(f"[{node}] Error processing req {task_id}: {e}")
                    try:
                        fail_resp = {"type": "sign_response_pqc", "task_id": task_id, "error": f"Processing error: {e}"}
                        await send_msg(writer, fail_resp)
                    except Exception: pass

            else: print(f"[{node}] Unexpected msg type: {req.get('type')}")
        except asyncio.CancelledError: print(f"[{node}] Signer loop cancelled."); break
        except Exception as e: print(f"[{node}] Signer loop error: {e}"); break

# --- Main Client Function ---
async def run_client(node_type: str, node_name: str, ctrl_host: str, ctrl_port: int):
    print(f"--- Simplified PQC-Only Client ---")
    print(f"Init {node_type}: {node_name} -> {ctrl_host}:{ctrl_port}")
    print("(!) Ensure OQS versions are compatible!")
    try: keys = DevicePqcKeys(PQC_SIG_ALG)
    except Exception: print(f"[{node_name}] FATAL: Key init failed."); return

    while True:
        reader, writer, task = None, None, None
        peer = 'Unknown Server'
        try:
            print(f"[{node_name}] Connecting...")
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ctrl_host, ctrl_port), timeout=10.0)
            peer = writer.get_extra_info('peername')
            print(f"[{node_name}] Connected to {peer}")

            pqc_b64 = base64.b64encode(keys.get_pqc_pub_key()).decode('ascii')
            reg_msg = { "type": f"register_{node_type.lower()}", "name": node_name,
                        "pqc_public_key_b64": pqc_b64 }
            if not await send_msg(writer, reg_msg): raise ConnectionError("Failed send reg")
            ack = await asyncio.wait_for(read_msg(reader), timeout=10.0)
            if ack and ack.get("status") == "OK" and ack.get("node_type") == node_type: print(f"[{node_name}] Registered.")
            else: raise ConnectionError(f"Reg failed: {ack}")

            if node_type == "Sensor": task = asyncio.create_task(sensor_loop(node_name, writer, keys, SENSOR_DATA_INTERVAL_SECONDS))
            elif node_type == "Signer": task = asyncio.create_task(signer_loop(node_name, reader, writer, keys))
            else: print(f"[{node_name}] Invalid type for PQC-Only."); break
            await task

        except (OSError, ConnectionError, asyncio.TimeoutError, asyncio.CancelledError) as e:
            print(f"[{node_name}] Connection/Task Error ({peer}): {type(e).__name__}. Reconnecting...")
        except Exception as e: print(f"[{node_name}] UNEXPECTED Error ({peer}): {e}. Reconnecting...")
        finally:
             if task and not task.done(): task.cancel(); await asyncio.sleep(0.1)
             if writer and not writer.is_closing(): writer.close(); await asyncio.sleep(0.1)
             wait = random.uniform(3, 7)
             print(f"[{node_name}] Waiting {wait:.1f}s...")
             await asyncio.sleep(wait)

# --- Script Entry Point ---
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python client_pqc_only.py <Type> <Name> <Host:Port>")
        print("  Type: Sensor or Signer")
        sys.exit(1)
    node_type, node_name, ctrl_addr = sys.argv[1], sys.argv[2], sys.argv[3]
    valid_types = ["Sensor", "Signer"]
    if node_type not in valid_types: print(f"Invalid Type '{node_type}'. Must be Sensor or Signer."); sys.exit(1)
    try: host, port_str = ctrl_addr.split(':'); port = int(port_str)
    except ValueError: print(f"Invalid address '{ctrl_addr}'."); sys.exit(1)

    try: asyncio.run(run_client(node_type, node_name, host, port))
    except KeyboardInterrupt: print(f"\n[{node_name}] Client stopped.")
    except Exception as e: print(f"[{node_name}] Fatal error: {e}")
