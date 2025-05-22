# client_final.py
import asyncio
import json
import time
import random
import sys
import oqs
import base64
from contextlib import suppress

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("FATAL ERROR: 'cryptography' library not found. Please install it: pip install cryptography")
    exit()

PQC_SIG_ALG = "ML-DSA-44"
ECC_CURVE = ec.SECP384R1()
ECC_HASH_ALG = hashes.SHA384()
SENSOR_DATA_INTERVAL_SECONDS = 8

class DeviceKeys:
    def __init__(self, pqc_alg: str, ecc_curve):
        self.pqc_alg = pqc_alg
        self.ecc_curve = ecc_curve
        self.pqc_pub_key: bytes | None = None
        self.pqc_priv_key: bytes | None = None
        self.pqc_signer: oqs.Signature | None = None
        self.ecdsa_priv_key = None
        self.ecdsa_pub_key = None
        print("[Keys] Generating PQC and ECC keys...")
        try:
            self.pqc_signer = oqs.Signature(self.pqc_alg)
            self.pqc_pub_key = self.pqc_signer.generate_keypair()
            self.pqc_priv_key = self.pqc_signer.export_secret_key()
            self.ecdsa_priv_key = ec.generate_private_key(self.ecc_curve)
            self.ecdsa_pub_key = self.ecdsa_priv_key.public_key()
            print("[Keys] Key generation complete.")
        except Exception as e:
            print(f"[Keys] FATAL: Key generation failed: {e}")
            raise

    def sign_pqc(self, msg: bytes) -> bytes | None:
        if not self.pqc_signer: print("[Sign] PQC signer N/A."); return None
        try: return self.pqc_signer.sign(msg)
        except Exception as e: print(f"[Sign] PQC sign error: {e}"); return None

    def sign_ecdsa(self, msg: bytes) -> bytes | None:
        if not self.ecdsa_priv_key: print("[Sign] ECDSA key N/A."); return None
        try: return self.ecdsa_priv_key.sign(msg, ec.ECDSA(ECC_HASH_ALG))
        except Exception as e: print(f"[Sign] ECDSA sign error: {e}"); return None

    def get_pqc_pub_key(self) -> bytes | None: return self.pqc_pub_key

    def get_ecdsa_pub_pem(self) -> bytes | None:
        if not self.ecdsa_pub_key: return None
        try:
            return self.ecdsa_pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except Exception as e: print(f"[Keys] Error get ECDSA PEM: {e}"); return None

def create_sensor_data(node: str, num: int) -> dict:
    ts = time.time()
    status = random.choices(["PASS", "WARN"], weights=[95, 5], k=1)[0]
    return {
        "id": f"{node}-{num}", "ts": ts, "part": f"P{random.randint(100, 999)}",
        "stn": node, "stat": status, "val": round(random.uniform(1, 100), 1)
    }

def serialize_pkt(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True).encode('utf-8')

def deserialize_pkt(data: bytes) -> dict | None:
    try: return json.loads(data.decode('utf-8'))
    except Exception: return None

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

def verify_pqc_sig(message: bytes, signature: bytes, pub_key: bytes) -> bool:
    if not all([message, signature, pub_key]): return False
    try: return oqs.Signature(PQC_SIG_ALG).verify(message, signature, pub_key)
    except Exception as e: print(f"[Verify] PQC Verify Error: {e}"); return False

def verify_ecdsa_sig(message: bytes, signature: bytes, pub_key) -> bool:
    if not all([message, signature, pub_key]): return False
    try: pub_key.verify(signature, message, ec.ECDSA(ECC_HASH_ALG)); return True
    except InvalidSignature: print("[Verify] ECDSA InvalidSig"); return False
    except Exception as e: print(f"[Verify] ECDSA Verify Error: {e}"); return False

async def sensor_loop(node: str, writer: asyncio.StreamWriter, keys: DeviceKeys, interval: float):
    print(f"[{node}] Starting sensor loop (Interval: {interval}s).")
    pkt_count = 0
    while True:
        try:
            await asyncio.sleep(interval)
            pkt_count += 1
            data_dict = create_sensor_data(node, pkt_count)
            data_bytes = serialize_pkt(data_dict)
            pqc_sig = keys.sign_pqc(data_bytes)
            ecdsa_sig = keys.sign_ecdsa(data_bytes)
            if pqc_sig is None or ecdsa_sig is None: print(f"[{node}] ERROR: Sign failed pkt {pkt_count}!"); continue
            msg = {
                "type": "sensor_data_signed_hybrid", "origin_node": node,
                "data_b64": data_bytes,
                "pqc_signature_b64": pqc_sig,
                "ecdsa_signature_b64": ecdsa_sig
            }
            if not await send_msg(writer, msg): print(f"[{node}] Failed send pkt {pkt_count}."); break
            else: print(f"[{node}] Sent packet {pkt_count}.")
        except asyncio.CancelledError: print(f"[{node}] Sensor loop cancelled."); break
        except Exception as e: print(f"[{node}] Sensor loop error: {e}."); break

async def signer_loop(node: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, keys: DeviceKeys):
    print(f"[{node}] Starting signer loop...")
    while True:
        try:
            req = await read_msg(reader)
            if req is None: print(f"[{node}] Connection lost."); break

            if req.get("type") == "sign_request_hybrid":
                task_id = req.get("task_id", "?")
                subpacket_b64_str = req.get("subpacket")

                if not subpacket_b64_str or not isinstance(subpacket_b64_str, str):
                    print(f"[{node}] Req {task_id} invalid subpacket field.")
                    fail_resp = {"type": "sign_response_hybrid", "task_id": task_id, "error": "Invalid subpacket data"}
                    await send_msg(writer, fail_resp)
                    continue

                try:
                    subpacket_bytes = base64.b64decode(subpacket_b64_str)
                    print(f"[{node}] Received sign req {task_id} ({len(subpacket_bytes)}B decoded). Signing...")
                    await asyncio.sleep(random.uniform(0.001, 0.005))

                    pqc_sig = keys.sign_pqc(subpacket_bytes)
                    ecdsa_sig = keys.sign_ecdsa(subpacket_bytes)

                    resp = { "type": "sign_response_hybrid", "task_id": task_id }
                    if pqc_sig and ecdsa_sig:
                        resp["pqc_signature_b64"] = pqc_sig
                        resp["ecdsa_signature_b64"] = ecdsa_sig
                    else:
                        resp["error"] = "Internal signing failed"
                        print(f"[{node}] Sending FAILURE resp {task_id} (Sign func failed).")

                    if not await send_msg(writer, resp): print(f"[{node}] Failed send resp {task_id}."); break

                except base64.binascii.Error as b64e:
                    print(f"[{node}] Error processing req {task_id}: Base64 decode failed - {b64e}")
                    fail_resp = {"type": "sign_response_hybrid", "task_id": task_id, "error": "Subpacket base64 decode failed"}
                    await send_msg(writer, fail_resp)
                except Exception as e:
                    print(f"[{node}] Error processing req {task_id}: {e}")
                    try:
                        fail_resp = {"type": "sign_response_hybrid", "task_id": task_id, "error": f"Processing error: {e}"}
                        await send_msg(writer, fail_resp)
                    except Exception: pass

            else: print(f"[{node}] Unexpected msg type: {req.get('type')}")
        except asyncio.CancelledError: print(f"[{node}] Signer loop cancelled."); break
        except Exception as e: print(f"[{node}] Signer loop error: {e}"); break

# --- CORRECTED workstation_loop ---
async def workstation_loop(node: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    print(f"[{node}] Starting workstation loop...")
    keys_cache = {} # Cache loaded ECDSA keys
    while True:
        try:
            msg = await read_msg(reader)
            if msg is None: print(f"[{node}] Connection lost."); break

            if msg.get("type") == "verified_hybrid_bundle":
                target = msg.get("target")
                pld = msg.get("payload") # Payload is the main dictionary

                # Basic check for essential structure
                if target != node or not isinstance(pld, dict):
                    print(f"[{node}] Ignoring bundle: Wrong target or no payload dict.")
                    continue

                orig_node = pld.get("origin", {}).get("node", "Unknown") # Safe access
                pkt_id = pld.get("pkt_id", "?") # Safe access
                print(f"[{node}] Received bundle '{pkt_id}' from '{orig_node}'. Verifying...")
                print(f"--- WS Verify Start (Pkt: {pkt_id}) ---")
                final_ok = True
                errs = []

                try:
                    # Get original data bytes safely
                    orig_data_b64 = pld.get("orig_data_b64")
                    if not orig_data_b64: raise ValueError("Missing original_data_b64 in payload")
                    orig_data_bytes = base64.b64decode(orig_data_b64)

                    # 1. Verify Origin Signature (if present) safely
                    orig_info = pld.get("origin")
                    if isinstance(orig_info, dict): # Check if origin info exists and is a dict
                        orig_sigs = orig_info.get("sigs")
                        orig_keys = orig_info.get("keys")
                        orig_node_name = orig_info.get("node")

                        if isinstance(orig_sigs, dict) and isinstance(orig_keys, dict) and orig_node_name:
                            pqc_sig_b64 = orig_sigs.get("pqc_b64")
                            ecdsa_sig_b64 = orig_sigs.get("ecdsa_b64")
                            pqc_key_b64 = orig_keys.get("pqc_b64")
                            ecdsa_pem_b64 = orig_keys.get("ecdsa_pem_b64")

                            if all([pqc_sig_b64, ecdsa_sig_b64, pqc_key_b64, ecdsa_pem_b64]):
                                try:
                                    orig_pqc_sig = base64.b64decode(pqc_sig_b64)
                                    orig_ecdsa_sig = base64.b64decode(ecdsa_sig_b64)
                                    orig_pqc_pub = base64.b64decode(pqc_key_b64)

                                    # Load/Cache ECDSA key
                                    if orig_node_name not in keys_cache:
                                        orig_ecdsa_pem = base64.b64decode(ecdsa_pem_b64)
                                        keys_cache[orig_node_name] = serialization.load_pem_public_key(orig_ecdsa_pem)
                                    orig_ecdsa_pub = keys_cache[orig_node_name]

                                    pqc_orig_ok = verify_pqc_sig(orig_data_bytes, orig_pqc_sig, orig_pqc_pub)
                                    ecdsa_orig_ok = verify_ecdsa_sig(orig_data_bytes, orig_ecdsa_sig, orig_ecdsa_pub)

                                    if not (pqc_orig_ok and ecdsa_orig_ok):
                                        print(f"[Verify] Origin '{orig_node_name}' sig FAILED (PQC:{pqc_orig_ok}, ECDSA:{ecdsa_orig_ok})."); final_ok = False; errs.append("Origin sig fail")
                                    else: print(f"[Verify] Origin '{orig_node_name}' sig OK.")
                                except Exception as e:
                                    print(f"[Verify] Error decoding/loading origin keys/sigs: {e}"); final_ok = False; errs.append("Origin data decode error")
                            else:
                                print(f"[Verify] Origin info incomplete."); final_ok = False; errs.append("Origin info incomplete")
                        else:
                            print(f"[Verify] Origin sigs/keys/node missing."); final_ok = False; errs.append("Origin sigs/keys missing")
                    elif orig_info is not None:
                        print("[Verify] Origin info present but not a dictionary.") # Log if origin exists but isn't a dict

                    # 2. Verify Signer Signatures and Reassemble safely
                    reassembled = b""
                    signer_keys_map = pld.get("signer_keys", {}) # Use default {}
                    sub_pkts_list = pld.get("sub_pkts", []) # Use default []

                    if not isinstance(signer_keys_map, dict): raise ValueError("signer_keys is not a dict")
                    if not isinstance(sub_pkts_list, list): raise ValueError("sub_pkts is not a list")

                    for i, item in enumerate(sub_pkts_list):
                         if not isinstance(item, dict):
                             print(f"[Verify] SubPkt {i+1} item is not a dict."); final_ok = False; errs.append(f"SubPkt {i+1} invalid format"); continue

                         sp_b64 = item.get("sp_b64")
                         sigs_dict = item.get("sigs")
                         signer_name = item.get("signer")

                         if not sp_b64 or not isinstance(sigs_dict, dict) or not signer_name:
                             print(f"[Verify] SubPkt {i+1} missing data/sigs/signer."); final_ok = False; errs.append(f"SubPkt {i+1} missing fields"); continue

                         pqc_sig_b64 = sigs_dict.get("pqc_b64")
                         ecdsa_sig_b64 = sigs_dict.get("ecdsa_b64")
                         signer_keys_info = signer_keys_map.get(signer_name) # Safely get signer keys dict

                         if not pqc_sig_b64 or not ecdsa_sig_b64 or not isinstance(signer_keys_info, dict):
                             print(f"[Verify] SubPkt {i+1} missing sigs or signer keys for '{signer_name}'."); final_ok = False; errs.append(f"SubPkt {i+1} missing sigs/keys"); continue

                         pqc_key_b64 = signer_keys_info.get("pqc_b64")
                         ecdsa_pem_b64 = signer_keys_info.get("ecdsa_pem_b64")

                         if not pqc_key_b64 or not ecdsa_pem_b64:
                             print(f"[Verify] SubPkt {i+1} public key data missing for signer '{signer_name}'."); final_ok = False; errs.append(f"SubPkt {i+1} pubkey missing"); continue

                         try:
                             sp_data = base64.b64decode(sp_b64)
                             pqc_sig = base64.b64decode(pqc_sig_b64)
                             ecdsa_sig = base64.b64decode(ecdsa_sig_b64)
                             s_pqc_pub = base64.b64decode(pqc_key_b64)

                             if signer_name not in keys_cache:
                                 s_ecdsa_pem = base64.b64decode(ecdsa_pem_b64)
                                 keys_cache[signer_name] = serialization.load_pem_public_key(s_ecdsa_pem)
                             s_ecdsa_pub = keys_cache[signer_name]

                             pqc_sp_ok = verify_pqc_sig(sp_data, pqc_sig, s_pqc_pub)
                             ecdsa_sp_ok = verify_ecdsa_sig(sp_data, ecdsa_sig, s_ecdsa_pub)

                             if not (pqc_sp_ok and ecdsa_sp_ok):
                                 print(f"[Verify] SubPkt {i+1} sig by '{signer}' FAILED (PQC:{pqc_sp_ok}, ECDSA:{ecdsa_sp_ok})."); final_ok = False; errs.append(f"Signer {signer} sig fail")
                             # else: print(f"[Verify] SubPkt {i+1} sig by '{signer}' OK.") # Less verbose
                             reassembled += sp_data
                         except Exception as e:
                             print(f"[Verify] Error decoding/loading SubPkt {i+1} data/keys: {e}"); final_ok = False; errs.append(f"SubPkt {i+1} decode error"); continue

                    # 3. Check Reassembly safely
                    if final_ok and pld.get("orig_data_b64"): # Check original data exists
                         if reassembled != base64.b64decode(pld["orig_data_b64"]):
                              print("[Verify] Reassembly FAILED!"); final_ok = False; errs.append("Reassembly mismatch")
                         # else: print("[Verify] Reassembly OK.")

                except Exception as e: # Catch errors during the main try block
                    print(f"[Verify] Bundle verify error: {e}"); final_ok = False; errs.append(f"Processing err: {e}")

                if final_ok: print(f"--- WS Verify SUCCESS (Pkt: {pkt_id}) ---")
                else: print(f"--- WS Verify FAILED (Pkt: {pkt_id}) --- Errors: {errs}")

            else: print(f"[{node}] Unexpected msg type: {msg.get('type')}")
        except asyncio.CancelledError: print(f"[{node}] Workstation loop cancelled."); break
        except Exception as e:
            # This is the catch block that was likely triggering the 'NoneType' error before
            print(f"[{node}] Workstation loop error: {e}")
            break # Break loop on error to allow reconnect attempt by run_client

async def run_client(node_type: str, node_name: str, ctrl_host: str, ctrl_port: int):
    print(f"--- Simplified Hybrid Client ---")
    print(f"Init {node_type}: {node_name} -> {ctrl_host}:{ctrl_port}")
    print("(!) Ensure OQS versions are compatible!")
    try: keys = DeviceKeys(PQC_SIG_ALG, ECC_CURVE)
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
            ecdsa_b64 = base64.b64encode(keys.get_ecdsa_pub_pem()).decode('ascii')
            reg_msg = { "type": f"register_{node_type.lower()}", "name": node_name,
                        "pqc_public_key_b64": pqc_b64, "ecdsa_public_key_pem_b64": ecdsa_b64 }
            if not await send_msg(writer, reg_msg): raise ConnectionError("Failed send reg")
            ack = await asyncio.wait_for(read_msg(reader), timeout=10.0)
            if ack and ack.get("status") == "OK" and ack.get("node_type") == node_type: print(f"[{node_name}] Registered.")
            else: raise ConnectionError(f"Reg failed: {ack}")

            if node_type == "Sensor": task = asyncio.create_task(sensor_loop(node_name, writer, keys, SENSOR_DATA_INTERVAL_SECONDS))
            elif node_type == "Signer": task = asyncio.create_task(signer_loop(node_name, reader, writer, keys))
            elif node_type == "Workstation": task = asyncio.create_task(workstation_loop(node_name, reader, writer))
            else: print(f"[{node_name}] Unknown type."); break
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

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python client_final.py <Type> <Name> <Host:Port>")
        print("  Type: Sensor, Signer, or Workstation")
        sys.exit(1)
    node_type, node_name, ctrl_addr = sys.argv[1], sys.argv[2], sys.argv[3]
    valid_types = ["Sensor", "Signer", "Workstation"]
    if node_type not in valid_types: print(f"Invalid Type '{node_type}'."); sys.exit(1)
    try: host, port_str = ctrl_addr.split(':'); port = int(port_str)
    except ValueError: print(f"Invalid address '{ctrl_addr}'."); sys.exit(1)

    try: asyncio.run(run_client(node_type, node_name, host, port))
    except KeyboardInterrupt: print(f"\n[{node_name}] Client stopped.")
    except Exception as e: print(f"[{node_name}] Fatal error: {e}")
