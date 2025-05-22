# controller_final.py
import asyncio
import json
import time
import random
import oqs
import base64
import socket
from contextlib import suppress

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("FATAL ERROR: 'cryptography' library not found. Please install it: pip install cryptography")
    exit()

CONTROLLER_HOST = '127.0.0.1'
CONTROLLER_PORT = 8904 # Port from your recent logs
PQC_SIG_ALG = "ML-DSA-44"
ECC_CURVE = ec.SECP384R1()
ECC_HASH_ALG = hashes.SHA384()
SIMULATE_SENSOR_INPUT = True
SIMULATION_INTERVAL = 5.0
SIMULATION_COUNT = 10

connected_nodes = {}
state_lock = asyncio.Lock()
data_queue = asyncio.Queue()
shutdown_flag = asyncio.Event()

def verify_pqc_sig(message: bytes, signature: bytes, pub_key: bytes) -> bool:
    if not all([message, signature, pub_key]): return False
    try:
        verifier = oqs.Signature(PQC_SIG_ALG)
        is_valid = verifier.verify(message, signature, pub_key)
        if not is_valid: print("[Verify] PQC Verification FAILED")
        return is_valid
    except Exception as e:
        print(f"[Verify] PQC Verify Error: {e}")
        return False

def verify_ecdsa_sig(message: bytes, signature: bytes, pub_key) -> bool:
    if not all([message, signature, pub_key]): return False
    try:
        pub_key.verify(signature, message, ec.ECDSA(ECC_HASH_ALG))
        return True
    except InvalidSignature:
        print("[Verify] ECDSA Verification FAILED (InvalidSignature)")
        return False
    except Exception as e:
        print(f"[Verify] ECDSA Verify Error: {e}")
        return False

def create_data_packet(pkt_id: str) -> bytes:
    timestamp = time.time()
    payload = { "T": round(random.uniform(15, 35), 1), "H": round(random.uniform(30, 70), 1), "St": random.choice(["OK", "WARN", "ERR"]) }
    pkt_dict = { "id": pkt_id, "ts": timestamp, "src": "SimSensor", "pld": payload }
    return json.dumps(pkt_dict, separators=(',', ':')).encode('utf-8')

def deserialize_packet(data: bytes) -> dict | None:
    try: return json.loads(data.decode('utf-8'))
    except Exception as e: print(f"[Process] Failed deserialize: {e}. Data: {data[:100]}"); return None

def split_data(data: bytes, n_splits: int) -> list[bytes]:
    total_len = len(data)
    if n_splits <= 0 or total_len == 0: return []
    if n_splits == 1 or n_splits >= total_len: return [data]
    try:
        count = min(n_splits - 1, total_len - 1)
        if count <= 0: return [data]
        indices = sorted(random.sample(range(1, total_len), count))
    except ValueError: return [data]
    indices = [0] + indices + [total_len]
    sub_pkts = [data[indices[i]:indices[i+1]] for i in range(len(indices) - 1)]
    return [sp for sp in sub_pkts if sp]

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

async def select_signer() -> tuple[str, asyncio.StreamWriter] | None:
    while not shutdown_flag.is_set():
        async with state_lock:
            available = [(name, info) for name, info in connected_nodes.items()
                         if info.get('node_type') == 'Signer' and not info.get('busy')]
            if available:
                 chosen_name, chosen_info = random.choice(available)
                 chosen_info['busy'] = True
                 print(f"[Scheduler] Assigning SIGN task to '{chosen_name}'")
                 return chosen_name, chosen_info['writer']
            else:
                 signer_exists = any(i.get('node_type') == 'Signer' for i in connected_nodes.values())
                 wait_time = 2.0 if not signer_exists else 0.1
                 if not signer_exists: print("[Scheduler] SIGN: No Signers connected. Waiting...")
        await asyncio.sleep(wait_time)
    print("[Scheduler] Shutdown signalled, stopping selection.")
    return None

async def request_hybrid_sig(sub_pkt_data: bytes, node_name: str, writer: asyncio.StreamWriter) -> dict:
    task_id = f"hyb_{node_name}_{random.randint(1000,9999)}"
    req = {"type": "sign_request_hybrid", "subpacket": sub_pkt_data, "task_id": task_id}
    res = {"signer": node_name, "subpacket_data": sub_pkt_data, "task_id": task_id,
              "pqc_sig": None, "ecdsa_sig": None, "ok": False, "err": None}
    start_time = time.monotonic()
    reader = None
    node_info = None
    async with state_lock: node_info = connected_nodes.get(node_name)
    if node_info: reader = node_info.get('reader')

    if not reader or reader.at_eof():
         res["err"] = "Node disconnected or reader missing before response read"
         print(f"[Task {task_id}] ERROR: Reader missing/closed for '{node_name}'")
         async with state_lock:
             if node_info := connected_nodes.get(node_name): node_info['busy'] = False
         return res

    try:
        if not await send_msg(writer, req):
            res["err"] = "Send fail (Connection Error)"
            raise ConnectionError("Send failed")

        resp = await asyncio.wait_for(read_msg(reader), timeout=30.0)

        if resp and resp.get("type") == "sign_response_hybrid" and resp.get("task_id") == task_id:
            pqc_b64 = resp.get("pqc_signature_b64")
            ecdsa_b64 = resp.get("ecdsa_signature_b64")
            err_msg = resp.get("error")
            if err_msg:
                res["err"] = f"Client error: {err_msg}"
            elif pqc_b64 and ecdsa_b64:
                try:
                    res["pqc_sig"] = base64.b64decode(pqc_b64)
                    res["ecdsa_sig"] = base64.b64decode(ecdsa_b64)
                    res["ok"] = True
                    dur = time.monotonic() - start_time
                    print(f"[Task {task_id}] OK from '{node_name}'. Duration: {dur:.3f}s.")
                except Exception as e:
                    res["err"] = f"Decode error: {e}"
            else:
                res["err"] = "Response missing sigs"
        elif resp is None:
             res["err"] = "Connection lost waiting for resp"
        else:
            res["err"] = f"Unexpected response: {resp.get('type')}/{resp.get('task_id')}"

    except asyncio.TimeoutError: res["err"] = "Timeout waiting for sig response"
    except ConnectionError as e: res["err"] = f"Connection error: {e}"
    except Exception as e: res["err"] = f"Unexpected exception: {e}"; print(f"[Task {task_id}] UNEXPECTED ERROR '{node_name}': {e}")
    finally:
        async with state_lock:
            current_node_info = connected_nodes.get(node_name)
            if current_node_info and current_node_info.get('writer') is writer and current_node_info.get('busy'):
                 current_node_info['busy'] = False
    if not res["ok"]: print(f"[Task {task_id}] FAILED for '{node_name}': {res['err']}")
    return res

async def assign_and_run_signing_task(sp_data: bytes, sub_pkt_index: int, pkt_id: str) -> dict | Exception:
    signer_info = None
    signer_name = None
    writer = None
    try:
        signer_info = await select_signer()
        if signer_info:
            signer_name, writer = signer_info
            result = await request_hybrid_sig(sp_data, signer_name, writer)
            return result
        elif shutdown_flag.is_set():
            print(f"[Assigner] Shutdown during selection Pkt '{pkt_id}' SubPkt {sub_pkt_index+1}.")
            return ConnectionAbortedError("Shutdown")
        else:
            print(f"[Assigner] Failed select signer Pkt '{pkt_id}' SubPkt {sub_pkt_index+1}.")
            return TimeoutError("Failed select signer")
    except Exception as e:
        print(f"[Assigner] Error assign/run Pkt '{pkt_id}' SubPkt {sub_pkt_index+1}: {e}")
        if signer_info:
            signer_name, writer = signer_info
            async with state_lock:
                node_info = connected_nodes.get(signer_name)
                if node_info and node_info.get('writer') is writer and node_info.get('busy'):
                    node_info['busy'] = False
        return e

async def process_data_queue():
    print("[Processor] Starting data processing task...")
    while not shutdown_flag.is_set():
        origin_node, recv_msg = None, None
        try:
            origin_node, recv_msg = await asyncio.wait_for(data_queue.get(), timeout=1.0)
        except asyncio.TimeoutError: continue
        except Exception as e: print(f"[Processor] Queue Error: {e}"); continue

        print(f"[Processor] Processing data from '{origin_node}'...")
        is_sim = (origin_node == "SimulatedSensor")
        orig_data = None
        initial_ok = False
        origin_keys = {}
        orig_pqc_sig = None
        orig_ecdsa_sig = None

        if is_sim:
            orig_data = recv_msg.get("simulated_data_bytes")
            if not orig_data: print(f"[Processor] Sim msg missing data."); data_queue.task_done(); continue
            initial_ok = True
        else:
            data_b64 = recv_msg.get("data_b64")
            pqc_b64 = recv_msg.get("pqc_signature_b64")
            ecdsa_b64 = recv_msg.get("ecdsa_signature_b64")
            if not all([data_b64, pqc_b64, ecdsa_b64]): print(f"[Processor] Invalid sensor msg from '{origin_node}'."); data_queue.task_done(); continue
            try:
                orig_data = base64.b64decode(data_b64)
                orig_pqc_sig = base64.b64decode(pqc_b64)
                orig_ecdsa_sig = base64.b64decode(ecdsa_b64)
                async with state_lock:
                     node_info = connected_nodes.get(origin_node)
                     if node_info:
                         origin_keys['pqc_pub'] = node_info.get('pqc_pub')
                         origin_keys['ecdsa_pub'] = node_info.get('ecdsa_pub')
                if not origin_keys.get('pqc_pub') or not origin_keys.get('ecdsa_pub'): print(f"[Processor] Keys missing for '{origin_node}'."); data_queue.task_done(); continue

                pqc_ok = verify_pqc_sig(orig_data, orig_pqc_sig, origin_keys['pqc_pub'])
                ecdsa_ok = verify_ecdsa_sig(orig_data, orig_ecdsa_sig, origin_keys['ecdsa_pub'])
                if pqc_ok and ecdsa_ok: initial_ok = True
                else: print(f"[Processor] Initial HYBRID verify FAILED '{origin_node}'."); data_queue.task_done(); continue
            except Exception as e: print(f"[Processor] Error initial verify '{origin_node}': {e}"); data_queue.task_done(); continue

        if not initial_ok: data_queue.task_done(); continue

        pkt_dict = deserialize_packet(orig_data)
        pkt_id = pkt_dict.get("id", f"NoID_{random.randint(100,999)}") if pkt_dict else f"Raw_{random.randint(100,999)}"
        print(f"[Processor] Processing packet ID '{pkt_id}' from '{origin_node}' for re-signing...")

        n_splits = 2
        sub_pkts = split_data(orig_data, n_splits)
        if not sub_pkts: print(f"[Processor] Failed split data for '{pkt_id}'."); data_queue.task_done(); continue
        print(f"[Processor] Split packet '{pkt_id}' into {len(sub_pkts)} parts.")

        assign_sign_tasks = []
        for i, sp_data in enumerate(sub_pkts):
            assign_sign_tasks.append(
                asyncio.create_task(assign_and_run_signing_task(sp_data, i, pkt_id))
            )

        if not assign_sign_tasks: print(f"[Processor] No signing tasks created for '{pkt_id}'."); data_queue.task_done(); continue
        print(f"[Processor] Waiting for {len(assign_sign_tasks)} re-sign tasks for '{pkt_id}'...")
        sig_results = await asyncio.gather(*assign_sign_tasks, return_exceptions=True)

        bundle_parts = []
        final_ok = True
        signer_keys_for_bundle = {}
        verified_count = 0

        for i, res in enumerate(sig_results):
            if isinstance(res, (Exception, TimeoutError, ConnectionAbortedError)): print(f"[Processor] Task {i+1} '{pkt_id}' FAILED (Exception/Timeout/Abort): {type(res).__name__}"); final_ok = False; continue
            if not isinstance(res, dict) or not res.get('ok'): print(f"[Processor] Task {i+1} '{pkt_id}' FAILED (Reported): {res.get('err')}"); final_ok = False; continue

            signer_name = res['signer']
            sp_data = res['subpacket_data']
            pqc_sig = res['pqc_sig']
            ecdsa_sig = res['ecdsa_sig']
            s_keys = {}
            async with state_lock:
                if node_info := connected_nodes.get(signer_name):
                     s_keys['pqc_pub'] = node_info.get('pqc_pub')
                     s_keys['ecdsa_pub'] = node_info.get('ecdsa_pub')

            if not s_keys.get('pqc_pub') or not s_keys.get('ecdsa_pub'): print(f"[Processor] Keys missing for signer '{signer_name}' re-verify."); final_ok = False; continue

            pqc_ok = verify_pqc_sig(sp_data, pqc_sig, s_keys['pqc_pub'])
            ecdsa_ok = verify_ecdsa_sig(sp_data, ecdsa_sig, s_keys['ecdsa_pub'])

            if pqc_ok and ecdsa_ok:
                verified_count += 1
                try:
                    pqc_pub_b64 = base64.b64encode(s_keys['pqc_pub']).decode('ascii')
                    ecdsa_pem = s_keys['ecdsa_pub'].public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                    ecdsa_pem_b64 = base64.b64encode(ecdsa_pem).decode('ascii')
                    bundle_parts.append({
                        "sp_b64": base64.b64encode(sp_data).decode('ascii'), "signer": signer_name,
                        "sigs": {"pqc_b64": base64.b64encode(pqc_sig).decode('ascii'), "ecdsa_b64": base64.b64encode(ecdsa_sig).decode('ascii')}
                    })
                    if signer_name not in signer_keys_for_bundle: signer_keys_for_bundle[signer_name] = {"pqc_b64": pqc_pub_b64, "ecdsa_pem_b64": ecdsa_pem_b64}
                except Exception as e: print(f"[Processor] Error prep bundle part {i+1}: {e}"); final_ok = False; break
            else:
                print(f"[Processor] Re-sig verify FAILED subpacket {i+1} by '{signer_name}' (PQC:{pqc_ok}, ECC:{ecdsa_ok})!")
                final_ok = False; break

        if final_ok and verified_count == len(sub_pkts):
            target_station = "Station_B"
            print(f"[Processor] Packet '{pkt_id}' processed OK. Preparing bundle for '{target_station}'.")
            orig_info = None
            if not is_sim and orig_data is not None and orig_pqc_sig is not None and orig_ecdsa_sig is not None:
                 try:
                     orig_pqc_b64 = base64.b64encode(origin_keys['pqc_pub']).decode('ascii')
                     orig_ecdsa_pem = origin_keys['ecdsa_pub'].public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                     orig_ecdsa_b64 = base64.b64encode(orig_ecdsa_pem).decode('ascii')
                     orig_info = {
                         "node": origin_node,
                         "sigs": {"pqc_b64": base64.b64encode(orig_pqc_sig).decode('ascii'), "ecdsa_b64": base64.b64encode(orig_ecdsa_sig).decode('ascii')},
                         "keys": {"pqc_b64": orig_pqc_b64, "ecdsa_pem_b64": orig_ecdsa_b64}
                     }
                 except Exception as e: print(f"[Processor] Error prep origin info: {e}")

            bundle = {
                "type": "verified_hybrid_bundle", "target": target_station,
                "payload": {
                    "pkt_id": pkt_id, "orig_data_b64": base64.b64encode(orig_data).decode('ascii'),
                    "origin": orig_info, "sub_pkts": bundle_parts, "signer_keys": signer_keys_for_bundle
                }
            }
            async with state_lock: ws_info = connected_nodes.get(target_station)
            if ws_info and ws_info.get('node_type') == 'Workstation' and ws_info.get('writer'):
                if await send_msg(ws_info['writer'], bundle): print(f"[Processor] Bundle '{pkt_id}' sent to '{target_station}'.")
                else: print(f"[Processor] Failed send bundle '{pkt_id}' to '{target_station}'.")
            else: print(f"[Processor] Target '{target_station}' unavailable for bundle '{pkt_id}'.")
        else:
            print(f"[Processor] Packet '{pkt_id}' FAILED final stage (Success: {final_ok}, Parts OK: {verified_count}/{len(sub_pkts)}). Bundle not sent.")

        data_queue.task_done()

    print("[Processor] Data processing task finished.")

async def simulate_sensor_input():
    print(f"[Simulator] Starting ({SIMULATION_COUNT} packets, interval {SIMULATION_INTERVAL}s)...")
    await asyncio.sleep(3)
    for i in range(SIMULATION_COUNT):
        if shutdown_flag.is_set(): print("[Simulator] Shutdown."); break
        pkt_id = f"SIM_{int(time.time())}_{i+1:03d}"
        print(f"[Simulator] Generating packet {i+1}/{SIMULATION_COUNT} (ID: {pkt_id})...")
        sim_data = create_data_packet(pkt_id)
        sim_msg = {"simulated_data_bytes": sim_data}
        await data_queue.put(("SimulatedSensor", sim_msg))
        await asyncio.sleep(SIMULATION_INTERVAL)
    print("[Simulator] Finished generating packets.")
    
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peername = 'Unknown Peer'
    node_name_reg = None
    node_type_reg = None
    try:
        peername = str(writer.get_extra_info('peername', '?'))
        print(f"[Server] Connection from {peername}")

        reg_msg = await asyncio.wait_for(read_msg(reader), timeout=20.0)
        if not reg_msg: raise ConnectionError("Closed before registration")

        reg_type = reg_msg.get("type")
        node_name = reg_msg.get("name")
        pqc_b64 = reg_msg.get("pqc_public_key_b64")
        ecdsa_b64 = reg_msg.get("ecdsa_public_key_pem_b64")
        valid_type = None
        if reg_type == "register_sensor": valid_type = "Sensor"
        elif reg_type == "register_signer": valid_type = "Signer"
        elif reg_type == "register_workstation": valid_type = "Workstation"

        if node_name and valid_type and pqc_b64 and ecdsa_b64:
            try:
                pqc_pub = base64.b64decode(pqc_b64)
                ecdsa_pem = base64.b64decode(ecdsa_b64)
                ecdsa_pub = serialization.load_pem_public_key(ecdsa_pem)

                async with state_lock:
                    if node_name in connected_nodes:
                        old_peer = connected_nodes[node_name].get('peername','?')
                        print(f"[Server] Node '{node_name}' reconnected from {peername}. Closing old from {old_peer}.")
                        old_writer = connected_nodes[node_name].get('writer')
                        if old_writer and not old_writer.is_closing(): old_writer.close()
                    connected_nodes[node_name] = {
                        'reader': reader, 'writer': writer, 'node_type': valid_type, 'busy': False,
                        'pqc_pub': pqc_pub, 'ecdsa_pub': ecdsa_pub, 'peername': peername
                    }
                    node_name_reg = node_name
                    node_type_reg = valid_type

                print(f"[Server] Registered '{valid_type}' node: '{node_name}' from {peername}")
                await send_msg(writer, {"type": "register_ack", "status": "OK", "node_type": valid_type})
            except Exception as e:
                print(f"[Server] Reg key error for '{node_name or peername}': {e}")
                await send_msg(writer, {"type": "register_ack", "status": "Error", "detail": f"Invalid key: {e}"})
                return
        else:
            print(f"[Server] Reg failed for {peername}: Invalid message.")
            await send_msg(writer, {"type": "register_ack", "status": "Error", "detail": "Invalid registration"})
            return

        if node_type_reg == "Sensor":
            print(f"[Server] Sensor '{node_name_reg}' connected. Waiting for data...")
            while not shutdown_flag.is_set():
                msg = await read_msg(reader)
                if msg is None: print(f"[Server] Sensor '{node_name_reg}' disconnected."); break
                if msg.get("type") == "sensor_data_signed_hybrid":
                     if all(k in msg for k in ["data_b64", "pqc_signature_b64", "ecdsa_signature_b64"]):
                          await data_queue.put((node_name_reg, msg))
                     else: print(f"[Server] Invalid sensor msg from '{node_name_reg}'.")
                else: print(f"[Server] Unexpected msg type '{msg.get('type')}' from Sensor '{node_name_reg}'.")
        elif node_type_reg in ["Signer", "Workstation"]:
             print(f"[Server] {node_type_reg} '{node_name_reg}' connected. Monitoring.")
             while not shutdown_flag.is_set():
                  if reader.at_eof(): print(f"[Server] {node_type_reg} '{node_name_reg}' disconnected (EOF)."); break
                  await asyncio.sleep(2)

    except (asyncio.TimeoutError, ConnectionError, asyncio.IncompleteReadError, BrokenPipeError, OSError) as e:
        state = "registered" if node_name_reg else "pre-reg"
        print(f"[Server] Connection {peername} ('{node_name_reg or 'N/A'}') ended ({state}): {type(e).__name__}")
    except Exception as e:
        print(f"[Server] UNEXPECTED ERROR handling '{peername}' ('{node_name_reg or 'Unreg'}'): {e}")
    finally:
        if node_name_reg:
            async with state_lock:
                current_info = connected_nodes.get(node_name_reg)
                if current_info and current_info.get('writer') is writer:
                    print(f"[Server] Unregistering node: '{node_name_reg}'")
                    del connected_nodes[node_name_reg]
        if writer and not writer.is_closing():
            writer.close()
            with suppress(Exception): await writer.wait_closed()

async def start_controller():
    print("--- Simplified Hybrid Controller ---")
    print("(!) IMPORTANT: Ensure liboqs and oqs-python versions are compatible!")
    server = None
    proc_task = None
    sim_task = None
    try:
        try: oqs.Signature(PQC_SIG_ALG); ec.generate_private_key(ECC_CURVE); print("[Controller] Crypto libs OK.")
        except Exception as e: print(f"FATAL: Crypto init check failed: {e}"); return

        proc_task = asyncio.create_task(process_data_queue())
        if SIMULATE_SENSOR_INPUT: sim_task = asyncio.create_task(simulate_sensor_input())

        server = await asyncio.start_server(handle_client, CONTROLLER_HOST, CONTROLLER_PORT)
        addr = server.sockets[0].getsockname()
        print(f"[Server] Listening on {addr}")
        print("[Controller] Ready.")

        async with server: await shutdown_flag.wait()

    except OSError as e: print(f"FATAL: Server start failed {CONTROLLER_HOST}:{CONTROLLER_PORT}: {e}")
    except asyncio.CancelledError: print("[Controller] Main task cancelled.")
    except Exception as e: print(f"[Controller] Unexpected error main: {e}")
    finally:
        print("[Controller] Shutting down...")
        shutdown_flag.set()
        if server:
            server.close()
            await server.wait_closed()
            print("[Controller] Server closed.")
        for task in [proc_task, sim_task]:
            if task and not task.done():
                task.cancel()
                with suppress(asyncio.CancelledError): await task
        with suppress(asyncio.TimeoutError):
            print("[Controller] Waiting for queue...")
            await asyncio.wait_for(data_queue.join(), timeout=2.0)
        print("[Controller] Closing clients...")
        async with state_lock: active_conns = list(connected_nodes.values())
        closed_count = 0
        close_tasks = []
        for info in active_conns:
             writer = info.get('writer')
             if writer and not writer.is_closing():
                  writer.close()
                  closed_count += 1
                  # Create task for waiting but don't await here
                  close_tasks.append(asyncio.create_task(writer.wait_closed()))
        # Wait for all closing tasks concurrently outside the lock
        if close_tasks:
            print(f"[Controller] Waiting for {closed_count} connections to close...")
            await asyncio.gather(*close_tasks, return_exceptions=True)

        print("[Controller] Shutdown complete.")

if __name__ == "__main__":
    try: asyncio.run(start_controller())
    except KeyboardInterrupt: print("\n[Controller] Shutdown requested...")
    except Exception as e: print(f"FATAL ERROR: {e}")
