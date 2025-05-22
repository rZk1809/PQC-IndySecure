import asyncio
import json
import time
import random
import oqs  # Requires PQC support for "ML-DSA-44"
import base64
import socket

# --- Configuration ---
HOST = '127.0.0.1'
PORT = 8892
SIG_ALG = "ML-DSA-44"

# Global dictionaries to store connected node info and their public keys.
connected_nodes = {}       # { node_name: { 'reader': StreamReader, 'writer': StreamWriter, 'busy': bool } }
node_key_registry = {}     # { node_name: public_key (bytes) }
node_lock = asyncio.Lock()

# --- PQC Signature Verification ---
def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    try:
        verifier = oqs.Signature(SIG_ALG)
        return verifier.verify(message, signature, public_key)
    except Exception as e:
        print(f"[Controller] Signature verification error: {e}")
        return False

# --- Utility: Split a bytes object into a given number of parts ---
def split_data(data: bytes, parts: int) -> list:
    if parts <= 0 or len(data) == 0:
        return []
    if parts == 1 or parts >= len(data):
        return [data]
    try:
        indices = sorted(random.sample(range(1, len(data)), parts - 1))
    except ValueError:
        indices = sorted(random.sample(range(1, len(data)), max(1, min(parts - 1, len(data) - 1))))
    indices = [0] + indices + [len(data)]
    return [data[indices[i]:indices[i+1]] for i in range(len(indices)-1)]

# --- Network Message Helpers ---
async def send_message(writer: asyncio.StreamWriter, message: dict) -> bool:
    try:
        # Convert bytes objects into base64 strings
        message_json = json.dumps(message, default=lambda obj: base64.b64encode(obj).decode('ascii') if isinstance(obj, bytes) else obj).encode('utf-8')
        writer.write(len(message_json).to_bytes(4, 'big'))
        writer.write(message_json)
        await writer.drain()
        return True
    except Exception as e:
        print(f"[Controller] Error sending message: {e}")
        return False

async def read_message(reader: asyncio.StreamReader) -> dict or None:
    try:
        header = await reader.readexactly(4)
        msg_len = int.from_bytes(header, 'big')
        if msg_len > 5 * 1024 * 1024:  # 5MB limit
            print(f"[Controller] Message length {msg_len} exceeds limit")
            return None
        msg_json = await reader.readexactly(msg_len)
        return json.loads(msg_json.decode('utf-8'))
    except Exception as e:
        print(f"[Controller] Error reading message: {e}")
        return None

# --- Select an Available Node (first one found which is not busy) ---
async def select_node():
    async with node_lock:
        for name, info in connected_nodes.items():
            if not info['busy']:
                info['busy'] = True
                return name, info['reader'], info['writer']
    # If no node is free, wait briefly
    await asyncio.sleep(0.05)
    return None

# --- Issue a Signing Request to a Node ---
async def sign_task(subpacket: bytes, node_name: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> dict:
    task_id = f"task_{random.randint(1000, 9999)}"
    result = {"node": node_name, "task_id": task_id, "signature": None, "success": False}
    request = {"type": "sign_request_pqc", "subpacket": subpacket, "task_id": task_id}
    start_time = time.time()
    try:
        if not await send_message(writer, request):
            result["error"] = "Failed to send request"
            return result
        response = await asyncio.wait_for(read_message(reader), timeout=10)
        if response and response.get("type") == "sign_response_pqc" and response.get("task_id") == task_id:
            sig_b64 = response.get("signature")
            if sig_b64:
                result["signature"] = base64.b64decode(sig_b64)
                result["success"] = True
                print(f"[Controller] Task {task_id} from {node_name} succeeded in {time.time()-start_time:.4f} s.")
            else:
                result["error"] = response.get("error", "Missing signature")
        else:
            result["error"] = "Invalid response"
    except Exception as e:
        result["error"] = str(e)
    async with node_lock:
        if node_name in connected_nodes:
            connected_nodes[node_name]['busy'] = False
    return result

# --- Handle Node Registration and Keep Connection Alive ---
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info('peername')
    print(f"[Controller] New connection from {peer}")
    try:
        reg = await asyncio.wait_for(read_message(reader), timeout=15)
    except asyncio.TimeoutError:
        print(f"[Controller] Timeout waiting for registration from {peer}")
        writer.close()
        await writer.wait_closed()
        return

    if reg and reg.get("type") == "register_pqc":
        node_name = reg.get("name")
        pub_key_b64 = reg.get("public_key")
        if not node_name or not pub_key_b64:
            print(f"[Controller] Invalid registration from {peer}: missing name or public key")
            await send_message(writer, {"type": "register_ack", "status": "Error", "detail": "Missing data"})
            writer.close()
            await writer.wait_closed()
            return
        try:
            pub_key = base64.b64decode(pub_key_b64)
        except Exception as e:
            print(f"[Controller] Error decoding public key from {peer}: {e}")
            await send_message(writer, {"type": "register_ack", "status": "Error", "detail": "Invalid public key"})
            writer.close()
            await writer.wait_closed()
            return

        async with node_lock:
            connected_nodes[node_name] = {"reader": reader, "writer": writer, "busy": False}
            node_key_registry[node_name] = pub_key
        print(f"[Controller] Registered node: {node_name}")
        await send_message(writer, {"type": "register_ack", "status": "OK"})
    else:
        print(f"[Controller] Invalid registration attempt from {peer}")
        await send_message(writer, {"type": "register_ack", "status": "Error", "detail": "Invalid registration"})
        writer.close()
        await writer.wait_closed()
        return

    try:
        while not reader.at_eof():
            await asyncio.sleep(1)
    except Exception as e:
        print(f"[Controller] Error during connection with {node_name}: {e}")
    finally:
        async with node_lock:
            if reg.get("name") in connected_nodes:
                print(f"[Controller] Unregistering node: {reg.get('name')}")
                del connected_nodes[reg.get("name")]
        writer.close()
        await writer.wait_closed()

# --- Periodic Signing Test Loop ---
async def signing_loop(num_tests=10, interval=3):
    # Wait a little to let nodes connect.
    await asyncio.sleep(3)
    for i in range(num_tests):
        print(f"\n[Controller] Test cycle {i + 1}")
        async with node_lock:
            if not connected_nodes:
                print("[Controller] No nodes available.")
                await asyncio.sleep(interval)
                continue
            node_count = len(connected_nodes)
        message = f"Test message {i + 1} at {time.time()}".encode('utf-8')
        parts = min(node_count, 3)  # Use up to 3 parts
        subpackets = split_data(message, parts)
        tasks = []
        for sp in subpackets:
            node_info = await select_node()
            if node_info is None:
                print("[Controller] No available node for a subpacket!")
                continue
            node_name, r, w = node_info
            tasks.append(sign_task(sp, node_name, r, w))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_ok = True
        for idx, res in enumerate(results):
            if isinstance(res, Exception) or not res.get("success"):
                print(f"[Controller] Subpacket {idx + 1}: Failed ({res})")
                all_ok = False
            else:
                node = res.get("node")
                sig = res.get("signature")
                pub = node_key_registry.get(node)
                if pub and verify_signature(subpackets[idx], sig, pub):
                    print(f"[Controller] Subpacket {idx + 1}: Verified signature from {node}")
                else:
                    print(f"[Controller] Subpacket {idx + 1}: Invalid signature from {node}")
                    all_ok = False
        if all_ok:
            print("[Controller] Test successful!")
        else:
            print("[Controller] Test failed!")
        await asyncio.sleep(interval)

# --- Main Controller Function ---
async def main_controller():
    try:
        # Check if the PQC algorithm is supported.
        oqs.Signature(SIG_ALG)
    except Exception as e:
        print(f"[Controller] PQC algorithm {SIG_ALG} not supported: {e}")
        return

    test_task = asyncio.create_task(signing_loop(num_tests=10))
    server = await asyncio.start_server(handle_client, HOST, PORT)
    for sock in server.sockets:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    addr = server.sockets[0].getsockname()
    print(f"[Controller] Server listening on {addr}")

    async with server:
        await asyncio.gather(server.serve_forever(), test_task)

if __name__ == "__main__":
    asyncio.run(main_controller())

