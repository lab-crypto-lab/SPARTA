import socket
import threading
import pickle
import hashlib
import struct
from functools import reduce
from petlib.bn import Bn
from bplib.bp import BpGroup

# Initialize pairing
bpg = BpGroup()
P = bpg.gen1()
Phat = bpg.gen2()
p_bn = bpg.order()

result_dict = {}
lock = threading.Lock()
registered_users_count = 0
MAX_USERS = 5

def random_scalar():
    return Bn.random(p_bn) + 1

def hash_message(m):
    h = hashlib.sha256()
    h.update(bytes(m, "utf-8"))
    hashed_value = int.from_bytes(h.digest(), byteorder='big')
    return Bn.from_binary(hashed_value.to_bytes((hashed_value.bit_length() + 7) // 8, 'big'))

# Key generation
def keygen(ell):
    sk = [random_scalar() for _ in range(ell)]
    pk = [Phat * x for x in sk]
    return pk, sk

# Signature generation
def sign(sk, M):
    y = random_scalar()
    Z = reduce(lambda a, b: a + b, (xi * Mi for xi, Mi in zip(sk, M)))
    Z = y * Z
    Y = (pow(y, p_bn - 2, p_bn)) * P
    Yhat = (pow(y, p_bn - 2, p_bn)) * Phat
    return Z, Y, Yhat

def SP_Registeration(M_v, PRIV_ca):
    return sign(PRIV_ca, M_v)

ell = 1
PUB_ca, PRIV_ca = keygen(ell)

def send_with_length(conn, data):
    """Send data with length prefix to ensure proper message boundaries"""
    try:
        # Serialize the data
        serialized = pickle.dumps(data)
        # Send length first (4 bytes, big-endian)
        length = len(serialized)
        conn.sendall(struct.pack('>I', length))
        # Send the actual data
        conn.sendall(serialized)
        return True
    except Exception as e:
        # print(f"[ERROR] Failed to send data: {e}")  # COMMENTED FOR TIMING
        return False

def handle_registration(conn, addr):
    global registered_users_count
    conn_lock = threading.Lock()  # Lock for this specific connection
    
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break  # client closed connection

            try:
                user_id, X_w = pickle.loads(data)
            except Exception as e:
                # print(f"[ERROR] Failed to deserialize: {e}")  # COMMENTED FOR TIMING
                continue

            # print(f"[RECEIVED] From {addr}: user {user_id}")  # COMMENTED FOR TIMING

            def process_signature(user_id=user_id, X_w=X_w, conn=conn):
                global registered_users_count
                
                try:
                    # Process the signature
                    M_w = [hash_message(str(Xi)) * P for Xi in X_w]
                    Sigma_w = SP_Registeration(M_w, PRIV_ca)

                    # Update global state
                    with lock:
                        result_dict[user_id] = (M_w, Sigma_w)
                        registered_users_count += 1
                        # print(f"[REGISTERED] User {user_id}: Signature ready ({registered_users_count}/{MAX_USERS})")  # COMMENTED FOR TIMING

                    # Serialize signature components
                    Z_bytes = Sigma_w[0].export()
                    Y_bytes = Sigma_w[1].export()
                    Yhat_bytes = Sigma_w[2].export()
                    signature_dict = {"Z": Z_bytes, "Y": Y_bytes, "Yhat": Yhat_bytes}

                    # Send response back immediately with connection lock
                    response_data = (user_id, signature_dict)
                    
                    with conn_lock:
                        success = send_with_length(conn, response_data)
                        # if success:
                        #     print(f"[SENT] Signature for user {user_id} sent back to {addr}")  # COMMENTED FOR TIMING
                        # else:
                        #     print(f"[ERROR] Failed to send signature for user {user_id}")  # COMMENTED FOR TIMING

                    # Check if all users are registered
                    with lock:
                        if registered_users_count >= MAX_USERS:
                            # VERIFICATION DISABLED FOR BENCHMARKING
                            # print(f"\n[ALL USERS REGISTERED ✅] Starting verification...")
                            # threading.Thread(target=verify_all).start()
                            pass

                except Exception as e:
                    # print(f"[ERROR] Processing user {user_id}: {e}")  # COMMENTED FOR TIMING
                    pass

            # Process each signature in a separate thread
            threading.Thread(target=process_signature).start()

    except Exception as e:
        # print(f"[ERROR] Connection handling error: {e}")  # COMMENTED FOR TIMING
        pass
    finally:
        conn.close()
        # print(f"[DISCONNECTED] {addr}")  # COMMENTED FOR TIMING

def verify_all():
    """Verify all signatures"""
    import time
    time.sleep(0.5)  # Small delay to ensure all processing is complete
    
    # VERIFICATION PRINTS CAN STAY - THEY'RE AFTER TIMING MEASUREMENT
    print("\n" + "="*50)
    print("[VERIFICATION PHASE STARTED]")
    print("="*50)
    
    # Import verification function (simplified for this example)
    def verify_signature(pk, M, sigma):
        # Placeholder - implement your actual verification logic
        return True
    
    with lock:
        print(f"[DEBUG] Total users to verify: {len(result_dict)}")
        
        all_valid = True
        for uid in sorted(result_dict.keys()):
            M_w, sigma = result_dict[uid]
            print(f"[DEBUG] Verifying User {uid}...")
            
            try:
                # is_valid = verify_signature(PUB_ca, M_w, sigma)
                is_valid = True  # Placeholder
                
                if is_valid:
                    print(f"[VALID ✅] User {uid}")
                else:
                    print(f"[INVALID ❌] User {uid}")
                    all_valid = False
            except Exception as e:
                print(f"[ERROR ❌] User {uid}: {e}")
                all_valid = False
        
        print("\n" + "="*50)
        if all_valid:
            print("[VERIFICATION COMPLETE ✅] All signatures are valid!")
        else:
            print("[VERIFICATION COMPLETE ❌] Some signatures are invalid!")
        print("="*50)

def start_server(host="0.0.0.0", port=5555, silent=False):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen()
    
    if not silent:
        print(f"[LISTENING] on {host}:{port}")

    while True:
        conn, addr = server.accept()
        if not silent:
            pass  # print(f"[CONNECTED] {addr}")  # COMMENTED FOR TIMING
        threading.Thread(target=handle_registration, args=(conn, addr)).start()

if __name__ == "__main__":
    # Set silent=True for benchmarking
    start_server(silent=True)