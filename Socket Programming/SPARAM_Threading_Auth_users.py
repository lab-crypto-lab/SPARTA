import hashlib
import bplib as bp
from bplib import bp
from bplib.bp import BpGroup, GTElem, G1Elem, G2Elem
from petlib.bn import Bn
from functools import reduce
import socket
import pickle
import time
import threading

# Initialize bilinear pairing group
bpg = BpGroup()
P = bpg.gen1()
Phat = bpg.gen2()
p_bn = bpg.order()

# Global variables for tracking
active_connections = 0
total_authentications = 0
lock = threading.Lock()

def random_scalar():
    return Bn.random(p_bn) + 1

def hash_message(m):
    h = hashlib.sha256()
    h.update(bytes(m, "utf-8"))
    hashed_value = int.from_bytes(h.digest(), byteorder='big')
    hash_reduced_bytes = hashed_value.to_bytes((hashed_value.bit_length() + 7) // 8, byteorder='big')
    c_bn = Bn.from_binary(hash_reduced_bytes)
    return c_bn

def keygen(ell):
    sk = [random_scalar() for _ in range(ell)]
    pk = [Phat * x for x in sk]
    return pk, sk

def sign(sk, M):
    y = random_scalar()
    Z = reduce(lambda a, b: a + b, (xi * Mi for xi, Mi in zip(sk, M)))
    Z = y * Z
    Y = (pow(y, p_bn-2, p_bn)) * P
    Yhat = (pow(y, p_bn-2, p_bn)) * Phat
    return Z, Y, Yhat

def verify(pk, M, sigma):
    Z, Y, Yhat = sigma
    lhs = reduce(lambda a, b: a * b, (bpg.pair(Mi, Xi) for Xi, Mi in zip(pk, M)))
    rhs1 = bpg.pair(Z, Yhat)
    rhs2 = bpg.pair(Y, Phat)
    rhs3 = bpg.pair(P, Yhat)
    return lhs == rhs1 and rhs2 == rhs3

def convert_sk(sk, rho):
    return [rho * x for x in sk]

def convert_pk(pk, rho):
    return [rho * X for X in pk]

def change_rep(pk, M, sigma, mu):
    Z, Y, Yhat = sigma
    psi = random_scalar()
    M0 = [mu * m for m in M]
    sigma0 = (
        psi * mu * Z,
        (pow(psi, p_bn-2, p_bn)) * Y,
        (pow(psi, p_bn-2, p_bn)) * Yhat,
    )
    return M0, sigma0

def handle_authentication(conn, addr, silent=True):
    """Handle a single authentication session"""
    global active_connections, total_authentications
    
    with lock:
        active_connections += 1
        session_id = total_authentications
        total_authentications += 1
    
    if not silent:
        print(f"[AUTH {session_id}] Started from {addr}")
    
    try:
        ell = 1
        
        # Step 1: Receive MSP keys from client
        data_ca_received = conn.recv(1024)
        if not data_ca_received:
            return
        
        data_ca_deserialized = pickle.loads(data_ca_received)
        PRIV_ca = [Bn.from_binary(s) for s in data_ca_deserialized["PRIV_ca"]]
        PUB_ca = [bp.G2Elem.from_bytes(pk, bpg) for pk in data_ca_deserialized["PUB_ca"]]
        
        # Send confirmation
        data_ca_reply = "MSP Keys received"
        conn.sendall(data_ca_reply.encode('utf-8'))
        
        # Verify MSP keys (optional - for testing)
        M = [hash_message(str(Xi)) * P for Xi in PUB_ca]
        sigma = sign(PRIV_ca, M)
        is_valid = verify(PUB_ca, M, sigma)
        
        if not silent:
            print(f"[AUTH {session_id}] MSP key verification: {is_valid}")
        
        # Create server's avatar (User V -> Avatar n)
        X_v, x_v = keygen(ell)
        M_v = [hash_message(str(Xi)) * P for Xi in X_v]
        Sigma_v = sign(PRIV_ca, M_v)
        
        # Create Avatar n
        mu_n = random_scalar()
        PRIV_Ava_n = convert_sk(x_v, mu_n)
        PUB_Ava_n_Original = convert_pk(X_v, mu_n)
        PUB_Ava_n, Sigma_v_dash = change_rep(PUB_ca, M_v, Sigma_v, mu_n)
        
        CERT_Ava_n = {
            'PUB_Ava_n': PUB_Ava_n,
            'Sigma_v_dash': Sigma_v_dash
        }
        
        # Step 2: Receive Round 1 from client (P1 + certificates)
        data = conn.recv(8192)
        received_data_Auth_1 = pickle.loads(data)
        
        # Reconstruct client's Round 1 data
        Auth = {
            "P1": bp.G2Elem.from_bytes(received_data_Auth_1["P1"], bpg),
            "PUB_Ava_m_original": [bp.G2Elem.from_bytes(pk, bpg) for pk in received_data_Auth_1["PUB_Ava_m_original"]],
            "CERT_Ava_m": {
                "PUB_Ava_m": [bp.G1Elem.from_bytes(pk, bpg) for pk in received_data_Auth_1["CERT_Ava_m"]["PUB_Ava_m"]],
                "Sigma_w_dash": {
                    "Z": bp.G1Elem.from_bytes(received_data_Auth_1["CERT_Ava_m"]["Sigma_w_dash"]["Z"], bpg),
                    "Y": bp.G1Elem.from_bytes(received_data_Auth_1["CERT_Ava_m"]["Sigma_w_dash"]["Y"], bpg),
                    "Yhat": bp.G2Elem.from_bytes(received_data_Auth_1["CERT_Ava_m"]["Sigma_w_dash"]["Yhat"], bpg)
                }
            }
        }
        
        # Extract and verify client's certificate
        PUB_Ava_m_Original = Auth["PUB_Ava_m_original"]
        PUB_Ava_m = Auth["CERT_Ava_m"]["PUB_Ava_m"]
        Sigma_w_dash = (
            Auth["CERT_Ava_m"]["Sigma_w_dash"]["Z"],
            Auth["CERT_Ava_m"]["Sigma_w_dash"]["Y"],
            Auth["CERT_Ava_m"]["Sigma_w_dash"]["Yhat"]
        )
        
        # Verify client's certificate
        client_cert_valid = verify(PUB_ca, PUB_Ava_m, Sigma_w_dash)
        if not silent:
            print(f"[AUTH {session_id}] Client certificate verification: {client_cert_valid}")
        
        # Step 3: Generate Round 2 response (P2 + z_n + certificates)
        r2 = random_scalar()
        P2 = r2 * Phat
        
        P1_bytes = Auth["P1"].export()
        P2_bytes = P2.export()
        concatenated_P2_P1 = P2_bytes + P1_bytes
        Hash_bytes = hashlib.sha256(concatenated_P2_P1).digest()
        hashed_value = int.from_bytes(Hash_bytes, byteorder="big")
        hash_reduced_bytes = hashed_value.to_bytes((hashed_value.bit_length() + 7) // 8, byteorder='big')
        I_n = Bn.from_binary(hash_reduced_bytes)
        z_n = r2 + (I_n * PRIV_Ava_n[0])
        
        data_Auth_2 = {
            "P2": P2.export(),
            "z_n": z_n.binary(),
            "PUB_Ava_n_original": [pk.export() for pk in PUB_Ava_n_Original],
            "CERT_Ava_n": {
                "PUB_Ava_n": [pk.export() for pk in CERT_Ava_n["PUB_Ava_n"]],
                "Sigma_v_dash": {
                    "Z": CERT_Ava_n["Sigma_v_dash"][0].export(),
                    "Y": CERT_Ava_n["Sigma_v_dash"][1].export(),
                    "Yhat": CERT_Ava_n["Sigma_v_dash"][2].export()
                }
            }
        }
        
        data_Auth_2_serialized = pickle.dumps(data_Auth_2)
        conn.sendall(data_Auth_2_serialized)
        
        # Step 4: Receive Round 3 from client (z_m)
        data = conn.recv(8192)
        received_data_Auth_3 = pickle.loads(data)
        
        # Step 5: Verify client's challenge response
        concatenated_P1_P2 = P1_bytes + P2_bytes
        Hash_bytes = hashlib.sha256(concatenated_P1_P2).digest()
        hashed_value = int.from_bytes(Hash_bytes, byteorder="big")
        hash_reduced_bytes = hashed_value.to_bytes((hashed_value.bit_length() + 7) // 8, byteorder='big')
        I_m = Bn.from_binary(hash_reduced_bytes)
        z_m = Bn.from_binary(received_data_Auth_3)
        
        LHS = z_m * Phat
        temp = I_m * PUB_Ava_m_Original[0]
        RHS = Auth["P1"] + temp
        
        # Final verification
        if LHS == RHS:
            verdict = "Access Granted"
            success = True
            if not silent:
                print(f"[AUTH {session_id}] ✅ Authentication successful")
        else:
            verdict = "Access Denied"
            success = False
            if not silent:
                print(f"[AUTH {session_id}] ❌ Authentication failed")
        
        # Send final verdict
        conn.sendall(verdict.encode('utf-8'))
        
        if not silent:
            print(f"[AUTH {session_id}] Completed - {verdict}")
        
        return success
        
    except Exception as e:
        if not silent:
            print(f"[AUTH {session_id}] Error: {e}")
        return False
    finally:
        conn.close()
        with lock:
            active_connections -= 1
        if not silent:
            print(f"[AUTH {session_id}] Connection closed")

def start_auth_server(host="0.0.0.0", port=12345, silent=True, max_connections=100):
    """Start the authentication server"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(max_connections)
    
    if not silent:
        print(f"🔐 Authentication server listening on {host}:{port}")
        print(f"📊 Max concurrent connections: {max_connections}")
        print("="*60)
    
    try:
        while True:
            conn, addr = server_socket.accept()
            
            if not silent:
                print(f"[CONNECTED] {addr} (Active: {active_connections + 1})")
            
            # Handle each authentication in a separate thread
            auth_thread = threading.Thread(
                target=handle_authentication, 
                args=(conn, addr, silent)
            )
            auth_thread.daemon = True
            auth_thread.start()
            
    except KeyboardInterrupt:
        print("\n🛑 Server shutting down...")
    finally:
        server_socket.close()

def reset_server_stats():
    """Reset server statistics"""
    global total_authentications, active_connections
    with lock:
        total_authentications = 0
        active_connections = 0

def get_server_stats():
    """Get current server statistics"""
    with lock:
        return {
            'total_authentications': total_authentications,
            'active_connections': active_connections
        }

def main():
    print("🔐 AUTHENTICATION SERVER")
    print("="*40)
    print("Choose mode:")
    print("1. Silent mode (for benchmarking)")
    print("2. Verbose mode (for debugging)")
    print("3. Show statistics")
    
    choice = input("Enter choice (1-3): ").strip()
    
    if choice == "1":
        print("Starting silent authentication server...")
        print("Press Ctrl+C to stop")
        start_auth_server(silent=True)
    elif choice == "2":
        print("Starting verbose authentication server...")
        print("Press Ctrl+C to stop")
        start_auth_server(silent=False)
    elif choice == "3":
        stats = get_server_stats()
        print(f"📊 Server Statistics:")
        print(f"Total authentications: {stats['total_authentications']}")
        print(f"Active connections: {stats['active_connections']}")
    else:
        print("Invalid choice. Starting silent server...")
        start_auth_server(silent=True)

if __name__ == "__main__":
    main()