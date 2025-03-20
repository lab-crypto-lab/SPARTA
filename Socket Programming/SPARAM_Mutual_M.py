import hashlib
import bplib as bp
from bplib import bp
from bplib.bp import BpGroup
from petlib.bn import Bn
from functools import reduce
import socket
import pickle
import time

# Initialize bilinear pairing group
bpg = BpGroup()
P = bpg.gen1()       # Generator in G1
Phat = bpg.gen2()    # Generator in G2
p_bn = bpg.order()   #  to get p of the curve


def random_scalar():
    """Generate a random scalar from the curve order."""
    return Bn.random(p_bn) + 1         # Generate a random integer from the curve group order

def hash_message(m):
    """Hash a message to a large scalar compatible with bplib."""
    h = hashlib.sha256()
    h.update(bytes(m, "utf-8"))
    hashed_value = int.from_bytes(h.digest(), byteorder='big')
    hash_reduced_bytes = hashed_value.to_bytes((hashed_value.bit_length() + 7) // 8, byteorder='big')
    c_bn = Bn.from_binary(hash_reduced_bytes)

    # Convert hash to scalar using bplib's order
    return c_bn

# ----------------------- KEY GENERATION -----------------------

def keygen(ell):
    """Generate public-private key pairs for ell attributes."""
    
    # Generate a list of ell secret keys (random scalars)
    sk = [random_scalar() for _ in range(ell)]

    # Compute the corresponding public keys by multiplying the generator in G2 with each secret key
    # Formula: pk[i] = sk[i] * Phat
    pk = [Phat * x for x in sk]

    # Return both the public and secret keys
    return pk, sk


# ----------------------- SIGNATURE GENERATION -----------------------

def sign(sk, M):
    """Sign a message using the secret key."""
    y = random_scalar()  # Random nonce

    # Compute aggregated signature:
    # Z = y * sum(sk[i] * M[i])
    #Z = sum((xi * Mi for xi, Mi in zip(sk, M)), P * 0) * y
    Z = reduce(lambda a, b: a + b, (xi * Mi for xi, Mi in zip(sk, M)))
    Z = y * Z

    # Compute nonce-based values:
    Y = (pow(y, p_bn-2, p_bn)) * P
    Yhat = (pow(y, p_bn-2, p_bn)) * Phat

    #print("Z is",Z)
    #print("Y is",Y)
    #print("Yhat is",Yhat)

    return Z, Y, Yhat

# ----------------------- SIGNATURE VERIFICATION -----------------------

def verify(pk, M, sigma):
    """Verify a signature using the public key."""

    # Unpack the signature
    Z, Y, Yhat = sigma
    #print("Z is",Z)
    #print("Y is",Y)
    #print("Yhat is",Yhat)

    lhs = reduce(lambda a, b: a * b, (bpg.pair(Mi, Xi) for Xi, Mi in zip(pk, M)))

    # ####### IF I DO NOT USE REDUCE METHOD ###### 
    # Initialize lhs with the first pairing result
    #pairings = [bpg.pair(Mi, Xi) for Xi, Mi in zip(pk, M)]
    #lhs = pairings[0]  # Start with the first pairing

    # Multiply all other pairings together
    #for pairing in pairings[1:]:  # Skip the first since it's already in lhs
     #   lhs *= pairing


    # Compute the right-hand side pairings, ensuring correct group order:
    rhs1 = bpg.pair(Z, Yhat)     # Z (G1), Yhat (G2)
    rhs2 = bpg.pair(Y, Phat)     # Y (G1), Phat (G2)
    rhs3 = bpg.pair(P, Yhat)     # P (G1), Yhat (G2) ← SWAPPED

    # Return True if both checks pass
    return lhs == rhs1 and rhs2 == rhs3

# ----------------------- CONVERSION FUNCTIONS -----------------------

def convert_sk(sk, rho):
    """Convert private key representation by scaling with rho."""
    # Multiply each secret key scalar by rho
    return [rho * x for x in sk]

def convert_pk(pk, rho):
    """Convert public key representation by scaling with rho."""
    # Multiply each public key point by rho
    return [rho * X for X in pk]

def convert_sig(sigma, rho):
    """Convert signature representation by scaling with rho."""
    
    # Unpack the signature
    Z, Y, Yhat = sigma

    # Generate a random scalar psi for re-randomization
    psi = random_scalar()

    # Return the transformed signature
    # Z' = psi * rho * Z
    # Y' = psi^-1 * Y
    # Yhat' = psi^-1 * Yhat
    return (
        psi * rho * Z,
        (pow(psi, p_bn-2, p_bn)) * Y,
        (pow(psi, p_bn-2, p_bn)) * Yhat,
    )

def change_rep(pk, M, sigma, mu):
    """Change representation of both message and signature using mu."""
    
    # Unpack the signature
    Z, Y, Yhat = sigma

    # Generate a random scalar psi for re-randomization
    psi = random_scalar()

    # Change message representation: M0[i] = mu * M[i]
    M0 = [mu * m for m in M]

    # Change signature representation:
    # Z' = psi * mu * Z
    # Y' = psi^-1 * Y
    # Yhat' = psi^-1 * Yhat
    sigma0 = (
        psi * mu * Z,
        (pow(psi, p_bn-2, p_bn)) * Y,
        (pow(psi, p_bn-2, p_bn)) * Yhat,
    )

    # Return both modified messages and signature
    return M0, sigma0

if __name__ == '__main__':

    ell = 1

    server_ip = '192.168.2.1' # ip address of mac on ethernet connection
    server_port = 12345 # proposed port for communication
    # Initializing the socket programming for the client
    client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    # Step 1: Generate keys for the MSP

    PUB_ca, PRIV_ca = keygen(ell)

    # Sending MSP keys to MAC
    # 
    data_ca = {
        "PRIV_ca": [s.binary() for s in PRIV_ca],  # Convert Bn scalars to bytes
        "PUB_ca": [pk.export() for pk in PUB_ca]  # Convert G2 elements to bytes
    }

    data_ca_serialized = pickle.dumps(data_ca)
    client_socket.sendall(data_ca_serialized)
    data_ca_reply = client_socket.recv(1024)
    data_ca_reply = data_ca_reply.decode('utf-8')
    print(data_ca_reply)


    # Creating a User w that will creat Avatar m

    X_w , x_w = keygen(ell)
    M_w = [hash_message(str(Xi)) * P for Xi in X_w] # Hashing the public key to a point in G1 to be able to sign and verify it, because pairing (G1 , G2)
    Sigma_w = sign(PRIV_ca,M_w)

    # Creating Avatar m
    mu_m = random_scalar()
    PRIV_Ava_m = convert_sk(x_w,mu_m) # Generating Private Key of Avatar n
    PUB_Ava_m_Original = convert_pk(X_w,mu_m) # Public key in G2.
    PUB_Ava_m ,Sigma_w_dash = change_rep(PUB_ca,M_w,Sigma_w,mu_m) # Public key here is in G1

    CERT_Ava_m = {
        'PUB_Ava_m' : PUB_Ava_m,
        'Sigma_w_dash' : Sigma_w_dash
    }

    # Verify the changed representation signature
    #is_valid3 = verify(PUB_ca, PUB_Ava_m, Sigma_w_dash)
    #print(f"✅ Changed representation signature valid: {is_valid3}")

    #PUB_Ava_m_original_bytes = [pk.export() for pk in PUB_Ava_m_Original]
    #PUB_Ava_m_original_serialized = pickle.dumps(PUB_Ava_m_original_bytes)
    #client_socket.sendall(PUB_Ava_m_original_serialized)

    #PUB_Ava_n_original = client_socket.recv(1024)
    #PUB_Ava_n_original = [bp.G2Elem.from_bytes(pk,bpg) for pk in PUB_Ava_n_original]


    # Starting the Mutual Authentication Phase
    Start_time = time.time()
    r1 = random_scalar()
    P1 = r1 * Phat # Scalar Multiplication 

    
    data_Auth_1 = {
            "P1": P1.export(),  # Convert P1 (G2) to bytes
            "PUB_Ava_m_original" : [pk.export() for pk in PUB_Ava_m_Original],
            "CERT_Ava_m": {
                "PUB_Ava_m": [pk.export() for pk in CERT_Ava_m["PUB_Ava_m"]],  # G1 list (Converted to G1 Element)
                "Sigma_w_dash": {
                    "Z": CERT_Ava_m["Sigma_w_dash"][0].export(),  # G1
                    "Y": CERT_Ava_m["Sigma_w_dash"][1].export(),  # G1
                    "Yhat": CERT_Ava_m["Sigma_w_dash"][2].export()  # G2
                }
            }
        }
    
    data_Auth_1_serialized = pickle.dumps(data_Auth_1)
    client_socket.sendall(data_Auth_1_serialized)


    data = client_socket.recv(8192)
    received_data_auth_2 = pickle.loads(data)

    Auth = {
        "P2": bp.G2Elem.from_bytes(received_data_auth_2["P2"], bpg),  # G2 element
        "z_n" : Bn.from_binary(received_data_auth_2["z_n"]),
        "PUB_Ava_n_original": [bp.G2Elem.from_bytes(pk, bpg) for pk in received_data_auth_2["PUB_Ava_n_original"]],
        "CERT_Ava_n": {
            "PUB_Ava_n": [bp.G1Elem.from_bytes(pk, bpg) for pk in received_data_auth_2["CERT_Ava_n"]["PUB_Ava_n"]],  # G1 list
            "Sigma_v_dash": {
                "Z": bp.G1Elem.from_bytes(received_data_auth_2["CERT_Ava_n"]["Sigma_v_dash"]["Z"], bpg),  # G1
                "Y": bp.G1Elem.from_bytes(received_data_auth_2["CERT_Ava_n"]["Sigma_v_dash"]["Y"], bpg),  # G1
                "Yhat": bp.G2Elem.from_bytes(received_data_auth_2["CERT_Ava_n"]["Sigma_v_dash"]["Yhat"], bpg)  # G2
                }
            }
        }

    PUB_Ava_n_Original = Auth["PUB_Ava_n_original"]
    PUB_Ava_n = Auth["CERT_Ava_n"]["PUB_Ava_n"]  # Extract public key list
    z_n = Auth["z_n"]
    P2 = Auth["P2"]
    Sigma_v_dash = (
    Auth["CERT_Ava_n"]["Sigma_v_dash"]["Z"],  # G1 element
    Auth["CERT_Ava_n"]["Sigma_v_dash"]["Y"],  # G1 element
    Auth["CERT_Ava_n"]["Sigma_v_dash"]["Yhat"]  # G2 element
        )

        # Verify the changed representation signature
    is_valid3 = verify(PUB_ca, PUB_Ava_n, Sigma_v_dash)
    #print(f"✅ Avatar n Certificate Verification: {is_valid3}")

    P1_bytes = P1.export()
    P2_bytes = P2.export()
    concatenated_P2_P1 = P2_bytes + P1_bytes
    Hash_bytes = hashlib.sha256(concatenated_P2_P1).digest()
    hashed_value = int.from_bytes(Hash_bytes, byteorder="big")
    hash_reduced_bytes = hashed_value.to_bytes((hashed_value.bit_length() + 7) // 8, byteorder='big')
    I_n = Bn.from_binary(hash_reduced_bytes)

    LHS = z_n * Phat
    temp = I_n * PUB_Ava_n_Original[0]
    RHS = P2 + temp

    #if LHS == RHS:
     #   print("✅ Verification successful: LHS = RHS")
    #else:
     #   print("❌ Verification failed: LHS ≠ RHS")

    concatenated_P1_P2 = P1_bytes + P2_bytes
    Hash_bytes = hashlib.sha256(concatenated_P1_P2).digest()
    hashed_value = int.from_bytes(Hash_bytes, byteorder="big")
    hash_reduced_bytes = hashed_value.to_bytes((hashed_value.bit_length() + 7) // 8, byteorder='big')
    I_m = Bn.from_binary(hash_reduced_bytes)

    z_m = r1 + (I_m * PRIV_Ava_m[0])

    data_Auth_3 = z_m.binary()
    data_Auth_3_serialized = pickle.dumps(data_Auth_3)
    client_socket.sendall(data_Auth_3_serialized)


    Verdict = client_socket.recv(1024)
    End_time = time.time()
    Verdict = Verdict.decode('utf-8')
    print(Verdict)
    
    Auth_Exec_time = End_time - Start_time
    print(f"Authentication Execution time is :{Auth_Exec_time} seconds")




    

