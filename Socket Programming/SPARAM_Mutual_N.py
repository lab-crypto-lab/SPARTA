import hashlib
import bplib as bp
from bplib import bp
from bplib.bp import BpGroup ,GTElem,G1Elem,G2Elem
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
    """Generate public-private key pairs for `ell` attributes."""
    
    # Generate a list of `ell` secret keys (random scalars)
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
    """Convert private key representation by scaling with `rho`."""
    # Multiply each secret key scalar by `rho`
    return [rho * x for x in sk]

def convert_pk(pk, rho):
    """Convert public key representation by scaling with `rho`."""
    # Multiply each public key point by `rho`
    return [rho * X for X in pk]

def convert_sig(sigma, rho):
    """Convert signature representation by scaling with `rho`."""
    
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
    """Change representation of both message and signature using `mu`."""
    
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

if __name__ == "__main__":

    ell = 1

    # Create a socket object
    host = '0.0.0.0'  # Listen on all available interfaces
    port = 12345       # Port to listen on
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    
    print(f"Server listening on {host}:{port}")

    # Accept a connection
    conn, addr = server_socket.accept()

    while True:
        # Receive data from the client
        data_ca_received = conn.recv(1024)
        if not data_ca_received:
            break

        #Receiving the Public key of the MSP

        data_ca_deserialized = pickle.loads(data_ca_received)
        PRIV_ca = [Bn.from_binary(s) for s in data_ca_deserialized["PRIV_ca"]]  # Convert bytes back to Bn scalars
        PUB_ca = [bp.G2Elem.from_bytes(pk, bpg) for pk in data_ca_deserialized["PUB_ca"]]  # Convert bytes back to G2 elements

        #print("PUB_ca is ",PUB_ca)
        data_ca_received = "MSP Keys received"
        conn.sendall(data_ca_received.encode('utf-8'))

        M = [hash_message(str(Xi)) * P for Xi in PUB_ca]

        # Step 3: Generate signature using private key and message
        sigma = sign(PRIV_ca, M)
        #print("✅ Signature generated")


        # Step 4: Verify the generated signature using public key
        is_valid = verify(PUB_ca, M, sigma)
        print(f"✅ Signature valid: {is_valid}") 

        # Creating a User V that will creat Avatar n

        X_v , x_v = keygen(ell)
        M_v = [hash_message(str(Xi)) * P for Xi in X_v] # Hashing the public key to a point in G1 to be able to sign and verify it, because pairing (G1 , G2)
        Sigma_v = sign(PRIV_ca,M_v)

        # Creating Avatar n
        mu_n = random_scalar()
        PRIV_Ava_n = convert_sk(x_v,mu_n) # Generating Private Key of Avatar n
        PUB_Ava_n_Original = convert_pk(X_v,mu_n)
        PUB_Ava_n ,Sigma_v_dash = change_rep(PUB_ca,M_v,Sigma_v,mu_n)

        CERT_Ava_n = {
            'PUB_Ava_n' : PUB_Ava_n,
            'Sigma_v_dash' : Sigma_v_dash
        }

        #PUB_Ava_m_original = conn.recv(8192)
        #PUB_Ava_m_original = [bp.G2Elem.from_bytes(pk,bpg) for pk in PUB_Ava_m_original]

        #PUB_Ava_n_original_bytes = [pk.export() for pk in PUB_Ava_n_Original]
        #PUB_Ava_n_original_serialized = pickle.dumps(PUB_Ava_n_original_bytes)
        #conn.sendall(PUB_Ava_n_original_serialized)

        # Verify the changed representation signature
        #is_valid3 = verify(PUB_ca, PUB_Ava_n, Sigma_v_dash)
        #print(f"✅ Changed representation signature valid: {is_valid3}")

        # Starting Mutual Authentication Phase
        data = conn.recv(8192)  # Increase buffer size to handle larger data
        received_data_Auth_1 = pickle.loads(data)  # Deserialize received bytes

        Auth = {
        "P1": bp.G2Elem.from_bytes(received_data_Auth_1["P1"], bpg),  # G2 element
        "PUB_Ava_m_original": [bp.G2Elem.from_bytes(pk, bpg) for pk in received_data_Auth_1["PUB_Ava_m_original"]],
        "CERT_Ava_m": {
            "PUB_Ava_m": [bp.G1Elem.from_bytes(pk, bpg) for pk in received_data_Auth_1["CERT_Ava_m"]["PUB_Ava_m"]],  # G1 list
            "Sigma_w_dash": {
                "Z": bp.G1Elem.from_bytes(received_data_Auth_1["CERT_Ava_m"]["Sigma_w_dash"]["Z"], bpg),  # G1
                "Y": bp.G1Elem.from_bytes(received_data_Auth_1["CERT_Ava_m"]["Sigma_w_dash"]["Y"], bpg),  # G1
                "Yhat": bp.G2Elem.from_bytes(received_data_Auth_1["CERT_Ava_m"]["Sigma_w_dash"]["Yhat"], bpg)  # G2
                }
            }
        }

        PUB_Ava_m_Original = Auth["PUB_Ava_m_original"]
        PUB_Ava_m = Auth["CERT_Ava_m"]["PUB_Ava_m"]  # Extract public key list
        Sigma_w_dash = (
        Auth["CERT_Ava_m"]["Sigma_w_dash"]["Z"],  # G1 element
        Auth["CERT_Ava_m"]["Sigma_w_dash"]["Y"],  # G1 element
        Auth["CERT_Ava_m"]["Sigma_w_dash"]["Yhat"]  # G2 element
        )

        # Verify the changed representation signature
        is_valid3 = verify(PUB_ca, PUB_Ava_m, Sigma_w_dash)
        print(f"✅ Avatar m Certificate Verification: {is_valid3}")

        # Avatar n creates second msg in authentication
        r2 = random_scalar()
        P2 = r2 * Phat # Scalar Multiplication 
        P1_bytes = Auth["P1"].export()  # Convert P1 to bytes
        P2_bytes = P2.export()  # Convert P2 to bytes
        concatenated_P2_P1 = P2_bytes + P1_bytes
        Hash_bytes = hashlib.sha256(concatenated_P2_P1).digest()
        hashed_value = int.from_bytes(Hash_bytes, byteorder="big")
        hash_reduced_bytes = hashed_value.to_bytes((hashed_value.bit_length() + 7) // 8, byteorder='big')
        I_n = Bn.from_binary(hash_reduced_bytes)
        z_n = r2 + (I_n * PRIV_Ava_n[0])
        print("type of z_n is",type(z_n))

        data_Auth_2 = {
            "P2" : P2.export(),
            "z_n" : z_n.binary(),
            "PUB_Ava_n_original" : [pk.export() for pk in PUB_Ava_n_Original],
            "CERT_Ava_n": {
                "PUB_Ava_n": [pk.export() for pk in CERT_Ava_n["PUB_Ava_n"]],  # G1 list (Converted to G1 Element)
                "Sigma_v_dash": {
                    "Z": CERT_Ava_n["Sigma_v_dash"][0].export(),  # G1
                    "Y": CERT_Ava_n["Sigma_v_dash"][1].export(),  # G1
                    "Yhat": CERT_Ava_n["Sigma_v_dash"][2].export()  # G2
                }
            }
        }

        data_Auth_2_serialized = pickle.dumps(data_Auth_2)
        conn.sendall(data_Auth_2_serialized)

        data = conn.recv(8192)  # Increase buffer size to handle larger data
        received_data_Auth_3 = pickle.loads(data)  # Deserialize received bytes

        concatenated_P1_P2 = P1_bytes + P2_bytes
        Hash_bytes = hashlib.sha256(concatenated_P1_P2).digest()
        hashed_value = int.from_bytes(Hash_bytes, byteorder="big")
        hash_reduced_bytes = hashed_value.to_bytes((hashed_value.bit_length() + 7) // 8, byteorder='big')
        I_m = Bn.from_binary(hash_reduced_bytes)
        z_m = Bn.from_binary(received_data_Auth_3)
        LHS = z_m * Phat
        temp = I_m * PUB_Ava_m_Original[0]
        RHS = Auth["P1"] + temp

        if LHS == RHS:
            print("✅ Verification successful: LHS = RHS")
        else:
            print("❌ Verification failed: LHS ≠ RHS")

        Verdict = "Access Granted"
        conn.sendall(Verdict.encode('utf-8'))
        