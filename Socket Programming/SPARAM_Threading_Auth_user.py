import hashlib
import bplib as bp
from bplib import bp
from bplib.bp import BpGroup
from petlib.bn import Bn
from functools import reduce
import socket
import pickle
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd

# Initialize bilinear pairing group
bpg = BpGroup()
P = bpg.gen1()
Phat = bpg.gen2()
p_bn = bpg.order()

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

def authenticate_single_user(user_id, server_ip, server_port, ell=1, verbose=False):
    """Perform single authentication - simulates one user authentication"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(30)
            
            # Connect to server
            client_socket.connect((server_ip, server_port))
            if verbose:
                print(f"[USER {user_id}] Connected to server")
            
            # Generate MSP keys
            PUB_ca, PRIV_ca = keygen(ell)
            
            # Send MSP keys to server
            data_ca = {
                "PRIV_ca": [s.binary() for s in PRIV_ca],
                "PUB_ca": [pk.export() for pk in PUB_ca]
            }
            data_ca_serialized = pickle.dumps(data_ca)
            client_socket.sendall(data_ca_serialized)
            
            # Receive MSP confirmation
            data_ca_reply = client_socket.recv(1024)
            if verbose:
                print(f"[USER {user_id}] MSP keys sent")
            
            # Create User w and Avatar m
            X_w, x_w = keygen(ell)
            M_w = [hash_message(str(Xi)) * P for Xi in X_w]
            Sigma_w = sign(PRIV_ca, M_w)
            
            # Create Avatar m
            mu_m = random_scalar()
            PRIV_Ava_m = convert_sk(x_w, mu_m)
            PUB_Ava_m_Original = convert_pk(X_w, mu_m)
            PUB_Ava_m, Sigma_w_dash = change_rep(PUB_ca, M_w, Sigma_w, mu_m)
            
            CERT_Ava_m = {
                'PUB_Ava_m': PUB_Ava_m,
                'Sigma_w_dash': Sigma_w_dash
            }
            
            # === AUTHENTICATION PROTOCOL STARTS ===
            auth_start_time = time.time()
            
            # Round 1: Send P1 and certificates
            r1 = random_scalar()
            P1 = r1 * Phat
            
            data_Auth_1 = {
                "P1": P1.export(),
                "PUB_Ava_m_original": [pk.export() for pk in PUB_Ava_m_Original],
                "CERT_Ava_m": {
                    "PUB_Ava_m": [pk.export() for pk in CERT_Ava_m["PUB_Ava_m"]],
                    "Sigma_w_dash": {
                        "Z": CERT_Ava_m["Sigma_w_dash"][0].export(),
                        "Y": CERT_Ava_m["Sigma_w_dash"][1].export(),
                        "Yhat": CERT_Ava_m["Sigma_w_dash"][2].export()
                    }
                }
            }
            
            data_Auth_1_serialized = pickle.dumps(data_Auth_1)
            client_socket.sendall(data_Auth_1_serialized)
            
            # Round 2: Receive P2, z_n, and server certificates
            data = client_socket.recv(8192)
            received_data_auth_2 = pickle.loads(data)
            
            # Reconstruct received data
            Auth = {
                "P2": bp.G2Elem.from_bytes(received_data_auth_2["P2"], bpg),
                "z_n": Bn.from_binary(received_data_auth_2["z_n"]),
                "PUB_Ava_n_original": [bp.G2Elem.from_bytes(pk, bpg) for pk in received_data_auth_2["PUB_Ava_n_original"]],
                "CERT_Ava_n": {
                    "PUB_Ava_n": [bp.G1Elem.from_bytes(pk, bpg) for pk in received_data_auth_2["CERT_Ava_n"]["PUB_Ava_n"]],
                    "Sigma_v_dash": {
                        "Z": bp.G1Elem.from_bytes(received_data_auth_2["CERT_Ava_n"]["Sigma_v_dash"]["Z"], bpg),
                        "Y": bp.G1Elem.from_bytes(received_data_auth_2["CERT_Ava_n"]["Sigma_v_dash"]["Y"], bpg),
                        "Yhat": bp.G2Elem.from_bytes(received_data_auth_2["CERT_Ava_n"]["Sigma_v_dash"]["Yhat"], bpg)
                    }
                }
            }
            
            # Verify server's certificate
            PUB_Ava_n = Auth["CERT_Ava_n"]["PUB_Ava_n"]
            Sigma_v_dash = (
                Auth["CERT_Ava_n"]["Sigma_v_dash"]["Z"],
                Auth["CERT_Ava_n"]["Sigma_v_dash"]["Y"],
                Auth["CERT_Ava_n"]["Sigma_v_dash"]["Yhat"]
            )
            
            is_valid = verify(PUB_ca, PUB_Ava_n, Sigma_v_dash)
            if not is_valid and verbose:
                print(f"[USER {user_id}] Server certificate verification failed")
            
            # Verify server's challenge response
            P2 = Auth["P2"]
            z_n = Auth["z_n"]
            PUB_Ava_n_Original = Auth["PUB_Ava_n_original"]
            
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
            
            if LHS != RHS and verbose:
                print(f"[USER {user_id}] Server challenge verification failed")
            
            # Round 3: Send our challenge response
            concatenated_P1_P2 = P1_bytes + P2_bytes
            Hash_bytes = hashlib.sha256(concatenated_P1_P2).digest()
            hashed_value = int.from_bytes(Hash_bytes, byteorder="big")
            hash_reduced_bytes = hashed_value.to_bytes((hashed_value.bit_length() + 7) // 8, byteorder='big')
            I_m = Bn.from_binary(hash_reduced_bytes)
            
            z_m = r1 + (I_m * PRIV_Ava_m[0])
            
            data_Auth_3 = z_m.binary()
            data_Auth_3_serialized = pickle.dumps(data_Auth_3)
            client_socket.sendall(data_Auth_3_serialized)
            
            # Receive final verdict
            Verdict = client_socket.recv(1024)
            auth_end_time = time.time()
            
            verdict_str = Verdict.decode('utf-8')
            auth_time = auth_end_time - auth_start_time
            
            if verbose:
                print(f"[USER {user_id}] Authentication completed: {verdict_str} in {auth_time:.3f}s")
            
            success = verdict_str == "Access Granted"
            return (user_id, success, auth_time)
            
    except Exception as e:
        if verbose:
            print(f"[USER {user_id}] Authentication failed: {e}")
        return (user_id, False, 0.0)

def export_to_excel(times_data, filename_prefix="auth_benchmark"):
    """Export timing data to Excel for analysis"""
    timestamp = int(time.time())
    filename = f"{filename_prefix}_{timestamp}.xlsx"
    
    # Create DataFrame
    df = pd.DataFrame(times_data)
    
    # Export to Excel
    try:
        df.to_excel(filename, index=False)
        print(f"\nData exported to: {filename}")
        return filename
    except Exception as e:
        print(f"\nFailed to export to Excel: {e}")
        return None

def benchmark_authentication(method="sequential", target_successful_runs=100, server_ip="192.168.2.1", server_port=12345, total_users=5, verbose=False):
    """Benchmark authentication method until reaching target successful runs"""
    print(f"BENCHMARKING {method.upper()} AUTHENTICATION")
    print(f"Target successful runs: {target_successful_runs}")
    print(f"Users per iteration: {total_users}")
    print(f"Server: {server_ip}:{server_port}")
    print("="*60)
    
    times = []
    successful_runs = 0
    failed_runs = 0
    total_attempts = 0
    total_auth_time = 0
    
    while successful_runs < target_successful_runs:
        total_attempts += 1
        
        try:
            start_time = time.time()
            
            if method == "concurrent":
                results = concurrent_authentication(server_ip, server_port, total_users, verbose)
            else:
                results = sequential_authentication(server_ip, server_port, total_users, verbose)
            
            end_time = time.time()
            run_time = end_time - start_time
            
            # Count successful authentications in this run
            run_successes = sum(1 for _, success, _ in results if success)
            run_auth_time = sum(auth_time for _, _, auth_time in results)
            
            if run_successes == total_users:
                times.append(run_time)
                successful_runs += 1
                total_auth_time += run_auth_time
                if verbose:
                    print(f"[RUN {successful_runs}] Success in {run_time:.3f}s")
            else:
                failed_runs += 1
                if verbose:
                    print(f"[ATTEMPT {total_attempts}] Partial success: {run_successes}/{total_users} users")
            
            # Small delay between runs
            time.sleep(0.2)
            
        except Exception as e:
            failed_runs += 1
            if verbose:
                print(f"[ATTEMPT {total_attempts}] Failed: {e}")
    
    # Calculate statistics
    if times:
        avg_time = sum(times) / len(times)
        min_time = min(times)
        max_time = max(times)
        median_time = sorted(times)[len(times)//2]
        avg_auth_time = total_auth_time / (successful_runs * total_users)
        total_benchmark_time = sum(times)
        
        print("\n" + "="*60)
        print(f"AUTHENTICATION BENCHMARK RESULTS ({method.upper()})")
        print("="*60)
        print(f"Successful runs: {successful_runs}/{total_attempts} ({successful_runs/total_attempts*100:.1f}%)")
        print(f"Failed runs: {failed_runs}/{total_attempts} ({failed_runs/total_attempts*100:.1f}%)")
        print(f"Average time per run: {avg_time:.3f}s")
        print(f"Fastest time: {min_time:.3f}s")
        print(f"Slowest time: {max_time:.3f}s")
        print(f"Median time: {median_time:.3f}s")
        print(f"Average authentication time: {avg_auth_time:.3f}s")
        print(f"Throughput: {total_users/avg_time:.1f} authentications/second")
        print(f"Total authentications: {successful_runs * total_users:,}")
        print(f"Total authentication time: {total_benchmark_time:.3f}s ({total_benchmark_time/60:.1f} minutes)")
        
        # Prepare data for Excel export
        timing_data = {
            'Run_Number': list(range(1, len(times) + 1)),
            'Time_Seconds': times,
            'Method': [method.upper()] * len(times),
            'Users_Per_Run': [total_users] * len(times),
            'Auths_Per_Second': [total_users/t for t in times]
        }
        
        return times, timing_data
    else:
        print("\nNo successful runs to analyze!")
        return [], {}

def compare_methods(target_successful_runs=50, server_ip="192.168.2.1", server_port=12345, total_users=5, verbose=False):
    """Compare sequential vs concurrent methods"""
    print("AUTHENTICATION METHOD COMPARISON")
    print("="*60)
    
    methods = ["sequential", "concurrent"]
    all_timing_data = []
    results = {}
    
    for i, method in enumerate(methods):
        print(f"\nTesting method {i+1}/2: {method}")
        times, timing_data = benchmark_authentication(method, target_successful_runs, server_ip, server_port, total_users, verbose)
        if times:
            results[method] = sum(times) / len(times)
            all_timing_data.extend([{**row, 'Run_ID': f"{timing_data['Method'][0]}_{row['Run_Number']}"} 
                                   for row in [{k: v[idx] for k, v in timing_data.items()} 
                                             for idx in range(len(timing_data['Run_Number']))]])
        
        if i < len(methods) - 1:
            print("\nWaiting 2 seconds before next test...")
            time.sleep(2)
    
    # Export all data to Excel
    if all_timing_data:
        # Convert to DataFrame format
        df_data = {}
        for key in all_timing_data[0].keys():
            df_data[key] = [row[key] for row in all_timing_data]
        
        filename = export_to_excel(df_data, "auth_comparison")
        if filename:
            print(f"\nAll timing data exported to: {filename}")
    
    # Final comparison
    if len(results) > 1:
        print("\nFINAL COMPARISON")
        print("="*30)
        
        sorted_results = sorted(results.items(), key=lambda x: x[1])
        fastest_time = sorted_results[0][1]
        
        for method, avg_time in sorted_results:
            speedup = fastest_time / avg_time if avg_time != fastest_time else 1.0
            relative_performance = "FASTEST" if avg_time == fastest_time else f"{speedup:.2f}x slower"
            print(f"{method:15}: {avg_time:.3f}s ({relative_performance})")

def concurrent_authentication(server_ip, server_port, total_users, verbose=False):
    """Perform concurrent authentications"""
    results = []
    max_workers = min(total_users, 10)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_user = {
            executor.submit(authenticate_single_user, user_id, server_ip, server_port, 1, verbose): user_id 
            for user_id in range(total_users)
        }
        
        for future in as_completed(future_to_user):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                user_id = future_to_user[future]
                results.append((user_id, False, 0.0))
    
    return results

def sequential_authentication(server_ip, server_port, total_users, verbose=False):
    """Perform sequential authentications"""
    results = []
    
    for user_id in range(total_users):
        result = authenticate_single_user(user_id, server_ip, server_port, 1, verbose)
        results.append(result)
    
    return results

def main():
    print("AUTHENTICATION BENCHMARKING TOOL")
    print("="*60)
    print("Choose benchmark type:")
    print("1. Benchmark Sequential authentication")
    print("2. Benchmark Concurrent authentication") 
    print("3. Compare both methods")
    print("4. Single authentication test")
    
    choice = input("Enter choice (1-4): ").strip()
    
    if choice in ["1", "2", "3"]:
        try:
            target_runs = int(input("Enter target successful runs (default: 100): ") or "100")
            users = int(input("Enter number of users per iteration (default: 5): ") or "5")
            server_ip = input("Enter server IP (default: 192.168.2.1): ") or "192.168.2.1"
        except ValueError:
            print("Invalid input, using defaults")
            target_runs, users, server_ip = 100, 5, "192.168.2.1"
        
        if choice == "1":
            times, timing_data = benchmark_authentication("sequential", target_runs, server_ip, 12345, users)
            if timing_data:
                export_to_excel(timing_data, "auth_sequential")
        elif choice == "2":
            times, timing_data = benchmark_authentication("concurrent", target_runs, server_ip, 12345, users)
            
            if timing_data:
                export_to_excel(timing_data, "auth_concurrent")
        elif choice == "3":
            compare_methods(target_runs, server_ip, 12345, users)
            
    elif choice == "4":
        result = authenticate_single_user(0, "192.168.2.1", 12345, 1, True)
        user_id, success, auth_time = result
        print(f"\nSingle authentication result:")
        print(f"Success: {success}")
        print(f"Time: {auth_time:.3f}s")
    
    else:
        print("Invalid choice!")

if __name__ == "__main__":
    main()