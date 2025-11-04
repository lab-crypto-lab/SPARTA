import hashlib
import bplib as bp
from bplib import bp
from bplib.bp import BpGroup
from petlib.bn import Bn
import socket
import pickle
import time
import threading
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize bilinear pairing group
bpg = BpGroup()
P = bpg.gen1()
Phat = bpg.gen2()
p_bn = bpg.order()

def random_scalar():
    return Bn.random(p_bn) + 1

def keygen(ell):
    sk = [random_scalar() for _ in range(ell)]
    pk = [Phat * x for x in sk]
    return pk, sk

def receive_with_length(sock):
    """Receive data with length prefix"""
    try:
        # Receive length (4 bytes)
        length_data = b""
        while len(length_data) < 4:
            chunk = sock.recv(4 - len(length_data))
            if not chunk:
                return None
            length_data += chunk
        
        length = struct.unpack('>I', length_data)[0]
        
        # Receive data
        data = b""
        while len(data) < length:
            chunk = sock.recv(min(4096, length - len(data)))
            if not chunk:
                return None
            data += chunk
        
        return pickle.loads(data)
    except Exception as e:
        print(f"[ERROR] Failed to receive data: {e}")
        return None

def register_single_user(user_id, server_ip, server_port, ell=1):
    """Register a single user - this simulates one real user"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(30)
            
            # Connect
            start_time = time.time()
            sock.connect((server_ip, server_port))
            connect_time = time.time() - start_time
            print(f"[USER {user_id}] Connected in {connect_time:.3f}s")
            
            # Generate and send public key
            start_time = time.time()
            X_w, x_w = keygen(ell)
            X_w_bytes = [Xi.export() for Xi in X_w]
            message = pickle.dumps((user_id, X_w_bytes))
            sock.sendall(message)
            send_time = time.time() - start_time
            print(f"[USER {user_id}] Public key sent in {send_time:.3f}s")
            
            # Receive signature
            start_time = time.time()
            response = receive_with_length(sock)
            if response is None:
                print(f"[USER {user_id}] ❌ Failed to receive signature")
                return None
            
            recv_user_id, sigma_bytes = response
            
            # Reconstruct signature
            G1_type = type(P)
            G2_type = type(Phat)
            
            Z = G1_type.from_bytes(sigma_bytes["Z"], bpg)
            Y = G1_type.from_bytes(sigma_bytes["Y"], bpg)
            Yhat = G2_type.from_bytes(sigma_bytes["Yhat"], bpg)
            
            recv_time = time.time() - start_time
            print(f"[USER {user_id}] ✅ Signature received in {recv_time:.3f}s")
            
            return (user_id, (Z, Y, Yhat))
            
    except Exception as e:
        print(f"[USER {user_id}] ❌ Error: {e}")
        return None

def concurrent_registration(server_ip="192.168.2.1", server_port=5555, total_users=5):
    """Register all users concurrently"""
    print(f"🚀 Starting CONCURRENT registration of {total_users} users")
    print("="*60)
    
    start_time = time.time()
    received_signatures = {}
    
    # Use ThreadPoolExecutor for true concurrency
    with ThreadPoolExecutor(max_workers=total_users) as executor:
        # Submit all registration tasks simultaneously
        future_to_user = {
            executor.submit(register_single_user, user_id, server_ip, server_port): user_id 
            for user_id in range(total_users)
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_user):
            user_id = future_to_user[future]
            try:
                result = future.result()
                if result:
                    uid, signature = result
                    received_signatures[uid] = signature
                    print(f"[COMPLETE] User {uid} registration finished ({len(received_signatures)}/{total_users})")
            except Exception as e:
                print(f"[ERROR] User {user_id} failed: {e}")
    
    total_time = time.time() - start_time
    print("="*60)
    print(f"🏁 CONCURRENT registration completed in {total_time:.3f}s")
    print(f"✅ Successfully registered: {len(received_signatures)}/{total_users} users")
    
    return received_signatures

def sequential_registration(server_ip="192.168.2.1", server_port=5555, total_users=5):
    """Your current approach - for comparison"""
    print(f"🐌 Starting SEQUENTIAL registration of {total_users} users")
    print("="*60)
    
    start_time = time.time()
    received_signatures = {}
    
    for user_id in range(total_users):
        result = register_single_user(user_id, server_ip, server_port)
        if result:
            uid, signature = result
            received_signatures[uid] = signature
    
    total_time = time.time() - start_time
    print("="*60)
    print(f"🐌 SEQUENTIAL registration completed in {total_time:.3f}s")
    print(f"✅ Successfully registered: {len(received_signatures)}/{total_users} users")
    
    return received_signatures

def benchmark_registration(method="concurrent", iterations=100, server_ip="192.168.2.1", server_port=5555, total_users=5):
    """Benchmark registration method over multiple iterations"""
    print(f"🔬 BENCHMARKING {method.upper()} REGISTRATION")
    print(f"📊 Iterations: {iterations}")
    print(f"👥 Users per iteration: {total_users}")
    print(f"🎯 Server: {server_ip}:{server_port}")
    print("="*60)
    
    times = []
    successful_runs = 0
    failed_runs = 0
    
    for i in range(iterations):
        #print(f"\n[RUN {i+1}/{iterations}] Starting...")
        
        try:
            start_time = time.time()
            
            if method == "concurrent":
                signatures = concurrent_registration_quiet(server_ip, server_port, total_users)
            else:
                signatures = sequential_registration_quiet(server_ip, server_port, total_users)
            
            end_time = time.time()
            run_time = end_time - start_time
            
            if len(signatures) == total_users:
                times.append(run_time)
                successful_runs += 1
                #print(f"[RUN {i+1}] ✅ Success in {run_time:.3f}s ({len(signatures)}/{total_users} users)")
            else:
                failed_runs += 1
                #print(f"[RUN {i+1}] ❌ Partial success - {len(signatures)}/{total_users} users in {run_time:.3f}s")
            
            # Small delay between runs to avoid overwhelming server
            time.sleep(0.1)
            
        except Exception as e:
            failed_runs += 1
            print(f"[RUN {i+1}] ❌ Failed: {e}")
    
    # Calculate statistics
    if times:
        avg_time = sum(times) / len(times)
        min_time = min(times)
        max_time = max(times)
        median_time = sorted(times)[len(times)//2]
        total_benchmark_time = sum(times)  # Total time for all successful runs
        
        print("\n" + "="*60)
        print(f"📈 BENCHMARK RESULTS ({method.upper()})")
        print("="*60)
        print(f"✅ Successful runs: {successful_runs}/{iterations} ({successful_runs/iterations*100:.1f}%)")
        print(f"❌ Failed runs: {failed_runs}/{iterations} ({failed_runs/iterations*100:.1f}%)")
        print(f"⏱️  Average time: {avg_time:.3f}s")
        print(f"⚡ Fastest time: {min_time:.3f}s")
        print(f"🐌 Slowest time: {max_time:.3f}s")
        print(f"📊 Median time: {median_time:.3f}s")
        print(f"🏆 Total throughput: {total_users/avg_time:.1f} users/second")
        print(f"🕒 Total registration time: {total_benchmark_time:.3f}s ({total_benchmark_time/60:.1f} minutes)")
        
        # Show distribution
        if len(times) >= 10:
            print(f"\n📊 Time Distribution:")
            time_ranges = [(0, 0.1), (0.1, 0.5), (0.5, 1.0), (1.0, 2.0), (2.0, float('inf'))]
            for min_t, max_t in time_ranges:
                count = sum(1 for t in times if min_t <= t < max_t)
                percentage = count / len(times) * 100
                range_str = f"{min_t:.1f}s-{max_t:.1f}s" if max_t != float('inf') else f">{min_t:.1f}s"
                print(f"  {range_str:>8}: {count:3d} runs ({percentage:4.1f}%)")
    else:
        print("\n❌ No successful runs to analyze!")
    
    return times

def concurrent_registration_quiet(server_ip, server_port, total_users):
    """Concurrent registration without verbose output for benchmarking"""
    received_signatures = {}
    
    with ThreadPoolExecutor(max_workers=total_users) as executor:
        future_to_user = {
            executor.submit(register_single_user_quiet, user_id, server_ip, server_port): user_id 
            for user_id in range(total_users)
        }
        
        for future in as_completed(future_to_user):
            try:
                result = future.result()
                if result:
                    uid, signature = result
                    received_signatures[uid] = signature
            except Exception:
                pass  # Silent failure for benchmarking
    
    return received_signatures

def sequential_registration_quiet(server_ip, server_port, total_users):
    """Sequential registration without verbose output for benchmarking"""
    received_signatures = {}
    
    for user_id in range(total_users):
        try:
            result = register_single_user_quiet(user_id, server_ip, server_port)
            if result:
                uid, signature = result
                received_signatures[uid] = signature
        except Exception:
            pass  # Silent failure for benchmarking
    
    return received_signatures

def register_single_user_quiet(user_id, server_ip, server_port, ell=1):
    """Register single user without verbose output for benchmarking"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)  # Shorter timeout for benchmarking
            
            sock.connect((server_ip, server_port))
            
            # Generate and send public key
            X_w, x_w = keygen(ell)
            X_w_bytes = [Xi.export() for Xi in X_w]
            message = pickle.dumps((user_id, X_w_bytes))
            sock.sendall(message)
            
            # Receive signature
            response = receive_with_length(sock)
            if response is None:
                return None
            
            recv_user_id, sigma_bytes = response
            
            # Reconstruct signature
            G1_type = type(P)
            G2_type = type(Phat)
            
            Z = G1_type.from_bytes(sigma_bytes["Z"], bpg)
            Y = G1_type.from_bytes(sigma_bytes["Y"], bpg)
            Yhat = G2_type.from_bytes(sigma_bytes["Yhat"], bpg)
            
            return (user_id, (Z, Y, Yhat))
            
    except Exception:
        return None

def compare_methods(iterations=50, server_ip="192.168.2.1", server_port=5555, total_users=5):
    """Compare concurrent vs sequential methods"""
    print("🏁 COMPARISON: CONCURRENT vs SEQUENTIAL")
    print("="*60)
    
    # Test concurrent method
    print("Testing CONCURRENT method...")
    concurrent_times = benchmark_registration("concurrent", iterations, server_ip, server_port, total_users)
    
    print("\n" + "🔄"*20)
    print("Waiting 2 seconds before next test...")
    time.sleep(2)
    
    # Test sequential method  
    print("Testing SEQUENTIAL method...")
    sequential_times = benchmark_registration("sequential", iterations, server_ip, server_port, total_users)
    
    # Final comparison
    if concurrent_times and sequential_times:
        conc_avg = sum(concurrent_times) / len(concurrent_times)
        seq_avg = sum(sequential_times) / len(sequential_times)
        speedup = seq_avg / conc_avg
        
        print("\n" + "🏆"*20)
        print("FINAL COMPARISON")
        print("🏆"*20)
        print(f"Concurrent average: {conc_avg:.3f}s")
        print(f"Sequential average: {seq_avg:.3f}s")
        print(f"Speedup: {speedup:.2f}x {'faster' if speedup > 1 else 'slower'}")
        print(f"Time saved per run: {abs(seq_avg - conc_avg):.3f}s")

def main():
    print("🚀 CRYPTOGRAPHIC REGISTRATION BENCHMARKING TOOL")
    print("="*60)
    print("Choose benchmark type:")
    print("1. Benchmark Concurrent registration")
    print("2. Benchmark Sequential registration") 
    print("3. Compare both methods")
    print("4. Single test run (original functionality)")
    
    choice = input("Enter choice (1-4): ").strip()
    
    if choice in ["1", "2", "3"]:
        try:
            iterations = int(input("Enter number of iterations (default: 100): ") or "100")
            users = int(input("Enter number of users per iteration (default: 5): ") or "5")
            server_ip = input("Enter server IP (default: 192.168.2.1): ") or "192.168.2.1"
        except ValueError:
            print("Invalid input, using defaults")
            iterations, users, server_ip = 100, 5, "192.168.2.1"
        
        if choice == "1":
            benchmark_registration("concurrent", iterations, server_ip, 5555, users)
        elif choice == "2":
            benchmark_registration("sequential", iterations, server_ip, 5555, users)
        elif choice == "3":
            compare_methods(iterations, server_ip, 5555, users)
            
    elif choice == "4":
        print("Choose registration method:")
        print("1. Concurrent (all users register simultaneously)")
        print("2. Sequential (one user at a time)")
        
        method_choice = input("Enter choice (1 or 2): ").strip()
        
        if method_choice == "1":
            signatures = concurrent_registration()
        else:
            signatures = sequential_registration()
        
        # Display results
        print(f"\n📊 FINAL RESULTS:")
        print("="*50)
        for uid in sorted(signatures.keys()):
            Z, Y, Yhat = signatures[uid]
            print(f"User {uid}: Z({type(Z).__name__}), Y({type(Y).__name__}), Yhat({type(Yhat).__name__})")
    
    else:
        print("Invalid choice!")

if __name__ == "__main__":
    main()