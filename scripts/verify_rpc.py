import subprocess
import time
import requests
import json
import os
import signal

# Configuration
RPC_PORT = 8098
RPC_URL = f"http://127.0.0.1:{RPC_PORT}"
CONFIG_FILE = "config_test.json"
KEYS_FILE = "api_keys_test.json"
RADIX_BIN = "./build/radix_blockchain"
LOG_FILE = "node_verification_output.log"

def setup():
    # Create config file
    config = {
        "rpc": {
            "enabled": True,
            "port": RPC_PORT,
            "auth_required": True,
            "keys_file": KEYS_FILE,
            "rate_limit": 5,
            "rate_limit_authenticated": 100,
            "ip_whitelist": [] # Empty whitelist to force auth check on localhost
        },
        "blockchain": {
            "data_dir": "test_chain",
            "difficulty": 1
        }
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)
        
    # Clean up previous keys file if exists
    if os.path.exists(KEYS_FILE):
        os.remove(KEYS_FILE)

def generate_key():
    print("Generating API key...")
    result = subprocess.run(
        [RADIX_BIN, "--rpc-genkey", "test_user", KEYS_FILE], 
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"Failed to generate key: {result.stderr}")
        return None
    
    # Extract key from output "Generated new API Key for 'test_user': <KEY>"
    for line in result.stdout.splitlines():
        if "Generated new API Key" in line:
            return line.split(": ")[1].strip()
    return None

def start_node():
    print("Starting Radix node...")
    # Start node in background with redirection to file
    log_file = open(LOG_FILE, "w")
    process = subprocess.Popen(
        [RADIX_BIN, "--config", CONFIG_FILE, "--server", "--rpc"],
        stdout=log_file,
        stderr=subprocess.STDOUT, # Redirect stderr to stdout
        text=True
    )
    time.sleep(30) # Wait for startup
    return process, log_file

def test_rpc(key=None):
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
        
    payload = {
        "jsonrpc": "2.0",
        "method": "getblockcount",
        "params": [],
        "id": 1
    }
    
    try:
        response = requests.post(RPC_URL, json=payload, headers=headers, timeout=2)
        return response
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None

def main():
    if not os.path.exists(RADIX_BIN):
        print(f"Error: {RADIX_BIN} not found. Please build the project first.")
        return

    setup()
    
    # 1. Generate Key
    api_key = generate_key()
    if not api_key:
        print("Failed to get API key")
        return
    print(f"Generated API Key: {api_key}")
    
    # 2. Start Node
    node_process, log_file_handle = start_node()
    
    try:
        # 3. Test Unauthorized Access
        print("\n--- Testing Unauthorized Access ---")
        resp = test_rpc(key=None)
        if resp and resp.status_code == 401:
            print("PASS: Unauthorized request rejected (401)")
        else:
            print(f"FAIL: Expected 401, got {resp.status_code if resp else 'None'}")
        
        time.sleep(1)

        # 4. Test Invalid Key
        print("\n--- Testing Invalid Key ---")
        resp = test_rpc(key="invalid_key_123")
        if resp and resp.status_code == 401:
            print("PASS: Invalid key rejected (401)")
        else:
            print(f"FAIL: Expected 401, got {resp.status_code if resp else 'None'}")

        time.sleep(1)

        # 5. Test Authorized Access
        print("\n--- Testing Authorized Access ---")
        resp = test_rpc(key=api_key)
        if resp and resp.status_code == 200:
            print("PASS: Authorized request accepted (200)")
            print(f"Response: {resp.json()}")
        else:
            print(f"FAIL: Expected 200, got {resp.status_code if resp else 'None'}")
            if resp: print(resp.text)

        time.sleep(1)

        # 6. Test Rate Limit (Authenticated)
        print("\n--- Testing Rate Limit (Authenticated) ---")
        
        success_count = 0
        for _ in range(10):
            resp = test_rpc(key=api_key)
            if resp and resp.status_code == 200:
                success_count += 1
        
        if success_count == 10:
             print("PASS: Multiple authenticated requests succeeded")
        else:
             print(f"FAIL: Only {success_count}/10 requests succeeded")

    finally:
        print("\nStopping node...")
        node_process.terminate()
        try:
             node_process.wait(timeout=5)
        except:
             node_process.kill()
             print("Node force killed.")
        
        log_file_handle.close()
        
        print("\n=== Node Output ===")
        with open(LOG_FILE, "r") as f:
             print(f.read())
        print("===================")

        # Cleanup
        if os.path.exists(CONFIG_FILE):
             os.remove(CONFIG_FILE)
        if os.path.exists(KEYS_FILE):
             os.remove(KEYS_FILE)
        if os.path.exists(LOG_FILE):
             os.remove(LOG_FILE)

if __name__ == "__main__":
    main()
