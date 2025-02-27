import requests
import socks
import socket
import logging
import hashlib
import json
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# ======================
# Setup Logging
# ======================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ======================
# Tor Proxy Configuration
# ======================
TOR_SOCKS_PROXY = "127.0.0.1:9050"  # Tor SOCKS5 Proxy
BLOCKCHAIN_NODE_ONION = "your_hidden_service.onion"  # Ersetze mit der .onion-Adresse des Nodes

socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
socket.socket = socks.socksocket

# ======================
# Blockchain Client Functions
# ======================

def get_chain():
    url = f"http://{BLOCKCHAIN_NODE_ONION}/chain"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        logging.info("Blockchain received successfully.")
        return response.json()
    except requests.RequestException as e:
        logging.error(f"Failed to connect to node: {e}")
    return None

def get_balance(address):
    url = f"http://{BLOCKCHAIN_NODE_ONION}/balance/{address}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        logging.info("Balance retrieved successfully.")
        return response.json()
    except requests.RequestException as e:
        logging.error(f"Failed to connect to node: {e}")
    return None

def mine_block():
    url = f"http://{BLOCKCHAIN_NODE_ONION}/mine"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        logging.info("Mining successful.")
        return response.json()
    except requests.RequestException as e:
        logging.error(f"Failed to connect to node: {e}")
    return None

def send_transaction(sender, recipient, amount, signature):
    url = f"http://{BLOCKCHAIN_NODE_ONION}/transaction"
    payload = {
        "sender": sender,
        "recipient": recipient,
        "amount": amount,
        "signature": signature
    }
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        logging.info("Transaction sent successfully.")
        return response.json()
    except requests.RequestException as e:
        logging.error(f"Failed to connect to node: {e}")
    return None

def visualize_ascii():
    url = f"http://{BLOCKCHAIN_NODE_ONION}/visualize/ascii"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        logging.info("Blockchain ASCII visualization received successfully.")
        print(response.text)
    except requests.RequestException as e:
        logging.error(f"Failed to connect to node: {e}")

# ======================
# Blockchain Integrity Check
# ======================

def verify_chain():
    blockchain_data = get_chain()
    if not blockchain_data:
        logging.error("Failed to fetch blockchain data.")
        return False
    
    chain = blockchain_data['chain']
    for i in range(1, len(chain)):
        prev_block = chain[i - 1]
        current_block = chain[i]
        if current_block['previous_hash'] != hashlib.sha256(json.dumps(prev_block, sort_keys=True).encode()).hexdigest():
            logging.warning("Blockchain integrity compromised! Requesting valid chain.")
            return replace_invalid_chain()
    logging.info("Blockchain integrity verified.")
    return True

def replace_invalid_chain():
    logging.info("Requesting valid blockchain copy from peers...")
    return None

# ======================
# Wallet Generation
# ======================

def generate_wallet():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    return {"public_key": public_key, "private_key": private_key_pem}

# ======================
# Main Execution
# ======================

if __name__ == "__main__":
    logging.info("Connecting to the Blockchain Node via Tor...")
    verify_chain()
    
    new_wallet = generate_wallet()
    logging.info(f"New Wallet Public Key: {new_wallet['public_key']}")
    
    example_address = "your_wallet_address_here"
    balance_data = get_balance(example_address)
    if balance_data:
        logging.info(f"Balance for {example_address}: {balance_data['balance']}")
    
    visualize_ascii()
    
    mine_block()