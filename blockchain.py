import hashlib
import time
import json
import threading
import logging
import psutil
import os
from flask import Flask, request, jsonify
from collections import defaultdict
from stem.control import Controller
from stem import Signal
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# ======================
# Setup Logging
# ======================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ======================
# Blockchain Core with UTXO
# ======================

class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.utxo = defaultdict(dict)
        self.block_time = 60
        self.difficulty = 4
        self.lock = threading.Lock()
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_tx = {
            'hash': 'genesis',
            'outputs': [{'recipient': '0'*64, 'amount': 1000000, 'index': 0}]
        }
        with self.lock:
            self.utxo['genesis'][0] = genesis_tx['outputs'][0]
        self.create_block(proof=100, previous_hash='0'*64, transactions=[genesis_tx])

    def create_block(self, proof, previous_hash, transactions):
        with self.lock:
            block = {
                'index': len(self.chain),
                'timestamp': time.time(),
                'transactions': transactions.copy(),
                'proof': proof,
                'previous_hash': previous_hash,
                'difficulty': self.difficulty,
                'nonce': 0
            }
            self.chain.append(block)
            return block

    def proof_of_work(self, last_proof):
        proof = 0
        while not self.valid_proof(last_proof, proof):
            proof += 1
        return proof

    def valid_proof(self, last_proof, proof):
        guess = f"{last_proof}{proof}".encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:self.difficulty] == '0' * self.difficulty

    def hash(self, block):
        return hashlib.sha256(json.dumps(block, sort_keys=True).encode()).hexdigest()

    def get_balance(self, address):
        balance = 0
        for tx_hash in self.utxo:
            for output in self.utxo[tx_hash].values():
                if output['recipient'] == address:
                    balance += output['amount']
        return balance

# ======================
# Wallet System
# ======================

class Wallet:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.serialize_public_key()
        self.address = hashlib.sha256(self.public_key.encode()).hexdigest()

    def serialize_public_key(self):
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

# ======================
# Tor Hidden Service Setup
# ======================

class TorHiddenService:
    def __init__(self, control_port=9051, hidden_service_dir='/var/lib/tor/hidden_service/', password=""):
        self.control_port = control_port
        self.hidden_service_dir = hidden_service_dir
        self.password = password
        self.hostname = None
        self.controller = self.connect_tor()
        self.setup_hidden_service()

    def connect_tor(self):
        try:
            controller = Controller.from_port(port=self.control_port)
            controller.authenticate(password=self.password)
            logging.info("Tor connected successfully!")
            return controller
        except Exception as e:
            logging.error(f"Tor connection failed: {e}")
            return None

    def setup_hidden_service(self):
        if not self.controller:
            return
        try:
            self.controller.signal(Signal.NEWNYM)
            self.controller.create_hidden_service(self.hidden_service_dir, 80, target_port=5000)
            with open(os.path.join(self.hidden_service_dir, "hostname"), "r") as f:
                self.hostname = f.read().strip()
            logging.info(f"Hidden Service running at {self.hostname}")
        except Exception as e:
            logging.error(f"Error setting up hidden service: {e}")

# ======================
# Flask Web Application
# ======================

app = Flask(__name__)
blockchain = Blockchain()
tor_service = TorHiddenService()
wallet = Wallet()

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {'chain': blockchain.chain, 'length': len(blockchain.chain)}
    return jsonify(response), 200

@app.route('/balance/<address>', methods=['GET'])
def get_balance(address):
    balance = blockchain.get_balance(address)
    return jsonify({'address': address, 'balance': balance}), 200

@app.route('/mine', methods=['GET'])
def mine_block():
    last_block = blockchain.chain[-1]
    proof = blockchain.proof_of_work(last_block['proof'])
    new_block = blockchain.create_block(proof, blockchain.hash(last_block), blockchain.pending_transactions)
    blockchain.pending_transactions = []
    return jsonify({'message': 'New block mined!', 'block': new_block}), 200

@app.route('/transaction', methods=['POST'])
def create_transaction():
    data = request.get_json()
    blockchain.pending_transactions.append(data)
    return jsonify({'message': 'Transaction added!'}), 201

@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    new_wallet = Wallet()
    return jsonify({'public_key': new_wallet.public_key, 'address': new_wallet.address}), 200

@app.route('/visualize/ascii', methods=['GET'])
def visualize_ascii():
    visualization = []
    for block in blockchain.chain:
        visualization.append(f"Block #{block['index']} | Hash: {blockchain.hash(block)[:10]}... | Proof: {block['proof']}")
    return '<pre>' + '\n'.join(visualization) + '</pre>'

if __name__ == '__main__':
    if tor_service.hostname:
        logging.info(f"Access your node at {tor_service.hostname}")
    app.run(host='127.0.0.1', port=5000, threaded=True)
