import socket
import threading
import os
import ssl
import base64
import json
import random
from time import sleep
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

class DirectoryService:
    def __init__(self, directory_server_address=('127.0.0.1', 6000)):
        self.directory_server = directory_server_address
        self.known_nodes = {}  # {node_id: {'address': address, 'public_key': public_key_obj}}
        self.private_key, self.public_key = generate_rsa_key_pair()
        
    def request_node_list(self):
        """Request the list of all available nodes from directory server"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(self.directory_server)
                s.sendall(b"LIST")
                response = s.recv(8192)
                # Parse the response and update known_nodes
                node_data = json.loads(response.decode())
                
                for node_id, info in node_data.items():
                    node_id = int(node_id)  # Convert string keys back to integers
                    address = tuple(info['address'])  # Convert list back to tuple
                    # Convert public key from string to cryptography PublicKey object
                    public_key = serialization.load_pem_public_key(info['public_key'].encode())
                    self.known_nodes[node_id] = {
                        'address': address,
                        'public_key': public_key
                    }
                
                print(f"Received information about {len(self.known_nodes)} nodes")
                return self.known_nodes
        except Exception as e:
            print(f"Error requesting node list: {e}")
            return {}
    
    def request_private_nodes(self, auth_token):
        """Request access to private nodes with authentication"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(self.directory_server)
                # Send auth token to get private nodes
                auth_message = f"PRIVATE {auth_token}".encode()
                s.sendall(auth_message)
                response = s.recv(8192)
                
                # Parse the response and update known_nodes
                private_node_data = json.loads(response.decode())
                private_nodes = {}
                
                for node_id, info in private_node_data.items():
                    node_id = int(node_id)  # Convert string keys back to integers
                    address = tuple(info['address'])  # Convert list back to tuple
                    # Convert public key from string to cryptography PublicKey object
                    public_key = serialization.load_pem_public_key(info['public_key'].encode())
                    private_nodes[node_id] = {
                        'address': address,
                        'public_key': public_key
                    }
                    # Also update main known_nodes dictionary
                    self.known_nodes[node_id] = private_nodes[node_id]
                
                print(f"Received information about {len(private_nodes)} private nodes")
                return private_nodes
        except Exception as e:
            print(f"Error requesting private nodes: {e}")
            return {}
    
    def build_circuit(self, length=3, prefer_private=False):
        """Build a circuit of specified length, optionally preferring private nodes"""
        if not self.known_nodes:
            self.request_node_list()
            
        if len(self.known_nodes) < length:
            raise ValueError(f"Not enough nodes available. Need {length}, have {len(self.known_nodes)}")
        
        # Get node IDs and convert to list for random selection
        node_ids = list(self.known_nodes.keys())
        
        # Simple random selection for now
        # In a real implementation, you might want to consider node diversity, 
        # reliability, bandwidth, etc.
        selected_ids = random.sample(node_ids, length)
        
        # Build the circuit with node information
        circuit = []
        for node_id in selected_ids:
            circuit.append({
                'id': node_id,
                'address': self.known_nodes[node_id]['address'],
                'public_key': self.known_nodes[node_id]['public_key']
            })
            
        return circuit

class TorClient:
    def __init__(self, directory_service=None, auth_token=None):
        self.directory_service = directory_service or DirectoryService()
        self.auth_token = auth_token
        self.private_key, self.public_key = generate_rsa_key_pair()
        
    def encrypt_layer(self, data, public_key, next_address=None):
        """
        Encrypt a layer of data for the onion routing
        If next_address is provided, it's included in the encrypted data
        """
        # Prepare the message
        if next_address:
            # If we have a next address, prepend it to the data
            ip, port = next_address
            
            # Use a very clear delimiter format that's unlikely to be misinterpreted
            # Format: "ROUTE:127.0.0.1:5001:"
            prefix = f"ROUTE:{ip}:{port}:".encode('utf-8')
            print(f"Adding routing prefix: {prefix}")
            message = prefix + data
            print(f"Message with routing prefix starts with: {message[:50]}")
        else:
            message = data
            
        # RSA encryption has size limitations
        # Maximum size for RSA 2048 with OAEP is around 190 bytes
        chunk_size = 190
        chunks = [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]
        print(f"Split into {len(chunks)} chunks for encryption")
        
        for i, chunk in enumerate(chunks):
            print(f"Chunk {i} length: {len(chunk)}")
            if i == 0 and next_address:
                print(f"First chunk starts with: {chunk[:20]}")
        
        # Encrypt each chunk
        encrypted_chunks = []
        for chunk in chunks:
            encrypted_chunk = public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_chunks.append(encrypted_chunk)
            
        # Join chunks with a delimiter
        chunk_delimiter = b"::CHUNK::"
        encoded_chunks = [base64.b64encode(chunk) for chunk in encrypted_chunks]
        encrypted_data = chunk_delimiter.join(encoded_chunks)
        
        return encrypted_data
    
    def build_onion_request(self, circuit, request_data):
        """Build a layered encrypted request"""
        print(f"Building onion with {len(circuit)} layers")
        data = request_data  # Start with the plaintext HTTP request
        print(f"Original request: {data[:50]}")
        
        # Build the onion from the exit node back to the entry node
        for i in range(len(circuit) - 1, -1, -1):
            node = circuit[i]
            print(f"Layer {i}: Using node {node['id']}")
            
            if i > 0:  # If not the entry node, include the next hop's address
                next_node = circuit[i-1]
                next_ip, next_port = next_node['address']
                
                # Format with very clear prefix
                message = f"ROUTE:{next_ip}:{next_port}:".encode() + data
                print(f"Layer {i}: Adding routing to {next_ip}:{next_port}")
                print(f"Layer {i}: Message starts with: {message[:50]}")
                
                # Use node's public key to encrypt
                data = self.encrypt_layer(message, node['public_key'])
                print(f"Layer {i}: Encrypted size: {len(data)}")
            else:
                # Entry node (outermost layer)
                print(f"Layer {i}: Final encryption for entry node")
                data = self.encrypt_layer(data, node['public_key'])
                print(f"Layer {i}: Final encrypted size: {len(data)}")
        
        print(f"Final encrypted data size: {len(data)} bytes")        
        return data
    
    def send_request(self, entry_node, encrypted_data):
        """Send the request to the entry node and get the response"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(entry_node['address'])
                print(f"Connected to entry node at {entry_node['address']}")
                
                # Send the encrypted data
                s.sendall(encrypted_data)
                print("Request sent, waiting for response...")
                
                # Receive the response
                # In a real implementation, you'd need to handle chunking for large responses
                s.settimeout(10.0)  # Set a reasonable timeout
                response = b""
                while True:
                    try:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                    except socket.timeout:
                        break
                        
                return response
        except Exception as e:
            print(f"Error sending request: {e}")
            return None
            
    def browse(self, destination_host, request_path="/", circuit_length=3, use_private=False):
        """
        Main method to send a request through the Tor network
        Returns the response from the destination server
        """
        # 1. Set up directory service and get node information
        self.directory_service.request_node_list()  # Always get public nodes
        
        # Additionally get private nodes if requested
        if use_private and self.auth_token:
            self.directory_service.request_private_nodes(self.auth_token)
            
        print(f"Total nodes available: {len(self.directory_service.known_nodes)}")
            
        # 2. Build a circuit
        try:
            circuit = self.directory_service.build_circuit(length=circuit_length, prefer_private=use_private)
            print(f"Built circuit with {len(circuit)} nodes")
        except ValueError as e:
            print(f"Error building circuit: {e}")
            return None
            
        # 3. Create the HTTP request
        request = f"GET {request_path} HTTP/1.1\r\nHost: {destination_host}\r\n\r\n".encode()
        
        # 4. Build the onion-encrypted request
        encrypted_request = self.build_onion_request(circuit, request)
        
        # 5. Send the request through the entry node
        entry_node = circuit[0]
        response = self.send_request(entry_node, encrypted_request)
        
        # 6. Return the response (already decrypted by the exit node)
        return response

# Generate RSA key pair using cryptography library
def generate_rsa_key_pair():
    # Generate a new RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Extract the public key
    public_key = private_key.public_key()
    
    return private_key, public_key

# Serialization helpers for keys
def serialize_private_key(private_key):
    """Convert private key to PEM format string"""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def serialize_public_key(public_key):
    """Convert public key to PEM format string"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def test_single_node_encryption():
    """Test direct encryption/decryption with a single node"""
    print("\n=== RUNNING ENCRYPTION TEST ===\n")
    
    # Connect to directory to get node info
    directory_service = DirectoryService()
    directory_service.request_node_list()
    
    # Get any node
    if not directory_service.known_nodes:
        print("No nodes available for testing")
        return
        
    node_id = list(directory_service.known_nodes.keys())[0]
    node = directory_service.known_nodes[node_id]
    
    # Create a simple message
    original_message = b"ROUTE:127.0.0.1:5001:TEST MESSAGE"
    print(f"Original message: {original_message}")
    
    # Encrypt with the node's public key
    client = TorClient(directory_service)
    encrypted = client.encrypt_layer(original_message, node['public_key'])
    
    # Output the encrypted data for debugging
    print(f"Encrypted length: {len(encrypted)}")
    print(f"Encrypted format: {encrypted[:50]} [...] {encrypted[-50:]}")
    
    # Connect to the node directly
    print(f"Connecting to node {node_id} at {node['address']}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(node['address'])
        s.sendall(encrypted)
        # No need to wait for response, we're just testing encryption
    
    print("\n=== ENCRYPTION TEST COMPLETE ===\n")

DESTINATION_HOST = "www.google.com"
def main():
    # Create a directory service
    directory_service = DirectoryService()
    
    # Create a Tor client with the directory service
    # Optionally provide an auth token for private nodes
    auth_token = "secret_token_123"  # This would be agreed upon with your partner
    tor_client = TorClient(directory_service, auth_token)
    
    # Test single node encryption
    test_single_node_encryption()
    
    # Use the client to browse through the Tor network
    # Set use_private=True to use private nodes if available
    response = tor_client.browse(
        destination_host=DESTINATION_HOST,
        request_path="/",
        circuit_length=2,  # Minimum of 2 per requirements
        use_private=True
    )
    
    if response:
        # Print the response
        print("Response received:")
        print(response.decode(errors='replace'))
    else:
        print("Failed to get a response")

if __name__ == "__main__":
    main()