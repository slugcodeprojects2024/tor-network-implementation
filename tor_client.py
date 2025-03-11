import socket
import threading
import os
import ssl
import base64
import json
import random
import argparse
import time
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
        """Build a circuit using all nodes available"""
        if not self.known_nodes:
            self.request_node_list()
            
        circuit = []
        
        # First ensure we have all three nodes in known_nodes
        # If not, request private nodes if we're in private mode
        if len(self.known_nodes) < 3 and prefer_private:
            # Request private nodes with the auth token
            auth_token = "secret_token_123"  # Default token
            private_nodes = self.request_private_nodes(auth_token)
        
        # Add nodes to the circuit in order (0, 1, 2 for consistency)
        for node_id in range(3):  # Explicitly request nodes 0, 1, and 2
            if node_id in self.known_nodes:
                circuit.append({
                    'id': node_id,
                    'address': self.known_nodes[node_id]['address'],
                    'public_key': self.known_nodes[node_id]['public_key']
                })
            else:
                print(f"Warning: Node {node_id} not found in directory")
        
        # If we don't have enough nodes, print a warning
        if len(circuit) < length:
            print(f"Warning: Could only build a circuit with {len(circuit)} nodes (requested {length})")
        else:
            node_ids = [node['id'] for node in circuit]
            print(f"Created circuit: Node {node_ids[0]} → Node {node_ids[1]} → Node {node_ids[2]}")
        
        return circuit

class TorClient:
    def __init__(self, directory_service=None, auth_token=None, client_id=None):
        self.directory_service = directory_service or DirectoryService()
        self.auth_token = auth_token
        self.private_key, self.public_key = generate_rsa_key_pair()
        # Add a unique client ID (generate if not provided)
        self.client_id = client_id or random.randint(10000, 99999)
        # Register client key with directory
        self.register_client_key()
        
    def register_client_key(self):
        """Register this client's public key with the directory server"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(self.directory_service.directory_server)
                
                # Format client info as JSON
                client_info = {
                    'id': f"client_{self.client_id}",
                    'public_key': serialize_public_key(self.public_key).decode()
                }
                
                # Send registration message
                message = f"REGISTER_CLIENT {json.dumps(client_info)}".encode()
                s.sendall(message)
                
                # Get response
                response = s.recv(1024)
                if response == b"SUCCESS":
                    print(f"Client {self.client_id} registered with directory service")
                    return True
                else:
                    print(f"Registration failed: {response}")
                    return False
                    
        except Exception as e:
            print(f"Error registering with directory service: {e}")
            return False
    
    def encrypt_layer(self, data, public_key, next_address=None):
        """Encrypt a layer of data for the onion routing"""
        # Prepare the message
        if next_address:
            # If we have a next address, prepend it to the data
            ip, port = next_address
            prefix = f"ROUTE:{ip}:{port}:".encode('utf-8')
            message = prefix + data
        else:
            message = data
            
        # RSA encryption has size limitations
        # Maximum size for RSA 2048 with OAEP is around 190 bytes
        chunk_size = 190
        chunks = [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]
        
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
        """Build a layered encrypted request for a circuit of any length"""
        print(f"Building onion with {len(circuit)} layers")
        
        # Add client ID and public key to data so exit node knows who to encrypt for
        client_id_marker = f"CLIENT_ID:{self.client_id}:".encode()
        key_data = serialize_public_key(self.public_key) + b"::KEY_END::"
        data = client_id_marker + key_data + request_data
        print(f"Added client ID {self.client_id} and public key to request")
        
        # Start with the exit node (last in the circuit)
        exit_node_index = len(circuit) - 1
        exit_node = circuit[exit_node_index]
        print(f"Exit node is Node {exit_node['id']}")
        
        # First, encrypt with exit node's key
        data = self.encrypt_layer(data, exit_node['public_key'])
        print(f"Encrypted with exit node's key, size: {len(data)}")
        
        # For each remaining node, working backward
        for i in range(exit_node_index - 1, -1, -1):
            current_node = circuit[i]
            next_node = circuit[i + 1]
            
            # Encrypt with current node's key, including next node's address
            data = self.encrypt_layer(data, current_node['public_key'], next_node['address'])
            print(f"Encrypted with node {current_node['id']}'s key, size: {len(data)}")
        
        return data
    
    def send_request(self, circuit, encrypted_data):
        """Send the request through the first node in the circuit and handle the response"""
        try:
            # Get the entry node (first in the circuit)
            entry_node = circuit[0]
            
            print(f"Connecting to entry node {entry_node['id']} at {entry_node['address']}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(entry_node['address'])
                
                # Add end marker and send
                s.sendall(encrypted_data)
                s.sendall(b"::END::")
                print("Request sent, waiting for response...")
                
                # Receive the response
                s.settimeout(10.0)
                response = b""
                
                while True:
                    try:
                        chunk = s.recv(8192)
                        if not chunk:
                            print("Connection closed by server")
                            break
                        
                        response += chunk
                        print(f"Received chunk: {len(chunk)} bytes, total: {len(response)}")
                        
                        if b"::END::" in chunk:
                            response = response.split(b"::END::")[0]
                            print("End marker received")
                            break
                    except socket.timeout:
                        print("Socket timeout")
                        break
                
                if response:
                    print(f"Total response size: {len(response)} bytes")
                    
                    # Check for error messages
                    if response.startswith(b"ERROR:"):
                        print(f"Received error: {response.decode('utf-8')}")
                        return response
                    
                    # Try to decrypt the response
                    decrypted_response = self.decrypt_response(response)
                    return decrypted_response
                else:
                    print("No response received")
                    return None
        except Exception as e:
            print(f"Error sending request: {e}")
            return None
    
    def decrypt_response(self, encrypted_data):
        """Decrypt a response encrypted with our public key"""
        try:
            # Check if the response is an error message
            if encrypted_data.startswith(b"ERROR:"):
                return encrypted_data
                
            # Split the data into chunks using the delimiter
            chunk_delimiter = b"::CHUNK::"
            if chunk_delimiter in encrypted_data:
                encrypted_chunks = encrypted_data.split(chunk_delimiter)
                print(f"Splitting response into {len(encrypted_chunks)} chunks")
                
                # Decrypt each chunk
                decrypted_chunks = []
                for i, chunk in enumerate(encrypted_chunks):
                    if not chunk:  # Skip empty chunks
                        continue
                        
                    try:
                        # Base64 decode the chunk
                        padding_needed = len(chunk) % 4
                        if padding_needed:
                            chunk += b'=' * (4 - padding_needed)
                            
                        decoded_chunk = base64.b64decode(chunk)
                        
                        # Try to decrypt with our private key using OAEP padding
                        try:
                            decrypted_chunk = self.private_key.decrypt(
                                decoded_chunk,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                        except Exception as oaep_err:
                            # Fall back to PKCS1v15 padding
                            decrypted_chunk = self.private_key.decrypt(
                                decoded_chunk,
                                padding.PKCS1v15()
                            )
                            
                        decrypted_chunks.append(decrypted_chunk)
                        
                    except Exception as e:
                        print(f"Error decrypting chunk {i}: {e}")
                
                # Join the decrypted chunks
                if decrypted_chunks:
                    result = b"".join(decrypted_chunks)
                    return result
                else:
                    print("No chunks could be decrypted")
                    return encrypted_data
            else:
                # No delimiter, try to handle as a single encrypted chunk
                try:
                    # Make sure padding is correct for base64
                    padding_needed = len(encrypted_data) % 4
                    if padding_needed:
                        padded_data = encrypted_data + b'=' * (4 - padding_needed)
                    else:
                        padded_data = encrypted_data
                        
                    decoded_data = base64.b64decode(padded_data)
                    
                    # Try to decrypt with our private key
                    try:
                        decrypted_data = self.private_key.decrypt(
                            decoded_data,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                    except:
                        # Try PKCS1v15 padding
                        decrypted_data = self.private_key.decrypt(
                            decoded_data,
                            padding.PKCS1v15()
                        )
                        
                    return decrypted_data
                except:
                    pass
            
            # If decryption failed, return the encrypted data
            return encrypted_data
                    
        except Exception as e:
            print(f"Error in decrypt_response: {e}")
            return encrypted_data
    
    def process_response(self, response):
        """Process the response to extract and format HTTP content"""
        try:
            # If response is None or an error message, return as is
            if response is None or (isinstance(response, bytes) and response.startswith(b"ERROR:")):
                if response:
                    return response.decode('utf-8', errors='replace')
                return "No response received"
            
            # Check if this is an HTTP response
            if isinstance(response, bytes) and (b"HTTP/" in response[:20] or b"HTTP/" in response):
                # This is an HTTP response, try to find the headers and body
                header_end = response.find(b"\r\n\r\n")
                if header_end > 0:
                    headers = response[:header_end]
                    body = response[header_end + 4:]
                    
                    print("\n=== HTTP HEADERS ===")
                    print(headers.decode('utf-8', errors='replace'))
                    
                    # Try to detect Content-Type
                    content_type = None
                    for line in headers.split(b'\r\n'):
                        if line.lower().startswith(b'content-type:'):
                            content_type = line[13:].strip().decode('ascii', errors='ignore')
                            break
                            
                    # Handle JSON responses
                    if content_type and 'json' in content_type.lower():
                        try:
                            json_data = json.loads(body.decode('utf-8', errors='replace'))
                            print("\n=== JSON RESPONSE ===")
                            return json.dumps(json_data, indent=2)
                        except:
                            pass
                    
                    # Try to decode the body as text
                    try:
                        body_text = body.decode('utf-8', errors='replace')
                        return body_text
                    except:
                        # Last resort - return as binary
                        return body
                
                # If we couldn't parse headers/body, return the whole response as text
                try:
                    return response.decode('utf-8', errors='replace')
                except:
                    return f"Binary response ({len(response)} bytes)"
            
            # Check if response might be JSON data directly
            if isinstance(response, bytes) and response.startswith(b'{'):
                try:
                    json_data = json.loads(response.decode('utf-8', errors='replace'))
                    return json.dumps(json_data, indent=2)
                except:
                    pass
            
            # If not HTTP or JSON, try to decode as text
            if isinstance(response, bytes):
                try:
                    return response.decode('utf-8', errors='replace')
                except:
                    return f"Binary response ({len(response)} bytes)"
            
            # If already a string, return as is
            return response
            
        except Exception as e:
            print(f"Error processing response: {e}")
            if isinstance(response, bytes):
                try:
                    return response.decode('utf-8', errors='replace')
                except:
                    return f"Binary response ({len(response)} bytes)"
            return str(response)
    
    def browse(self, destination_host, request_path="/", circuit_length=3, use_private=False, force_all_nodes=False):
        """Send an HTTP request through the Tor circuit and return the response"""
        try:
            # Create HTTP request for destination
            request = f"GET {request_path} HTTP/1.1\r\nHost: {destination_host}\r\nConnection: close\r\n\r\n".encode()
            
            # Get node list if needed
            if not self.directory_service.known_nodes:
                self.directory_service.request_node_list()
                
                # Request private nodes if needed
                if (use_private or force_all_nodes) and self.auth_token:
                    self.directory_service.request_private_nodes(self.auth_token)
            
            # Build circuit
            circuit = self.directory_service.build_circuit(length=circuit_length, prefer_private=use_private)
            
            if len(circuit) < circuit_length:
                print(f"Warning: Could only build a circuit with {len(circuit)} nodes (requested {circuit_length})")
                if len(circuit) == 0:
                    return "Error: Could not build a circuit, no nodes available"
            
            # Build the onion-encrypted request
            encrypted_request = self.build_onion_request(circuit, request)
            
            # Send the request through the first node in the circuit
            response = self.send_request(circuit, encrypted_request)
            
            # Process the response
            processed_response = self.process_response(response)
            return processed_response
            
        except Exception as e:
            print(f"Error browsing through Tor: {e}")
            import traceback
            traceback.print_exc()
            return f"Error: {str(e)}"

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

def parse_arguments():
    parser = argparse.ArgumentParser(description='Tor-like client implementation')
    parser.add_argument('--private', action='store_true', help='Use private nodes')
    parser.add_argument('--token', type=str, default="secret_token_123", help='Auth token for private nodes')
    parser.add_argument('--host', type=str, default="httpbin.org", help='Destination host')
    parser.add_argument('--path', type=str, default="/get", help='Request path')
    parser.add_argument('--force3', action='store_true', help='Force using all 3 nodes even in public mode')
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    # Create a directory service
    directory_service = DirectoryService()
    
    # Create a Tor client with the directory service and optional auth token
    # Set auth token if either private or force3 is enabled
    auth_token = args.token if (args.private or args.force3) else None
    tor_client = TorClient(directory_service, auth_token)
    
    print(f"\n=== TESTING WITH {'PRIVATE' if args.private else 'PUBLIC'} NODES ===\n")
    
    # Get the list of public nodes
    directory_service.request_node_list()
    
    # If in private mode or force3 mode, explicitly request private nodes
    if args.private or args.force3:
        directory_service.request_private_nodes(args.token)
    
    # Use the client to browse through the Tor network
    response = tor_client.browse(
        destination_host=args.host,
        request_path=args.path,
        circuit_length=3,  # Always request 3 nodes
        use_private=args.private or args.force3  # Use private nodes if force3 is set
    )
    
    print("\n=== RESPONSE ===\n")
    print(response)

if __name__ == "__main__":
    main()