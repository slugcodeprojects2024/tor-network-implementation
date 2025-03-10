import socket
import threading
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

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

class DirectoryServer:
    def __init__(self, address=('127.0.0.1', 6000)):
        self.address = address
        self.nodes = {}  # {node_id: {'address': addr, 'public_key': key_str, 'is_private': bool}}
        self.clients = {}  # {client_id: {'public_key': key_str}}
        self.private_key, self.public_key = generate_rsa_key_pair()
        self.auth_tokens = {
            "secret_token_123": {"access_level": "full"},
            "demo_token": {"access_level": "limited"}
        }
        
    def start(self):
        """Start the directory server"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(self.address)
            s.listen()
            print(f"Directory server listening on {self.address[0]}:{self.address[1]}")
            while True:
                conn, addr = s.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.start()
    
    def handle_client(self, conn, addr):
        """Handle incoming connections from nodes and clients"""
        try:
            data = conn.recv(4096)
            message = data.decode()
            
            if message.startswith("REGISTER "):
                # Handle node registration
                node_info = json.loads(message[9:])  # Extract JSON after "REGISTER "
                node_id = node_info['id']
                
                # Store the node information
                self.nodes[node_id] = {
                    'address': node_info['address'],
                    'public_key': node_info['public_key'],  # This is already PEM format string
                    'is_private': node_info.get('is_private', False)
                }
                
                print(f"Registered node {node_id} at {node_info['address']}")
                conn.sendall(b"SUCCESS")
            
            elif message.startswith("REGISTER_CLIENT "):
                # Handle client registration
                try:
                    client_info = json.loads(message[16:])  # Extract JSON after "REGISTER_CLIENT "
                    client_id = client_info['id']
                    
                    # Store the client information
                    self.clients[client_id] = {
                        'public_key': client_info['public_key']  # This is already PEM format string
                    }
                    
                    print(f"Registered client {client_id}")
                    conn.sendall(b"SUCCESS")
                except Exception as e:
                    print(f"Error registering client: {e}")
                    conn.sendall(b"ERROR")
                
            elif message.startswith("GETKEY "):
                # Handle request for a node's public key
                try:
                    node_id = int(message[7:])
                    if node_id in self.nodes:
                        # Return the public key for this node
                        print(f"Sending public key for node {node_id} to {addr}")
                        conn.sendall(self.nodes[node_id]['public_key'].encode())
                    else:
                        print(f"Node {node_id} not found, request from {addr}")
                        conn.sendall(b"NOTFOUND")
                except Exception as e:
                    print(f"Error processing GETKEY request: {e}")
                    conn.sendall(b"ERROR")
            
            elif message.startswith("GETCLIENTKEY "):
                # Handle request for a client's public key
                try:
                    client_id = message[13:]  # Extract client ID after "GETCLIENTKEY "
                    if client_id in self.clients:
                        # Return the public key for this client
                        print(f"Sending public key for client {client_id} to {addr}")
                        conn.sendall(self.clients[client_id]['public_key'].encode())
                    else:
                        print(f"Client {client_id} not found, request from {addr}")
                        conn.sendall(b"NOTFOUND")
                except Exception as e:
                    print(f"Error processing GETCLIENTKEY request: {e}")
                    conn.sendall(b"ERROR")
            
            elif message == "LIST":
                # Return list of public nodes
                public_nodes = {id: info for id, info in self.nodes.items() 
                               if not info['is_private']}
                
                # Convert to string for transmission
                response = json.dumps(public_nodes)
                conn.sendall(response.encode())
                print(f"Sent list of {len(public_nodes)} public nodes to {addr}")
                
            elif message.startswith("PRIVATE"):
                # Handle private node access request
                auth_token = message[8:]  # Extract token after "PRIVATE "
                
                # Verify the token
                if auth_token in self.auth_tokens:
                    # Get nodes the token has access to (all private nodes for now)
                    # In a real system, you'd have more granular access control
                    authorized_private_nodes = {
                        id: info for id, info in self.nodes.items() 
                        if info['is_private']
                    }
                    
                    response = json.dumps(authorized_private_nodes)
                    conn.sendall(response.encode())
                    print(f"Sent list of {len(authorized_private_nodes)} private nodes to authorized client")
                else:
                    # Token not authorized
                    conn.sendall(json.dumps({}).encode())
                    print(f"Rejected unauthorized private node request from {addr}")
                
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            conn.close()
    
    def save_state(self, filename="directory_state.json"):
        """Save the current state of registered nodes and clients to a file"""
        # Convert node data to serializable format
        serializable_nodes = {}
        for node_id, info in self.nodes.items():
            serializable_nodes[str(node_id)] = {
                'address': info['address'],
                'public_key': info['public_key'],
                'is_private': info['is_private']
            }
        
        # Convert client data to serializable format
        serializable_clients = {}
        for client_id, info in self.clients.items():
            serializable_clients[client_id] = {
                'public_key': info['public_key']
            }
            
        with open(filename, 'w') as f:
            json.dump({
                'nodes': serializable_nodes,
                'clients': serializable_clients,
                'auth_tokens': self.auth_tokens
            }, f)
        
        print(f"Directory state saved to {filename}")
    
    def load_state(self, filename="directory_state.json"):
        """Load node and client state from a file"""
        if not os.path.exists(filename):
            print(f"State file {filename} not found")
            return False
            
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                
            # Load nodes
            self.nodes = {}
            for node_id_str, info in data['nodes'].items():
                self.nodes[int(node_id_str)] = info
            
            # Load clients if present
            if 'clients' in data:
                self.clients = {}
                for client_id, info in data['clients'].items():
                    self.clients[client_id] = info
                
            # Load auth tokens
            self.auth_tokens = data['auth_tokens']
            
            client_count = len(self.clients) if hasattr(self, 'clients') else 0
            print(f"Loaded {len(self.nodes)} nodes, {client_count} clients, and {len(self.auth_tokens)} auth tokens")
            return True
        except Exception as e:
            print(f"Error loading state: {e}")
            return False

if __name__ == "__main__":
    # Create and start the directory server
    server = DirectoryServer()
    
    # Try to load saved state
    server.load_state()
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("Directory server shutting down...")
        server.save_state()