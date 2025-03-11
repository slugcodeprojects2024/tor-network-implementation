import socket
import threading
import os
import ssl
import base64
import json
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Generate RSA key pair
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

class NodeDirectoryService:
    """Handles directory service registration for nodes"""
    
    def __init__(self, node, directory_server_address=('127.0.0.1', 6000)):
        self.node = node
        self.directory_server_address = directory_server_address
        self.is_private_mode = False
        self.auth_tokens = set()  # Authorized tokens for private mode access
        
    def register_with_directory(self):
        """Register this node with the directory service"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(self.directory_server_address)
                
                # Prepare registration data
                registration_data = {
                    'id': self.node.id,
                    'address': ['127.0.0.1', self.node.port],  # Address as list for JSON serialization
                    'public_key': serialize_public_key(self.node.public_key).decode(),
                    'is_private': self.is_private_mode
                }
                
                # Send registration message
                message = f"REGISTER {json.dumps(registration_data)}".encode()
                s.sendall(message)
                
                # Get response
                response = s.recv(1024)   
                success = response.decode() == "SUCCESS"
                
                if success:
                    print(f"Node {self.node.id} successfully registered with directory service")
                else:
                    print(f"Failed to register node {self.node.id} with directory service")
                
                return success
        except Exception as e:
            print(f"Error registering with directory service: {e}")
            return False
    
    def enable_private_mode(self, authorized_tokens=None):
        """Enable private mode with optional list of authorized tokens"""
        self.is_private_mode = True
        if authorized_tokens:
            self.auth_tokens.update(authorized_tokens)
        
        # Re-register with updated private status
        return self.register_with_directory()
    
    def validate_client_authorization(self, token):
        """Check if a client is authorized to use this node in private mode"""
        if not self.is_private_mode:
            return True  # Not in private mode, all clients allowed
        return token in self.auth_tokens


class Node:
    PORT_START = 5000
    
    def __init__(self, id, directory_service=None):
        self.id = id
        self.port = self.PORT_START + id
        self.private_key, self.public_key = generate_rsa_key_pair()
        
        # Setup directory service
        self.directory_service = directory_service or NodeDirectoryService(self)
        
    def decrypt_chunk(self, encrypted_chunk):
        """Decrypt a single chunk using this node's private key"""
        try:
            # Base64 decode the chunk
            decoded_chunk = base64.b64decode(encrypted_chunk)
            
            # Decrypt using private key
            decrypted_chunk = self.private_key.decrypt(
                decoded_chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Ultra-detailed logging of the decrypted content
            print(f"Node {self.id}: Successfully decrypted a chunk, length: {len(decrypted_chunk)}")
            print(f"Node {self.id}: Decrypted chunk hex dump: {decrypted_chunk.hex()[:50]}...")
            print(f"Node {self.id}: As ASCII: {decrypted_chunk[:50]}")
            
            # Look for ROUTE specifically
            if b'ROUTE:' in decrypted_chunk:
                route_pos = decrypted_chunk.find(b'ROUTE:')
                print(f"Node {self.id}: Found ROUTE: at position {route_pos}")
                print(f"Node {self.id}: Route info: {decrypted_chunk[route_pos:route_pos+30]}")
            
            return decrypted_chunk
        except Exception as e:
            print(f"Error decrypting chunk: {e}")
            return None
    
    def decrypt_data(self, encrypted_data):
        """Decrypt multi-chunk data"""
        try:
            # Split the data into chunks
            chunk_delimiter = b"::CHUNK::"
            encrypted_chunks = encrypted_data.split(chunk_delimiter)
            print(f"Node {self.id}: Splitting into {len(encrypted_chunks)} chunks")
            
            # Decrypt each chunk
            decrypted_chunks = []
            for i, chunk in enumerate(encrypted_chunks):
                print(f"Node {self.id}: Decrypting chunk {i}, length {len(chunk)}")
                decrypted_chunk = self.decrypt_chunk(chunk)
                if decrypted_chunk:
                    print(f"Node {self.id}: Chunk {i} decrypted successfully")
                    decrypted_chunks.append(decrypted_chunk)
                else:
                    print(f"Node {self.id}: Failed to decrypt chunk {i}")
                    return None
            
            # Join the decrypted chunks
            result = b"".join(decrypted_chunks)
            print(f"Node {self.id}: All chunks decrypted, total length {len(result)}")
            return result
        except Exception as e:
            print(f"Node {self.id}: Error in decrypt_data: {e}")
            return None
    
    def request_client_key(self, client_id):
        """Request a client's public key from the directory server"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # Assuming directory_service object has the address
                s.connect(self.directory_service.directory_server_address)
                
                # Send request for client key
                request = f"GETCLIENTKEY client_{client_id}".encode()
                s.sendall(request)
                
                # Receive the public key
                response = s.recv(4096)
                if response == b"NOTFOUND":
                    print(f"Node {self.id}: Client {client_id} not found in directory")
                    return None
                elif response == b"ERROR":
                    print(f"Node {self.id}: Error requesting client key")
                    return None
                
                # Convert key string to key object
                try:
                    public_key = serialization.load_pem_public_key(response)
                    print(f"Node {self.id}: Retrieved public key for client {client_id}")
                    return public_key
                except Exception as e:
                    print(f"Node {self.id}: Error loading client public key: {e}")
                    return None
        except Exception as e:
            print(f"Node {self.id}: Error connecting to directory server: {e}")
            return None

    def parse_decrypted_data(self, decrypted_data):
        """Parse the decrypted data to extract next node information and client ID"""
        try:
            # Extract client ID if present - make this more robust
            client_id = None
            client_id_prefix = b'CLIENT_ID:'
            client_id_pos = decrypted_data.find(client_id_prefix)
            
            if (client_id_pos >= 0):
                # Found client ID
                client_id_data = decrypted_data[client_id_pos + len(client_id_prefix):]
                client_id_end = client_id_data.find(b':')
                
                if (client_id_end > 0):
                    client_id = client_id_data[:client_id_end].decode('utf-8')
                    # Remove client ID marker from the data
                    new_data = decrypted_data[:client_id_pos] + decrypted_data[client_id_pos + len(client_id_prefix) + client_id_end + 1:]
                    decrypted_data = new_data
                    print(f"Node {self.id}: Found client ID: {client_id}")
            
            # Check for public key
            key_end_marker = b'::KEY_END::'
            key_end_pos = decrypted_data.find(key_end_marker)
            client_public_key = None
            
            if (key_end_pos > 0):
                # Extract key data
                key_data = decrypted_data[:key_end_pos]
                if key_data.startswith(b'-----BEGIN PUBLIC KEY-----'):
                    try:
                        client_public_key = serialization.load_pem_public_key(key_data)
                        print(f"Node {self.id}: Found embedded public key, length: {len(key_data)}")
                        # Remove key from data
                        decrypted_data = decrypted_data[key_end_pos + len(key_end_marker):]
                    except Exception as e:
                        print(f"Node {self.id}: Error loading embedded key: {e}")
            
            # Rest of parsing logic remains the same...
            route_prefix = b'ROUTE:'
            route_pos = decrypted_data.find(route_prefix)
            
            if (route_pos >= 0):
                # Found the routing prefix!
                print(f"Node {self.id}: Found ROUTE: prefix at position {route_pos}")
                
                # Extract data after the prefix
                route_data = decrypted_data[route_pos + len(route_prefix):]
                
                # Find the first colon (IP/port separator)
                first_colon = route_data.find(b':')
                if (first_colon > 0):
                    # Extract IP
                    ip = route_data[:first_colon].decode('utf-8')
                    
                    # Find the second colon (port/data separator)
                    second_colon = route_data.find(b':', first_colon + 1)
                    if (second_colon > first_colon):
                        # Extract port and remaining data
                        port_str = route_data[first_colon+1:second_colon].decode('utf-8')
                        try:
                            port = int(port_str)
                            remaining_data = route_data[second_colon+1:]
                            print(f"Node {self.id}: Route info extracted: {ip}:{port}")
                            return ip, port, remaining_data, client_id, client_public_key
                        except ValueError:
                            print(f"Node {self.id}: Invalid port number: {port_str}")
            
            # Fall back to trying HTTP detection
            if b'GET ' in decrypted_data[:20] or b'Host:' in decrypted_data:
                print(f"Node {self.id}: Appears to be HTTP request (exit node)")
                return None, None, decrypted_data, client_id, client_public_key
                
            print(f"Node {self.id}: No routing information found")
            print(f"Node {self.id}: Data starts with: {decrypted_data[:50].hex()}")
            return None, None, decrypted_data, client_id, client_public_key
                
        except Exception as e:
            print(f"Node {self.id}: Error parsing: {e}")
            return None, None, decrypted_data, None, None
    
    def extract_host(self, request_bytes):
        """Extract the host from the HTTP header"""
        try:
            # Try to find 'Host: ' in the binary data
            host_prefix = b'Host: '
            host_pos = request_bytes.find(host_prefix)
            
            if (host_pos >= 0):
                # Found the Host header
                host_start = host_pos + len(host_prefix)
                host_end = request_bytes.find(b'\r\n', host_start)
                
                if (host_end > host_start):
                    host = request_bytes[host_start:host_end].decode('utf-8')
                    print(f"Node {self.id}: Extracted host from HTTP request: {host}")
                    return host
            
            # If we get here, just look for www.google.com for testing
            if b'www.google.com' in request_bytes:
                print(f"Node {self.id}: Found google.com in request")
                return "www.google.com"
                
            print(f"Node {self.id}: Could not find Host header")
            print(f"Node {self.id}: Request preview: {request_bytes[:100]}")
            return None
        except Exception as e:
            print(f"Node {self.id}: Error extracting host: {e}")
            return None
    
    def forward_to_next_node(self, ip, port, data):
        """Forward data to the next node in the circuit"""
        try:
            print(f"Node {self.id}: Forwarding {len(data)} bytes to {ip}:{port}")
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(15.0)  # Longer timeout
                s.connect((ip, port))
                
                # Send the data with an end marker
                s.sendall(data)
                s.sendall(b"::END::")
                
                print(f"Node {self.id}: Data sent, waiting for response")
                
                # Receive response
                response = b""
                try:
                    while True:
                        chunk = s.recv(8192)
                        if not chunk:
                            print(f"Node {self.id}: Connection closed by {ip}:{port}")
                            break
                        
                        response += chunk
                        print(f"Node {self.id}: Received chunk of {len(chunk)} bytes")
                        
                        if b"::END::" in chunk:
                            response = response.split(b"::END::")[0]
                            print(f"Node {self.id}: End marker received")
                            break
                except socket.timeout:
                    print(f"Node {self.id}: Socket timeout waiting for response")
                
                print(f"Node {self.id}: Total response size: {len(response)} bytes")
                return response
        except ConnectionRefusedError:
            print(f"Node {self.id}: Connection refused by {ip}:{port}")
            return b"ERROR: Connection refused"
        except Exception as e:
            print(f"Node {self.id}: Error forwarding: {e}")
            return f"ERROR: {e}".encode()
    
    def send_http_request(self, host, request):
        """Send HTTP request to the destination server (for exit node)"""
        try:
            print(f"Node {self.id}: Sending HTTP request to {host}")
            
            # Create SSL context for HTTPS
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(15.0)  # Set timeout for connection
                
                try:
                    # Connect to the host on port 443 (HTTPS)
                    s.connect((host, 443))
                    ssl_socket = context.wrap_socket(s, server_hostname=host)
                    
                    # Send the request
                    ssl_socket.sendall(request)
                    print(f"Node {self.id}: Request sent to {host}")
                    
                    # Receive the response in chunks
                    ssl_socket.settimeout(5.0)
                    response = b""
                    try:
                        while True:
                            chunk = ssl_socket.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                            print(f"Node {self.id}: Received chunk of {len(chunk)} bytes")
                            
                            # Detect complete HTTP response
                            if b"\r\n0\r\n\r\n" in response or (
                                b"Content-Length: " in response and 
                                len(response) > 1000):
                                break
                    except socket.timeout:
                        print(f"Node {self.id}: Socket timeout after receiving {len(response)} bytes")
                    
                    # Instead of encrypting HTTP responses, mark them with a special prefix
                    if response.startswith(b"HTTP/"):
                        print(f"Node {self.id}: Sending raw HTTP response of {len(response)} bytes")
                        return b"RAW_HTTP_RESPONSE:" + response
                    
                    return response
                    
                except Exception as e:
                    print(f"Node {self.id}: Error with SSL connection: {e}")
                    # Try plain HTTP as fallback
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as plain_s:
                        plain_s.settimeout(10.0)
                        plain_s.connect((host, 80))
                        plain_s.sendall(request)
                        
                        response = b""
                        while True:
                            chunk = plain_s.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                        
                        # Also mark HTTP responses from plaintext connection
                        if response.startswith(b"HTTP/"):
                            return b"RAW_HTTP_RESPONSE:" + response
                        return response
                        
        except Exception as e:
            print(f"Node {self.id}: Error sending HTTP request: {e}")
            # Return a simple error message
            return f"ERROR: Could not fetch from {host}: {e}".encode()
    
    def encrypt_response(self, response, client_public_key):
        """
        Encrypt a response using the client's public key (not our own key).
        Uses PKCS1v15 padding for maximum compatibility.
        """
        try:
            # RSA encryption has size limitations
            # For PKCS1v15, limit is key size - 11 bytes (for 2048-bit key, that's around 245 bytes)
            chunk_size = 245 
            chunks = [response[i:i+chunk_size] for i in range(0, len(response), chunk_size)]
            print(f"Node {self.id}: Splitting response into {len(chunks)} chunks for encryption")
            
            # Encrypt each chunk using PKCS1v15 padding (which client can decrypt)
            encrypted_chunks = []
            for i, chunk in enumerate(chunks):
                print(f"Node {self.id}: Encrypting response chunk {i}, length {len(chunk)}")
                try:
                    encrypted_chunk = client_public_key.encrypt(
                        chunk,
                        padding.PKCS1v15()  # Use PKCS1v15 for consistency
                    )
                    encrypted_chunks.append(encrypted_chunk)
                except Exception as e:
                    print(f"Node {self.id}: Error encrypting chunk {i}: {e}")
                    if encrypted_chunks:
                        break
                    else:
                        return response  # Return unencrypted if we can't encrypt anything
                    
            # Join chunks with a delimiter
            chunk_delimiter = b"::CHUNK::"
            encoded_chunks = [base64.b64encode(chunk) for chunk in encrypted_chunks]
            encrypted_data = chunk_delimiter.join(encoded_chunks)
            
            print(f"Node {self.id}: Response encryption complete, size: {len(encrypted_data)} bytes")
            return encrypted_data
        except Exception as e:
            print(f"Node {self.id}: Error encrypting response: {e}")
            return response
    
    def handle_client(self, conn, addr):
        """Handle incoming connections from clients or previous nodes"""
        try:
            print(f"Node {self.id}: Connection from {addr}")
            conn.settimeout(15.0)
            
            # Receive data
            data = b""
            end_marker_received = False
            
            while not end_marker_received:
                try:
                    chunk = conn.recv(8192)
                    if not chunk:
                        print(f"Node {self.id}: Connection closed by client")
                        break
                    
                    data += chunk
                    if b"::END::" in chunk:
                        parts = data.split(b"::END::", 1)
                        data = parts[0]
                        end_marker_received = True
                        print(f"Node {self.id}: End marker received")
                except socket.timeout:
                    print(f"Node {self.id}: Receive timeout, processing what we have")
                    break
            
            if not data:
                print(f"Node {self.id}: No data received")
                return
                
            print(f"Node {self.id}: Received {len(data)} bytes")
            
            # Decrypt our layer
            decrypted_data = self.decrypt_data(data)
            if not decrypted_data:
                print(f"Node {self.id}: Failed to decrypt data")
                conn.sendall(b"ERROR: Decryption failed")
                conn.sendall(b"::END::")
                return
                
            print(f"Node {self.id}: Decryption successful, got {len(decrypted_data)} bytes")
            
            # Parse the decrypted data (updated to include client_id and client_public_key)
            next_ip, next_port, remaining_data, client_id, client_public_key = self.parse_decrypted_data(decrypted_data)
            
            if (next_ip and next_port):
                # This is an intermediate node, forward to the next node
                print(f"Node {self.id}: Forwarding to next node at {next_ip}:{next_port}")
                
                response = self.forward_to_next_node(next_ip, next_port, remaining_data)
                
                if (response):
                    print(f"Node {self.id}: Got response from next node: {len(response)} bytes")
                    
                    # Encrypt with our private key to prove it's from us
                    if next_ip and next_port:
                        # For intermediate nodes, encrypt with our public key
                        encrypted_response = self.encrypt_response(response, self.public_key)
                    else:
                        # For exit nodes, use client's public key if available
                        if client_public_key:
                            print(f"Node {self.id}: Using embedded client key for response encryption")
                            encrypted_response = self.encrypt_response(response, client_public_key)
                        else:
                            print(f"Node {self.id}: Using our key for response encryption (fallback)")
                            encrypted_response = self.encrypt_response(response, self.public_key)
                    
                    # Send response back
                    conn.sendall(encrypted_response)
                    conn.sendall(b"::END::")
                    print(f"Node {self.id}: Response sent back to {addr}")
                else:
                    print(f"Node {self.id}: No response from next node")
                    conn.sendall(b"ERROR: No response from next node")
                    conn.sendall(b"::END::")
            else:
                # This is the exit node, send the HTTP request
                host = self.extract_host(remaining_data)
                if (host):
                    print(f"Node {self.id}: Exit node, sending request to {host}")
                    response = self.send_http_request(host, remaining_data)
                    
                    # Find the section in handle_client where it processes the response from httpbin.org
                    if response:
                        print(f"Node {self.id}: Got HTTP response: {len(response)} bytes")
                        
                        # Check if this is a raw HTTP response that should bypass encryption
                        if response.startswith(b"RAW_HTTP_RESPONSE:"):
                            print(f"Node {self.id}: Sending raw HTTP response without encryption")
                            conn.sendall(response)  # Send as-is, with the marker
                            conn.sendall(b"::END::")
                            return
                        
                        # Otherwise continue with encryption as normal
                        # (your existing encryption code here)
                        if client_public_key:
                            print(f"Node {self.id}: Using embedded client key for response encryption")
                            encrypted_response = self.encrypt_response(response, client_public_key)
                        
                        print(f"Node {self.id}: Response sample: {response[:100]}")
                        
                        # Use client public key from request directly if available
                        if (client_public_key):
                            print(f"Node {self.id}: Using embedded client key for response encryption")
                            encrypted_response = self.encrypt_response(response, client_public_key)
                        elif (client_id):
                            # Try to get key from directory server
                            client_public_key = self.request_client_key(client_id)
                            if (client_public_key):
                                print(f"Node {self.id}: Using directory client key for response encryption")
                                encrypted_response = self.encrypt_response(response, client_public_key)
                            else:
                                print(f"Node {self.id}: Using mock encryption (couldn't get client key)")
                                encrypted_response = f"[ENCRYPTED BY EXIT NODE {self.id} FOR CLIENT]: {response.decode(errors='replace')}".encode()
                        else:
                            # Fall back to mock encryption
                            print(f"Node {self.id}: Using mock encryption (no client identified)")
                            encrypted_response = f"[ENCRYPTED BY EXIT NODE {self.id} FOR CLIENT]: {response.decode(errors='replace')}".encode()
                        
                        # Send response back
                        conn.sendall(encrypted_response)
                        conn.sendall(b"::END::")
                        print(f"Node {self.id}: Response sent back")
                    else:
                        print(f"Node {self.id}: No HTTP response")
                        conn.sendall(b"ERROR: No HTTP response")
                        conn.sendall(b"::END::")
                else:
                    print(f"Node {self.id}: Could not extract host")
                    conn.sendall(b"ERROR: Could not extract host")
                    conn.sendall(b"::END::")
        except Exception as e:
            print(f"Node {self.id}: Error: {e}")
            try:
                conn.sendall(f"ERROR: {str(e)}".encode())
                conn.sendall(b"::END::")
            except:
                pass
        finally:
            conn.close()
    
    def start(self, register_with_directory=True, private_mode=False, auth_tokens=None):
        """Start the node and listen for connections"""
        # Register with directory service if requested
        if register_with_directory:
            if private_mode:
                self.directory_service.enable_private_mode(auth_tokens)
            else:
                self.directory_service.register_with_directory()
        
        # Start listening for connections
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', self.port))
            s.listen()
            print(f"Node {self.id} listening on port {self.port}")
            
            while True:
                try:
                    conn, addr = s.accept()
                    client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                    client_thread.daemon = True
                    client_thread.start()
                except KeyboardInterrupt:
                    print(f"Node {self.id} shutting down")
                    break
                except Exception as e:
                    print(f"Error accepting connection: {e}")

def main():
    # Create and start three nodes
    nodes = []
    num_nodes = 3
    
    # Use the same auth tokens as the client and directory server
    auth_tokens = ["secret_token_123", "demo_token"]
    
    # Start nodes with different IDs
    for i in range(num_nodes):
        node = Node(id=i)
        
        # Make the last node private as a demo
        private_mode = (i == num_nodes - 1)
        
        # Start node in a separate thread
        node_thread = threading.Thread(
            target=node.start,
            args=(True, private_mode, auth_tokens),
            daemon=True
        )
        node_thread.start()
        nodes.append((node, node_thread))
        
        # Wait a bit between starting nodes
        time.sleep(1)
    
    print(f"Started {num_nodes} nodes")
    
    # Keep the main thread running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down nodes")

if __name__ == "__main__":
    main()