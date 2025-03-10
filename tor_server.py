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
    
    def parse_decrypted_data(self, decrypted_data):
        """Parse the decrypted data to extract next node information"""
        try:
            # Scan for the ROUTE: prefix anywhere in the first 20 bytes
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
                            return ip, port, remaining_data
                        except ValueError:
                            print(f"Node {self.id}: Invalid port number: {port_str}")
            
            # Fall back to trying HTTP detection
            if b'GET ' in decrypted_data[:20] or b'Host:' in decrypted_data:
                print(f"Node {self.id}: Appears to be HTTP request (exit node)")
                return None, None, decrypted_data
                
            print(f"Node {self.id}: No routing information found")
            print(f"Node {self.id}: Data starts with: {decrypted_data[:50].hex()}")
            return None, None, decrypted_data
                
        except Exception as e:
            print(f"Node {self.id}: Error parsing: {e}")
            return None, None, decrypted_data
    
    def extract_host(self, request_bytes):
        """Extract the host from the HTTP header"""
        try:
            # Try to find 'Host: ' in the binary data
            host_prefix = b'Host: '
            host_pos = request_bytes.find(host_prefix)
            
            if host_pos >= 0:
                # Found the Host header
                host_start = host_pos + len(host_prefix)
                host_end = request_bytes.find(b'\r\n', host_start)
                
                if host_end > host_start:
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
            
            # Create a new socket for this connection
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(30.0)  # Longer timeout
            
            try:
                # Connect to the next node
                s.connect((ip, port))

                # Send the data
                s.sendall(data)

                #Send End indicator
                end = f"::END::".encode()
                s.sendall(end)
                
                print(f"Node {self.id}: Waiting for response from {ip}:{port}")
                # Receive response
                response = b""
                
                try:
                    while True:
                        chunk = s.recv(8192)
                        if not chunk:
                            print(f"Node {self.id}: Connection closed by {ip}:{port}")
                            break
                        response += chunk
                        if b"::END::" in chunk:
                            break
                        print(f"Node {self.id}: Received chunk of {len(chunk)} bytes from {ip}:{port}")
                        
                        # If we got a substantial response, we can return it
                        if len(response) > 0:
                            break
                except socket.timeout:
                    print(f"Node {self.id}: Socket timeout waiting for response from {ip}:{port}")
                
                print(f"Node {self.id}: Total response size from {ip}:{port}: {len(response)} bytes")
                return response
            finally:
                # Always close the socket when done
                s.close()
        except Exception as e:
            print(f"Node {self.id}: Error forwarding to {ip}:{port}: {e}")
            return None
    
    def send_http_request(self, host, request):
        """Send HTTP request to the destination server (for exit node)"""
        try:
            print(f"Node {self.id}: Sending HTTP request to {host}")
            
            # Create SSL context for HTTPS
            context = ssl.create_default_context()
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(15.0)  # Set timeout for connection
                with context.wrap_socket(s, server_hostname=host) as ssl_socket:
                    # Connect to the host on port 443 (HTTPS)
                    ssl_socket.connect((host, 443))
                    
                    # Send the request
                    ssl_socket.sendall(request)
                    print(f"Node {self.id}: Request sent to {host}")
                    
                    # Receive the response in chunks
                    ssl_socket.settimeout(1.0)
                    response = b""
                    content_length = 2**63
                    try:
                        while True:
                            chunk = ssl_socket.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                    
                            print(f"Node {self.id}: Received chunk of {len(chunk)} bytes")
                    except socket.timeout:
                        print(f"Node {self.id}: Socket timeout after receiving {len(response)} bytes")
                        chunk += response
                    
                    print(f"Node {self.id}: Total response size: {len(response)} bytes")
                    return response
        except Exception as e:
            print(f"Node {self.id}: Error sending HTTP request: {e}")
            # Return a simple error message
            return f"ERROR: Could not fetch from {host}: {e}".encode()
    
    def handle_client(self, conn, addr):
        """Handle incoming connections from clients or previous nodes"""
        try:
            print(f"Node {self.id}: Connection from {addr}")
            conn.settimeout(30.0)  # Set a timeout for receiving data
            
            # Receive encrypted data
            data = b""
            while True:
                try:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"::END::" in chunk:
                        break
                except socket.timeout:
                    break
            
            if not data:
                print(f"Node {self.id}: No data received")
                return
                    
            print(f"Node {self.id}: Received {len(data)} bytes")
            
            # Special case for plaintext messages (like TEST MESSAGE)
            if data.startswith(b'TEST '):
                print(f"Node {self.id}: Received plaintext test message")
                # Just return a simple response for tests
                conn.sendall(b"TEST RESPONSE")
                return
            
            # Decrypt our layer
            decrypted_data = self.decrypt_data(data)
            if not decrypted_data:
                print(f"Node {self.id}: Failed to decrypt data")
                return
                    
            print(f"Node {self.id}: Decryption successful, got {len(decrypted_data)} bytes")
            
            # Parse the decrypted data to get next hop or final destination
            next_ip, next_port, remaining_data = self.parse_decrypted_data(decrypted_data)
            
            if next_ip and next_port:
                # This is an intermediate node, forward to the next node
                print(f"Node {self.id}: Forwarding to next node at {next_ip}:{next_port}")
                response = self.forward_to_next_node(next_ip, next_port, remaining_data)
                
                if response:
                    # Return the response back through the circuit
                    print(f"Node {self.id}: Got response from next node, {len(response)} bytes")
                    print(f"Node {self.id}: Sending response back to client")
                    
                    conn.sendall(response)
                    # Append end indicator
                    end = f"::END::".encode()
                    conn.sendall(end)
                    print(f"Node {self.id}: Response sent back successfully")
                else:
                    print(f"Node {self.id}: No response from next node")
            else:
                # This is the exit node, send the actual HTTP request
                host = self.extract_host(remaining_data)
                if host:
                    print(f"Node {self.id}: Exit node, sending request to {host}")
                    response = self.send_http_request(host, remaining_data)
                    
                    # Send response back through the circuit
                    if response:
                        print(f"Node {self.id}: Sending HTTP response back, {len(response)} bytes")
                        try:
                            # Send the response back to the original connection
                            conn.sendall(response)
                            end = f"::END::".encode()
                            conn.sendall(end)
                            print(f"Node {self.id}: Response sent successfully through original connection")
                        except Exception as e:
                            print(f"Node {self.id}: Error sending response: {e}")
                    else:
                        print(f"Node {self.id}: No response from HTTP request")
                        conn.sendall(b"ERROR: No response from target server")
                else:
                    print(f"Node {self.id}: Could not extract host from request")
                    conn.sendall(b"ERROR: Could not extract host from request")
        
        except Exception as e:
            print(f"Node {self.id}: Error handling client: {e}")
            try:
                conn.sendall(f"ERROR: {e}".encode())
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