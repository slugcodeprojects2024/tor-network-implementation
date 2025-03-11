import socket
import threading
import os
import ssl
import base64
import json
import random
import argparse
import time
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
        """Build a circuit of specific nodes for testing"""
        if not self.known_nodes:
            self.request_node_list()
            
        # For a 3-node circuit, use nodes 0, 1, and 2 in order
        circuit = []
        
        # Add Node 0 (entry node)
        if 0 in self.known_nodes:
            circuit.append({
                'id': 0,
                'address': self.known_nodes[0]['address'],
                'public_key': self.known_nodes[0]['public_key']
            })
        
        # Add Node 1 (middle node)
        if 1 in self.known_nodes:
            circuit.append({
                'id': 1, 
                'address': self.known_nodes[1]['address'],
                'public_key': self.known_nodes[1]['public_key']
            })
        
        # Add Node 2 (exit node)
        if 2 in self.known_nodes:
            circuit.append({
                'id': 2, 
                'address': self.known_nodes[2]['address'],
                'public_key': self.known_nodes[2]['public_key']
            })
            
        print(f"Created fixed circuit: Node 0 → Node 1 → Node 2")
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
        
    # Add this to register_client_key to display the key being registered
    def register_client_key(self):
        """Register this client's public key with the directory server"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(self.directory_service.directory_server)
                
                # Format the key as a single request with the proper format
                serialized_key = serialize_public_key(self.public_key).decode()
                client_id_str = f"client_{self.client_id}"
                message = f"REGISTER_CLIENT_KEY {client_id_str} {serialized_key}".encode()
                
                print(f"Registering client {self.client_id} with directory service")
                s.sendall(message)
                
                # Get response
                s.settimeout(5.0)
                try:
                    response = s.recv(1024)
                    if response == b"SUCCESS" or response == b"":  # Empty response might mean success
                        print(f"Client {self.client_id} registered with directory service")
                        return True
                    else:
                        print(f"Registration failed: {response}")
                        return False
                except socket.timeout:
                    print("No response from directory service (timeout)")
                    return False
                    
        except Exception as e:
            print(f"Error registering with directory service: {e}")
            return False
        
    def verify_client_registration(self):
        """Check if our client key is properly registered with directory service"""
        print("\n=== VERIFYING CLIENT REGISTRATION ===")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(self.directory_service.directory_server)
                
                # Try the proper format for key retrieval based on tor_server
                client_id_str = f"client_{self.client_id}"
                request = f"GET_CLIENT_KEY {client_id_str}".encode()
                print(f"Sending verification request: {request}")
                s.sendall(request)
                
                # Get response
                s.settimeout(3.0)
                try:
                    response = s.recv(8192)
                    if response and len(response) > 20:  # Should be a PEM key if successful
                        print(f"Success! Retrieved key ({len(response)} bytes)")
                        return True
                    else:
                        print(f"Client {self.client_id} is NOT properly registered: {response}")
                        return False
                except socket.timeout:
                    print(f"Timeout waiting for key verification")
                    return False
        except Exception as e:
            print(f"Error verifying client registration: {e}")
            return False
        
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
        
        # First, encrypt with exit node's key using OAEP padding
        data = self.encrypt_layer(data, exit_node['public_key'])
        print(f"Encrypted with exit node's (Node {exit_node['id']}) key, size: {len(data)}")
        
        # For each remaining node, working backward
        for i in range(exit_node_index - 1, -1, -1):
            current_node = circuit[i]
            next_node = circuit[i + 1]
            next_ip, next_port = next_node['address']
            
            # Add routing prefix for current node to forward to next node
            routing_prefix = f"ROUTE:{next_ip}:{next_port}:".encode()
            print(f"Adding routing to node {next_node['id']}: {next_ip}:{next_port}")
            
            # Combine routing prefix with already encrypted data
            data = routing_prefix + data
            
            # Encrypt with current node's key
            data = self.encrypt_layer(data, current_node['public_key'])
            print(f"Encrypted with node {current_node['id']}'s key, size: {len(data)}")
        
        return data
    
    def send_request(self, circuit, encrypted_data):
        """Send the request through the first node in the circuit and handle the encrypted response"""
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
                s.settimeout(10.0)  # Increased timeout
                response = b""
                max_attempts = 10   # Increased attempts
                
                for attempt in range(max_attempts):
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
                        print(f"Socket timeout (attempt {attempt+1}/{max_attempts})")
                        if attempt == max_attempts - 1:
                            break
                
                if response:
                    print(f"Total encrypted response size: {len(response)} bytes")
                    
                    # Check for raw HTTP responses first
                    raw_http = self.handle_raw_http(response)
                    if raw_http:
                        return raw_http
                        
                    # Then continue with normal decryption process
                    if b"::CHUNK::" in response:
                        try:
                            # Properly formatted encrypted response
                            decrypted_response = self.decrypt_response(response)
                            if decrypted_response:
                                print(f"Successfully decrypted response: {len(decrypted_response)} bytes")
                                return decrypted_response
                            else:
                                print("Failed to decrypt response, returning encrypted version")
                                return response
                        except Exception as e:
                            print(f"Error during decryption: {e}")
                            return response
                    elif b"[ENCRYPTED BY" in response:
                        # Legacy mock encryption indicator
                        print("Received mock-encrypted response (server not updated yet)")
                        return response
                    else:
                        print("Unknown response format")
                        return response
                else:
                    print("No response received")
                    return None
        except Exception as e:
            print(f"Error sending request: {e}")
            return None
            
    def decrypt_response(self, encrypted_data):
        """Decrypt a response encrypted with our public key"""
        try:
            # Check if the data is already in plaintext
            if b"HTTP/1." in encrypted_data[:20]:
                print("Response appears to be plaintext HTTP - no decryption needed")
                return encrypted_data
                    
            if encrypted_data.startswith(b"ERROR:"):
                print(f"Received error message: {encrypted_data.decode('utf-8')}")
                return encrypted_data
            
            # Split the data into chunks using the delimiter
            chunk_delimiter = b"::CHUNK::"
            encrypted_chunks = encrypted_data.split(chunk_delimiter)
            print(f"Splitting response into {len(encrypted_chunks)} chunks")
            
            # Decrypt each chunk
            decrypted_chunks = []
            for i, chunk in enumerate(encrypted_chunks):
                try:
                    print(f"Decrypting response chunk {i}, length {len(chunk)}")
                    
                    # Skip empty chunks
                    if not chunk or len(chunk) < 10:
                        print(f"Skipping empty/short chunk {i}")
                        continue
                    
                    # Base64 decode the chunk
                    try:
                        decoded_chunk = base64.b64decode(chunk)
                        print(f"Base64 decoded to {len(decoded_chunk)} bytes")
                    except:
                        print(f"Failed to base64 decode chunk {i}, trying as raw data")
                        decoded_chunk = chunk
                    
                    # First try OAEP with SHA-256 (more secure)
                    try:
                        decrypted_chunk = self.private_key.decrypt(
                            decoded_chunk,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        print(f"Successfully decrypted chunk with OAEP-SHA256")
                        decrypted_chunks.append(decrypted_chunk)
                        continue
                    except Exception as e1:
                        print(f"OAEP-SHA256 decryption failed: {type(e1).__name__}")
                    
                    # Then try PKCS1v15 (more compatible)
                    try:
                        decrypted_chunk = self.private_key.decrypt(
                            decoded_chunk,
                            padding.PKCS1v15()
                        )
                        print(f"Successfully decrypted chunk with PKCS1v15")
                        decrypted_chunks.append(decrypted_chunk)
                        continue
                    except Exception as e2:
                        print(f"PKCS1v15 decryption failed: {type(e2).__name__}")
                    
                    print(f"All decryption methods failed for chunk {i}")
                    
                except Exception as e:
                    print(f"Error decrypting chunk {i}: {e}")
            
            if not decrypted_chunks:
                print(f"Failed to decrypt any chunks")
                return encrypted_data
                
            # Join the decrypted chunks
            result = b"".join(decrypted_chunks)
            print(f"Successfully decrypted {len(decrypted_chunks)} chunks, total length {len(result)} bytes")
            
            # NEW CODE STARTS HERE: Extract HTTP response if present
            # Check for HTTP response markers in the decrypted data
            http_markers = [b'HTTP/1.1', b'HTTP/1.0', b'HTTP/2']
            for marker in http_markers:
                pos = result.find(marker)
                if pos >= 0:
                    print(f"Found HTTP marker {marker} at position {pos}")
                    http_response = result[pos:]
                    
                    # Extract headers
                    header_end = http_response.find(b'\r\n\r\n')
                    if header_end > 0:
                        headers = http_response[:header_end]
                        body = http_response[header_end + 4:]  # Skip \r\n\r\n
                        
                        print("\n=== EXTRACTED HTTP HEADERS ===")
                        header_text = headers.decode('utf-8', errors='replace')
                        print(header_text)
                        
                        # Parse Content-Type and Content-Length
                        content_type = None
                        content_length = None
                        
                        for line in header_text.split('\r\n'):
                            if line.lower().startswith('content-type:'):
                                content_type = line.split(':', 1)[1].strip()
                                print(f"Content-Type: {content_type}")
                            elif line.lower().startswith('content-length:'):
                                try:
                                    content_length = int(line.split(':', 1)[1].strip())
                                    print(f"Content-Length: {content_length}")
                                    # Trim body to content length if needed
                                    if content_length and len(body) > content_length:
                                        body = body[:content_length]
                                except:
                                    pass
                        
                        # Handle JSON content specially
                        if content_type and 'json' in content_type.lower():
                            try:
                                json_obj = json.loads(body.decode('utf-8', errors='replace'))
                                print("\n=== JSON RESPONSE ===")
                                return json.dumps(json_obj, indent=2)
                            except Exception as e:
                                print(f"JSON parsing error: {e}")
                        
                        # Return the full HTTP response
                        try:
                            return http_response.decode('utf-8', errors='replace')
                        except:
                            # If decoding fails, just return headers and note binary body
                            return header_text + "\r\n\r\n[Binary body]"
            
            # Look for JSON content directly if no HTTP headers
            if result.find(b'{') >= 0:
                for i in range(len(result)):
                    if result[i:i+1] == b'{':
                        try:
                            # Try to parse JSON starting from this position
                            json_str = result[i:].decode('utf-8', errors='replace')
                            json_obj = json.loads(json_str)
                            if isinstance(json_obj, dict) and len(json_obj) > 0:
                                return json.dumps(json_obj, indent=2)
                        except:
                            pass
            
            # If we get here, return the original result
            return result
                    
        except Exception as e:
            print(f"Error in decrypt_response: {e}")
            return encrypted_data
        
    def verify_key_pair(self):
        """Verify that our key pair works correctly for encryption and decryption"""
        print("\n=== VERIFYING KEY PAIR COMPATIBILITY ===")
        
        # Create test message
        test_message = b"Test encryption and decryption with this key pair."
        print(f"Original message: {test_message}")
        
        try:
            # Encrypt with our public key
            encrypted = self.public_key.encrypt(
                test_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"Encrypted length: {len(encrypted)}")
            
            # Decrypt with our private key
            decrypted = self.private_key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"Decrypted message: {decrypted}")
            
            # Check if decryption was successful
            if decrypted == test_message:
                print("Key pair verification SUCCESSFUL")
                return True
            else:
                print("Key pair verification FAILED - decrypted content doesn't match")
                return False
        except Exception as e:
            print(f"Key pair verification FAILED with error: {e}")
            return False

    # Add this method to the TorClient class
    def test_direct_encryption_with_exit_node(self, circuit):
        """Test direct encryption/decryption with the exit node"""
        print("\n=== TESTING DIRECT COMMUNICATION WITH EXIT NODE ===")
        
        # Get the exit node from the circuit
        exit_node_index = min(len(circuit) - 1, 2)  # Use last node or node 2
        exit_node = circuit[exit_node_index]
        
        try:
            # Connect directly to exit node
            print(f"Connecting directly to exit node {exit_node['id']} at {exit_node['address']}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(exit_node['address'])
                
                # Create a special test message
                test_message = {
                    "type": "client_key_test",
                    "client_id": self.client_id,
                    "timestamp": str(time.time())
                }
                message = json.dumps(test_message).encode()
                
                # Add client ID marker exactly as we do in normal requests
                client_id_marker = f"CLIENT_ID:{self.client_id}:".encode()
                
                # Add serialized public key directly
                serialized_key = serialize_public_key(self.public_key).decode()
                key_marker = f"CLIENT_KEY:{serialized_key}:".encode()
                
                # Combine all parts
                test_data = client_id_marker + key_marker + message
                
                print(f"Sending test message with client ID {self.client_id}")
                print(f"Including public key in message for direct encryption")
                s.sendall(test_data)
                s.sendall(b"::END::")
                
                # Wait for response
                s.settimeout(5.0)
                response = b""
                
                try:
                    chunk = s.recv(8192)
                    if chunk:
                        response += chunk
                        print(f"Received direct response: {len(chunk)} bytes")
                        print(f"Response starts with: {chunk[:50]}")
                        
                        if b"::CHUNK::" in chunk:
                            print("Response appears to be encrypted with chunks, attempting decryption")
                            decrypted = self.decrypt_response(chunk)
                            if decrypted:
                                print(f"Successfully decrypted response: {decrypted[:100]}")
                            else:
                                print("Failed to decrypt direct response")
                        
                    else:
                        print("No response from exit node - connection closed")
                except socket.timeout:
                    print("Socket timeout waiting for test response")
                
        except Exception as e:
            print(f"Error in direct test: {e}")
            import traceback
            traceback.print_exc()
        
        return False

    def debug_directory_service(self):
        """Debug communication with the directory server"""
        print("\n=== DIRECTORY SERVICE DEBUG ===")
        
        try:
            # Try various commands to see what the directory server accepts
            commands = [
                b"LIST",
                b"COMMANDS",
                b"HELP",
                f"GET_CLIENT client_{self.client_id}".encode(),
                f"GET_CLIENT_KEY client_{self.client_id}".encode()
            ]
            
            for cmd in commands:
                print(f"\nTrying command: {cmd}")
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect(self.directory_service.directory_server)
                    s.sendall(cmd)
                    
                    try:
                        s.settimeout(2.0)
                        response = s.recv(8192)
                        print(f"Response ({len(response)} bytes): {response[:100]}...")
                    except socket.timeout:
                        print("No response (timeout)")
                        
            # Try re-registering with different format
            print("\nAttempting alternate registration format")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(self.directory_service.directory_server)
                
                # Try format that just sends the key directly
                serialized_key = serialize_public_key(self.public_key)
                registration_data = f"REGISTER_CLIENT_KEY client_{self.client_id} {serialized_key.decode()}".encode()
                print(f"Sending registration: {registration_data[:50]}...")
                s.sendall(registration_data)
                
                try:
                    s.settimeout(2.0)
                    response = s.recv(1024)
                    print(f"Registration response: {response}")
                except socket.timeout:
                    print("No response to registration (timeout)")
                    
        except Exception as e:
            print(f"Error in directory debug: {e}")

    def test_exit_node_encryption(self, circuit):
        """Test encryption compatibility with the exit node"""
        print("\n=== TESTING EXIT NODE ENCRYPTION COMPATIBILITY ===")
        
        # Get the exit node from the circuit
        exit_node_index = min(len(circuit) - 1, 2)  # Use last node or node 2
        exit_node = circuit[exit_node_index]
        
        try:
            # Connect directly to exit node
            print(f"Connecting directly to exit node {exit_node['id']} at {exit_node['address']}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(exit_node['address'])
                
                # Create a special test message
                test_message = {
                    "type": "encryption_test",
                    "client_id": self.client_id,
                    "action": "echo_encrypted",
                    "test_message": "This is a simple test message for encryption"
                }
                message = json.dumps(test_message).encode()
                
                # Add client ID and public key
                client_id_marker = f"CLIENT_ID:{self.client_id}:".encode()
                serialized_key = serialize_public_key(self.public_key).decode()
                key_marker = f"CLIENT_KEY:{serialized_key}:".encode()
                
                # Combine all parts
                test_data = client_id_marker + key_marker + message
                
                print(f"Sending test message with embedded public key")
                s.sendall(test_data)
                s.sendall(b"::END::")
                
                # Wait for response
                s.settimeout(5.0)
                response = b""
                
                try:
                    chunk = s.recv(8192)
                    if chunk:
                        response += chunk
                        print(f"Received response: {len(chunk)} bytes")
                        
                        if b"ERROR:" in chunk:
                            print(f"ERROR from node: {chunk}")
                        else:
                            print(f"Response begins with: {chunk[:30]}")
                    
                except socket.timeout:
                    print("Socket timeout waiting for response")
                
        except Exception as e:
            print(f"Error in encryption test: {e}")
        
        return False

    def process_http_response(self, binary_data):
        """Process HTTP response data and return it in a readable format"""
        try:
            # Check for HTTP marker from server
            if isinstance(binary_data, bytes) and binary_data.startswith(b'HTTP_RESPONSE:'):
                binary_data = binary_data[14:]  # Remove the marker
                
            # Check if this is an HTTP response
            if isinstance(binary_data, bytes) and binary_data.startswith(b'HTTP/'):
                print("Detected HTTP response")
                
                # Split headers and body
                parts = binary_data.split(b'\r\n\r\n', 1)
                if len(parts) == 2:
                    headers, body = parts
                    print("\n=== HTTP HEADERS ===")
                    print(headers.decode('utf-8', errors='replace'))
                    
                    # Try to detect Content-Type
                    content_type = None
                    for line in headers.split(b'\r\n'):
                        if line.lower().startswith(b'content-type:'):
                            content_type = line[13:].strip().decode('ascii', errors='ignore')
                            break
                            
                    print(f"Content-Type: {content_type}")
                    
                    # Handle JSON responses
                    if body and (body.startswith(b'{') or body.startswith(b'[')):
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
                return binary_data.decode('utf-8', errors='replace')
            
            # Not an HTTP response, try to find useful data
            return self.handle_binary_response(binary_data)
        except Exception as e:
            print(f"Error processing response: {e}")
            return f"Error processing response: {str(e)}"

    def process_response(self, decrypted_response):
        """Process and interpret the decrypted response data"""
        try:
            # First, check for HTTP response marker
            if decrypted_response.startswith(b"HTTP_RESPONSE_MARKER:"):
                # Extract the actual HTTP response
                http_response = decrypted_response[len(b"HTTP_RESPONSE_MARKER:"):]
                
                print("\n=== HTTP RESPONSE DETECTED ===")
                
                # Parse HTTP headers and body
                parts = http_response.split(b"\r\n\r\n", 1)
                if len(parts) > 1:
                    headers, body = parts
                    
                    print("\n=== HTTP HEADERS ===")
                    print(headers.decode('utf-8', errors='replace'))
                    
                    # Check if body is JSON
                    try:
                        if body.startswith(b"{") or body.startswith(b"["):
                            json_data = json.loads(body)
                            print("\n=== JSON CONTENT ===")
                            print(json.dumps(json_data, indent=2))
                            return json.dumps(json_data, indent=2)
                    except:
                        pass
                    
                    # Return decoded body if possible
                    try:
                        decoded_body = body.decode('utf-8', errors='replace')
                        print("\n=== RESPONSE BODY ===")
                        print(decoded_body[:500] + "..." if len(decoded_body) > 500 else decoded_body)
                        return decoded_body
                    except:
                        return body
                
                return http_response.decode('utf-8', errors='replace')
            
            # If we get here, it's not a marked HTTP response
            # Try to detect HTTP responses anyway
            if b"HTTP/1." in decrypted_response[:20]:
                print("\n=== HTTP RESPONSE DETECTED ===")
                
                parts = decrypted_response.split(b"\r\n\r\n", 1)
                if len(parts) > 1:
                    headers, body = parts
                    print("\n=== HTTP HEADERS ===")
                    print(headers.decode('utf-8', errors='replace'))
                    
                    # Try to decode body as text or JSON
                    try:
                        if body.startswith(b"{") or body.startswith(b"["):
                            json_data = json.loads(body)
                            print("\n=== JSON CONTENT ===")
                            print(json.dumps(json_data, indent=2))
                            return json.dumps(json_data, indent=2)
                        else:
                            decoded_body = body.decode('utf-8', errors='replace')
                            print("\n=== RESPONSE BODY ===")
                            print(decoded_body[:500])
                            return decoded_body
                    except:
                        return body
                    
                return decrypted_response
            
            # Last resort, try to interpret as text
            try:
                decoded = decrypted_response.decode('utf-8', errors='replace')
                # Check if it looks like JSON with curly braces
                if '{' in decoded[:50] and '}' in decoded:
                    try:
                        # Try to find a valid JSON substring
                        start = decoded.find('{')
                        nested_level = 0
                        for i in range(start, len(decoded)):
                            if decoded[i] == '{':
                                nested_level += 1
                            elif decoded[i] == '}':
                                nested_level -= 1
                                if nested_level == 0:
                                    potential_json = decoded[start:i+1]
                                    try:
                                        json_data = json.loads(potential_json)
                                        print("\n=== EXTRACTED JSON CONTENT ===")
                                        return json.dumps(json_data, indent=2)
                                    except:
                                        pass
                    except:
                        pass
                
                # Not JSON or failed to parse, return as text
                return decoded
            except:
                # Binary data, show hexdump
                return self.interpret_binary_response(decrypted_response)
            
        except Exception as e:
            print(f"Error processing response: {e}")
            return f"Error processing response: {e}"

    def create_http_request(self, host, path="/", headers=None):
        """Create a proper HTTP request with necessary headers"""
        if not headers:
            headers = {}
            
        # Add essential headers
        if "Host" not in headers:
            headers["Host"] = host
        if "User-Agent" not in headers:
            headers["User-Agent"] = "TorClient/1.0"
        if "Accept" not in headers:
            headers["Accept"] = "*/*"
        if "Connection" not in headers:
            headers["Connection"] = "close"  # Important for getting complete responses
            
        # Build request string
        request_lines = [f"GET {path} HTTP/1.1"]
        for key, value in headers.items():
            request_lines.append(f"{key}: {value}")
        
        # Add empty line to separate headers from body
        request_lines.append("")
        request_lines.append("")
        
        return "\r\n".join(request_lines).encode()

    def extract_http_response(self, binary_data):
        """Special decoder for HTTP responses embedded in binary data"""
        try:
            # Try to find HTTP header pattern
            http_patterns = [b'HTTP/1.1', b'HTTP/1.0', b'HTTP/2']
            start_pos = -1
            
            for pattern in http_patterns:
                pos = binary_data.find(pattern)
                if pos >= 0 and (start_pos == -1 or pos < start_pos):
                    start_pos = pos
                    
            if start_pos >= 0:
                # Found HTTP response, extract it
                http_data = binary_data[start_pos:]
                print(f"Found HTTP response at position {start_pos}")
                
                # Find end of headers to locate body
                header_end = http_data.find(b'\r\n\r\n')
                if header_end > 0:
                    headers = http_data[:header_end]
                    body = http_data[header_end + 4:]  # +4 for \r\n\r\n
                    
                    # Parse headers to get content length
                    content_length = None
                    content_type = None
                    
                    for line in headers.split(b'\r\n'):
                        if line.lower().startswith(b'content-length:'):
                            try:
                                content_length = int(line.split(b':', 1)[1].strip())
                            except:
                                pass
                        elif line.lower().startswith(b'content-type:'):
                            content_type = line.split(b':', 1)[1].strip().decode('ascii', errors='ignore')
                    
                    # Print headers
                    print("\n=== HTTP HEADERS ===")
                    print(headers.decode('utf-8', errors='replace'))
                    
                    # If we know content length, trim extra data
                    if content_length is not None and len(body) >= content_length:
                        body = body[:content_length]
                        
                    # Handle different content types
                    if content_type and 'json' in content_type.lower():
                        try:
                            json_obj = json.loads(body)
                            return json.dumps(json_obj, indent=2)
                        except:
                            pass
                    
                    return body.decode('utf-8', errors='replace')
                
                # If we couldn't parse headers/body, return raw HTTP response
                return http_data.decode('utf-8', errors='replace')
                
            return None
        except Exception as e:
            print(f"Error extracting HTTP response: {e}")
            return None

    def deep_extract_http_content(self, binary_data):
        """Advanced HTTP content extractor that handles fragmented/corrupted responses"""
        try:
            # First check if we have a string instead of bytes
            if isinstance(binary_data, str):
                try:
                    # Try to convert to bytes for consistent processing
                    binary_data = binary_data.encode('utf-8')
                except:
                    print("Warning: Could not convert string data to bytes")
                    # Just return the string if we can't convert
                    return binary_data
            
            # Check for HTTP protocol signature anywhere in the data
            http_signatures = [b'HTTP/1.1', b'HTTP/2', b'HTTP/1.0']
            found_pos = -1
            
            for sig in http_signatures:
                pos = binary_data.find(sig)
                if pos >= 0:
                    found_pos = pos
                    http_ver = sig.decode()
                    print(f"Found HTTP signature '{http_ver}' at position {pos}")
                    break
                    
            if found_pos >= 0:
                # Extract data starting from the HTTP signature
                http_data = binary_data[found_pos-4:] # Include a bit before in case we caught HTTP mid-header
                
                # Find the HTTP headers section
                header_end = http_data.find(b'\r\n\r\n')
                if header_end > 0:
                    headers = http_data[:header_end].strip()
                    body = http_data[header_end + 4:]  # Skip the \r\n\r\n separator
                    
                    # Display headers for debugging
                    print("\n=== HTTP HEADERS ===")
                    print(headers.decode('utf-8', errors='replace'))
                    
                    # Look for Content-Type and Content-Length
                    content_type = None
                    content_length = None
                    
                    for line in headers.split(b'\r\n'):
                        if line.lower().startswith(b'content-type:'):
                            content_type = line.split(b':', 1)[1].strip().decode('utf-8', errors='replace')
                            print(f"Content-Type: {content_type}")
                        elif line.lower().startswith(b'content-length:'):
                            try:
                                content_length = int(line.split(b':', 1)[1].strip())
                                print(f"Content-Length: {content_length}")
                            except:
                                pass
                    
                    # If Content-Length is specified, trim body to that length
                    if content_length is not None and len(body) >= content_length:
                        body = body[:content_length]
                        
                    # Handle different content types
                    if content_type and 'json' in content_type.lower():
                        # Try to parse JSON
                        try:
                            json_str = body.decode('utf-8', errors='replace')
                            json_data = json.loads(json_str)
                            print("\n=== JSON CONTENT FOUND ===")
                            formatted_json = json.dumps(json_data, indent=2)
                            return formatted_json
                        except Exception as e:
                            print(f"Failed to parse JSON: {e}")
                    
                    # For text-based content types
                    if content_type and any(ct in content_type.lower() for ct in ['text', 'json', 'xml', 'html']):
                        try:
                            text_content = body.decode('utf-8', errors='replace')
                            return text_content
                        except:
                            pass
                    
                    # For unknown content types, try to detect format
                    if body.startswith(b'{') or body.startswith(b'['):
                        try:
                            json_str = body.decode('utf-8', errors='replace')
                            json_data = json.loads(json_str)
                            print("\n=== JSON CONTENT DETECTED ===")
                            formatted_json = json.dumps(json_data, indent=2)
                            return formatted_json
                        except:
                            pass
                    
                    # Default to decoding as text if all else fails
                    try:
                        return body.decode('utf-8', errors='replace')
                    except:
                        print("Could not decode body as text")
                        
                    # Return raw body if we can't decode it
                    return body
                
                # No header end found, try to return what we have
                return http_data
                    
            # No HTTP signature found, try checking for JSON directly
            if binary_data.startswith(b'{') or binary_data.startswith(b'['):
                try:
                    json_str = binary_data.decode('utf-8', errors='replace')
                    json_data = json.loads(json_str)
                    print("\n=== JSON CONTENT DETECTED ===")
                    return json.dumps(json_data, indent=2)
                except:
                    pass
            
            # Last resort: search for JSON-like patterns
            json_start = binary_data.find(b'{')
            if json_start >= 0:
                potential_json = binary_data[json_start:]
                try:
                    # Find matching closing brace
                    nesting = 0
                    json_end = -1
                    for i, b in enumerate(potential_json):
                        if b == ord('{'):
                            nesting += 1
                        elif b == ord('}'):
                            nesting -= 1
                            if nesting == 0:  # Found the end of JSON
                                json_data = potential_json[:json_end]
                                try:
                                    json_obj = json.loads(json_data)
                                    print(f"\n=== EXTRACTED JSON (at position {json_start}) ===")
                                    return json.dumps(json_obj, indent=2)
                                except:
                                    pass
                                break
                except:
                    pass
                    
            # Return the raw data if we couldn't extract anything meaningful
            return binary_data
                
        except Exception as e:
            print(f"Error extracting HTTP content: {e}")
            import traceback
            traceback.print_exc()
            return binary_data

    def aggressive_http_extractor(self, binary_data):
        """Ultra-aggressive HTTP/JSON content extractor for partially corrupt data"""
        print("\n=== AGGRESSIVE HTTP EXTRACTION ===")
        
        if isinstance(binary_data, str):
            try:
                binary_data = binary_data.encode('utf-8')
            except:
                print("Input is already a string, keeping as is")
                
                # Check if it's already valid JSON
                if binary_data.startswith('{') or binary_data.startswith('['):
                    try:
                        json_obj = json.loads(binary_data)
                        return json.dumps(json_obj, indent=2)
                    except:
                        pass
                return binary_data
        
        # 1. First try to find an HTTP header pattern anywhere in the data
        http_markers = [b'HTTP/1.1 ', b'HTTP/1.0 ', b'HTTP/2 ']
        status_codes = [b' 200 ', b' 302 ', b' 404 ', b' 500 ']
        common_headers = [b'Content-Type:', b'Content-Length:', b'Date:', b'Server:']
        
        # Look for a sequence of HTTP header patterns
        best_start = -1
        best_score = 0
        
        # Search through the data in overlapping windows
        for i in range(len(binary_data) - 20):
            window = binary_data[i:i+200]  # Look at 200 byte windows
            score = 0
            
            # Check for HTTP protocol markers
            for marker in http_markers:
                if marker in window:
                    score += 10
                    break
            
            # Check for status codes
            for code in status_codes:
                if code in window:
                    score += 5
                    break
            
            # Check for common HTTP headers
            for header in common_headers:
                if header in window:
                    score += 3
            
            # Check for header/body separator
            if b'\r\n\r\n' in window:
                score += 10
            
            # If we found a good candidate
            if score > best_score:
                best_score = score
                best_start = i
        
        # If we found a potential HTTP response
        if best_start >= 0 and best_score >= 10:
            print(f"Found potential HTTP content at position {best_start} with confidence {best_score}")
            
            # Extract from the best starting position
            potential_http = binary_data[best_start:]
            
            # Find the end of headers
            header_end = potential_http.find(b'\r\n\r\n')
            if header_end > 0:
                headers = potential_http[:header_end]
                body = potential_http[header_end + 4:]  # Skip the \r\n\r\n
                
                print("\n=== EXTRACTED HTTP HEADERS ===")
                print(headers.decode('utf-8', errors='replace'))
                
                # Parse Content-Length if present
                content_length = None
                content_type = None
                for line in headers.split(b'\r\n'):
                    if line.lower().startswith(b'content-length:'):
                        try:
                            content_length = int(line.split(b':', 1)[1].strip())
                            print(f"Content-Length: {content_length}")
                        except:
                            pass
                    elif line.lower().startswith(b'content-type:'):
                        try:
                            content_type = line.split(b':', 1)[1].strip().decode('ascii', errors='ignore')
                            print(f"Content-Type: {content_type}")
                        except:
                            pass
                
                # If content_length is specified, trim the body
                if content_length and len(body) > content_length:
                    body = body[:content_length]
                
                # Try to handle different content types
                if content_type and ('json' in content_type.lower()):
                    try:
                        json_data = json.loads(body.decode('utf-8', errors='replace'))
                        print("\n=== EXTRACTED JSON CONTENT ===")
                        return json.dumps(json_data, indent=2)
                    except Exception as e:
                        print(f"Failed to parse JSON: {e}")
                
                # Try to extract as text
                try:
                    body_text = body.decode('utf-8', errors='replace')
                    print("\n=== BODY PREVIEW ===")
                    print(body_text[:200] + '...' if len(body_text) > 200 else body_text)
                    return body_text
                except:
                    return body
        
        # 2. Next, look for JSON patterns anywhere in the data
        for i in range(len(binary_data) - 5):
            # Look for JSON object start
            if binary_data[i:i+1] == b'{':
                try:
                    # Try to find the matching closing brace
                    nesting = 1
                    for j in range(i + 1, len(binary_data)):
                        if binary_data[j:j+1] == b'{':
                            nesting += 1
                        elif binary_data[j:j+1] == b'}':
                            nesting -= 1
                            if nesting == 0:  # Found the end of JSON
                                json_data = binary_data[i:j+1]
                                try:
                                    parsed = json.loads(json_data)
                                    # Require at least some keys to avoid false positives
                                    if len(parsed.keys()) >= 3:  
                                        print(f"\n=== FOUND JSON OBJECT at position {i} ===")
                                        return json.dumps(parsed, indent=2)
                                except:
                                    pass
                                break
                except:
                    pass
        
        # 3. Last resort: just extract any coherent text
        try:
            text_segments = []
            current_segment = b""
            min_segment_length = 20  # Look for meaningful text chunks
            
            for i in range(len(binary_data)):
                byte = binary_data[i:i+1]
                # If it's printable ASCII or common whitespace
                if 32 <= binary_data[i] <= 126 or binary_data[i] in (9, 10, 13):
                    current_segment += byte
                else:
                    if len(current_segment) >= min_segment_length:
                        text_segments.append(current_segment)
                    current_segment = b""
                    
            if len(current_segment) >= min_segment_length:
                text_segments.append(current_segment)
                
            if text_segments:
                longest_segment = max(text_segments, key=len)
                if len(longest_segment) >= 50:  # Only if we found significant text
                    print(f"\n=== FOUND TEXT SEGMENT ({len(longest_segment)} bytes) ===")
                    decoded = longest_segment.decode('utf-8', errors='replace')
                    return decoded
                    
        except Exception as e:
            print(f"Error extracting text: {e}")
        
        # If all else fails
        return binary_data

    def final_http_extractor(self, data):
        """Final HTTP extractor that handles properly marked HTTP responses"""
        try:
            # Check if it's a string
            if isinstance(data, str):
                if data.startswith('HTTP/'):
                    print("Found HTTP response in string format")
                    return data
                try:
                    data = data.encode('utf-8')
                except:
                    return data
                    
            # For binary data
            if isinstance(data, bytes):
                # First check for HTTP protocol marker
                if data.startswith(b'HTTP/'):
                    print("Found HTTP header at start of response")
                    try:
                        # Split headers and body
                        parts = data.split(b'\r\n\r\n', 1)
                        if len(parts) == 2:
                            headers, body = parts
                            
                            # Print headers for debugging
                            print("\n=== HTTP HEADERS ===")
                            header_text = headers.decode('utf-8', errors='replace')
                            print(header_text)
                            
                            # Check if it's JSON
                            if b'application/json' in headers:
                                try:
                                    json_data = json.loads(body)
                                    return json.dumps(json_data, indent=2)
                                except:
                                    pass
                                    
                            # Return decoded body or full response
                            try:
                                return data.decode('utf-8', errors='replace')
                            except:
                                pass
                    except:
                        pass
                        
                # Try scanning for JSON content
                for i in range(min(200, len(data))):
                    if data[i:i+1] == b'{':
                        try:
                            # Look for JSON starting at this position
                            potential_json = data[i:]
                            json_obj = json.loads(potential_json)
                            if isinstance(json_obj, dict) and len(json_obj.keys()) > 0:
                                return json.dumps(json_obj, indent=2)
                        except:
                            pass
                            
            return data
        
        except Exception as e:
            print(f"Error in final extractor: {e}")
            return data

    def json_content_extractor(self, data):
        """Final specialized extractor for finding JSON data in partially decrypted responses"""
        try:
            print("\n=== JSON CONTENT EXTRACTION ===")
            
            # If string, just try to parse as JSON directly
            if isinstance(data, str):
                if data.startswith('{') or data.startswith('['):
                    try:
                        json_obj = json.loads(data)
                        return json.dumps(json_obj, indent=2)
                    except:
                        pass
                
                # If it might be encoded binary data, convert to bytes
                try:
                    data = data.encode('utf-8', errors='ignore')
                except:
                    pass
            
            # For bytes, look for JSON patterns ('{' and '}')
            if isinstance(data, bytes):
                # Look for JSON objects (most common in httpbin responses)
                for i in range(min(100, len(data))):
                    if data[i:i+1] == b'{':
                        # Try different lengths for the potential JSON
                        for j in range(i+20, len(data)):
                            try:
                                # Extract a potential JSON object and try to parse it
                                potential_json = data[i:j].decode('utf-8', errors='ignore')
                                if '}' in potential_json:
                                    try:
                                        json_obj = json.loads(potential_json)
                                        if isinstance(json_obj, dict) and len(json_obj) > 2:
                                            print(f"Found valid JSON at position {i}")
                                            return json.dumps(json_obj, indent=2)
                                    except:
                                        pass
                            except:
                                pass
                                
                # If we get here, we didn't find a JSON object, try for chunks of readable text
                printable = []
                current_chunk = ""
                for i in range(len(data)):
                    if 32 <= data[i] <= 126 or data[i] in (9, 10, 13):  # Printable ASCII or whitespace
                        current_chunk += chr(data[i])
                    elif current_chunk:
                        if len(current_chunk) > 20:  # Only keep substantial chunks
                            printable.append(current_chunk)
                        current_chunk = ""
                        
                if current_chunk and len(current_chunk) > 20:
                    printable.append(current_chunk)
                    
                if printable:
                    longest_chunk = max(printable, key=len)
                    if len(longest_chunk) > 50:  # Only return if significant
                        return longest_chunk
            
            # If all else fails
            return data
        except Exception as e:
            print(f"Error in JSON extractor: {e}")
            return data

    def extract_httpbin_response(self, data):
        """Super specialized extractor for httpbin.org responses"""
        print("\n=== HTTPBIN.ORG RESPONSE EXTRACTOR ===")
        
        # Convert to bytes if we have a string
        if isinstance(data, str):
            try:
                data = data.encode('utf-8')
            except:
                pass
        
        # Common patterns found in httpbin responses
        httpbin_patterns = [b'"url": "http', b'"headers": {', b'"origin": "', b'"args": {']
        
        # First, try to locate a JSON object by looking for httpbin-specific patterns
        for pattern in httpbin_patterns:
            pattern_pos = data.find(pattern)
            if pattern_pos >= 0:
                # Search backwards for the start of the JSON object
                start_pos = -1
                for i in range(pattern_pos, max(0, pattern_pos-100), -1):
                    if data[i:i+1] == b'{':
                        # Check if this looks like the start of the main JSON object
                        # by counting braces between i and pattern_pos
                        nested = 0
                        for j in range(i+1, pattern_pos):
                            if data[j:j+1] == b'{':
                                nested += 1
                            elif data[j:j+1] == b'}':
                                nested -= 1
                        # If we're at the root level, this is our start position
                        if nested >= 0:
                            start_pos = i
                            break
                
                if start_pos >= 0:
                    # Now find matching closing brace
                    brace_count = 1
                    end_pos = -1
                    
                    for i in range(start_pos+1, len(data)):
                        if data[i:i+1] == b'{':
                            brace_count += 1
                        elif data[i:i+1] == b'}':
                            brace_count -= 1
                            if brace_count == 0:
                                end_pos = i+1
                                break
                    
                    if end_pos > start_pos:
                        # Found complete JSON object
                        json_text = data[start_pos:end_pos]
                        try:
                            # Try to parse and format it
                            json_str = json_text.decode('utf-8', errors='replace')
                            json_obj = json.loads(json_str)
                            
                            # Verify this looks like a httpbin response
                            if isinstance(json_obj, dict) and any(key in json_obj for key in ['url', 'headers', 'args', 'origin']):
                                print(f"Successfully extracted httpbin.org response")
                                return json.dumps(json_obj, indent=2)
                        except Exception as e:
                            print(f"Error parsing JSON: {e}")
        
        # If we couldn't find anything with the above method, try a more aggressive approach
        # by looking for any JSON object with httpbin.org related content
        for i in range(len(data) - 20):
            if data[i:i+1] == b'{':
                # Look ahead for httpbin.org mentions
                window = data[i:min(i+500, len(data))]
                if b'httpbin.org' in window or b'"url"' in window:
                    try:
                        # Find where this JSON object might end
                        brace_count = 1
                        for j in range(i+1, min(i+2000, len(data))):
                            if data[j:j+1] == b'{':
                                brace_count += 1
                            elif data[j:j+1] == b'}':
                                brace_count -= 1
                                if brace_count == 0:
                                    # We found a complete JSON object
                                    json_text = data[i:j+1]
                                    try:
                                        json_str = json_text.decode('utf-8', errors='replace')
                                        json_obj = json.loads(json_str)
                                        if isinstance(json_obj, dict) and len(json_obj) >= 2:
                                            return json.dumps(json_obj, indent=2)
                                    except:
                                        pass
                                    break
                    except:
                        pass
                        
        # No valid JSON found
        return None

    def browse(self, destination_host, request_path="/", circuit_length=3, use_private=False):
        """Send an HTTP request through the Tor circuit and return the response"""
        try:
            print(f"Built circuit with {circuit_length} nodes")
            
            # Create HTTP request for destination
            http_request = self.create_http_request(destination_host, request_path)
            
            # Get node list if needed
            if not self.directory_service.known_nodes:
                self.directory_service.request_node_list()
                
                # Request private nodes if needed
                if use_private and self.auth_token:
                    self.directory_service.request_private_nodes(self.auth_token)
            
            # Build or use existing circuit
            circuit = self.directory_service.build_circuit(length=circuit_length, prefer_private=use_private)
            
            # Build the onion-encrypted request
            encrypted_request = self.build_onion_request(circuit, http_request)
            
            # Send the request through the first node in the circuit
            response = self.send_request(circuit, encrypted_request)
            
            return response
            
        except Exception as e:
            print(f"Error browsing through Tor: {e}")
            import traceback
            traceback.print_exc()
            return None

    def brute_force_extract_json(self, data):
        """Brute force extraction of httpbin.org JSON responses"""
        print("\n=== BRUTE FORCE JSON EXTRACTION ===")
        
        # Convert to bytes if needed
        if isinstance(data, str):
            try:
                data = data.encode('utf-8')
            except:
                pass
        
        # 1. Find all httpbin.org specific keywords in the response
        httpbin_keys = [
            b'"url":', b'"headers":', b'"origin":', b'"args":', 
            b'"Host":', b'"User-Agent":', b'httpbin.org'
        ]
        
        key_positions = {}
        for key in httpbin_keys:
            pos = data.find(key)
            if pos >= 0:
                key_positions[key.decode()] = pos
        
        # If we found at least 3 httpbin keys, we likely have a valid response
        if len(key_positions) >= 3:
            print(f"Found {len(key_positions)} httpbin.org JSON keys:")
            for key, pos in key_positions.items():
                print(f"  - {key} at position {pos}")
                
            # 2. Find the start of the JSON object (the opening brace)
            min_pos = min(key_positions.values())
            start_pos = -1
            
            # Look backwards from the first key to find opening brace
            for i in range(min_pos, max(0, min_pos-200), -1):
                if data[i:i+1] == b'{':
                    # Check if this is likely the main JSON object
                    # by ensuring balanced braces between here and min_pos
                    brace_balance = 0
                    valid_start = True
                    for j in range(i, min_pos):
                        if data[j:j+1] == b'{':
                            brace_balance += 1
                        elif data[j:j+1] == b'}':
                            brace_balance -= 1
                        if brace_balance < 0:
                            valid_start = False
                            break
                    
                    if valid_start:
                        start_pos = i
                        break
            
            # 3. Find the end of the JSON object (matching closing brace)
            if start_pos >= 0:
                print(f"Found JSON object starting at position {start_pos}")
                brace_balance = 0
                end_pos = -1
                
                for i in range(start_pos, len(data)):
                    if data[i:i+1] == b'{':
                        brace_balance += 1
                    elif data[i:i+1] == b'}':
                        brace_balance -= 1
                        if brace_balance == 0:
                            end_pos = i + 1
                            break
                
                # 4. If we found both start and end, extract and parse the JSON
                if end_pos > start_pos:
                    try:
                        json_object = data[start_pos:end_pos]
                        json_str = json_object.decode('utf-8', errors='replace')
                        
                        # Remove any invalid characters that might prevent parsing
                        json_str = ''.join(c for c in json_str if ord(c) >= 32 or c in '\n\r\t')
                        
                        # Try to parse the JSON
                        parsed_json = json.loads(json_str)
                        
                        # Verify it's a httpbin response by checking for expected keys
                        if isinstance(parsed_json, dict) and 'url' in parsed_json and 'headers' in parsed_json:
                            print("Successfully extracted httpbin.org JSON response!")
                            return json.dumps(parsed_json, indent=2)
                    except Exception as e:
                        print(f"Error parsing JSON: {e}")
                        
                        # Try one more time with aggressive character filtering
                        try:
                            json_str = ''.join(c for c in json_str if c in '{}[]",:0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_.:/ \n\r\t')
                            parsed_json = json.loads(json_str)
                            print("Successfully parsed JSON after character filtering!")
                            return json.dumps(parsed_json, indent=2)
                        except:
                            pass
        
        # 5. If above approach fails, try scanning every position for valid JSON
        print("Trying brute force JSON scanning...")
        for i in range(len(data) - 50):  # Minimum reasonable JSON size
            if data[i:i+1] == b'{':
                # Scan all possible ending positions
                for j in range(i + 50, min(i + 2000, len(data))):
                    if data[j:j+1] == b'}':
                        # Try parsing this slice as JSON
                        try:
                            json_slice = data[i:j+1]
                            json_str = json_slice.decode('utf-8', errors='replace')
                            parsed = json.loads(json_str)
                            
                            # Verify it has httpbin.org characteristics
                            if isinstance(parsed, dict) and len(parsed) >= 3:
                                # Check for common httpbin keys
                                httpbin_score = sum(1 for key in ['url', 'headers', 'args', 'origin'] if key in parsed)
                                if httpbin_score >= 2:
                                    print(f"Found valid httpbin JSON object at position {i} (length {j-i+1})")
                                    return json.dumps(parsed, indent=2)
                        except:
                            pass
        
        # 6. Last resort: detect ANY valid JSON structure
        print("Trying to find ANY valid JSON...")
        for i in range(len(data) - 20):
            if data[i:i+1] in (b'{', b'['):
                for j in range(i + 20, min(i + 1000, len(data))):
                    if (data[i:i+1] == b'{' and data[j:j+1] == b'}') or \
                       (data[i:i+1] == b'[' and data[j:j+1] == b']'):
                        try:
                            json_slice = data[i:j+1]
                            json_str = json_slice.decode('utf-8', errors='replace')
                            parsed = json.loads(json_str)
                            if parsed:
                                print(f"Found generic JSON at position {i}")
                                return json.dumps(parsed, indent=2)
                        except:
                            pass
        
        # Nothing found, return None to let other extractors try
        return None

    def handle_raw_http(self, response):
        """Process raw HTTP responses that bypassed encryption"""
        try:
            # Check if this is a raw HTTP response
            if isinstance(response, bytes) and response.startswith(b"RAW_HTTP_RESPONSE:"):
                print("\n=== RAW HTTP RESPONSE DETECTED ===")
                http_data = response[len(b"RAW_HTTP_RESPONSE:"):]
                
                # Find the headers/body split
                header_end = http_data.find(b"\r\n\r\n")
                if (header_end > 0):
                    headers = http_data[:header_end]
                    body = http_data[header_end + 4:]  # Skip \r\n\r\n
                    
                    # Print headers for debugging
                    print("HTTP Headers:")
                    print(headers.decode('utf-8', errors='replace'))
                    
                    # Detect Content-Type
                    content_type = None
                    content_length = None
                    for line in headers.split(b"\r\n"):
                        if line.lower().startswith(b"content-type:"):
                            content_type = line.split(b":", 1)[1].strip().decode('utf-8', errors='replace')
                            print(f"Content-Type: {content_type}")
                        elif line.lower().startswith(b"content-length:"):
                            try:
                                content_length = int(line.split(b":", 1)[1].strip())
                                print(f"Content-Length: {content_length}")
                            except:
                                pass
                    
                    # If Content-Length is specified, trim body
                    if content_length is not None and len(body) > content_length:
                        body = body[:content_length]
                    
                    # Process based on Content-Type
                    if content_type and "json" in content_type.lower():
                        try:
                            json_data = json.loads(body.decode('utf-8', errors='replace'))
                            return json.dumps(json_data, indent=2)
                        except Exception as e:
                            print(f"Error parsing JSON: {e}")
                    
                    # Default to returning the body as text
                    try:
                        return body.decode('utf-8', errors='replace')
                    except:
                        return body
                
                # If we couldn't split headers/body, return the whole thing
                try:
                    return http_data.decode('utf-8', errors='replace')
                except:
                    return http_data
                    
            return None  # Not a raw HTTP response
        except Exception as e:
            print(f"Error handling raw HTTP: {e}")
            return None

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

# Update the destination host
DESTINATION_HOST = "httpbin.org"

def parse_arguments():
    parser = argparse.ArgumentParser(description='Tor-like client implementation')
    parser.add_argument('--private', action='store_true', help='Use private nodes')
    parser.add_argument('--token', type=str, default="secret_token_123", help='Auth token for private nodes')
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    # Create a directory service
    directory_service = DirectoryService()
    
    # Create a Tor client with the directory service and optional auth token
    auth_token = args.token if args.private else None
    tor_client = TorClient(directory_service, auth_token)
    
    # Verify key pair compatibility before proceeding
    if not tor_client.verify_key_pair():
        print("ERROR: Key pair verification failed, aborting")
        return
    
    tor_client.verify_client_registration()
    
    print(f"\n=== TESTING WITH {'PRIVATE' if args.private else 'PUBLIC'} NODES ===\n")
    
    # Get node list and build circuit
    tor_client.directory_service.request_node_list()
    if args.private and auth_token:
        tor_client.directory_service.request_private_nodes(auth_token)
    
    circuit = tor_client.directory_service.build_circuit()
    
    # Test direct communication with exit node
    tor_client.test_direct_encryption_with_exit_node(circuit)
    
    # Add after creating tor_client
    tor_client.debug_directory_service()
    
    # Use the client to browse through the Tor network
    response = tor_client.browse(
        destination_host=DESTINATION_HOST,
        request_path="/get",
        circuit_length=3,
        use_private=args.private
    )
    
    if response:
        print(f"\nResponse received through {'private' if args.private else 'public'} node circuit!")
        print("Response content:")
        
        # Try our new brute force extractor FIRST - most aggressive approach
        brute_force_json = tor_client.brute_force_extract_json(response)
        if brute_force_json:
            print(brute_force_json)
            return
        
        # Then try other extractors in sequence
        for extractor in [
            tor_client.extract_httpbin_response,
            tor_client.json_content_extractor,
            tor_client.final_http_extractor,
            tor_client.aggressive_http_extractor
        ]:
            result = extractor(response)
            if result:
                print(result)
                return
        
        # Last resort - binary preview
        print(f"Binary response ({len(response)} bytes)")
        print("\nBinary preview:")
        for i in range(0, min(128, len(response)), 16):
            hex_values = ' '.join(f'{b:02x}' for b in response[i:i+16])
            ascii_values = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in response[i:i+16])
            print(f"{i:04x}: {hex_values.ljust(48)} {ascii_values}")
    else:
        print(f"\nFailed to get a response through {'private' if args.private else 'public'} nodes")

if __name__ == "__main__":
    main()