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
                
                # Prepare registration data - serialize the key
                serialized_key = serialize_public_key(self.public_key)
                
                # Print key fingerprint for debugging
                key_fingerprint = serialized_key[:20].decode() + "..." + serialized_key[-20:].decode()
                print(f"Registering public key: {key_fingerprint}")
                
                # Format as expected by tor_server implementation:
                # The format is likely: REGISTER_CLIENT_KEY client_ID KEY_DATA
                client_id_str = f"client_{self.client_id}"
                message = f"REGISTER_CLIENT_KEY {client_id_str}".encode() + b" " + serialized_key
                
                print(f"Sending registration with format: REGISTER_CLIENT_KEY {client_id_str} [key_data]")
                s.sendall(message)
                
                # Get response
                s.settimeout(5.0)
                try:
                    response = s.recv(1024)
                    print(f"Registration response: {response}")
                    success = response == b"SUCCESS" or response == b""  # Empty might mean success too
                    
                    if success:
                        print(f"Client {self.client_id} registered with directory service")
                        # Verify registration
                        self.verify_client_registration()
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
        
        # Serialize our public key to include it in the request
        serialized_key = serialize_public_key(self.public_key).decode()
        
        # Add client ID AND public key to data so exit node doesn't need to fetch from directory
        client_id_marker = f"CLIENT_ID:{self.client_id}:".encode()
        key_marker = f"CLIENT_KEY:{serialized_key}:".encode()
        
        # Format: CLIENT_ID:id:CLIENT_KEY:key:actual-data
        data = client_id_marker + key_marker + request_data
        print(f"Added client ID {self.client_id} and public key to request")
        
        # Start with the exit node (last in the circuit)
        exit_node_index = len(circuit) - 1
        exit_node = circuit[exit_node_index]
        print(f"Exit node is Node {exit_node['id']}")
        
        # First, encrypt with exit node's key
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
                    
                    # Attempt to decrypt the response
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
            # First check if the response is already plaintext
            if b"HTTP/" in encrypted_data[:20] or b"{" in encrypted_data[:5]:
                print("Response appears to be plaintext - no decryption needed")
                return encrypted_data
            
            # Split the data into chunks
            chunk_delimiter = b"::CHUNK::"
            encrypted_chunks = encrypted_data.split(chunk_delimiter)
            print(f"Splitting response into {len(encrypted_chunks)} chunks")
            
            # Decrypt each chunk
            decrypted_chunks = []
            for i, chunk in enumerate(encrypted_chunks):
                if not chunk.strip():
                    continue
                
                print(f"Decrypting response chunk {i}, length {len(chunk)}")
                
                try:
                    # Base64 decode the chunk
                    decoded_chunk = base64.b64decode(chunk)
                    print(f"Base64 decoded to {len(decoded_chunk)} bytes")
                    
                    # Try with various padding configurations
                    padding_configurations = [
                        padding.PKCS1v15(),  # Try this first since it worked before
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        ),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA1()),
                            algorithm=hashes.SHA1(),
                            label=None
                        )
                    ]
                    
                    success = False
                    for pad_config in padding_configurations:
                        try:
                            decrypted_chunk = self.private_key.decrypt(decoded_chunk, pad_config)
                            print(f"Successfully decrypted chunk with {pad_config.__class__.__name__}")
                            decrypted_chunks.append(decrypted_chunk)
                            success = True
                            break
                        except Exception:
                            continue
                    
                    if not success:
                        print(f"Failed to decrypt chunk {i}")
                
                except Exception as e:
                    print(f"Error processing chunk {i}: {e}")
            
            if decrypted_chunks:
                result = b"".join(decrypted_chunks)
                print(f"Successfully decrypted {len(decrypted_chunks)} chunks, total length {len(result)}")
                
                # Attempt to interpret the binary data
                print(f"First 20 bytes: {' '.join(f'{b:02x}' for b in result[:20])}")
                
                # Try to detect different formats
                if result.startswith(b"HTTP/") or b"\r\n\r\n" in result[:100]:
                    print("Response appears to be HTTP")
                    return result
                elif result.startswith(b"{") and b"}" in result:
                    print("Response appears to be JSON")
                    return result
                elif b"\x00\x00\x00" in result[:20]:  # Common in binary formats
                    print("Response appears to be binary data")
                    
                    # Try to extract any text from binary data
                    printable = bytes([b for b in result if 32 <= b <= 126 or b in (9, 10, 13)])
                    if len(printable) > len(result) * 0.5:  # If at least 50% is printable
                        print(f"Found readable text in binary: {printable[:100]}")
                    
                    return result
                else:
                    # It could be encrypted with another layer or in another format
                    print("Data format unknown, returning binary data")
                    return result
                
            return encrypted_data
        
        except Exception as e:
            print(f"Error in decrypt_response: {e}")
            return encrypted_data

    def interpret_binary_response(self, binary_data):
        """Better interpret the binary responses returned from nodes"""
        print("\n=== ANALYZING BINARY RESPONSE ===")
        
        # Create hexdump for visualization
        def hexdump(data, length=16):
            result = []
            for i in range(0, len(data), length):
                chunk = data[i:i+length]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                printable = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                result.append(f"{i:04x}: {hex_part.ljust(length*3)} {printable}")
            return '\n'.join(result)
        
        # Print first few bytes as hex for debugging
        print(f"First 64 bytes as hex:")
        print(hexdump(binary_data[:64]))
        
        # Check for HTTP signatures in binary data
        if b"HTTP/" in binary_data:
            print("HTTP response detected in binary data!")
            parts = binary_data.split(b"\r\n\r\n", 1)
            if len(parts) > 1:
                headers, body = parts
                print("\nHTTP Headers:")
                print(headers.decode(errors='replace'))
                print("\nBody:")
                return body
        
        # Check for JSON content
        try:
            # Try to find JSON by looking for { and } characters
            start_idx = binary_data.find(b"{")
            if start_idx >= 0:
                for end_idx in range(len(binary_data)-1, start_idx, -1):
                    if binary_data[end_idx] == ord(b'}'):
                        json_data = binary_data[start_idx:end_idx+1]
                        try:
                            parsed = json.loads(json_data)
                            print("\nJSON data found:")
                            print(json.dumps(parsed, indent=2))
                            return json_data
                        except:
                            pass
        except:
            pass

        # Extract any readable text
        printable = bytes([b for b in binary_data if 32 <= b <= 126 or b in (9, 10, 13)])
        if len(printable) > len(binary_data) * 0.2:  # If at least 20% is printable
            print("\nExtracted readable text:")
            print(printable.decode(errors='replace'))
        
        return binary_data

    def handle_binary_response(self, binary_data):
        """Extract meaningful information from binary responses"""
        print("\n=== EXTRACTING DATA FROM BINARY RESPONSE ===")
        
        # Create a cleaner hexdump for better analysis
        def hexdump(data, length=16):
            result = []
            for i in range(0, min(256, len(data)), length):
                chunk = data[i:i+length]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                result.append(f"{i:04x}: {hex_part.ljust(length*3)} {ascii_part}")
            return '\n'.join(result)
        
        print(f"Response size: {len(binary_data)} bytes")
        print(f"Hexdump of first 256 bytes:")
        print(hexdump(binary_data))
        
        # Try to identify a payload marker - common in binary protocols
        marker_candidates = [b"DATA:", b"PAYLOAD:", b"\x00\x00\x00\x01", b"HTTP/"]
        for marker in marker_candidates:
            pos = binary_data.find(marker)
            if pos >= 0:
                print(f"Found marker '{marker}' at position {pos}")
                payload = binary_data[pos+len(marker):]
                print(f"Extracted payload ({len(payload)} bytes)")
                return payload
                
        # Try to extract any text content - often hidden in binary responses
        import string
        printable_chars = string.printable.encode()
        text_segments = []
        current_segment = []
        
        for byte in binary_data:
            if byte in printable_chars:
                current_segment.append(byte)
            elif current_segment:
                if len(current_segment) > 4:  # Only keep segments of reasonable length
                    text_segments.append(bytes(current_segment))
                current_segment = []
                
        if current_segment and len(current_segment) > 4:
            text_segments.append(bytes(current_segment))
            
        if text_segments:
            print(f"Found {len(text_segments)} text segments")
            for i, segment in enumerate(text_segments[:3]):  # Show first 3
                print(f"Segment {i}: {segment.decode(errors='replace')}")
                
        # If all else fails, return the original data
        return binary_data
            
    def browse(self, destination_host, request_path="/", circuit_length=2, use_private=False):
        """
        Main method to send a request through the Tor network
        """
        # 1. Get node information
        self.directory_service.request_node_list()
        if use_private and self.auth_token:
            self.directory_service.request_private_nodes(self.auth_token)
            
        # 2. Build a circuit
        try:
            circuit = self.directory_service.build_circuit(length=circuit_length)
            print(f"Built circuit with {len(circuit)} nodes")
        except ValueError as e:
            print(f"Error building circuit: {e}")
            return None
            
        # 3. Create the HTTP request
        request = f"GET {request_path} HTTP/1.1\r\nHost: {destination_host}\r\n\r\n".encode()
        
        # 4. Build the onion-encrypted request
        encrypted_request = self.build_onion_request(circuit, request)
        
        # 5. Send the request through the entry node
        response = self.send_request(circuit, encrypted_request)
        
        if response:
            # Try to interpret the binary response
            interpreted_response = self.interpret_binary_response(response)
            # Try to extract useful data from binary format
            extracted_data = self.handle_binary_response(interpreted_response)
            return extracted_data
        
        return None

    # Add this method to the TorClient class
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
        print(response.decode(errors='replace'))
    else:
        print(f"\nFailed to get a response through {'private' if args.private else 'public'} nodes")

if __name__ == "__main__":
    main()