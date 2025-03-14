# Tor-like Network Implementation

This project implements a simplified version of the Tor network, featuring multi-hop routing, multi-layer encryption, and directory services.

## Components

- **Directory Server**: Central service for node discovery and registration
  - `directory_server.py`

- **Client Implementation** (Part 2):
  - `tor_client.py` - Client that builds circuits and sends requests through the Tor-like network
  - Usage: 
    - Public nodes only: `python tor_client.py`
    - With private nodes: `python tor_client.py --private`

- **Server Implementation** (Part 3):
  - `tor_server.py` - Nodes that form the network, relaying encrypted traffic

## Features

- Multi-layer "onion" encryption
- Circuit building through multiple nodes
- Directory services for node discovery
- Support for private nodes (bonus feature)
- End-to-end request/response handling

## Setup and Testing

1. Start the directory server: `python directory_server.py`
2. Start the server nodes: `python tor_server.py`
3. Run the client: `python tor_client.py`
4. Run the client: `python tor_client.py --private` to use private nodes

## Requirements

- Python 3.x
- cryptography library: `pip install cryptography`