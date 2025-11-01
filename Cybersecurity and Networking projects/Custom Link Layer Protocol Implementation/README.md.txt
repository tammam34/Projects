# Custom Network Protocol with Stop-and-Wait ARQ

A Python-based implementation of a custom Layer 2 network protocol using Scapy, featuring encrypted messaging, stop-and-wait ARQ (Automatic Repeat reQuest), and real-time network observation.

## Overview

This project implements a reliable data link layer protocol that operates directly over Ethernet frames. It includes encryption for secure messaging, automatic retransmission on packet loss, and a monitoring system to observe network traffic in real-time.

## What It Does

- **Custom Protocol Layer**: Implements a custom protocol on top of Ethernet (EtherType: 0x1234)
- **Encrypted Communication**: Uses AES encryption to secure all transmitted messages
- **Stop-and-Wait ARQ**: Ensures reliable delivery with automatic retransmission
- **Acknowledgment System**: Receiver sends ACK frames for each successfully received packet
- **Network Monitoring**: Observer component to passively monitor all protocol traffic
- **Timeout & Retry**: Automatic retransmission if ACK is not received within timeout period

## Tools & Technologies Used

### Core Technologies
- **Python 3.x** - Primary programming language
- **Scapy** - Packet manipulation and network sniffing
- **PyCryptodome** - AES encryption/decryption
- **Raw Sockets** - Layer 2 communication

### Key Libraries
```python
scapy           # Network packet crafting and sniffing
pycryptodome    # AES encryption (Crypto.Cipher)
time            # Timeout handling
```

## Project Architecture

### Components

#### 1. Sender.py
The transmitting endpoint that:
- Takes user input messages
- Encrypts messages using AES
- Sends custom protocol frames
- Waits for ACK with timeout
- Retransmits on timeout

#### 2. Receiver.py
The receiving endpoint that:
- Listens for incoming data frames
- Decrypts received messages
- Displays message content
- Sends ACK frames back to sender

#### 3. Observer.py
A passive monitoring tool that:
- Captures all protocol traffic
- Displays DATA and ACK frames
- Shows source and destination MAC addresses
- Provides real-time network visibility

#### 4. Custom_proto.py
The protocol definition containing:
- Custom packet structure
- AES encryption/decryption functions
- Protocol layer binding

## Custom Protocol Structure
```
+----------------+----------------+----------------+----------------+
|   Ethernet     |   CustomProto  |   Encrypted    |                |
|   Header       |   Header       |   Payload      |    Padding     |
+----------------+----------------+----------------+----------------+

CustomProto Header:
- id (2 bytes): Sequence number
- msg_type (1 byte): 0 = DATA, 1 = ACK
- len (2 bytes): Payload length
- payload (variable): Encrypted message data
```

## Security Features

- **AES Encryption**: All messages encrypted with AES-128 in ECB mode
- **Secret Key**: `1234567890abcdef` (configurable in Custom_proto.py)
- **PKCS7 Padding**: Automatic padding for AES block alignment

## Requirements

### Inputs
- **Network Interface**: eth0 (or your configured interface)
- **Receiver MAC Address**: Must be configured in Sender.py
- **Root Privileges**: Required for raw socket access

### System Requirements
- Python 3.6 or higher
- Linux/Unix system with network interface
- Root/sudo access for packet transmission

## Quick Start

### Installation
```bash
# Install required dependencies
pip install scapy pycryptodome

# Clone the repository
git clone <repository-url>
cd custom-network-protocol
```

### Setup
```bash
# Ensure you have the correct network interface
# Default: eth0
# Modify INTERFACE variable in each script if needed

# Sender and Receiver need appropriate MAC addresses
# Update DEST_MAC in Sender.py to match your Receiver's MAC
```

### Usage

#### Terminal 1 - Start Receiver
```bash
sudo python3 Receiver.py
```

#### Terminal 2 - Start Sender
```bash
sudo python3 Sender.py
```

#### Terminal 3 - Start Observer (Optional)
```bash
sudo python3 Observer.py
```

### Example Session
```
[SENDER] Starting sender...

Enter message to send (or 'exit' to quit): Hello World
[SENDER] Sent frame #1
[SENDER] Waiting for ACK #1...
[SENDER] ACK received for frame #1

Enter message to send (or 'exit' to quit): Test Message
[SENDER] Sent frame #2
[SENDER] Waiting for ACK #2...
[SENDER] ACK received for frame #2
```

## Configuration

### Key Parameters

| Parameter | Location | Default | Description |
|-----------|----------|---------|-------------|
| `INTERFACE` | All files | `eth0` | Network interface to use |
| `DEST_MAC` | Sender.py | `02:42:ac:11:00:03` | Receiver's MAC address |
| `TIMEOUT` | Sender.py | `3` seconds | ACK timeout duration |
| `SECRET_KEY` | Custom_proto.py | `1234567890abcdef` | AES encryption key |
| `ETHER_TYPE` | All files | `0x1234` | Custom protocol identifier |

## Protocol Flow

### Successful Transmission
```
Sender                    Receiver
  |                          |
  |---- DATA Frame #1 ------>|
  |                          |
  |                     [Decrypt & Process]
  |                          |
  |<---- ACK Frame #1 -------|
  |                          |
[Next Message]
```

### Timeout & Retransmission
```
Sender                    Receiver
  |                          |
  |---- DATA Frame #1 ---X   | (Lost)
  |                          |
  |   [Timeout - 3s]         |
  |                          |
  |---- DATA Frame #1 ------>| (Retransmit)
  |                          |
  |<---- ACK Frame #1 -------|
  |                          |
```

## Frame Types

### DATA Frame (msg_type = 0)
- Contains encrypted user message
- Includes sequence number
- Requires ACK response

### ACK Frame (msg_type = 1)
- Acknowledges received DATA frame
- Contains matching sequence number
- Minimal payload (just "ACK")

## Main Results & Outputs

### Sender Output
```
[SENDER] Starting sender...
[SENDER] Sent frame #1
[SENDER] Waiting for ACK #1...
[SENDER] ACK received for frame #1
```

### Receiver Output
```
[RECEIVER] Starting receiver...
[RECEIVER] Listening on interface: eth0
[RECEIVER] Received frame #1 from 02:42:ac:11:00:02
==================================================
Frame #1
From: 02:42:ac:11:00:02
Message: Hello World
==================================================
[RECEIVER] Sent ACK for frame #1
```

### Observer Output
```
[OBSERVER] Listening...
DATA frame #1: 02:42:ac:11:00:02 -> 02:42:ac:11:00:03
ACK frame #1: 02:42:ac:11:00:03 -> 02:42:ac:11:00:02
```

## Use Cases

- **Network Protocol Education**: Learn about Layer 2 protocols and ARQ mechanisms
- **Secure Point-to-Point Communication**: Encrypted messaging between two endpoints
- **Network Testing**: Test reliability mechanisms and packet loss scenarios
- **Protocol Development**: Foundation for building custom network protocols
- **Network Forensics Training**: Understand packet capture and protocol analysis

## Features Implemented

### Reliability
- Stop-and-Wait ARQ protocol
- Sequence numbering
- Timeout-based retransmission
- Duplicate detection

### Security
- AES-128 encryption
- All messages encrypted before transmission
- Secure key-based communication

### Monitoring
- Real-time packet observation
- Traffic analysis capabilities
- Protocol debugging support

## Command Line Arguments

None required. All configuration is done via editing the Python files directly.

## Troubleshooting

### Common Issues

**Permission Denied**
```bash
# Solution: Run with sudo
sudo python3 Sender.py
```

**Interface Not Found**
```bash
# Solution: Check available interfaces
ip link show

# Update INTERFACE variable in scripts
INTERFACE = "your_interface_name"
```

**MAC Address Mismatch**
```bash
# Solution: Find receiver's MAC address
ip link show eth0

# Update DEST_MAC in Sender.py
DEST_MAC = "actual_mac_address"
```

**No ACK Received**
- Check if Receiver is running
- Verify MAC addresses match
- Ensure both are on same network/interface
- Check firewall settings

## Technical Specifications

### Protocol Details
- **Layer**: Data Link Layer (Layer 2)
- **EtherType**: 0x1234 (Custom)
- **Encryption**: AES-128-ECB
- **ARQ Method**: Stop-and-Wait
- **Timeout**: 3 seconds (configurable)

### Packet Format
- **Sequence ID**: 16-bit unsigned integer
- **Message Type**: 8-bit (0=DATA, 1=ACK)
- **Length Field**: 16-bit payload length
- **Payload**: Variable length encrypted data

## Acknowledgments

- Scapy library for packet manipulation capabilities
- PyCryptodome for encryption functionality
- Computer networking principles from data link layer protocols
