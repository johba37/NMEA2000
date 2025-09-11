# CZONE Development Tools

This directory contains development and reverse engineering tools used to understand the CZONE proprietary protocol. These are research tools, not part of the main NMEA2000 library.

## Tools Overview

### Primary Analysis Tool
- **czone_switch_decoder.cpp** - Main protocol analyzer with multiple modes:
  - Message capture and filtering 
  - Binary payload analysis
  - Protocol reverse engineering
  - Live network monitoring
  - Switch control testing

*Note: The compiled binary `czone_switch_decoder` remains in the root directory for agent use.*

### Python Analysis Scripts
- **analyze_*.py** - Various protocol analysis scripts
- **systematic_mapper.py** - Systematic protocol mapping
- **live_decoder.py** - Real-time message decoding
- **extract_binary_payloads.py** - Payload extraction tools

### Specialized Tools
- **counter_decoder.cpp** - Timestamp counter analysis
- **passive_decoder.cpp** - Passive network monitoring
- **switch_investigation.cpp** - Switch state investigation
- **raw_can_analyzer.cpp** - Low-level CAN analysis

### Capture Data
- **\*.txt** - Network capture files from various test scenarios
- **\*.csv** - Processed analysis data
- **\*.sh** - Test automation scripts

## Integration Status

The knowledge gained from these tools has been integrated into the main NMEA2000 library:
- **src/N2kCZone.h** - CZONE protocol definitions and API
- **src/N2kCZone.cpp** - CZONE message parsing and generation
- **Examples/CZoneSwitchMonitor/** - Example implementation

## Development Workflow

1. Use `czone_switch_decoder` for live protocol analysis
2. Capture network traffic with various scenarios
3. Analyze captured data with Python scripts
4. Update main library with confirmed protocol findings
5. Test integration with CZoneSwitchMonitor example

## Current Protocol Understanding

### Confirmed Structures
- CZONE uses proprietary NMEA2000 format: `93 13 XX`
- Message structure (17 bytes): `[Instance][0xFF][Type][Timestamp_4B][0x08][Payload_9B]`
- PGN mapping: 65282/65283 for different message types
- Network-synchronized 100ms timestamp counter

### Areas Needing Investigation
- Switch state encoding within payload bytes
- Message type 0x64 payload structure 
- Control message authentication/acceptance
- Device configuration protocols

## Usage

Compiled binaries remain in root directory for agent access:
```bash
# From repository root
./czone_switch_decoder --help
./czone_switch_decoder --capture --device 0x12 --count 10
```

Source files are in this directory for development and modification.