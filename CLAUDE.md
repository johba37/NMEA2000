# CZONE Switch Bank Protocol Analysis

## Test Setup Hardware Configuration (Specific to Development Environment)
- 1 CZONE control panel (12 physical buttons)
- 2 CZONE switch banks (6 switches each) 
- Communication via NMEA2000 network only
- Connected via Actisense NGT-1 USB adapter (/dev/ttyUSB0)

## Current Switch States
- Bank 1 (Device 0x12): ON, ON, ON, OFF, OFF, OFF
- Bank 2 (Device 0x13): ON, ON, ON, OFF, ON, OFF

## Confirmed Device Identification (from SignalK)

### Physical Devices (Standard NMEA2000)
- **Switch Bank 1**: BEP Marine "Contact 6 Plus" 
  - NMEA2000 Address: 0x01 (src "1")
  - Device Instance: 1
  - Software: 6.17.17.0
  - Standard PGNs: 126996, 127508, 60928
  - **Firmware Impact**: Older firmware uses simpler CZONE protocol (Type 0x09 only)

- **Switch Bank 2**: BEP Marine "Contact 6 Plus"
  - NMEA2000 Address: 0x02 (src "2")  
  - Device Instance: 3
  - Software: 6.21.23.0
  - Standard PGNs: 126996, 60928
  - **Firmware Impact**: Newer firmware uses complex CZONE protocol (Type 0x09 + 0x24)

- **Control Panel**: BEP Marine "Key Pad"
  - NMEA2000 Address: 0x03 (src "3")
  - Device Instance: 96 (0x60)
  - Software: 6.21.23.0
  - Standard PGNs: 126996, 60928

### CZONE Protocol Addresses (Proprietary)
- **0x12**: CZONE messages from Switch Bank 1 (PGN 65282)
- **0x13**: CZONE messages from Switch Bank 2 (PGN 65282/65283)
- **0x46**: CZONE messages from Control Panel (PGN 65282)

**Key Discovery**: Devices use dual addressing - standard NMEA2000 addresses (0x01-0x03) for standard messages and CZONE proprietary addresses (0x12, 0x13, 0x46) for switch control.

## Analysis Tools

### Primary Tool: Canboat NMEA2000 Analysis Suite
Use the professional-grade canboat toolkit located at `./tools/canboat/` for all NMEA2000 and CZONE protocol analysis.

**Tool Location:**
- Binaries: `./tools/canboat/rel/linux-x86_64/`
- All captures MUST be saved to `./czone_data/` directory (git-excluded)

**CRITICAL WARNING:**
- NEVER use `ls -la /dev/ttyUSB*` command - it kills the NGT-1 USB process
- Always use short timeouts for capture operations to avoid crashes
- Include switch states in filenames when known: `sb1-on-on-on-off-off-off-<timestamp>.txt`
- Current switch states: Bank 1 (0x12): ON,ON,ON,OFF,OFF,OFF | Bank 2 (0x13): ON,ON,ON,OFF,ON,OFF

**IMPORTANT RULES:**
- Use the czone-protocol-analyzer agent for all NMEA2000/CZONE investigation tasks
- DO NOT create new tools or scripts, except for parsing canboat output
- NEVER question the NMEA2000 bus functionality - there are no other connections, buttons, wires or config files
- Everything goes over the NMEA2000 bus - if data isn't found, it's because the NGT-1 is not configured properly
- Firmware versions ARE transmitted on the bus (SignalK reads them) via PGN 126996

### Using the CZONE Protocol Analyzer Agent
For any NMEA2000/CZONE analysis task, use:
```
Use the czone-protocol-analyzer agent to [describe your investigation goal]
```

Examples:
- "Use the czone-protocol-analyzer agent to capture and analyze network traffic patterns"
- "Use the czone-protocol-analyzer agent to find firmware versions from BEP devices"
- "Use the czone-protocol-analyzer agent to identify CZONE message structure and encoding"

## Protocol Analysis Results

### CZONE Protocol Structure (NMEA2000 Proprietary)

**Message Format**:
```
93 13 [PGN_OFFSET] [SOURCE] [DEST] [17-byte CZONE Data]
```

**Header Fields**:
- `93 13` = CZONE proprietary protocol identifier
- `PGN_OFFSET` = Message type (0x02 → PGN 65282, 0x03 → PGN 65283)  
- `SOURCE` = Device ID (0x12, 0x13, 0x46, etc.)
- `DEST` = Destination (0xF1=functional, 0xFF=broadcast)

**Key Discovery**: CZONE uses proprietary 17+ byte payloads with NMEA2000 single-frame PGNs (65280-65535), violating standard 8-byte frame limits.

### CZONE Message Types and Structure

**Base Format**: `01 FF [MSG_TYPE] [TIMESTAMP_4B] [TYPE_SPECIFIC_PAYLOAD]`

**Message Types** (byte 2 of CZONE payload):
- `0x09` = Heartbeat/basic status (~48% of traffic)
  - Payload: `08 00 [counter] 11 ff 7f ff 7f fd [checksum]`
  - From all devices, high frequency
  
- `0x24` = Extended data/status (~32% of traffic)  
  - Payload: `08 [SEQ_HIGH] [SEQ_LOW] [data...] fd [checksum]`
  - Bytes 1-2 form a 16-bit sequence counter
  - From all devices, lower frequency
  
- `0x23` = Unknown function (~14% of traffic)
  - From devices 0x19 (unknown module) and 0x3 (control panel)
  - Uses both PGN 65282 and 65283
  - Payload pattern: `08 ff ...` or `08 ff ff 7f ...`
  
- `0x64` = Unknown function (~5% of traffic)
  - From devices 0x1 and 0x2 (switch banks!)
  - Only uses PGN 65283
  - Could be switch state reports or configuration data

**Timestamp**: 32-bit little-endian (positions 3-6 after 01 FF)
- Network-synchronized across all devices
- 100ms resolution (confirmed by measurement)
- Persistent counter, not Unix timestamp

### Firmware Version Detection
**Status**: CONFIRMED - Can be inferred from CZONE message patterns

**Detection Method**:
- **Firmware 6.17.x**: Sends only Type 0x09 messages on PGN 65282
- **Firmware 6.21.x**: Sends Type 0x09 + Type 0x24 messages on both PGN 65282/65283

**Impact on Protocol**:
- Different firmware versions encode switch states differently
- Cannot assume identical encoding between Bank 1 and Bank 2
- Each firmware must be reverse-engineered separately

### Switch State Encoding
**Status**: INVESTIGATION ONGOING - Firmware differences complicate analysis

**0x24 Message Structure** (PGN 65282):
```
01 ff 24 [timestamp_4B] 02 [SEQ_HIGH] [SEQ_LOW] [byte10] [payload...]
Position: 0  1  2  3-6      7  8         9        10       11+
```

**Important Discovery**: 
- Bytes 8-9 form a 16-bit sequence counter that increments continuously (~256 per message)
- This counter is NOT related to switch states - it increments regardless of state
- The apparent "ranges" previously documented were just the counter happening to be at different values during captures

**Actual State Encoding**: UNKNOWN
- Byte 10 shows slight variation (0x21 vs 0x22 for state 111000)
- Switch states may be encoded in 0x09 messages instead
- Or states might not be directly encoded but inferred from other data

**Next Steps**:
- Analyze 0x09 messages for state encoding
- Check if switch state changes trigger specific message patterns
- Investigate byte 10 variations more systematically

### PGN 65280 Switch Control (Not Working)
**Status**: Commands not accepted by switch banks.

**Tested Configurations**:
- Multiple destinations: 0x12, 0x13, 0x46, 0xF1, 0xFF
- Multiple source IDs: 0x03, 0x46, 0xFF
- Various message formats and switch indices
- Result: Switch banks ignore PGN 65280 messages

**Observations**:
- No PGN 65280 messages seen when physical buttons pressed
- Switch banks appear to handle physical buttons locally
- PGN 65280 protocol may be disabled or require authentication


## Network Topology
```
Switch Bank 1 (0x12) ─┐
                      ├─→ NMEA2000 Bus ─→ Control Panel/Module (0x46)
Switch Bank 2 (0x13) ─┘
```

### Other Network Devices
- 0x19: Unknown CZONE module (PGN 65283 only)
- 0x01, 0x02, 0x03: System modules (lower message rates)
- Various other devices using different PGN ranges

## Refactoring Recommendations for czone_switch_decoder

### Current Tool Limitations
- Mixed analysis modes in single file (~1000+ lines)
- Hard to extend for new analysis types
- Limited data export capabilities
- No persistent storage of findings

### Suggested Modular Structure
```
czone_analyzer/
├── core/
│   ├── protocol.h          # CZONE protocol definitions
│   ├── message_parser.cpp  # Clean parsing logic
│   └── device_tracker.cpp  # Device state management
├── analyzers/
│   ├── switch_decoder.cpp  # Switch state analysis
│   ├── traffic_analyzer.cpp # Network traffic patterns
│   └── timing_analyzer.cpp  # Message timing analysis
├── exporters/
│   ├── csv_exporter.cpp    # Export to CSV/Excel
│   └── json_exporter.cpp   # Export for other tools
└── tools/
    ├── live_monitor        # Real-time monitoring
    ├── batch_analyzer      # Process capture files
    └── switch_tester       # Interactive switch testing
```

### Key Improvements Needed
1. **Separate parsing from analysis** - Clean protocol definitions
2. **Plugin architecture** - Easy to add new decoders  
3. **Data persistence** - Store findings across sessions
4. **Interactive mode** - Real-time switch testing with immediate feedback
5. **Export capabilities** - Generate reports for documentation