/*
 * CZONE Switch Decoder - Reverse Engineering Tool
 * 
 * Decodes CZONE proprietary NMEA2000 messages for switch bank analysis
 * Connected via Actisense NGT-1 USB adapter on /dev/ttyUSB0
 * 
 * Protocol: CZONE uses proprietary 17+ byte payloads with NMEA2000 single-frame
 * PGNs (65280-65535), violating standard 8-byte frame limits.
 * 
 * Confirmed Devices:
 * - 0x12: Switch Bank 1 (PGN 65282 only)
 * - 0x13: Switch Bank 2 (PGN 65282/65283 mixed)
 * - 0x46: Control Panel/Module (responds to switch changes)
 * 
 * Message Format: 93 13 [PGN_OFFSET] [SOURCE] [DEST] [17-byte CZONE Data]
 * 
 * Compile: g++ -std=c++14 -O2 -o czone_switch_decoder czone_switch_decoder.cpp
 * TODO: Refactor into modular analyzer (see CLAUDE.md for architecture)
 */

#include <iostream>
#include <fstream>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <cstring>
#include <iomanip>
#include <vector>
#include <set>
#include <map>
#include <chrono>
#include <algorithm>
#include <signal.h>
#include <atomic>
#include <poll.h>
#include <errno.h>
#include <stdint.h>

// Include NMEA2000 library headers via our transport
#include "N2kNGT1.h"        // Our minimal NMEA2000 transport
#include "../../src/N2kCZone.h"
#include "../../src/N2kMessages.h"

// =============================================================================
// CZONE Protocol Definitions
// =============================================================================

namespace CZone {
    // Protocol markers and identifiers
    constexpr uint8_t PROTOCOL_MARKER_1 = 0x93;  // CZONE protocol identifier byte 1
    constexpr uint8_t PROTOCOL_MARKER_2 = 0x13;  // CZONE protocol identifier byte 2
    
    // PGN definitions
    constexpr uint32_t PGN_BASE = 65280;         // 0xFF00 - Proprietary PDU2 range start
    constexpr uint32_t PGN_SWITCH_STATUS = 65282;  // 0xFF02 - Switch status messages
    constexpr uint32_t PGN_SWITCH_CONTROL = 65283; // 0xFF03 - Switch control messages
    
    // Message structure offsets (in raw buffer)
    constexpr size_t OFFSET_MARKER_1 = 0;        // Protocol marker 1
    constexpr size_t OFFSET_MARKER_2 = 1;        // Protocol marker 2  
    constexpr size_t OFFSET_PGN_OFFSET = 2;      // PGN offset byte
    constexpr size_t OFFSET_SOURCE = 3;          // Source device ID
    constexpr size_t OFFSET_DESTINATION = 4;     // Destination ID
    constexpr size_t OFFSET_DATA_START = 5;      // Start of CZONE data payload
    
    // Message header sizes
    constexpr size_t HEADER_SIZE = 5;            // Bytes before data payload
    constexpr size_t MIN_MESSAGE_SIZE = 5;       // Minimum valid message size
    
    // Data payload structure (within CZONE data)
    constexpr size_t DATA_DEVICE_INSTANCE = 0;   // Device instance/version
    constexpr size_t DATA_HEADER_MARKER = 1;     // Always 0xFF
    constexpr size_t DATA_MESSAGE_TYPE = 2;      // 0x09=status, 0x24=extended
    constexpr size_t DATA_TIMESTAMP_START = 3;   // 32-bit LE timestamp start
    constexpr size_t DATA_TIMESTAMP_SIZE = 4;    // Timestamp is 4 bytes
    
    // Message types (byte 2 of data payload)
    constexpr uint8_t MSG_TYPE_STATUS = 0x09;    // Status/heartbeat message
    constexpr uint8_t MSG_TYPE_EXTENDED = 0x24;  // Extended data message
    
    // Known device IDs
    constexpr uint8_t DEVICE_SWITCH_BANK_1 = 0x12;
    constexpr uint8_t DEVICE_SWITCH_BANK_2 = 0x13;
    constexpr uint8_t DEVICE_CONTROL_PANEL = 0x46;
    
    // Destination addresses
    constexpr uint8_t DEST_BROADCAST = 0xFF;     // Broadcast to all
    constexpr uint8_t DEST_FUNCTIONAL = 0xF1;    // Functional address
    
    // Switch control (PGN 65280)
    constexpr uint32_t PGN_SWITCH_CONTROL_CMD = 65280;  // 0xFF00 - Switch control commands
    constexpr uint8_t SWITCH_CMD_ON = 0xF1;      // Set switch ON
    constexpr uint8_t SWITCH_CMD_OFF = 0xF4;     // Set switch OFF  
    constexpr uint8_t SWITCH_CMD_TOGGLE = 0xF2;  // Toggle switch
    constexpr uint8_t SWITCH_CMD_END = 0x40;     // End of change
    
    // Switch indices (byte 2 of control message)
    constexpr uint8_t SWITCH_INDEX_START = 0x05; // First switch index
    constexpr uint8_t SWITCH_INDEX_END = 0x0C;   // Last switch index (8 switches total)
    
    // Helper functions
    inline bool IsKnownDevice(uint8_t device_id) {
        return device_id == DEVICE_SWITCH_BANK_1 || 
               device_id == DEVICE_SWITCH_BANK_2 || 
               device_id == DEVICE_CONTROL_PANEL;
    }
    
    inline bool IsCZONEPGN(uint32_t pgn) {
        return pgn == PGN_SWITCH_STATUS || pgn == PGN_SWITCH_CONTROL;
    }
    
    inline const char* GetDeviceName(uint8_t device_id) {
        switch(device_id) {
            case DEVICE_SWITCH_BANK_1: return "Switch Bank 1";
            case DEVICE_SWITCH_BANK_2: return "Switch Bank 2";
            case DEVICE_CONTROL_PANEL: return "Control Panel";
            default: return "Unknown Device";
        }
    }
}

// Global flag for signal handling
std::atomic<bool> g_running(true);

void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        g_running = false;
    }
}
// Use message type constants from library
// (N2kCZone_MsgType_Heartbeat, N2kCZone_MsgType_Extended, etc.)

// Use type-specific structures from library
// (tN2kCZoneHeartbeat, tN2kCZoneExtended, tN2kCZoneSwitchState)

// Generic parsed message that can hold any type
struct CZoneParsedMessage {
    uint8_t MessageType;       // 0x09, 0x24, 0x23, 0x64
    uint8_t SourceDevice;      // NMEA2000 source address
    uint32_t PGN;             // NMEA2000 PGN (65282, 65283, etc.)
    
    union {
        tN2kCZoneHeartbeat heartbeat;
        tN2kCZoneExtended extended;
        tN2kCZoneSwitchState switchState;
        tN2kCZoneSwitchState unknown23;  // Reuse switchState structure for type 0x23
        tN2kCZoneMessage raw;  // Fallback for unknown types
    } data;
};

// Use the library's tN2kCZoneMessage structure from N2kCZone.h
using CZoneRawMessage = tN2kCZoneMessage;

// Generic parser - proper implementation based on tN2kCZoneMessage structure
bool ParseCZoneMessage(const unsigned char* RawData, int DataLen, CZoneRawMessage &CZoneMsg) {
    // CZONE messages are exactly 17 bytes
    if (DataLen != 17) {
        return false;
    }
    
    // Parse according to tN2kCZoneMessage structure
    CZoneMsg.DeviceInstance = RawData[0];
    CZoneMsg.Header = RawData[1];
    CZoneMsg.DeviceType = RawData[2];
    
    // 32-bit little-endian timestamp at bytes 3-6
    CZoneMsg.Timestamp = RawData[3] | 
                        (RawData[4] << 8) | 
                        (RawData[5] << 16) | 
                        (RawData[6] << 24);
    
    CZoneMsg.DataLength = RawData[7];
    
    // Copy 9-byte payload (bytes 8-16)
    memcpy(CZoneMsg.Payload, &RawData[8], 9);
    
    return true;
}

// Type-specific parsing functions - now uses library functions to eliminate duplication
bool ParseCZoneTypedMessage(const unsigned char* RawData, int DataLen, uint8_t SourceDevice, uint32_t PGN, CZoneParsedMessage &ParsedMsg) {
    // First parse using library function
    if (!ParseCZoneMessage(RawData, DataLen, ParsedMsg.data.raw)) {
        return false;
    }
    
    // Extract common fields
    ParsedMsg.MessageType = ParsedMsg.data.raw.DeviceType;  // DeviceType is actually MessageType
    ParsedMsg.SourceDevice = SourceDevice;
    ParsedMsg.PGN = PGN;
    
    // Type-specific parsing using library functions
    switch(ParsedMsg.MessageType) {
        case N2kCZone_MsgType_Heartbeat:
            // Parse heartbeat message (type 0x09)
            ParsedMsg.data.heartbeat.DeviceInstance = ParsedMsg.data.raw.DeviceInstance;
            ParsedMsg.data.heartbeat.Timestamp = ParsedMsg.data.raw.Timestamp;
            ParsedMsg.data.heartbeat.Counter = ParsedMsg.data.raw.Payload[2];
            memcpy(ParsedMsg.data.heartbeat.FixedData, &ParsedMsg.data.raw.Payload[3], 6);
            ParsedMsg.data.heartbeat.Checksum = ParsedMsg.data.raw.Payload[8];
            return true;
            
        case N2kCZone_MsgType_Extended:
            // Parse extended message (type 0x24)
            ParsedMsg.data.extended.DeviceInstance = ParsedMsg.data.raw.DeviceInstance;
            ParsedMsg.data.extended.Timestamp = ParsedMsg.data.raw.Timestamp;
            ParsedMsg.data.extended.SequenceCounter = ParsedMsg.data.raw.Payload[0] | (ParsedMsg.data.raw.Payload[1] << 8);
            memcpy(ParsedMsg.data.extended.Data, &ParsedMsg.data.raw.Payload[2], 7);
            ParsedMsg.data.extended.Checksum = ParsedMsg.data.raw.Payload[8];
            return true;
            
        case N2kCZone_MsgType_SwitchState:
            // Parse switch state message (type 0x64)
            ParsedMsg.data.switchState.DeviceInstance = ParsedMsg.data.raw.DeviceInstance;
            ParsedMsg.data.switchState.Timestamp = ParsedMsg.data.raw.Timestamp;
            memcpy(ParsedMsg.data.switchState.Payload, ParsedMsg.data.raw.Payload, 9);
            return true;
            
        case N2kCZone_MsgType_Control:
            // Use switch state structure for type 0x23 as they have similar payload
            // Parse type 23 message (control message)
            // Use same structure as switch state for now since format is unknown
            ParsedMsg.data.unknown23.DeviceInstance = ParsedMsg.data.raw.DeviceInstance;
            ParsedMsg.data.unknown23.Timestamp = ParsedMsg.data.raw.Timestamp;
            memcpy(ParsedMsg.data.unknown23.Payload, ParsedMsg.data.raw.Payload, 9);
            return true;
            
        default:
            // Raw data already parsed above
            return true;
    }
}

// Helper function to get message type name - now calls library function
const char* GetCZoneMessageTypeName(uint8_t msgType) {
    // Simple message type name mapping
    switch (msgType) {
        case 0x09: return "Heartbeat";
        case 0x23: return "Type23";
        case 0x24: return "Extended";
        case 0x64: return "Type64";
        default: return "Unknown";
    }
}

// Helper to print parsed message
void PrintCZoneParsedMessage(const CZoneParsedMessage& msg) {
    std::cout << "Type: 0x" << std::hex << (int)msg.MessageType << std::dec 
              << " (" << GetCZoneMessageTypeName(msg.MessageType) << ")"
              << " from device 0x" << std::hex << (int)msg.SourceDevice << std::dec
              << " via PGN " << msg.PGN << std::endl;
    
    switch(msg.MessageType) {
        case N2kCZone_MsgType_Heartbeat:
            std::cout << "  Counter: " << (int)msg.data.heartbeat.Counter 
                     << " Timestamp: " << msg.data.heartbeat.Timestamp << std::endl;
            break;
            
        case N2kCZone_MsgType_Extended:
            std::cout << "  Sequence: " << msg.data.extended.SequenceCounter 
                     << " Timestamp: " << msg.data.extended.Timestamp << std::endl;
            break;
            
        case N2kCZone_MsgType_SwitchState:
            std::cout << "  Payload: ";
            for(int i = 0; i < 9; i++) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') 
                         << (int)msg.data.switchState.Payload[i] << " ";
            }
            std::cout << std::dec << std::endl;
            break;
            
        default:
            std::cout << "  [Raw data]" << std::endl;
    }
}

// Debug checksum calculation
uint8_t CalculateSimpleChecksum(const unsigned char* data, int len) {
    uint8_t sum = 0;
    for (int i = 0; i < len; i++) {
        sum += data[i];
    }
    return sum;
}

uint8_t CalculateXORChecksum(const unsigned char* data, int len) {
    uint8_t xor_result = 0;
    for (int i = 0; i < len; i++) {
        xor_result ^= data[i];
    }
    return xor_result;
}

// Protocol Analysis Core - extracted from monolithic decoder
class CZoneProtocolAnalyzer {
private:
    std::vector<CZoneRawMessage> message_db;
    
public:
    void AddMessage(const CZoneRawMessage& msg) {
        message_db.push_back(msg);
    }
    
    size_t GetMessageCount() const {
        return message_db.size();
    }
    
    // TODO: Move analysis methods here incrementally
    // For now, just basic storage and access
};

// Removed hardcoded switch state assumption functions
// These made premature assumptions about protocol semantics

class CZONESwitchDecoder {
private:
    int fd;
    CZoneProtocolAnalyzer analyzer;  // New: extracted protocol analysis
    
    enum Constants {
        DLE = 0x10,
        STX = 0x02,
        ETX = 0x03
    };
    
    enum State {
        WAIT_DLE,
        WAIT_STX,
        READ_MESSAGE,
        WAIT_ETX,
        ESCAPE_NEXT
    };
    
    State state = WAIT_DLE;
    std::vector<uint8_t> message_buffer;
    
    // Track switch states by source address
    std::map<uint8_t, std::vector<uint8_t>> last_data_by_source;
    bool baseline_captured = false;
    std::chrono::steady_clock::time_point baseline_start;
    
public:
    struct N2KMessage {
        uint32_t pgn;
        uint8_t source;
        uint8_t destination;
        uint8_t priority;
        uint8_t data_len;
        uint8_t data[223];
        std::chrono::steady_clock::time_point timestamp;
    };
    
    // Send a switch control command - now uses library Set function directly
    bool SendSwitchCommand(uint8_t switch_num, uint8_t command, uint8_t dest = 0x12) {
        // Convert command constants to library format
        tN2kCZoneSwitchCommand libCommand;
        switch (command) {
            case CZone::SWITCH_CMD_ON: libCommand = N2kCZoneSwitchCmd_On; break;
            case CZone::SWITCH_CMD_OFF: libCommand = N2kCZoneSwitchCmd_Off; break;
            case CZone::SWITCH_CMD_TOGGLE: libCommand = N2kCZoneSwitchCmd_Toggle; break;
            default: 
                std::cerr << "Invalid switch command: " << (int)command << std::endl;
                return false;
        }
        
        // Create message using library Set function - no duplication!
        tN2kMsg N2kMsg;
        SetN2kCZoneSwitchControlMessage(N2kMsg, switch_num, libCommand, dest, 0x03);
        
        // Send via NMEA2000 transport
        bool result = NMEA2000.SendMsg(N2kMsg);
        
        if (result) {
            // Debug: show what we sent
            std::cout << "Sent CZONE message: PGN " << N2kMsg.PGN 
                      << " from 0x" << std::hex << (int)N2kMsg.Source 
                      << " to 0x" << (int)N2kMsg.Destination 
                      << " (" << (int)N2kMsg.DataLen << " bytes)" << std::dec << std::endl;
        }
        
        return result;
    }
    
    CZONESwitchDecoder(const char* device) : fd(-1) {
        fd = open(device, O_RDWR | O_NOCTTY);
        if (fd < 0) {
            std::cerr << "Failed to open " << device << ": " << strerror(errno) << std::endl;
            return;
        }
        
        struct termios tty;
        if (tcgetattr(fd, &tty) != 0) {
            std::cerr << "Failed to get serial attributes" << std::endl;
            close(fd);
            fd = -1;
            return;
        }
        
        cfsetospeed(&tty, B115200);
        cfsetispeed(&tty, B115200);
        
        tty.c_cflag &= ~PARENB;
        tty.c_cflag &= ~CSTOPB;
        tty.c_cflag &= ~CSIZE;
        tty.c_cflag |= CS8;
        tty.c_cflag &= ~CRTSCTS;
        tty.c_cflag |= CREAD | CLOCAL;
        
        tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
        tty.c_iflag &= ~(IXON | IXOFF | IXANY | IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL);
        tty.c_oflag &= ~OPOST;
        
        tty.c_cc[VMIN] = 0;
        tty.c_cc[VTIME] = 1;
        
        if (tcsetattr(fd, TCSANOW, &tty) != 0) {
            std::cerr << "Failed to set serial attributes" << std::endl;
            close(fd);
            fd = -1;
        }
    }
    
    ~CZONESwitchDecoder() {
        if (fd >= 0) close(fd);
    }
    
    bool IsOpen() const { return fd >= 0; }
    
    bool ReadMessage(N2KMessage& msg, bool non_blocking = false) {
        if (fd < 0) return false;
        
        // Allow caller to check running flag
        if (!g_running) return false;
        
        // Use poll for timeout-based reading
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        
        uint8_t byte;
        // Keep trying to read with timeouts
        while (g_running) {
            // Poll with 100ms timeout
            int ret = poll(&pfd, 1, 100);
            
            if (ret > 0 && (pfd.revents & POLLIN)) {
                // Data available, read it
                while (read(fd, &byte, 1) == 1) {
                    if (ProcessByte(byte, msg)) {
                        return true;
                    }
                    // Check if more data available
                    ret = poll(&pfd, 1, 0);  // No timeout, just check
                    if (ret <= 0 || !(pfd.revents & POLLIN)) {
                        break;  // No more data immediately available
                    }
                }
            } else if (ret < 0) {
                // Error in poll (possibly interrupted by signal)
                if (errno == EINTR) {
                    continue;  // Signal interrupted, check g_running and continue
                }
                return false;
            }
            // ret == 0 means timeout, loop continues if g_running is true
            
            // In non-blocking mode, return immediately after first poll
            if (non_blocking) {
                return false;
            }
        }
        return false;
    }
    
    void PrintBinaryPayload(const N2KMessage& msg) {
        if (msg.pgn != 65282 && msg.pgn != 65283) return;  // Only CZONE proprietary
        
        std::cout << "Dev 0x" << std::hex << std::setw(2) << std::setfill('0') << (int)msg.source 
                  << " PGN " << std::dec << msg.pgn << ": ";
        
        // Show each byte in binary
        for (int i = 0; i < msg.data_len && i < 17; i++) {
            for (int bit = 7; bit >= 0; bit--) {
                std::cout << ((msg.data[i] >> bit) & 1);
            }
            if (i < msg.data_len - 1) std::cout << " ";
        }
        std::cout << std::endl;
    }
    
    void CaptureDeviceMessages(int device, int count, bool binary_mode = false, int pgn_filter = -1, int msg_type_filter = -1) {
        int captured = 0;
        N2KMessage msg;
        
        if (device >= 0) {
            std::cout << "Capturing " << count << " messages from device 0x" 
                      << std::hex << device << std::dec;
        } else {
            std::cout << "Capturing " << count << " messages from all CZONE devices";
        }
        
        if (pgn_filter >= 0) {
            std::cout << " (PGN " << pgn_filter << ")";
        }
        if (msg_type_filter >= 0) {
            std::cout << " (MSG type 0x" << std::hex << msg_type_filter << std::dec << ")";
        }
        std::cout << "..." << std::endl;
        
        while (captured < count && g_running) {
            if (ReadMessage(msg)) {
                // Apply PGN filter first (broader filter)
                bool pgn_match = (pgn_filter < 0) || (msg.pgn == pgn_filter);
                if (!pgn_match) continue;
                
                // Check if it's a CZONE message for device and message type filtering
                if ((msg.pgn == CZone::PGN_SWITCH_STATUS || msg.pgn == CZone::PGN_SWITCH_CONTROL)) {
                    // Apply device filter
                    bool device_match = (device < 0) || (msg.source == device);
                    if (!device_match) continue;
                    
                    // Apply message type filter if specified
                    bool msg_type_match = true;
                    if (msg_type_filter >= 0) {
                        CZoneParsedMessage parsed;
                        if (ParseCZoneTypedMessage(msg.data, msg.data_len, msg.source, msg.pgn, parsed)) {
                            msg_type_match = (parsed.MessageType == msg_type_filter);
                        } else {
                            msg_type_match = false; // Can't parse = doesn't match
                        }
                    }
                    if (!msg_type_match) continue;
                    
                    // Message passed all filters
                    if (binary_mode) {
                        PrintBinaryPayload(msg);
                    } else {
                        std::cout << "[" << captured + 1 << "] ";
                        PrintMessageCompact(msg);
                    }
                    captured++;
                }
            } else if (!g_running) {
                // ReadMessage returned false due to signal interruption
                break;
            }
        }
        
        if (!g_running && captured < count) {
            std::cout << "\nCapture interrupted by signal (got " << captured << "/" << count << " messages)" << std::endl;
        }
    }
    
    void PrintMessageCompact(const N2KMessage& msg) {
        std::cout << "PGN " << msg.pgn << " from 0x" << std::hex << (int)msg.source << std::dec << ": ";
        for (int i = 0; i < msg.data_len && i < 17; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)msg.data[i] << " ";
        }
        std::cout << std::dec << std::endl;
    }
    
    void AnalyzeMessage(const N2KMessage& msg, bool debug_mode = false) {
        static int message_count = 0;
        message_count++;
        
        if (debug_mode) {
            // Show every single message in debug mode
            std::cout << "[" << message_count << "] PGN:" << msg.pgn 
                      << " (0x" << std::hex << msg.pgn << std::dec << ")"
                      << " Src:0x" << std::hex << (int)msg.source << std::dec
                      << " Dst:0x" << std::hex << (int)msg.destination << std::dec
                      << " Len:" << (int)msg.data_len;
            
            // Show ALL data bytes
            std::cout << " Data:";
            for (int i = 0; i < (int)msg.data_len; i++) {
                std::cout << " " << std::hex << std::setfill('0') << std::setw(2) << (int)msg.data[i];
            }
            std::cout << std::dec;
            
            // Check filtering status
            bool would_be_filtered = IsKnownNonSwitchPGN(msg.pgn);
            if (would_be_filtered) {
                std::cout << " [FILTERED]";
            } else {
                std::cout << " [PASSES FILTER]";
                
                // Check if CZONE address
                if (msg.source >= 0x40 && msg.source <= 0x4F) {
                    std::cout << " ⭐ CZONE SRC!";
                }
                if (msg.destination >= 0x40 && msg.destination <= 0x4F) {
                    std::cout << " ⭐ CZONE DST!";
                }
            }
            std::cout << std::endl;
            
            // Decode CZONE switch change requests
            if (msg.pgn == 65280 && msg.data_len >= 7) {
                std::cout << "    🎯 CZONE SWITCH CHANGE REQUEST!" << std::endl;
                std::cout << "       Byte 2 (switch index): 0x" << std::hex << (int)msg.data[2] << std::dec;
                uint8_t switchIdx = msg.data[2];
                if (switchIdx >= 5 && switchIdx <= 0x0C) {
                    int switchNum = switchIdx - 4;  // Convert to 1-8
                    std::cout << " = Switch " << switchNum;
                    if (switchNum <= 4) std::cout << " (Bank 1)";
                    else std::cout << " (Bank 2)";
                }
                std::cout << std::endl;
                std::cout << "       Byte 6 (action): 0x" << std::hex << (int)msg.data[6] << std::dec;
                switch(msg.data[6]) {
                    case 0xF1: std::cout << " = SET ON"; break;
                    case 0xF2: std::cout << " = TOGGLE"; break;
                    case 0xF4: std::cout << " = SET OFF"; break;
                    case 0x40: std::cout << " = END OF CHANGE"; break;
                    default: std::cout << " = UNKNOWN"; break;
                }
                std::cout << std::endl;
            }
            
            // Decode CZONE acknowledgments
            if (msg.pgn == 65283) {
                std::cout << "    📡 CZONE ACK from device 0x" << std::hex << (int)msg.source << std::dec << std::endl;
            }
            
            return; // In debug mode, just show all messages
        }
        
        // Normal mode - filter and process
        if (IsKnownNonSwitchPGN(msg.pgn)) {
            return; // Skip weather, navigation, engine data, etc.
        }
        
        // Focus on potential CZONE messages
        if (IsPotentialCZONEMessage(msg)) {
            std::vector<uint8_t> current_data(msg.data, msg.data + msg.data_len);
            std::vector<uint8_t>& last_data = last_data_by_source[msg.source];
            
            if (last_data != current_data) {
                PrintCZONEChange(msg, last_data, current_data);
                last_data = current_data;
            }
        }
    }
    
    struct MessageCapture {
        uint8_t device;
        uint32_t timestamp;  // 32-bit LE timestamp from message
        uint8_t payload[9];  // Full 9-byte payload
    };
    
    std::vector<MessageCapture> captures;
    int captureCount = 0;
    
    void TestCZoneParser(const N2KMessage& msg) {
        if (msg.pgn != 65282) return;
        
        CZoneRawMessage czoneMsg;
        if (ParseCZoneMessage(msg.data, msg.data_len, czoneMsg)) {
            // Add to protocol analyzer for systematic analysis
            analyzer.AddMessage(czoneMsg);
            // Only show DeviceType=0x9 devices (switch banks)
            if (czoneMsg.DeviceType != 0x09) return;
            
            // Capture messages from switch bank devices (expand for analysis)
            if (msg.source == 0x46 || msg.source == 0x3 || msg.source == 0x13 || msg.source == 0x12) {
                MessageCapture capture;
                capture.device = msg.source;
                capture.timestamp = czoneMsg.Timestamp;
                for (int i = 0; i < 9; i++) {
                    capture.payload[i] = czoneMsg.Payload[i];
                }
                captures.push_back(capture);
                captureCount++;
                
                // Show detailed debug analysis for devices 0x46 and 0x3
                if (captureCount <= 20) {
                    std::cout << "📊 Device 0x" << std::hex << (int)msg.source << std::dec << std::endl;
                    
                    // Display properly parsed timestamp
                    std::cout << "  🔍 TIMESTAMP DEBUG:" << std::endl;
                    std::cout << "     32-bit LE Timestamp: " << czoneMsg.Timestamp 
                              << " (0x" << std::hex << czoneMsg.Timestamp << std::dec << ")" << std::endl;
                    
                    // Convert to human-readable time (10Hz / 100ms ticks)
                    double seconds = czoneMsg.Timestamp * 0.1;  // 100ms per tick
                    double minutes = seconds / 60.0;
                    double hours = minutes / 60.0;
                    double days = hours / 24.0;
                    
                    std::cout << "     Network uptime: " << seconds << " seconds" << std::endl;
                    std::cout << "                   = " << minutes << " minutes" << std::endl;
                    std::cout << "                   = " << hours << " hours" << std::endl;
                    std::cout << "                   = " << days << " days" << std::endl;
                    std::cout << "     Resolution: 10Hz (100ms per tick)" << std::endl;
                    
                    // Compare with previous timestamp if we have captures
                    if (captures.size() > 1) {
                        auto& prev = captures[captures.size()-2];
                        if (prev.device == msg.source) {
                            uint32_t time_diff = czoneMsg.Timestamp - prev.timestamp;
                            std::cout << "     Time diff from prev: " << time_diff 
                                      << " ticks (" << (time_diff * 100) << "ms)" << std::endl;
                        }
                    }
                    
                    // Debug payload boundary
                    std::cout << "  🔍 PAYLOAD BOUNDARY DEBUG:" << std::endl;
                    std::cout << "     CZONE_DATA[0-7]: ";
                    for (int i = 0; i < 8; i++) {
                        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)msg.data[i] << " ";
                    }
                    std::cout << std::dec << std::endl;
                    
                    std::cout << "     CZONE_DATA[8-15]: ";
                    for (int i = 8; i < 16; i++) {
                        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)msg.data[i] << " ";
                    }
                    std::cout << std::dec << std::endl;
                    
                    std::cout << "     CZONE_DATA[16]: 0x" << std::hex << (int)msg.data[16] << std::dec << std::endl;
                    
                    // Alternative interpretation (if CZONE_DATA[8] belongs to header)
                    std::cout << "     Alt CZONE_DATA[0-8]: ";
                    for (int i = 0; i < 9; i++) {
                        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)msg.data[i] << " ";
                    }
                    std::cout << std::dec << std::endl;
                    
                    std::cout << "     Alt CZONE_DATA[9-16]: ";
                    for (int i = 9; i < 17; i++) {
                        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)msg.data[i] << " ";
                    }
                    std::cout << std::dec << std::endl;
                    
                    // Find the actual checksum field
                    std::cout << "  🔍 FIND ACTUAL CHECKSUM FIELD:" << std::endl;
                    
                    // Test comprehensive checksum possibilities including byte 16 as payload
                    std::cout << "     Testing multiple payload ranges:" << std::endl;
                    
                    // Test payload[8-15] vs all bytes
                    uint8_t sum_8_15 = CalculateSimpleChecksum(&msg.data[8], 8);
                    uint8_t xor_8_15 = CalculateXORChecksum(&msg.data[8], 8);
                    
                    // Test payload[8-16] (including byte 16 as payload!)
                    uint8_t sum_8_16 = CalculateSimpleChecksum(&msg.data[8], 9);
                    uint8_t xor_8_16 = CalculateXORChecksum(&msg.data[8], 9);
                    
                    // Test all[0-15] vs byte 16
                    uint8_t sum_0_15 = CalculateSimpleChecksum(msg.data, 16);
                    uint8_t xor_0_15 = CalculateXORChecksum(msg.data, 16);
                    
                    // Test header[0-7] checksum
                    uint8_t sum_0_7 = CalculateSimpleChecksum(msg.data, 8);
                    uint8_t xor_0_7 = CalculateXORChecksum(msg.data, 8);
                    
                    // SYSTEMATIC CHECKSUM HYPOTHESIS TESTING
                    // Message structure: Header[0-8] + Payload[9-16] (8 bytes each)
                    
                    static std::map<uint8_t, std::map<std::string, std::pair<int, int>>> device_checksum_stats;
                    
                    if (device_checksum_stats.find(msg.source) == device_checksum_stats.end()) {
                        device_checksum_stats[msg.source] = std::map<std::string, std::pair<int, int>>();
                    }
                    
                    // Calculate various checksum ranges
                    uint8_t sum_payload = CalculateSimpleChecksum(&msg.data[9], 8);    // Payload[9-15]
                    uint8_t xor_payload = CalculateXORChecksum(&msg.data[9], 8);       // Payload[9-15] 
                    uint8_t sum_header = CalculateSimpleChecksum(&msg.data[0], 8);     // Header[0-7]
                    uint8_t xor_header = CalculateXORChecksum(&msg.data[0], 8);        // Header[0-7]
                    uint8_t sum_all = CalculateSimpleChecksum(&msg.data[0], 16);       // All[0-15]
                    uint8_t xor_all = CalculateXORChecksum(&msg.data[0], 16);          // All[0-15]
                    
                    // HYPOTHESIS TESTS
                    struct ChecksumHypothesis {
                        int byte_pos;
                        uint8_t calculated;
                        std::string name;
                    };
                    
                    std::vector<ChecksumHypothesis> hypotheses = {
                        // Header checksum hypotheses
                        {5, sum_payload, "H5_SUM_PAYLOAD"},      // Byte 5 = checksum of payload  
                        {6, sum_payload, "H6_SUM_PAYLOAD"},      // Byte 6 = checksum of payload
                        {7, sum_payload, "H7_SUM_PAYLOAD"},      // Byte 7 = checksum of payload
                        {8, sum_payload, "H8_SUM_PAYLOAD"},      // Byte 8 = checksum of payload
                        
                        // End-of-message checksum hypotheses  
                        {16, sum_payload, "END_SUM_PAYLOAD"},    // Byte 16 = checksum of payload
                        {16, xor_payload, "END_XOR_PAYLOAD"},    // Byte 16 = XOR of payload
                        {16, sum_header, "END_SUM_HEADER"},      // Byte 16 = checksum of header
                        {16, xor_header, "END_XOR_HEADER"},      // Byte 16 = XOR of header
                        {16, sum_all, "END_SUM_ALL"},            // Byte 16 = checksum of all
                        {16, xor_all, "END_XOR_ALL"},            // Byte 16 = XOR of all
                    };
                    
                    // Test each hypothesis
                    for (const auto& hyp : hypotheses) {
                        if (device_checksum_stats[msg.source].find(hyp.name) == device_checksum_stats[msg.source].end()) {
                            device_checksum_stats[msg.source][hyp.name] = {0, 0};
                        }
                        
                        device_checksum_stats[msg.source][hyp.name].second++;  // total count
                        
                        if (msg.data[hyp.byte_pos] == hyp.calculated) {
                            device_checksum_stats[msg.source][hyp.name].first++;  // match count
                            std::cout << "     🎯 " << hyp.name << " MATCH! (0x" << std::hex << (int)hyp.calculated << std::dec << ")" << std::endl;
                        }
                    }
                    
                    // Show hypothesis validation results
                    static int report_interval = 0;
                    report_interval++;
                    if (report_interval % 5 == 0) {  // Report every 5 messages
                        std::cout << "     📊 HYPOTHESIS VALIDATION for 0x" << std::hex << (int)msg.source << std::dec << ":" << std::endl;
                        for (const auto& stat : device_checksum_stats[msg.source]) {
                            const std::string& name = stat.first;
                            int matches = stat.second.first;
                            int total = stat.second.second;
                            double consistency = (double)matches / total * 100;
                            
                            if (consistency >= 90) {
                                std::cout << "        ✅ " << name << ": " << matches << "/" << total << " (" << (int)consistency << "% - CONFIRMED)" << std::endl;
                            } else if (consistency >= 70) {
                                std::cout << "        ⚠️  " << name << ": " << matches << "/" << total << " (" << (int)consistency << "% - LIKELY)" << std::endl;
                            } else if (matches > 0) {
                                std::cout << "        ❓ " << name << ": " << matches << "/" << total << " (" << (int)consistency << "% - DOUBTFUL)" << std::endl;
                            }
                        }
                    }
                    
                    // Show switch state consistency check
                    std::cout << "  🔍 SWITCH STATE CONSISTENCY:" << std::endl;
                    std::cout << "     Byte[16] value: 0x" << std::hex << (int)msg.data[16] << std::dec 
                              << " (switches haven't changed - should be constant!)" << std::endl;
                    
                    // Enhanced checksum validation tests
                    std::cout << "  🔍 CHECKSUM VS PAYLOAD CORRELATION:" << std::endl;
                    
                    // Compare with previous message to see if checksum changes when payload changes
                    if (captures.size() > 1) {
                        auto& prev = captures[captures.size()-2];
                        if (prev.device == msg.source) {
                            bool payload_changed = false;
                            for (int i = 0; i < 8; i++) {
                                if (capture.payload[i] != prev.payload[i]) {
                                    payload_changed = true;
                                    break;
                                }
                            }
                            // Last byte of payload might be special
                            bool last_byte_changed = (capture.payload[8] != prev.payload[8]);
                            
                            std::cout << "     Payload changed: " << (payload_changed ? "YES" : "NO") << std::endl;
                            std::cout << "     Last byte changed: " << (last_byte_changed ? "YES" : "NO") << std::endl;
                        }
                    }
                    
                    // Extended range checksum tests
                    std::cout << "  🔍 EXTENDED CHECKSUM TESTS:" << std::endl;
                    
                    // Test with neighboring bytes
                    uint8_t sum_7_15 = CalculateSimpleChecksum(&msg.data[7], 9);  // Include byte 7
                    std::cout << "     Sum[7-15]: 0x" << std::hex << (int)sum_7_15 << std::dec;
                    if (sum_7_15 == msg.data[16]) std::cout << " ✅ MATCH!";
                    std::cout << std::endl;
                    
                    uint8_t xor_7_15 = CalculateXORChecksum(&msg.data[7], 9);
                    std::cout << "     XOR[7-15]: 0x" << std::hex << (int)xor_7_15 << std::dec;
                    if (xor_7_15 == msg.data[16]) std::cout << " ✅ MATCH!";
                    std::cout << std::endl;
                    
                    // Test without first bytes
                    uint8_t sum_9_15 = CalculateSimpleChecksum(&msg.data[9], 7);
                    std::cout << "     Sum[9-15]: 0x" << std::hex << (int)sum_9_15 << std::dec;
                    if (sum_9_15 == msg.data[16]) std::cout << " ✅ MATCH!";
                    std::cout << std::endl;
                    
                    uint8_t xor_9_15 = CalculateXORChecksum(&msg.data[9], 7);
                    std::cout << "     XOR[9-15]: 0x" << std::hex << (int)xor_9_15 << std::dec;
                    if (xor_9_15 == msg.data[16]) std::cout << " ✅ MATCH!";
                    std::cout << std::endl;
                    
                    std::cout << std::endl;
                    
                    // Every 5 captures, show sequence continuity analysis
                    if (captureCount % 5 == 0) {
                        CheckSequenceContinuity();
                    }
                }
            }
        }
    }
    
    void CheckSequenceContinuity() {
        std::cout << "\n🔍 SEQUENCE CONTINUITY CHECK:" << std::endl;
        
        // Group by device
        std::map<uint8_t, std::vector<MessageCapture*>> deviceGroups;
        int startIdx = std::max(0, (int)captures.size() - 12);
        
        for (int i = startIdx; i < captures.size(); i++) {
            deviceGroups[captures[i].device].push_back(&captures[i]);
        }
        
        for (auto& group : deviceGroups) {
            uint8_t device = group.first;
            auto& msgs = group.second;
            
            if (msgs.size() < 2) continue;
            
            // Sort by sequence number
            std::sort(msgs.begin(), msgs.end(), [](MessageCapture* a, MessageCapture* b) {
                return a->timestamp < b->timestamp;
            });
            
            std::cout << "Device 0x" << std::hex << (int)device << std::dec << " timestamps: ";
            
            // Check timestamp continuity
            bool isRegular = true;
            for (int i = 0; i < msgs.size(); i++) {
                std::cout << msgs[i]->timestamp;
                if (i < msgs.size() - 1) {
                    uint32_t gap = msgs[i+1]->timestamp - msgs[i]->timestamp;
                    std::cout << " +" << gap << " ";
                    if (gap > 100 || gap < 1) {  // More than 10 seconds or negative
                        isRegular = false;
                    }
                }
            }
            
            std::cout << " [" << (isRegular ? "REGULAR" : "IRREGULAR") << "]" << std::endl;
            
            // Show 3 example full payloads
            if (msgs.size() >= 3) {
                std::cout << "  Examples (first 3):" << std::endl;
                for (int i = 0; i < 3; i++) {
                    std::cout << "    Timestamp " << msgs[i]->timestamp << ": ";
                    for (int byte = 0; byte < 8; byte++) {
                        for (int bit = 7; bit >= 0; bit--) {
                            std::cout << ((msgs[i]->payload[byte] >> bit) & 1);
                        }
                        std::cout << " ";
                    }
                    std::cout << "| Last byte: 0x" << std::hex << std::setfill('0') << std::setw(2) 
                              << (int)msgs[i]->payload[8] << std::dec << std::endl;
                }
            }
        }
        std::cout << std::endl;
    }
    
    void ShowSequenceAnalysis() {
        std::cout << "\n🔍 SEQUENCE ANALYSIS (Last 10 captures):" << std::endl;
        
        // Group by device
        std::map<uint8_t, std::vector<MessageCapture*>> deviceGroups;
        int startIdx = std::max(0, (int)captures.size() - 10);
        
        for (int i = startIdx; i < captures.size(); i++) {
            deviceGroups[captures[i].device].push_back(&captures[i]);
        }
        
        for (auto& group : deviceGroups) {
            uint8_t device = group.first;
            auto& msgs = group.second;
            
            if (msgs.size() < 2) continue;
            
            std::cout << "Device 0x" << std::hex << (int)device << std::dec << ":" << std::endl;
            
            // Find sequential messages
            std::sort(msgs.begin(), msgs.end(), [](MessageCapture* a, MessageCapture* b) {
                return a->timestamp < b->timestamp;
            });
            
            for (int i = 0; i < std::min(3, (int)msgs.size()); i++) {
                std::cout << "  Timestamp " << msgs[i]->timestamp << ": ";
                
                // Show payload differences
                for (int byte = 0; byte < 8; byte++) {
                    bool differs = false;
                    if (i > 0) {
                        differs = (msgs[i]->payload[byte] != msgs[i-1]->payload[byte]);
                    }
                    
                    if (differs) std::cout << ">";
                    else std::cout << " ";
                    
                    for (int bit = 7; bit >= 0; bit--) {
                        std::cout << ((msgs[i]->payload[byte] >> bit) & 1);
                    }
                    
                    if (differs) std::cout << "<";
                    else std::cout << " ";
                    
                    if (byte < 7) std::cout << " ";
                }
                
                // Show last byte (might be checksum or status)
                bool lastDiffers = (i > 0) && (msgs[i]->payload[8] != msgs[i-1]->payload[8]);
                if (lastDiffers) std::cout << " >";
                else std::cout << "  ";
                
                std::cout << "0x" << std::hex << std::setfill('0') << std::setw(2) 
                          << (int)msgs[i]->payload[8] << std::dec;
                
                if (lastDiffers) std::cout << "<";
                std::cout << std::endl;
            }
        }
        std::cout << std::endl;
    }
    
    bool IsKnownNonSwitchPGN(uint32_t pgn) {
        // NOTE: This function was originally used to filter out "noise" PGNs
        // to focus on CZONE traffic. To allow analysis of ALL PGNs, this function
        // now returns false for all PGNs, effectively disabling the filter.
        // The original filtering logic is preserved in comments for reference.
        
        /* ORIGINAL FILTERING LOGIC (now disabled):
        // Weather station PGNs
        if (pgn == 130323) return true;  // Meteorological Station Data
        if (pgn == 130306) return true;  // Wind Data
        if (pgn == 130310) return true;  // Environmental Parameters
        if (pgn == 130311) return true;  // Environmental Parameters
        if (pgn == 130312) return true;  // Temperature
        if (pgn == 130313) return true;  // Humidity  
        if (pgn == 130314) return true;  // Actual Pressure
        if (pgn == 130316) return true;  // Temperature Extended Range
        
        // Navigation/GNSS PGNs
        if (pgn == 129029) return true;  // GNSS Position Data
        if (pgn == 129025) return true;  // Position Update
        if (pgn == 129026) return true;  // COG & SOG Rapid Update
        if (pgn == 129033) return true;  // Local Time Offset
        if (pgn == 129539) return true;  // GNSS DOPs
        if (pgn == 129540) return true;  // GNSS Sats in View
        
        // Engine/Power PGNs
        if (pgn == 127488) return true;  // Engine Parameters Rapid
        if (pgn == 127489) return true;  // Engine Parameters Dynamic
        if (pgn == 127505) return true;  // Fluid Level
        if (pgn == 127506) return true;  // DC Detailed Status
        if (pgn == 127508) return true;  // Battery Status
        if (pgn == 127513) return true;  // Battery Configuration
        
        // Attitude/Heading PGNs
        if (pgn == 127250) return true;  // Vessel Heading
        if (pgn == 127251) return true;  // Rate of Turn
        if (pgn == 127257) return true;  // Attitude
        if (pgn == 127258) return true;  // Magnetic Variation
        
        // System PGNs
        if (pgn == 126992) return true;  // System Time
        if (pgn == 126993) return true;  // Heartbeat
        if (pgn == 126996) return true;  // Product Information
        if (pgn == 126998) return true;  // Configuration Information
        if (pgn == 60928) return true;   // ISO Address Claim
        if (pgn == 59904) return true;   // ISO Request
        if (pgn == 59392) return true;   // ISO Acknowledgment
        */
        
        return false; // Allow ALL PGNs through (filtering disabled)
    }
    
    bool IsPotentialCZONEMessage(const N2KMessage& msg) {
        // CZONE address range
        if (msg.source >= 0x40 && msg.source <= 0x4F) return true;
        
        // Standard switch bank PGNs
        if (msg.pgn == 127501) return true;  // Binary Status Report
        if (msg.pgn == 127502) return true;  // Switch Bank Control
        
        // Proprietary PGN range
        if (msg.pgn >= 65280 && msg.pgn <= 65535) return true;
        
        // Unknown PGNs that passed the exclusion filter
        return true;
    }
    
private:
    bool ProcessByte(uint8_t byte, N2KMessage& msg) {
        switch (state) {
        case WAIT_DLE:
            if (byte == DLE) {
                state = WAIT_STX;
            }
            break;
            
        case WAIT_STX:
            if (byte == STX) {
                state = READ_MESSAGE;
                message_buffer.clear();
            } else {
                state = WAIT_DLE;
            }
            break;
            
        case READ_MESSAGE:
            if (byte == DLE) {
                state = ESCAPE_NEXT;
            } else {
                message_buffer.push_back(byte);
            }
            break;
            
        case ESCAPE_NEXT:
            if (byte == ETX) {
                if (DecodeMessage(msg, false)) {  // No debug output in normal mode
                    state = WAIT_DLE;
                    return true;
                }
                state = WAIT_DLE;
            } else if (byte == DLE) {
                message_buffer.push_back(DLE);
                state = READ_MESSAGE;
            } else {
                state = WAIT_DLE;
            }
            break;
        }
        return false;
    }
    
    bool ParseCZONEMessage(const std::vector<uint8_t>& buffer, N2KMessage& msg) {
        // Validate minimum size
        if (buffer.size() < CZone::MIN_MESSAGE_SIZE) {
            return false;
        }
        
        // Check CZONE markers
        if (buffer[CZone::OFFSET_MARKER_1] != CZone::PROTOCOL_MARKER_1 ||
            buffer[CZone::OFFSET_MARKER_2] != CZone::PROTOCOL_MARKER_2) {
            return false;
        }
        
        // Extract header fields
        uint8_t pgn_offset = buffer[CZone::OFFSET_PGN_OFFSET];
        uint8_t source_id = buffer[CZone::OFFSET_SOURCE];
        uint8_t dest_id = buffer[CZone::OFFSET_DESTINATION];
        
        // Build message
        msg.timestamp = std::chrono::steady_clock::now();
        msg.priority = 6;  // Default priority for CZONE
        msg.pgn = CZone::PGN_BASE + pgn_offset;
        msg.source = source_id;
        msg.destination = dest_id;
        
        // Copy data payload
        msg.data_len = buffer.size() - CZone::HEADER_SIZE;
        if (msg.data_len > 223) msg.data_len = 223;  // Cap at NMEA2000 limit
        memcpy(msg.data, &buffer[CZone::OFFSET_DATA_START], msg.data_len);
        
        return true;
    }
    
    bool DecodeMessage(N2KMessage& msg, bool debug_decode = false) {
        static int decode_attempts = 0;
        decode_attempts++;
        
        if (debug_decode && decode_attempts % 100 == 1) {
            std::cout << "🔍 [DecodeAttempt " << decode_attempts << "] Buffer size:" << message_buffer.size();
            if (message_buffer.size() > 0) {
                std::cout << " First bytes:";
                for (int i = 0; i < std::min(8, (int)message_buffer.size()); i++) {
                    std::cout << " " << std::hex << std::setfill('0') << std::setw(2) << (int)message_buffer[i];
                }
                std::cout << std::dec;
            }
            std::cout << std::endl;
        }
        
        if (message_buffer.size() < 5) {
            if (debug_decode && decode_attempts % 100 == 1) {
                std::cout << "    → REJECTED: Too short (need 5, got " << message_buffer.size() << ")" << std::endl;
            }
            return false;
        }
        
        // Try to parse as CZONE message
        if (ParseCZONEMessage(message_buffer, msg)) {
            if (debug_decode && decode_attempts % 100 == 1) {
                std::cout << "    → CZONE PROPRIETARY FORMAT DETECTED!" << std::endl;
                std::cout << "       Raw bytes: " << std::hex;
                for (int i = 0; i < std::min(8, (int)message_buffer.size()); i++) {
                    std::cout << " " << std::setfill('0') << std::setw(2) << (int)message_buffer[i];
                }
                std::cout << std::dec << std::endl;
                std::cout << "       Parsed: PGN=" << msg.pgn 
                          << " Src=0x" << std::hex << (int)msg.source
                          << " Dst=0x" << (int)msg.destination << std::dec 
                          << " Len=" << (int)msg.data_len << std::endl;
            }
            return true;
        }
        
        // Standard NMEA2000 format
        if (message_buffer.size() < 11) {
            if (debug_decode && decode_attempts % 100 == 1) {
                std::cout << "    → REJECTED: Too short for NMEA2000 (need 11, got " << message_buffer.size() << ")" << std::endl;
            }
            return false;
        }
        
        if (message_buffer[0] != 0x93) {
            if (debug_decode && decode_attempts % 100 == 1) {
                std::cout << "    → REJECTED: Wrong message type (got 0x" << std::hex << (int)message_buffer[0] << std::dec << ", need 0x93)" << std::endl;
            }
            return false;
        }
        
        msg.timestamp = std::chrono::steady_clock::now();
        msg.priority = message_buffer[2];
        msg.pgn = message_buffer[3] | (message_buffer[4] << 8) | (message_buffer[5] << 16);
        msg.destination = message_buffer[6];
        msg.source = message_buffer[7];
        msg.data_len = message_buffer[10];
        
        if (msg.data_len > 223) {
            if (debug_decode && decode_attempts % 100 == 1) {
                std::cout << "    → REJECTED: Data length too big (" << (int)msg.data_len << ")" << std::endl;
            }
            return false;
        }
        
        if (message_buffer.size() < 11 + msg.data_len) {
            if (debug_decode && decode_attempts % 100 == 1) {
                std::cout << "    → ADJUSTING: Buffer shorter than expected, using available data (" << message_buffer.size() << " bytes)" << std::endl;
            }
            // Use whatever data we have available
            msg.data_len = message_buffer.size() - 11;
            if (msg.data_len < 0) msg.data_len = 0;
        }
        
        memcpy(msg.data, &message_buffer[11], msg.data_len);
        
        if (debug_decode && decode_attempts % 100 == 1) {
            std::cout << "    → ACCEPTED NMEA2000: PGN=" << msg.pgn << " Src=0x" << std::hex << (int)msg.source << std::dec << std::endl;
        }
        
        return true;
    }
    
    void PrintCZONEChange(const N2KMessage& msg, const std::vector<uint8_t>& old_data, const std::vector<uint8_t>& new_data, bool verbose = true) {
        auto now = std::chrono::steady_clock::now();
        static auto start_time = now;
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
        
        if (verbose) {
            std::cout << "[" << elapsed << "ms] Change: ";
        }
        std::cout << "PGN " << msg.pgn << " (0x" << std::hex << msg.pgn << std::dec << ") from 0x" << std::hex << (int)msg.source << std::dec << std::endl;
        
        if (!verbose) return;
        
        // Show the differences byte by byte
        for (int i = 0; i < std::max(old_data.size(), new_data.size()); i++) {
            uint8_t old_val = (i < old_data.size()) ? old_data[i] : 0x00;
            uint8_t new_val = (i < new_data.size()) ? new_data[i] : 0x00;
            
            if (old_val != new_val) {
                std::cout << "  [" << std::setw(2) << i << "]: 0x" 
                          << std::hex << std::setfill('0') << std::setw(2) << (int)old_val
                          << " -> 0x" << std::setw(2) << (int)new_val << std::dec
                          << " (";
                
                // Show binary representation inline
                for (int bit = 7; bit >= 0; bit--) {
                    std::cout << ((old_val >> bit) & 1);
                }
                std::cout << "->";
                for (int bit = 7; bit >= 0; bit--) {
                    std::cout << ((new_val >> bit) & 1);
                }
                std::cout << ")" << std::endl;
            }
        }
    }
    
    std::string SwitchStateToString(uint8_t state) {
        switch (state) {
            case 0: return "OFF";
            case 1: return "ON";
            case 2: return "ERR";
            case 3: return "N/A";
            default: return "?";
        }
    }
};

void ShowUsage(const char* program_name) {
    std::cout << "CZONE Protocol Reverse Engineering Tool" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Usage: " << program_name << " [mode] [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Modes:" << std::endl;
    std::cout << "  --capture                   Capture messages (default: all devices)" << std::endl;
    std::cout << "  --binary                    Show messages in binary format" << std::endl;
    std::cout << "  --monitor                   Monitor for switch state changes" << std::endl;
    std::cout << "  --analyze                   Deep protocol analysis mode" << std::endl;
    std::cout << "  --raw                       Raw message capture, no filtering" << std::endl;
    std::cout << "  --decode                    Focus on CZONE message decoding" << std::endl;
    std::cout << "  --diff                      Compare messages to find differences" << std::endl;
    std::cout << "  --types                     Analyze message type distribution" << std::endl;
    std::cout << std::endl;
    std::cout << "Switch Control:" << std::endl;
    std::cout << "  --switch-on <num>           Turn switch on (1-8)" << std::endl;
    std::cout << "  --switch-off <num>          Turn switch off (1-8)" << std::endl;
    std::cout << "  --switch-toggle <num>       Toggle switch (1-8)" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --device <hex>              Specific device to monitor (e.g., 0x12)" << std::endl;
    std::cout << "  --pgn <num>                 Filter by PGN (e.g., 65282, 65283)" << std::endl;
    std::cout << "  --msg-type <hex>            Filter by CZONE message type (0x09, 0x24, 0x23, 0x64)" << std::endl;
    std::cout << "  --count <n>                 Number of messages to capture (default: 5)" << std::endl;
    std::cout << "  --quiet                     Minimal output, data only" << std::endl;
    std::cout << std::endl;
    std::cout << "CZONE Message Types:" << std::endl;
    std::cout << "  0x09  HEARTBEAT       High-frequency status messages" << std::endl;
    std::cout << "  0x24  EXTENDED_DATA   Extended data with 16-bit sequence counter" << std::endl;
    std::cout << "  0x23  UNKNOWN_23      From control panel and device 0x19" << std::endl;
    std::cout << "  0x64  SWITCH_STATE    From physical switch banks (likely contains states)" << std::endl;
    std::cout << std::endl;
    std::cout << "PGN to Message Type Mapping:" << std::endl;
    std::cout << "  PGN 65282  Carries types 0x09, 0x23, 0x24 (0x24 is exclusive to 65282)" << std::endl;
    std::cout << "  PGN 65283  Carries types 0x09, 0x23, 0x64 (0x64 is exclusive to 65283)" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << program_name << " --capture                     # Capture from all devices" << std::endl;
    std::cout << "  " << program_name << " --capture --device 0x12       # Capture from device 0x12" << std::endl;
    std::cout << "  " << program_name << " --capture --pgn 65282         # Capture only PGN 65282 messages" << std::endl;
    std::cout << "  " << program_name << " --capture --msg-type 0x64     # Capture only type 0x64 messages" << std::endl;
    std::cout << "  " << program_name << " --binary --device 0x12 --msg-type 0x24  # Binary view of type 0x24 from device 0x12" << std::endl;
    std::cout << "  " << program_name << " --types --count 100           # Analyze message type distribution" << std::endl;
    std::cout << "  " << program_name << " --switch-on 3                 # Turn switch 3 on" << std::endl;
}

int main(int argc, char* argv[]) {
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    enum Mode {
        MODE_DEFAULT,
        MODE_CAPTURE,
        MODE_BINARY,
        MODE_MONITOR,
        MODE_ANALYZE,
        MODE_RAW,
        MODE_DECODE,
        MODE_DIFF,
        MODE_QUIET,
        MODE_SWITCH_CONTROL
    };
    
    Mode mode = MODE_DEFAULT;
    int target_device = -1;
    int capture_count = 5;
    bool quiet = false;
    int switch_num = -1;
    uint8_t switch_command = 0;
    int switch_dest = 0x12;  // Default to switch bank 1
    int switch_bank = 0;     // Default to bank 0 for standard NMEA2000
    int target_pgn = -1;      // Filter by PGN (-1 = all)
    int target_msg_type = -1; // Filter by CZONE message type (-1 = all)
    
    // Parse command line
    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        
        if (arg == "--help" || arg == "-h") {
            ShowUsage(argv[0]);
            return 0;
        } else if (arg == "--capture") {
            mode = MODE_CAPTURE;
        } else if (arg == "--binary") {
            mode = MODE_BINARY;
        } else if (arg == "--monitor") {
            mode = MODE_MONITOR;
        } else if (arg == "--analyze") {
            mode = MODE_ANALYZE;
        } else if (arg == "--raw") {
            mode = MODE_RAW;
        } else if (arg == "--decode") {
            mode = MODE_DECODE;
        } else if (arg == "--diff") {
            mode = MODE_DIFF;
        } else if (arg == "--quiet") {
            quiet = true;
        } else if (arg == "--device") {
            if (i + 1 < argc) {
                target_device = std::stoi(argv[++i], nullptr, 0);
            } else {
                std::cerr << "Error: --device requires a value" << std::endl;
                return 1;
            }
        } else if (arg == "--count") {
            if (i + 1 < argc) {
                capture_count = std::stoi(argv[++i]);
            } else {
                std::cerr << "Error: --count requires a value" << std::endl;
                return 1;
            }
        } else if (arg == "--debug") {
            // Keep for compatibility
            mode = MODE_RAW;
        } else if (arg == "--switch-on") {
            if (i + 1 < argc) {
                switch_num = std::stoi(argv[++i]);
                switch_command = CZone::SWITCH_CMD_ON;
                mode = MODE_SWITCH_CONTROL;
            } else {
                std::cerr << "Error: --switch-on requires a switch number" << std::endl;
                return 1;
            }
        } else if (arg == "--switch-off") {
            if (i + 1 < argc) {
                switch_num = std::stoi(argv[++i]);
                switch_command = CZone::SWITCH_CMD_OFF;
                mode = MODE_SWITCH_CONTROL;
            } else {
                std::cerr << "Error: --switch-off requires a switch number" << std::endl;
                return 1;
            }
        } else if (arg == "--switch-toggle") {
            if (i + 1 < argc) {
                switch_num = std::stoi(argv[++i]);
                switch_command = CZone::SWITCH_CMD_TOGGLE;
                mode = MODE_SWITCH_CONTROL;
            } else {
                std::cerr << "Error: --switch-toggle requires a switch number" << std::endl;
                return 1;
            }
        } else if (arg == "--switch-dest") {
            if (i + 1 < argc) {
                switch_dest = std::stoi(argv[++i], nullptr, 0);
            } else {
                std::cerr << "Error: --switch-dest requires a device ID" << std::endl;
                return 1;
            }
        } else if (arg == "--bank") {
            if (i + 1 < argc) {
                switch_bank = std::stoi(argv[++i]);
            } else {
                std::cerr << "Error: --bank requires a bank number (0-based)" << std::endl;
                return 1;
            }
        } else if (arg == "--pgn") {
            if (i + 1 < argc) {
                target_pgn = std::stoi(argv[++i], nullptr, 0);
            } else {
                std::cerr << "Error: --pgn requires a PGN value" << std::endl;
                return 1;
            }
        } else if (arg == "--msg-type") {
            if (i + 1 < argc) {
                target_msg_type = std::stoi(argv[++i], nullptr, 0);
            } else {
                std::cerr << "Error: --msg-type requires a message type value" << std::endl;
                return 1;
            }
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            std::cerr << "Use --help for usage information" << std::endl;
            return 1;
        }
    }
    
    if (!quiet) {
        switch (mode) {
            case MODE_CAPTURE:
                std::cout << "CZONE Message Capture Mode" << std::endl;
                if (target_device >= 0) {
                    std::cout << "Target device: 0x" << std::hex << target_device << std::dec << std::endl;
                }
                break;
            case MODE_BINARY:
                std::cout << "Binary Payload Display Mode" << std::endl;
                if (target_device >= 0) {
                    std::cout << "Monitoring device: 0x" << std::hex << target_device << std::dec << std::endl;
                }
                break;
            case MODE_MONITOR:
                std::cout << "Switch State Monitoring Mode" << std::endl;
                break;
            case MODE_ANALYZE:
                std::cout << "Deep Protocol Analysis Mode" << std::endl;
                break;
            case MODE_RAW:
                std::cout << "Raw Message Capture (No Filtering)" << std::endl;
                break;
            case MODE_DECODE:
                std::cout << "CZONE Message Decode Focus" << std::endl;
                break;
            case MODE_DIFF:
                std::cout << "Message Difference Analysis" << std::endl;
                break;
            case MODE_SWITCH_CONTROL:
                std::cout << "Switch Control Mode" << std::endl;
                break;
            default:
                std::cout << "CZONE Protocol Analyzer" << std::endl;
        }
        std::cout << "=================================" << std::endl;
    }
    
    // Initialize appropriate transport based on mode
    CZONESwitchDecoder* decoder = nullptr;
    
    if (mode != MODE_SWITCH_CONTROL) {
        // For analysis/capture modes, use the decoder
        decoder = new CZONESwitchDecoder("/dev/ttyUSB0");
        if (!decoder->IsOpen()) {
            std::cerr << "Failed to open NGT-1" << std::endl;
            return 1;
        }
    }
    
    if (mode == MODE_SWITCH_CONTROL) {
        // For switch control, only use NMEA2000 transport
        std::cout << "Initializing NMEA2000 transport..." << std::endl;
        
        // NMEA2000 uses a timer-based state machine, so we need to call Open() and ParseMessages() in a loop
        // We need to wait for OpenState to reach os_Open, not just os_WaitOpen
        auto start = std::chrono::steady_clock::now();
        bool opened = false;
        
        // First, get Open() to return true (reaches os_WaitOpen)
        while (std::chrono::steady_clock::now() - start < std::chrono::seconds(5) && !opened) {
            NMEA2000.ParseMessages();
            if (NMEA2000.Open()) {
                opened = true;
                break;
            }
            usleep(10000); // 10ms delay
        }
        
        if (opened) {
            // Now wait for the full initialization (os_WaitOpen -> os_Open transition takes 200ms)
            auto wait_start = std::chrono::steady_clock::now();
            while (std::chrono::steady_clock::now() - wait_start < std::chrono::seconds(2)) {
                NMEA2000.ParseMessages();
                usleep(50000); // 50ms delay
            }
        }
        
        if (!opened) {
            std::cerr << "Failed to initialize NMEA2000 transport (timeout)" << std::endl;
            return 1;
        }
    }
    
    if (!quiet) {
        std::cout << "Connected to NGT-1" << std::endl << std::endl;
        
        // Check NGT-1 configuration and show warnings
        tNMEA2000_NGT1* ngt1 = dynamic_cast<tNMEA2000_NGT1*>(&NMEA2000);
        if (ngt1) {
            ngt1->CheckNGT1Status();
            ngt1->PrintNGT1Warnings();
        }
    }
    
    // Handle different modes
    if (mode == MODE_SWITCH_CONTROL) {
        if (switch_num < 1 || switch_num > 8) {
            std::cerr << "Error: Switch number must be between 1 and 8" << std::endl;
            return 1;
        }
        
        std::cout << "Sending switch command: Switch " << switch_num << " -> ";
        switch (switch_command) {
            case CZone::SWITCH_CMD_ON:
                std::cout << "ON" << std::endl;
                break;
            case CZone::SWITCH_CMD_OFF:
                std::cout << "OFF" << std::endl;
                break;
            case CZone::SWITCH_CMD_TOGGLE:
                std::cout << "TOGGLE" << std::endl;
                break;
        }
        
        // Convert command constants to library format
        tN2kCZoneSwitchCommand libCommand;
        switch (switch_command) {
            case CZone::SWITCH_CMD_ON: libCommand = N2kCZoneSwitchCmd_On; break;
            case CZone::SWITCH_CMD_OFF: libCommand = N2kCZoneSwitchCmd_Off; break;
            case CZone::SWITCH_CMD_TOGGLE: libCommand = N2kCZoneSwitchCmd_Toggle; break;
            default: 
                std::cerr << "Invalid switch command: " << (int)switch_command << std::endl;
                return 1;
        }
        
        // Send standard NMEA2000 PGN 127502 - Switch Bank Control
        std::cout << "Sending standard NMEA2000 PGN 127502 (Switch Bank Control)..." << std::endl;
        
        tN2kMsg SwitchMsg;
        SwitchMsg.SetPGN(127502);  // PGN 127502 - Switch Bank Control
        SwitchMsg.Priority = 3;
        SwitchMsg.Source = 0x05;  // Our unique address
        SwitchMsg.Destination = 0xFF;  // Broadcast
        
        // PGN 127502 format:
        // Byte 0: SID (Sequence ID)
        // Byte 1: Switch Bank Instance (0 = bank 0, 1 = bank 1, etc.)
        // Bytes 2-5: Switch status pairs (2 bits per switch)
        //   00 = Off, 01 = On, 10 = Error, 11 = Unavailable
        
        SwitchMsg.AddByte(0x00);  // SID
        SwitchMsg.AddByte(switch_bank);  // Bank number (0-based)
        
        // Build switch status bytes (2 bits per switch, 4 switches per byte)
        // For turning off switch 4 (index 3), set bits 6-7 of byte 2 to 00
        unsigned char switchStates[4] = {0xFF, 0xFF, 0xFF, 0xFF}; // All unavailable by default
        
        // Calculate which byte and bit position for the switch
        int switchIndex = switch_num - 1;  // Convert to 0-based
        int byteIndex = switchIndex / 4;
        int bitPosition = (switchIndex % 4) * 2;
        
        // Clear the 2 bits for this switch and set new state
        switchStates[byteIndex] &= ~(0x03 << bitPosition);  // Clear bits
        if (switch_command == CZone::SWITCH_CMD_ON) {
            switchStates[byteIndex] |= (0x01 << bitPosition);  // Set to On
        }
        // Off = 0x00, so no need to set bits for OFF command
        
        SwitchMsg.AddByte(switchStates[0]);
        SwitchMsg.AddByte(switchStates[1]);
        SwitchMsg.AddByte(switchStates[2]);
        SwitchMsg.AddByte(switchStates[3]);
        
        bool standardResult = NMEA2000.SendMsg(SwitchMsg);
        std::cout << "Standard PGN 127502 result: " << (standardResult ? "SUCCESS" : "FAILED") << std::endl;
        std::cout << "Sent to Bank " << switch_bank << ", Switch " << switch_num 
                  << " -> " << (switch_command == CZone::SWITCH_CMD_ON ? "ON" : "OFF") << std::endl;
        
        usleep(500000);  // Wait 500ms between messages
        
        // Now try the original PGN 65280 message
        std::cout << "Testing proprietary PGN 65280..." << std::endl;
        
        tN2kMsg N2kMsg;
        N2kMsg.SetPGN(65280);  // PGN 65280
        N2kMsg.Priority = 6;
        N2kMsg.Source = 0x03;
        N2kMsg.Destination = switch_dest;
        
        // Direct PGN 65280 payload - matches ParseCZoneMFDSwitchChangeRequest65280 example
        N2kMsg.AddByte(0x93);                    // CZoneMessage byte 0 
        N2kMsg.AddByte(0x13);                    // CZoneMessage byte 1
        N2kMsg.AddByte(switch_num + 4);          // Switch index (byte 2): 5=switch1, 6=switch2, etc.
        N2kMsg.AddByte(0x00);                    // Padding
        N2kMsg.AddByte(0x00);                    // Padding  
        N2kMsg.AddByte(0x03);                    // CzDipSwitch (byte 5): device identifier
        N2kMsg.AddByte((unsigned char)libCommand); // Command (byte 6): 0xF1=ON, 0xF4=OFF, 0xF2=TOGGLE
        
        
        std::cout << "Sending to device 0x" << std::hex << switch_dest << std::dec << std::endl;
        
        // Give the NMEA2000 library more time to complete initialization
        for (int i = 0; i < 10; i++) {
            NMEA2000.ParseMessages();
            usleep(100000); // 100ms delay
        }
        
        // Send via NMEA2000 transport
        bool sendResult = NMEA2000.SendMsg(N2kMsg);
        
        if (sendResult) {
            std::cout << "Command sent successfully" << std::endl;
            std::cout << "Sent CZONE message: PGN " << N2kMsg.PGN 
                      << " from 0x" << std::hex << (int)N2kMsg.Source 
                      << " to 0x" << (int)N2kMsg.Destination 
                      << " (" << (int)N2kMsg.DataLen << " bytes)" << std::dec << std::endl;
        } else {
            std::cerr << "Failed to send command" << std::endl;
            return 1;
        }
        return 0;
    }
    
    if (mode == MODE_CAPTURE) {
        decoder->CaptureDeviceMessages(target_device, capture_count, false, target_pgn, target_msg_type);
        return 0;
    }
    
    if (mode == MODE_BINARY) {
        decoder->CaptureDeviceMessages(target_device, capture_count, true, target_pgn, target_msg_type);
        return 0;
    }
    
    if (mode == MODE_RAW) {
        // Raw capture mode - show everything
        CZONESwitchDecoder::N2KMessage msg;
        while (g_running) {
            if (decoder->ReadMessage(msg)) {
                decoder->PrintMessageCompact(msg);
            }
        }
        if (!quiet) {
            std::cout << "\nTerminated by signal" << std::endl;
        }
        return 0;
    }
    
    if (mode == MODE_MONITOR) {
        // TOP-DOWN ANALYSIS: Classify devices by message patterns and structure
        std::cout << "\nTOP-DOWN ANALYSIS: Classifying CZONE devices..." << std::endl;
        
        CZONESwitchDecoder::N2KMessage msg;
        auto start = std::chrono::steady_clock::now();
        auto end = start + std::chrono::seconds(15);
        
        // Comprehensive device tracking
        struct DeviceProfile {
            uint8_t source;
            std::vector<uint32_t> pgns_used;
            std::map<uint32_t, int> pgn_counts;
            std::map<uint32_t, std::vector<std::vector<uint8_t>>> message_samples;
            std::map<uint8_t, int> destination_counts;
            int total_messages = 0;
        };
        
        std::map<uint8_t, DeviceProfile> devices;
        
        while (std::chrono::steady_clock::now() < end && g_running) {
            if (decoder->ReadMessage(msg)) {
                uint8_t src = msg.source;
                DeviceProfile& profile = devices[src];
                profile.source = src;
                profile.total_messages++;
                profile.pgn_counts[msg.pgn]++;
                profile.destination_counts[msg.destination]++;
                
                // Store first 3 samples of each PGN per device
                if (profile.message_samples[msg.pgn].size() < 3) {
                    std::vector<uint8_t> sample(msg.data, msg.data + msg.data_len);
                    profile.message_samples[msg.pgn].push_back(sample);
                }
                
                // Track unique PGNs
                if (std::find(profile.pgns_used.begin(), profile.pgns_used.end(), msg.pgn) == profile.pgns_used.end()) {
                    profile.pgns_used.push_back(msg.pgn);
                }
            }
        }
        
        std::cout << "\nDevice Classification Results:" << std::endl;
        std::cout << "==============================" << std::endl;
        
        // Group devices by similarity
        std::vector<std::pair<uint8_t, DeviceProfile*>> sorted_devices;
        for (auto& pair : devices) {
            sorted_devices.push_back({pair.first, &pair.second});
        }
        
        // Sort by total message count (most active first)
        std::sort(sorted_devices.begin(), sorted_devices.end(), 
                 [](const auto& a, const auto& b) { return a.second->total_messages > b.second->total_messages; });
        
        for (auto& pair : sorted_devices) {
            uint8_t src = pair.first;
            DeviceProfile& profile = *pair.second;
            
            std::cout << "\nDevice 0x" << std::hex << std::setw(2) << std::setfill('0') << (int)src << std::dec << " (Total: " << profile.total_messages << " msgs)" << std::endl;
            
            // Show PGN usage pattern
            std::cout << "  PGNs used: ";
            for (uint32_t pgn : profile.pgns_used) {
                int count = profile.pgn_counts[pgn];
                double percentage = (double)count / profile.total_messages * 100;
                std::cout << pgn << "(" << count << "," << std::fixed << std::setprecision(1) << percentage << "%) ";
            }
            std::cout << std::endl;
            
            // Show destinations
            std::cout << "  Destinations: ";
            for (auto& dest_pair : profile.destination_counts) {
                std::cout << "0x" << std::hex << (int)dest_pair.first << std::dec << "(" << dest_pair.second << ") ";
            }
            std::cout << std::endl;
            
            // Show message structure for PGN 65282 (most relevant)
            if (profile.message_samples.find(65282) != profile.message_samples.end()) {
                std::cout << "  PGN 65282 samples:" << std::endl;
                for (size_t i = 0; i < profile.message_samples[65282].size(); i++) {
                    std::cout << "    Sample " << (i+1) << ": ";
                    auto& sample = profile.message_samples[65282][i];
                    for (size_t j = 0; j < sample.size() && j < 17; j++) {
                        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)sample[j] << " ";
                    }
                    std::cout << std::dec << std::endl;
                }
            }
        }
        
        // SIMILARITY ANALYSIS
        std::cout << "\n🔍 SIMILARITY ANALYSIS:" << std::endl;
        std::cout << "========================" << std::endl;
        
        // Find devices that use the same PGNs with similar frequencies
        std::vector<std::pair<uint8_t, uint8_t>> similar_pairs;
        
        for (size_t i = 0; i < sorted_devices.size(); i++) {
            for (size_t j = i + 1; j < sorted_devices.size(); j++) {
                auto& dev1 = *sorted_devices[i].second;
                auto& dev2 = *sorted_devices[j].second;
                
                // Check if both use PGN 65282 (status messages)
                bool both_use_65282 = (dev1.pgn_counts.find(65282) != dev1.pgn_counts.end()) &&
                                      (dev2.pgn_counts.find(65282) != dev2.pgn_counts.end());
                
                if (both_use_65282) {
                    int count1 = dev1.pgn_counts[65282];
                    int count2 = dev2.pgn_counts[65282];
                    double ratio = (double)std::min(count1, count2) / std::max(count1, count2);
                    
                    std::cout << "  Device 0x" << std::hex << dev1.source << " vs 0x" << dev2.source << std::dec;
                    std::cout << ": PGN 65282 counts " << count1 << " vs " << count2;
                    std::cout << " (similarity: " << std::fixed << std::setprecision(2) << ratio << ")" << std::endl;
                    
                    if (ratio > 0.5) { // Similar frequency
                        similar_pairs.push_back({dev1.source, dev2.source});
                    }
                }
            }
        }
        
        // STRUCTURAL ANALYSIS BY EXCLUSION - Focus on devices 0x46 (Bank 1) and 0x13 (Bank 2)
        std::cout << "\n🎯 STRUCTURAL ANALYSIS BY EXCLUSION:" << std::endl;
        std::cout << "======================================" << std::endl;
        std::cout << "Assumption: 0x46 = Bank 1, 0x13 = Bank 2" << std::endl;
        
        // Get samples from both devices
        auto& bank1_device = devices[0x46];
        auto& bank2_device = devices[0x13];
        
        if (bank1_device.message_samples[65282].size() > 0 && bank2_device.message_samples[65282].size() > 0) {
            auto& bank1_msgs = bank1_device.message_samples[65282];
            auto& bank2_msgs = bank2_device.message_samples[65282];
            
            std::cout << "\n📊 BYTE-BY-BYTE STRUCTURAL ANALYSIS:" << std::endl;
            std::cout << "=====================================" << std::endl;
            
            // Analyze first message from each device
            auto& msg1 = bank1_msgs[0];  // Bank 1 (0x46) 
            auto& msg2 = bank2_msgs[0];  // Bank 2 (0x13)
            
            std::cout << "Bank 1 (0x46): ";
            for (size_t i = 0; i < std::min(msg1.size(), (size_t)17); i++) {
                std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)msg1[i] << " ";
            }
            std::cout << std::endl;
            
            std::cout << "Bank 2 (0x13): ";
            for (size_t i = 0; i < std::min(msg2.size(), (size_t)17); i++) {
                std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)msg2[i] << " ";
            }
            std::cout << std::dec << std::endl;
            
            std::cout << "\nBYTE CLASSIFICATION:" << std::endl;
            std::cout << "Byte# Bank1  Bank2  Status" << std::endl;
            std::cout << "----- ----- ----- -------------------------" << std::endl;
            
            for (size_t i = 0; i < std::min({msg1.size(), msg2.size(), (size_t)17}); i++) {
                uint8_t b1 = msg1[i];
                uint8_t b2 = msg2[i];
                
                std::cout << std::setw(2) << i << ":   ";
                std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)b1 << "    ";
                std::cout << std::setw(2) << (int)b2 << std::dec << "   ";
                
                if (b1 == b2) {
                    std::cout << "IDENTICAL - likely structure/header";
                    
                    // Identify known structural bytes based on CZONE protocol
                    if (i == 0) std::cout << " (Message type/instance)";
                    else if (i == 1) std::cout << " (Always 0xFF - CZONE header)";
                    else if (i == 2) std::cout << " (Message subtype)";
                    else if (i == 6) std::cout << " (Always 0x00 - padding)";
                    else if (i == 7) std::cout << " (Always 0x08 - data length)";
                    else std::cout << " (Timestamp/sequence/checksum?)";
                } else {
                    std::cout << "DIFFERENT - potential switch data";
                    
                    // Analyze what these different bytes might represent
                    std::cout << " | B1_bits: ";
                    for (int bit = 7; bit >= 0; bit--) {
                        std::cout << ((b1 >> bit) & 1);
                    }
                    std::cout << " B2_bits: ";
                    for (int bit = 7; bit >= 0; bit--) {
                        std::cout << ((b2 >> bit) & 1);
                    }
                    
                    // Check for our expected patterns
                    if (b1 == 0x07 || b1 == 0x38) std::cout << " 🎯 B1=BANK1_PATTERN";
                    if (b2 == 0x17 || b2 == 0x3A) std::cout << " 🎯 B2=BANK2_PATTERN";
                    if (b1 == 0x17 || b1 == 0x3A) std::cout << " 🎯 B1=BANK2_PATTERN"; 
                    if (b2 == 0x07 || b2 == 0x38) std::cout << " 🎯 B2=BANK1_PATTERN";
                }
                std::cout << std::endl;
            }
            
            // Multiple message comparison to identify truly variable vs static bytes
            std::cout << "\n📈 VARIABILITY ANALYSIS (Multiple Messages):" << std::endl;
            std::cout << "=============================================" << std::endl;
            
            for (size_t i = 0; i < 17; i++) {
                std::set<uint8_t> bank1_values, bank2_values;
                
                // Collect values from multiple messages
                for (size_t msgIdx = 0; msgIdx < std::min(bank1_msgs.size(), (size_t)3); msgIdx++) {
                    if (i < bank1_msgs[msgIdx].size()) {
                        bank1_values.insert(bank1_msgs[msgIdx][i]);
                    }
                }
                for (size_t msgIdx = 0; msgIdx < std::min(bank2_msgs.size(), (size_t)3); msgIdx++) {
                    if (i < bank2_msgs[msgIdx].size()) {
                        bank2_values.insert(bank2_msgs[msgIdx][i]);
                    }
                }
                
                std::cout << "Byte " << std::setw(2) << i << ": ";
                std::cout << "Bank1_values={";
                for (auto val : bank1_values) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)val << " ";
                }
                std::cout << "} Bank2_values={";
                for (auto val : bank2_values) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)val << " ";
                }
                std::cout << "}" << std::dec;
                
                if (bank1_values.size() == 1 && bank2_values.size() == 1) {
                    if (*bank1_values.begin() == *bank2_values.begin()) {
                        std::cout << " -> STATIC/STRUCTURAL";
                    } else {
                        std::cout << " -> DEVICE_SPECIFIC (potential switch data)";
                    }
                } else {
                    std::cout << " -> VARIABLE (timestamp/counter/checksum)";
                }
                std::cout << std::endl;
            }
            
            std::cout << "\n🔍 SWITCH STATE INTERPRETATION:" << std::endl;
            std::cout << "================================" << std::endl;
            std::cout << "Expected states:" << std::endl;
            std::cout << "Bank 1 (0x46): ON,ON,ON,OFF,OFF,OFF" << std::endl; 
            std::cout << "Bank 2 (0x13): ON,ON,ON,OFF,ON,OFF" << std::endl;
            std::cout << std::endl;
            
            // Focus only on bytes that are different and device-specific
            std::cout << "Examining device-specific bytes for switch patterns..." << std::endl;
        } else {
            std::cout << "Insufficient message samples from devices 0x46 and 0x13" << std::endl;
        }
        
        return 0;
    }
    
    std::cout << std::endl;
    std::cout << "Current switch states:" << std::endl;
    std::cout << "  Bank 1: ON, ON, ON, OFF, OFF, OFF" << std::endl;
    std::cout << "  Bank 2: ON, ON, ON, OFF, ON, OFF" << std::endl;
    std::cout << std::endl;
    std::cout << "📊 Phase 1: Capturing baseline for 5 seconds (don't touch switches)..." << std::endl;
    
    auto start_time = std::chrono::steady_clock::now();
    auto baseline_end = start_time + std::chrono::seconds(5);
    auto capture_end = baseline_end + std::chrono::seconds(15);
    
    int total_messages = 0;
    int potential_czone_messages = 0;
    CZONESwitchDecoder::N2KMessage msg;
    
    // Phase 1: Capture baseline
    while (std::chrono::steady_clock::now() < baseline_end && g_running) {
        if (decoder->ReadMessage(msg)) {
            total_messages++;
            decoder->AnalyzeMessage(msg, false);
            decoder->TestCZoneParser(msg);
        }
    }
    
    std::cout << std::endl;
    std::cout << "✅ Baseline captured!" << std::endl;
    std::cout << std::endl;
    std::cout << "🔥🔥🔥 Phase 2: TOGGLE CZONE SWITCHES NOW! 🔥🔥🔥" << std::endl;
    std::cout << "⏱️  Monitoring for 15 seconds..." << std::endl;
    std::cout << std::endl;
    
    // Phase 2: Monitor for changes
    while (std::chrono::steady_clock::now() < capture_end && g_running) {
        if (decoder->ReadMessage(msg)) {
            total_messages++;
            
            // Count potential CZONE messages
            if (!decoder->IsKnownNonSwitchPGN(msg.pgn) && decoder->IsPotentialCZONEMessage(msg)) {
                potential_czone_messages++;
            }
            
            decoder->AnalyzeMessage(msg, false);
            decoder->TestCZoneParser(msg);
            
            // Progress update every 2 seconds
            auto now = std::chrono::steady_clock::now();
            auto remaining = std::chrono::duration_cast<std::chrono::seconds>(capture_end - now).count();
            
            static int last_remaining = -1;
            if (remaining != last_remaining && remaining % 2 == 0 && remaining > 0) {
                std::cout << "⏰ " << remaining << " seconds remaining..." << std::endl;
                last_remaining = remaining;
            }
        }
    }
    
    std::cout << std::endl;
    std::cout << "🔴 SCRIPT STOPPED" << std::endl;
    std::cout << "📊 Summary: " << total_messages << " total messages, " << potential_czone_messages << " potential CZONE messages" << std::endl;
    
    // Cleanup
    if (decoder) {
        delete decoder;
    }
    
    return 0;
}