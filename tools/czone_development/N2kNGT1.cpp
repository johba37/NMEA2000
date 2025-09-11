/*
N2kNGT1.cpp

Minimal NMEA2000 transport implementation for NGT-1 via serial port
*/

#include "N2kNGT1.h"
#include <chrono>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <cstring>
#include <vector>

// NGT-1 protocol constants
const unsigned char DLE = 0x10;
const unsigned char STX = 0x02;
const unsigned char ETX = 0x03;

//*****************************************************************************
// Global NMEA2000 instance
//*****************************************************************************
tNMEA2000_NGT1 NMEA2000;

//*****************************************************************************
// Timing functions provided by N2kTimer.cpp
//*****************************************************************************

//*****************************************************************************
// tNMEA2000_NGT1 implementation
//*****************************************************************************
tNMEA2000_NGT1::tNMEA2000_NGT1(const char* port) : tNMEA2000(), port_name(port), serial_fd(-1) {
    // Configure device information for development tool
    SetDeviceInformation(12345,        // Unique number
                        132,           // Device function (Generic)
                        25,            // Device class (Inter/Intranetwork Device)
                        2040);         // Manufacturer code (generic)
                        
    // Set a reasonable product information
    SetProductInformation("1234",           // Manufacturer's Model serial code
                         100,              // Manufacturer's product code
                         "CZONE DevTool",  // Manufacturer's Model ID
                         "1.0.0",          // Manufacturer's Software version code
                         "1.0.0"           // Manufacturer's Model version
                        );
    
    // Make sure we're not in listen-only mode
    SetMode(tNMEA2000::N2km_NodeOnly, 0x05); // Set as active node with source 0x05
}

tNMEA2000_NGT1::~tNMEA2000_NGT1() {
    if (serial_fd >= 0) {
        close(serial_fd);
        serial_fd = -1;
    }
}

bool tNMEA2000_NGT1::CANOpen() {
    
    // Open serial port
    serial_fd = open(port_name.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (serial_fd < 0) {
        std::cerr << "Failed to open " << port_name << ": " << strerror(errno) << std::endl;
        return false;
    }
    
    // Configure serial port for NGT-1 (115200 baud, 8N1)
    struct termios tty;
    memset(&tty, 0, sizeof(tty));
    
    if (tcgetattr(serial_fd, &tty) != 0) {
        std::cerr << "Failed to get terminal attributes" << std::endl;
        close(serial_fd);
        serial_fd = -1;
        return false;
    }
    
    // Set baud rate
    cfsetospeed(&tty, B115200);
    cfsetispeed(&tty, B115200);
    
    // 8N1, no flow control
    tty.c_cflag &= ~PARENB;        // No parity
    tty.c_cflag &= ~CSTOPB;        // One stop bit
    tty.c_cflag &= ~CSIZE;         // Clear size bits
    tty.c_cflag |= CS8;            // 8 data bits
    tty.c_cflag &= ~CRTSCTS;       // No hardware flow control
    tty.c_cflag |= CREAD | CLOCAL; // Enable reading, ignore control lines
    
    // Raw mode
    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    tty.c_iflag &= ~(IXON | IXOFF | IXANY | INLCR | ICRNL);
    tty.c_oflag &= ~OPOST;
    
    // Set timeouts
    tty.c_cc[VMIN] = 0;   // Non-blocking read
    tty.c_cc[VTIME] = 1;  // 100ms timeout
    
    if (tcsetattr(serial_fd, TCSANOW, &tty) != 0) {
        std::cerr << "Failed to set terminal attributes" << std::endl;
        close(serial_fd);
        serial_fd = -1;
        return false;
    }
    
    // Flush any existing data
    tcflush(serial_fd, TCIOFLUSH);
    
    // Configure NGT-1 for PGN transmission
    // Wait for device to be ready
    usleep(200000);  // 200ms
    
    // Send NGT-1 startup sequence exactly like canboat
    std::cout << "Sending NGT-1 startup sequence..." << std::endl;
    
    // Canboat NGT_STARTUP_SEQ: {0x11, 0x02, 0x00} via NGT_MSG_SEND (0xA1)
    unsigned char startup_data[] = {0x11, 0x02, 0x00};
    
    if (!SendNGTMessage(startup_data, sizeof(startup_data))) {
        std::cerr << "Failed to send NGT-1 startup sequence" << std::endl;
        return false;
    }
    
    usleep(100000);  // Wait for NGT-1 to process
    std::cout << "NGT-1 initialization completed" << std::endl;
    
    return true;
}

bool tNMEA2000_NGT1::CheckNGT1Status() {
    if (serial_fd < 0) {
        return false;
    }
    
    std::cout << "\n=== NGT-1 Configuration Status Check ===" << std::endl;
    
    // Request device version/info using EBL_VERSION command
    WriteNGT1Byte(DLE);
    WriteNGT1Byte(STX);
    WriteNGT1Byte(0x01);  // EBL_VERSION - version info request
    WriteNGT1Byte(0x00);  // Length
    WriteNGT1Byte(0xFF);  // Checksum (command + length + checksum = 0 mod 256)
    WriteNGT1Byte(DLE);
    WriteNGT1Byte(ETX);
    
    // Try to read response with timeout
    usleep(200000);  // 200ms wait for response
    
    unsigned char response[256];
    int bytes_read = 0;
    bool found_response = false;
    
    // Set non-blocking mode temporarily
    int flags = fcntl(serial_fd, F_GETFL, 0);
    fcntl(serial_fd, F_SETFL, flags | O_NONBLOCK);
    
    // Try to read response for 1 second total
    for (int i = 0; i < 10 && !found_response; i++) {
        int n = read(serial_fd, response + bytes_read, sizeof(response) - bytes_read - 1);
        if (n > 0) {
            bytes_read += n;
            // Look for DLE STX pattern in response
            for (int j = 0; j < bytes_read - 1; j++) {
                if (response[j] == DLE && response[j+1] == STX) {
                    found_response = true;
                    break;
                }
            }
        }
        if (!found_response) usleep(100000);  // 100ms between attempts
    }
    
    // Restore blocking mode
    fcntl(serial_fd, F_SETFL, flags);
    
    if (found_response && bytes_read > 0) {
        std::cout << "NGT-1 responded (received " << bytes_read << " bytes)" << std::endl;
        
        // Basic response analysis
        bool has_version_response = false;
        for (int i = 0; i < bytes_read - 2; i++) {
            if (response[i] == DLE && response[i+1] == STX && response[i+2] == 0x01) {
                has_version_response = true;
                break;
            }
        }
        
        if (has_version_response) {
            std::cout << "✓ NGT-1 version command responded correctly" << std::endl;
        } else {
            std::cout << "⚠ NGT-1 response format unexpected" << std::endl;
        }
    } else {
        std::cout << "⚠ NGT-1 did not respond to status request" << std::endl;
        std::cout << "  This may indicate communication issues or firmware problems" << std::endl;
    }
    
    return found_response;
}

bool tNMEA2000_NGT1::SendActisenseMessage(unsigned char command, unsigned long pgn, unsigned char dst, 
                                       unsigned char src, unsigned char priority, const unsigned char* data, int len) {
    if (serial_fd < 0) {
        return false;
    }
    
    // Build Actisense message format: [command] [length] [priority] [PGN_low] [PGN_mid] [PGN_high] [dst] [src] [time_low] [time_high] [len] [data...]
    unsigned char message[256];
    int pos = 0;
    
    message[pos++] = command;  // Command (0x94 for N2K_MSG_SEND)
    
    // Total length (will be filled in later)  
    int length_pos = pos++;
    
    // Priority
    message[pos++] = priority;
    
    // PGN (3 bytes, little-endian)
    message[pos++] = pgn & 0xFF;
    message[pos++] = (pgn >> 8) & 0xFF;  
    message[pos++] = (pgn >> 16) & 0xFF;
    
    // Destination
    message[pos++] = dst;
    
    // Source 
    message[pos++] = src;
    
    // Timestamp (not used, set to 0xFF)
    message[pos++] = 0xFF;
    message[pos++] = 0xFF;
    
    // Data length
    message[pos++] = len;
    
    // Data payload
    for (int i = 0; i < len; i++) {
        message[pos++] = data[i];
    }
    
    // Set total length
    message[length_pos] = pos - 2;  // Length doesn't include command and length bytes
    
    // Send with DLE/STX/ETX framing
    WriteNGT1Byte(DLE);
    WriteNGT1Byte(STX);
    WriteNGT1Bytes(message, pos);
    WriteNGT1Byte(DLE);
    WriteNGT1Byte(ETX);
    
    return true;
}

bool tNMEA2000_NGT1::SendActisenseCommand(unsigned char command, const unsigned char* data, int len) {
    if (serial_fd < 0) {
        return false;
    }
    
    // Build simple Actisense command format: [command] [length] [data...]
    unsigned char message[256];
    int pos = 0;
    
    message[pos++] = command;  // Command (0xA1 for NGT_MSG_SEND)
    message[pos++] = len;      // Data length
    
    // Data payload
    for (int i = 0; i < len; i++) {
        message[pos++] = data[i];
    }
    
    // Send with DLE/STX/ETX framing
    WriteNGT1Byte(DLE);
    WriteNGT1Byte(STX);
    WriteNGT1Bytes(message, pos);
    WriteNGT1Byte(DLE);
    WriteNGT1Byte(ETX);
    
    return true;
}

bool tNMEA2000_NGT1::SendMessage(unsigned long pgn, unsigned char dst, const unsigned char* data, int len) {
    // Use canboat-compatible N2K_MSG_SEND (0x94) for NMEA2000 messages
    return SendActisenseMessage(0x94, pgn, dst, 0x05, 0x06, data, len);
}

bool tNMEA2000_NGT1::SendNGTMessage(const unsigned char* data, int len) {
    // Use NGT_MSG_SEND (0xA1) for NGT-specific commands like startup
    return SendActisenseCommand(0xA1, data, len);
}

void tNMEA2000_NGT1::PrintNGT1Warnings() {
    std::cout << "NGT-1 may require Actisense software configuration for PGN transmission" << std::endl;
}

// CANClose is not virtual - handle cleanup in destructor

bool tNMEA2000_NGT1::CANSendFrame(unsigned long id, unsigned char len, const unsigned char *buf, bool wait_sent) {
    if (serial_fd < 0) {
        return false;
    }
    
    // Extract NMEA2000 message components from CAN frame
    unsigned char src = id & 0xFF;
    unsigned char priority = (id >> 26) & 0x07;
    unsigned long pgn = (id >> 8) & 0x1FFFFUL;  // Extract PGN from bits 8-25
    unsigned char dst = 0xFF;  // Broadcast by default
    
    // For PDU1 format (PF < 240), destination is embedded in the PGN field
    unsigned char pf = (pgn >> 8) & 0xFF;
    if (pf < 240) {  // PDU1 format
        dst = pgn & 0xFF;
        pgn = pgn & 0x1FF00UL;  // Clear the destination byte for PDU1
    }
    
    // Only log CZONE messages
    if (pgn == 65280) {
        std::cout << "Sending CZONE message: PGN " << pgn << ", src: 0x" << std::hex << (int)src 
                  << ", dst: 0x" << (int)dst << std::dec << ", len: " << (int)len << std::endl;
    }
    return SendActisenseMessage(0x94, pgn, dst, src, priority, buf, len);
}

bool tNMEA2000_NGT1::CANGetFrame(unsigned long &id, unsigned char &len, unsigned char *buf) {
    // For development tool, we mainly send messages, not receive frames for CAN layer
    // Receiving is handled separately in the decoder's ReadMessage function
    return false;
}


bool tNMEA2000_NGT1::EnableTxPGN(unsigned long pgn) {
    if (serial_fd < 0) {
        return false;
    }
    
    std::cout << "Configuring NGT-1 to enable PGN " << pgn << " for transmission..." << std::endl;
    
    // Try multiple A1 command formats - one of these should work
    
    // FORMAT 1: Basic A1 command with rate
    std::cout << "Trying A1 format 1 (basic with rate)..." << std::endl;
    unsigned char message1[16];
    int pos = 0;
    message1[pos++] = 0xA1;  // Add Tx PGN command
    int length_pos = pos++;
    message1[pos++] = pgn & 0xFF;
    message1[pos++] = (pgn >> 8) & 0xFF;  
    message1[pos++] = (pgn >> 16) & 0xFF;
    message1[pos++] = 0xFF;  // Rate: no automatic rate
    message1[pos++] = 0xFF;
    message1[pos++] = 0xFF;
    message1[pos++] = 0xFF;
    message1[length_pos] = pos - 2;
    
    WriteNGT1Byte(DLE);
    WriteNGT1Byte(STX);
    WriteNGT1Bytes(message1, pos);
    WriteNGT1Byte(DLE);
    WriteNGT1Byte(ETX);
    usleep(100000);  // 100ms
    
    // FORMAT 2: A1 command without rate parameter
    std::cout << "Trying A1 format 2 (no rate)..." << std::endl;
    pos = 0;
    unsigned char message2[16];
    message2[pos++] = 0xA1;
    length_pos = pos++;
    message2[pos++] = pgn & 0xFF;
    message2[pos++] = (pgn >> 8) & 0xFF;  
    message2[pos++] = (pgn >> 16) & 0xFF;
    message2[length_pos] = pos - 2;
    
    WriteNGT1Byte(DLE);
    WriteNGT1Byte(STX);
    WriteNGT1Bytes(message2, pos);
    WriteNGT1Byte(DLE);
    WriteNGT1Byte(ETX);
    usleep(100000);
    
    // FORMAT 3: A2 command (different command type)
    std::cout << "Trying A2 format (enable PGN)..." << std::endl;
    pos = 0;
    unsigned char message3[16];
    message3[pos++] = 0xA2;  // Different command
    length_pos = pos++;
    message3[pos++] = pgn & 0xFF;
    message3[pos++] = (pgn >> 8) & 0xFF;  
    message3[pos++] = (pgn >> 16) & 0xFF;
    message3[pos++] = 0x01;  // Enable flag
    message3[length_pos] = pos - 2;
    
    WriteNGT1Byte(DLE);
    WriteNGT1Byte(STX);
    WriteNGT1Bytes(message3, pos);
    WriteNGT1Byte(DLE);
    WriteNGT1Byte(ETX);
    usleep(100000);
    
    std::cout << "PGN " << pgn << " configuration commands sent" << std::endl;
    return true;
}

void tNMEA2000_NGT1::WriteNGT1Byte(unsigned char b) {
    if (serial_fd < 0) return;
    
    // Escape DLE bytes in data
    if (b == DLE) {
        unsigned char escaped[] = {DLE, DLE};
        write(serial_fd, escaped, 2);
    } else {
        write(serial_fd, &b, 1);
    }
}

void tNMEA2000_NGT1::WriteNGT1Bytes(const unsigned char* data, int len) {
    for (int i = 0; i < len; i++) {
        WriteNGT1Byte(data[i]);
    }
}