/*
N2kNGT1.h

Minimal NMEA2000 transport for NGT-1 via serial port
Provides just enough functionality to use NMEA2000 library Set functions
for protocol development and testing.

Based on patterns from NMEA2000_socketCAN library.
*/

#ifndef N2kNGT1_h
#define N2kNGT1_h

#include "../../src/NMEA2000.h"
#include <string>

//*****************************************************************************
// Minimal NMEA2000 transport for NGT-1 serial communication
//*****************************************************************************
class tNMEA2000_NGT1 : public tNMEA2000 {
public:
    tNMEA2000_NGT1(const char* port = "/dev/ttyUSB0");
    virtual ~tNMEA2000_NGT1();
    
    // Override required transport methods
    bool CANSendFrame(unsigned long id, unsigned char len, const unsigned char *buf, bool wait_sent = true) override;
    bool CANGetFrame(unsigned long &id, unsigned char &len, unsigned char *buf) override;
    bool CANOpen() override;

private:
    std::string port_name;
    int serial_fd;
    
    // NGT-1 protocol helpers  
    bool EnableTxPGN(unsigned long pgn);
    bool SendMessage(unsigned long pgn, unsigned char dst, const unsigned char* data, int len);
    bool SendNGTMessage(const unsigned char* data, int len);
    bool SendActisenseMessage(unsigned char command, unsigned long pgn, unsigned char dst, 
                             unsigned char src, unsigned char priority, const unsigned char* data, int len);
    bool SendActisenseCommand(unsigned char command, const unsigned char* data, int len);
    
public:
    bool CheckNGT1Status();
    void PrintNGT1Warnings();
    
private:
    void WriteNGT1Byte(unsigned char b);
    void WriteNGT1Bytes(const unsigned char* data, int len);
};

//*****************************************************************************
// Platform function declarations - implemented in N2kNGT1.cpp
//*****************************************************************************

// Note: N2kMillis() is already declared in N2kTimer.h

// Create global NMEA2000 instance for easy access
extern tNMEA2000_NGT1 NMEA2000;

#endif