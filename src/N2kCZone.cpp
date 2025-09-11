/*
N2kCZone.cpp

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

CZONE (Mastervolt/Power Products) switch bank support for NMEA2000 library.

Based on successful reverse engineering of CZONE proprietary protocol:
- CZONE uses proprietary message format: 93 13 XX (not standard NMEA2000)
- CZONE addresses: 0x46 (primary switch bank), 0x13, 0x19, 0x12
- CZONE PGNs: 65282-65287 (proprietary range)
*/

#include "N2kCZone.h"
#include <cstring>

//*****************************************************************************
bool N2kIsCZoneProprietaryMessage(const unsigned char* RawData, int DataLen) {
    if (DataLen < 3) return false;
    
    return (RawData[0] == N2kCZone_ProprietaryHeader1 && 
            RawData[1] == N2kCZone_ProprietaryHeader2 &&
            RawData[2] >= 0x02 && RawData[2] <= 0x07);
}

//*****************************************************************************
bool ParseN2kCZoneProprietaryMessage(const unsigned char* RawData, int DataLen,
                                     unsigned long &PGN, unsigned char &Source, 
                                     unsigned char &Destination,
                                     const unsigned char* &PayloadData, int &PayloadLen) {
    if (!N2kIsCZoneProprietaryMessage(RawData, DataLen)) return false;
    if (DataLen < 5) return false;  // Minimum: header(2) + offset(1) + src(1) + dest(1)
    
    // Parse CZONE proprietary format: 93 13 XX SS DD [data...]
    PGN = 65280 + RawData[2];  // Convert offset to PGN (65282-65287)
    Source = RawData[3];
    Destination = RawData[4];
    
    if (DataLen > 5) {
        PayloadData = &RawData[5];
        PayloadLen = DataLen - 5;
    } else {
        PayloadData = nullptr;
        PayloadLen = 0;
    }
    
    return true;
}

//*****************************************************************************
bool N2kIsCZoneDevice(unsigned char Source) {
    // Known CZONE device addresses discovered through network analysis
    return (Source == N2kCZone_PrimarySwitchBank ||
            Source == N2kCZone_Module1 ||
            Source == N2kCZone_Module2 ||
            Source == N2kCZone_Module3);
}

//*****************************************************************************
void SetN2kCZoneProprietaryMessage(tN2kMsg &N2kMsg, unsigned long PGN,
                                   unsigned char Source, unsigned char Destination,
                                   const unsigned char* PayloadData, int PayloadLen) {
    // Validate PGN is in CZONE proprietary range
    if (PGN < 65282 || PGN > 65287) return;
    
    // Set the PGN and priority for proprietary messages
    N2kMsg.SetPGN(PGN);
    N2kMsg.Priority = 6;  // Medium priority for switch bank messages
    N2kMsg.Source = Source;
    N2kMsg.Destination = Destination;
    
    // Add CZONE proprietary header
    N2kMsg.AddByte(N2kCZone_ProprietaryHeader1);  // 0x93
    N2kMsg.AddByte(N2kCZone_ProprietaryHeader2);  // 0x13
    N2kMsg.AddByte(PGN - 65280);                  // PGN offset (0x02-0x07)
    N2kMsg.AddByte(Source);
    N2kMsg.AddByte(Destination);
    
    // Add payload data
    if (PayloadData && PayloadLen > 0) {
        for (int i = 0; i < PayloadLen; i++) {
            N2kMsg.AddByte(PayloadData[i]);
        }
    }
}

//*****************************************************************************
void SetN2kCZoneSwitchControlMessage(tN2kMsg &N2kMsg, unsigned char SwitchNum,
                                     tN2kCZoneSwitchCommand Command,
                                     unsigned char Destination,
                                     unsigned char Source) {
    // Validate switch number range
    if (SwitchNum < 1 || SwitchNum > 20) {
        return;  // Invalid switch number
    }
    
    // Set the PGN and priority for switch control
    N2kMsg.SetPGN(N2kCZone_PGN_SwitchControlCmd);
    N2kMsg.Priority = 6;  // Medium priority for switch commands
    N2kMsg.Source = Source;
    N2kMsg.Destination = Destination;
    
    // Add CZONE proprietary header for PGN 65280
    N2kMsg.AddByte(N2kCZone_ProprietaryHeader1);  // 0x93
    N2kMsg.AddByte(N2kCZone_ProprietaryHeader2);  // 0x13
    N2kMsg.AddByte(0x00);                         // PGN offset for 65280
    N2kMsg.AddByte(Source);
    N2kMsg.AddByte(Destination);
    
    // Add CZONE switch control payload (matches working example code)
    N2kMsg.AddByte(0x01);                    // Device instance  
    N2kMsg.AddByte(0xFF);                    // Header marker
    N2kMsg.AddByte(SwitchNum + 4);           // Switch index (5-12, where 5=switch 1)
    N2kMsg.AddByte(0x00);                    // Unknown byte 0
    N2kMsg.AddByte(0x00);                    // Unknown byte 1  
    N2kMsg.AddByte(0x03);                    // CzDipSwitch (device identifier)
    N2kMsg.AddByte((unsigned char)Command);  // Command (0xF1=ON/0xF4=OFF/0xF2=TOGGLE)
    
    // Pad remaining bytes with zeros
    for (int i = 0; i < 10; i++) {
        N2kMsg.AddByte(0x00);
    }
}

//*****************************************************************************
bool ParseN2kCZonePGN65282(const unsigned char* RawData, int DataLen, tN2kCZoneMessage &CZoneMsg) {
    if (DataLen != 17) return false;
    
    CZoneMsg.DeviceInstance = RawData[0];
    CZoneMsg.Header = RawData[1];
    CZoneMsg.DeviceType = RawData[2];
    
    // Fix: Parse 32-bit little-endian timestamp from bytes 3-6
    CZoneMsg.Timestamp = RawData[3] | 
                        (RawData[4] << 8) | 
                        (RawData[5] << 16) | 
                        (RawData[6] << 24);
    
    CZoneMsg.DataLength = RawData[7];
    
    // Fix: Copy full 9-byte payload (bytes 8-16)
    for (int i = 0; i < 9; i++) {
        CZoneMsg.Payload[i] = RawData[8 + i];
    }
    
    return true;
}

//*****************************************************************************
bool GetN2kCZoneSwitchStates(const tN2kCZoneMessage &CZoneMsg, unsigned char &SwitchStates) {
    // Only extract switch states from Bank 1 (device type 0x09, device instance 0x00)
    if (CZoneMsg.DeviceInstance != 0x00 || CZoneMsg.DeviceType != 0x09) {
        return false;
    }
    
    // Fix: Use last byte of payload (switch state encoding still being researched)
    SwitchStates = CZoneMsg.Payload[8];  // Last byte of 9-byte payload
    return true;
}

//*****************************************************************************
bool ParseN2kCZoneHeartbeat(const tN2kCZoneMessage &msg, tN2kCZoneHeartbeat &heartbeat) {
    if (msg.DeviceType != N2kCZone_MsgType_Heartbeat) return false;
    
    heartbeat.DeviceInstance = msg.DeviceInstance;
    heartbeat.Timestamp = msg.Timestamp;
    heartbeat.Counter = msg.Payload[2];  // Byte 2 of payload increments
    
    // Copy fixed data pattern (usually: 11 ff 7f ff 7f fd)
    for (int i = 0; i < 6; i++) {
        heartbeat.FixedData[i] = msg.Payload[3 + i];
    }
    
    heartbeat.Checksum = (msg.DataLength > 8) ? msg.Payload[8] : 0;
    
    return true;
}

//*****************************************************************************
bool ParseN2kCZoneExtended(const tN2kCZoneMessage &msg, tN2kCZoneExtended &extended) {
    if (msg.DeviceType != N2kCZone_MsgType_Extended) return false;
    
    extended.DeviceInstance = msg.DeviceInstance;
    extended.Timestamp = msg.Timestamp;
    
    // Extract 16-bit sequence counter (big-endian in payload bytes 0-1)
    extended.SequenceCounter = (msg.Payload[0] << 8) | msg.Payload[1];
    
    // Copy remaining data
    for (int i = 0; i < 7; i++) {
        extended.Data[i] = msg.Payload[2 + i];
    }
    
    extended.Checksum = (msg.DataLength > 8) ? msg.Payload[8] : 0;
    
    return true;
}

//*****************************************************************************
bool ParseN2kCZoneSwitchState(const tN2kCZoneMessage &msg, tN2kCZoneSwitchState &switchState) {
    if (msg.DeviceType != N2kCZone_MsgType_SwitchState) return false;
    
    switchState.DeviceInstance = msg.DeviceInstance;
    switchState.Timestamp = msg.Timestamp;
    
    // Copy full payload (switch state encoding still being researched)
    for (int i = 0; i < 9; i++) {
        switchState.Payload[i] = msg.Payload[i];
    }
    
    return true;
}

//*****************************************************************************
const char* N2kCZoneGetMessageTypeName(unsigned char msgType) {
    switch(msgType) {
        case N2kCZone_MsgType_Heartbeat: return "Heartbeat";
        case N2kCZone_MsgType_Control: return "Control";
        case N2kCZone_MsgType_Extended: return "Extended";
        case N2kCZone_MsgType_SwitchState: return "SwitchState";
        default: return "Unknown";
    }
}