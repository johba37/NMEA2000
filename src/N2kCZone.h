/*
N2kCZone.h

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
Provides basic on/off switching functionality for CZONE digital switching systems.

Based on reverse engineering of CZONE protocol:
- CZONE uses standard NMEA2000 message format with proprietary PGNs 65282-65287
- Previous assumption that "93 13 XX" was CZONE protocol was incorrect - that's NGT-1 framing
- Message structure analysis ongoing:
  - Uses proprietary PGN range 65282-65287 for switch control
  - Message payload structure still being reverse-engineered
  - Contains device timestamps and switch state information
*/

#ifndef N2kCZone_h
#define N2kCZone_h

#include "N2kMessages.h"
#include "N2kMsg.h"
#include "N2kTypes.h"

//*****************************************************************************
// CZONE Constants
//*****************************************************************************

// CZONE manufacturer code (Mastervolt)
#define N2kCZone_ManufacturerCode 355

// CZONE proprietary PGNs (discovered through network analysis)
#define N2kCZone_PGN_SwitchStatus    65282  // Switch bank status reports
#define N2kCZone_PGN_SwitchControl   65283  // Switch bank control commands
#define N2kCZone_PGN_Configuration   65284  // Configuration messages
#define N2kCZone_PGN_Extended1       65285  // Extended functionality
#define N2kCZone_PGN_Extended2       65286  // Extended functionality
#define N2kCZone_PGN_Extended3       65287  // Extended functionality

// CZONE switch control PGN (discovered through reverse engineering)  
#define N2kCZone_PGN_SwitchControlCmd 65280  // Direct switch control commands

// CZONE proprietary message header
#define N2kCZone_ProprietaryHeader1  0x93
#define N2kCZone_ProprietaryHeader2  0x13

// CZONE switch states
enum tN2kCZoneOnOff {
  N2kCZoneOnOff_Off = 0,
  N2kCZoneOnOff_On = 1,
  N2kCZoneOnOff_Error = 2,
  N2kCZoneOnOff_Unavailable = 3
};

// CZONE switch control commands (discovered through reverse engineering)
enum tN2kCZoneSwitchCommand {
  N2kCZoneSwitchCmd_On = 0xF1,      // Set switch ON
  N2kCZoneSwitchCmd_Off = 0xF4,     // Set switch OFF  
  N2kCZoneSwitchCmd_Toggle = 0xF2   // Toggle switch state
};

// Common CZONE device address ranges (observed in various installations)
// Note: Actual addresses vary by installation and configuration
// These are examples only - use device discovery to find your actual addresses
enum tN2kCZoneAddressExamples {
  N2kCZone_AddressRange_Start = 0x01,
  N2kCZone_AddressRange_End = 0xFF
  // Common observed addresses include: 0x12, 0x13, 0x19, 0x46
  // but these are NOT universal - they depend on your specific setup
};

// Example device addresses (from development environment - may vary by installation)
#define N2kCZone_PrimarySwitchBank 0x12  // Example: Primary switch bank
#define N2kCZone_Module1           0x13  // Example: Secondary switch bank  
#define N2kCZone_Module2           0x19  // Example: Unknown module
#define N2kCZone_Module3           0x46  // Example: Control panel

// CZONE Message Types (discovered through protocol analysis)
#define N2kCZone_MsgType_Heartbeat    0x09  // High-frequency status from all devices
#define N2kCZone_MsgType_Control      0x23  // From control panels and device 0x19
#define N2kCZone_MsgType_Extended     0x24  // Extended data with sequence counter (PGN 65282 only)
#define N2kCZone_MsgType_SwitchState  0x64  // From physical switch banks (PGN 65283 only)

//*****************************************************************************
// CZONE Message Structure (from structural analysis)
//*****************************************************************************

// CZONE Message Structure (17 bytes total) - CONFIRMED:
// Byte 0: Device Instance (often 0x01)
// Byte 1: 0xFF (CZONE header marker)  
// Byte 2: Device Type (varies by device)
// Bytes 3-6: 32-bit LITTLE-ENDIAN timestamp (10Hz/100ms ticks)
// Byte 7: 0x08 (data length indicator)
// Bytes 8-16: Payload data (9 bytes, purpose/encoding unknown)

struct tN2kCZoneMessage {
  unsigned char DeviceInstance;    // Byte 0: Instance/version byte
  unsigned char Header;            // Byte 1: Always 0xFF
  unsigned char DeviceType;        // Byte 2: Message type identifier (0x09, 0x24, 0x23, 0x64)
  uint32_t Timestamp;              // Bytes 3-6: 32-bit LE timestamp (100ms resolution)
  unsigned char DataLength;        // Byte 7: Always 0x08
  unsigned char Payload[9];        // Bytes 8-16: Payload data (type-specific)
};

// Type-specific message structures (for detailed parsing)
struct tN2kCZoneHeartbeat {      // Message type 0x09
  unsigned char DeviceInstance;
  uint32_t Timestamp;
  unsigned char Counter;         // Increments with each heartbeat (payload byte 2)
  unsigned char FixedData[6];    // Usually: 11 ff 7f ff 7f fd
  unsigned char Checksum;
};

struct tN2kCZoneExtended {       // Message type 0x24
  unsigned char DeviceInstance;
  uint32_t Timestamp;
  uint16_t SequenceCounter;      // 16-bit sequence counter (payload bytes 0-1)
  unsigned char Data[7];         // Remaining payload data
  unsigned char Checksum;
};

struct tN2kCZoneSwitchState {    // Message type 0x64
  unsigned char DeviceInstance;
  uint32_t Timestamp;
  unsigned char Payload[9];      // Switch state encoding (still being researched)
};

//*****************************************************************************
// CZONE Switch Bank Functions
//*****************************************************************************

/************************************************************************//*!
 * \brief Check if this message is a CZONE proprietary message
 * 
 * This function checks for the CZONE proprietary message format:
 * 93 13 XX where XX is the PGN offset (02-07)
 * 
 * \param RawData     Raw message bytes
 * \param DataLen     Length of raw data
 * 
 * \return true     Message is CZONE proprietary format
 * \return false    Message is not CZONE format
 */
bool N2kIsCZoneProprietaryMessage(const unsigned char* RawData, int DataLen);

/************************************************************************//*!
 * \brief Parse CZONE proprietary message format
 * 
 * Parses the CZONE proprietary format: 93 13 XX SS DD [data...]
 * - Bytes 0-1: 93 13 (CZONE header)
 * - Byte 2: PGN offset (0x02-0x07 → PGNs 65282-65287)
 * - Byte 3: Source address
 * - Byte 4: Destination address
 * - Byte 5+: Data payload
 * 
 * \param RawData     Raw message bytes
 * \param DataLen     Length of raw data
 * \param PGN         Output: Calculated PGN (65282-65287)
 * \param Source      Output: Source address
 * \param Destination Output: Destination address
 * \param PayloadData Output: Pointer to payload data
 * \param PayloadLen  Output: Length of payload data
 * 
 * \return true     Parsing successful
 * \return false    Parsing failed
 */
bool ParseN2kCZoneProprietaryMessage(const unsigned char* RawData, int DataLen,
                                     unsigned long &PGN, unsigned char &Source, 
                                     unsigned char &Destination,
                                     const unsigned char* &PayloadData, int &PayloadLen);

/************************************************************************//*!
 * \brief Check if this message is from a CZONE device
 * 
 * This function checks if a message originated from a known CZONE device
 * by checking source addresses against known CZONE devices
 * 
 * \param Source      Source address from message
 * 
 * \return true     Source is known CZONE device
 * \return false    Source is not CZONE device
 */
bool N2kIsCZoneDevice(unsigned char Source);

/************************************************************************//*!
 * \brief Helper function to create CZONE proprietary message
 * 
 * Creates a message with CZONE proprietary format for sending commands
 * 
 * \param N2kMsg      Output: NMEA2000 message
 * \param PGN         CZONE PGN (65282-65287)
 * \param Source      Source address
 * \param Destination Destination address
 * \param PayloadData Data payload
 * \param PayloadLen  Length of payload
 */
void SetN2kCZoneProprietaryMessage(tN2kMsg &N2kMsg, unsigned long PGN,
                                   unsigned char Source, unsigned char Destination,
                                   const unsigned char* PayloadData, int PayloadLen);

/************************************************************************//*!
 * \brief Create CZONE switch control message
 * 
 * Creates a CZONE proprietary switch control message for sending switch
 * commands to CZONE switch banks. This function handles the proper CZONE
 * protocol formatting automatically.
 * 
 * \param N2kMsg      Output: NMEA2000 message 
 * \param SwitchNum   Switch number (1-20, device dependent)
 * \param Command     Switch command (On/Off/Toggle)
 * \param Destination CZONE device address (e.g., N2kCZone_PrimarySwitchBank)
 * \param Source      Source address (optional, defaults to broadcast)
 * 
 * \note Switch control success depends on CZONE network configuration
 * \note Not all CZONE installations accept external switch commands
 */
void SetN2kCZoneSwitchControlMessage(tN2kMsg &N2kMsg, unsigned char SwitchNum,
                                     tN2kCZoneSwitchCommand Command,
                                     unsigned char Destination,
                                     unsigned char Source = 0xFF);

/************************************************************************//*!
 * \brief Parse CZONE PGN 65282 switch status message
 * 
 * Parses the 17-byte CZONE switch status message based on structural analysis:
 * - Header (bytes 0-7): Device info, timestamps, padding
 * - Payload (bytes 8-15): Device-specific data 
 * - Byte 16: Variable - may contain switch states, checksum, or other data
 * 
 * \param RawData         Raw 17-byte message data
 * \param DataLen         Should be 17 bytes
 * \param CZoneMsg        Output: Parsed message structure
 * 
 * \return true     Parsing successful
 * \return false    Invalid data length or format
 */
bool ParseN2kCZonePGN65282(const unsigned char* RawData, int DataLen, tN2kCZoneMessage &CZoneMsg);

/************************************************************************//*!
 * \brief Parse CZONE heartbeat message (type 0x09)
 * 
 * \param msg         Parsed CZONE message
 * \param heartbeat   Output: Heartbeat-specific data
 * 
 * \return true     Parsing successful
 * \return false    Wrong message type or invalid data
 */
bool ParseN2kCZoneHeartbeat(const tN2kCZoneMessage &msg, tN2kCZoneHeartbeat &heartbeat);

/************************************************************************//*!
 * \brief Parse CZONE extended message (type 0x24)
 * 
 * \param msg         Parsed CZONE message
 * \param extended    Output: Extended message data with sequence counter
 * 
 * \return true     Parsing successful
 * \return false    Wrong message type or invalid data
 */
bool ParseN2kCZoneExtended(const tN2kCZoneMessage &msg, tN2kCZoneExtended &extended);

/************************************************************************//*!
 * \brief Parse CZONE switch state message (type 0x64)
 * 
 * \param msg         Parsed CZONE message  
 * \param switchState Output: Switch state data (encoding still being researched)
 * 
 * \return true     Parsing successful
 * \return false    Wrong message type or invalid data
 */
bool ParseN2kCZoneSwitchState(const tN2kCZoneMessage &msg, tN2kCZoneSwitchState &switchState);

/************************************************************************//*!
 * \brief Get message type name for debugging
 * 
 * \param msgType     Message type (0x09, 0x24, 0x23, 0x64)
 * 
 * \return const char* Human-readable message type name
 */
const char* N2kCZoneGetMessageTypeName(unsigned char msgType);

/************************************************************************//*!
 * \brief Get switch states from CZONE message
 * 
 * Attempts to extract switch states from CZONE messages.
 * The location and encoding of switch states varies by device type
 * and configuration. This is a generic interface that implementations
 * must customize for their specific CZONE setup.
 * 
 * \param CZoneMsg        Parsed CZONE message
 * \param SwitchStates    Output: Switch states (device-specific encoding)
 * 
 * \return true     Switch states extracted
 * \return false    Unable to extract switch states
 */
bool GetN2kCZoneSwitchStates(const tN2kCZoneMessage &CZoneMsg, unsigned char &SwitchStates);

#endif