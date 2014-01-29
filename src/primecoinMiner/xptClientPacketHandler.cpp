#include"global.h"
#include"ticker.h"
#include <inttypes.h>
#include <iostream>
/*
 * Called when a packet with the opcode XPT_OPC_S_AUTH_ACK is received
 */
bool xptClient_processPacket_authResponse(xptClient_t* xptClient)
{
	xptPacketbuffer_t* cpb = xptClient->recvBuffer;
	// read data from the packet
	xptPacketbuffer_beginReadPacket(cpb);
	// start parsing
	bool readError = false;
	// read error code field
	uint32 authErrorCode = xptPacketbuffer_readU32(cpb, &readError);
	if( readError )
		return false;
	// read reject reason / motd
	char rejectReason[512];
	xptPacketbuffer_readString(cpb, rejectReason, 512, &readError);
	rejectReason[511] = '\0';
	if( readError )
		return false;
	if( authErrorCode == 0 )
	{
		xptClient->clientState = XPT_CLIENT_STATE_LOGGED_IN;
			std::cout << "xpt: Logged in" << std::endl;
			if( rejectReason[0] != '\0' )
				std::cout << "Message from server: " << rejectReason << std::endl;
		// start ping mechanism
		xptClient->time_sendPing = (uint32)time(NULL) + 60; // first ping after one minute
	}
	else
	{
		// error logging in -> disconnect
			std::cout << "xpt: Failed to log in" << std::endl;
		if( rejectReason[0] != '\0' )
			std::cout << "Reason: " << rejectReason << std::endl;
		return false;
	}
	return true;
}

/*
 * Called when a packet with the opcode XPT_OPC_S_WORKDATA1 is received
 * This is the first version of xpt 'getwork'
 */
bool xptClient_processPacket_blockData1(xptClient_t* xptClient)
{
	// parse block data
	bool recvError = false;
	xptPacketbuffer_beginReadPacket(xptClient->recvBuffer);
	xptClient->workDataValid = false;
	// add general block info
	xptClient->blockWorkInfo.version = xptPacketbuffer_readU32(xptClient->recvBuffer, &recvError);			// version
	xptClient->blockWorkInfo.height = xptPacketbuffer_readU32(xptClient->recvBuffer, &recvError);			// block height
	xptClient->blockWorkInfo.nBits = xptPacketbuffer_readU32(xptClient->recvBuffer, &recvError);			// nBits
	xptClient->blockWorkInfo.nBitsShare = xptPacketbuffer_readU32(xptClient->recvBuffer, &recvError);		// nBitsRecommended / nBitsShare
	xptClient->blockWorkInfo.nTime = xptPacketbuffer_readU32(xptClient->recvBuffer, &recvError);			// nTimestamp
	xptPacketbuffer_readData(xptClient->recvBuffer, xptClient->blockWorkInfo.prevBlock, 32, &recvError);	// prevBlockHash

	// New in xpt version 6 - Targets are send in compact format (4 bytes instead of 32)
//    uint32 targetCompact = xptPacketbuffer_readU32(xptClient->recvBuffer, &recvError);
//    uint32 targetShareCompact = xptPacketbuffer_readU32(xptClient->recvBuffer, &recvError);
//    xptClient_getDifficultyTargetFromCompact(targetCompact, (uint32*)xptClient->blockWorkInfo.target);
//    xptClient_getDifficultyTargetFromCompact(targetShareCompact, (uint32*)xptClient->blockWorkInfo.targetShare);
	
	
	
	uint32 payloadNum = xptPacketbuffer_readU32(xptClient->recvBuffer, &recvError);							// payload num
	if( recvError )
	{
			std::cout << "xptClient_processPacket_blockData1(): Parse error" << std::endl;
		return false;
	}
	if( xptClient->payloadNum != payloadNum )
	{
			std::cout << "xptClient_processPacket_blockData1(): Invalid payloadNum" << std::endl;
		return false;
	}
	for(uint32 i=0; i<payloadNum; i++)
	{
		// read merkle root for each work data entry
		xptPacketbuffer_readData(xptClient->recvBuffer, xptClient->workData[i].merkleRoot, 32, &recvError);
	}
	if( recvError )
	{
			std::cout << "xptClient_processPacket_blockData1(): Parse error 2" << std::endl;
		return false;
	}
	xptClient->workDataValid = true;
	xptClient->workDataCounter++;
	return true;
}

/*
 * Called when a packet with the opcode XPT_OPC_S_SHARE_ACK is received
 */
bool xptClient_processPacket_shareAck(xptClient_t* xptClient)
{
	xptPacketbuffer_t* cpb = xptClient->recvBuffer;
	// read data from the packet
	xptPacketbuffer_beginReadPacket(cpb);
	// start parsing
	bool readError = false;
	// read error code field
	uint32 shareErrorCode = xptPacketbuffer_readU32(cpb, &readError);
	if( readError )
		return false;
	// read reject reason
	char rejectReason[512];
	xptPacketbuffer_readString(cpb, rejectReason, 512, &readError);
	rejectReason[511] = '\0';
	float shareValue = xptPacketbuffer_readFloat(cpb, &readError);
	if( readError )
		return false;
	if( shareErrorCode == 0 )
	{
		total_shares++;
		valid_shares++;
		time_t now = time(0);
		char* dt = ctime(&now);
			std::cout << "ACCEPTED [ " << valid_shares << " / " << total_shares << " val: " << shareValue << "] " << dt << std::endl;
		primeStats.fShareValue += shareValue;
		primeStats.fBlockShareValue += shareValue;
		primeStats.fTotalSubmittedShareValue += shareValue;
	}
	else
	{
		// error logging in -> disconnect
		total_shares++;
			std::cout << "Invalid share" << std::endl;
			if( rejectReason[0] != '\0' )
				std::cout << "Reason: " << rejectReason << std::endl;
	}
	return true;
}


/*
 * Called when a packet with the opcode XPT_OPC_S_MESSAGE is received
 */
bool xptClient_processPacket_message(xptClient_t* xptClient)
{
        xptPacketbuffer_t* cpb = xptClient->recvBuffer;
        // read data from the packet
        xptPacketbuffer_beginReadPacket(cpb);
        // start parsing
        bool readError = false;
        // read type field (not used yet)
        uint32 messageType = xptPacketbuffer_readU8(cpb, &readError);
        if( readError )
                return false;
        // read message text (up to 1024 bytes)
        char messageText[1024];
        xptPacketbuffer_readString(cpb, messageText, 1024, &readError);
        messageText[1023] = '\0';
        if( readError )
                return false;
        printf("Server message: %s\n", messageText);
        return true;
}

/*
 * Called when a packet with the opcode XPT_OPC_S_PING is received
 */
bool xptClient_processPacket_ping(xptClient_t* xptClient)
{
  xptPacketbuffer_t* cpb = xptClient->recvBuffer;
  // read data from the packet
  xptPacketbuffer_beginReadPacket(cpb);
  // start parsing
  bool readError = false;
  // read timestamp
  uint64 timestamp = xptPacketbuffer_readU64(cpb, &readError);
  if( readError )
    return false;
  // get current high precision time and frequency
  uint64 timestampNow = getTimeHighRes();
  // calculate time difference in ms
	uint64 timeDif = timestampNow - timestamp;
#ifdef _WIN32
  timeDif *= 10000ULL;
  timeDif /= getTimerRes();
#else
	timeDif /= 100000;
#endif
  // update and calculate simple average
  xptClient->pingSum += timeDif;
  xptClient->pingCount++;
  double averagePing = (double)xptClient->pingSum / (double)xptClient->pingCount / 10.0;
  printf("Ping %d.%dms (Average %.1lf)\n", (sint32)(timeDif/10), (sint32)(timeDif%10), averagePing);
  return true;
}
