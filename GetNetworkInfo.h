#ifndef GET_NETWORK_INFO_H
#define GET_NETWORK_INFO_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef unsigned char BYTE;

int GetLocalIPAddress(/*out*/ BYTE* ip);

int GetLocalMacAddress(/*out*/ BYTE* mac);

int ConvertAddrToByteIP(/*in*/ char* addr, /*out*/ BYTE* ip);

int GetMacAddress(/*in*/ char* ipStr, /*out*/ BYTE* mac);

int GetMacAddressFromByte(/*in*/ BYTE* ip, /*out*/ BYTE* mac);

int GetGatewayIP(/*out*/ BYTE* ip);

#endif // GET_NETWORK_INO_H
