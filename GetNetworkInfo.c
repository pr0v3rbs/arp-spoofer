#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "AttackInfo.h"
#include "GetNetworkInfo.h"

BYTE ConvertStrToByte(char c1, char c2)
{
    BYTE numHigh, numLow;

    if ('0' <= c1 && c1 <= '9')
        numHigh = c1 - '0';
    else if ('a' <= c1 && c1 <= 'z')
        numHigh = c1 - 'a' + 10;
    else
        numHigh = c1 - 'A' + 10;

    if ('0' <= c2 && c2 <= '9')
        numLow = c2 - '0';
    else if ('a' <= c2 && c2 <= 'z')
        numLow = c2 - 'a' + 10;
    else
        numLow = c2 - 'A' + 10;

    return (numHigh << 4) + numLow;
}

int ConvertAddrToByteIP(/*in*/ char* addr, /*out*/ BYTE* ip)
{
    int result = 0;
    struct in_addr structAddr;

    if (result = inet_aton(addr, &structAddr))
    {
        ip[3] = (structAddr.s_addr & 0xff000000) >> 24;
        ip[2] = (structAddr.s_addr & 0x00ff0000) >> 16;
        ip[1] = (structAddr.s_addr & 0x0000ff00) >> 8;
        ip[0] = (structAddr.s_addr & 0x000000ff);
    }

    return result;
}

int GetLocalMacAddress(/*out*/ BYTE* mac)
{
    int result = 0;
    FILE* fp;
    char macStr[17] = "";

    if (fp = popen("ifconfig eth0 | egrep -io \"([0-9a-fA-F]{2}[:]){5}([0-9a-fA-F]{2})\"", "r"))
    {
        if (fread(macStr, 17, 1, fp) > 0)
        {
            mac[0] = ConvertStrToByte(macStr[0], macStr[1]);
            mac[1] = ConvertStrToByte(macStr[3], macStr[4]);
            mac[2] = ConvertStrToByte(macStr[6], macStr[7]);
            mac[3] = ConvertStrToByte(macStr[9], macStr[10]);
            mac[4] = ConvertStrToByte(macStr[12], macStr[13]);
            mac[5] = ConvertStrToByte(macStr[15], macStr[16]);
            result = 1;
        }
    }

    return result;
}

int GetMacAddress(/*in*/ char* ipStr, /*out*/ BYTE* mac)
{
    int result = 0;
    FILE* fp;
    char command[100] = "arping -I eth0 ";
    char data[17];

    strcat(command, ipStr);
    strcat(command, " -c 1 | egrep -io \"([0-9a-fA-F]{2}[:]){5}([0-9a-fA-F]{2})\"");

    fp = popen(command, "r");
    if (fp && fread(data, 17, 1, fp) > 0)
    {
        mac[0] = ConvertStrToByte(data[0], data[1]);
        mac[1] = ConvertStrToByte(data[3], data[4]);
        mac[2] = ConvertStrToByte(data[6], data[7]);
        mac[3] = ConvertStrToByte(data[9], data[10]);
        mac[4] = ConvertStrToByte(data[12], data[13]);
        mac[5] = ConvertStrToByte(data[15], data[16]);
        result = 1;
    }

    return result;
}

int GetMacAddressFromByte(/*in*/ BYTE* ip, /*out*/ BYTE* mac)
{
    char ipStr[20];

    sprintf(ipStr, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

    return GetMacAddress(ipStr, mac);
}

int GetGatewayIP(/*out*/ BYTE* ip)
{
    int result = 0;
    FILE* fp;
    char* line = NULL;
    size_t len = 0;

    if (fp = popen("route -n|grep \"UG\"|grep -v \"UGH\"|cut -f 10 -d \" \"", "r"))
    {
        if (getline(&line, &len, fp) != -1)
        {
            if (ConvertAddrToByteIP(line, ip))
            {
                result = 1;
            }
            free(line);
        }
    }

    return result;
}
