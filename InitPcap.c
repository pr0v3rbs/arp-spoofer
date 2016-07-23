#include <stdio.h>
#include <pcap.h>
#include <pthread.h>
#include "InitPcap.h"
#include "AttackInfo.h"

void PacketCallback(u_char* args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // check if dst ip is not me.
    
    // check packet and rely packet;
}

static void *ThreadFunction(void *arg)
{
    pcap_t** handle = arg;

    pcap_loop(*handle, 0, (pcap_handler)PacketCallback, NULL);

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
        *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
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
