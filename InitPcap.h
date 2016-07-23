#ifndef INIT_PCAP_H
#define INIT_PCAP_H

#include <stdio.h>
#include <pcap.h>

void PacketCallback(u_char* args, const struct pcap_pkthdr *header, const u_char *packet);

static void *ThreadFunction(void *arg);

int InitPcap(pcap_t** handle);

#endif // INIT_PCAP_H
