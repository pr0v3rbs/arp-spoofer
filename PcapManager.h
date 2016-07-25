#ifndef PCAP_MANAGER_H
#define PCAP_MANAGER_H

#include <stdio.h>
#include <pcap.h>

void MakeArpReplyPacket(BYTE* localMac, BYTE* victimMac, BYTE* arpSenderMac, BYTE* arpSenderIp, BYTE* arpTargetIp, BYTE* packet);

void PacketCallback(u_char* args, const struct pcap_pkthdr *header, const u_char *packet);

static void *ThreadFunction(void *arg);

int InitPcap(pcap_t** handle);

#endif // PCAP_MANAGER_H
