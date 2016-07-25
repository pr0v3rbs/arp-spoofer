#ifndef STD_H
#define STD_H

typedef unsigned char BYTE;
#define MAC_LEN 6
#define IP_LEN 4

struct ETH
{
    BYTE dstMac[MAC_LEN];
    BYTE srcMac[MAC_LEN];
    unsigned short type;
};

struct ARP
{
    unsigned short hardwareType;
    unsigned short protocolType;
    BYTE hardwareSize;
    BYTE protocolSize;
    unsigned short opcode;
    BYTE senderHardwareAddr[MAC_LEN];
    BYTE senderProtocolAddr[IP_LEN];
    BYTE targetHardwareAddr[MAC_LEN];
    BYTE targetProtocolAddr[IP_LEN];
};

struct IP
{
    BYTE	ip_hl:4,		/* header length */
		ip_v:4;			/* version */
    BYTE	ip_tos;			/* type of service */
    short	ip_len;			/* total length */
    unsigned short ip_id;		/* identification */
    short	ip_off;			/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
    BYTE	ip_ttl;			/* time to live */
    BYTE	ip_p;			/* protocol */
    unsigned short ip_sum;		/* checksum */
    BYTE srcIp[4];
    BYTE dstIp[4];
};

#endif // STD_H
