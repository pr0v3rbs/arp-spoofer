#include "std.h"
#include <stdio.h>
#include "Print.h"

void PrintIp(/*in*/ char* head, /*in*/ BYTE* ip, /*in*/ char* tail)
{
    printf("%s%d.%d.%d.%d%s", head, ip[0], ip[1], ip[2], ip[3], tail);
}

void PrintMac(/*in*/ char* head, /*in*/ BYTE* mac, /*in*/ char* tail)
{
    printf("%s%02x:%02x:%02x:%02x:%02x:%02x%s", head, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], tail);
}
