#include "std.h"
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include "AttackInfo.h"
#include "Print.h"

int InsertAttackInfo(BYTE* ip, BYTE* mac)
{
    int result = 1;
    int i = 0;

    for (; i < ATTACK_TABLE_MAX; i++)
    {
        if (gAttackInfoArr[i].set == 0)
        {
            gAttackInfoArr[i].set = 1;
            memcpy(gAttackInfoArr[i].ip, ip, IP_LEN);
            memcpy(gAttackInfoArr[i].mac, mac, MAC_LEN);
            break;
        }
    }

    if (i == ATTACK_TABLE_MAX)
        result = 0; // fail

    return result;
}

int IsIpInTable(/*in*/ const u_char* ip, /*out*/ BYTE* mac)
{
    int result = 0;
    int i = 0;

    for (; i < ATTACK_TABLE_MAX; i++)
    {
        if (gAttackInfoArr[i].set == 1 &&
            memcmp(gAttackInfoArr[i].ip, ip, IP_LEN) == 0)
        {
            memcpy(mac, gAttackInfoArr[i].mac, MAC_LEN);
            result = 1;
            break;
        }
    }

    return result;
}

int IsMacInTable(const u_char* mac)
{
    int result = 0;
    int i = 0;

    for (; i < ATTACK_TABLE_MAX; i++)
    {
        if (gAttackInfoArr[i].set == 1 &&
            memcmp(gAttackInfoArr[i].mac, mac, MAC_LEN) == 0)
        {
            result = 1;
            break;
        }
    }

    return result;
}

void PrintAttackInfo()
{
    int i = 0;
    int idx = 1;
    for (; i < ATTACK_TABLE_MAX; i++)
    {
        if (gAttackInfoArr[i].set == 1)
        {
            printf("%d. ", idx++);
            PrintIp("", gAttackInfoArr[i].ip, "\n");
        }
    }
}

int GetAttackInfo(int userIdx, BYTE* ip, BYTE* mac)
{
    int result = -1;
    int i = 0;
    int idx = 1;

    for (; i < ATTACK_TABLE_MAX; i++)
    {
        if (gAttackInfoArr[i].set == 1)
        {
            if (idx == userIdx)
            {
                memcpy(ip, gAttackInfoArr[i].ip, IP_LEN);
                memcpy(mac, gAttackInfoArr[i].mac, MAC_LEN);
                result = 0;
                break;
            }
            idx++;
        }
    }

    return result;
}

int DeleteAttackInfo(int userIdx)
{
    int result = -1;
    int i = 0;
    int idx = 1;

    for (; i < ATTACK_TABLE_MAX; i++)
    {
        if (gAttackInfoArr[i].set == 1)
        {
            if (idx == userIdx)
            {
                gAttackInfoArr[i].set = 0;
                result = 0;
                break;
            }
            idx++;
        }
    }

    return result;
}
