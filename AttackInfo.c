#include <stdio.h>
#include <string.h>
#include "AttackInfo.h"

int InsertAttackInfo(BYTE* ip, BYTE* mac)
{
    int result = 1;
    int i = 0;

    for (; i < ATTACK_TABLE_MAX; i++)
    {
        if (gAttackInfoArr[i].set == 0)
        {
            gAttackInfoArr[i].set = 1;
            memcpy(gAttackInfoArr[i].ip, ip, 4);
            memcpy(gAttackInfoArr[i].mac, mac, 6);
            break;
        }
    }

    if (i == ATTACK_TABLE_MAX)
        result = 0; // fail

    return result;
}

int DeleteAttackInfo(BYTE* ip)
{
    int result = 1;
    int i = 0;

    for (; i < ATTACK_TABLE_MAX; i++)
    {
        if (!memcmp(gAttackInfoArr[i].ip, ip, 4))
        {
            gAttackInfoArr[i].set = 0;
            break;
        }
    }

    if (i == ATTACK_TABLE_MAX)
        result = 0;

    return result;
}
