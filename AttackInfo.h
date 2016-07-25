#ifndef ATTACK_INFO_H
#define ATTACK_INFO_H

#define ATTACK_TABLE_MAX 10

struct AttackInfo
{
    int set;
    BYTE ip[IP_LEN];
    BYTE mac[MAC_LEN];
};

struct AttackInfo gAttackInfoArr[ATTACK_TABLE_MAX];
struct AttackInfo gateway;

int InsertAttackInfo(BYTE* ip, BYTE* mac);

int IsIpInTable(/*in*/ const u_char* ip, /*out*/ BYTE* mac);

int IsMacInTable(const u_char* mac);

void PrintAttackTable();

int GetAttackInfo(int userIdx, BYTE* ip, BYTE* mac);

int DeleteAttackInfo(int userIdx);

#endif // ATTACK_INFO_H
