#include "api.h"

void readUnixSocket(int connfd, IA *destIPAddr, int *ifindex,
                    uint16_t *hatype, uint8_t *halen)
{
    SendToARP readData;
    Read(connfd, &readData, sizeof(readData));
    destIPAddr->s_addr = readData.ipaddr.s_addr;
    *ifindex           = readData.ifindex;
    *hatype            = readData.hatype;
    *halen             = readData.halen;
}

void writeUnixSocket(int connfd, char *hwaddr) {
    ReceiveFromARP writeData;
    memcpy(&writeData, hwaddr, IF_HADDR);
    Writen(connfd, &writeData, sizeof(writeData));
}

