#ifndef _ARP_H
#define _ARP_H

#include "utils.h"

#define DEBUG           0
#define PROTOCOL_NUMBER 0x5454
#define IDENT_NUMBER    0x4545
#define HARD_TYPE       ARPHRD_ETHER

#define GET_IDENT_NUM(frame) ((frame)->packet.identNum)
#define GET_HARD_TYPE(frame) ((frame)->packet.hatype)
#define GET_HARD_SIZE(frame) ((frame)->packet.halen)
#define GET_PROT_SIZE(frame) ((frame)->packet.protSize)
#define GET_OP_TYPE(frame)   ((frame)->packet.opType)
#define GET_SRC_IP(frame)    ((frame)->packet.srcIP)
#define GET_DEST_IP(frame)   ((frame)->packet.destIP)
#define GET_SRC_MAC(frame)   ((frame)->packet.srcMAC)
#define GET_DEST_MAC(frame)  ((frame)->packet.destMAC)

// ARP OP feild type
typedef enum {
    REQUEST = 1,
    REPLY   = 2
} ARPOpType;

// ARP Packet
typedef struct {
    uint16_t identNum;
    uint16_t hatype;
    uint16_t protocol;
    uint8_t halen;
    uint8_t protSize;
    uint16_t opType;
    char srcMAC[IF_HADDR];
    IA srcIP;
    char destMAC[IF_HADDR];
    IA destIP;
} ARPPacket;

// Ethernet Frame
typedef struct {
    uint8_t destMAC[IF_HADDR];
    uint8_t srcMAC[IF_HADDR];
    uint16_t protocol;
    ARPPacket packet;
} EthernetFrame;

typedef struct {
    bool isValid;
    IA ipAddr;
    char hwAddr[IF_HADDR];
    int ifindex;
    uint16_t hatype;
    int connfd;
} ARPCache;

ARPCache* searchARPCache(IA ipAddr);
void invalidateCache(IA ipAddr); 
bool updateARPCache(IA ipAddr, char *hwAddr, int ifindex, uint8_t hatype,
                    int connfd, bool forceUpdate);

void readUnixSocket(int connfd, IA *destIPAddr, int *ifindex,
                    uint16_t *hatype, uint8_t *halen);
void writeUnixSocket(int connfd, char *hwaddr);

#endif /* !_ARP_H */
