#ifndef _TOUR_H
#define _TOUR_H

#include "utils.h"
#include <netinet/ip.h>

#define MAXHOPS         100    // hops
#define IPPROTO_TOUR    154    // Between 143-252
#define UNIQ_ID         0x6565
#define TTL_OUT         1
#define AREQ_TIMEOUT    5      // sec
#define PING_TIMEOUT    1      // sec
#define PING_COUNTDOWN  5
#define MULTICAST_IP    "234.245.210.123"
#define MULTICAST_PORT  9850
#define MAX_BUF         1000
#define READ_TIMEOUT    5

/*
    ########################### TOUR Message format ######################
    | IP Multicast Address | Port number | Current Index | IP LIST       |
    | STRING NUMBER        |   UINT_16   |   UINT_16     | ARRAY IP[MAX] |
    |#####################################################################
*/

typedef struct {
    IA multicastIP;
    uint16_t multicastPort;
    uint16_t curIndex;
    IA tourList[MAXHOPS];
} TourPayload;

typedef struct {
    struct ip iphead;
    TourPayload payload;
} IPPacket;

typedef struct {
    int      sll_ifindex;    /* Interface number */
    uint16_t sll_hatype;     /* Hardware type */
    uint8_t  sll_halen;      /* Length of address */
    uint8_t  sll_addr[8];    /* Physical layer address */
} HWAddr;

int areq(SA *IPaddr, socklen_t salen, HWAddr *hwaddr);

#endif /* !_TOUR_H */
