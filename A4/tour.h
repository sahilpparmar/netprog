#ifndef _TOUR_H
#define _TOUR_H

#include "utils.h"

#define MAXHOPS 100
#define IPPROTO_TOUR 154 // Between 143-252
#define UNIQ_ID 101
#define TTL_OUT 1

/*
    ########################### TOUR Message format ######################
    | IP Multicast Address | Port number | Current Index | IP LIST       |
    | STRING NUMBER        |   UINT_16   |   UINT_16     | ARRAY IP[MAX] |
    |#####################################################################
*/

typedef struct {
    IP multicastIP;
    uint16_t multicastPort;
    uint16_t curIndex;
    IP tourList[MAXHOPS];
} TourPayload; //TODO include iphdr

#endif /* !_TOUR_H */
