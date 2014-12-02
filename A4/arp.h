#ifndef _ARP_H
#define _ARP_H

#include "utils.h"
#include "hw_addrs.h"

#define PROTOCOL_NUMBER 0x5454

typedef struct {
    IP ipaddr;
    char hwaddr[IF_HADDR];
} Eth0AddrPairs;

#endif /* !_ARP_H */
