#ifndef _API_H
#define _API_H

#include "utils.h"

typedef struct {
    IA ipaddr;
    int ifindex;
    uint16_t hatype;
    uint8_t halen;
} SendToARP;

typedef struct {
    char hwaddr[IF_HADDR];
} ReceiveFromARP;

#endif /* !_API_H */
