#ifndef _UTILS_H
#define _UTILS_H

#include <assert.h>
#include <setjmp.h>
#include "unp.h"

#define ARP_FILE    "/tmp-arp"
#define TOUR_FILE   "/tmp-tour-xxxxxx"

#define IPLEN 30
typedef char IP[IPLEN];
typedef struct in_addr IA;

typedef enum {
    TRUE  = 1,
    FALSE = 0
} bool;

int getVmNodeByIP(char *ip);
char* getIPByVmNode(char *ip, int node);
int getHostVmNodeNo();
char* getFullPath(char *fullPath, char *fileName, int size, bool isTemp);
bool isSameIPAddr(IA ip1, IA ip2);

#endif /* !_UTILS_H */
