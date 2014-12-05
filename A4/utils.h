#ifndef _UTILS_H
#define _UTILS_H

#include <assert.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include "unp.h"
#include "hw_addrs.h"

#define CLIENT_IN "tour.in"
#define ARP_FILE    "/tmp-arp"
#define TOUR_FILE   "/tmp-tour-xxxxxx"

#define IPLEN 30
#define PARAM_SIZE 10
typedef char IP[IPLEN];
typedef struct in_addr IA;

typedef enum {
    TRUE  = 1,
    FALSE = 0
} bool;

char* getVmNameByIPAddr(IA ipAddr);
char* getIPStrByVmNode(char *ip, int node);
char* getIPStrByIPAddr(IA ipAddr);
IA getIPAddrByIPStr(char *ipStr);
IA getIPAddrByVmNode(int node);
int getHostVmNodeNo();
char* getFullPath(char *fullPath, char *fileName, int size, bool isTemp);
bool isSameIPAddr(IA ip1, IA ip2);
char* ethAddrNtoP(char *nMAC);

#endif /* !_UTILS_H */
