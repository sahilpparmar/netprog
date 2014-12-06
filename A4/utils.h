#ifndef _UTILS_H
#define _UTILS_H

#include <assert.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include "unp.h"
#include "hw_addrs.h"

#define ARP_FILE    "/tmp-arp"
#define IPLEN       30
#define MAX_NODES   10

typedef char IP[IPLEN];
typedef struct in_addr IA;

typedef enum {
    TRUE  = 1,
    FALSE = 0
} bool;

typedef struct {
    IA ipaddr;
    char hwaddr[IF_HADDR];
} Eth0AddrPairs;

int getVmNodeByIPAddr(IA ipAddr);
char* getIPStrByVmNode(char *ip, int node);
char* getIPStrByIPAddr(IA ipAddr);
IA getIPAddrByIPStr(char *ipStr);
IA getIPAddrByVmNode(int node);
int getHostVmNodeNo();
char* getFullPath(char *fullPath, char *fileName, int size, bool isTemp);
bool isSameIPAddr(IA ip1, IA ip2);
char* ethAddrNtoP(char *nMAC);
int getEth0IfaceAddrPairs(Eth0AddrPairs *eth0AddrPairs);
char* curTimeStr();
uint16_t in_cksum(uint16_t *addr, int len);
void tv_sub(struct timeval *out, struct timeval *in);

#endif /* !_UTILS_H */
