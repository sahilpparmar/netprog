#ifndef _UTILS_H
#define _UTILS_H

#include <assert.h>
#include <setjmp.h>
#include "unp.h"

#define IPLEN 30
typedef char IP[IPLEN];

int getVmNodeByIP(char *ip);
char* getIPByVmNode(char *ip, int node);
int getHostVmNodeNo();

#endif /* !_UTILS_H */
