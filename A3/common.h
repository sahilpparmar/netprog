#ifndef _COMMON_H
#define _COMMON_H

#include <assert.h>
#include <setjmp.h>
#include "unp.h"

#define _1TAB   "\t"
#define _2TABS  "\t\t"
#define _3TABS  "\t\t\t"
#define _4TABS  "\t\t\t\t"

#define KRED    "\x1B[31m"
#define KGRN    "\x1B[32m"
#define KYEL    "\x1B[33m"
#define KBLU    "\x1B[34m"
#define KMAG    "\x1B[35m"
#define KCYM    "\x1B[36m"
#define KWHT    "\x1B[37m"
#define RESET   "\033[0m"

#define ODR_FILE    "/tmp-odr"
#define SER_FILE    "/tmp-server"
#define CLI_FILE    "/tmp-client-XXXXXX"
#define SER_PORT    13
#define CLI_TIMEOUT 5
#define TOTAL_VMS   10

typedef enum {
    TRUE  = 1,
    FALSE = 0
} bool;

char* getFullPath(char *fullPath, char *fileName, int size, bool isTemp);
int getVmNodeByIP(char *ip);
char* getIPByVmNode(char *ip, int node);
int getHostVmNodeNo();
int createAndBindUnixSocket(char *filePath);

#endif /* !_COMMON_H */
