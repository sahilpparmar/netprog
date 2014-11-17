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

typedef enum {
    TRUE  = 1,
    FALSE = 0
} bool;

extern char canonicalIP[11][100];
char* getFullPath(char *fullPath, char *fileName, int size, bool isTemp);
int getHostVmNodeNo();

void msg_send(int sockfd, char *destIP, int destPort, char *msg, int forceRediscovery);
int msg_recv(int sockfd, char *msg, char *srcIP, int *srcPort);

#endif /* !_COMMON_H */
