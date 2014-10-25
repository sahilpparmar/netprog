#ifndef _COMMON_H
#define _COMMON_H

#include <setjmp.h>
#include "unp.h"
#include "unpifiplus.h"

#define SERVER_IN       "server.in"
#define CLIENT_IN       "client.in"
#define PARAM_SIZE      100
#define MAX_RETRANSMIT  12

#define _1TAB    "\t"
#define _2TABS   "\t\t"
#define _3TABS   "\t\t\t"
#define _4TABS   "\t\t\t\t"

char* getStringParamValue(FILE *inp_file, char *paramVal);
int getIntParamValue(FILE *inp_file);
float getFloatParamValue(FILE *inp_file);

int print_ifi_info_plus(struct ifi_info *ifihead);
int verifyIfLocalAndGetHostIP(struct ifi_info *ifihead,
                              struct in_addr *remote_ip,
                              struct in_addr *host_ip);

#endif /* !_COMMON_H */
