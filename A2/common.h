#ifndef _COMMON_H
#define _COMMON_H

#include <setjmp.h>
#include "unp.h"
#include "unpifiplus.h"

#define SERVER_IN       "server.in"
#define CLIENT_IN       "client.in"
#define PARAM_SIZE      100
#define MAX_RETRANSMIT  12
#define MAX_PAYLOAD 500 // bytes
#define HEADER_LEN 12 // bytes
#define DATAGRAM_SIZE 512


typedef struct {
    unsigned int seqNum; // 32 bits
    unsigned int ackNum; // 32 bits
    unsigned int winSize; // 32 bits
    char data[MAX_PAYLOAD]; // max 500
}tcpPckt; // Total size: 512


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


int fillPckt(tcpPckt *packet, unsigned int seqNum, unsigned int ackNum, unsigned int winSize, char* dataPtr, int len);
int readPckt(tcpPckt *packet, int packet_size, unsigned int *seqNum, unsigned int *ackNum, unsigned int *winSize, char* dataPtr); 
#endif /* !_COMMON_H */
