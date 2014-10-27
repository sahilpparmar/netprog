#ifndef _COMMON_H
#define _COMMON_H

#include <setjmp.h>
#include "unp.h"
#include "unpifiplus.h"

#define _1TAB    "\t"
#define _2TABS   "\t\t"
#define _3TABS   "\t\t\t"
#define _4TABS   "\t\t\t\t"

#define SERVER_IN       "server.in"
#define CLIENT_IN       "client.in"
#define PARAM_SIZE      100
#define MAX_RETRANSMIT  12

#define HEADER_LEN      12
#define MAX_PAYLOAD     500
#define DATAGRAM_SIZE   512

#define SYN_SEQ_NO      1
#define SYN_ACK_SEQ_NO  2
#define ACK_SEQ_NO      3
#define DATA_SEQ_NO     11

typedef struct {
    unsigned int seqNum;    // 4 bytes
    unsigned int ackNum;    // 4 bytes
    unsigned int winSize;   // 4 bytes
    char data[MAX_PAYLOAD]; // 500 bytes
} TcpPckt;                  // Total size: 512

char* getStringParamValue(FILE *inp_file, char *paramVal);
int getIntParamValue(FILE *inp_file);
float getFloatParamValue(FILE *inp_file);

int print_ifi_info_plus(struct ifi_info *ifihead);
int verifyIfLocalAndGetHostIP(struct ifi_info *ifihead,
                              struct in_addr *remote_ip,
                              struct in_addr *host_ip);


int fillPckt(TcpPckt *packet, unsigned int seqNum, unsigned int ackNum,
        unsigned int winSize, char* dataPtr, int len);
int readPckt(TcpPckt *packet, int packet_size, unsigned int *seqNum,
        unsigned int *ackNum, unsigned int *winSize, char* dataPtr);

#endif /* !_COMMON_H */
