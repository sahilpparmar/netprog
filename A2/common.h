#ifndef _COMMON_H
#define _COMMON_H

#include <assert.h>
#include <setjmp.h>
#include "unp.h"
#include "unpifiplus.h"

#define _1TAB           "\t"
#define _2TABS          "\t\t"
#define _3TABS          "\t\t\t"
#define _4TABS          "\t\t\t\t"

#define KRED            "\x1B[31m"
#define KGRN            "\x1B[32m"
#define KYEL            "\x1B[33m"
#define KBLU            "\x1B[34m"
#define KMAG            "\x1B[35m"
#define KCYM            "\x1B[36m"
#define KWHT            "\x1B[37m"
#define RESET           "\033[0m"

#define ACK_PRINT_BUFF  50

#define SERVER_IN       "server.in"
#define CLIENT_IN       "client.in"
#define PARAM_SIZE      100
#define MAX_RETRANSMIT  12

#define HEADER_LEN      12
#define MAX_PAYLOAD     512
#define DATAGRAM_SIZE   (MAX_PAYLOAD + HEADER_LEN)

#define SYN_SEQ_NO      1
#define SYN_ACK_SEQ_NO  2
#define ACK_SEQ_NO      3
#define FIN_SEQ_NO      4
#define FIN_ACK_NO      5
#define PROBE_SEQ_NO    6
#define PROBE_ACK_NO    7
#define CLI_DEF_SEQ_NO  8
#define DATA_SEQ_NO     11


#define CLIENT_TIMER    3000 // millisec
#define PROBE_TIMER     3000 // millisec
#define FIN_ACK_TIMER   3000 // millisec

#define GET_INDEX(    winQ, seqNum) ((seqNum)%(winQ->winSize))
#define GET_WNODE(    winQ, seqNum) (&(winQ->wnode[GET_INDEX(winQ, seqNum)]))
#define IS_PRESENT(   winQ, ind)    (winQ->wnode[ind].isPresent)
#define GET_PACKET(   winQ, ind)    (&(winQ->wnode[ind].packet))
#define GET_SEQ_NUM(  winQ, ind)    (GET_PACKET(winQ, ind)->seqNum)
#define GET_DATA_SIZE(winQ, ind)    (winQ->wnode[ind].dataSize)

typedef struct {
    uint32_t seqNum;            // 4 bytes
    uint32_t ackNum;            // 4 bytes
    uint32_t winSize;           // 4 bytes
    char data[MAX_PAYLOAD+1];   // 500 bytes
} TcpPckt;                      // 512 bytes

char* getStringParamValue(FILE *inp_file, char *paramVal);
int getIntParamValue(FILE *inp_file);
float getFloatParamValue(FILE *inp_file);

int print_ifi_info_plus(struct ifi_info *ifihead);
int verifyIfLocalAndGetHostIP(struct ifi_info *ifihead,
                              struct in_addr *remote_ip,
                              struct in_addr *host_ip);

int fillPckt(TcpPckt *packet, uint32_t seqNum, uint32_t ackNum,
        uint32_t winSize, char* dataPtr, int len);
int readPckt(TcpPckt *packet, int packet_size, uint32_t *seqNum,
        uint32_t *ackNum, uint32_t *winSize, char* dataPtr);

int setTimer(struct itimerval *timer, long int milliSec);

#endif /* !_COMMON_H */
